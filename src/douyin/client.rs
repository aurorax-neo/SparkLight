use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use anyhow::{Context, Result};
use reqwest::{header, Client, Method};
use serde_json::Value;
use base64::Engine;

use super::types::{CheckCookieResult, DouyinFriend, DouyinUserProfile, SendSparkResult, SparkConversationInfo};

#[path = "web.rs"]
mod web;
pub(crate) const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

pub struct DouyinClient {
    client: Client,
    current_cookie: Arc<Mutex<String>>,
    cookie_changed: Arc<Mutex<bool>>,
    risk_limited: Arc<AtomicBool>,
    verified_uid: Mutex<Option<u64>>,
    send_blocked: AtomicBool,
    send_credential: Mutex<Option<super::im_auth::ImSendCredential>>,
    web_context: Mutex<Option<super::im_auth::WebSessionContext>>,
    pub account_alias: String,
    send_claim: Mutex<Option<(sqlx::SqlitePool,String,String,Vec<u8>)>>,
    send_history: Mutex<HashMap<String,(u64,i32,chrono::NaiveDate,bool)>>,
    pcim_initial: Mutex<Option<session_auth::pcim_init::InitialBinding>>,
}

/// 清洗与提取完整 Cookie 字符串（支持直接粘贴 cURL 命令或纯 32 位 sessionid）
pub fn extract_clean_cookie(raw: &str) -> String {
    let text = raw.trim();
    // 1. 尝试从 cURL 命令行中解析提取 Cookie
    if text.contains("-H ") || text.contains("--header ") || text.contains("-b ") || text.contains("--cookie ") {
        let lower = text.to_lowercase();
        if let Some(pos) = lower.find("cookie:") {
            // Chrome 的 cURL 是 -H 'cookie: ...'，引号在字段名前，不能向后寻找起始引号。
            let before = text[..pos].trim_end();
            if let Some(q @ ('\'' | '"')) = before.chars().last() {
                let after = &text[pos + 7..];
                if let Some(end) = after.find(q) {
                    return after[..end].trim().replace('\n', "").replace('\r', "");
                }
            }
        }
        if let Some(pos) = text.find("-b ").or_else(|| text.find("--cookie ")) {
            let offset = if text.contains("-b ") { 3 } else { 9 };
            let after = &text[pos + offset..];
            let trimmed = after.trim_start();
            let quote = trimmed.chars().next();
            if let Some(q @ ('\'' | '"')) = quote {
                let inside = &trimmed[1..];
                if let Some(end_pos) = inside.find(q) {
                    return inside[..end_pos].trim().replace('\n', "").replace('\r', "");
                }
            }
        }
    }
    // 2. 如果用户仅输入了 32~64 位纯 sessionid 字符串
    if text.len() >= 32 && text.len() <= 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return format!("sessionid={text}; sessionid_ss={text}; sid_tt={text}");
    }
    text.replace('\n', "").replace('\r', "")
}
#[derive(Debug, Clone, Default)]
pub struct ParsedCredential {
    pub cookie: String,
    pub uid: Option<String>,
    pub nickname: Option<String>,
    pub guard: Option<(String, String)>,
}

/// 全量解析油猴 2.2.0 或用户输入凭证对象
pub fn parse_credential_full(raw: &str) -> ParsedCredential {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let cookie = val.get("cookie").and_then(|v| v.as_str())
                .map(|s| extract_clean_cookie(s))
                .unwrap_or_else(|| extract_clean_cookie(trimmed));
            let uid = val.get("uid").and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string);
            let nickname = val.get("nickname").and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string);
            let priv_key = val.get("guard_private_key").and_then(|v| v.as_str())
                .or_else(|| val.pointer("/guard/private_key").and_then(|v| v.as_str()))
                .or_else(|| val.pointer("/guard/private_key_hex").and_then(|v| v.as_str()))
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string);
            let srv_data = val.get("guard_server_data")
                .or_else(|| val.pointer("/guard/server_data"))
                .and_then(|v| {
                    let mut s = if let Some(s) = v.as_str() {
                        let trimmed = s.trim();
                        if trimmed.is_empty() { return None; }
                        if trimmed.starts_with('"') && trimmed.ends_with('"') {
                            serde_json::from_str::<String>(trimmed).unwrap_or_else(|_| trimmed.to_string())
                        } else {
                            trimmed.to_string()
                        }
                    } else if v.is_object() {
                        serde_json::to_string(v).ok()?
                    } else {
                        return None;
                    };

                    // 解包可能嵌套的 {"data": "{\"ticket\": ...}"} 或 {"data": {"ticket": ...}}
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                        if let Some(inner) = val.get("data") {
                            if let Some(inner_str) = inner.as_str() {
                                s = inner_str.trim().to_string();
                            } else if inner.is_object() {
                                if let Ok(inner_json) = serde_json::to_string(inner) {
                                    s = inner_json;
                                }
                            }
                        }
                    }
                    Some(s)
                });
            let guard = match (priv_key, srv_data) {
                (Some(k), Some(d)) => Some((k, d)),
                _ => None,
            };
            return ParsedCredential { cookie, uid, nickname, guard };
        }
    }
    ParsedCredential {
        cookie: extract_clean_cookie(trimmed),
        uid: None,
        nickname: None,
        guard: None,
    }
}

/// 解析用户输入：可能是包含 Cookie 与 Guard 密钥材料的完整 JSON，或者纯 Cookie
pub fn parse_credential_payload(raw: &str) -> (String, Option<(String, String)>) {
    let p = parse_credential_full(raw);
    (p.cookie, p.guard)
}
impl DouyinClient {
    pub fn new(cookie: &str, account_alias: &str) -> Result<Self> {
        let cookie_clean = extract_clean_cookie(cookie);
        let client = Self::build_http_client(&cookie_clean)?;

        Ok(Self {
            client,
            current_cookie: Arc::new(Mutex::new(cookie_clean)),
            cookie_changed: Arc::new(Mutex::new(false)),
            risk_limited: Arc::new(AtomicBool::new(false)),
            verified_uid: Mutex::new(None),
            send_blocked: AtomicBool::new(false),
            send_credential: Mutex::new(None),
            web_context: Mutex::new(None),
            account_alias: account_alias.to_string(),
            send_claim: Mutex::new(None),
            send_history: Mutex::new(HashMap::new()),
            pcim_initial: Mutex::new(None),
        })
    }

    fn build_http_client(_cookie_str: &str) -> Result<Client> {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static(DEFAULT_USER_AGENT),
        );
        headers.insert(
            header::REFERER,
            header::HeaderValue::from_static("https://www.douyin.com/"),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json, text/plain, */*"),
        );
        headers.insert(
            header::ACCEPT_LANGUAGE,
            header::HeaderValue::from_static("zh-CN,zh;q=0.9,en;q=0.8"),
        );
        headers.insert(
            "sec-fetch-dest",
            header::HeaderValue::from_static("empty"),
        );
        headers.insert(
            "sec-fetch-mode",
            header::HeaderValue::from_static("cors"),
        );
        headers.insert(
            "sec-fetch-site",
            header::HeaderValue::from_static("same-origin"),
        );


        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none());

        if let Ok(proxy_val) = std::env::var("SPARK_PROXY").or_else(|_| std::env::var("HTTP_PROXY")) {
            if let Ok(p) = reqwest::Proxy::all(&proxy_val) {
                builder = builder.proxy(p);
            }
        }

        builder.build().context("failed to build isolated reqwest client")
    }

    pub fn get_current_cookie(&self) -> String {
        self.current_cookie.lock().unwrap().clone()
    }

    pub fn is_cookie_changed(&self) -> bool {
        *self.cookie_changed.lock().unwrap()
    }

    pub fn extract_cookie_val(&self, name: &str) -> Option<String> {
        let guard = self.current_cookie.lock().unwrap();
        for item in guard.split(';') {
            let item = item.trim();
            if let Some((k, v)) = item.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    }

    fn confirm_profile(&self, profile: DouyinUserProfile) -> CheckCookieResult {
        self.clear_session_block();
        let uid = profile.uid.parse::<u64>().ok().filter(|uid| *uid > 0);
        *self.verified_uid.lock().unwrap() = uid;
        if uid.is_none() {
            return CheckCookieResult::Expired("当前会话未返回有效发送身份".to_string());
        }
        let uid=uid.unwrap();
        // 只读 SESSION_AUTH：仅在尚未初始化会话上下文时建立初始骨架；已有上下文严禁重建冲刷
        let needs_init = self.web_context.lock().unwrap().is_none();
        if needs_init {
            match super::im_auth::WebSessionContext::from_session(uid, &self.get_current_cookie(), DEFAULT_USER_AGENT) {
                Ok(context) => {
                    if self.set_web_context(context).is_err() {
                        return CheckCookieResult::NetworkError("IM 只读会话初始化失败".into());
                    }
                }
                Err(_) => return CheckCookieResult::NetworkError("IM 只读会话初始化失败".into()),
            }
        }
        CheckCookieResult::Valid(profile)
    }

    pub fn verified_sender_uid(&self, expected_uid: Option<&str>) -> Result<u64> {
        self.ensure_requests_allowed()?;
        let confirmed = self.verified_uid.lock().unwrap().context("未确认当前 Cookie 的发送身份，禁止发送")?;
        if let Some(expected) = expected_uid {
            let expected = expected.parse::<u64>().ok().filter(|uid| *uid > 0)
                .context("账号 UID 无效，禁止发送")?;
            if expected != confirmed {
                self.stop_requests(web::FailureKind::Expired);
                anyhow::bail!("当前 Cookie 身份与所属账号不符，禁止发送");
            }
        }
        Ok(confirmed)
    }

    pub fn set_send_credential(&self, credential: super::im_auth::ImSendCredential) -> Result<()> {
        let current=self.web_context.lock().unwrap().clone();
        if let Some(context)=current.as_ref().filter(|c|c.has_identity()) {
            credential.validate_identity_binding(context,credential.uid,&self.get_current_cookie())?;
        } else {
            self.set_web_context(super::im_auth::WebSessionContext::from_credential(&credential))?;
        }
        anyhow::ensure!(credential.session_hash == super::im_auth::session_hash(&self.get_current_cookie())?, "IM 凭证与当前 Cookie 不符，禁止发送");
        *self.send_credential.lock().unwrap() = Some(credential);
        Ok(())
    }

    pub fn set_web_context(&self, mut context: super::im_auth::WebSessionContext) -> Result<()> {
        context.validate_session(context.uid, &self.get_current_cookie())?;
        let mut guard = self.web_context.lock().unwrap();
        if let Some(old) = guard.as_ref() {
            context.inherit_guard_materials(old);
        }
        *guard = Some(context);
        Ok(())
    }

    pub async fn load_web_context(&self, pool: &sqlx::SqlitePool, secret: &crate::crypto::SecretBox, account_id: &str, uid: Option<&str>) -> Result<()> {
        let encrypted: Option<(Vec<u8>,)> = sqlx::query_as("SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1").bind(account_id).fetch_optional(pool).await?;
        if let Some((encrypted,))=encrypted {
            let context: super::im_auth::WebSessionContext = serde_json::from_slice(&secret.decrypt(&encrypted)?).context("Web 上下文解码失败")?;
            if context.session_hash == super::im_auth::session_hash(&self.get_current_cookie())? {
                anyhow::ensure!(uid==Some(context.uid.to_string().as_str()),"账号 Web 上下文身份不符");
                self.set_web_context(context)?;
            }
        }
        Ok(())
    }

    pub fn im_history_status(&self, uid: Option<&str>) -> (&'static str, Option<i64>) {
        self.web_context.lock().unwrap().as_ref().map_or(("MISSING", None), |context|
            context.history_status(uid, &self.get_current_cookie(), chrono::Utc::now().timestamp()))
    }

    /// 独立获取官方身份 Token；不生成发送签名或一次性发送授权。
    pub async fn acquire_im_identity(&self, expected_uid: Option<&str>) -> Result<()> {
        let uid=self.verified_sender_uid(expected_uid)?;
        let cookie=self.get_current_cookie();
        let now=chrono::Utc::now().timestamp();
        if self.web_context.lock().unwrap().as_ref().is_some_and(|c| {
            c.history_status(Some(&uid.to_string()),&cookie,now).0=="AVAILABLE"
                && c.identity_acquired_at.is_some_and(|at| now.checked_sub(at).is_some_and(|age| age <= 300))
        }) { return Ok(()); }
        let biz_trace_id = format!("{:08x}", rand::random::<u32>());
        let ms_token = self.extract_cookie_val("msToken").unwrap_or_else(|| {
            use rand::Rng;
            const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
            let mut rng = rand::thread_rng();
            (0..176).map(|_| { let idx = rng.gen_range(0..CHARSET.len()); CHARSET[idx] as char }).collect()
        });
        let request=self.web_request(Method::GET,"https://www.douyin.com/passport/safe/get_identity_security_token/")?
            .query(&[("aid","6383"),("scene","web_im"),("auto_retry_req","0"),("skip_verify","false"),("identity_token_force_get_tag","0"),
                ("biz_trace_id",&biz_trace_id),("id_token_version","1.2.10"),("passport_jssdk_version","4.2.3"),("passport_jssdk_type","lite"),
                ("is_from_ttaccountsdk","1"),("language","zh"),("msToken",&ms_token)])
            .header("x-tt-passport-csrf-token",self.extract_cookie_val("passport_csrf_token").or_else(||self.extract_cookie_val("passport_csrf_token_default")).unwrap_or_default())
            .header("x-tt-passport-trace-id",&biz_trace_id)
            .header("sec-ch-ua", "\"Brave\";v=\"155\", \"Chromium\";v=\"155\", \"Not(A:Brand\";v=\"24\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"macOS\"")
            .header("accept", "application/json, text/javascript");
        let response=self.web_json(request).await?;
        let old_ctx = self.web_context.lock().unwrap().clone();
        let ua = old_ctx.as_ref().map(|o| o.user_agent.as_str()).unwrap_or(DEFAULT_USER_AGENT);
        let mut context=super::im_auth::WebSessionContext::from_session(uid,&cookie,ua)?.with_identity(&response)?;
        if let Some(ref old) = old_ctx {
            context.inherit_guard_materials(old);
        }
        anyhow::ensure!(matches!(self.check_cookie().await,CheckCookieResult::Valid(_)),"IM 身份凭证获取后登录态未确认，未保存凭证");
        self.verified_sender_uid(Some(&uid.to_string()))?;
        context.validate_session(uid,&self.get_current_cookie())?;
        self.set_web_context(context)
    }

    /// 自动任务共用：拉取失败或身份变化时在消费发送授权之前停止。
    pub async fn prepare_im_identity(&self, expected_uid: Option<&str>) -> Result<()> {
        if let Err(error)=self.acquire_im_identity(expected_uid).await {
            self.send_blocked.store(true,Ordering::Relaxed);
            return Err(error.context("IM 身份续取失败，未发送且未自动重试"));
        }
        Ok(())
    }

    /// 同事务保存 Cookie 与上下文，拒绝覆盖请求期间换入的新会话。
    pub async fn persist_im_session(&self,pool: &sqlx::SqlitePool,secret: &crate::crypto::SecretBox,
        account_id: &str,original_encrypted_cookie: &[u8],expected_uid: Option<&str>) -> Result<()> {
        let uid=self.verified_sender_uid(expected_uid)?;
        let mut context=self.web_context.lock().unwrap().clone().context("IM 上下文不存在")?;
        context.validate_session(uid,&self.get_current_cookie())?;
        if context.guard_secret_hex.is_none() || context.guard_server_data.is_none() {
            if let Ok(Some(old_enc)) = sqlx::query_scalar::<_, Vec<u8>>("SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1").bind(account_id).fetch_optional(pool).await {
                if let Ok(old_plain) = secret.decrypt(&old_enc) {
                    if let Ok(old_saved) = serde_json::from_slice::<super::im_auth::WebSessionContext>(&old_plain) {
                        context.inherit_guard_materials(&old_saved);
                    }
                }
            }
        }
        let encrypted_cookie=secret.encrypt(self.get_current_cookie().as_bytes())?;
        let encrypted_context=secret.encrypt(&serde_json::to_vec(&context)?)?;
        let mut tx=pool.begin().await?;
        let changed=sqlx::query("UPDATE accounts SET encrypted_cookie=?1 WHERE id=?2 AND encrypted_cookie=?3 AND uid=?4 AND status='ACTIVE'")
            .bind(encrypted_cookie).bind(account_id).bind(original_encrypted_cookie).bind(uid.to_string()).execute(&mut *tx).await?;
        anyhow::ensure!(changed.rows_affected()==1,"请求期间账号会话已变化，未保存旧 IM 凭证");
        sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
            .bind(account_id).bind(encrypted_context).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn persist_web_context(&self, pool: &sqlx::SqlitePool, secret: &crate::crypto::SecretBox, account_id: &str) -> Result<()> {
        let context=self.web_context.lock().unwrap().clone();
        if let Some(mut ctx)=context {
            if ctx.session_hash != super::im_auth::session_hash(&self.get_current_cookie())? { return Ok(()); }
            if ctx.guard_secret_hex.is_none() || ctx.guard_server_data.is_none() {
                if let Ok(Some(old_enc)) = sqlx::query_scalar::<_, Vec<u8>>("SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1").bind(account_id).fetch_optional(pool).await {
                    if let Ok(old_plain) = secret.decrypt(&old_enc) {
                        if let Ok(old_saved) = serde_json::from_slice::<super::im_auth::WebSessionContext>(&old_plain) {
                            ctx.inherit_guard_materials(&old_saved);
                        }
                    }
                }
            }
            let encrypted=secret.encrypt(&serde_json::to_vec(&ctx)?)?;
            sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
                .bind(account_id).bind(encrypted).execute(pool).await?;
            if let Some(mem_ctx) = self.web_context.lock().unwrap().as_mut() {
                mem_ctx.inherit_guard_materials(&ctx);
            }
        }
        Ok(())
    }

    /// 官方 TokenBeat 机制：通过 /passport/token/beat/web/ 进行会话保活并自动同步身份令牌与 Cookie
    pub async fn passport_token_beat(&self, scene: &str) -> Result<bool> {
        let cookie = self.get_current_cookie();
        let url = format!("https://www.douyin.com/passport/token/beat/web/?scene={scene}&aid=6383");
        let resp = self.client.get(&url)
            .header(header::COOKIE, &cookie)
            .header(header::USER_AGENT, DEFAULT_USER_AGENT)
            .header("web-sdk-version", "1")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(false);
        }
        let headers = resp.headers().clone();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let success = body.get("data").and_then(|d| d.get("error_code")).and_then(|c| c.as_i64()) == Some(0)
            || body.get("message").and_then(|m| m.as_str()) == Some("success");
        if success {
            self.merge_response_headers(&headers);
        }
        Ok(success)
    }

    /// 确保当前账号具备有效的 GuardKey 与已建联的服务端票据材料。
    pub async fn ensure_guard_bound(&self) -> Result<(super::pcim_guard::GuardKey, super::pcim_guard::BoundGuardMaterial)> {
        let cookie = self.get_current_cookie();
        let (key, material) = {
            let mut ctx = self.web_context.lock().unwrap().clone().context("缺少 IM 上下文")?;
            let key = ctx.get_or_create_guard_key()?;
            let mat = ctx.get_guard_material(&key, &cookie)?;
            (key, mat)
        };
        if let Some(material) = material {
            return Ok((key, material));
        }
        #[cfg(test)]
        if im_identity_tests::active() {
            anyhow::bail!("OFFLINE_MOCK_NO_GUARD_BOUND");
        }
        anyhow::bail!("当前账号尚未绑定有效的 Guard 签名票据材料，禁止发送未签名请求以防会话被踢下线");
    }

    /// 拉取 DTrait 中央公钥配置并缓存在 Web 上下文中。
    pub async fn acquire_dtrait_config(&self) -> Result<()> {
        let _cookie = self.get_current_cookie();
        let csrf = self.extract_cookie_val("passport_csrf_token")
            .or_else(|| self.extract_cookie_val("passport_csrf_token_default"))
            .unwrap_or_default();
        let request = self.web_request(Method::POST, "https://www.douyin.com/passport/ticket_guard/get_client_cert/?aid=6383&type=trait&sdk_version=1.0.25&is_from_ttaccountsdk=1")?
            .header(header::ACCEPT, "application/json")
            .header("x-tt-passport-csrf-token", csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("server_data=1&need_session_dtrait=1");
        let json = self.web_json(request).await?;
        let data = json.get("data").context("DTRAIT_DATA_MISSING")?;
        let public_b64 = data.get("x-tt-session-dtrait-pk1").and_then(serde_json::Value::as_str).context("DTRAIT_PK1_MISSING")?;
        let version = data.get("x-tt-session-dtrait-pk1-version").and_then(serde_json::Value::as_str).context("DTRAIT_VERSION_MISSING")?;
        let pem_bytes = base64::engine::general_purpose::STANDARD.decode(public_b64).context("DTRAIT_DECODE_FAILED")?;
        let pem = String::from_utf8(pem_bytes).context("DTRAIT_PEM_INVALID")?;
        if let Some(mut ctx) = self.web_context.lock().unwrap().clone() {
            ctx.set_dtrait_config(&pem, version);
            self.set_web_context(ctx)?;
        }
        Ok(())
    }

    pub fn clear_send_credential(&self) {
        *self.send_credential.lock().unwrap() = None;
        *self.send_claim.lock().unwrap() = None;
        *self.pcim_initial.lock().unwrap() = None;
    }

    pub fn sending_blocked(&self) -> bool {
        self.send_blocked.load(Ordering::Relaxed)
    }


    /// 抖音会话活跃状态探测：直接复用安全的原生 Web 接口探测，彻底移除高危的 Mobile SDK 打点
    pub async fn token_beat(&self) -> super::types::HeartbeatResult {
        match self.check_cookie().await {
            super::types::CheckCookieResult::Valid(_) => super::types::HeartbeatResult::Alive,
            super::types::CheckCookieResult::Expired(r) => super::types::HeartbeatResult::Expired(r),
            super::types::CheckCookieResult::NeedVerify(r) => super::types::HeartbeatResult::Expired(format!("需安全验证: {r}")),
            super::types::CheckCookieResult::NetworkError(e) => super::types::HeartbeatResult::Error(e),
        }
    }

    pub async fn get_profile_by_url(&self, profile_url: &str) -> Result<String> {
        self.verified_sender_uid(None)?;
        let request = self.web_request(Method::GET, profile_url)?;
        let json = self.web_json(request).await?;
        json.get("user").and_then(|u| u.get("nickname")).and_then(Value::as_str)
            .filter(|n| !n.trim().is_empty()).map(str::to_string).context("Web 未返回目标昵称，保留原资料")
    }

    /// 登录身份仅由 Passport/self 确认，不以 query/other 接口猜测当前账号。
    pub async fn check_cookie(&self) -> CheckCookieResult {
        *self.verified_uid.lock().unwrap() = None;
        let request = match self.web_request_allow_probe(Method::GET, "https://www.douyin.com/passport/account/info/v2/?aid=6383") {
            Ok(r) => r, Err(e) => return Self::check_failure(e),
        };
        let passport = match self.web_json(request).await { Ok(v) => v, Err(e) => return Self::check_failure(e) };
        let Some(data) = passport.get("data") else { return CheckCookieResult::NetworkError("Passport 缺少账号资料，未继续请求".into()); };
        let uid = data.get("user_id_str").or_else(|| data.get("user_id")).and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|u| u.to_string()))).unwrap_or_default();
        if uid.parse::<u64>().ok().filter(|u| *u>0).is_none() {
            self.stop_requests(web::FailureKind::Expired);
            return CheckCookieResult::Expired("Passport 未返回有效登录身份".into());
        }
        if self.web_context.lock().unwrap().as_ref().is_some_and(|c| c.uid.to_string() != uid) {
            self.stop_requests(web::FailureKind::Expired);
            return CheckCookieResult::Expired("Cookie 身份与绑定 Web 上下文不符，停止请求".into());
        }
        let mut profile = DouyinUserProfile {
            uid: uid.clone(), sec_uid:data.get("sec_user_id").and_then(Value::as_str).unwrap_or("").into(),
            nickname:data.get("screen_name").or_else(|| data.get("name")).and_then(Value::as_str).unwrap_or("抖音用户").into(),
            avatar_url:data.get("avatar_url").and_then(Value::as_str).unwrap_or("").into(),
        };
        #[cfg(test)]
        if im_identity_tests::active() {
            if !profile.sec_uid.is_empty() && !profile.nickname.starts_with("用户") && profile.nickname!="抖音用户" {
                return self.confirm_profile(profile);
            }
        }
        // 优先从权威的个人主页接口获取最新昵称与头像；若暂不可用则平滑保留 Passport 资料
        if let Ok(request) = self.web_request_allow_probe(Method::GET, "https://www.douyin.com/aweme/v1/web/user/profile/self/") {
            if let Ok(json) = self.web_json(request).await {
                if let Some(user) = json.get("user").filter(|u| u.is_object()) {
                    let self_uid = user.get("uid").and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|u| u.to_string())));
                    if self_uid.as_deref() == Some(uid.as_str()) {
                        if let Some(sec) = user.get("sec_uid").and_then(Value::as_str).filter(|s| !s.is_empty()) { profile.sec_uid = sec.into(); }
                        if let Some(nick) = user.get("nickname").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) { profile.nickname = nick.into(); }
                        if let Some(avatar) = user.pointer("/avatar_thumb/url_list/0").and_then(Value::as_str) { profile.avatar_url = avatar.into(); }
                    }
                }
            }
        }
        self.confirm_profile(profile)
    }


    pub fn risk_limited(&self) -> bool {
        self.risk_limited.load(Ordering::Relaxed)
    }

    fn parse_friend_remark(item: &Value, nickname: &str) -> Option<String> {
        let mut raw = String::new();
        for key in ["remark_name", "remark", "alias", "alias_name"] {
            if let Some(text) = item.get(key).and_then(|v| v.as_str()) {
                let text = text.trim();
                if !text.is_empty() {
                    raw = text.to_string();
                    break;
                }
            }
        }
        if raw.is_empty() {
            if let Some(text) = item
                .get("follow_info")
                .and_then(|f| f.get("remark_name").or_else(|| f.get("remark")))
                .and_then(|v| v.as_str())
            {
                let text = text.trim();
                if !text.is_empty() {
                    raw = text.to_string();
                }
            }
        }
        if raw.is_empty() || raw == nickname {
            None
        } else {
            Some(raw)
        }
    }

    /// 网页 IM 用户资料。备注在表单字段 sec_user_ids（JSON 数组），不在 query 上。
    async fn fetch_im_remarks(&self, sec_uids: &[String]) -> Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        for chunk in sec_uids.chunks(20) {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("sec_user_ids", &serde_json::to_string(chunk)?).finish();
            let request = self.web_request(Method::POST,"https://www.douyin.com/aweme/v1/web/im/user/info/")?
                .header(header::CONTENT_TYPE,"application/x-www-form-urlencoded").body(body);
            let json = self.web_json(request).await?;
            let arr = json.get("data").and_then(Value::as_array).context("IM 用户资料列表缺失，保留原备注")?;
            for item in arr {
                let sec = item.get("sec_uid").and_then(Value::as_str).unwrap_or("");
                let nick = item.get("nickname").and_then(Value::as_str).unwrap_or("");
                if !sec.is_empty() { if let Some(rem) = Self::parse_friend_remark(item,nick) { map.insert(sec.into(),rem); } }
            }
        }
        Ok(map)
    }

    pub async fn fetch_following_friends(&self, uid: &str, sec_uid: &str) -> Result<Vec<DouyinFriend>> {
        let needs_check=self.verified_uid.lock().unwrap().is_none();
        if needs_check {
            let checked=self.check_cookie().await;
            anyhow::ensure!(checked.is_valid(), "{}",checked.error_message().unwrap_or("登录态未确认，停止好友同步"));
        }
        let my_uid = self.verified_sender_uid(Some(uid))?;
        anyhow::ensure!(!sec_uid.is_empty(),"缺少当前账号 SecUID，停止同步");
        let mut friends = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut spotlight = reqwest::Url::parse("https://www.douyin.com/aweme/v1/web/im/spotlight/relation/")?;
        spotlight.query_pairs_mut().extend_pairs([
            ("count","50"),("source","coldup"),("min_time","0"),("need_remove_share_panel","1"),
            ("need_sorted_info","1"),("with_fstatus","1"),("with_recent_share_day","1")
        ]).append_pair("max_time",&chrono::Utc::now().timestamp_millis().to_string());
        let json = self.web_json(self.web_request(Method::GET,spotlight.as_str())?).await?;
        let list = json.get("followings").and_then(Value::as_array).context("好友关系列表缺失，未回退重试")?;
        for item in list { push_friend(item,&mut friends,&mut seen); }
        if let Some(groups) = json.get("recent_share_groups").and_then(Value::as_array) {
            for g in groups {
                let cid = g.get("conv_id").and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|v| v.to_string()))).unwrap_or_default();
                if cid.parse::<u64>().ok().filter(|id| *id>0).is_none() || !seen.insert(cid.clone()) { continue; }
                friends.push(DouyinFriend { uid:String::new(),sec_uid:cid.clone(),nickname:format!("群聊 ({})",&cid[cid.len().saturating_sub(6)..]),
                    avatar_url:String::new(),spark_days:None,spark_desc:None,is_sparked_today:None,target_type:Some(2),conversation_id:Some(cid),remark_name:None });
            }
        }
        // 一条有界关注列表分页链，复用联系人和备注；不再重复 fallback 后又重拉第一页。
        let mut cursor = 0_i64;
        let mut cursors = std::collections::HashSet::new();
        for _ in 0..8 {
            let mut url = reqwest::Url::parse("https://www.douyin.com/aweme/v1/web/user/following/list/")?;
            url.query_pairs_mut().extend_pairs([("user_id",uid),("sec_user_id",sec_uid),("count","20"),("offset","0"),("source_type","1"),("min_time","0")])
                .append_pair("max_time",&cursor.to_string());
            let json = self.web_json(self.web_request(Method::GET,url.as_str())?).await?;
            let list = json.get("followings").and_then(Value::as_array).context("关注列表缺失，停止翻页并保留原资料")?;
            for item in list {
                push_friend(item,&mut friends,&mut seen);
                let sec = item.get("sec_uid").and_then(Value::as_str).unwrap_or("");
                if let Some(rem) = Self::parse_friend_remark(item,item.get("nickname").and_then(Value::as_str).unwrap_or("")) {
                    if let Some(f) = friends.iter_mut().find(|f| f.sec_uid==sec) { f.remark_name=Some(rem); }
                }
            }
            let more = json.get("has_more").is_some_and(|v| v.as_bool()==Some(true) || v.as_i64()==Some(1));
            if !more || list.is_empty() { break; }
            let next = json.get("min_time").and_then(Value::as_i64).filter(|v| *v>0).context("关注列表游标缺失，停止翻页")?;
            anyhow::ensure!(next != cursor && cursors.insert(next), "关注列表游标循环，停止翻页");
            cursor=next;
        }
        let missing: Vec<_> = friends.iter().filter(|f| f.target_type==Some(1) && f.remark_name.is_none()).map(|f| f.sec_uid.clone()).collect();
        let remarks = self.fetch_im_remarks(&missing).await?;
        for f in &mut friends { if let Some(rem)=remarks.get(&f.sec_uid) { f.remark_name=Some(rem.clone()); } }
        let targets: Vec<_> = friends.iter().filter_map(|f| {
            if f.target_type==Some(2) { Some(DouyinTargetParam { conv_id:f.conversation_id.clone()?,conv_type:2,short_id:None }) }
            else { let peer=f.uid.parse::<u64>().ok().filter(|u| *u>0 && *u!=my_uid)?; Some(DouyinTargetParam {conv_id:format!("0:1:{}:{}",my_uid.min(peer),my_uid.max(peer)),conv_type:1,short_id:None}) }
        }).collect();
        // IM 上下文缺失/过期时保留未知值，不伪造未点亮或未发送。
        if !targets.is_empty() && self.web_context.lock().unwrap().as_ref().is_some_and(|c| (0..=600).contains(&(chrono::Utc::now().timestamp()-c.captured_at))) {
            for batch in targets.chunks(200) {
                let spark = self.fetch_available_conversation_spark_status(batch).await?;
                for f in &mut friends {
                    let cid = if f.target_type==Some(2) { f.conversation_id.clone().unwrap_or_default() }
                        else if let Ok(peer)=f.uid.parse::<u64>() { format!("0:1:{}:{}",my_uid.min(peer),my_uid.max(peer)) } else { continue; };
                    if let Some(info)=spark.get(&cid) {
                        f.spark_days=Some(info.days); f.spark_desc=Some(info.desc.clone());
                        if f.target_type==Some(2) {
                            if let Some(name)=&info.conv_name { f.nickname=name.clone(); }
                        } else if let Ok(peer)=f.uid.parse::<u64>() {
                            if let Some((_, alias)) = info.aliases.iter().find(|(uid, _)| *uid == peer) {
                                if !alias.trim().is_empty() {
                                    f.remark_name = Some(alias.trim().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(friends)
    }

    /// Batch fetch exact spark streak status (a:consecutive_chat_data) via Douyin IM Protobuf API (cmd 610)
    pub async fn fetch_batch_conversation_spark_status(
        &self,
        targets: &[DouyinTargetParam],
    ) -> Result<HashMap<String, SparkConversationInfo>> {
        let results = self.fetch_available_conversation_spark_status(targets).await?;
        anyhow::ensure!(targets.iter().all(|t| results.contains_key(&t.conv_id)),"IM 未返回当前目标会话，火花状态未知，保留原数据");
        Ok(results)
    }

    /// 联系人不一定已建立 IM 会话；同步仅合并明确返回的会话，其余保持未知。
    pub async fn fetch_available_conversation_spark_status(
        &self, targets: &[DouyinTargetParam],
    ) -> Result<HashMap<String, SparkConversationInfo>> {
        let mut results = HashMap::new();
        if targets.is_empty() {
            return Ok(results);
        }

        let uid = self.verified_sender_uid(None)?;
        anyhow::ensure!(targets.len() <= 200, "IM 批量会话数量超限");
        for target in targets { validate_conversation(uid,&target.conv_id,target.conv_type)?; }
        let mut list_req = Vec::new();
        for t in targets {
            let mut single = Vec::new();
            encode_field_bytes(1, t.conv_id.as_bytes(), &mut single);
            if let Some(sid) = t.short_id {
                encode_field_varint(2, sid, &mut single);
            }
            encode_field_varint(3, t.conv_type as u64, &mut single);
            encode_field_varint(4, 1, &mut single); // need_coreinfo_related = true
            encode_field_varint(5, 1, &mut single); // need_userinfo_related = true
            encode_field_varint(7, 1, &mut single); // need_settinginfo_related = true

            encode_field_bytes(1, &single, &mut list_req);
        }

        let mut req_body = Vec::new();
        encode_field_bytes(610, &list_req, &mut req_body);

        let bytes = self.web_im("https://imapi.douyin.com/v2/conversation/get_info_list",610,&req_body).await?;
        results.extend(parse_im_conversation_list_response(&bytes)?);
        for cid in results.keys() {
            let target = targets.iter().find(|t| t.conv_id == *cid).context("IM 返回了未请求的会话，停止合并")?;
            validate_conversation(uid,cid,target.conv_type)?;
        }
        Ok(results)
    }

    pub async fn send_spark_message(
        &self,
        conv_id_opt: Option<&str>,
        conv_type: i32,
        target_sec_uid: &str,
        target_uid: Option<&str>,
        content: &str,
    ) -> SendSparkResult {
        if self.pcim_initial.lock().unwrap().is_some() {
            return self.send_pcim_initial(conv_id_opt, conv_type, target_sec_uid, target_uid, content).await;
        }
        let text_msg = if content.trim().is_empty() {
            "🔥"
        } else {
            content.trim()
        };
        let my_uid = match self.verified_sender_uid(None) {
            Ok(uid) if !self.sending_blocked() => uid,
            Ok(_) => return SendSparkResult::failure("会话或鉴权已失败，当前操作禁止继续发送"),
            Err(_) => return SendSparkResult::failure("未确认当前 Cookie 的有效发送身份，禁止发送"),
        };

        if self.send_credential.lock().unwrap().is_none() {
            return SendSparkResult::failure("缺少官方 IM 发送鉴权凭证，未发送；身份 Token 不能替代独立发送授权");
        }
        if self.prepare_im_identity(Some(&my_uid.to_string())).await.is_err() {
            return SendSparkResult::failure("IM 身份 Token 续取失败或身份变化，未发送且未自动重试");
        }
        let parsed_to_uid = if conv_type == 2 { 0 } else { target_uid.and_then(|s| s.parse().ok()).filter(|u| *u>0).unwrap_or(0) };
        let req = match self.build_send_request(
            "https://imapi.douyin.com/v1/message/send", my_uid, conv_id_opt,
            conv_type, target_sec_uid, parsed_to_uid, text_msg,
        ) {
            Ok(req) => req,
            Err(e) => return SendSparkResult::failure(&e.to_string()),
        };

        match self.execute_web(req).await {
            Ok((headers, bytes, _guard)) => {
                let (ok,code,message,id) = parse_im_send_response(&bytes);
                if ok {
                    self.merge_response_headers(&headers);
                    SendSparkResult { success:true,message:format!("续火花消息已成功送达！(内容: {text_msg}, 消息ID: {id})"),spark_days:None,raw_response:Some(format!("MsgID: {id}, status: {code}")) }
                } else {
                    self.send_blocked.store(true,Ordering::Relaxed);
                    self.stop_requests(web::FailureKind::Protocol);
                    SendSparkResult::failure(&format!("IM 未确认发送成功（状态 {code}）: {message}；禁止发送重试"))
                }
            }
            Err(e) => {
                self.stop_requests(e.downcast_ref::<web::WebFailure>().map(|e| e.kind).unwrap_or(web::FailureKind::Network));
                SendSparkResult::failure(&format!("{e}；发送结果未知，禁止发送重试"))
            }
        }
    }

    /// 实际 HTTP 发送与离线测试共用此构造器，不从 Cookie 猜测 UID。
    fn build_send_request(
        &self, url: &str, my_uid: u64, conv_id_opt: Option<&str>, conv_type: i32,
        target_sec_uid: &str, target_uid: u64, text_msg: &str,
    ) -> Result<reqwest::Request> {
        // 捕获的 Ticket Guard 只属于官方发送路径，必须在消费凭证前拒绝跨路径使用。
        super::sdk_runtime::validate_captured_send_endpoint(url)?;
        self.ensure_requests_allowed()?;
        anyhow::ensure!(self.verified_sender_uid(None)? == my_uid, "发送身份不符，禁止发送");
        let cid = if conv_type == 2 {
            conv_id_opt.unwrap_or(target_sec_uid).to_string()
        } else {
            anyhow::ensure!(conv_type == 1 && target_uid > 0 && my_uid != target_uid, "单聊目标身份无效，禁止发送");
            let cid = format!("0:1:{}:{}", my_uid.min(target_uid), my_uid.max(target_uid));
            anyhow::ensure!(conv_id_opt.is_none_or(|stored| stored == cid), "目标会话与当前账号身份不符，禁止发送");
            cid
        };
        let mut guard = self.send_credential.lock().unwrap();
        let credential = guard.as_ref().context("缺少官方 IM 发送鉴权凭证，单独更新 Cookie 不足以发送；请同步当前会话的官方发送请求，禁止发送")?;
        credential.validate(my_uid, &self.get_current_cookie(), &cid, conv_type)?;
        let context=self.web_context.lock().unwrap().clone().context("缺少当前 IM 身份 Token，禁止发送")?;
        credential.validate_identity_binding(&context,my_uid,&self.get_current_cookie())?;
        let credential = guard.take().expect("validated credential");
        let mut request = self.web_request(Method::POST,url)?
            .header(header::USER_AGENT, &credential.user_agent)
            .header(header::CONTENT_TYPE, "application/x-protobuf")
            .header(header::ACCEPT, "application/x-protobuf")
            .body(credential.request_body(text_msg));
        for (key, value) in &credential.http_headers { request = request.header(key, value); }
        request.build().context("无法构造官方 IM 发送请求")
    }

    /// Check whether I (current user) have sent any message to this conversation today
    pub async fn check_i_sent_message_today(
        &self,
        my_uid: u64,
        conv_id: &str,
        conv_type: i32,
        short_id: u64,
    ) -> Result<bool> {
        let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
        let query_day = chrono::Utc::now().with_timezone(&cst).date_naive();
        anyhow::ensure!(self.verified_sender_uid(None)?==my_uid,"消息历史查询身份不符");
        validate_conversation(my_uid,conv_id,conv_type)?;

        let mut effective_short_id = short_id;
        if effective_short_id == 0 {
            let single_param = DouyinTargetParam {
                conv_id: conv_id.to_string(),
                conv_type,
                short_id: None,
            };
            let map = self.fetch_batch_conversation_spark_status(&[single_param]).await?;
            if let Some(info) = map.get(conv_id) {
                effective_short_id = info.short_id;
            }
        }

        anyhow::ensure!(effective_short_id>0,"未取得真实会话短 ID，今日发送情况未知，禁止发送");
        let mut msg_req = Vec::new();
        encode_field_bytes(1, conv_id.as_bytes(), &mut msg_req);
        encode_field_varint(2, conv_type as u64, &mut msg_req);
        if effective_short_id > 0 {
            encode_field_varint(3, effective_short_id, &mut msg_req);
        }
        encode_field_varint(4, 1, &mut msg_req); // direction = 1 (older)
        encode_field_varint(6, 50, &mut msg_req); // limit = 50

        let mut req_body = Vec::new();
        encode_field_bytes(301, &msg_req, &mut req_body);

        let bytes = self.web_im("https://imapi.douyin.com/v1/message/get_by_conversation",301,&req_body).await?;
        let sent = parse_im_check_my_message_today(&bytes, my_uid)?;
        anyhow::ensure!(chrono::Utc::now().with_timezone(&cst).date_naive() == query_day,
            "消息历史检测跨越北京时间零点，请重新刷新，今日发送情况未知");
        self.send_history.lock().unwrap().insert(conv_id.into(),(my_uid,conv_type,query_day,sent));
        Ok(sent)
    }

    pub(crate) fn bind_send_claim(&self,pool:sqlx::SqlitePool,account_id:&str,conversation_id:&str,encrypted:Vec<u8>) {
        *self.send_claim.lock().unwrap()=Some((pool,account_id.into(),conversation_id.into(),encrypted));
    }

    fn validate_send_history(&self,request:&reqwest::Request) -> Result<()> {
        let field=|data:&[u8],number|parse_protobuf_fields(data).into_iter().find(|(n,w,_)|*n==number&&*w==2).map(|(_,_,b)|b);
        let data=request.body().and_then(|b|b.as_bytes()).context("发送请求体不可检查")?;
        let body=field(data,8).and_then(|b|field(&b,100)).context("发送会话不可检查")?;
        let cid=String::from_utf8(field(&body,1).context("发送会话缺失")?)?;
        let uid=self.verified_sender_uid(None)?;
        let history=self.send_history.lock().unwrap();
        let (sender,kind,day,sent)=history.get(&cid).context("缺少该会话完整今日历史确认，禁止发送")?;
        let request_kind=parse_protobuf_fields(&body).into_iter().find(|(n,w,_)|*n==2&&*w==0).and_then(|(_,_,b)|read_varint(&b,0).map(|(v,_)|v as i32));
        let force = self.pcim_initial.lock().unwrap().as_ref().map_or(false, |b| b.force);
        anyhow::ensure!(*sender==uid&&Some(*kind)==request_kind&&(!*sent || force)&&*day==chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive(),
            "今日历史已发送、身份不符或跨越北京时间零点，停止发送");
        let context=self.web_context.lock().unwrap().clone().context("IM 身份缺失，停止发送")?;
        anyhow::ensure!(context.identity_is_current(uid,&self.get_current_cookie(),chrono::Utc::now().timestamp()),"发送排队期间 IM 身份已过期，停止发送");
        Ok(())
    }

    async fn claim_send_authorization(&self) -> Result<()> {
        let claim=self.send_claim.lock().unwrap().take();
        if let Some((pool,account,cid,encrypted))=claim {
            let result=sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1 AND conversation_id=?2 AND encrypted_credential=?3")
                .bind(account).bind(cid).bind(encrypted).execute(&pool).await?;
            anyhow::ensure!(result.rows_affected()==1,"发送授权已变化或被消费，禁止发送");
        }
        Ok(())
    }
}

fn push_friend(item: &Value, friends: &mut Vec<DouyinFriend>, seen: &mut std::collections::HashSet<String>) {
    let sec = item.get("sec_uid").and_then(Value::as_str).unwrap_or("");
    let uid = item.get("uid").and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_u64().map(|v| v.to_string()))).unwrap_or_default();
    if sec.is_empty() || uid.parse::<u64>().ok().filter(|u| *u>0).is_none() || !seen.insert(sec.into()) { return; }
    let nick = item.get("nickname").and_then(Value::as_str).unwrap_or("好友");
    friends.push(DouyinFriend { uid,sec_uid:sec.into(),nickname:nick.into(),avatar_url:item.pointer("/avatar_thumb/url_list/0").and_then(Value::as_str).unwrap_or("").into(),
        spark_days:None,spark_desc:None,is_sparked_today:None,target_type:Some(1),conversation_id:None,remark_name:DouyinClient::parse_friend_remark(item,nick) });
}

fn validate_conversation(uid: u64, id: &str, kind: i32) -> Result<()> {
    anyhow::ensure!(uid>0,"未确认会话查询身份");
    if kind==2 { anyhow::ensure!(id.parse::<u64>().ok().filter(|v| *v>0).is_some(),"群聊会话 ID 无效"); }
    else {
        let p:Vec<_>=id.split(':').collect();
        anyhow::ensure!(kind==1 && p.len()==4 && p[0]=="0" && p[1]=="1","单聊会话格式无效");
        let a=p[2].parse::<u64>()?; let b=p[3].parse::<u64>()?;
        anyhow::ensure!(a>0 && a<b && (uid==a || uid==b),"会话不属于当前账号，禁止请求");
    }
    Ok(())
}

fn requires_security_verification(json: &Value) -> bool {
    [json.get("message"), json.get("status_msg"), json.get("description"),
        json.get("data").and_then(|data| data.get("description")),
        json.get("data").and_then(|data| data.get("message"))]
        .into_iter().flatten().filter_map(Value::as_str).any(|msg| {
            let msg = msg.to_ascii_lowercase();
            ["verify", "verification", "captcha", "验证", "风控"].iter().any(|word| msg.contains(word))
        })
}

pub(crate) fn is_fatal_send_error(code: i64, message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    matches!(code, 401 | 403 | 2154 | 2483)
        || ["http错误: 401", "http错误: 403", "错误码:401", "错误码:403", "错误码:2154", "错误码:2483"].iter().any(|word| msg.contains(word))
        || ["session", "auth", "cookie", "token", "passport", "login", "verify", "captcha", "conversation", "会话", "鉴权", "身份", "登录", "验证", "风控", "频繁", "禁止发送"]
            .iter().any(|word| msg.contains(word))
}

fn parse_im_send_response(data: &[u8]) -> (bool, i64, String, String) {
    if data.is_empty() || matches!(data.iter().copied().find(|b| !b.is_ascii_whitespace()), Some(b'{' | b'[' | b'<')) {
        return (false, -1, "IM 返回非 Protobuf 响应，发送鉴权未通过或需要安全验证；禁止发送重试".into(), String::new());
    }
    let fields = parse_protobuf_fields(data);
    let status = fields.iter().find(|(n, w, _)| *n == 3 && *w == 0)
        .and_then(|(_, _, b)| read_varint(b, 0)).map(|(v, _)| v as i32 as i64);
    let desc = fields.iter().find(|(n, w, _)| *n == 4 && *w == 2)
        .map(|(_, _, b)| String::from_utf8_lossy(b).to_string()).unwrap_or_default();
    let Some(status) = status else {
        return (false, -1, "IM 响应缺少有效状态字段，无法确认结果；禁止发送重试".into(), String::new());
    };
    let send = fields.iter().find(|(n, w, _)| *n == 6 && *w == 2)
        .and_then(|(_, _, body)| parse_protobuf_fields(body).into_iter().find(|(n, w, _)| *n == 100 && *w == 2))
        .map(|(_, _, b)| parse_protobuf_fields(&b)).unwrap_or_default();
    let int = |n| send.iter().find(|(num, w, _)| *num == n && *w == 0)
        .and_then(|(_, _, b)| read_varint(b, 0)).map(|(v, _)| v);
    let message_id = int(1).filter(|id| *id > 0).map(|id| id.to_string()).unwrap_or_default();
    let inner_status = int(3).unwrap_or(0);
    let check_code = int(5).unwrap_or(0);
    if status != 0 { return (false, status, desc, message_id); }
    if inner_status != 0 || check_code != 0 {
        return (false, inner_status.max(check_code) as i64, "IM 发送业务校验失败，需检查会话或安全验证；禁止发送重试".into(), message_id);
    }
    if message_id.is_empty() {
        return (false, -1, "IM 响应未确认消息 ID，发送结果未知；禁止发送重试".into(), message_id);
    }
    (true, 0, "OK".into(), message_id)
}

pub(crate) fn read_varint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        if shift == 63 && b > 1 { return None; }
        val |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some((val, pos));
        }
        shift += 7;
        if shift >= 64 { return None; }
    }
    None
}

fn encode_varint(mut n: u64, buf: &mut Vec<u8>) {
    while n > 0x7f {
        buf.push(((n & 0x7f) as u8) | 0x80);
        n >>= 7;
    }
    buf.push((n & 0x7f) as u8);
}

pub(crate) fn encode_field_varint(field_num: u32, val: u64, buf: &mut Vec<u8>) {
    let tag = (field_num << 3) | 0;
    encode_varint(tag as u64, buf);
    encode_varint(val, buf);
}

pub(crate) fn encode_field_bytes(field_num: u32, data: &[u8], buf: &mut Vec<u8>) {
    let tag = (field_num << 3) | 2;
    encode_varint(tag as u64, buf);
    encode_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}
fn parse_im_conversation_list_response(data: &[u8]) -> Result<HashMap<String, SparkConversationInfo>> {
    let mut map = HashMap::new();
    let envelope = parse_protobuf_fields(data);

    let resp_body_bytes = match envelope.into_iter().find(|(num, wire, _)| *num == 6 && *wire == 2) {
        Some((_, _, b)) => b,
        None => anyhow::bail!("IM 会话响应缺少内容"),
    };

    let body_fields = parse_protobuf_fields(&resp_body_bytes);
    let f610_bytes = match body_fields.into_iter().find(|(num, wire, _)| *num == 610 && *wire == 2) {
        Some((_, _, b)) => b,
        None => anyhow::bail!("IM 会话响应缺少查询结果"),
    };

    let list_fields = parse_protobuf_fields(&f610_bytes);
    anyhow::ensure!(f610_bytes.is_empty() || !list_fields.is_empty(),"IM 会话列表截断，保留原数据");
    let now = chrono::Utc::now().timestamp();

    for (l_num, l_wire, l_val) in list_fields {
        if l_num == 1 && l_wire == 2 {
            let conv_fields = parse_protobuf_fields(&l_val);
            anyhow::ensure!(!conv_fields.is_empty(),"IM 会话报文截断，保留原数据");
            anyhow::ensure!(conv_fields.iter().any(|(n,w,_)| *n==50 && *w==2),"IM 会话核心资料缺失，火花状态未知");
            let mut conv_id = String::new();
            let mut short_id = 0u64;
            let mut conv_name = None;
            let mut aliases: Vec<(u64, String)> = Vec::new();
            let mut core_ext = HashMap::new();

            for (c_num, c_wire, c_val) in conv_fields {
                if c_num == 1 && c_wire == 2 {
                    conv_id = String::from_utf8_lossy(&c_val).to_string();
                } else if c_num == 2 && c_wire == 0 {
                    short_id = read_varint(&c_val, 0).map(|(v, _)| v).unwrap_or(0);
                } else if c_num == 50 && c_wire == 2 {
                    let core_fields = parse_protobuf_fields(&c_val);
                    anyhow::ensure!(!core_fields.is_empty(),"IM 会话核心资料截断，火花状态未知");
                    if let Some((_, _, b)) = core_fields.iter().find(|(k, wire, _)| *k == 5 && *wire == 2) {
                        let n = String::from_utf8_lossy(b).trim().to_string();
                        if !n.is_empty() {
                            conv_name = Some(n);
                        }
                    }
                    for (cr_num, cr_wire, cr_val) in core_fields {
                        if cr_num == 11 && cr_wire == 2 {
                            let entry_fields = parse_protobuf_fields(&cr_val);
                            anyhow::ensure!(!entry_fields.is_empty(),"IM 会话扩展截断，火花状态未知");
                            let mut k = String::new();
                            let mut v = String::new();
                            for (e_num, e_wire, e_val) in entry_fields {
                                if e_num == 1 && e_wire == 2 {
                                    k = String::from_utf8_lossy(&e_val).to_string();
                                } else if e_num == 2 && e_wire == 2 {
                                    v = String::from_utf8_lossy(&e_val).to_string();
                                }
                            }
                            if !k.is_empty() {
                                core_ext.insert(k, v);
                            }
                        }
                    }
                } else if c_num == 6 && c_wire == 2 {
                    for (p_num, p_wire, p_val) in parse_protobuf_fields(&c_val) {
                        if p_num != 1 || p_wire != 2 {
                            continue;
                        }
                        let mut peer_uid = 0u64;
                        let mut alias = String::new();
                        for (f_num, f_wire, f_val) in parse_protobuf_fields(&p_val) {
                            if f_num == 1 && f_wire == 0 {
                                peer_uid = read_varint(&f_val, 0).map(|(v, _)| v).unwrap_or(0);
                            } else if f_num == 4 && f_wire == 2 {
                                alias = String::from_utf8_lossy(&f_val).trim().to_string();
                            }
                        }
                        if peer_uid > 0 && !alias.is_empty() {
                            aliases.push((peer_uid, alias));
                        }
                    }
                }
            }

            anyhow::ensure!(!conv_id.is_empty() && short_id>0,"IM 会话标识缺失，火花状态未知");

            if let Some(json_str) = core_ext.get("a:consecutive_chat_data") {
                let val:serde_json::Value=serde_json::from_str(json_str).context("官方火花数据格式异常，保留原状态")?;
                anyhow::ensure!(val.is_object(),"官方火花数据不是对象，保留原状态");
                {
                    let count = val.get("consecutive_count_info")
                        .and_then(|c| c.get("consecutive_count"))
                        .and_then(|n| n.as_i64())
                        .unwrap_or(0) as i32;

                    let up_ms = val.get("update_time_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                    let cst_offset = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
                    let today_cst = chrono::Utc::now().with_timezone(&cst_offset).date_naive();
                    let is_updated_today = if up_ms > 0 {
                        chrono::DateTime::from_timestamp(up_ms / 1000, 0)
                            .map(|dt| dt.with_timezone(&cst_offset).date_naive() == today_cst)
                            .unwrap_or(false)
                    } else {
                        false
                    };

                    let flames = val.get("flame_infos").and_then(|f| f.as_array());
                    let mut cur_flame = None;
                    if let Some(fl_list) = flames {
                        for fl in fl_list {
                            let start = fl.get("start").and_then(|s| s.as_i64()).unwrap_or(0);
                            let end = fl.get("end").and_then(|e| e.as_i64()).unwrap_or(0);
                            if start <= now && now <= end {
                                cur_flame = Some(fl);
                                break;
                            }
                        }
                        if cur_flame.is_none() && !fl_list.is_empty() {
                            cur_flame = Some(&fl_list[0]);
                        }
                    }

                    let state = cur_flame
                        .and_then(|f| f.get("state"))
                        .and_then(|s| s.as_i64())
                        .unwrap_or(4) as i32;

                    let level = cur_flame
                        .and_then(|f| f.get("level"))
                        .and_then(|l| l.as_str())
                        .unwrap_or("");

                    let real_days = cur_flame
                        .and_then(|f| f.get("real_days").or_else(|| f.get("days")))
                        .and_then(|d| d.as_i64())
                        .unwrap_or(count as i64) as i32;

                    let text = cur_flame
                        .and_then(|f| f.get("text"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let rec_d = cur_flame
                        .and_then(|f| f.get("recover_days"))
                        .and_then(|r| r.as_i64())
                        .unwrap_or(0) as i32;
                    let rec_need = cur_flame
                        .and_then(|f| f.get("recover_need_days"))
                        .and_then(|r| r.as_i64())
                        .unwrap_or(0) as i32;

                    let (days, desc) = if text.starts_with("重燃中") || state == 3 {
                        let d = if text.starts_with("重燃中") {
                            text.to_string()
                        } else if rec_need > 0 {
                            format!("重燃中 {rec_d}/{rec_need}")
                        } else {
                            "重燃中".to_string()
                        };
                        (real_days, d)
                    } else if real_days >= 3 {
                        (real_days, format!("已点亮 {real_days} 天"))
                    } else if real_days == 2 || count == 2 {
                        (2, "连续中 2/3".to_string())
                    } else if real_days == 1 || count == 1 {
                        (1, "连续中 1/3".to_string())
                    } else {
                        (0, "未点亮".to_string())
                    };

                    let is_sparked_today = if state == 1 {
                        true
                    } else if level.contains("gray") {
                        false
                    } else if level.contains("recover_normal") {
                        true
                    } else if is_updated_today && (real_days > 0 || count > 0) {
                        true
                    } else {
                        false
                    };

                    map.insert(conv_id, SparkConversationInfo { days, desc, is_sparked_today, short_id, conv_name, aliases: aliases.clone() });
                }
            } else {
                map.insert(conv_id, SparkConversationInfo { days: 0, desc: "未点亮".to_string(), is_sparked_today: false, short_id, conv_name, aliases: aliases.clone() });
            }
        }
    }

    Ok(map)
}

fn parse_im_check_my_message_today(data: &[u8], my_uid: u64) -> Result<bool> {
    parse_im_check_my_message_today_at(data, my_uid, chrono::Utc::now())
}

fn parse_im_check_my_message_today_at(data: &[u8], my_uid: u64, now: chrono::DateTime<chrono::Utc>) -> Result<bool> {
    let env = parse_protobuf_fields(data);
    let body_bytes = env.into_iter().find(|(k,wire,_)| *k==6 && *wire==2).context("IM 历史响应缺少内容")?.2;
    let f301_bytes = parse_protobuf_fields(&body_bytes).into_iter().find(|(k,wire,_)| *k==301 && *wire==2).context("IM 历史响应缺少查询结果")?.2;
    let resp_fields = parse_protobuf_fields(&f301_bytes);
    anyhow::ensure!(f301_bytes.is_empty() || !resp_fields.is_empty(),"消息历史报文不完整，今日发送情况未知");
    let has_more = resp_fields.iter().find(|(n,w,_)| *n==3 && *w==0).and_then(|(_,_,b)| read_varint(b,0)).is_some_and(|(v,_)| v!=0);
    let mut oldest = None;

    let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    let today_cst = now.with_timezone(&cst).date_naive();

    for (rk, rt, rv) in resp_fields {
        if rk == 1 && rt == 2 { // MessageBody
            let m_fields = parse_protobuf_fields(&rv);
            let sender = m_fields.iter().find(|(k,w,_)| *k==7 && *w==0).and_then(|(_,_,v)| read_varint(v,0).map(|(v,_)| v)).filter(|v| *v>0).context("消息发送者缺失，今日发送情况未知")?;
            let ctime = m_fields.iter().find(|(k,w,_)| *k==10 && *w==0).and_then(|(_,_,v)| read_varint(v,0).map(|(v,_)| v)).filter(|v| *v>0).context("消息时间缺失，今日发送情况未知")?;
            let ts=if ctime>10_000_000_000 {ctime/1000} else {ctime};
            anyhow::ensure!(i64::try_from(ts).ok().and_then(|ts| chrono::DateTime::from_timestamp(ts,0)).is_some(),"消息时间无效，今日发送情况未知");
            oldest=Some(oldest.map_or(ts,|old: u64| old.min(ts)));

            if sender == my_uid {
                let ts = if ctime > 10_000_000_000 { ctime / 1000 } else { ctime };
                if let Some(dt) = chrono::DateTime::from_timestamp(ts as i64, 0) {
                    if dt <= now && dt.with_timezone(&cst).date_naive() == today_cst {
                        return Ok(true);
                    }
                }
            }
        }
    }
    let day_start=today_cst.and_hms_opt(0,0,0).unwrap().and_local_timezone(cst).single().unwrap().timestamp() as u64;
    anyhow::ensure!(!has_more || oldest.is_some_and(|ts| ts<day_start),"今天的历史记录未读取完整，发送情况未知，禁止重复发送");
    Ok(false)
}

#[derive(Debug, Clone)]
pub struct DouyinTargetParam {
    pub conv_id: String,
    pub conv_type: i32,
    pub short_id: Option<u64>,
}

pub(crate) fn parse_protobuf_fields(data: &[u8]) -> Vec<(u32, u8, Vec<u8>)> {
    let mut pos = 0;
    let mut fields = Vec::new();
    while pos < data.len() {
        let (tag, new_pos) = match read_varint(data, pos) {
            Some(v) => v,
            None => return Vec::new(),
        };
        pos = new_pos;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        if field_num == 0 || tag >> 3 > 0x1fff_ffff { return Vec::new(); }
        match wire_type {
            0 => {
                let (val, new_pos) = match read_varint(data, pos) {
                    Some(v) => v,
                    None => return Vec::new(),
                };
                pos = new_pos;
                let mut b = Vec::new();
                encode_varint(val, &mut b);
                fields.push((field_num, wire_type, b));
            }
            2 => {
                let (len, new_pos) = match read_varint(data, pos) {
                    Some(v) => v,
                    None => return Vec::new(),
                };
                pos = new_pos;
                let Ok(len) = usize::try_from(len) else { return Vec::new(); };
                if len > data.len() - pos {
                    return Vec::new();
                }
                let bytes = data[pos..pos + len].to_vec();
                pos += len;
                fields.push((field_num, wire_type, bytes));
            }
            1 => {
                if data.len() - pos < 8 { return Vec::new(); }
                fields.push((field_num, wire_type, data[pos..pos+8].to_vec()));
                pos += 8;
            }
            5 => {
                if data.len() - pos < 4 { return Vec::new(); }
                fields.push((field_num, wire_type, data[pos..pos+4].to_vec()));
                pos += 4;
            }
            _ => return Vec::new(),
        }
    }
    fields
}


pub fn merge_cookies(old_cookie: &str, set_cookies: &[&str]) -> (String, bool) {
    let mut map: BTreeMap<String, String> = BTreeMap::new();

    for item in old_cookie.split(';') {
        let item = item.trim();
        if let Some((k, v)) = item.split_once('=') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if !key.is_empty() {
                map.insert(key, val);
            }
        }
    }

    let mut changed = false;

    // 核心会话鉴权 Key：严禁被服务端的注销指令、空值或假值冲掉
    const PROTECTED_KEYS: &[&str] = &[
        "sessionid",
        "sessionid_ss",
        "sid_tt",
        "sid_guard",
        "uid_tt",
        "uid_tt_ss",
        "passport_csrf_token",
    ];

    for sc in set_cookies {
        let sc_lower = sc.to_lowercase();
        // 检测是否是注销或失效指令
        let is_deletion = sc_lower.contains("max-age=0")
            || sc_lower.contains("expires=thu, 01 jan 1970")
            || sc_lower.contains("expires=wed, 31 dec 1969");

        if let Some(cookie_part) = sc.split(';').next() {
            if let Some((k, v)) = cookie_part.trim().split_once('=') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();

                if key.is_empty() {
                    continue;
                }

                // 保护核心会话令牌，若收到注销/空值则直接忽略该字段的覆盖
                if PROTECTED_KEYS.contains(&key.as_str()) {
                    if is_deletion || val.is_empty() || val == "\"\"" || val == "deleted" || val.len() < 10 {
                        tracing::warn!(key = %key, "忽略服务端的 Session 销毁/注销 Set-Cookie 指令，保留现有会话凭证");
                        continue;
                    }
                } else if is_deletion || val.is_empty() || val == "\"\"" || val == "deleted" {
                    continue;
                }

                if let Some(existing) = map.get(&key) {
                    if existing != &val {
                        map.insert(key, val);
                        changed = true;
                    }
                } else {
                    map.insert(key, val);
                    changed = true;
                }
            }
        }
    }

    let merged = map
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");

    (merged, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation_and_cookie_stripping() {
        let cookie_raw = " sessionid=abc123xyz;\r\n passport_csrf_token=def456; \n";
        let client = DouyinClient::new(cookie_raw, "test_account").expect("create client");
        assert_eq!(client.get_current_cookie(), "sessionid=abc123xyz; passport_csrf_token=def456;");
        assert_eq!(client.account_alias, "test_account");
    }

    #[test]
    fn test_parse_credential_full_nested_data_unpacking() {
        let inner_srv = r#"{"ticket":"hash.test","ts_sign":"ts.2.test","client_cert":"pub.test","create_time":1792147876}"#;
        let wrapped_srv = format!(r#"{{"data": "{}"}}"#, inner_srv.replace('"', r#"\""#));

        let raw_json = serde_json::json!({
            "cookie": "sessionid=test_session_123; passport_csrf_token=test_token",
            "guard_private_key": "0101010101010101010101010101010101010101010101010101010101010101",
            "guard_server_data": wrapped_srv,
            "uid": "123456",
            "nickname": "测试用户"
        }).to_string();

        let parsed = parse_credential_full(&raw_json);
        assert_eq!(parsed.uid.as_deref(), Some("123456"));
        assert_eq!(parsed.nickname.as_deref(), Some("测试用户"));
        let (priv_key, srv_data) = parsed.guard.expect("guard parsed");
        assert_eq!(priv_key, "0101010101010101010101010101010101010101010101010101010101010101");
        let srv_obj: serde_json::Value = serde_json::from_str(&srv_data).expect("valid json");
        assert_eq!(srv_obj["ticket"], "hash.test");
        assert_eq!(srv_obj["create_time"], 1792147876);
    }

    #[test]
    fn test_client_creation_and_cookie_stripping_base() {
        let cookie_raw = " sessionid=abc123xyz;\r\n passport_csrf_token=def456; \n";
        let client = DouyinClient::new(cookie_raw, "test_account").expect("create client");
        assert_eq!(client.get_current_cookie(), "sessionid=abc123xyz; passport_csrf_token=def456;");
        assert_eq!(client.account_alias, "test_account");
    }

    #[test]
    fn test_merge_set_cookies_renewal() {
        let old = "sessionid=old_session_123; passport_csrf_token=csrf_111; ttwid=tt_aaa";
        let set_cookies = [
            "sessionid=new_session_999; Path=/; Domain=.douyin.com; HttpOnly",
            "passport_csrf_token=csrf_111; Path=/",
            "odin_tt=odin_new_token; Path=/; Domain=.douyin.com",
        ];

        let (updated, changed) = merge_cookies(old, &set_cookies);
        assert!(changed);
        assert!(updated.contains("sessionid=new_session_999"));
        assert!(updated.contains("odin_tt=odin_new_token"));
        assert!(updated.contains("ttwid=tt_aaa"));
        assert!(updated.contains("ttwid=tt_aaa"));
    }

    #[test]
    fn test_merge_set_cookies_protects_sessionid() {
        let old = "sessionid=9825f78b25c7cea87ba30a6a4c8efd79; passport_csrf_token=csrf_111;";
        let malicious_set_cookies = [
            "sessionid=; Path=/; Domain=.douyin.com; Max-Age=0; HttpOnly",
            "passport_csrf_token=deleted; Max-Age=0",
            "some_new_tag=active_tag_123; Path=/",
        ];
        let (updated, changed) = merge_cookies(old, &malicious_set_cookies);
        assert!(changed);
        assert!(updated.contains("sessionid=9825f78b25c7cea87ba30a6a4c8efd79"));
        assert!(updated.contains("passport_csrf_token=csrf_111"));
        assert!(updated.contains("some_new_tag=active_tag_123"));
    }

    #[test]
    fn test_parse_friend_remark() {
        let same = serde_json::json!({"remark_name": "春风不语"});
        assert!(DouyinClient::parse_friend_remark(&same, "春风不语").is_none());
        let marked = serde_json::json!({"remark_name": "发小"});
        assert_eq!(DouyinClient::parse_friend_remark(&marked, "春风不语").as_deref(), Some("发小"));
        let alias = serde_json::json!({"alias": "老同学"});
        assert_eq!(DouyinClient::parse_friend_remark(&alias, "春风不语").as_deref(), Some("老同学"));
    }

}

#[cfg(test)]
mod send_identity_tests {
    use super::*;

    fn confirmed_client(cookie: &str) -> DouyinClient {
        let client = DouyinClient::new(cookie, "12345678").unwrap();
        assert!(client.confirm_profile(DouyinUserProfile {
            uid: "99191692311".into(), sec_uid: "sender_sec".into(),
            nickname: "12345678".into(), avatar_url: String::new(),
        }).is_valid());
        client
    }

    fn bytes_field(data: &[u8], field: u32) -> Vec<u8> {
        parse_protobuf_fields(data).into_iter().find(|(f, w, _)| *f == field && *w == 2).unwrap().2
    }

    fn varint_field(data: &[u8], field: u32) -> u64 {
        let value = parse_protobuf_fields(data).into_iter().find(|(f, w, _)| *f == field && *w == 0).unwrap().2;
        read_varint(&value, 0).unwrap().0
    }
    #[test]
    fn send_path_is_checked_before_consuming_credential() {
        let cookie="sessionid=offline-path-binding";
        let client=confirmed_client(cookie);
        client.set_send_credential(super::super::im_auth::test_credential(cookie,"0:1:55696816245:99191692311",1)).unwrap();
        for url in ["https://imapi.douyin.com/v1/message/get_by_conversation","https://imapi.douyin.com/v1/message/send?x=1"] {
            assert!(client.build_send_request(url,99191692311,None,1,"recipient",55696816245,"offline").is_err());
            assert!(client.send_credential.lock().unwrap().is_some());
        }
        assert!(client.build_send_request("https://imapi.douyin.com/v1/message/send",99191692311,None,1,"recipient",55696816245,"offline").is_ok());
        assert!(client.send_credential.lock().unwrap().is_none());
        assert!(client.build_send_request("https://imapi.douyin.com/v1/message/send",99191692311,None,1,"recipient",55696816245,"offline").is_err());
    }


    #[test]
    fn actual_send_request_uses_confirmed_identity_and_session_auth() {
        for cookie in ["sessionid=test_session", "sessionid=test_session; user_uid=55696816245"] {
            let client = confirmed_client(cookie);
            client.set_send_credential(super::super::im_auth::test_credential(cookie, "0:1:55696816245:99191692311", 1)).unwrap();
            assert_eq!(client.verified_sender_uid(Some("99191692311")).unwrap(), 99191692311);
            let request = client.build_send_request(
                "https://imapi.douyin.com/v1/message/send", 99191692311,
                Some("0:1:55696816245:99191692311"), 1, "recipient_sec", 55696816245, "test",
            ).unwrap();
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(request.url().as_str(), "https://imapi.douyin.com/v1/message/send");
            let envelope = request.body().unwrap().as_bytes().unwrap();
            assert_eq!(varint_field(envelope, 1), 100);
            assert_eq!(varint_field(envelope, 18), 1);
            let body = bytes_field(envelope, 8);
            let send = bytes_field(&body, 100);
            assert_eq!(bytes_field(&send, 1), b"0:1:55696816245:99191692311");
            assert_eq!(varint_field(&send, 2), 1);
            assert_eq!(varint_field(&send, 3), 7300427740086387237);
            assert_eq!(bytes_field(&send, 7), b"test-conversation-ticket");
            assert_eq!(request.headers()["origin"], "https://www.douyin.com");
            assert_eq!(request.headers()["sec-fetch-site"], "same-site");
            assert_eq!(request.headers()["user-agent"], "TestBrowser/155");
            assert!(request.headers().contains_key("bd-ticket-guard-client-data"));
            assert!(client.build_send_request("http://127.0.0.1:1", 99191692311, None, 1, "recipient_sec", 55696816245, "test").is_err());
        }
    }

    #[tokio::test]
    async fn missing_sender_fails_before_http_send_even_with_cookie_uid() {
        let client = DouyinClient::new("sessionid=test; user_uid=99191692311", "12345678").unwrap();
        let result = client.send_spark_message(None, 1, "recipient", Some("55696816245"), "test").await;
        assert!(!result.success);
        assert!(result.message.contains("禁止发送"));
        assert!(client.verified_sender_uid(Some("99191692311")).is_err());
        assert!(client.build_send_request("http://127.0.0.1:1", 99191692311, None, 1, "recipient", 55696816245, "test").is_err());
    }

    #[test]
    fn mismatched_identity_or_conversation_is_rejected() {
        let client = confirmed_client("sessionid=identity-mismatch-offline");
        assert!(client.verified_sender_uid(Some("55696816245")).is_err());
        for expected in ["", "0", "invalid"] {
            assert!(client.verified_sender_uid(Some(expected)).is_err());
        }
        for (sender, target, conv) in [(55696816245, 55696816245, None), (99191692311, 0, None), (99191692311, 55696816245, Some("0:1:55696816245:55696816245"))] {
            assert!(client.build_send_request("http://127.0.0.1:1", sender, conv, 1, "recipient", target, "test").is_err());
        }
    }

    #[test]
    fn group_send_keeps_group_identity_and_session_auth() {
        let client = confirmed_client("sessionid=test");
        client.set_send_credential(super::super::im_auth::test_credential("sessionid=test", "7635702399042159110", 2)).unwrap();
        let request = client.build_send_request("https://imapi.douyin.com/v1/message/send", 99191692311, Some("7635702399042159110"), 2, "group", 0, "test").unwrap();
        let envelope = request.body().unwrap().as_bytes().unwrap();
        assert_eq!(varint_field(envelope, 18), 1);
        let send = bytes_field(&bytes_field(envelope, 8), 100);
        assert_eq!(varint_field(&send, 2), 2);
        assert_eq!(varint_field(&send, 3), 7635702399042159110);
    }

    #[tokio::test]
    async fn fatal_session_blocks_subsequent_send_before_http() {
        let client = confirmed_client("sessionid=test");
        assert!(is_fatal_send_error(1, "unexepcted session length"));
        client.send_blocked.store(true, Ordering::Relaxed);
        let result = client.send_spark_message(None, 1, "recipient", Some("55696816245"), "test").await;
        assert!(!result.success);
        assert!(result.is_fatal_failure());
    }

    #[test]
    fn send_success_requires_success_code_and_message_id() {
        let mut response = Vec::new();
        encode_field_varint(3, 0, &mut response);
        assert!(!parse_im_send_response(&response).0);
        let mut send = Vec::new();
        encode_field_varint(1, 123456, &mut send);
        let mut body = Vec::new();
        encode_field_bytes(100, &send, &mut body);
        encode_field_bytes(6, &body, &mut response);
        assert!(parse_im_send_response(&response).0);
        assert_eq!(parse_im_send_response(&response).3, "123456");
    }

    #[test]
    fn unconfirmed_or_malformed_send_responses_are_fatal() {
        for data in [b"".as_slice(), b"{\"status_code\":0}", b"<html>verify</html>", &[0x18, 0, 0x32, 0xff], &[0x18, 0, 0], &[0x18, 0, 0x80]] {
            let (ok, code, message, _) = parse_im_send_response(data);
            assert!(!ok);
            assert!(is_fatal_send_error(code, &message));
        }
        assert!(read_varint(&[0xff; 11], 0).is_none());
        assert!(read_varint(&[0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02], 0).is_none());
    }

    fn response_with_inner_status(inner: u64, check: u64) -> Vec<u8> {
        let mut send = Vec::new();
        encode_field_varint(1, 123456, &mut send);
        encode_field_varint(3, inner, &mut send);
        encode_field_varint(5, check, &mut send);
        let mut body = Vec::new();
        encode_field_bytes(100, &send, &mut body);
        let mut response = vec![0x51, 0, 0, 0, 0, 0, 0, 0, 0, 0x5d, 0, 0, 0, 0];
        encode_field_varint(3, 0, &mut response);
        encode_field_bytes(6, &body, &mut response);
        response
    }

    #[test]
    fn fixed_width_fields_do_not_hide_inner_business_failure() {
        assert!(parse_im_send_response(&response_with_inner_status(0, 0)).0);
        for (inner, check) in [(1, 0), (0, 2154)] {
            let (ok, code, message, _) = parse_im_send_response(&response_with_inner_status(inner, check));
            assert!(!ok);
            assert!(is_fatal_send_error(code, &message));
        }
        let mut truncated = response_with_inner_status(0, 0);
        truncated.push(0x80);
        assert!(!parse_im_send_response(&truncated).0);
    }

    #[tokio::test]
    async fn missing_credential_fails_before_network() {
        let client = confirmed_client("sessionid=test");
        let result = client.send_spark_message(None, 1, "recipient", Some("55696816245"), "test").await;
        assert!(!result.success);
        assert!(result.message.contains("缺少官方 IM"));
        assert!(result.is_fatal_failure());
    }
}

#[cfg(test)]
mod safety_check_tests {
    use super::*;

    #[test]
    fn safety_verification_is_a_blocker() {
        for value in [serde_json::json!({"message":"need verification"}), serde_json::json!({"data":{"description":"请完成安全验证"}}), serde_json::json!({"status_msg":"captcha required"})] {
            assert!(requires_security_verification(&value));
        }
        assert!(!requires_security_verification(&serde_json::json!({"message":"success"})));
    }

    #[test]
    fn invalid_confirmed_uid_does_not_enable_sending() {
        let client = DouyinClient::new("sessionid=test", "12345678").unwrap();
        for uid in ["0", "", "invalid"] {
            assert!(!client.confirm_profile(DouyinUserProfile { uid: uid.into(), sec_uid: "sec".into(), nickname: "12345678".into(), avatar_url: String::new() }).is_valid());
            assert!(client.verified_sender_uid(Some("99191692311")).is_err());
        }
    }
}

#[cfg(test)]
mod history_and_cookie_tests {
    use super::*;
    fn history(messages: &[(Option<u64>,Option<u64>)], cursor: u64, more: bool) -> Vec<u8> {
        let mut payload=Vec::new();
        for (uid,time) in messages {
            let mut message=Vec::new();
            if let Some(uid)=uid { encode_field_varint(7,*uid,&mut message); }
            if let Some(time)=time { encode_field_varint(10,*time,&mut message); }
            encode_field_bytes(1,&message,&mut payload);
        }
        encode_field_varint(2,cursor,&mut payload);
        encode_field_varint(3,u64::from(more),&mut payload);
        wrap(&payload)
    }
    fn wrap(payload:&[u8])->Vec<u8> {
        let mut body=Vec::new(); encode_field_bytes(301,payload,&mut body);
        let mut env=Vec::new(); encode_field_bytes(6,&body,&mut env); env
    }
    #[test]
    fn history_cursor_is_not_has_more_and_incoming_is_not_outgoing() {
        let now=chrono::Utc::now().timestamp() as u64;
        assert!(!parse_im_check_my_message_today(&history(&[(Some(2),Some(now))],999,false),1).unwrap());
        assert!(parse_im_check_my_message_today(&history(&[(Some(1),Some(now*1000))],999,true),1).unwrap());
        assert!(parse_im_check_my_message_today(&history(&[(Some(2),Some(now))],0,true),1).is_err());
        assert!(!parse_im_check_my_message_today(&history(&[(Some(2),Some(now-2*86400))],999,true),1).unwrap());
        assert!(parse_im_check_my_message_today(&history(&[],999,true),1).is_err());
        assert!(!parse_im_check_my_message_today(&history(&[],999,false),1).unwrap());
    }
    #[test]
    fn malformed_or_incomplete_history_never_means_not_sent() {
        let now=chrono::Utc::now().timestamp() as u64;
        for bytes in [history(&[(None,Some(now))],0,false),history(&[(Some(2),None)],0,false),history(&[(Some(2),Some(u64::MAX))],0,false),wrap(&[0x80]),vec![]] {
            assert!(parse_im_check_my_message_today(&bytes,1).is_err());
        }
    }
    #[test]
    fn history_uses_cst_midnight_and_only_the_current_sender() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-15T00:00:01+08:00").unwrap().with_timezone(&chrono::Utc);
        let midnight = (now.timestamp() - 1) as u64;
        for scale in [1, 1000] {
            assert!(!parse_im_check_my_message_today_at(&history(&[(Some(1),Some((midnight-1)*scale))],0,false),1,now).unwrap());
            assert!(parse_im_check_my_message_today_at(&history(&[(Some(1),Some(midnight*scale))],0,false),1,now).unwrap());
            assert!(!parse_im_check_my_message_today_at(&history(&[(Some(2),Some(midnight*scale))],0,false),1,now).unwrap());
        }
    }
    #[test]
    fn cookie_intake_handles_chrome_curl_and_quoted_cookie_flags() {
        for raw in ["curl 'https://www.douyin.com/' -H 'cookie: sessionid=offline; x=a=b' -H 'accept: */*'", "curl --header \"Cookie: sessionid=offline; x=a=b\"", "curl -b 'sessionid=offline; x=a=b'", "curl --cookie \"sessionid=offline; x=a=b\"", "sessionid=offline; x=a=b"] {
            assert_eq!(extract_clean_cookie(raw),"sessionid=offline; x=a=b");
        }
        let id="a".repeat(32);
        assert_eq!(extract_clean_cookie(&id),format!("sessionid={id}; sessionid_ss={id}; sid_tt={id}"));
    }
}

#[cfg(test)]
mod conversation_response_tests {
    use super::*;
    fn response(core: &[u8])->Vec<u8> {
        let mut conv=Vec::new();encode_field_bytes(1,b"0:1:1:2",&mut conv);encode_field_varint(2,123,&mut conv);encode_field_bytes(50,core,&mut conv);
        let mut list=Vec::new();encode_field_bytes(1,&conv,&mut list);
        let mut body=Vec::new();encode_field_bytes(610,&list,&mut body);
        let mut env=Vec::new();encode_field_bytes(6,&body,&mut env);env
    }
    #[test]
    fn malformed_core_or_spark_data_preserves_unknown_state() {
        for core in [vec![],vec![0x80]] { assert!(parse_im_conversation_list_response(&response(&core)).is_err()); }
        let mut entry=Vec::new();encode_field_bytes(1,b"a:consecutive_chat_data",&mut entry);encode_field_bytes(2,b"not-json",&mut entry);
        let mut core=Vec::new();encode_field_bytes(11,&entry,&mut core);
        assert!(parse_im_conversation_list_response(&response(&core)).is_err());
        assert!(parse_im_conversation_list_response(&[]).is_err());
        let mut valid_core=Vec::new();encode_field_bytes(5,b"test-conversation",&mut valid_core);
        let map=parse_im_conversation_list_response(&response(&valid_core)).unwrap();
        assert_eq!(map["0:1:1:2"].days,0);
        assert_eq!(map["0:1:1:2"].short_id,123);
    }
}

#[cfg(test)]
mod im_session_tests {
    use super::*;
    #[tokio::test]
    async fn identity_persistence_is_encrypted_account_bound_and_compare_and_swap() {
        let pool=crate::db::init_pool("sqlite::memory:").await.unwrap();
        let secret=crate::crypto::SecretBox::new(&[42;32]);
        let cookie="sessionid=PUBLIC-CAS-SESSION";
        let encrypted=secret.encrypt(cookie.as_bytes()).unwrap();
        let now=chrono::Utc::now();
        for id in ["selected","other"] {
            crate::db::insert_account(&pool,&crate::model::Account {
                id:id.into(),alias:id.into(),uid:Some("99191692311".into()),sec_uid:None,nickname:None,avatar_url:None,
                encrypted_cookie:encrypted.clone(),status:"ACTIVE".into(),bark_key_override:None,last_checked_at:None,created_at:now,updated_at:now,
            }).await.unwrap();
        }
        let client=DouyinClient::new(cookie,"public-test").unwrap();
        let profile=DouyinUserProfile{uid:"99191692311".into(),sec_uid:"public".into(),nickname:"public".into(),avatar_url:"".into()};
        assert!(client.confirm_profile(profile).is_valid());
        assert_eq!(client.im_history_status(Some("99191692311")).0,"AVAILABLE");
        assert!(client.send_credential.lock().unwrap().is_none());
        let context=super::super::im_auth::WebSessionContext::from_session(99191692311,cookie,"Test/1").unwrap()
            .with_identity(&serde_json::json!({"message":"success","data":{"identity_security_token":"PUBLIC-CAS-TOKEN","device_id":"PUBLIC-DEVICE"}})).unwrap();
        client.set_web_context(context).unwrap();
        let other=crate::db::get_account(&pool,"other").await.unwrap().unwrap();
        client.persist_im_session(&pool,&secret,"selected",&encrypted,Some("99191692311")).await.unwrap();
        assert_eq!(crate::db::get_account(&pool,"other").await.unwrap().unwrap().encrypted_cookie,other.encrypted_cookie);
        let stored:Vec<u8>=sqlx::query_scalar("SELECT encrypted_context FROM account_web_contexts WHERE account_id='selected'").fetch_one(&pool).await.unwrap();
        assert!(!stored.windows(b"PUBLIC-CAS-TOKEN".len()).any(|w|w==b"PUBLIC-CAS-TOKEN"));
        let decoded:super::super::im_auth::WebSessionContext=serde_json::from_slice(&secret.decrypt(&stored).unwrap()).unwrap();
        assert!(decoded.has_identity());
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM account_im_credentials").fetch_one(&pool).await.unwrap(),0);
        assert!(client.persist_im_session(&pool,&secret,"selected",&encrypted,Some("99191692311")).await.is_err());
        assert_eq!(sqlx::query_scalar::<_,Vec<u8>>("SELECT encrypted_context FROM account_web_contexts WHERE account_id='selected'").fetch_one(&pool).await.unwrap(),stored);
        assert!(client.acquire_im_identity(Some("1")).await.is_err());
    }
}

#[cfg(test)]
#[path = "im_identity_tests.rs"]
mod im_identity_tests;

#[path = "session_auth.rs"]
pub mod session_auth;

#[path = "browser_session.rs"]
pub mod browser_session;
