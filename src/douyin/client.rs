use anyhow::{Context, Result};
use base64::Engine;
use reqwest::{Client, Method, header};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use super::types::{
    CheckCookieResult, DouyinFriend, DouyinUserProfile, SendSparkResult, SparkConversationInfo,
};

#[path = "web.rs"]
mod web;

pub struct DouyinClient {
    client: Client,
    device: super::device_profile::DeviceProfile,
    current_cookie: Arc<Mutex<String>>,
    cookie_changed: Arc<Mutex<bool>>,
    risk_limited: Arc<AtomicBool>,
    verified_uid: Mutex<Option<u64>>,
    send_blocked: AtomicBool,
    send_credential: Mutex<Option<super::im_auth::ImSendCredential>>,
    web_context: Mutex<Option<super::im_auth::WebSessionContext>>,
    pub account_alias: String,
    send_claim: Mutex<Option<(sqlx::SqlitePool, String, String, Vec<u8>)>>,
    send_history: Mutex<HashMap<String, (u64, i32, chrono::NaiveDate, bool)>>,
    pcim_initial: Mutex<Option<session_auth::pcim_init::InitialBinding>>,
    trusted_time: Mutex<Option<crate::douyin::sdk_time::TrustedTimeAnchor>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityBeatStatus {
    Refreshed,
    MissingContext,
    MissingIdentity,
    MissingGuardMaterial,
}

/// 清洗内部传递的 Cookie 字符串，去掉换行与首尾空白。
pub fn extract_clean_cookie(raw: &str) -> String {
    raw.trim().replace(['\n', '\r'], "")
}
impl DouyinClient {
    /// 离线与测试用的临时客户端：指纹由账号别名派生，不写入任何账号。
    /// 生产路径必须使用 [`DouyinClient::with_device_profile`] 传入账号持久化的指纹。
    pub fn new(cookie: &str, account_alias: &str) -> Result<Self> {
        Self::with_device_profile(
            cookie,
            account_alias,
            super::device_profile::DeviceProfile::derive(account_alias),
        )
    }

    /// 生产构造入口：账号独占设备指纹必须由调用方从账号存储读取后传入。
    pub fn with_device_profile(
        cookie: &str,
        account_alias: &str,
        device: super::device_profile::DeviceProfile,
    ) -> Result<Self> {
        device.validate()?;
        let cookie_clean = extract_clean_cookie(cookie);
        let client = Self::build_http_client(&device)?;

        Ok(Self {
            client,
            device,
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
            trusted_time: Mutex::new(None),
        })
    }

    /// 生产统一入口：从账号存储读取（或首次派生）独占指纹后构造客户端。
    /// 任何携带账号凭证的请求都必须走这里，禁止回退到共享默认指纹。
    pub async fn for_account(
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
        cookie: &str,
        account_alias: &str,
    ) -> Result<Self> {
        let device = crate::db::load_or_create_device_profile(pool, secret, account_id).await?;
        Self::with_device_profile(cookie, account_alias, device)
    }

    fn build_http_client(device: &super::device_profile::DeviceProfile) -> Result<Client> {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&device.user_agent).context("设备指纹 UA 无效")?,
        );
        headers.insert(
            header::REFERER,
            header::HeaderValue::from_static(device.referer_origin()),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json, text/plain, */*"),
        );
        headers.insert(
            header::ACCEPT_LANGUAGE,
            header::HeaderValue::from_str(&device.accept_language)
                .context("设备指纹 accept-language 无效")?,
        );
        headers.insert("sec-fetch-dest", header::HeaderValue::from_static("empty"));
        headers.insert("sec-fetch-mode", header::HeaderValue::from_static("cors"));
        headers.insert(
            "sec-fetch-site",
            header::HeaderValue::from_static("same-origin"),
        );
        headers.insert(
            "sec-ch-ua",
            header::HeaderValue::from_str(&device.sec_ch_ua).context("设备指纹 sec-ch-ua 无效")?,
        );
        headers.insert(
            "sec-ch-ua-mobile",
            header::HeaderValue::from_str(&device.sec_ch_ua_mobile)
                .context("设备指纹 sec-ch-ua-mobile 无效")?,
        );
        headers.insert(
            "sec-ch-ua-platform",
            header::HeaderValue::from_str(&device.sec_ch_ua_platform)
                .context("设备指纹 sec-ch-ua-platform 无效")?,
        );

        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none());

        if let Ok(proxy_val) = std::env::var("SPARK_PROXY").or_else(|_| std::env::var("HTTP_PROXY"))
        {
            if let Ok(p) = reqwest::Proxy::all(&proxy_val) {
                builder = builder.proxy(p);
            }
        }

        builder
            .build()
            .context("failed to build isolated reqwest client")
    }

    /// 当前账号独占的设备指纹；只读。
    pub fn device(&self) -> &super::device_profile::DeviceProfile {
        &self.device
    }

    /// 当前 IM 上下文快照；不持有锁，调用方可安全地在异步边界之间使用。
    pub fn web_context_snapshot(&self) -> Option<super::im_auth::WebSessionContext> {
        self.web_context.lock().unwrap().clone()
    }

    pub fn get_current_cookie(&self) -> String {
        self.current_cookie.lock().unwrap().clone()
    }

    pub fn is_cookie_changed(&self) -> bool {
        *self.cookie_changed.lock().unwrap()
    }

    /// 修复历史版本遗留的 Guard Cookie 分叉。只使用已保存且与当前密钥、账号绑定的材料，
    /// 不生成新密钥，也不发起网络请求。
    pub fn repair_bound_guard_cookie(&self) -> Result<bool> {
        let cookie = self.get_current_cookie();
        let (key, material) = {
            let context = self.web_context.lock().unwrap();
            let Some(ctx) = context.as_ref() else {
                return Ok(false);
            };
            let Some(key) = ctx.get_guard_key()? else {
                return Ok(false);
            };
            let Some(material) = ctx.get_guard_material(&key, &cookie)? else {
                return Ok(false);
            };
            (key, material)
        };
        let aligned = super::pcim_guard::align_guard_cookie(
            &cookie,
            &key.public_key_base64(),
            Some(&material),
        )?;
        if aligned == cookie {
            return Ok(false);
        }
        let unchanged_session =
            super::im_auth::session_hash(&aligned)? == super::im_auth::session_hash(&cookie)?;
        anyhow::ensure!(unchanged_session, "Guard Cookie 对齐不得改变登录会话");
        *self.current_cookie.lock().unwrap() = aligned;
        *self.cookie_changed.lock().unwrap() = true;
        Ok(true)
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
        let uid = uid.unwrap();
        // 只读 SESSION_AUTH：仅在尚未初始化会话上下文时建立初始骨架；已有上下文严禁重建冲刷
        let needs_init = self.web_context.lock().unwrap().is_none();
        if needs_init {
            match super::im_auth::WebSessionContext::from_session_with_device(
                uid,
                &self.get_current_cookie(),
                &self.device.user_agent,
                Some(self.device.clone()),
            ) {
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
        let confirmed = self
            .verified_uid
            .lock()
            .unwrap()
            .context("未确认当前 Cookie 的发送身份，禁止发送")?;
        if let Some(expected) = expected_uid {
            let expected = expected
                .parse::<u64>()
                .ok()
                .filter(|uid| *uid > 0)
                .context("账号 UID 无效，禁止发送")?;
            if expected != confirmed {
                self.stop_requests(web::FailureKind::Expired);
                anyhow::bail!("当前 Cookie 身份与所属账号不符，禁止发送");
            }
        }
        Ok(confirmed)
    }

    pub fn set_send_credential(&self, credential: super::im_auth::ImSendCredential) -> Result<()> {
        let current = self.web_context.lock().unwrap().clone();
        if let Some(context) = current.as_ref().filter(|c| c.has_identity()) {
            credential.validate_identity_binding(
                context,
                credential.uid,
                &self.get_current_cookie(),
            )?;
        } else {
            self.set_web_context(super::im_auth::WebSessionContext::from_credential(
                &credential,
            ))?;
        }
        anyhow::ensure!(
            credential.session_hash == super::im_auth::session_hash(&self.get_current_cookie())?,
            "IM 凭证与当前 Cookie 不符，禁止发送"
        );
        *self.send_credential.lock().unwrap() = Some(credential);
        Ok(())
    }

    pub fn set_web_context(&self, mut context: super::im_auth::WebSessionContext) -> Result<()> {
        if context.adopt_device(&self.device) {
            tracing::info!(
                account = %self.account_alias,
                device = %self.device.device_tag,
                "已把账号独占设备指纹绑定到 IM 上下文；如指纹变化则同时作废旧身份 Token"
            );
        }
        context.validate_session(context.uid, &self.get_current_cookie())?;
        let mut guard = self.web_context.lock().unwrap();
        if let Some(old) = guard.as_ref() {
            context.inherit_guard_materials(old);
        }
        *guard = Some(context);
        Ok(())
    }

    pub async fn load_web_context(
        &self,
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
        uid: Option<&str>,
    ) -> Result<()> {
        let encrypted: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
        )
        .bind(account_id)
        .fetch_optional(pool)
        .await?;
        if let Some((encrypted,)) = encrypted {
            let mut context: super::im_auth::WebSessionContext =
                serde_json::from_slice(&secret.decrypt(&encrypted)?)
                    .context("Web 上下文解码失败")?;
            if context.session_hash == super::im_auth::session_hash(&self.get_current_cookie())? {
                anyhow::ensure!(
                    uid == Some(context.uid.to_string().as_str()),
                    "账号 Web 上下文身份不符"
                );
                self.set_web_context(context)?;
            } else if context.has_identity()
                && uid.and_then(|u| u.parse::<u64>().ok()).filter(|u| *u > 0) == Some(context.uid)
                && context.rebind_session(&self.get_current_cookie())?
            {
                // 会话 Cookie 轮换但账号身份未变：官方身份 Token 属于账号而非单次 sessionid，
                // 必须沿用并重新绑定当前会话哈希，否则下一次巡检会用无身份上下文覆盖库内凭证，
                // 导致账号必须反复人工重新采集。
                tracing::info!(account_id = %account_id, uid = context.uid, "检测到会话 Cookie 轮换，已沿用库内官方 IM 身份 Token 并重新绑定当前会话");
                self.set_web_context(context)?;
            }
        }
        Ok(())
    }

    pub fn im_history_status(&self, uid: Option<&str>) -> (&'static str, Option<i64>) {
        self.web_context
            .lock()
            .unwrap()
            .as_ref()
            .map_or(("MISSING", None), |context| {
                context.history_status(
                    uid,
                    &self.get_current_cookie(),
                    chrono::Utc::now().timestamp(),
                )
            })
    }

    /// 获取官方服务端授信单调时间戳；如无有效锚点则自动从官方端点拉取。
    pub async fn get_trusted_timestamp(&self, uid: u64) -> Result<i64> {
        let cookie = self.get_current_cookie();
        {
            let lock = self.trusted_time.lock().unwrap();
            if let Some(anchor) = lock.as_ref() {
                if let Ok(ts) = anchor.timestamp(uid, &cookie) {
                    return Ok(ts);
                }
            }
        }
        self.fetch_trusted_time(uid).await
    }

    /// 从官方 Passport 授信时间端点拉取最新时间锚点
    pub async fn fetch_trusted_time(&self, uid: u64) -> Result<i64> {
        // 离线响应队列无法伪造 bd-ticket-guard-ts，测试中禁止真实出网，保持确定性回退路径。
        #[cfg(test)]
        if im_identity_tests::active() {
            anyhow::bail!("离线测试禁用真实授信时间请求");
        }
        let cookie = self.get_current_cookie();
        let url_str =
            "https://www.douyin.com/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1";
        let url = reqwest::Url::parse(url_str)?;
        let request = self
            .web_request_allow_probe(Method::POST, url_str)?
            .header("accept", "application/json, text/plain, */*")
            .header("content-length", "0");
        let started = std::time::Instant::now();
        let response = self.client.execute(request.build()?).await?;
        let received = std::time::Instant::now();
        let received_wall = std::time::SystemTime::now();
        let status = response.status();
        let headers = response.headers().clone();
        self.merge_response_headers(&headers);

        let anchor = crate::douyin::sdk_time::TrustedTimeAnchor::from_response(
            uid,
            &cookie,
            &url,
            &Method::POST,
            status,
            &headers,
            started,
            received,
            received_wall,
        )?;
        let ts = anchor.timestamp(uid, &cookie)?;
        *self.trusted_time.lock().unwrap() = Some(anchor);
        tracing::debug!(uid = uid, ts = ts, "已获取官方授信时间锚点");
        Ok(ts)
    }

    /// 独立获取官方身份 Token；不生成发送签名或一次性发送授权。
    pub async fn acquire_im_identity(&self, expected_uid: Option<&str>) -> Result<()> {
        let uid = self.verified_sender_uid(expected_uid)?;
        let cookie = self.get_current_cookie();
        let now = chrono::Utc::now().timestamp();
        let existing_ctx = self.web_context.lock().unwrap().clone();
        if let Some(ctx) = existing_ctx {
            // 只有服务端真正返回过新 Token，才能延长身份有效期。
            // 不能把旧上下文的时间戳改成当前时间，否则 Token 已老化仍会被当成新凭证。
            let identity_age = ctx.identity_acquired_at.and_then(|at| now.checked_sub(at));
            if ctx.validate_session(uid, &cookie).is_ok()
                && ctx.has_identity()
                && identity_age.is_some_and(|age| {
                    (0..super::im_auth::IDENTITY_REFRESH_AGE_SECS).contains(&age)
                })
            {
                return Ok(());
            }
        }
        let biz_trace_id = format!("{:08x}", rand::random::<u32>());
        let ms_token = self.extract_cookie_val("msToken").unwrap_or_else(|| {
            use rand::Rng;
            const CHARSET: &[u8] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
            let mut rng = rand::thread_rng();
            (0..176)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect()
        });
        let request = self
            .web_request(
                Method::GET,
                "https://www.douyin.com/passport/safe/get_identity_security_token/",
            )?
            .query(&[
                ("aid", "6383"),
                ("scene", "web_im"),
                ("auto_retry_req", "0"),
                ("skip_verify", "false"),
                ("identity_token_force_get_tag", "0"),
                ("biz_trace_id", &biz_trace_id),
                ("id_token_version", "1.2.10"),
                ("passport_jssdk_version", "4.2.3"),
                ("passport_jssdk_type", "lite"),
                ("is_from_ttaccountsdk", "1"),
                ("language", "zh"),
                ("msToken", &ms_token),
            ])
            .header(
                "x-tt-passport-csrf-token",
                self.extract_cookie_val("passport_csrf_token")
                    .or_else(|| self.extract_cookie_val("passport_csrf_token_default"))
                    .unwrap_or_default(),
            )
            .header("x-tt-passport-trace-id", &biz_trace_id)
            .header("sec-ch-ua", &self.device.sec_ch_ua)
            .header("sec-ch-ua-mobile", &self.device.sec_ch_ua_mobile)
            .header("sec-ch-ua-platform", &self.device.sec_ch_ua_platform)
            .header("accept", "application/json, text/javascript");
        let response = self.web_json(request).await?;
        let old_ctx = self.web_context.lock().unwrap().clone();
        let mut context = match old_ctx {
            Some(c) if c.validate_session(uid, &cookie).is_ok() => c.with_identity(&response)?,
            Some(old) => {
                let mut fresh = super::im_auth::WebSessionContext::from_session_with_device(
                    uid,
                    &cookie,
                    &self.device.user_agent,
                    Some(self.device.clone()),
                )?
                .with_identity(&response)?;
                fresh.inherit_guard_materials(&old);
                fresh
            }
            None => super::im_auth::WebSessionContext::from_session_with_device(
                uid,
                &cookie,
                &self.device.user_agent,
                Some(self.device.clone()),
            )?
            .with_identity(&response)?,
        };
        context.identity_acquired_at = Some(now);
        context.captured_at = now;
        anyhow::ensure!(
            matches!(self.check_cookie().await, CheckCookieResult::Valid(_)),
            "IM 身份凭证获取后登录态未确认，未保存凭证"
        );
        self.verified_sender_uid(Some(&uid.to_string()))?;
        context.validate_session(uid, &self.get_current_cookie())?;
        self.set_web_context(context)
    }

    /// 自动任务共用：拉取失败或身份变化时在消费发送授权之前停止。
    pub async fn prepare_im_identity(&self, expected_uid: Option<&str>) -> Result<()> {
        if let Err(error) = self.acquire_im_identity(expected_uid).await {
            self.send_blocked.store(true, Ordering::Relaxed);
            return Err(error.context("IM 身份续取失败，未发送且未自动重试"));
        }
        Ok(())
    }

    /// 同事务保存 Cookie 与上下文，拒绝覆盖请求期间换入的新会话。
    pub async fn persist_im_session(
        &self,
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
        original_encrypted_cookie: &[u8],
        expected_uid: Option<&str>,
    ) -> Result<()> {
        self.persist_im_session_with_optional_device(
            pool,
            secret,
            account_id,
            original_encrypted_cookie,
            expected_uid,
            None,
        )
        .await
    }

    /// 同事务保存 Cookie、上下文和已变更的设备指纹，供真实浏览器轮转后使用。
    pub async fn persist_im_session_with_device(
        &self,
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
        original_encrypted_cookie: &[u8],
        expected_uid: Option<&str>,
        device: &super::device_profile::DeviceProfile,
    ) -> Result<()> {
        self.persist_im_session_with_optional_device(
            pool,
            secret,
            account_id,
            original_encrypted_cookie,
            expected_uid,
            Some(device),
        )
        .await
    }

    async fn persist_im_session_with_optional_device(
        &self,
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
        original_encrypted_cookie: &[u8],
        expected_uid: Option<&str>,
        device: Option<&super::device_profile::DeviceProfile>,
    ) -> Result<()> {
        let uid = self.verified_sender_uid(expected_uid)?;
        let mut context = self
            .web_context
            .lock()
            .unwrap()
            .clone()
            .context("IM 上下文不存在")?;
        context.validate_session(uid, &self.get_current_cookie())?;
        if context.guard_secret_hex.is_none() || context.guard_server_data.is_none() {
            if let Ok(Some(old_enc)) = sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
            )
            .bind(account_id)
            .fetch_optional(pool)
            .await
            {
                if let Ok(old_plain) = secret.decrypt(&old_enc) {
                    if let Ok(old_saved) =
                        serde_json::from_slice::<super::im_auth::WebSessionContext>(&old_plain)
                    {
                        context.inherit_guard_materials(&old_saved);
                    }
                }
            }
        }
        let encrypted_device = if let Some(device) = device {
            device.validate()?;
            anyhow::ensure!(
                device.user_agent == context.user_agent
                    && context
                        .device
                        .as_ref()
                        .is_none_or(|context_device| context_device == device),
                "待保存设备指纹与 Web 上下文不一致"
            );
            Some(secret.encrypt(&serde_json::to_vec(device)?)?)
        } else {
            None
        };
        let encrypted_cookie = secret.encrypt(self.get_current_cookie().as_bytes())?;
        let encrypted_context = secret.encrypt(&serde_json::to_vec(&context)?)?;
        let mut tx = pool.begin().await?;
        let changed=sqlx::query("UPDATE accounts SET encrypted_cookie=?1 WHERE id=?2 AND encrypted_cookie=?3 AND uid=?4 AND status='ACTIVE'")
            .bind(encrypted_cookie).bind(account_id).bind(original_encrypted_cookie).bind(uid.to_string()).execute(&mut *tx).await?;
        anyhow::ensure!(
            changed.rows_affected() == 1,
            "请求期间账号会话已变化，未保存旧 IM 凭证"
        );
        sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
            .bind(account_id).bind(encrypted_context).execute(&mut *tx).await?;
        if let Some(encrypted_device) = encrypted_device {
            sqlx::query("INSERT INTO account_device_profiles(account_id,encrypted_profile) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_profile=excluded.encrypted_profile")
                .bind(account_id)
                .bind(encrypted_device)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn persist_web_context(
        &self,
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
    ) -> Result<()> {
        let context = self.web_context.lock().unwrap().clone();
        if let Some(mut ctx) = context {
            let cookie = self.get_current_cookie();
            if ctx.session_hash != super::im_auth::session_hash(&cookie)? {
                // 会话轮换后不能丢弃已采集的账号级身份；只有身份齐全且库内账号 UID 一致才允许重绑落库。
                let stored_uid: Option<String> =
                    sqlx::query_scalar::<_, String>("SELECT uid FROM accounts WHERE id=?1")
                        .bind(account_id)
                        .fetch_optional(pool)
                        .await
                        .ok()
                        .flatten();
                if !ctx.has_identity()
                    || stored_uid.as_deref().and_then(|u| u.parse::<u64>().ok()) != Some(ctx.uid)
                {
                    return Ok(());
                }
                ctx.rebind_session(&cookie)?;
                tracing::info!(account_id = %account_id, uid = ctx.uid, "持久化时会话 Cookie 已轮换，已把官方 IM 身份 Token 重绑到当前会话");
            }
            ctx.captured_at = chrono::Utc::now().timestamp();
            if ctx.guard_secret_hex.is_none()
                || ctx.guard_server_data.is_none()
                || !ctx.has_identity()
            {
                if let Ok(Some(old_enc)) = sqlx::query_scalar::<_, Vec<u8>>(
                    "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
                )
                .bind(account_id)
                .fetch_optional(pool)
                .await
                {
                    if let Ok(old_plain) = secret.decrypt(&old_enc) {
                        if let Ok(old_saved) =
                            serde_json::from_slice::<super::im_auth::WebSessionContext>(&old_plain)
                        {
                            ctx.inherit_guard_materials(&old_saved);
                            if ctx.adopt_identity_from(&old_saved) {
                                tracing::info!(account_id = %account_id, uid = ctx.uid, "持久化前从库内既有上下文中恢复官方 IM 身份 Token，拒绝用无身份上下文覆盖");
                            }
                        }
                    }
                }
            }
            let encrypted = secret.encrypt(&serde_json::to_vec(&ctx)?)?;
            sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
                .bind(account_id).bind(encrypted).execute(pool).await?;
            if let Some(mem_ctx) = self.web_context.lock().unwrap().as_mut() {
                mem_ctx.session_hash = ctx.session_hash.clone();
                mem_ctx.captured_at = ctx.captured_at;
                mem_ctx.identity_acquired_at = ctx.identity_acquired_at;
                mem_ctx.inherit_guard_materials(&ctx);
            }
        }
        Ok(())
    }

    /// 确保当前账号具备有效的 GuardKey 与已建联的服务端票据材料。
    pub async fn ensure_guard_bound(
        &self,
    ) -> Result<(
        super::pcim_guard::GuardKey,
        super::pcim_guard::BoundGuardMaterial,
    )> {
        let cookie = self.get_current_cookie();
        let (key, material) = {
            let mut ctx = self
                .web_context
                .lock()
                .unwrap()
                .clone()
                .context("缺少 IM 上下文")?;
            let key = ctx.get_or_create_guard_key()?;
            let mat = ctx.get_guard_material(&key, &cookie)?;
            (key, mat)
        };

        let now = chrono::Utc::now().timestamp();
        if let Some(mat) = &material {
            if !mat.is_stale(now, 86400 * 3) {
                // 优先通过标准只读接口安全拉取 DTrait 中央公钥（若未配置）
                #[cfg(not(test))]
                if self
                    .web_context
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|c| c.dtrait_pk1_pem.as_ref())
                    .is_none()
                {
                    self.acquire_dtrait_config().await.ok();
                }
                return Ok((key, mat.clone()));
            }
        }

        if let Some(material) = material {
            if material.is_stale(now, 86400 * 3) {
                // 票据到期后不能继续拿旧 ticket 签名；先向官方换票，失败则保留现有登录态。
                if let Ok(refreshed) = self.refresh_guard_ticket().await {
                    return Ok((key, refreshed));
                }
            }
            return Ok((key, material));
        }
        #[cfg(test)]
        if im_identity_tests::active() {
            anyhow::bail!("OFFLINE_MOCK_NO_GUARD_BOUND");
        }
        anyhow::bail!(
            "当前账号尚未绑定有效的 Guard 签名票据材料（或已超过 72 小时有效期），已安全拦截发送以防被平台注销会话；请在账号管理对该账号重新登录一次以刷新官方票据"
        );
    }

    /// 自动向官方端点换取新鲜的 Guard Ticket 与 DTrait 配置，实现票据自愈与无缝续期。
    #[allow(dead_code)]
    pub async fn refresh_guard_ticket(&self) -> Result<super::pcim_guard::BoundGuardMaterial> {
        #[cfg(test)]
        if im_identity_tests::active() {
            anyhow::bail!("OFFLINE_MOCK_REFRESH_TICKET");
        }
        let cookie = self.get_current_cookie();
        let (key, uid, csrf) = {
            let mut ctx = self
                .web_context
                .lock()
                .unwrap()
                .clone()
                .context("缺少 IM 上下文")?;
            let key = ctx.get_or_create_guard_key()?;
            let uid = ctx.uid;
            let csrf = self
                .extract_cookie_val("passport_csrf_token")
                .or_else(|| self.extract_cookie_val("passport_csrf_token_default"))
                .unwrap_or_default();
            (key, uid, csrf)
        };

        let pub_b64 = key.public_key_base64();
        // 必须复用官方字段顺序；官方仅用 encodeURIComponent 转义 padding '='，
        // 套用 form_urlencoded 会额外转义 '+' 与 '/'，与浏览器指纹不一致。
        let client_data_b64 = base64::engine::general_purpose::STANDARD
            .encode(super::pcim_guard::guard_declaration_json(&pub_b64)?.as_bytes());
        let client_data_encoded = client_data_b64.replace('=', "%3D");

        let cookie_with_guard = {
            let mut items: Vec<String> = cookie
                .split(';')
                .map(|p| p.trim().to_string())
                .filter(|p| {
                    !p.starts_with("bd_ticket_guard_client_data=")
                        && !p.starts_with("bd_ticket_guard_client_web_domain=")
                        && !p.starts_with("bd_ticket_guard_server_data=")
                        && !p.starts_with("bd_ticket_guard_web_domain=")
                })
                .collect();
            items.push(format!("bd_ticket_guard_client_data={client_data_encoded}"));
            items.push("bd_ticket_guard_client_web_domain=2".to_string());
            items.join("; ")
        };
        *self.current_cookie.lock().unwrap() = cookie_with_guard;

        let request = self.web_request(
            Method::POST,
            "https://www.douyin.com/passport/ticket_guard/get_client_cert/?aid=6383&type=trait&sdk_version=1.0.25&is_from_ttaccountsdk=1",
        )?
        .header(header::ACCEPT, "application/json")
        .header("x-tt-passport-csrf-token", &csrf)
        .header("bd-ticket-guard-ree-public-key", &pub_b64)
        .header("bd-ticket-guard-web-version", "2")
        .header("bd-ticket-guard-version", "2")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("server_data=1&need_session_dtrait=1");

        let (response_headers, bytes, _guard) = self.execute_web(request.build()?).await?;
        self.merge_response_headers(&response_headers);

        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(data) = json.get("data") {
                if let (Some(pk1), Some(ver)) = (
                    data.get("x-tt-session-dtrait-pk1").and_then(|v| v.as_str()),
                    data.get("x-tt-session-dtrait-pk1-version")
                        .and_then(|v| v.as_str()),
                ) {
                    if let Ok(pem_bytes) = base64::engine::general_purpose::STANDARD.decode(pk1) {
                        if let Ok(pem) = String::from_utf8(pem_bytes) {
                            let existing_ctx = self.web_context.lock().unwrap().clone();
                            if let Some(mut ctx) = existing_ctx {
                                ctx.set_dtrait_config(&pem, ver);
                                self.set_web_context(ctx).ok();
                            }
                        }
                    }
                }
            }
        }

        let server_data_b64 = extract_server_data_from_headers(&response_headers)
            .or_else(|| {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    json.get("server_data")
                        .or_else(|| json.get("bd-ticket-guard-server-data"))
                        .or_else(|| {
                            json.get("data").and_then(|d| {
                                d.get("server_data")
                                    .or_else(|| d.get("bd-ticket-guard-server-data"))
                            })
                        })
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            });

        let acquired_at = chrono::Utc::now().timestamp();
        let (material, srv_json_str) = if let Some(server_data_b64) = server_data_b64 {
            let raw_bytes = base64::engine::general_purpose::STANDARD
                .decode(&server_data_b64)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&server_data_b64))
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(&server_data_b64)
                })
                .context("base64 解码 bd-ticket-guard-server-data 失败")?;
            let srv_json_str = String::from_utf8(raw_bytes)
                .context("bd-ticket-guard-server-data 不是有效的 UTF-8 JSON 文本")?;
            let material = super::pcim_guard::BoundGuardMaterial::from_saved(
                &srv_json_str,
                uid,
                &self.get_current_cookie(),
                acquired_at,
                &pub_b64,
            )
            .context("新换取的 Guard 签名票据校验失败")?;
            (material, srv_json_str)
        } else {
            let current_cookie = self.get_current_cookie();
            let material = key
                .bind_server_cookie(&current_cookie, uid, &current_cookie, acquired_at)?
                .context("换票接口未在响应中下发 bd-ticket-guard-server-data")?;
            let srv_json_str = material.server_data_json()?;
            (material, srv_json_str)
        };

        let aligned_cookie = super::pcim_guard::align_guard_cookie(
            &self.get_current_cookie(),
            &pub_b64,
            Some(&material),
        )?;
        *self.current_cookie.lock().unwrap() = aligned_cookie;

        {
            let mut lock = self.web_context.lock().unwrap();
            if let Some(ctx) = lock.as_mut() {
                ctx.guard_secret_hex = Some(key.to_hex());
                ctx.guard_server_data = Some(srv_json_str);
                ctx.guard_acquired_at = Some(acquired_at);
            }
        }
        tracing::info!(account = %self.account_alias, "成功向官方服务端换取全新 Guard Ticket 并完成公钥绑定");
        Ok(material)
    }

    /// 拉取 DTrait 中央公钥配置并缓存在 Web 上下文中。
    pub async fn acquire_dtrait_config(&self) -> Result<()> {
        let _cookie = self.get_current_cookie();
        let csrf = self
            .extract_cookie_val("passport_csrf_token")
            .or_else(|| self.extract_cookie_val("passport_csrf_token_default"))
            .unwrap_or_default();
        let request = self.web_request(Method::POST, "https://www.douyin.com/passport/ticket_guard/get_client_cert/?aid=6383&type=trait&sdk_version=1.0.25&is_from_ttaccountsdk=1")?
            .header(header::ACCEPT, "application/json")
            .header("x-tt-passport-csrf-token", csrf)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("server_data=1&need_session_dtrait=1");
        let json = self.web_json(request).await?;
        let data = json.get("data").context("DTRAIT_DATA_MISSING")?;
        let public_b64 = data
            .get("x-tt-session-dtrait-pk1")
            .and_then(serde_json::Value::as_str)
            .context("DTRAIT_PK1_MISSING")?;
        let version = data
            .get("x-tt-session-dtrait-pk1-version")
            .and_then(serde_json::Value::as_str)
            .context("DTRAIT_VERSION_MISSING")?;
        let pem_bytes = base64::engine::general_purpose::STANDARD
            .decode(public_b64)
            .context("DTRAIT_DECODE_FAILED")?;
        let pem = String::from_utf8(pem_bytes).context("DTRAIT_PEM_INVALID")?;
        let existing_ctx = self.web_context.lock().unwrap().clone();
        if let Some(mut ctx) = existing_ctx {
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

    /// 测试专用：把会话门禁设为指定的可恢复或明确失效状态。
    #[cfg(test)]
    pub(crate) fn test_block_session(&self, expired: bool, verify: bool) {
        let kind = if expired {
            web::FailureKind::Expired
        } else if verify {
            web::FailureKind::Verify
        } else {
            web::FailureKind::Limited
        };
        self.stop_requests(kind);
    }

    /// 使用账号既有 Guard 票据对官方 TokenBeat 路径签名，刷新身份 Token。
    ///
    /// 该接口不会滑动延长 `sid_guard` 的绝对有效期；它维护的是账号身份层。
    /// 只有响应、身份 Token 设备绑定、Cookie 与 Guard 材料全部校验通过后才原子提交。
    pub async fn refresh_identity_by_token_beat(&self, scene: &str) -> Result<IdentityBeatStatus> {
        anyhow::ensure!(
            matches!(scene, "boot" | "polling" | "active"),
            "TokenBeat scene 未登记"
        );
        let initial_context = self
            .web_context
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("TOKEN_BEAT_CONTEXT_MISSING"))?;
        if !initial_context.has_identity() {
            return Ok(IdentityBeatStatus::MissingIdentity);
        }
        let cookie = self.get_current_cookie();
        initial_context.validate_session(initial_context.uid, &cookie)?;
        if !matches!(self.check_cookie().await, CheckCookieResult::Valid(_)) {
            anyhow::bail!("TokenBeat 前本地会话门禁未通过");
        }

        let (trusted_ts, is_trusted) = match self.get_trusted_timestamp(initial_context.uid).await {
            Ok(ts) => (ts, true),
            Err(error) => {
                tracing::warn!(
                    account = %self.account_alias,
                    error = %error,
                    "TokenBeat 官方授信时间不可用，本次使用本机时间并标记为非授信"
                );
                (chrono::Utc::now().timestamp(), false)
            }
        };

        // 拉取授信时间可能轮转响应头中的 Guard 材料，必须在请求前重新取快照。
        let (key, material) = {
            let context = self
                .web_context
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow::anyhow!("TOKEN_BEAT_CONTEXT_MISSING"))?;
            let Some(key) = context.get_guard_key()? else {
                return Ok(IdentityBeatStatus::MissingGuardMaterial);
            };
            let cookie = self.get_current_cookie();
            let Some(material) = context.get_guard_material(&key, &cookie)? else {
                return Ok(IdentityBeatStatus::MissingGuardMaterial);
            };
            material.validate_freshness(trusted_ts)?;
            (key, material)
        };

        let cookie = self.get_current_cookie();
        let aligned_cookie =
            super::pcim_guard::align_guard_cookie(&cookie, &material.public, Some(&material))?;
        let mode = if material.data.ts_sign.starts_with("ts.1") {
            super::pcim_guard::GuardMode::Ecdsa
        } else {
            super::pcim_guard::GuardMode::Hmac {
                server_spki_der: super::pcim_guard::OFFICIAL_SERVER_SPKI_DER,
            }
        };
        let guard_headers = key.sign_path_with_trust(
            &material,
            "/passport/token/beat/web/",
            material.uid,
            &aligned_cookie,
            trusted_ts,
            mode,
            is_trusted,
        )?;
        let url = format!("https://www.douyin.com/passport/token/beat/web/?scene={scene}&aid=6383");
        let mut request = self
            .web_request(Method::GET, &url)?
            .header(header::ACCEPT, "application/json, text/plain, */*")
            .build()
            .context("无法构造 TokenBeat 请求")?;
        request.headers_mut().insert(
            header::COOKIE,
            header::HeaderValue::from_str(&aligned_cookie).context("TokenBeat Cookie 格式无效")?,
        );
        for (name, value) in guard_headers {
            if let Some(name) = name {
                request.headers_mut().insert(name, value);
            }
        }

        let (response_headers, bytes, guard) = self.execute_web_token_beat(request).await?;
        self.apply_token_beat_response(&response_headers, &bytes)?;
        drop(guard);
        tracing::info!(
            account = %self.account_alias,
            scene = scene,
            "纯 Rust TokenBeat 已完成身份 Token 自愈"
        );
        Ok(IdentityBeatStatus::Refreshed)
    }

    fn apply_token_beat_response(&self, headers: &header::HeaderMap, bytes: &[u8]) -> Result<()> {
        let json: Value = serde_json::from_slice(bytes).context("TokenBeat 返回非 JSON 报文")?;
        anyhow::ensure!(json.is_object(), "TokenBeat 返回报文不是对象");
        web::validate_json(&json)?;
        let identity_token = token_beat_identity_token(headers)?;

        let mut cookie = self.get_current_cookie();
        let mut context = self
            .web_context
            .lock()
            .unwrap()
            .clone()
            .context("TokenBeat 缺少 Web 上下文")?;
        let uid = context.uid;
        let now = chrono::Utc::now().timestamp();
        let set_cookies: Vec<_> = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        let (merged_cookie, mut cookie_changed) = merge_cookies(&cookie, &set_cookies);
        cookie = merged_cookie;

        let key = context
            .get_guard_key()?
            .context("TokenBeat 缺少本地 Guard 密钥")?;
        let mut material = key.bind_response_headers(headers, uid, &cookie, now)?;
        if material.is_none() {
            for set_cookie in &set_cookies {
                if let Some(candidate) = key.bind_server_cookie(set_cookie, uid, &cookie, now)? {
                    anyhow::ensure!(material.is_none(), "TokenBeat 返回了多份 Guard 服务端材料");
                    material = Some(candidate);
                }
            }
        }
        if let Some(material) = material.as_ref() {
            context.set_guard_material(material)?;
        }
        let effective_material = material
            .as_ref()
            .cloned()
            .or_else(|| context.get_guard_material(&key, &cookie).ok().flatten());
        let aligned = super::pcim_guard::align_guard_cookie(
            &cookie,
            &key.public_key_base64(),
            effective_material.as_ref(),
        )?;
        if aligned != cookie {
            cookie = aligned;
            cookie_changed = true;
        }
        if context.session_hash != super::im_auth::session_hash(&cookie)? {
            anyhow::ensure!(
                context.rebind_session(&cookie)?,
                "TokenBeat 会话哈希变化但未完成重绑"
            );
        }
        context.refresh_identity_token(&identity_token)?;
        context.validate_session(uid, &cookie)?;

        // 所有校验完成后才提交，任一失败都保留原 Cookie、Guard 材料和身份 Token。
        *self.current_cookie.lock().unwrap() = cookie;
        *self.web_context.lock().unwrap() = Some(context);
        *self.verified_uid.lock().unwrap() = Some(uid);
        if cookie_changed {
            *self.cookie_changed.lock().unwrap() = true;
        }
        self.clear_session_block();
        Ok(())
    }

    /// 抖音会话活跃状态探测：直接复用安全的原生 Web 接口探测，彻底移除高危的 Mobile SDK 打点
    pub async fn token_beat(&self) -> super::types::HeartbeatResult {
        match self.check_cookie().await {
            super::types::CheckCookieResult::Valid(_) => super::types::HeartbeatResult::Alive,
            super::types::CheckCookieResult::Expired(r) => {
                super::types::HeartbeatResult::Expired(r)
            }
            super::types::CheckCookieResult::NeedVerify(r) => {
                super::types::HeartbeatResult::Expired(format!("需安全验证: {r}"))
            }
            super::types::CheckCookieResult::NetworkError(e) => {
                super::types::HeartbeatResult::Error(e)
            }
        }
    }

    pub async fn get_profile_by_url(&self, profile_url: &str) -> Result<String> {
        self.verified_sender_uid(None)?;
        let request = self.web_request(Method::GET, profile_url)?;
        let json = self.web_json(request).await?;
        json.get("user")
            .and_then(|u| u.get("nickname"))
            .and_then(Value::as_str)
            .filter(|n| !n.trim().is_empty())
            .map(str::to_string)
            .context("Web 未返回目标昵称，保留原资料")
    }

    /// 本地只读校验登录票据，不向抖音发送任何请求。
    ///
    /// 抖音会对缺少页面签名上下文的裸 Cookie 请求做风控，严重时会直接注销
    /// `sessionid`。因此常规检测只校验 `sid_guard` 绝对到期、会话 Cookie 与已落库
    /// Web 上下文的一致性；真实网络有效性由后续签名 IM/Web 请求自然确认。
    pub async fn check_cookie(&self) -> CheckCookieResult {
        // 历史离线协议测试以账户资料响应模拟“身份后验”；该分支仅在 mock 队列激活时存在，
        // 生产构建不会包含任何 Cookie 探测请求。
        #[cfg(test)]
        if im_identity_tests::active() {
            return self.check_cookie_fixture_postcheck().await;
        }

        *self.verified_uid.lock().unwrap() = None;

        let cookie = self.get_current_cookie();
        if let Err(error) = super::im_auth::session_hash(&cookie) {
            return CheckCookieResult::Expired(error.to_string());
        }
        if let Some(expiry) = super::im_auth::sid_guard_expiry(&cookie) {
            if expiry <= chrono::Utc::now().timestamp() {
                return CheckCookieResult::Expired("登录会话已超过 sid_guard 绝对有效期".into());
            }
        }
        if let Err(error) = self.ensure_requests_allowed() {
            return Self::check_failure(error);
        }
        let Some(context) = self.web_context.lock().unwrap().clone() else {
            return CheckCookieResult::NetworkError(
                "SESSION_LOCAL_CONTEXT_MISSING: 本地官方 Web 上下文缺失，未发起抖音请求".into(),
            );
        };
        if let Err(error) = context.validate_session(context.uid, &cookie) {
            return CheckCookieResult::NetworkError(format!(
                "SESSION_LOCAL_CONTEXT_INVALID: {error}；未发起抖音请求"
            ));
        }
        if context.uid == 0 {
            return CheckCookieResult::NetworkError(
                "SESSION_LOCAL_CONTEXT_INVALID: 本地 Web 上下文缺少有效账号身份；未发起抖音请求"
                    .into(),
            );
        }
        *self.verified_uid.lock().unwrap() = Some(context.uid);
        CheckCookieResult::Valid(DouyinUserProfile {
            uid: context.uid.to_string(),
            sec_uid: String::new(),
            nickname: String::new(),
            avatar_url: String::new(),
        })
    }

    #[cfg(test)]
    async fn check_cookie_fixture_postcheck(&self) -> CheckCookieResult {
        *self.verified_uid.lock().unwrap() = None;
        let request = match self.web_request_allow_probe(
            Method::GET,
            "https://www.douyin.com/passport/account/info/v2/?aid=6383",
        ) {
            Ok(request) => request,
            Err(error) => return Self::check_failure(error),
        };
        let passport = match self.web_json(request).await {
            Ok(value) => value,
            Err(error) => return Self::check_failure(error),
        };
        let Some(data) = passport.get("data") else {
            return CheckCookieResult::NetworkError("Passport 缺少账号资料，未继续请求".into());
        };
        let uid = data
            .get("user_id_str")
            .or_else(|| data.get("user_id"))
            .and_then(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| value.as_u64().map(|uid| uid.to_string()))
            })
            .unwrap_or_default();
        if uid.parse::<u64>().ok().filter(|uid| *uid > 0).is_none() {
            self.stop_requests(web::FailureKind::Expired);
            return CheckCookieResult::Expired("Passport 未返回有效登录身份".into());
        }
        if self
            .web_context
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|context| context.uid.to_string() != uid)
        {
            self.stop_requests(web::FailureKind::Expired);
            return CheckCookieResult::Expired("Cookie 身份与绑定 Web 上下文不符，停止请求".into());
        }
        self.confirm_profile(DouyinUserProfile {
            uid: uid.clone(),
            sec_uid: data
                .get("sec_user_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            nickname: data
                .get("screen_name")
                .or_else(|| data.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("抖音用户")
                .into(),
            avatar_url: data
                .get("avatar_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        })
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
                .append_pair("sec_user_ids", &serde_json::to_string(chunk)?)
                .finish();
            let request = self
                .web_request(
                    Method::POST,
                    "https://www.douyin.com/aweme/v1/web/im/user/info/",
                )?
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body);
            let json = self.web_json(request).await?;
            let arr = json
                .get("data")
                .and_then(Value::as_array)
                .context("IM 用户资料列表缺失，保留原备注")?;
            for item in arr {
                let sec = item.get("sec_uid").and_then(Value::as_str).unwrap_or("");
                let nick = item.get("nickname").and_then(Value::as_str).unwrap_or("");
                if !sec.is_empty() {
                    if let Some(rem) = Self::parse_friend_remark(item, nick) {
                        map.insert(sec.into(), rem);
                    }
                }
            }
        }
        Ok(map)
    }

    pub async fn fetch_following_friends(
        &self,
        uid: &str,
        sec_uid: &str,
    ) -> Result<Vec<DouyinFriend>> {
        let needs_check = self.verified_uid.lock().unwrap().is_none();
        if needs_check {
            let checked = self.check_cookie().await;
            anyhow::ensure!(
                checked.is_valid(),
                "{}",
                checked
                    .error_message()
                    .unwrap_or("登录态未确认，停止好友同步")
            );
        }
        let my_uid = self.verified_sender_uid(Some(uid))?;
        anyhow::ensure!(!sec_uid.is_empty(), "缺少当前账号 SecUID，停止同步");
        let mut friends = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut spotlight =
            reqwest::Url::parse("https://www.douyin.com/aweme/v1/web/im/spotlight/relation/")?;
        spotlight
            .query_pairs_mut()
            .extend_pairs([
                ("count", "50"),
                ("source", "coldup"),
                ("min_time", "0"),
                ("need_remove_share_panel", "1"),
                ("need_sorted_info", "1"),
                ("with_fstatus", "1"),
                ("with_recent_share_day", "1"),
            ])
            .append_pair(
                "max_time",
                &chrono::Utc::now().timestamp_millis().to_string(),
            );
        let json = self
            .web_json_auxiliary(self.web_request(Method::GET, spotlight.as_str())?)
            .await?;
        let list = json
            .get("followings")
            .and_then(Value::as_array)
            .context("好友关系列表缺失，未回退重试")?;
        for item in list {
            push_friend(item, &mut friends, &mut seen);
        }
        if let Some(groups) = json.get("recent_share_groups").and_then(Value::as_array) {
            for g in groups {
                let cid = g
                    .get("conv_id")
                    .and_then(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .or_else(|| v.as_u64().map(|v| v.to_string()))
                    })
                    .unwrap_or_default();
                if cid.parse::<u64>().ok().filter(|id| *id > 0).is_none()
                    || !seen.insert(cid.clone())
                {
                    continue;
                }
                friends.push(DouyinFriend {
                    uid: String::new(),
                    sec_uid: cid.clone(),
                    nickname: format!("群聊 ({})", &cid[cid.len().saturating_sub(6)..]),
                    avatar_url: String::new(),
                    spark_days: None,
                    spark_desc: None,
                    is_sparked_today: None,
                    target_type: Some(2),
                    conversation_id: Some(cid),
                    remark_name: None,
                });
            }
        }
        // 一条有界关注列表分页链，复用联系人和备注；不再重复 fallback 后又重拉第一页。
        let mut cursor = 0_i64;
        let mut cursors = std::collections::HashSet::new();
        for _ in 0..8 {
            let mut url =
                reqwest::Url::parse("https://www.douyin.com/aweme/v1/web/user/following/list/")?;
            url.query_pairs_mut()
                .extend_pairs([
                    ("user_id", uid),
                    ("sec_user_id", sec_uid),
                    ("count", "20"),
                    ("offset", "0"),
                    ("source_type", "1"),
                    ("min_time", "0"),
                ])
                .append_pair("max_time", &cursor.to_string());
            let json = self
                .web_json_auxiliary(self.web_request(Method::GET, url.as_str())?)
                .await?;
            let list = json
                .get("followings")
                .and_then(Value::as_array)
                .context("关注列表缺失，停止翻页并保留原资料")?;
            for item in list {
                push_friend(item, &mut friends, &mut seen);
                let sec = item.get("sec_uid").and_then(Value::as_str).unwrap_or("");
                if let Some(rem) = Self::parse_friend_remark(
                    item,
                    item.get("nickname").and_then(Value::as_str).unwrap_or(""),
                ) {
                    if let Some(f) = friends.iter_mut().find(|f| f.sec_uid == sec) {
                        f.remark_name = Some(rem);
                    }
                }
            }
            let more = json
                .get("has_more")
                .is_some_and(|v| v.as_bool() == Some(true) || v.as_i64() == Some(1));
            if !more || list.is_empty() {
                break;
            }
            let next = json
                .get("min_time")
                .and_then(Value::as_i64)
                .filter(|v| *v > 0)
                .context("关注列表游标缺失，停止翻页")?;
            anyhow::ensure!(
                next != cursor && cursors.insert(next),
                "关注列表游标循环，停止翻页"
            );
            cursor = next;
        }
        let missing: Vec<_> = friends
            .iter()
            .filter(|f| f.target_type == Some(1) && f.remark_name.is_none())
            .map(|f| f.sec_uid.clone())
            .collect();
        let remarks = self.fetch_im_remarks(&missing).await?;
        for f in &mut friends {
            if let Some(rem) = remarks.get(&f.sec_uid) {
                f.remark_name = Some(rem.clone());
            }
        }
        let targets: Vec<_> = friends
            .iter()
            .filter_map(|f| {
                if f.target_type == Some(2) {
                    Some(DouyinTargetParam {
                        conv_id: f.conversation_id.clone()?,
                        conv_type: 2,
                        short_id: None,
                    })
                } else {
                    let peer = f
                        .uid
                        .parse::<u64>()
                        .ok()
                        .filter(|u| *u > 0 && *u != my_uid)?;
                    Some(DouyinTargetParam {
                        conv_id: format!("0:1:{}:{}", my_uid.min(peer), my_uid.max(peer)),
                        conv_type: 1,
                        short_id: None,
                    })
                }
            })
            .collect();
        // IM 上下文缺失/过期时保留未知值，不伪造未点亮或未发送。
        if !targets.is_empty()
            && self.web_context.lock().unwrap().as_ref().is_some_and(|c| {
                (0..=super::im_auth::MAX_AGE_SECS)
                    .contains(&(chrono::Utc::now().timestamp() - c.captured_at))
            })
        {
            for batch in targets.chunks(200) {
                let spark = self
                    .fetch_available_conversation_spark_status(batch)
                    .await?;
                for f in &mut friends {
                    let cid = if f.target_type == Some(2) {
                        f.conversation_id.clone().unwrap_or_default()
                    } else if let Ok(peer) = f.uid.parse::<u64>() {
                        format!("0:1:{}:{}", my_uid.min(peer), my_uid.max(peer))
                    } else {
                        continue;
                    };
                    if let Some(info) = spark.get(&cid) {
                        f.spark_days = Some(info.days);
                        f.spark_desc = Some(info.desc.clone());
                        if f.target_type == Some(2) {
                            if let Some(name) = &info.conv_name {
                                f.nickname = name.clone();
                            }
                        } else if let Ok(peer) = f.uid.parse::<u64>() {
                            if let Some((_, alias)) =
                                info.aliases.iter().find(|(uid, _)| *uid == peer)
                            {
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
        let results = self
            .fetch_available_conversation_spark_status(targets)
            .await?;
        anyhow::ensure!(
            targets.iter().all(|t| results.contains_key(&t.conv_id)),
            "IM 未返回当前目标会话，火花状态未知，保留原数据"
        );
        Ok(results)
    }

    /// 联系人不一定已建立 IM 会话；同步仅合并明确返回的会话，其余保持未知。
    pub async fn fetch_available_conversation_spark_status(
        &self,
        targets: &[DouyinTargetParam],
    ) -> Result<HashMap<String, SparkConversationInfo>> {
        let mut results = HashMap::new();
        if targets.is_empty() {
            return Ok(results);
        }

        let uid = self.verified_sender_uid(None)?;
        anyhow::ensure!(targets.len() <= 200, "IM 批量会话数量超限");
        for target in targets {
            validate_conversation(uid, &target.conv_id, target.conv_type)?;
        }
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

        let bytes = self
            .web_im_auxiliary(
                "https://imapi.douyin.com/v2/conversation/get_info_list",
                610,
                &req_body,
            )
            .await?;
        results.extend(parse_im_conversation_list_response(&bytes)?);
        for cid in results.keys() {
            let target = targets
                .iter()
                .find(|t| t.conv_id == *cid)
                .context("IM 返回了未请求的会话，停止合并")?;
            validate_conversation(uid, cid, target.conv_type)?;
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
            return self
                .send_pcim_initial(conv_id_opt, conv_type, target_sec_uid, target_uid, content)
                .await;
        }
        let text_msg = if content.trim().is_empty() {
            "🔥"
        } else {
            content.trim()
        };
        let my_uid = match self.verified_sender_uid(None) {
            Ok(uid) if !self.sending_blocked() => uid,
            Ok(_) => return SendSparkResult::failure("会话或鉴权已失败，当前操作禁止继续发送"),
            Err(_) => {
                return SendSparkResult::failure("未确认当前 Cookie 的有效发送身份，禁止发送");
            }
        };

        if self.send_credential.lock().unwrap().is_none() {
            return SendSparkResult::failure(
                "缺少官方 IM 发送鉴权凭证，未发送；身份 Token 不能替代独立发送授权",
            );
        }
        if self
            .prepare_im_identity(Some(&my_uid.to_string()))
            .await
            .is_err()
        {
            return SendSparkResult::failure(
                "IM 身份 Token 续取失败或身份变化，未发送且未自动重试",
            );
        }
        let parsed_to_uid = if conv_type == 2 {
            0
        } else {
            target_uid
                .and_then(|s| s.parse().ok())
                .filter(|u| *u > 0)
                .unwrap_or(0)
        };
        let req = match self.build_send_request(
            "https://imapi.douyin.com/v1/message/send",
            my_uid,
            conv_id_opt,
            conv_type,
            target_sec_uid,
            parsed_to_uid,
            text_msg,
        ) {
            Ok(req) => req,
            Err(e) => return SendSparkResult::failure(&e.to_string()),
        };

        match self.execute_web(req).await {
            Ok((headers, bytes, _guard)) => {
                let (ok, code, message, id) = parse_im_send_response(&bytes);
                if ok {
                    self.merge_response_headers(&headers);
                    SendSparkResult::accepted(
                        format!("续火花消息已成功送达！(内容: {text_msg}, 消息ID: {id})"),
                        None,
                        Some(format!("MsgID: {id}, status: {code}")),
                    )
                } else {
                    self.send_blocked.store(true, Ordering::Relaxed);
                    self.stop_requests(web::FailureKind::Protocol);
                    SendSparkResult::failure(&format!(
                        "IM 未确认发送成功（状态 {code}）: {message}；禁止发送重试"
                    ))
                }
            }
            Err(e) => {
                self.stop_requests(
                    e.downcast_ref::<web::WebFailure>()
                        .map(|e| e.kind)
                        .unwrap_or(web::FailureKind::Network),
                );
                SendSparkResult::unknown(&format!("{e}；发送结果未知，禁止发送重试"))
            }
        }
    }

    /// 实际 HTTP 发送与离线测试共用此构造器，不从 Cookie 猜测 UID。
    fn build_send_request(
        &self,
        url: &str,
        my_uid: u64,
        conv_id_opt: Option<&str>,
        conv_type: i32,
        target_sec_uid: &str,
        target_uid: u64,
        text_msg: &str,
    ) -> Result<reqwest::Request> {
        // 捕获的 Ticket Guard 只属于官方发送路径，必须在消费凭证前拒绝跨路径使用。
        super::sdk_runtime::validate_captured_send_endpoint(url)?;
        self.ensure_requests_allowed()?;
        anyhow::ensure!(
            self.verified_sender_uid(None)? == my_uid,
            "发送身份不符，禁止发送"
        );
        let cid = if conv_type == 2 {
            conv_id_opt.unwrap_or(target_sec_uid).to_string()
        } else {
            anyhow::ensure!(
                conv_type == 1 && target_uid > 0 && my_uid != target_uid,
                "单聊目标身份无效，禁止发送"
            );
            let cid = format!("0:1:{}:{}", my_uid.min(target_uid), my_uid.max(target_uid));
            anyhow::ensure!(
                conv_id_opt.is_none_or(|stored| stored == cid),
                "目标会话与当前账号身份不符，禁止发送"
            );
            cid
        };
        let mut guard = self.send_credential.lock().unwrap();
        let credential = guard.as_ref().context("缺少官方 IM 发送鉴权凭证，单独更新 Cookie 不足以发送；请同步当前会话的官方发送请求，禁止发送")?;
        credential.validate(my_uid, &self.get_current_cookie(), &cid, conv_type)?;
        let context = self
            .web_context
            .lock()
            .unwrap()
            .clone()
            .context("缺少当前 IM 身份 Token，禁止发送")?;
        credential.validate_identity_binding(&context, my_uid, &self.get_current_cookie())?;
        let credential = guard.take().expect("validated credential");
        let mut request = self
            .web_request(Method::POST, url)?
            .header(header::USER_AGENT, &credential.user_agent)
            .header(header::CONTENT_TYPE, "application/x-protobuf")
            .header(header::ACCEPT, "application/x-protobuf")
            .body(credential.request_body(text_msg));
        for (key, value) in &credential.http_headers {
            request = request.header(key, value);
        }
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
        anyhow::ensure!(
            self.verified_sender_uid(None)? == my_uid,
            "消息历史查询身份不符"
        );
        validate_conversation(my_uid, conv_id, conv_type)?;

        let mut effective_short_id = short_id;
        if effective_short_id == 0 {
            let single_param = DouyinTargetParam {
                conv_id: conv_id.to_string(),
                conv_type,
                short_id: None,
            };
            let map = self
                .fetch_batch_conversation_spark_status(&[single_param])
                .await?;
            if let Some(info) = map.get(conv_id) {
                effective_short_id = info.short_id;
            }
        }

        anyhow::ensure!(
            effective_short_id > 0,
            "未取得真实会话短 ID，今日发送情况未知，禁止发送"
        );
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

        let bytes = self
            .web_im_auxiliary(
                "https://imapi.douyin.com/v1/message/get_by_conversation",
                301,
                &req_body,
            )
            .await?;
        let sent = parse_im_check_my_message_today(&bytes, my_uid)?;
        anyhow::ensure!(
            chrono::Utc::now().with_timezone(&cst).date_naive() == query_day,
            "消息历史检测跨越北京时间零点，请重新刷新，今日发送情况未知"
        );
        self.send_history
            .lock()
            .unwrap()
            .insert(conv_id.into(), (my_uid, conv_type, query_day, sent));
        Ok(sent)
    }

    pub(crate) fn bind_send_claim(
        &self,
        pool: sqlx::SqlitePool,
        account_id: &str,
        conversation_id: &str,
        encrypted: Vec<u8>,
    ) {
        *self.send_claim.lock().unwrap() =
            Some((pool, account_id.into(), conversation_id.into(), encrypted));
    }

    fn validate_send_history(&self, request: &reqwest::Request) -> Result<()> {
        let field = |data: &[u8], number| {
            parse_protobuf_fields(data)
                .into_iter()
                .find(|(n, w, _)| *n == number && *w == 2)
                .map(|(_, _, b)| b)
        };
        let data = request
            .body()
            .and_then(|b| b.as_bytes())
            .context("发送请求体不可检查")?;
        let body = field(data, 8)
            .and_then(|b| field(&b, 100))
            .context("发送会话不可检查")?;
        let cid = String::from_utf8(field(&body, 1).context("发送会话缺失")?)?;
        let uid = self.verified_sender_uid(None)?;
        let history = self.send_history.lock().unwrap();
        let (sender, kind, day, sent) = history
            .get(&cid)
            .context("缺少该会话完整今日历史确认，禁止发送")?;
        let request_kind = parse_protobuf_fields(&body)
            .into_iter()
            .find(|(n, w, _)| *n == 2 && *w == 0)
            .and_then(|(_, _, b)| read_varint(&b, 0).map(|(v, _)| v as i32));
        let force = self
            .pcim_initial
            .lock()
            .unwrap()
            .as_ref()
            .map_or(false, |b| b.force);
        anyhow::ensure!(
            *sender == uid
                && Some(*kind) == request_kind
                && (!*sent || force)
                && *day
                    == chrono::Utc::now()
                        .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
                        .date_naive(),
            "今日历史已发送、身份不符或跨越北京时间零点，停止发送"
        );
        let context = self
            .web_context
            .lock()
            .unwrap()
            .clone()
            .context("IM 身份缺失，停止发送")?;
        anyhow::ensure!(
            context.identity_is_current(
                uid,
                &self.get_current_cookie(),
                chrono::Utc::now().timestamp()
            ),
            "发送排队期间 IM 身份已过期，停止发送"
        );
        Ok(())
    }

    async fn claim_send_authorization(&self) -> Result<()> {
        let claim = self.send_claim.lock().unwrap().take();
        if let Some((pool, account, cid, encrypted)) = claim {
            let result=sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1 AND conversation_id=?2 AND encrypted_credential=?3")
                .bind(account).bind(cid).bind(encrypted).execute(&pool).await?;
            anyhow::ensure!(
                result.rows_affected() == 1,
                "发送授权已变化或被消费，禁止发送"
            );
        }
        Ok(())
    }
}

fn push_friend(
    item: &Value,
    friends: &mut Vec<DouyinFriend>,
    seen: &mut std::collections::HashSet<String>,
) {
    let sec = item.get("sec_uid").and_then(Value::as_str).unwrap_or("");
    let uid = item
        .get("uid")
        .and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.as_u64().map(|v| v.to_string()))
        })
        .unwrap_or_default();
    if sec.is_empty()
        || uid.parse::<u64>().ok().filter(|u| *u > 0).is_none()
        || !seen.insert(sec.into())
    {
        return;
    }
    let nick = item
        .get("nickname")
        .and_then(Value::as_str)
        .unwrap_or("好友");
    friends.push(DouyinFriend {
        uid,
        sec_uid: sec.into(),
        nickname: nick.into(),
        avatar_url: item
            .pointer("/avatar_thumb/url_list/0")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        spark_days: None,
        spark_desc: None,
        is_sparked_today: None,
        target_type: Some(1),
        conversation_id: None,
        remark_name: DouyinClient::parse_friend_remark(item, nick),
    });
}

fn validate_conversation(uid: u64, id: &str, kind: i32) -> Result<()> {
    anyhow::ensure!(uid > 0, "未确认会话查询身份");
    if kind == 2 {
        anyhow::ensure!(
            id.parse::<u64>().ok().filter(|v| *v > 0).is_some(),
            "群聊会话 ID 无效"
        );
    } else {
        let p: Vec<_> = id.split(':').collect();
        anyhow::ensure!(
            kind == 1 && p.len() == 4 && p[0] == "0" && p[1] == "1",
            "单聊会话格式无效"
        );
        let a = p[2].parse::<u64>()?;
        let b = p[3].parse::<u64>()?;
        anyhow::ensure!(
            a > 0 && a < b && (uid == a || uid == b),
            "会话不属于当前账号，禁止请求"
        );
    }
    Ok(())
}

fn requires_security_verification(json: &Value) -> bool {
    [
        json.get("message"),
        json.get("status_msg"),
        json.get("description"),
        json.get("data").and_then(|data| data.get("description")),
        json.get("data").and_then(|data| data.get("message")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .any(|msg| {
        let msg = msg.to_ascii_lowercase();
        ["verify", "verification", "captcha", "验证", "风控"]
            .iter()
            .any(|word| msg.contains(word))
    })
}

pub(crate) fn is_fatal_send_error(code: i64, message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    matches!(code, 401 | 403 | 2154 | 2483)
        || [
            "http错误: 401",
            "http错误: 403",
            "错误码:401",
            "错误码:403",
            "错误码:2154",
            "错误码:2483",
        ]
        .iter()
        .any(|word| msg.contains(word))
        || [
            "session",
            "auth",
            "cookie",
            "token",
            "passport",
            "login",
            "verify",
            "captcha",
            "conversation",
            "会话",
            "鉴权",
            "身份",
            "登录",
            "验证",
            "风控",
            "频繁",
            "禁止发送",
        ]
        .iter()
        .any(|word| msg.contains(word))
}

pub(crate) fn extract_server_data_from_headers(
    headers: &reqwest::header::HeaderMap,
) -> Option<String> {
    if let Some(val) = headers.get("bd-ticket-guard-server-data") {
        if let Ok(s) = val.to_str() {
            if !s.trim().is_empty() {
                return Some(s.trim().to_string());
            }
        }
    }
    for cookie in headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
    {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k.trim() == "bd_ticket_guard_server_data" {
                    let decoded = percent_decode_str(v.trim());
                    if !decoded.is_empty() {
                        return Some(decoded.to_string());
                    }
                }
            }
        }
    }
    None
}

fn token_beat_identity_token(headers: &reqwest::header::HeaderMap) -> Result<String> {
    let values: Vec<_> = headers
        .get_all("bd-ticket-guard-identity-token")
        .iter()
        .collect();
    anyhow::ensure!(values.len() == 1, "TokenBeat 身份 Token 缺失或重复");
    let token = values[0]
        .to_str()
        .context("TokenBeat 身份 Token 不是合法 HTTP 文本")?
        .trim();
    anyhow::ensure!(
        !token.is_empty() && token.len() <= super::im_auth::MAX_BEAT_TOKEN_LEN,
        "TokenBeat 身份 Token 长度无效"
    );
    Ok(token.to_string())
}

fn percent_decode_str(s: &str) -> String {
    let mut bytes = Vec::new();
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let Ok(val) =
                    u8::from_str_radix(std::str::from_utf8(&[h1, h2]).unwrap_or(""), 16)
                {
                    bytes.push(val);
                    continue;
                }
            }
        }
        bytes.push(b);
    }
    String::from_utf8(bytes).unwrap_or_else(|_| s.to_string())
}

fn parse_im_send_response(data: &[u8]) -> (bool, i64, String, String) {
    if data.is_empty()
        || matches!(
            data.iter().copied().find(|b| !b.is_ascii_whitespace()),
            Some(b'{' | b'[' | b'<')
        )
    {
        return (
            false,
            -1,
            "IM 返回非 Protobuf 响应，发送鉴权未通过或需要安全验证；禁止发送重试".into(),
            String::new(),
        );
    }
    let fields = parse_protobuf_fields(data);
    let status = fields
        .iter()
        .find(|(n, w, _)| *n == 3 && *w == 0)
        .and_then(|(_, _, b)| read_varint(b, 0))
        .map(|(v, _)| v as i32 as i64);
    let desc = fields
        .iter()
        .find(|(n, w, _)| *n == 4 && *w == 2)
        .map(|(_, _, b)| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default();
    let Some(status) = status else {
        return (
            false,
            -1,
            "IM 响应缺少有效状态字段，无法确认结果；禁止发送重试".into(),
            String::new(),
        );
    };
    let send = fields
        .iter()
        .find(|(n, w, _)| *n == 6 && *w == 2)
        .and_then(|(_, _, body)| {
            parse_protobuf_fields(body)
                .into_iter()
                .find(|(n, w, _)| *n == 100 && *w == 2)
        })
        .map(|(_, _, b)| parse_protobuf_fields(&b))
        .unwrap_or_default();
    let int = |n| {
        send.iter()
            .find(|(num, w, _)| *num == n && *w == 0)
            .and_then(|(_, _, b)| read_varint(b, 0))
            .map(|(v, _)| v)
    };
    let message_id = int(1)
        .filter(|id| *id > 0)
        .map(|id| id.to_string())
        .unwrap_or_default();
    let inner_status = int(3).unwrap_or(0);
    let check_code = int(5).unwrap_or(0);
    if status != 0 {
        return (false, status, desc, message_id);
    }
    if inner_status != 0 || check_code != 0 {
        return (
            false,
            inner_status.max(check_code) as i64,
            "IM 发送业务校验失败，需检查会话或安全验证；禁止发送重试".into(),
            message_id,
        );
    }
    if message_id.is_empty() {
        return (
            false,
            -1,
            "IM 响应未确认消息 ID，发送结果未知；禁止发送重试".into(),
            message_id,
        );
    }
    (true, 0, "OK".into(), message_id)
}

pub(crate) fn read_varint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        if shift == 63 && b > 1 {
            return None;
        }
        val |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some((val, pos));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
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
fn parse_im_conversation_list_response(
    data: &[u8],
) -> Result<HashMap<String, SparkConversationInfo>> {
    let mut map = HashMap::new();
    let envelope = parse_protobuf_fields(data);

    let status = envelope
        .iter()
        .find(|(num, wire, _)| *num == 3 && *wire == 0)
        .and_then(|(_, _, value)| read_varint(value, 0).map(|(value, _)| value as i32));
    let error_desc = envelope
        .iter()
        .find(|(num, wire, _)| *num == 4 && *wire == 2)
        .map(|(_, _, value)| {
            String::from_utf8_lossy(value)
                .chars()
                .filter(|c| !c.is_control())
                .take(160)
                .collect::<String>()
        })
        .unwrap_or_default();
    if let Some(status) = status.filter(|status| *status != 0) {
        anyhow::bail!(
            "IM 会话查询业务失败: status={status} error_desc={error_desc}；火花状态未知，保留原数据"
        );
    }

    let resp_body_bytes = match envelope
        .into_iter()
        .find(|(num, wire, _)| *num == 6 && *wire == 2)
    {
        Some((_, _, b)) => b,
        None => anyhow::bail!("IM 会话响应缺少内容"),
    };

    let body_fields = parse_protobuf_fields(&resp_body_bytes);
    let f610_bytes = match body_fields
        .into_iter()
        .find(|(num, wire, _)| *num == 610 && *wire == 2)
    {
        Some((_, _, b)) => b,
        None => anyhow::bail!("IM 会话响应缺少查询结果"),
    };

    let list_fields = parse_protobuf_fields(&f610_bytes);
    anyhow::ensure!(
        f610_bytes.is_empty() || !list_fields.is_empty(),
        "IM 会话列表截断，保留原数据"
    );
    let now = chrono::Utc::now().timestamp();

    for (l_num, l_wire, l_val) in list_fields {
        if l_num == 1 && l_wire == 2 {
            let conv_fields = parse_protobuf_fields(&l_val);
            anyhow::ensure!(!conv_fields.is_empty(), "IM 会话报文截断，保留原数据");
            anyhow::ensure!(
                conv_fields.iter().any(|(n, w, _)| *n == 50 && *w == 2),
                "IM 会话核心资料缺失，火花状态未知"
            );
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
                    anyhow::ensure!(!core_fields.is_empty(), "IM 会话核心资料截断，火花状态未知");
                    if let Some((_, _, b)) = core_fields
                        .iter()
                        .find(|(k, wire, _)| *k == 5 && *wire == 2)
                    {
                        let n = String::from_utf8_lossy(b).trim().to_string();
                        if !n.is_empty() {
                            conv_name = Some(n);
                        }
                    }
                    for (cr_num, cr_wire, cr_val) in core_fields {
                        if cr_num == 11 && cr_wire == 2 {
                            let entry_fields = parse_protobuf_fields(&cr_val);
                            anyhow::ensure!(
                                !entry_fields.is_empty(),
                                "IM 会话扩展截断，火花状态未知"
                            );
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

            anyhow::ensure!(
                !conv_id.is_empty() && short_id > 0,
                "IM 会话标识缺失，火花状态未知"
            );

            if let Some(json_str) = core_ext.get("a:consecutive_chat_data") {
                let val: serde_json::Value =
                    serde_json::from_str(json_str).context("官方火花数据格式异常，保留原状态")?;
                anyhow::ensure!(val.is_object(), "官方火花数据不是对象，保留原状态");
                {
                    let count = val
                        .get("consecutive_count_info")
                        .and_then(|c| c.get("consecutive_count"))
                        .and_then(|n| n.as_i64())
                        .unwrap_or(0) as i32;

                    let up_ms = val
                        .get("update_time_ms")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
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

                    map.insert(
                        conv_id,
                        SparkConversationInfo {
                            days,
                            desc,
                            is_sparked_today,
                            short_id,
                            conv_name,
                            aliases: aliases.clone(),
                        },
                    );
                }
            } else {
                map.insert(
                    conv_id,
                    SparkConversationInfo {
                        days: 0,
                        desc: "未点亮".to_string(),
                        is_sparked_today: false,
                        short_id,
                        conv_name,
                        aliases: aliases.clone(),
                    },
                );
            }
        }
    }

    Ok(map)
}

fn parse_im_check_my_message_today(data: &[u8], my_uid: u64) -> Result<bool> {
    parse_im_check_my_message_today_at(data, my_uid, chrono::Utc::now())
}

fn parse_im_check_my_message_today_at(
    data: &[u8],
    my_uid: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    let env = parse_protobuf_fields(data);
    let body_bytes = env
        .into_iter()
        .find(|(k, wire, _)| *k == 6 && *wire == 2)
        .context("IM 历史响应缺少内容")?
        .2;
    let f301_bytes = parse_protobuf_fields(&body_bytes)
        .into_iter()
        .find(|(k, wire, _)| *k == 301 && *wire == 2)
        .context("IM 历史响应缺少查询结果")?
        .2;
    let resp_fields = parse_protobuf_fields(&f301_bytes);
    anyhow::ensure!(
        f301_bytes.is_empty() || !resp_fields.is_empty(),
        "消息历史报文不完整，今日发送情况未知"
    );
    let has_more = resp_fields
        .iter()
        .find(|(n, w, _)| *n == 3 && *w == 0)
        .and_then(|(_, _, b)| read_varint(b, 0))
        .is_some_and(|(v, _)| v != 0);
    let mut oldest = None;

    let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    let today_cst = now.with_timezone(&cst).date_naive();

    for (rk, rt, rv) in resp_fields {
        if rk == 1 && rt == 2 {
            // MessageBody
            let m_fields = parse_protobuf_fields(&rv);
            let sender = m_fields
                .iter()
                .find(|(k, w, _)| *k == 7 && *w == 0)
                .and_then(|(_, _, v)| read_varint(v, 0).map(|(v, _)| v))
                .filter(|v| *v > 0)
                .context("消息发送者缺失，今日发送情况未知")?;
            let ctime = m_fields
                .iter()
                .find(|(k, w, _)| *k == 10 && *w == 0)
                .and_then(|(_, _, v)| read_varint(v, 0).map(|(v, _)| v))
                .filter(|v| *v > 0)
                .context("消息时间缺失，今日发送情况未知")?;
            let ts = if ctime > 10_000_000_000 {
                ctime / 1000
            } else {
                ctime
            };
            anyhow::ensure!(
                i64::try_from(ts)
                    .ok()
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                    .is_some(),
                "消息时间无效，今日发送情况未知"
            );
            oldest = Some(oldest.map_or(ts, |old: u64| old.min(ts)));

            if sender == my_uid {
                let ts = if ctime > 10_000_000_000 {
                    ctime / 1000
                } else {
                    ctime
                };
                if let Some(dt) = chrono::DateTime::from_timestamp(ts as i64, 0) {
                    if dt <= now && dt.with_timezone(&cst).date_naive() == today_cst {
                        return Ok(true);
                    }
                }
            }
        }
    }
    let day_start = today_cst
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_local_timezone(cst)
        .single()
        .unwrap()
        .timestamp() as u64;
    anyhow::ensure!(
        !has_more || oldest.is_some_and(|ts| ts < day_start),
        "今天的历史记录未读取完整，发送情况未知，禁止重复发送"
    );
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
        if field_num == 0 || tag >> 3 > 0x1fff_ffff {
            return Vec::new();
        }
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
                let Ok(len) = usize::try_from(len) else {
                    return Vec::new();
                };
                if len > data.len() - pos {
                    return Vec::new();
                }
                let bytes = data[pos..pos + len].to_vec();
                pos += len;
                fields.push((field_num, wire_type, bytes));
            }
            1 => {
                if data.len() - pos < 8 {
                    return Vec::new();
                }
                fields.push((field_num, wire_type, data[pos..pos + 8].to_vec()));
                pos += 8;
            }
            5 => {
                if data.len() - pos < 4 {
                    return Vec::new();
                }
                fields.push((field_num, wire_type, data[pos..pos + 4].to_vec()));
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
                    if is_deletion
                        || val.is_empty()
                        || val == "\"\""
                        || val == "deleted"
                        || val.len() < 10
                    {
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

    fn token_beat_token(binding: &[u8], proof: &[u8]) -> String {
        let mut token = Vec::new();
        encode_field_bytes(1, proof, &mut token);
        encode_field_bytes(3, binding, &mut token);
        encode_field_bytes(4, &[3], &mut token);
        base64::engine::general_purpose::STANDARD.encode(token)
    }

    fn token_beat_client() -> DouyinClient {
        const UID: u64 = 99191692311;
        let cookie = "sessionid=token-beat-offline-session";
        let client = DouyinClient::new(cookie, "token-beat-offline").unwrap();
        let key = super::super::pcim_guard::GuardKey::generate();
        let server_data = serde_json::to_vec(&serde_json::json!({
            "ticket": "offline-token-beat-ticket",
            "ts_sign": "ts.2.offline-token-beat",
            "client_cert": format!("pub.{}", key.public_key_base64())
        }))
        .unwrap();
        let material = key
            .bind_response(&server_data, UID, cookie, chrono::Utc::now().timestamp())
            .unwrap();
        let identity = token_beat_token(
            b"offline-device-binding-0001",
            b"offline-identity-proof-0001",
        );
        let mut context = super::super::im_auth::WebSessionContext::from_session(
            UID,
            cookie,
            &client.device().user_agent,
        )
        .unwrap()
        .with_identity(&serde_json::json!({
            "message": "success",
            "data": {
                "identity_security_token": identity,
                "device_id": "offline-token-beat-device"
            }
        }))
        .unwrap();
        context.guard_secret_hex = Some(key.to_hex());
        context.set_guard_material(&material).unwrap();
        client.set_web_context(context).unwrap();
        let aligned = super::super::pcim_guard::align_guard_cookie(
            cookie,
            &key.public_key_base64(),
            Some(&material),
        )
        .unwrap();
        *client.current_cookie.lock().unwrap() = aligned;
        client
    }

    fn token_beat_headers(token: &str) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "bd-ticket-guard-identity-token",
            header::HeaderValue::from_str(token).unwrap(),
        );
        headers
    }

    #[test]
    fn token_beat_response_atomically_refreshes_identity() {
        let client = token_beat_client();
        let before = client.web_context_snapshot().unwrap();
        let fresh = token_beat_token(
            b"offline-device-binding-0001",
            b"offline-identity-proof-0002",
        );
        client
            .apply_token_beat_response(
                &token_beat_headers(&fresh),
                br#"{"error_code":0,"error_name":"success"}"#,
            )
            .unwrap();
        let after = client.web_context_snapshot().unwrap();
        assert_ne!(
            serde_json::to_value(&before).unwrap()["envelope"],
            serde_json::to_value(&after).unwrap()["envelope"]
        );
        assert_eq!(after.identity_acquired_at.is_some(), true);
        assert_eq!(after.last_beat_at, after.identity_acquired_at);
        assert_eq!(client.verified_sender_uid(None).unwrap(), 99191692311);
    }

    #[test]
    fn token_beat_rejection_preserves_cookie_and_all_identity_material() {
        let client = token_beat_client();
        let before_cookie = client.get_current_cookie();
        let before_context = serde_json::to_value(client.web_context_snapshot().unwrap()).unwrap();
        let foreign = token_beat_token(
            b"offline-device-binding-9999",
            b"offline-identity-proof-0002",
        );
        assert!(
            client
                .apply_token_beat_response(
                    &token_beat_headers(&foreign),
                    br#"{"error_code":0,"error_name":"success"}"#,
                )
                .is_err()
        );
        assert_eq!(client.get_current_cookie(), before_cookie);
        assert_eq!(
            serde_json::to_value(client.web_context_snapshot().unwrap()).unwrap(),
            before_context
        );
        assert!(client.verified_sender_uid(None).is_err());
    }

    #[test]
    fn test_client_creation_and_cookie_stripping() {
        let cookie_raw = " sessionid=abc123xyz;\r\n passport_csrf_token=def456; \n";
        let client = DouyinClient::new(cookie_raw, "test_account").expect("create client");
        assert_eq!(
            client.get_current_cookie(),
            "sessionid=abc123xyz; passport_csrf_token=def456;"
        );
        assert_eq!(client.account_alias, "test_account");
    }

    #[test]
    fn test_client_creation_and_cookie_stripping_base() {
        let cookie_raw = " sessionid=abc123xyz;\r\n passport_csrf_token=def456; \n";
        let client = DouyinClient::new(cookie_raw, "test_account").expect("create client");
        assert_eq!(
            client.get_current_cookie(),
            "sessionid=abc123xyz; passport_csrf_token=def456;"
        );
        assert_eq!(client.account_alias, "test_account");
    }

    #[tokio::test]
    async fn local_cookie_check_uses_persisted_context_without_network_probe() {
        let device = super::super::device_profile::DeviceProfile::derive("local-check");
        let login_ts = chrono::Utc::now().timestamp();
        let cookie = format!(
            "sessionid=local-only; sid_guard=local|{login_ts}|3600|local; ttwid=local-device"
        );
        let client =
            DouyinClient::with_device_profile(&cookie, "local-check", device.clone()).unwrap();
        let context = super::super::im_auth::WebSessionContext::from_session_with_device(
            123456789,
            &cookie,
            &device.user_agent,
            Some(device.clone()),
        )
        .unwrap();
        client.set_web_context(context).unwrap();

        let result = client.check_cookie().await;
        assert!(matches!(
            result,
            CheckCookieResult::Valid(DouyinUserProfile { ref uid, .. }) if uid == "123456789"
        ));
        assert_eq!(
            client.verified_sender_uid(Some("123456789")).unwrap(),
            123456789
        );
    }

    #[tokio::test]
    async fn local_cookie_check_rejects_expired_sid_guard_before_any_request() {
        let device = super::super::device_profile::DeviceProfile::derive("expired-local-check");
        let cookie = "sessionid=expired-only; sid_guard=expired%7C1%7C1%7CFri";
        let client =
            DouyinClient::with_device_profile(cookie, "expired-local-check", device.clone())
                .unwrap();
        let context = super::super::im_auth::WebSessionContext::from_session_with_device(
            123456789,
            cookie,
            &device.user_agent,
            Some(device.clone()),
        )
        .unwrap();
        client.set_web_context(context).unwrap();

        assert!(matches!(
            client.check_cookie().await,
            CheckCookieResult::Expired(_)
        ));
        assert!(client.verified_sender_uid(None).is_err());
    }

    #[tokio::test]
    async fn local_cookie_check_does_not_fall_back_to_a_naked_request() {
        let client = DouyinClient::new("sessionid=context-missing", "missing-context").unwrap();
        let result = client.check_cookie().await;
        assert!(matches!(
            result,
            CheckCookieResult::NetworkError(ref message)
                if message.contains("SESSION_LOCAL_CONTEXT_MISSING")
                    && message.contains("未发起抖音请求")
        ));
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
        assert_eq!(
            DouyinClient::parse_friend_remark(&marked, "春风不语").as_deref(),
            Some("发小")
        );
        let alias = serde_json::json!({"alias": "老同学"});
        assert_eq!(
            DouyinClient::parse_friend_remark(&alias, "春风不语").as_deref(),
            Some("老同学")
        );
    }

    #[test]
    fn web_requests_carry_each_accounts_isolated_browser_profile() {
        let first_device = super::super::device_profile::DeviceProfile::derive("acc_web_first");
        let second_device = (0..128)
            .map(|index| {
                super::super::device_profile::DeviceProfile::derive(&format!(
                    "acc_web_second_{index}"
                ))
            })
            .find(|profile| {
                profile.sec_ch_ua != first_device.sec_ch_ua
                    || profile.sec_ch_ua_platform != first_device.sec_ch_ua_platform
            })
            .expect("应能派生不同浏览器提示组合");
        let first = DouyinClient::with_device_profile(
            "sessionid=offline-first",
            "first",
            first_device.clone(),
        )
        .unwrap();
        let second = DouyinClient::with_device_profile(
            "sessionid=offline-second",
            "second",
            second_device.clone(),
        )
        .unwrap();
        let url = "https://www.douyin.com/aweme/v1/web/user/profile/self/";
        let first_request = first
            .web_request(Method::GET, url)
            .unwrap()
            .build()
            .unwrap();
        let second_request = second
            .web_request(Method::GET, url)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            first_request.headers()[header::USER_AGENT],
            first_device.user_agent
        );
        assert_eq!(
            second_request.headers()[header::USER_AGENT],
            second_device.user_agent
        );
        assert_ne!(
            first_request.headers()[header::USER_AGENT],
            second_request.headers()[header::USER_AGENT]
        );
        assert_ne!(
            first_request.headers()["sec-ch-ua"],
            second_request.headers()["sec-ch-ua"]
        );
        assert_ne!(
            first_request.headers()["sec-ch-ua-platform"],
            second_request.headers()["sec-ch-ua-platform"]
        );
    }
}

#[cfg(test)]
mod send_identity_tests {
    use super::*;

    fn confirmed_client(cookie: &str) -> DouyinClient {
        let client = DouyinClient::new(cookie, "12345678").unwrap();
        assert!(
            client
                .confirm_profile(DouyinUserProfile {
                    uid: "99191692311".into(),
                    sec_uid: "sender_sec".into(),
                    nickname: "12345678".into(),
                    avatar_url: String::new(),
                })
                .is_valid()
        );
        client
    }

    fn bytes_field(data: &[u8], field: u32) -> Vec<u8> {
        parse_protobuf_fields(data)
            .into_iter()
            .find(|(f, w, _)| *f == field && *w == 2)
            .unwrap()
            .2
    }

    fn varint_field(data: &[u8], field: u32) -> u64 {
        let value = parse_protobuf_fields(data)
            .into_iter()
            .find(|(f, w, _)| *f == field && *w == 0)
            .unwrap()
            .2;
        read_varint(&value, 0).unwrap().0
    }
    #[test]
    fn send_path_is_checked_before_consuming_credential() {
        let cookie = "sessionid=offline-path-binding";
        let client = confirmed_client(cookie);
        client
            .set_send_credential(super::super::im_auth::test_credential(
                cookie,
                "0:1:55696816245:99191692311",
                1,
            ))
            .unwrap();
        for url in [
            "https://imapi.douyin.com/v1/message/get_by_conversation",
            "https://imapi.douyin.com/v1/message/send?x=1",
        ] {
            assert!(
                client
                    .build_send_request(
                        url,
                        99191692311,
                        None,
                        1,
                        "recipient",
                        55696816245,
                        "offline"
                    )
                    .is_err()
            );
            assert!(client.send_credential.lock().unwrap().is_some());
        }
        assert!(
            client
                .build_send_request(
                    "https://imapi.douyin.com/v1/message/send",
                    99191692311,
                    None,
                    1,
                    "recipient",
                    55696816245,
                    "offline"
                )
                .is_ok()
        );
        assert!(client.send_credential.lock().unwrap().is_none());
        assert!(
            client
                .build_send_request(
                    "https://imapi.douyin.com/v1/message/send",
                    99191692311,
                    None,
                    1,
                    "recipient",
                    55696816245,
                    "offline"
                )
                .is_err()
        );
    }

    #[test]
    fn actual_send_request_uses_confirmed_identity_and_session_auth() {
        for cookie in [
            "sessionid=test_session",
            "sessionid=test_session; user_uid=55696816245",
        ] {
            let client = confirmed_client(cookie);
            client
                .set_send_credential(super::super::im_auth::test_credential(
                    cookie,
                    "0:1:55696816245:99191692311",
                    1,
                ))
                .unwrap();
            assert_eq!(
                client.verified_sender_uid(Some("99191692311")).unwrap(),
                99191692311
            );
            let request = client
                .build_send_request(
                    "https://imapi.douyin.com/v1/message/send",
                    99191692311,
                    Some("0:1:55696816245:99191692311"),
                    1,
                    "recipient_sec",
                    55696816245,
                    "test",
                )
                .unwrap();
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(
                request.url().as_str(),
                "https://imapi.douyin.com/v1/message/send"
            );
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
            assert!(
                request
                    .headers()
                    .contains_key("bd-ticket-guard-client-data")
            );
            assert!(
                client
                    .build_send_request(
                        "http://127.0.0.1:1",
                        99191692311,
                        None,
                        1,
                        "recipient_sec",
                        55696816245,
                        "test"
                    )
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn missing_sender_fails_before_http_send_even_with_cookie_uid() {
        let client = DouyinClient::new("sessionid=test; user_uid=99191692311", "12345678").unwrap();
        let result = client
            .send_spark_message(None, 1, "recipient", Some("55696816245"), "test")
            .await;
        assert!(!result.success);
        assert!(result.message.contains("禁止发送"));
        assert!(client.verified_sender_uid(Some("99191692311")).is_err());
        assert!(
            client
                .build_send_request(
                    "http://127.0.0.1:1",
                    99191692311,
                    None,
                    1,
                    "recipient",
                    55696816245,
                    "test"
                )
                .is_err()
        );
    }

    #[test]
    fn mismatched_identity_or_conversation_is_rejected() {
        let client = confirmed_client("sessionid=identity-mismatch-offline");
        assert!(client.verified_sender_uid(Some("55696816245")).is_err());
        for expected in ["", "0", "invalid"] {
            assert!(client.verified_sender_uid(Some(expected)).is_err());
        }
        for (sender, target, conv) in [
            (55696816245, 55696816245, None),
            (99191692311, 0, None),
            (
                99191692311,
                55696816245,
                Some("0:1:55696816245:55696816245"),
            ),
        ] {
            assert!(
                client
                    .build_send_request(
                        "http://127.0.0.1:1",
                        sender,
                        conv,
                        1,
                        "recipient",
                        target,
                        "test"
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn group_send_keeps_group_identity_and_session_auth() {
        let client = confirmed_client("sessionid=test");
        client
            .set_send_credential(super::super::im_auth::test_credential(
                "sessionid=test",
                "7635702399042159110",
                2,
            ))
            .unwrap();
        let request = client
            .build_send_request(
                "https://imapi.douyin.com/v1/message/send",
                99191692311,
                Some("7635702399042159110"),
                2,
                "group",
                0,
                "test",
            )
            .unwrap();
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
        let result = client
            .send_spark_message(None, 1, "recipient", Some("55696816245"), "test")
            .await;
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
        for data in [
            b"".as_slice(),
            b"{\"status_code\":0}",
            b"<html>verify</html>",
            &[0x18, 0, 0x32, 0xff],
            &[0x18, 0, 0],
            &[0x18, 0, 0x80],
        ] {
            let (ok, code, message, _) = parse_im_send_response(data);
            assert!(!ok);
            assert!(is_fatal_send_error(code, &message));
        }
        assert!(read_varint(&[0xff; 11], 0).is_none());
        assert!(
            read_varint(
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02],
                0
            )
            .is_none()
        );
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
            let (ok, code, message, _) =
                parse_im_send_response(&response_with_inner_status(inner, check));
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
        let result = client
            .send_spark_message(None, 1, "recipient", Some("55696816245"), "test")
            .await;
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
        for value in [
            serde_json::json!({"message":"need verification"}),
            serde_json::json!({"data":{"description":"请完成安全验证"}}),
            serde_json::json!({"status_msg":"captcha required"}),
        ] {
            assert!(requires_security_verification(&value));
        }
        assert!(!requires_security_verification(
            &serde_json::json!({"message":"success"})
        ));
    }

    #[test]
    fn invalid_confirmed_uid_does_not_enable_sending() {
        let client = DouyinClient::new("sessionid=test", "12345678").unwrap();
        for uid in ["0", "", "invalid"] {
            assert!(
                !client
                    .confirm_profile(DouyinUserProfile {
                        uid: uid.into(),
                        sec_uid: "sec".into(),
                        nickname: "12345678".into(),
                        avatar_url: String::new()
                    })
                    .is_valid()
            );
            assert!(client.verified_sender_uid(Some("99191692311")).is_err());
        }
    }
}

#[cfg(test)]
mod history_and_cookie_tests {
    use super::*;
    fn history(messages: &[(Option<u64>, Option<u64>)], cursor: u64, more: bool) -> Vec<u8> {
        let mut payload = Vec::new();
        for (uid, time) in messages {
            let mut message = Vec::new();
            if let Some(uid) = uid {
                encode_field_varint(7, *uid, &mut message);
            }
            if let Some(time) = time {
                encode_field_varint(10, *time, &mut message);
            }
            encode_field_bytes(1, &message, &mut payload);
        }
        encode_field_varint(2, cursor, &mut payload);
        encode_field_varint(3, u64::from(more), &mut payload);
        wrap(&payload)
    }
    fn wrap(payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        encode_field_bytes(301, payload, &mut body);
        let mut env = Vec::new();
        encode_field_bytes(6, &body, &mut env);
        env
    }
    #[test]
    fn history_cursor_is_not_has_more_and_incoming_is_not_outgoing() {
        let now = chrono::Utc::now().timestamp() as u64;
        assert!(
            !parse_im_check_my_message_today(&history(&[(Some(2), Some(now))], 999, false), 1)
                .unwrap()
        );
        assert!(
            parse_im_check_my_message_today(&history(&[(Some(1), Some(now * 1000))], 999, true), 1)
                .unwrap()
        );
        assert!(
            parse_im_check_my_message_today(&history(&[(Some(2), Some(now))], 0, true), 1).is_err()
        );
        assert!(
            !parse_im_check_my_message_today(
                &history(&[(Some(2), Some(now - 2 * 86400))], 999, true),
                1
            )
            .unwrap()
        );
        assert!(parse_im_check_my_message_today(&history(&[], 999, true), 1).is_err());
        assert!(!parse_im_check_my_message_today(&history(&[], 999, false), 1).unwrap());
    }
    #[test]
    fn malformed_or_incomplete_history_never_means_not_sent() {
        let now = chrono::Utc::now().timestamp() as u64;
        for bytes in [
            history(&[(None, Some(now))], 0, false),
            history(&[(Some(2), None)], 0, false),
            history(&[(Some(2), Some(u64::MAX))], 0, false),
            wrap(&[0x80]),
            vec![],
        ] {
            assert!(parse_im_check_my_message_today(&bytes, 1).is_err());
        }
    }
    #[test]
    fn history_uses_cst_midnight_and_only_the_current_sender() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-15T00:00:01+08:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let midnight = (now.timestamp() - 1) as u64;
        for scale in [1, 1000] {
            assert!(
                !parse_im_check_my_message_today_at(
                    &history(&[(Some(1), Some((midnight - 1) * scale))], 0, false),
                    1,
                    now
                )
                .unwrap()
            );
            assert!(
                parse_im_check_my_message_today_at(
                    &history(&[(Some(1), Some(midnight * scale))], 0, false),
                    1,
                    now
                )
                .unwrap()
            );
            assert!(
                !parse_im_check_my_message_today_at(
                    &history(&[(Some(2), Some(midnight * scale))], 0, false),
                    1,
                    now
                )
                .unwrap()
            );
        }
    }
    #[test]
    fn internal_cookie_normalization_only_trims_transport_noise() {
        let raw = "  sessionid=offline; x=a=b\r\n";
        assert_eq!(extract_clean_cookie(raw), "sessionid=offline; x=a=b");
    }
}

#[cfg(test)]
mod conversation_response_tests {
    use super::*;
    fn response(core: &[u8]) -> Vec<u8> {
        let mut conv = Vec::new();
        encode_field_bytes(1, b"0:1:1:2", &mut conv);
        encode_field_varint(2, 123, &mut conv);
        encode_field_bytes(50, core, &mut conv);
        let mut list = Vec::new();
        encode_field_bytes(1, &conv, &mut list);
        let mut body = Vec::new();
        encode_field_bytes(610, &list, &mut body);
        let mut env = Vec::new();
        encode_field_bytes(6, &body, &mut env);
        env
    }
    #[test]
    fn malformed_core_or_spark_data_preserves_unknown_state() {
        for core in [vec![], vec![0x80]] {
            assert!(parse_im_conversation_list_response(&response(&core)).is_err());
        }
        let mut entry = Vec::new();
        encode_field_bytes(1, b"a:consecutive_chat_data", &mut entry);
        encode_field_bytes(2, b"not-json", &mut entry);
        let mut core = Vec::new();
        encode_field_bytes(11, &entry, &mut core);
        assert!(parse_im_conversation_list_response(&response(&core)).is_err());
        assert!(parse_im_conversation_list_response(&[]).is_err());
        let mut valid_core = Vec::new();
        encode_field_bytes(5, b"test-conversation", &mut valid_core);
        let map = parse_im_conversation_list_response(&response(&valid_core)).unwrap();
        assert_eq!(map["0:1:1:2"].days, 0);
        assert_eq!(map["0:1:1:2"].short_id, 123);
    }

    #[test]
    fn nonzero_business_status_is_reported_without_treating_payload_as_success() {
        let mut env = Vec::new();
        encode_field_varint(1, 610, &mut env);
        encode_field_varint(3, 1, &mut env);
        encode_field_bytes(4, "conversation unavailable".as_bytes(), &mut env);
        let error = parse_im_conversation_list_response(&env).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("status=1"));
        assert!(message.contains("conversation unavailable"));
    }
}

#[cfg(test)]
mod im_session_tests {
    use super::*;
    #[tokio::test]
    async fn identity_persistence_is_encrypted_account_bound_and_compare_and_swap() {
        let pool = crate::db::init_pool("sqlite::memory:").await.unwrap();
        let secret = crate::crypto::SecretBox::new(&[42; 32]);
        let cookie = "sessionid=PUBLIC-CAS-SESSION";
        let encrypted = secret.encrypt(cookie.as_bytes()).unwrap();
        let now = chrono::Utc::now();
        for id in ["selected", "other"] {
            crate::db::insert_account(
                &pool,
                &crate::model::Account {
                    id: id.into(),
                    alias: id.into(),
                    uid: Some("99191692311".into()),
                    sec_uid: None,
                    nickname: None,
                    avatar_url: None,
                    encrypted_cookie: encrypted.clone(),
                    status: "ACTIVE".into(),
                    bark_key_override: None,
                    last_checked_at: None,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();
        }
        let client = DouyinClient::new(cookie, "public-test").unwrap();
        let profile = DouyinUserProfile {
            uid: "99191692311".into(),
            sec_uid: "public".into(),
            nickname: "public".into(),
            avatar_url: "".into(),
        };
        assert!(client.confirm_profile(profile).is_valid());
        assert_eq!(client.im_history_status(Some("99191692311")).0, "AVAILABLE");
        assert!(client.send_credential.lock().unwrap().is_none());
        let context=super::super::im_auth::WebSessionContext::from_session(99191692311,cookie,"Test/1").unwrap()
            .with_identity(&serde_json::json!({"message":"success","data":{"identity_security_token":"PUBLIC-CAS-TOKEN","device_id":"PUBLIC-DEVICE"}})).unwrap();
        client.set_web_context(context).unwrap();
        let other = crate::db::get_account(&pool, "other")
            .await
            .unwrap()
            .unwrap();
        client
            .persist_im_session(&pool, &secret, "selected", &encrypted, Some("99191692311"))
            .await
            .unwrap();
        assert_eq!(
            crate::db::get_account(&pool, "other")
                .await
                .unwrap()
                .unwrap()
                .encrypted_cookie,
            other.encrypted_cookie
        );
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_context FROM account_web_contexts WHERE account_id='selected'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !stored
                .windows(b"PUBLIC-CAS-TOKEN".len())
                .any(|w| w == b"PUBLIC-CAS-TOKEN")
        );
        let decoded: super::super::im_auth::WebSessionContext =
            serde_json::from_slice(&secret.decrypt(&stored).unwrap()).unwrap();
        assert!(decoded.has_identity());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM account_im_credentials")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert!(
            client
                .persist_im_session(&pool, &secret, "selected", &encrypted, Some("99191692311"))
                .await
                .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT encrypted_context FROM account_web_contexts WHERE account_id='selected'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            stored
        );
        assert!(client.acquire_im_identity(Some("1")).await.is_err());
    }
}

#[cfg(test)]
#[path = "im_identity_tests.rs"]
mod im_identity_tests;

#[path = "session_auth.rs"]
pub mod session_auth;
