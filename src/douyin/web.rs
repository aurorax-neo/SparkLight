//! Web 请求统一入口：不生成签名，不跨路径复用安全头，不跟随验证重定向。
use super::*;
use reqwest::{Method, Request, RequestBuilder, StatusCode};
use std::sync::OnceLock;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const REQUEST_GAP: Duration = Duration::from_millis(350);
const READONLY_IM_GAP: Duration = Duration::from_millis(40);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Expired,
    Verify,
    Limited,
    Protocol,
    Network,
    Business,
}

#[derive(Debug)]
pub(crate) struct WebFailure {
    pub kind: FailureKind,
    pub message: &'static str,
}
impl std::fmt::Display for WebFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for WebFailure {}

#[derive(Default)]
struct SessionState {
    blocked: Option<(FailureKind, i64)>,
    next_request: Option<std::time::Instant>,
    gate: Arc<tokio::sync::Mutex<()>>,
}
fn sessions() -> &'static Mutex<HashMap<String, SessionState>> {
    static STATES: OnceLock<Mutex<HashMap<String, SessionState>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn endpoint(url: &reqwest::Url, method: &Method) -> Result<bool> {
    anyhow::ensure!(
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "禁止请求非官方 Web 地址"
    );
    let im = match (url.host_str(), url.path(), method.as_str()) {
        (
            Some("www.douyin.com"),
            "/passport/account/info/v2/"
            | "/passport/safe/get_identity_security_token/"
            | "/passport/token/beat/web/"
            | "/aweme/v1/web/user/profile/self/"
            | "/aweme/v1/web/user/profile/other/"
            | "/aweme/v1/web/im/spotlight/relation/"
            | "/aweme/v1/web/user/following/list/",
            "GET",
        ) => false,
        (
            Some("www.douyin.com"),
            "/aweme/v1/web/im/user/info/"
            | "/passport/ticket_guard/get_client_cert/"
            | "/passport/user_info/get_sec_ts/",
            "POST",
        ) => false,
        (
            Some("imapi.douyin.com"),
            "/v2/conversation/get_info_list"
            | "/v1/message/get_by_conversation"
            | "/v1/conversation/get_ticket"
            | "/v1/message/send",
            "POST",
        ) => true,
        _ => anyhow::bail!("未登记的抖音 Web 接口，禁止携带账号凭证请求"),
    };
    Ok(im)
}
fn failure(kind: FailureKind, message: &'static str) -> anyhow::Error {
    WebFailure { kind, message }.into()
}
fn failure_with_diagnostic(
    kind: FailureKind,
    message: &'static str,
    diagnostic: &str,
) -> anyhow::Error {
    anyhow::Error::new(WebFailure { kind, message }).context(diagnostic.to_string())
}

/// 网络诊断只保留请求阶段和错误类别，避免 URL 查询参数或响应内容进入日志。
fn reqwest_diagnostic(error: &reqwest::Error) -> String {
    let mut parts = Vec::new();
    if error.is_timeout() {
        parts.push("timeout");
    }
    if error.is_connect() {
        parts.push("connect");
    }
    if error.is_request() {
        parts.push("request");
    }
    if error.is_body() {
        parts.push("body");
    }
    if error.is_decode() {
        parts.push("decode");
    }
    if error.is_redirect() {
        parts.push("redirect");
    }
    let kind = if parts.is_empty() {
        "other".to_string()
    } else {
        parts.join(",")
    };
    error.status().map_or_else(
        || format!("REQWEST {kind}"),
        |status| format!("REQWEST {kind} HTTP {}", status.as_u16()),
    )
}

impl DouyinClient {
    fn session_key(&self) -> String {
        super::super::im_auth::session_hash(&self.get_current_cookie()).unwrap_or_default()
    }
    pub fn clear_session_block(&self) {
        let key = self.session_key();
        if !key.is_empty() {
            let mut states = sessions().lock().unwrap();
            if let Some(state) = states.get_mut(&key) {
                state.blocked = None;
            }
        }
        self.risk_limited.store(false, Ordering::Relaxed);
    }
    pub(crate) fn ensure_requests_allowed(&self) -> Result<()> {
        let key = self.session_key();
        anyhow::ensure!(!key.is_empty(), "缺少有效会话 Cookie，禁止请求");
        let now = chrono::Utc::now().timestamp();
        if let Some((kind, until)) = sessions().lock().unwrap().get(&key).and_then(|s| s.blocked) {
            if until > now {
                return Err(failure(
                    kind,
                    match kind {
                        FailureKind::Expired => "当前会话已失效，请重新登录后同步 Cookie",
                        FailureKind::Verify => "当前会话需安全验证，请在官方网页完成后同步新会话",
                        _ => "当前会话处于请求冷却期，请稍后检查，不自动重试",
                    },
                ));
            }
        }
        if self.risk_limited() {
            return Err(failure(
                FailureKind::Protocol,
                "当前客户端请求已停止，请检查官方登录态后再操作",
            ));
        }
        Ok(())
    }
    pub(crate) fn stop_requests(&self, kind: FailureKind) {
        self.risk_limited.store(true, Ordering::Relaxed);
        self.send_blocked.store(true, Ordering::Relaxed);
        *self.verified_uid.lock().unwrap() = None;
        self.clear_send_credential();
        let seconds = match kind {
            FailureKind::Expired | FailureKind::Verify => 24 * 3600,
            _ => 30 * 60,
        };
        let key = self.session_key();
        if !key.is_empty() {
            let mut states = sessions().lock().unwrap();
            states.retain(|_, s| {
                Arc::strong_count(&s.gate) > 1
                    || s.blocked
                        .is_some_and(|(_, until)| until > chrono::Utc::now().timestamp())
                    || s.next_request
                        .is_some_and(|next| next > std::time::Instant::now())
            });
            states.entry(key).or_default().blocked =
                Some((kind, chrono::Utc::now().timestamp() + seconds));
        }
    }
    pub(crate) fn web_request(&self, method: Method, url: &str) -> Result<RequestBuilder> {
        self.ensure_requests_allowed()?;
        let mut url = reqwest::Url::parse(url).context("Web 接口地址无效")?;
        let im = endpoint(&url, &method)?;
        // Web API 参数统一补齐；不猜测设备 ID 或生成 a_bogus/msToken。
        if !im {
            let pairs: HashMap<String, String> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            anyhow::ensure!(
                pairs.get("aid").is_none_or(|v| v == "6383"),
                "Web 应用号不符"
            );
            let passport = url.path().starts_with("/passport/");
            let mut q = url.query_pairs_mut();
            for (k, v) in [
                ("aid", "6383"),
                ("device_platform", "webapp"),
                ("channel", "channel_pc_web"),
                ("pc_client_type", "1"),
            ] {
                if !pairs.contains_key(k) && (!passport || k == "aid") {
                    q.append_pair(k, v);
                }
            }
        }
        Ok(self.build_web_request(method, url, im)?)
    }
    pub(crate) fn web_request_allow_probe(
        &self,
        method: Method,
        url: &str,
    ) -> Result<RequestBuilder> {
        let mut url = reqwest::Url::parse(url).context("Web 接口地址无效")?;
        let im = endpoint(&url, &method)?;
        if !im {
            let pairs: HashMap<String, String> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            anyhow::ensure!(
                pairs.get("aid").is_none_or(|v| v == "6383"),
                "Web 应用号不符"
            );
            let passport = url.path().starts_with("/passport/");
            let mut q = url.query_pairs_mut();
            for (k, v) in [
                ("aid", "6383"),
                ("device_platform", "webapp"),
                ("channel", "channel_pc_web"),
                ("pc_client_type", "1"),
            ] {
                if !pairs.contains_key(k) && (!passport || k == "aid") {
                    q.append_pair(k, v);
                }
            }
        }
        Ok(self.build_web_request(method, url, im)?)
    }
    /// 单一出口：同一账号只允许一套浏览器身份。已落库的 IM 上下文优先级更高，
    /// 因为身份 Token 与该次采集的设备绑定；没有上下文时使用账号设备指纹。
    fn build_web_request(
        &self,
        method: Method,
        url: reqwest::Url,
        im: bool,
    ) -> Result<RequestBuilder> {
        let context = self.web_context.lock().unwrap().clone();
        let (ua, sec_ch_ua, sec_ch_ua_mobile, sec_ch_ua_platform) = match context.as_ref() {
            Some(ctx) => (
                ctx.user_agent.clone(),
                ctx.sec_ch_ua().to_string(),
                ctx.sec_ch_ua_mobile().to_string(),
                ctx.sec_ch_ua_platform().to_string(),
            ),
            None => (
                self.device().user_agent.clone(),
                self.device().sec_ch_ua.clone(),
                self.device().sec_ch_ua_mobile.clone(),
                self.device().sec_ch_ua_platform.clone(),
            ),
        };
        let mut request = self
            .client
            .request(method.clone(), url)
            .header(header::COOKIE, self.get_current_cookie())
            .header(header::USER_AGENT, ua)
            .header(header::REFERER, self.device().referer_origin())
            .header("sec-ch-ua", sec_ch_ua)
            .header("sec-ch-ua-mobile", sec_ch_ua_mobile)
            .header("sec-ch-ua-platform", sec_ch_ua_platform)
            .header(
                "sec-fetch-site",
                if im { "same-site" } else { "same-origin" },
            );
        if im || method == Method::POST {
            request = request.header(header::ORIGIN, "https://www.douyin.com");
        }
        Ok(request)
    }
    async fn pace_request_with_gap(&self, gap: Duration) -> Result<()> {
        self.ensure_requests_allowed()?;
        let key = self.session_key();
        let delay = {
            let now = std::time::Instant::now();
            let mut states = sessions().lock().unwrap();
            let state = states.entry(key).or_default();
            let slot = state.next_request.unwrap_or(now).max(now);
            state.next_request = Some(slot + gap);
            slot.saturating_duration_since(now)
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.ensure_requests_allowed()
    }
    #[cfg(test)]
    pub(crate) async fn test_lock_web_session(&self) -> tokio::sync::OwnedMutexGuard<()> {
        let gate = sessions()
            .lock()
            .unwrap()
            .entry(self.session_key())
            .or_default()
            .gate
            .clone();
        gate.lock_owned().await
    }
    pub(crate) async fn execute_web(
        &self,
        request: Request,
    ) -> Result<(header::HeaderMap, Vec<u8>, tokio::sync::OwnedMutexGuard<()>)> {
        self.execute_web_inner(request, None, true).await
    }
    pub(crate) async fn execute_web_initial(
        &self,
        request: Request,
        initial: &session_auth::pcim_init::InitialSubmission<'_>,
    ) -> Result<(header::HeaderMap, Vec<u8>, tokio::sync::OwnedMutexGuard<()>)> {
        self.execute_web_inner(request, Some(initial), true).await
    }
    pub(crate) async fn execute_web_token_beat(
        &self,
        request: Request,
    ) -> Result<(header::HeaderMap, Vec<u8>, tokio::sync::OwnedMutexGuard<()>)> {
        // TokenBeat 是低频自愈请求。单次 403、协议异常或读取失败只说明本次
        // 续期未完成，不能据此把仍然可用的登录会话封禁 30 分钟或 24 小时。
        self.execute_web_inner(request, None, false).await
    }
    async fn execute_web_inner(
        &self,
        mut request: Request,
        initial: Option<&session_auth::pcim_init::InitialSubmission<'_>>,
        stop_on_failure: bool,
    ) -> Result<(header::HeaderMap, Vec<u8>, tokio::sync::OwnedMutexGuard<()>)> {
        let key = self.session_key();
        let gate = sessions()
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .gate
            .clone();
        let guard = gate.lock_owned().await;
        endpoint(request.url(), request.method())?;
        let is_readonly_im = !cfg!(test)
            && initial.is_none()
            && matches!(
                request.url().path(),
                "/v2/conversation/get_info_list" | "/v1/message/get_by_conversation"
            );
        self.pace_request_with_gap(if is_readonly_im {
            READONLY_IM_GAP
        } else {
            REQUEST_GAP
        })
        .await?;
        let current_cookie = self.get_current_cookie();
        let original_cookie = request
            .headers()
            .get(header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .context("请求缺少会话 Cookie")?;
        anyhow::ensure!(
            super::super::im_auth::session_hash(original_cookie)?
                == super::super::im_auth::session_hash(&current_cookie)?,
            "请求排队期间会话已变化，停止请求"
        );
        if let Some(initial) = initial {
            initial.refresh_request(self, &mut request)?;
        } else {
            let cookie = if original_cookie.contains("bd_ticket_guard_client_data=") {
                original_cookie.to_string()
            } else {
                current_cookie
            };
            request.headers_mut().insert(
                header::COOKIE,
                header::HeaderValue::from_str(&cookie).context("Cookie HTTP 格式无效")?,
            );
        }
        if request.url().path() == "/v1/message/send" {
            self.validate_send_history(&request)?;
            if let Some(initial) = initial {
                initial.claim().await?;
            } else {
                anyhow::ensure!(
                    self.pcim_initial.lock().unwrap().is_none(),
                    "初始化分支禁止回退旧发送授权"
                );
                self.claim_send_authorization().await?;
            }
            // 原子占用提交后不持有数据库事务跨网络；排队/数据库等待跨日仍拒绝发送。
            self.validate_send_history(&request)?;
            if let Some(initial) = initial {
                initial.refresh_request(self, &mut request)?;
            }
        }
        #[cfg(test)]
        if super::im_identity_tests::active() {
            super::im_identity_tests::observe(&request);
            let bytes = super::im_identity_tests::respond(request.url().path())?;
            let headers = super::im_identity_tests::response_headers(request.url().path());
            return Ok((headers, bytes, guard));
        }
        #[cfg(test)]
        anyhow::ensure!(!cfg!(test), "OFFLINE_TEST_NO_MOCK: 测试禁止回退真实网络");
        let guard = if is_readonly_im {
            drop(guard);
            Arc::new(tokio::sync::Mutex::new(())).lock_owned().await
        } else {
            guard
        };
        let mut response = self.client.execute(request).await.map_err(|error| {
            failure_with_diagnostic(
                FailureKind::Network,
                "Web 网络请求失败，未自动重试",
                &reqwest_diagnostic(&error),
            )
        })?;
        let status = response.status();
        let response_headers = response.headers().clone();
        if let Some(kind) = http_failure(status, &response_headers) {
            if stop_on_failure {
                self.stop_requests(kind);
            }
            return Err(failure(
                kind,
                match kind {
                    FailureKind::Expired => "Web 登录态被拒绝，请重新登录",
                    FailureKind::Limited => "Web 请求被限流，已停止当前会话请求",
                    _ => "Web 要求安全验证或跳转，已停止请求",
                },
            ));
        }
        if !status.is_success() {
            return Err(failure_with_diagnostic(
                FailureKind::Network,
                "Web 服务暂不可用，未自动重试",
                &format!("HTTP {}", status.as_u16()),
            ));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            if stop_on_failure {
                self.stop_requests(FailureKind::Protocol);
            }
            return Err(failure(
                FailureKind::Protocol,
                "Web 响应超出安全上限，停止请求",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            failure(
                FailureKind::Network,
                "Web 响应读取失败，结果未知，禁止发送重试",
            )
        })? {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                if stop_on_failure {
                    self.stop_requests(FailureKind::Protocol);
                }
                return Err(failure(
                    FailureKind::Protocol,
                    "Web 响应超出安全上限，停止请求",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        // Cookie 仅在业务及协议校验通过后合并。
        Ok((response_headers, bytes, guard))
    }
    pub(super) fn merge_response_headers(&self, headers: &header::HeaderMap) {
        let initial = self.pcim_initial.lock().unwrap().is_some();
        let set: Vec<_> = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .filter(|value| {
                !initial
                    || !session_auth::pcim_init::old_guard(value.split('=').next().unwrap_or(""))
            })
            .collect();
        let mut cookie = self.current_cookie.lock().unwrap();
        let (updated, set_cookie_changed) = merge_cookies(&cookie, &set);
        if set_cookie_changed {
            *cookie = updated;
        }
        let mut changed = set_cookie_changed;

        // 服务端每轮响应都可能轮转 Guard 材料。材料、公钥与 crypt cookie 必须原子对齐，
        // 否则下一次签名发送会被平台识别为凭证分叉并注销整个会话。
        if let Some(server_data_b64) = super::extract_server_data_from_headers(headers) {
            use base64::Engine;
            let raw_bytes = base64::engine::general_purpose::STANDARD
                .decode(&server_data_b64)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&server_data_b64))
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(&server_data_b64)
                })
                .ok();
            if let Some(bytes) = raw_bytes {
                if let Ok(srv_json_str) = String::from_utf8(bytes) {
                    let mut context = self.web_context.lock().unwrap();
                    if let Some(ctx) = context.as_mut() {
                        if let Ok(Some(key)) = ctx.get_guard_key() {
                            let public_key = key.public_key_base64();
                            let acquired_at = chrono::Utc::now().timestamp();
                            if let Ok(material) =
                                crate::douyin::pcim_guard::BoundGuardMaterial::from_saved(
                                    &srv_json_str,
                                    ctx.uid,
                                    &cookie,
                                    acquired_at,
                                    &public_key,
                                )
                            {
                                if let Ok(aligned) = crate::douyin::pcim_guard::align_guard_cookie(
                                    &cookie,
                                    &public_key,
                                    Some(&material),
                                ) {
                                    if aligned != *cookie {
                                        *cookie = aligned;
                                        changed = true;
                                    }
                                    ctx.set_guard_material(&material).ok();
                                    tracing::info!(account = %self.account_alias, "已对齐最新 Guard 材料与 _bd_ticket_crypt_cookie，完成票据自愈");
                                }
                            }
                        }
                    }
                }
            }
        }
        if changed {
            *self.cookie_changed.lock().unwrap() = true;
        }

        let session_changed = self.web_context.lock().unwrap().as_ref().is_some_and(|c| {
            super::super::im_auth::session_hash(&cookie).ok().as_ref() != Some(&c.session_hash)
        });
        drop(cookie);
        if session_changed {
            self.stop_requests(FailureKind::Protocol);
        }
    }
    pub(crate) async fn web_json(&self, request: RequestBuilder) -> Result<Value> {
        self.web_json_inner(request, true).await
    }
    pub(crate) async fn web_json_auxiliary(&self, request: RequestBuilder) -> Result<Value> {
        self.web_json_inner(request, false).await
    }
    async fn web_json_inner(
        &self,
        request: RequestBuilder,
        stop_on_failure: bool,
    ) -> Result<Value> {
        // web_json 在构建请求前已经通过 web_request 做了冷却门禁；这里用原始
        // 请求直入执行器，避免把辅助模式误当成主链路而重复写冷却。
        let request = request.build().context("无法构造 Web 请求")?;
        let (headers, bytes, _guard) = self
            .execute_web_inner(request, None, stop_on_failure)
            .await?;
        self.process_web_json(&headers, &bytes, stop_on_failure)
    }
    fn process_web_json(
        &self,
        headers: &header::HeaderMap,
        bytes: &[u8],
        stop_on_failure: bool,
    ) -> Result<Value> {
        let json = match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) if v.is_object() => v,
            _ => {
                if stop_on_failure {
                    self.stop_requests(FailureKind::Protocol);
                }
                return Err(failure(
                    FailureKind::Protocol,
                    "Web 返回非 JSON 或异常报文，停止请求，不判定 Cookie 失效",
                ));
            }
        };
        if let Err(error) = validate_json(&json) {
            if let Some(e) = error.downcast_ref::<WebFailure>() {
                if stop_on_failure && e.kind != FailureKind::Business {
                    self.stop_requests(e.kind);
                }
            }
            return Err(error);
        }
        self.merge_response_headers(headers);
        Ok(json)
    }
    pub(crate) async fn web_im(&self, url: &str, command: u32, body: &[u8]) -> Result<Vec<u8>> {
        self.web_im_inner(url, command, body, true).await
    }

    /// 只读 IM 查询失败只让当前查询未确认，不能把同一登录会话锁进主发送冷却。
    pub(crate) async fn web_im_auxiliary(
        &self,
        url: &str,
        command: u32,
        body: &[u8],
    ) -> Result<Vec<u8>> {
        self.web_im_inner(url, command, body, false).await
    }

    async fn web_im_inner(
        &self,
        url: &str,
        command: u32,
        body: &[u8],
        stop_on_failure: bool,
    ) -> Result<Vec<u8>> {
        self.ensure_requests_allowed()?;
        let diagnostic_variant = std::env::var("SPARK_IM610_DIAG_VARIANT").ok();
        let (include_identity, include_guard) = match diagnostic_variant.as_deref() {
            None | Some("identity_guard") => (true, true),
            Some("identity") => (true, false),
            Some("session") => (false, false),
            Some("guard") => (false, true),
            Some("session_flow") => (false, false),
            Some(other) => anyhow::bail!("未知的 IM 诊断变体: {other}"),
        };
        let include_flow_tag = diagnostic_variant.as_deref() == Some("session_flow");
        let include_identity = include_identity && !include_flow_tag;
        let include_guard = include_guard && !include_flow_tag;
        let context = self
            .web_context
            .lock()
            .unwrap()
            .clone()
            .context("缺少官方 Web IM 上下文，需同步当前账号凭证，禁止请求")?;
        let uid = self.verified_sender_uid(Some(&context.uid.to_string()))?;
        let mut envelope = context.im_request(uid, &self.get_current_cookie(), command, body)?;
        if include_flow_tag {
            append_protobuf_header(&mut envelope, "flow-tag", "new");
        }
        if !include_identity {
            strip_im_identity_headers(&mut envelope);
        }
        if let Some(variant) = diagnostic_variant.as_deref() {
            let headers = parse_protobuf_fields(&envelope)
                .into_iter()
                .filter(|(number, wire, _)| *number == 15 && *wire == 2)
                .filter_map(|(_, _, value)| {
                    let fields = parse_protobuf_fields(&value);
                    let key = fields
                        .iter()
                        .find(|(number, wire, _)| *number == 1 && *wire == 2)
                        .and_then(|(_, _, value)| std::str::from_utf8(value).ok());
                    key.map(str::to_owned)
                })
                .collect::<Vec<_>>()
                .join(",");
            tracing::warn!(
                command,
                variant,
                include_identity,
                include_guard,
                envelope_headers = %headers,
                "IM 诊断请求变体"
            );
        }
        let mut request = self
            .web_request(Method::POST, url)?
            .header(header::CONTENT_TYPE, "application/x-protobuf")
            .header(header::ACCEPT, "application/x-protobuf")
            .body(envelope)
            .build()?;
        if include_guard {
            // 发送路径受 TicketGuard 保护。诊断环境可单独关闭它，验证只读 610
            // 是否应沿用 SESSION_AUTH 而不携带发送身份材料。
            let timestamp = self
                .get_trusted_timestamp(uid)
                .await
                .unwrap_or_else(|_| chrono::Utc::now().timestamp());
            // 拉取授信时间可能轮转 Guard 材料，签名前必须重新取快照。
            let (key, material) = self
                .ensure_guard_bound()
                .await
                .context("Web IM Guard 票据不可用，本次查询未确认，禁止发送重试")?;
            let aligned_cookie = super::super::pcim_guard::align_guard_cookie(
                &self.get_current_cookie(),
                &material.public,
                Some(&material),
            )?;
            let mode = if material.data.ts_sign.starts_with("ts.1") {
                super::super::pcim_guard::GuardMode::Ecdsa
            } else {
                super::super::pcim_guard::GuardMode::Hmac {
                    server_spki_der: super::super::pcim_guard::OFFICIAL_SERVER_SPKI_DER,
                }
            };
            let guard_headers = key.sign_path(
                &material,
                request.url().path(),
                uid,
                &aligned_cookie,
                timestamp,
                mode,
            )?;
            request.headers_mut().insert(
                header::COOKIE,
                header::HeaderValue::from_str(&aligned_cookie).context("Web IM Cookie 格式无效")?,
            );
            for (name, value) in guard_headers {
                if let Some(name) = name {
                    request.headers_mut().insert(name, value);
                }
            }
        }
        let (headers, bytes, _guard) = self
            .execute_web_inner(request, None, stop_on_failure)
            .await?;
        if std::env::var_os("SPARK_DEBUG_IM").is_some() {
            let fields = parse_protobuf_fields(&bytes);
            let response_command = fields
                .iter()
                .find(|(n, w, _)| *n == 1 && *w == 0)
                .and_then(|(_, _, v)| read_varint(v, 0).map(|(v, _)| v));
            let status = fields
                .iter()
                .find(|(n, w, _)| *n == 3 && *w == 0)
                .and_then(|(_, _, v)| read_varint(v, 0).map(|(v, _)| v as i32));
            let error_desc = fields
                .iter()
                .find(|(n, w, _)| *n == 4 && *w == 2)
                .map(|(_, _, v)| String::from_utf8_lossy(v).to_string())
                .map(|v| {
                    v.chars()
                        .filter(|c| !c.is_control())
                        .take(160)
                        .collect::<String>()
                })
                .unwrap_or_default();
            let top_fields = fields
                .iter()
                .map(|(n, w, _)| format!("{n}:{w}"))
                .collect::<Vec<_>>()
                .join(",");
            tracing::warn!(
                endpoint = url,
                expected_command = command,
                response_len = bytes.len(),
                response_command = ?response_command,
                response_status = ?status,
                response_error_desc = %error_desc,
                top_fields = %top_fields,
                "IM 诊断响应结构"
            );
        }
        if let Err(e) = validate_im_response(&bytes, command) {
            if stop_on_failure {
                self.stop_requests(
                    e.downcast_ref::<WebFailure>()
                        .map(|e| e.kind)
                        .unwrap_or(FailureKind::Protocol),
                );
            }
            return Err(e);
        }
        self.merge_response_headers(&headers);
        Ok(bytes)
    }
    pub(crate) fn check_failure(error: anyhow::Error) -> CheckCookieResult {
        match error.downcast_ref::<WebFailure>().map(|e| e.kind) {
            Some(FailureKind::Expired) => {
                CheckCookieResult::Expired("SESSION_EXPIRED: 登录会话已失效".into())
            }
            Some(FailureKind::Verify) => CheckCookieResult::NeedVerify(
                "SESSION_VERIFY_REQUIRED: 当前会话需要安全验证".into(),
            ),
            Some(FailureKind::Limited) => CheckCookieResult::NetworkError(
                "SESSION_LIMITED: 当前会话被限流，未确认登录态".into(),
            ),
            Some(FailureKind::Protocol) => CheckCookieResult::NetworkError(
                "SESSION_PROTOCOL: 响应协议异常，未确认登录态".into(),
            ),
            Some(FailureKind::Business) => CheckCookieResult::NetworkError(
                "SESSION_BUSINESS: 业务响应未成功，未确认登录态".into(),
            ),
            Some(FailureKind::Network) => CheckCookieResult::NetworkError(
                "SESSION_NETWORK: 网络请求未完成，未确认登录态".into(),
            ),
            None => CheckCookieResult::NetworkError(
                "SESSION_UNCONFIRMED: 本地处理或响应异常，未确认登录态".into(),
            ),
        }
    }
}

fn http_failure(status: StatusCode, headers: &header::HeaderMap) -> Option<FailureKind> {
    if status == StatusCode::UNAUTHORIZED {
        Some(FailureKind::Expired)
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        Some(FailureKind::Limited)
    } else if status == StatusCode::FORBIDDEN
        || status.is_redirection()
        || headers.contains_key("x-tt-verify-id")
        || headers.contains_key("x-verify-code")
        || headers.contains_key("x-tt-verify-passport-decision")
        || headers.contains_key("x-vc-bdturing-parameters")
    {
        Some(FailureKind::Verify)
    } else if headers.contains_key("x-tt-identity-zt-err") {
        Some(FailureKind::Protocol)
    } else {
        None
    }
}
fn json_code(json: &Value) -> Option<i64> {
    let codes = [
        json.get("status_code"),
        json.get("error_code"),
        json.get("data").and_then(|d| d.get("error_code")),
    ];
    let parsed: Vec<_> = codes
        .into_iter()
        .flatten()
        .filter_map(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .collect();
    parsed
        .iter()
        .copied()
        .find(|c| matches!(c, 2154 | 2483 | 401 | 429))
        .or_else(|| parsed.iter().copied().find(|c| *c != 0))
        .or_else(|| parsed.first().copied())
}
fn strip_im_identity_headers(envelope: &mut Vec<u8>) {
    let mut cleaned = Vec::with_capacity(envelope.len());
    for (number, wire, value) in parse_protobuf_fields(envelope) {
        if number == 15 && wire == 2 {
            let header = parse_protobuf_fields(&value);
            let key = header
                .iter()
                .find(|(n, w, _)| *n == 1 && *w == 2)
                .and_then(|(_, _, bytes)| std::str::from_utf8(bytes).ok());
            if matches!(
                key,
                Some(
                    "identity_security_token"
                        | "identity_security_device_id"
                        | "identity_security_aid"
                )
            ) {
                continue;
            }
        }
        append_protobuf_field(number, wire, &value, &mut cleaned);
    }
    *envelope = cleaned;
}
fn append_protobuf_header(envelope: &mut Vec<u8>, key: &str, value: &str) {
    let mut header = Vec::new();
    encode_field_bytes(1, key.as_bytes(), &mut header);
    encode_field_bytes(2, value.as_bytes(), &mut header);
    encode_field_bytes(15, &header, envelope);
}
fn append_protobuf_field(number: u32, wire: u8, value: &[u8], out: &mut Vec<u8>) {
    match wire {
        0 => {
            if let Some((value, _)) = read_varint(value, 0) {
                encode_field_varint(number, value, out);
            }
        }
        1 | 5 => {
            encode_varint((u64::from(number) << 3) | u64::from(wire), out);
            out.extend_from_slice(value);
        }
        2 => encode_field_bytes(number, value, out),
        _ => {}
    }
}
pub(crate) fn validate_json(json: &Value) -> Result<()> {
    let code = json_code(json);
    let message = [
        json.get("message"),
        json.get("status_msg"),
        json.get("description"),
        json.get("data").and_then(|d| d.get("description")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    if requires_security_verification(json) || matches!(code, Some(2154 | 2483)) {
        return Err(failure(
            FailureKind::Verify,
            "Web 要求安全验证，停止当前会话请求",
        ));
    }
    if ["频繁", "风控", "限流", "too many", "rate limit"]
        .iter()
        .any(|s| message.contains(s))
        || code == Some(429)
    {
        return Err(failure(
            FailureKind::Limited,
            "Web 请求受限，停止当前会话请求",
        ));
    }
    let login_expired = code == Some(13)
        && ["login", "登录"].iter().any(|s| message.contains(s))
        && ["expir", "过期", "失效"]
            .iter()
            .any(|s| message.contains(s));
    if login_expired
        || code == Some(401)
        || [
            "未登录",
            "登录失效",
            "登录过期",
            "login required",
            "not login",
            "session expired",
        ]
        .iter()
        .any(|s| message.contains(s))
    {
        return Err(failure(FailureKind::Expired, "Web 会话未登录或已失效"));
    }
    if code == Some(0)
        || (code.is_none() && json.get("message").and_then(Value::as_str) == Some("success"))
    {
        return Ok(());
    }
    Err(failure(
        if code.is_some() {
            FailureKind::Business
        } else {
            FailureKind::Protocol
        },
        "Web 业务响应未确认成功，保留原数据，停止当前操作",
    ))
}
fn validate_im_response(bytes: &[u8], command: u32) -> Result<()> {
    if matches!(
        bytes.iter().copied().find(|b| !b.is_ascii_whitespace()),
        Some(b'{' | b'[' | b'<')
    ) {
        return Err(failure(
            FailureKind::Protocol,
            "IM 返回非 Protobuf 响应，停止请求",
        ));
    }
    let fields = parse_protobuf_fields(bytes);
    let int = |n| {
        fields
            .iter()
            .find(|(k, w, _)| *k == n && *w == 0)
            .and_then(|(_, _, v)| read_varint(v, 0).map(|(v, _)| v))
    };
    if int(1) != Some(command as u64) || int(3).is_none() {
        return Err(failure(
            FailureKind::Protocol,
            "IM 响应命令或状态不完整，保留原数据",
        ));
    }
    let status = int(3).unwrap() as i32 as i64;
    if status != 0 {
        let desc = fields
            .iter()
            .find(|(n, w, _)| *n == 4 && *w == 2)
            .map(|(_, _, v)| String::from_utf8_lossy(v).to_ascii_lowercase())
            .unwrap_or_default();
        let kind = if status == 401 {
            FailureKind::Expired
        } else if ["verify", "captcha", "验证"]
            .iter()
            .any(|s| desc.contains(s))
            || matches!(status, 2154 | 2483 | 403)
        {
            FailureKind::Verify
        } else {
            FailureKind::Protocol
        };
        return Err(failure(
            kind,
            "IM 业务响应失败，停止当前会话请求，保留原数据",
        ));
    }
    let body = fields
        .iter()
        .find(|(n, w, _)| *n == 6 && *w == 2)
        .context("IM 响应缺少请求结果")?;
    let inner = parse_protobuf_fields(&body.2);
    let payload = inner
        .iter()
        .find(|(n, w, _)| *n == command && *w == 2)
        .context("IM 响应缺少对应命令结果")?;
    anyhow::ensure!(
        payload.2.is_empty() || !parse_protobuf_fields(&payload.2).is_empty(),
        "IM 命令结果截断或格式异常"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> DouyinClient {
        DouyinClient::new(
            &format!("sessionid=offline-{}", uuid::Uuid::new_v4()),
            "test",
        )
        .unwrap()
    }
    #[test]
    fn request_context_uses_current_cookie_and_correct_origin() {
        let c = client();
        let cookie = c.get_current_cookie();
        let credential = super::super::super::im_auth::test_credential(
            &cookie,
            "0:1:55696816245:99191692311",
            1,
        );
        c.set_send_credential(credential).unwrap();
        *c.current_cookie.lock().unwrap() = format!("{cookie}; ttwid=refreshed");
        let web = c
            .web_request(
                Method::GET,
                "https://www.douyin.com/aweme/v1/web/user/profile/self/",
            )
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(web.headers()[header::COOKIE], c.get_current_cookie());
        assert_eq!(web.headers()[header::USER_AGENT], "TestBrowser/155");
        assert_eq!(web.headers()["sec-fetch-site"], "same-origin");
        assert!(!web.headers().contains_key("bd-ticket-guard-client-data"));
        assert!(
            web.url()
                .query_pairs()
                .any(|(k, v)| k == "aid" && v == "6383")
        );
        let im = c
            .web_request(
                Method::POST,
                "https://imapi.douyin.com/v1/message/get_by_conversation",
            )
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(im.headers()["sec-fetch-site"], "same-site");
        assert_eq!(im.headers()[header::ORIGIN], "https://www.douyin.com");
        assert!(!im.headers().contains_key("bd-ticket-guard-client-data"));
    }
    #[test]
    fn credentials_never_go_to_external_or_unregistered_endpoints() {
        let c = client();
        for url in [
            "http://www.douyin.com/aweme/v1/web/user/profile/self/",
            "https://www.douyin.com.evil.test/aweme/v1/web/user/profile/self/",
            "https://www.douyin.com:8443/aweme/v1/web/user/profile/self/",
            "https://evil@www.douyin.com/aweme/v1/web/user/profile/self/",
            "https://www.douyin.com/not-registered",
            "https://www.douyin.com/aweme/v1/web/user/profile/self/?aid=1128",
        ] {
            assert!(c.web_request(Method::GET, url).is_err());
        }
        let token_beat = "https://www.douyin.com/passport/token/beat/web/?scene=boot";
        assert!(c.web_request(Method::GET, token_beat).is_ok());
        assert!(c.web_request(Method::POST, token_beat).is_err());
    }
    #[test]
    fn risk_blocks_new_clients_for_same_session_but_not_other_accounts() {
        let a = client();
        let b = DouyinClient::new(&a.get_current_cookie(), "same-session").unwrap();
        let other = client();
        a.stop_requests(FailureKind::Limited);
        assert!(a.ensure_requests_allowed().is_err());
        assert!(b.ensure_requests_allowed().is_err());
        assert!(other.ensure_requests_allowed().is_ok());
        assert!(a.sending_blocked());
        let failure = b.ensure_requests_allowed().unwrap_err();
        assert!(matches!(
            DouyinClient::check_failure(failure),
            CheckCookieResult::NetworkError(_)
        ));
    }
    #[tokio::test]
    async fn auxiliary_request_failure_does_not_block_primary_session() {
        let a = client();
        let b = DouyinClient::new(&a.get_current_cookie(), "same-session").unwrap();
        let _request = a
            .web_request(
                Method::GET,
                "https://www.douyin.com/aweme/v1/web/im/spotlight/relation/",
            )
            .unwrap();
        let result = a.process_web_json(
            &header::HeaderMap::new(),
            b"<html>rate limited</html>",
            false,
        );
        assert!(result.is_err());
        assert!(b.ensure_requests_allowed().is_ok());
    }
    #[test]
    fn http_errors_have_distinct_risk_meanings() {
        let h = header::HeaderMap::new();
        assert_eq!(
            http_failure(StatusCode::UNAUTHORIZED, &h),
            Some(FailureKind::Expired)
        );
        assert_eq!(
            http_failure(StatusCode::FORBIDDEN, &h),
            Some(FailureKind::Verify)
        );
        assert_eq!(
            http_failure(StatusCode::FOUND, &h),
            Some(FailureKind::Verify)
        );
        assert_eq!(
            http_failure(StatusCode::TOO_MANY_REQUESTS, &h),
            Some(FailureKind::Limited)
        );
        assert_eq!(http_failure(StatusCode::SERVICE_UNAVAILABLE, &h), None);
    }
    #[test]
    fn identity_endpoint_is_exact_get_and_security_headers_stop_requests() {
        let c = client();
        let url = "https://www.douyin.com/passport/safe/get_identity_security_token/";
        assert!(c.web_request(Method::GET, url).is_ok());
        assert!(c.web_request(Method::POST, url).is_err());
        assert!(
            c.web_request(Method::GET, &format!("{url}?aid=1128"))
                .is_err()
        );
        for name in ["x-tt-verify-passport-decision", "x-vc-bdturing-parameters"] {
            let mut headers = header::HeaderMap::new();
            headers.insert(name, header::HeaderValue::from_static("PUBLIC"));
            assert_eq!(
                http_failure(StatusCode::OK, &headers),
                Some(FailureKind::Verify)
            );
        }
    }
    #[test]
    fn trusted_time_endpoint_is_registered_as_post_only() {
        let c = client();
        let url =
            "https://www.douyin.com/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1";
        assert!(c.web_request(Method::POST, url).is_ok());
        assert!(c.web_request(Method::GET, url).is_err());
        assert!(
            c.web_request(
                Method::POST,
                "https://www.douyin.com/passport/user_info/get_sec_ts/?aid=1128"
            )
            .is_err()
        );
    }

    #[test]
    fn strip_identity_headers_preserves_other_envelope_fields() {
        let mut envelope = Vec::new();
        encode_field_varint(1, 610, &mut envelope);
        for (key, value) in [
            ("identity_security_token", "PUBLIC-TOKEN"),
            ("identity_security_device_id", "PUBLIC-DEVICE"),
            ("session_aid", "6383"),
            ("identity_security_aid", "6383"),
            ("flow-tag", "new"),
        ] {
            let mut header = Vec::new();
            encode_field_bytes(1, key.as_bytes(), &mut header);
            encode_field_bytes(2, value.as_bytes(), &mut header);
            encode_field_bytes(15, &header, &mut envelope);
        }
        encode_field_bytes(6, b"PUBLIC-BODY", &mut envelope);
        encode_field_bytes(9, b"0", &mut envelope);

        strip_im_identity_headers(&mut envelope);

        let fields = parse_protobuf_fields(&envelope);
        assert_eq!(
            fields.iter().filter(|(number, _, _)| *number == 15).count(),
            2
        );
        assert_eq!(
            fields
                .iter()
                .filter(|(number, wire, _)| *number == 1 && *wire == 0)
                .filter_map(|(_, _, value)| read_varint(value, 0))
                .map(|(value, _)| value)
                .collect::<Vec<_>>(),
            vec![610]
        );
        assert!(fields.iter().any(|(number, wire, value)| {
            *number == 6 && *wire == 2 && value == b"PUBLIC-BODY"
        }));
        assert!(
            fields
                .iter()
                .any(|(number, wire, value)| *number == 9 && *wire == 2 && value == b"0")
        );
        let keys = fields
            .iter()
            .filter(|(number, wire, _)| *number == 15 && *wire == 2)
            .filter_map(|(_, _, value)| {
                parse_protobuf_fields(value)
                    .into_iter()
                    .find(|(number, wire, _)| *number == 1 && *wire == 2)
                    .map(|(_, _, key)| String::from_utf8(key).unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["session_aid", "flow-tag"]);
    }

    #[test]
    fn json_success_never_overrides_security_or_login_errors() {
        for (v, kind) in [
            (
                serde_json::json!({"status_code":0,"message":"captcha required"}),
                FailureKind::Verify,
            ),
            (
                serde_json::json!({"status_code":0,"data":{"description":"未登录"}}),
                FailureKind::Expired,
            ),
            (serde_json::json!({"status_code":429}), FailureKind::Limited),
            (
                serde_json::json!({"error_code":"2154"}),
                FailureKind::Verify,
            ),
            (serde_json::json!({"data":{}}), FailureKind::Protocol),
        ] {
            assert_eq!(
                validate_json(&v)
                    .unwrap_err()
                    .downcast_ref::<WebFailure>()
                    .unwrap()
                    .kind,
                kind
            );
        }
        assert!(validate_json(&serde_json::json!({"status_code":"0"})).is_ok());
        assert_eq!(
            validate_json(&serde_json::json!({"status_code":0,"data":{"error_code":2154}}))
                .unwrap_err()
                .downcast_ref::<WebFailure>()
                .unwrap()
                .kind,
            FailureKind::Verify
        );
        assert!(validate_json(&serde_json::json!({"status_code":0,"error_code":7})).is_err());
        assert!(validate_json(&serde_json::json!({"message":"success","data":{}})).is_ok());
    }
    fn im_response(command: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        encode_field_bytes(command, payload, &mut body);
        let mut env = Vec::new();
        encode_field_varint(1, command as u64, &mut env);
        encode_field_varint(3, 0, &mut env);
        encode_field_bytes(6, &body, &mut env);
        env
    }
    #[test]
    fn im_requires_matching_command_status_and_complete_payload() {
        assert!(validate_im_response(&im_response(610, &[]), 610).is_ok());
        assert!(validate_im_response(&im_response(301, &[]), 610).is_err());
        for bytes in [
            b"<html>challenge</html>".to_vec(),
            im_response(610, &[0x80]),
            vec![0x18, 0],
        ] {
            assert!(validate_im_response(&bytes, 610).is_err());
        }
    }
    #[tokio::test]
    async fn missing_im_context_is_error_before_network() {
        let c = client();
        assert!(
            c.web_im(
                "https://imapi.douyin.com/v2/conversation/get_info_list",
                610,
                &[]
            )
            .await
            .is_err()
        );
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn check_failure_keeps_category_without_error_contents() {
        for (kind, code) in [
            (FailureKind::Expired, "SESSION_EXPIRED"),
            (FailureKind::Verify, "SESSION_VERIFY_REQUIRED"),
            (FailureKind::Limited, "SESSION_LIMITED"),
            (FailureKind::Protocol, "SESSION_PROTOCOL"),
            (FailureKind::Business, "SESSION_BUSINESS"),
            (FailureKind::Network, "SESSION_NETWORK"),
        ] {
            let result = DouyinClient::check_failure(failure(kind, "public-secret-fixture"));
            assert!(result.safe_diagnostic().starts_with(code));
            assert!(
                !result
                    .error_message()
                    .unwrap()
                    .contains("public-secret-fixture")
            );
        }
        let unknown = DouyinClient::check_failure(anyhow::anyhow!("public-secret-fixture"));
        assert!(unknown.safe_diagnostic().starts_with("SESSION_UNCONFIRMED"));
        assert!(
            !unknown
                .error_message()
                .unwrap()
                .contains("public-secret-fixture")
        );
    }
    #[test]
    fn passport_login_expired_is_not_generic_business_failure() {
        for description in ["Login expired", "登录已过期"] {
            let error=validate_json(&serde_json::json!({"message":"error","data":{"error_code":13,"description":description}})).unwrap_err();
            assert_eq!(
                error.downcast_ref::<WebFailure>().unwrap().kind,
                FailureKind::Expired
            );
        }
        let error = validate_json(
            &serde_json::json!({"data":{"error_code":13,"description":"unrelated business error"}}),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<WebFailure>().unwrap().kind,
            FailureKind::Business
        );
    }
}
