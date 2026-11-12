//! 官方 Web IM 上下文与发送凭证。只读会话、身份 Token 和一次性发送授权分离。
use super::client::{encode_field_bytes, encode_field_varint, parse_protobuf_fields, read_varint};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_AGE_SECS: i64 = 30 * 86400;
/// 身份 Token 必须在此年龄内重新向官方换取；不改变上下文捕获寿命。
pub const IDENTITY_REFRESH_AGE_SECS: i64 = 6 * 3600;

/// token beat 下发身份 Token 的长度上限，避免异常报文被写入本地身份材料。
pub const MAX_BEAT_TOKEN_LEN: usize = 4096;

/// 解析 `sid_guard` 登录会话的绝对过期时间（Unix 秒）。
///
/// 官方 Web 端格式为 `<sid>|<login_ts>|<max_age>|<过期时间字符串>`，Cookie 中 `|` 会被
/// encodeURIComponent 转义成 `%7C`。过期时间直接由 `login_ts + max_age` 推导，
/// 避免依赖本地时区解析英文日期串。
/// 该值只用于到期预警：平台不接受无交互的登录会话滑动续期，到期必须重新登录同步。
pub fn sid_guard_expiry(cookie: &str) -> Option<i64> {
    let raw = cookie
        .split(';')
        .map(str::trim)
        .find_map(|item| item.strip_prefix("sid_guard="))?;
    let decoded = raw.replace("%7C", "|").replace("%7c", "|");
    let mut parts = decoded.split('|');
    let _sid = parts.next()?;
    let login_ts: i64 = parts.next()?.trim().parse().ok()?;
    let max_age: i64 = parts.next()?.trim().parse().ok()?;
    if login_ts <= 0 || max_age <= 0 {
        return None;
    }
    login_ts.checked_add(max_age)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ImSendCredential {
    pub uid: u64,
    pub conversation_id: String,
    pub conversation_type: i32,
    pub short_id: u64,
    pub captured_at: i64,
    pub session_hash: String,
    pub user_agent: String,
    pub http_headers: BTreeMap<String, String>,
    pub envelope: Vec<u8>,
    pub send_body: Vec<u8>,
}

/// 可复用浏览器身份；IM 令牌仍按采集时间短期有效，不含路径签名或会话 Ticket。
#[derive(Clone, Serialize, Deserialize)]
pub struct WebSessionContext {
    pub uid: u64,
    pub session_hash: String,
    pub user_agent: String,
    /// 该上下文采集时使用的账号设备指纹。升级前的历史上下文缺省为空，
    /// 此时客户端提示由 `user_agent` 推导，绝不凭空换一套浏览器身份。
    #[serde(default)]
    pub device: Option<super::device_profile::DeviceProfile>,
    pub captured_at: i64,
    /// 与只读上下文时间分离；旧存量记录缺省为未知，必须重新获取。
    #[serde(default)]
    pub identity_acquired_at: Option<i64>,
    pub envelope: Vec<u8>,
    #[serde(default)]
    pub guard_secret_hex: Option<String>,
    #[serde(default)]
    pub guard_server_data: Option<String>,
    #[serde(default)]
    pub guard_acquired_at: Option<i64>,
    #[serde(default)]
    pub last_beat_at: Option<i64>,
    /// 最后一次由真实页面 securitySDK 完成 Cookie、Guard 与身份材料整体轮转的时间。
    /// 旧上下文没有该字段时必须视为未知，而不能用身份 Token 心跳时间代替。
    #[serde(default)]
    pub last_browser_refresh_at: Option<i64>,
    #[serde(default)]
    pub dtrait_pk1_pem: Option<String>,
    #[serde(default)]
    pub dtrait_version: Option<String>,
}
impl WebSessionContext {
    /// SESSION_AUTH 只读初始化不依赖发送捕获，不携带路径签名或虚构设备 ID。
    pub fn from_session(uid: u64, cookie: &str, user_agent: &str) -> Result<Self> {
        Self::from_session_with_device(uid, cookie, user_agent, None)
    }

    /// 生产初始化入口：上下文必须携带账号独占设备指纹。
    pub fn from_session_with_device(
        uid: u64,
        cookie: &str,
        user_agent: &str,
        device: Option<super::device_profile::DeviceProfile>,
    ) -> Result<Self> {
        ensure!(uid > 0, "IM 初始化账号身份无效");
        if let Some(device) = &device {
            device.validate()?;
            ensure!(
                device.user_agent == user_agent,
                "IM 初始化设备指纹与浏览器身份不一致"
            );
        }
        let mut envelope = Vec::new();
        for (n, value) in [
            (3, "1.1.3"),
            (4, ""),
            (
                7,
                "8aa2dcb:Detached: 8aa2dcb88b41538885168e4afbbd2b6bac8aefb2",
            ),
            (11, "douyin_pc"),
            (21, "douyin_web"),
            (22, "web_sdk"),
        ] {
            encode_field_bytes(n, value.as_bytes(), &mut envelope);
        }
        for (n, value) in [(5, 3), (6, 1), (18, 1)] {
            encode_field_varint(n, value, &mut envelope);
        }
        for (key, value) in [("session_aid", "6383"), ("user_agent", user_agent)] {
            append_header(key, value, &mut envelope);
        }
        let context = Self {
            uid,
            session_hash: session_hash(cookie)?,
            user_agent: user_agent.into(),
            device,
            captured_at: chrono::Utc::now().timestamp(),
            identity_acquired_at: None,
            envelope,
            guard_secret_hex: None,
            guard_server_data: None,
            guard_acquired_at: None,
            last_beat_at: None,
            last_browser_refresh_at: None,
            dtrait_pk1_pem: None,
            dtrait_version: None,
        };
        context.validate_session(uid, cookie)?;
        Ok(context)
    }
    /// 上下文实际使用的客户端提示；历史上下文从 UA 推导，避免与 UA 家族冲突。
    pub fn client_hints(&self) -> (String, String, String) {
        match self.device.as_ref() {
            Some(device) => (
                device.sec_ch_ua.clone(),
                device.sec_ch_ua_mobile.clone(),
                device.sec_ch_ua_platform.clone(),
            ),
            None => super::device_profile::client_hints_from_user_agent(&self.user_agent),
        }
    }
    pub fn sec_ch_ua(&self) -> String {
        self.client_hints().0
    }
    pub fn sec_ch_ua_mobile(&self) -> String {
        self.client_hints().1
    }
    pub fn sec_ch_ua_platform(&self) -> String {
        self.client_hints().2
    }

    /// 把账号独占设备指纹绑定到上下文。
    ///
    /// 只补齐缺失的绑定，不改写已观测到的浏览器身份：如果上下文携带的 UA 与账号指纹不同，
    /// 说明账号的真实身份来自别处（历史采集或登录流程），此时必须由账号级迁移把该 UA 并入
    /// 指纹，绝不能在这里把请求换成一个身份 Token 从未见过的 UA。
    pub fn adopt_device(&mut self, device: &super::device_profile::DeviceProfile) -> bool {
        if self.device.is_some() || self.user_agent != device.user_agent {
            return false;
        }
        self.device = Some(device.clone());
        true
    }
    pub fn with_identity(mut self, response: &serde_json::Value) -> Result<Self> {
        ensure!(
            response.get("message").and_then(|v| v.as_str()) == Some("success"),
            "IM 身份凭证响应未确认成功"
        );
        let data = response.get("data").context("IM 身份凭证响应缺少数据")?;
        for object in [response, data] {
            for key in ["error_code", "status_code"] {
                ensure!(
                    object
                        .get(key)
                        .is_none_or(|v| v.as_i64() == Some(0) || v.as_str() == Some("0")),
                    "IM 身份凭证业务响应失败"
                );
            }
        }
        let token = data
            .get("identity_security_token")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty() && v.len() <= 16 * 1024)
            .context("IM 身份 Token 缺失或无效")?;
        let device = data
            .get("device_id")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty() && v.len() <= 1024)
            .context("IM 服务器设备身份缺失或无效")?;
        let mut clean_envelope = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&self.envelope) {
            if n == 15 && w == 2 {
                if let Ok(key) = field_text(&b, 1) {
                    if [
                        "identity_security_token",
                        "identity_security_device_id",
                        "identity_security_aid",
                    ]
                    .contains(&key.as_str())
                    {
                        continue;
                    }
                }
            }
            append_field(n, w, &b, &mut clean_envelope);
        }
        self.envelope = clean_envelope;
        append_header(
            "identity_security_token",
            &serde_json::json!({"token":token}).to_string(),
            &mut self.envelope,
        );
        append_header("identity_security_device_id", device, &mut self.envelope);
        append_header("identity_security_aid", "6383", &mut self.envelope);
        self.identity_acquired_at = Some(chrono::Utc::now().timestamp());
        Ok(self)
    }
    pub fn has_identity(&self) -> bool {
        let headers: BTreeMap<_, _> = parse_protobuf_fields(&self.envelope)
            .into_iter()
            .filter(|(n, w, _)| *n == 15 && *w == 2)
            .filter_map(|(_, _, b)| Some((field_text(&b, 1).ok()?, field_text(&b, 2).ok()?)))
            .collect();
        headers
            .get("identity_security_device_id")
            .is_some_and(|v| !v.is_empty())
            && headers
                .get("identity_security_token")
                .and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok())
                .is_some_and(|v| {
                    v.get("token")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| !v.is_empty())
                })
    }

    /// 读取报文中的身份安全头（键 -> 值）。
    fn identity_headers(&self) -> BTreeMap<String, String> {
        parse_protobuf_fields(&self.envelope)
            .into_iter()
            .filter(|(n, w, _)| *n == 15 && *w == 2)
            .filter_map(|(_, _, b)| Some((field_text(&b, 1).ok()?, field_text(&b, 2).ok()?)))
            .collect()
    }

    /// 用官方 token beat 响应头 `/passport/token/beat/web/` 的
    /// `bd-ticket-guard-identity-token` 刷新本地身份 Token。
    ///
    /// 只接受与当前身份材料**同一设备绑定**的 Token：两次 Token 的第 3 号字段必须逐字节相同。
    /// 结构不符、绑定不一致或长度异常一律拒绝，调用方保持原材料不变。
    pub fn refresh_identity_token(&mut self, raw_token: &str) -> Result<()> {
        use base64::Engine;
        let raw = raw_token.trim();
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_BEAT_TOKEN_LEN,
            "token beat 身份 Token 缺失或超长"
        );
        let existing = self.identity_headers();
        let current = existing
            .get("identity_security_token")
            .context("token beat 要求已有身份 Token")?;
        let current: serde_json::Value =
            serde_json::from_str(current).context("本地身份 Token 包装格式无效")?;
        let current = current
            .get("token")
            .and_then(|v| v.as_str())
            .context("本地身份 Token 为空")?;

        let decode = |value: &str| -> Result<Vec<u8>> {
            let trimmed = value.trim();
            base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
                .context("身份 Token 不是合法 base64")
        };
        // 官方 Token 结构：1 号为会话证明，3 号为设备绑定，两者必须各出现一次且非空。
        let shape_of = |bytes: &[u8]| -> Result<(Vec<u8>, Vec<u8>)> {
            let fields = parse_protobuf_fields(bytes);
            let unique = |number: u32| -> Result<Vec<u8>> {
                let mut found = fields.iter().filter(|(n, w, _)| *n == number && *w == 2);
                let value = found
                    .next()
                    .with_context(|| format!("身份 Token 缺少 {number} 号字段"))?
                    .2
                    .clone();
                ensure!(found.next().is_none(), "身份 Token 字段重复");
                Ok(value)
            };
            let proof = unique(1)?;
            let binding = unique(3)?;
            ensure!(
                (16..=1024).contains(&proof.len()),
                "身份 Token 证明字段长度无效"
            );
            ensure!(
                (16..=1024).contains(&binding.len()),
                "身份 Token 设备绑定字段长度无效"
            );
            Ok((proof, binding))
        };
        let (_, current_binding) = shape_of(&decode(current)?)?;
        let (_, new_binding) = shape_of(&decode(raw)?)?;
        ensure!(
            current_binding == new_binding,
            "token beat 返回的身份 Token 绑定到其他设备或会话，已拒绝"
        );

        let mut updated = self.envelope.clone();
        let mut seen = false;
        let mut cleaned = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&updated) {
            if n == 15
                && w == 2
                && field_text(&b, 1).ok().as_deref() == Some("identity_security_token")
            {
                ensure!(!seen, "身份 Token 字段重复");
                seen = true;
                append_header(
                    "identity_security_token",
                    &serde_json::json!({ "token": raw }).to_string(),
                    &mut cleaned,
                );
                continue;
            }
            append_field(n, w, &b, &mut cleaned);
        }
        ensure!(seen, "本地身份 Token 字段缺失");
        updated = cleaned;
        self.envelope = updated;
        self.identity_acquired_at = Some(chrono::Utc::now().timestamp());
        self.last_beat_at = self.identity_acquired_at;
        Ok(())
    }
    /// 仅当自身缺少官方身份 Token 时，从同一账号的既有上下文补全身份字段。
    /// 官方身份 Token 绑定账号而非单次 sessionid，会话 Cookie 轮换后必须沿用，
    /// 否则会被无身份上下文覆盖，逼迫用户反复人工重新采集。
    pub fn adopt_identity_from(&mut self, source: &WebSessionContext) -> bool {
        if self.uid != source.uid || self.has_identity() || !source.has_identity() {
            return false;
        }
        const IDENTITY_KEYS: [&str; 3] = [
            "identity_security_token",
            "identity_security_device_id",
            "identity_security_aid",
        ];
        let is_identity_entry = |entry: &[u8]| {
            field_text(entry, 1)
                .ok()
                .is_some_and(|name| IDENTITY_KEYS.contains(&name.as_str()))
        };
        let adopted: Vec<Vec<u8>> = parse_protobuf_fields(&source.envelope)
            .into_iter()
            .filter(|(n, w, _)| *n == 15 && *w == 2)
            .map(|(_, _, b)| b)
            .filter(|b| is_identity_entry(b))
            .collect();
        if adopted.len() != IDENTITY_KEYS.len() {
            return false;
        }
        let mut cleaned = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&self.envelope) {
            if n == 15 && w == 2 && is_identity_entry(&b) {
                continue;
            }
            append_field(n, w, &b, &mut cleaned);
        }
        for entry in adopted {
            append_field(15, 2, &entry, &mut cleaned);
        }
        self.envelope = cleaned;
        self.identity_acquired_at = source.identity_acquired_at.or(Some(source.captured_at));
        true
    }
    /// 会话 Cookie 轮换（sessionid 变化）但账号未变：把已采集的官方身份重绑到新会话。
    /// 缺少身份 Token 时必须拒绝重绑，避免把无身份骨架误当作可用凭证。
    pub fn rebind_session(&mut self, cookie: &str) -> Result<bool> {
        let hash = session_hash(cookie)?;
        if self.session_hash == hash {
            return Ok(false);
        }
        ensure!(self.has_identity(), "缺少官方 IM 身份 Token，禁止重绑会话");
        self.session_hash = hash;
        let now = chrono::Utc::now().timestamp();
        self.captured_at = now;
        if self.identity_acquired_at.is_none() {
            self.identity_acquired_at = Some(now);
        }
        Ok(true)
    }
    pub fn identity_is_current(&self, uid: u64, cookie: &str, now: i64) -> bool {
        self.validate_session(uid, cookie).is_ok()
            && self.has_identity()
            && self
                .identity_acquired_at
                .and_then(|at| now.checked_sub(at))
                .is_some_and(|age| (0..=MAX_AGE_SECS).contains(&age))
    }
    pub fn from_credential(c: &ImSendCredential) -> Self {
        let mut envelope = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&c.envelope) {
            if !matches!(
                n,
                3 | 4
                    | 5
                    | 6
                    | 7
                    | 9
                    | 10
                    | 11
                    | 12
                    | 13
                    | 14
                    | 15
                    | 16
                    | 17
                    | 18
                    | 19
                    | 20
                    | 21
                    | 22
            ) {
                continue;
            }
            if n == 15
                && field_text(&b, 1)
                    .ok()
                    .is_some_and(|k| matches!(k.as_str(), "is-retry" | "retry_count"))
            {
                continue;
            }
            append_field(n, w, &b, &mut envelope);
        }
        Self {
            uid: c.uid,
            session_hash: c.session_hash.clone(),
            user_agent: c.user_agent.clone(),
            device: None,
            captured_at: c.captured_at,
            identity_acquired_at: Some(c.captured_at),
            envelope,
            guard_secret_hex: None,
            guard_server_data: None,
            guard_acquired_at: None,
            last_beat_at: None,
            last_browser_refresh_at: None,
            dtrait_pk1_pem: None,
            dtrait_version: None,
        }
    }
    pub fn get_or_create_guard_key(&mut self) -> Result<crate::douyin::pcim_guard::GuardKey> {
        if let Some(ref hex_str) = self.guard_secret_hex {
            if let Ok(key) = crate::douyin::pcim_guard::GuardKey::from_hex(hex_str) {
                return Ok(key);
            }
        }
        let key = crate::douyin::pcim_guard::GuardKey::generate();
        self.guard_secret_hex = Some(key.to_hex());
        self.guard_server_data = None;
        self.guard_acquired_at = None;
        Ok(key)
    }
    pub fn get_guard_key(&self) -> Result<Option<crate::douyin::pcim_guard::GuardKey>> {
        self.guard_secret_hex
            .as_deref()
            .map(crate::douyin::pcim_guard::GuardKey::from_hex)
            .transpose()
    }
    pub fn set_guard_material(
        &mut self,
        material: &crate::douyin::pcim_guard::BoundGuardMaterial,
    ) -> Result<()> {
        self.guard_server_data = Some(material.server_data_json()?);
        self.guard_acquired_at = Some(material.acquired_at());
        Ok(())
    }
    pub fn get_guard_material(
        &self,
        key: &crate::douyin::pcim_guard::GuardKey,
        cookie: &str,
    ) -> Result<Option<crate::douyin::pcim_guard::BoundGuardMaterial>> {
        let (Some(json), Some(acquired_at)) =
            (self.guard_server_data.as_deref(), self.guard_acquired_at)
        else {
            return Ok(None);
        };
        let now = chrono::Utc::now().timestamp();
        if now
            .checked_sub(acquired_at)
            .is_none_or(|age| age > 86400 * 30)
        {
            return Ok(None);
        }
        match crate::douyin::pcim_guard::BoundGuardMaterial::from_saved(
            json,
            self.uid,
            cookie,
            acquired_at,
            &key.public_key_base64(),
        ) {
            Ok(mat) => Ok(Some(mat)),
            Err(e) => {
                tracing::warn!(error = %e, "保存的 GuardMaterial 与当前密钥不匹配或无效，忽略陈旧材料");
                Ok(None)
            }
        }
    }
    pub fn get_dtrait_cipher(&self) -> Result<Option<crate::douyin::pcim_dtrait::DTraitCipher>> {
        let (Some(pem), Some(version)) = (
            self.dtrait_pk1_pem.as_deref(),
            self.dtrait_version.as_deref(),
        ) else {
            return Ok(None);
        };
        crate::douyin::pcim_dtrait::DTraitCipher::new(pem, version).map(Some)
    }
    pub fn set_dtrait_config(&mut self, pem: &str, version: &str) {
        self.dtrait_pk1_pem = Some(pem.to_owned());
        self.dtrait_version = Some(version.to_owned());
    }
    pub fn inherit_guard_materials(&mut self, source: &WebSessionContext) {
        if self.guard_secret_hex.is_none() && source.guard_secret_hex.is_some() {
            self.guard_secret_hex = source.guard_secret_hex.clone();
        }
        if self.guard_server_data.is_none() && source.guard_server_data.is_some() {
            self.guard_server_data = source.guard_server_data.clone();
            self.guard_acquired_at = source.guard_acquired_at;
        }
        if self.dtrait_pk1_pem.is_none() && source.dtrait_pk1_pem.is_some() {
            self.dtrait_pk1_pem = source.dtrait_pk1_pem.clone();
            self.dtrait_version = source.dtrait_version.clone();
        }
    }
    pub fn validate_session(&self, uid: u64, cookie: &str) -> Result<()> {
        ensure!(
            self.uid == uid && self.session_hash == session_hash(cookie)?,
            "Web 上下文与当前账号或 Cookie 不符，禁止请求"
        );
        ensure!(
            !self.user_agent.is_empty() && self.user_agent.len() <= 1024,
            "Web 浏览器身份无效"
        );
        reqwest::header::HeaderValue::from_str(&self.user_agent).context("Web UA 格式无效")?;
        if let Some(device) = &self.device {
            device.validate()?;
            ensure!(
                device.user_agent == self.user_agent,
                "Web 上下文设备指纹与浏览器身份不一致"
            );
        }
        Ok(())
    }
    /// 仅评估本地只读材料，不代表平台接受或发送能力。
    pub fn history_status(
        &self,
        uid: Option<&str>,
        cookie: &str,
        now: i64,
    ) -> (&'static str, Option<i64>) {
        if uid.and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0) != Some(self.uid)
            || self.validate_session(self.uid, cookie).is_err()
        {
            return ("INVALID", None);
        }
        let age = now.checked_sub(self.captured_at);
        if !age.is_some_and(|age| (0..=MAX_AGE_SECS).contains(&age)) {
            return ("EXPIRED", None);
        }
        ("AVAILABLE", self.captured_at.checked_add(MAX_AGE_SECS))
    }
    pub fn im_request(&self, uid: u64, cookie: &str, command: u32, body: &[u8]) -> Result<Vec<u8>> {
        self.validate_session(uid, cookie)?;
        ensure!(
            matches!(command, 301 | 610 | 2005),
            "会话上下文禁止直接用于消息发送"
        );
        ensure!(
            (0..=MAX_AGE_SECS).contains(&(chrono::Utc::now().timestamp() - self.captured_at)),
            "官方 IM 上下文已过期，请重新同步，禁止请求"
        );
        let mut request = self.envelope.clone();
        encode_field_varint(1, command as u64, &mut request);
        encode_field_varint(
            2,
            chrono::Utc::now().timestamp_millis() as u64,
            &mut request,
        );
        encode_field_bytes(8, body, &mut request);
        Ok(request)
    }
}

fn append_header(key: &str, value: &str, envelope: &mut Vec<u8>) {
    let mut entry = Vec::new();
    encode_field_bytes(1, key.as_bytes(), &mut entry);
    encode_field_bytes(2, value.as_bytes(), &mut entry);
    encode_field_bytes(15, &entry, envelope);
}

pub(crate) fn session_hash(cookie: &str) -> Result<String> {
    let values: BTreeMap<_, _> = cookie
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let value = ["sessionid", "sessionid_ss", "sid_tt"]
        .into_iter()
        .filter_map(|key| values.get(key))
        .find(|value| !value.is_empty())
        .context("缺少会话 Cookie，禁止请求")?;
    Ok(hex::encode(Sha256::digest(value.as_bytes())))
}

fn field_bytes(data: &[u8], number: u32) -> Option<Vec<u8>> {
    parse_protobuf_fields(data)
        .into_iter()
        .find(|(n, w, _)| *n == number && *w == 2)
        .map(|(_, _, b)| b)
}
fn field_int(data: &[u8], number: u32) -> Option<u64> {
    parse_protobuf_fields(data)
        .into_iter()
        .find(|(n, w, _)| *n == number && *w == 0)
        .and_then(|(_, _, b)| read_varint(&b, 0).map(|(v, _)| v))
}
fn field_text(data: &[u8], number: u32) -> Result<String> {
    String::from_utf8(field_bytes(data, number).context("官方 IM 报文字段缺失")?)
        .context("官方 IM 报文字段格式无效")
}

impl ImSendCredential {
    pub fn from_capture(
        uid: u64,
        cookie: &str,
        envelope: Vec<u8>,
        user_agent: String,
        headers: BTreeMap<String, String>,
    ) -> Result<Self> {
        ensure!(
            uid > 0 && envelope.len() <= 64 * 1024,
            "官方 IM 凭证格式无效"
        );
        ensure!(
            field_int(&envelope, 1) == Some(100) && field_int(&envelope, 18) == Some(1),
            "仅接受 SESSION_AUTH 的官方消息发送报文"
        );
        ensure!(
            field_bytes(&envelope, 4).is_none_or(|b| b.is_empty()),
            "不接受旧版顶层 Token 鉴权"
        );
        let mut identity = BTreeMap::new();
        for (n, w, bytes) in parse_protobuf_fields(&envelope) {
            if n == 15 && w == 2 {
                identity.insert(field_text(&bytes, 1)?, field_text(&bytes, 2)?);
            }
        }
        for key in ["identity_security_token", "identity_security_device_id"] {
            ensure!(
                identity.get(key).is_some_and(|v| !v.is_empty()),
                "缺少官方 IM 身份安全凭证，禁止发送"
            );
        }
        let token: serde_json::Value =
            serde_json::from_str(&identity["identity_security_token"])
                .map_err(|_| anyhow::anyhow!("官方 IM 身份安全凭证格式无效"))?;
        ensure!(
            token
                .get("token")
                .and_then(|v| v.as_str())
                .is_some_and(|v| !v.is_empty()),
            "官方 IM 身份安全 Token 为空"
        );
        let aid = identity
            .get("identity_security_aid")
            .filter(|v| !v.is_empty())
            .or_else(|| identity.get("session_aid"));
        ensure!(aid.is_some_and(|v| v == "6383"), "官方 IM 应用身份不符");
        ensure!(
            !user_agent.is_empty() && user_agent.len() <= 1024,
            "官方浏览器 UA 无效"
        );
        ensure!(
            identity.get("user_agent").is_some_and(|v| *v == user_agent),
            "官方 IM 报文与 HTTP 浏览器身份不一致"
        );
        let body = field_bytes(&envelope, 8).context("官方 IM 请求体缺失")?;
        let send_body = field_bytes(&body, 100).context("官方 IM 发送体缺失")?;
        let conversation_id = field_text(&send_body, 1)?;
        let conversation_type = field_int(&send_body, 2).context("会话类型缺失")? as i32;
        ensure!(matches!(conversation_type, 1 | 2), "会话类型无效");
        if conversation_type == 1 {
            let parts: Vec<_> = conversation_id.split(':').collect();
            ensure!(
                parts.len() == 4 && parts[0] == "0" && parts[1] == "1",
                "单聊会话格式无效"
            );
            let a = parts[2].parse::<u64>().context("单聊参与者无效")?;
            let b = parts[3].parse::<u64>().context("单聊参与者无效")?;
            ensure!(
                a > 0 && b > 0 && a < b && (a == uid || b == uid),
                "官方会话不属于当前发送账号"
            );
        }
        let short_id = field_int(&send_body, 3)
            .filter(|id| *id > 0)
            .context("官方会话短 ID 缺失，禁止发送")?;
        ensure!(
            !field_text(&send_body, 7)?.is_empty(),
            "官方会话 Ticket 缺失，禁止发送"
        );
        let mut http_headers = BTreeMap::new();
        for (name, value) in headers {
            let name = name.to_ascii_lowercase();
            if name.starts_with("bd-ticket-guard-") || name == "x-tt-session-dtrait" {
                ensure!(value.len() <= 16 * 1024, "官方鉴权头过长");
                reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .context("官方鉴权头名称无效")?;
                reqwest::header::HeaderValue::from_str(&value).context("官方鉴权头格式无效")?;
                http_headers.insert(name, value);
            }
        }
        for key in [
            "bd-ticket-guard-client-data",
            "bd-ticket-guard-ree-public-key",
            "bd-ticket-guard-version",
        ] {
            ensure!(
                http_headers.get(key).is_some_and(|v| !v.is_empty()),
                "缺少官方 HTTP 发送鉴权头，禁止发送"
            );
        }
        Ok(Self {
            uid,
            conversation_id,
            conversation_type,
            short_id,
            captured_at: chrono::Utc::now().timestamp(),
            session_hash: session_hash(cookie)?,
            user_agent,
            http_headers,
            envelope,
            send_body,
        })
    }

    pub fn validate(
        &self,
        uid: u64,
        cookie: &str,
        conversation_id: &str,
        conversation_type: i32,
    ) -> Result<()> {
        ensure!(self.uid == uid, "IM 凭证与发送身份不符，禁止发送");
        ensure!(
            self.session_hash == session_hash(cookie)?,
            "Cookie 已更换，需重新同步官方 IM 凭证，禁止发送"
        );
        let age = chrono::Utc::now().timestamp() - self.captured_at;
        ensure!(
            (0..=MAX_AGE_SECS).contains(&age),
            "官方 IM 凭证已过期，需重新同步，禁止发送"
        );
        ensure!(
            self.conversation_id == conversation_id && self.conversation_type == conversation_type,
            "目标会话未绑定官方 IM 凭证，禁止发送"
        );
        Ok(())
    }

    /// 刷新身份不能延长捕获授权寿命，也不能将新 token 与旧鉴权头拼接。
    pub fn validate_identity_binding(
        &self,
        context: &WebSessionContext,
        uid: u64,
        cookie: &str,
    ) -> Result<()> {
        ensure!(
            context.identity_is_current(uid, cookie, chrono::Utc::now().timestamp()),
            "IM 身份 Token 已过期或未获取，禁止发送"
        );
        let captured = WebSessionContext::from_credential(self);
        let headers = |c: &WebSessionContext| -> BTreeMap<String, String> {
            parse_protobuf_fields(&c.envelope)
                .into_iter()
                .filter(|(n, w, _)| *n == 15 && *w == 2)
                .filter_map(|(_, _, b)| Some((field_text(&b, 1).ok()?, field_text(&b, 2).ok()?)))
                .collect()
        };
        let current = headers(context);
        let original = headers(&captured);
        ensure!(
            self.user_agent == context.user_agent
                && [
                    "identity_security_token",
                    "identity_security_device_id",
                    "identity_security_aid"
                ]
                .into_iter()
                .all(|key| current.get(key).is_some() && current.get(key) == original.get(key)),
            "IM 身份已更新，旧发送授权与新 Token 不匹配，禁止拼接或重放"
        );
        Ok(())
    }

    pub fn request_body(&self, text: &str) -> Vec<u8> {
        let mut send = Vec::new();
        let client_id = uuid::Uuid::new_v4().to_string();
        for (n, w, b) in parse_protobuf_fields(&self.send_body) {
            if matches!(n, 4 | 8 | 9 | 11) {
                continue;
            }
            if n == 5 && w == 2 && field_text(&b, 1).ok().as_deref() == Some("s:client_message_id")
            {
                continue;
            }
            append_field(n, w, &b, &mut send);
        }
        let mut client_id_entry = Vec::new();
        encode_field_bytes(1, b"s:client_message_id", &mut client_id_entry);
        encode_field_bytes(2, client_id.as_bytes(), &mut client_id_entry);
        encode_field_bytes(5, &client_id_entry, &mut send);
        let mut content = field_text(&self.send_body, 4)
            .ok()
            .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
            .filter(|v| v.is_object())
            .unwrap_or_else(|| serde_json::json!({}));
        content["text"] = serde_json::Value::String(text.into());
        encode_field_bytes(4, content.to_string().as_bytes(), &mut send);
        encode_field_bytes(8, client_id.as_bytes(), &mut send);
        let mut body = Vec::new();
        encode_field_bytes(100, &send, &mut body);
        let mut envelope = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&self.envelope) {
            if matches!(n, 2 | 8) {
                continue;
            }
            append_field(n, w, &b, &mut envelope);
        }
        encode_field_varint(
            2,
            chrono::Utc::now().timestamp_millis() as u64,
            &mut envelope,
        );
        encode_field_bytes(8, &body, &mut envelope);
        envelope
    }
}

fn append_field(n: u32, w: u8, b: &[u8], out: &mut Vec<u8>) {
    if w == 2 {
        encode_field_bytes(n, b, out);
    } else if w == 0 {
        if let Some((value, _)) = read_varint(b, 0) {
            encode_field_varint(n, value, out);
        }
    }
}

#[cfg(test)]
pub(crate) fn test_credential(cookie: &str, conversation_id: &str, kind: i32) -> ImSendCredential {
    let mut send = Vec::new();
    encode_field_bytes(1, conversation_id.as_bytes(), &mut send);
    encode_field_varint(2, kind as u64, &mut send);
    encode_field_varint(
        3,
        if kind == 2 {
            conversation_id.parse().unwrap()
        } else {
            7300427740086387237
        },
        &mut send,
    );
    encode_field_bytes(
        4,
        br#"{"text":"draft","aweType":700,"richTextInfos":[],"mentionIds":[]}"#,
        &mut send,
    );
    encode_field_varint(6, 7, &mut send);
    encode_field_bytes(7, b"test-conversation-ticket", &mut send);
    encode_field_bytes(8, b"old-client-id", &mut send);
    let mut body = Vec::new();
    encode_field_bytes(100, &send, &mut body);
    let mut envelope = Vec::new();
    encode_field_varint(1, 100, &mut envelope);
    encode_field_varint(2, 123, &mut envelope);
    encode_field_varint(6, 0, &mut envelope);
    encode_field_bytes(8, &body, &mut envelope);
    encode_field_varint(18, 1, &mut envelope);
    for (key, value) in [
        (
            "identity_security_token",
            "{\"token\":\"fake-token-for-offline-test\"}",
        ),
        ("identity_security_device_id", "test-device"),
        ("identity_security_aid", "6383"),
        ("user_agent", "TestBrowser/155"),
    ] {
        let mut entry = Vec::new();
        encode_field_bytes(1, key.as_bytes(), &mut entry);
        encode_field_bytes(2, value.as_bytes(), &mut entry);
        encode_field_bytes(15, &entry, &mut envelope);
    }
    let headers = BTreeMap::from([
        (
            "bd-ticket-guard-client-data".into(),
            "fake-signature".into(),
        ),
        (
            "bd-ticket-guard-ree-public-key".into(),
            "fake-public-key".into(),
        ),
        ("bd-ticket-guard-version".into(), "2".into()),
    ]);
    ImSendCredential::from_capture(
        99191692311,
        cookie,
        envelope,
        "TestBrowser/155".into(),
        headers,
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    const CONV: &str = "0:1:55696816245:99191692311";

    fn beat_token(binding: &[u8], proof: &[u8]) -> String {
        let mut blob = Vec::new();
        encode_field_bytes(1, proof, &mut blob);
        encode_field_bytes(3, binding, &mut blob);
        encode_field_bytes(4, &[3], &mut blob);
        base64::engine::general_purpose::STANDARD.encode(&blob)
    }

    fn context_with_identity(binding: &[u8], proof: &[u8]) -> WebSessionContext {
        let mut context = WebSessionContext::from_session(
            99191692311,
            "sessionid=beat-offline",
            "TestBrowser/155",
        )
        .unwrap();
        let mut envelope = Vec::new();
        for (key, value) in [
            (
                "identity_security_token",
                serde_json::json!({ "token": beat_token(binding, proof) }).to_string(),
            ),
            ("identity_security_device_id", "test-device".to_string()),
            ("identity_security_aid", "6383".to_string()),
        ] {
            let mut entry = Vec::new();
            encode_field_bytes(1, key.as_bytes(), &mut entry);
            encode_field_bytes(2, value.as_bytes(), &mut entry);
            encode_field_bytes(15, &entry, &mut envelope);
        }
        context.envelope = envelope;
        context.identity_acquired_at = Some(chrono::Utc::now().timestamp() - 60);
        context
    }

    #[test]
    fn token_beat_refresh_requires_same_device_binding() {
        let binding = b"public-device-binding-fixture-0001";
        let mut context = context_with_identity(binding, b"public-old-proof-0000000000001");
        let before = context.identity_headers();
        let fresh = beat_token(binding, b"public-new-proof-0000000000001");
        context.refresh_identity_token(&fresh).unwrap();
        let after = context.identity_headers();
        assert_ne!(
            before["identity_security_token"],
            after["identity_security_token"]
        );
        assert_eq!(
            after["identity_security_token"],
            serde_json::json!({ "token": fresh }).to_string()
        );
        assert_eq!(after["identity_security_device_id"], "test-device");
        assert_eq!(after["identity_security_aid"], "6383");
        assert!(context.last_beat_at.is_some());
        context
            .validate_session(99191692311, "sessionid=beat-offline")
            .unwrap();
    }

    #[test]
    fn token_beat_refresh_rejects_other_device_or_malformed_tokens() {
        let binding = b"public-device-binding-fixture-aaaa";
        let mut context = context_with_identity(binding, b"public-old-proof-0000000000001");
        let original = context.identity_headers()["identity_security_token"].clone();
        for rejected in [
            beat_token(
                b"public-device-binding-fixture-bbbb",
                b"public-new-proof-0000000000001",
            ),
            "not-base64!!".to_string(),
            String::new(),
            "A".repeat(MAX_BEAT_TOKEN_LEN + 1),
            base64::engine::general_purpose::STANDARD.encode(encode_fields(&[(
                1,
                b"public-old-proof-0000000000001".to_vec(),
            )])),
            base64::engine::general_purpose::STANDARD
                .encode(encode_fields(&[(3, binding.to_vec())])),
            base64::engine::general_purpose::STANDARD.encode(encode_fields(&[
                (1, b"short".to_vec()),
                (3, binding.to_vec()),
            ])),
        ] {
            assert!(
                context.refresh_identity_token(&rejected).is_err(),
                "必须拒绝非本设备绑定的身份 Token"
            );
            assert_eq!(
                context.identity_headers()["identity_security_token"],
                original,
                "拒绝后不得改动本地身份材料"
            );
        }
        assert!(context.last_beat_at.is_none());
    }

    #[test]
    fn token_beat_refresh_requires_existing_identity() {
        let mut context =
            WebSessionContext::from_session(99191692311, "sessionid=beat-empty", "TestBrowser/155")
                .unwrap();
        assert!(
            context
                .refresh_identity_token(&beat_token(b"binding", b"proof"))
                .is_err()
        );
    }

    fn encode_fields(fields: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut blob = Vec::new();
        for (number, value) in fields {
            encode_field_bytes(*number, value, &mut blob);
        }
        blob
    }

    #[test]
    fn credential_is_bound_to_cookie_sender_and_conversation() {
        let mut c = test_credential("sessionid=test-session", CONV, 1);
        assert!(
            c.validate(99191692311, "sessionid=test-session", CONV, 1)
                .is_ok()
        );
        assert!(
            c.validate(55696816245, "sessionid=test-session", CONV, 1)
                .is_err()
        );
        assert!(
            c.validate(99191692311, "sessionid=replaced-session", CONV, 1)
                .is_err()
        );
        assert!(
            c.validate(
                99191692311,
                "sessionid=test-session",
                "0:1:1:99191692311",
                1
            )
            .is_err()
        );
        c.captured_at -= MAX_AGE_SECS + 1;
        assert!(
            c.validate(99191692311, "sessionid=test-session", CONV, 1)
                .is_err()
        );
    }

    #[test]
    fn official_empty_identity_aid_uses_session_aid() {
        let c = test_credential("sessionid=test-session", CONV, 1);
        let mut envelope = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&c.envelope) {
            if n == 15 && field_text(&b, 1).unwrap() == "identity_security_aid" {
                continue;
            }
            append_field(n, w, &b, &mut envelope);
        }
        for (key, value) in [("identity_security_aid", ""), ("session_aid", "6383")] {
            let mut entry = Vec::new();
            encode_field_bytes(1, key.as_bytes(), &mut entry);
            encode_field_bytes(2, value.as_bytes(), &mut entry);
            encode_field_bytes(15, &entry, &mut envelope);
        }
        assert!(
            ImSendCredential::from_capture(
                c.uid,
                "sessionid=test-session",
                envelope,
                c.user_agent,
                c.http_headers
            )
            .is_ok()
        );
    }

    #[test]
    fn captured_dtrait_is_preserved_without_allowing_other_sensitive_headers() {
        let c = test_credential("sessionid=test-session", CONV, 1);
        let mut headers = c.http_headers.clone();
        headers.insert(
            "X-TT-Session-DTrait".into(),
            "offline-public-dtrait-fixture".into(),
        );
        headers.insert("Cookie".into(), "must-not-be-imported".into());
        headers.insert("Authorization".into(), "must-not-be-imported".into());
        headers.insert(
            "x-tt-session-dtrait-extra".into(),
            "must-not-be-imported".into(),
        );
        let imported = ImSendCredential::from_capture(
            c.uid,
            "sessionid=test-session",
            c.envelope.clone(),
            c.user_agent.clone(),
            headers.clone(),
        )
        .unwrap();
        assert_eq!(
            imported
                .http_headers
                .get("x-tt-session-dtrait")
                .map(String::as_str),
            Some("offline-public-dtrait-fixture")
        );
        assert_eq!(imported.http_headers.len(), c.http_headers.len() + 1);
        for invalid in ["bad\r\nheader".to_owned(), "x".repeat(16 * 1024 + 1)] {
            headers.insert("X-TT-Session-DTrait".into(), invalid);
            assert!(
                ImSendCredential::from_capture(
                    c.uid,
                    "sessionid=test-session",
                    c.envelope.clone(),
                    c.user_agent.clone(),
                    headers.clone()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn import_rejects_incomplete_auth_or_wrong_identity() {
        let c = test_credential("sessionid=test-session", CONV, 1);
        assert!(
            ImSendCredential::from_capture(
                1,
                "sessionid=test-session",
                c.envelope.clone(),
                c.user_agent.clone(),
                c.http_headers.clone()
            )
            .is_err()
        );
        assert!(
            ImSendCredential::from_capture(
                c.uid,
                "sessionid=test-session",
                c.envelope.clone(),
                "DifferentBrowser".into(),
                c.http_headers.clone()
            )
            .is_err()
        );
        assert!(
            ImSendCredential::from_capture(
                c.uid,
                "sessionid=test-session",
                c.envelope.clone(),
                c.user_agent.clone(),
                BTreeMap::new()
            )
            .is_err()
        );
        let mut missing = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&c.envelope) {
            if n != 15 {
                append_field(n, w, &b, &mut missing);
            }
        }
        assert!(
            ImSendCredential::from_capture(
                c.uid,
                "sessionid=test-session",
                missing,
                c.user_agent.clone(),
                c.http_headers.clone()
            )
            .is_err()
        );
        let mut old_auth = Vec::new();
        for (n, w, b) in parse_protobuf_fields(&c.envelope) {
            if n != 18 {
                append_field(n, w, &b, &mut old_auth);
            }
        }
        encode_field_varint(18, 4, &mut old_auth);
        assert!(
            ImSendCredential::from_capture(
                c.uid,
                "sessionid=test-session",
                old_auth,
                c.user_agent.clone(),
                c.http_headers.clone()
            )
            .is_err()
        );
    }

    #[test]
    fn request_keeps_official_auth_short_id_and_ticket_but_uses_fresh_message_id() {
        let c = test_credential("sessionid=test-session", CONV, 1);
        let a = c.request_body("new message");
        let b = c.request_body("new message");
        assert_eq!(field_int(&a, 18), Some(1));
        let send_a = field_bytes(&field_bytes(&a, 8).unwrap(), 100).unwrap();
        let send_b = field_bytes(&field_bytes(&b, 8).unwrap(), 100).unwrap();
        assert_eq!(field_int(&send_a, 3), Some(7300427740086387237));
        assert_eq!(field_text(&send_a, 7).unwrap(), "test-conversation-ticket");
        assert_ne!(
            field_text(&send_a, 8).unwrap(),
            field_text(&send_b, 8).unwrap()
        );
        assert!(field_text(&send_a, 4).unwrap().contains("new message"));
        assert_eq!(
            parse_protobuf_fields(&a)
                .iter()
                .filter(|(n, _, _)| *n == 15)
                .count(),
            4
        );
    }
    #[test]
    fn request_client_id_matches_extension_and_replaces_all_stale_copies() {
        let mut c = test_credential("sessionid=test-session", CONV, 1);
        for (key, value) in [
            ("s:client_message_id", "old-client-id"),
            ("s:client_message_id", "duplicate-old-id"),
            ("s:mentioned_users", ""),
            ("s:stime", "public-test-time"),
        ] {
            let mut entry = Vec::new();
            encode_field_bytes(1, key.as_bytes(), &mut entry);
            encode_field_bytes(2, value.as_bytes(), &mut entry);
            encode_field_bytes(5, &entry, &mut c.send_body);
        }
        let original = c.send_body.clone();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let request = c.request_body("new message");
            let send = field_bytes(&field_bytes(&request, 8).unwrap(), 100).unwrap();
            let id = field_text(&send, 8).unwrap();
            assert!(uuid::Uuid::parse_str(&id).is_ok());
            let ext: Vec<_> = parse_protobuf_fields(&send)
                .into_iter()
                .filter(|(n, w, _)| *n == 5 && *w == 2)
                .map(|(_, _, b)| (field_text(&b, 1).unwrap(), field_text(&b, 2).unwrap()))
                .collect();
            let message_ids: Vec<_> = ext
                .iter()
                .filter(|(k, _)| k == "s:client_message_id")
                .map(|(_, v)| v.as_str())
                .collect();
            assert_eq!(message_ids, vec![id.as_str()]);
            assert!(ext.contains(&("s:mentioned_users".into(), "".into())));
            assert!(ext.contains(&("s:stime".into(), "public-test-time".into())));
            ids.push(id);
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(c.send_body, original);
        let c = test_credential("sessionid=test-session", CONV, 1);
        let request = c.request_body("new message");
        let send = field_bytes(&field_bytes(&request, 8).unwrap(), 100).unwrap();
        let ext = field_bytes(&send, 5).unwrap();
        assert_eq!(field_text(&ext, 1).unwrap(), "s:client_message_id");
        assert_eq!(field_text(&ext, 2).unwrap(), field_text(&send, 8).unwrap());
    }

    #[test]
    fn readonly_context_is_bound_short_lived_and_cannot_send() {
        let cookie = "sessionid=readonly-offline";
        let credential = test_credential(cookie, CONV, 1);
        let mut context = WebSessionContext::from_credential(&credential);
        assert!(field_bytes(&context.envelope, 8).is_none());
        assert!(field_int(&context.envelope, 1).is_none());
        assert_eq!(field_int(&context.envelope, 18), Some(1));
        for command in [301, 610] {
            let request = context
                .im_request(credential.uid, cookie, command, b"readonly")
                .unwrap();
            assert_eq!(field_int(&request, 1), Some(command as u64));
            assert_eq!(field_bytes(&request, 8).unwrap(), b"readonly");
        }
        assert!(
            context
                .im_request(credential.uid, cookie, 100, b"send")
                .is_err()
        );
        assert!(context.validate_session(1, cookie).is_err());
        assert!(
            context
                .validate_session(credential.uid, "sessionid=replaced")
                .is_err()
        );
        context.captured_at = chrono::Utc::now().timestamp() - MAX_AGE_SECS - 1;
        assert!(
            context
                .im_request(credential.uid, cookie, 301, b"")
                .is_err()
        );
        // HTTP 浏览器身份可保留，过期 IM 令牌不可继续查询。
        assert!(context.validate_session(credential.uid, cookie).is_ok());
        context.captured_at = chrono::Utc::now().timestamp() + 60;
        assert!(
            context
                .im_request(credential.uid, cookie, 610, b"")
                .is_err()
        );
    }
    #[test]
    fn local_history_readiness_is_account_session_and_time_bound() {
        let cookie = "sessionid=public-offline";
        let c = test_credential(cookie, CONV, 1);
        let mut ctx = WebSessionContext::from_credential(&c);
        let now = ctx.captured_at;
        let uid = c.uid.to_string();
        assert_eq!(
            ctx.history_status(Some(&uid), cookie, now),
            ("AVAILABLE", Some(now + MAX_AGE_SECS))
        );
        assert_eq!(
            ctx.history_status(Some(&uid), cookie, now + MAX_AGE_SECS + 1)
                .0,
            "EXPIRED"
        );
        assert_eq!(ctx.history_status(Some(&uid), cookie, now - 1).0, "EXPIRED");
        assert_eq!(ctx.history_status(Some("1"), cookie, now).0, "INVALID");
        assert_eq!(ctx.history_status(None, cookie, now).0, "INVALID");
        assert_eq!(
            ctx.history_status(Some(&uid), "sessionid=other", now).0,
            "INVALID"
        );
        ctx.captured_at = i64::MIN;
        assert_eq!(ctx.history_status(Some(&uid), cookie, now).0, "EXPIRED");
    }
    #[test]
    fn rotated_session_rebinds_but_never_drops_captured_identity() {
        let old_cookie = "sessionid=public-old-session";
        let credential = test_credential(old_cookie, CONV, 1);
        let captured = WebSessionContext::from_credential(&credential);
        assert!(captured.has_identity());
        // 同一账号换用新 sessionid 后，只读骨架必须能从既有上下文补全官方身份。
        let new_cookie = "sessionid=public-new-session";
        let mut rotated =
            WebSessionContext::from_session(credential.uid, new_cookie, "Test/1").unwrap();
        assert!(!rotated.has_identity());
        assert!(rotated.adopt_identity_from(&captured));
        assert!(rotated.has_identity());
        assert_eq!(rotated.session_hash, session_hash(new_cookie).unwrap());
        assert_eq!(rotated.identity_acquired_at, Some(captured.captured_at));
        // 已有身份不得被再次覆盖，跨账号身份不得借用。
        let before = rotated.envelope.clone();
        assert!(!rotated.adopt_identity_from(&captured));
        assert_eq!(rotated.envelope, before);
        let mut foreign =
            WebSessionContext::from_session(credential.uid + 1, new_cookie, "Test/1").unwrap();
        assert!(!foreign.adopt_identity_from(&captured));
        assert!(!foreign.has_identity());

        // 重绑必须保留账号级身份年龄，且无身份骨架严禁被当成可沿用会话。
        let mut rebindable = captured.clone();
        assert!(rebindable.rebind_session(new_cookie).unwrap());
        assert_eq!(rebindable.session_hash, session_hash(new_cookie).unwrap());
        assert_eq!(
            rebindable.identity_acquired_at,
            captured.identity_acquired_at
        );
        assert!(!rebindable.rebind_session(new_cookie).unwrap());
        let mut bare =
            WebSessionContext::from_session(credential.uid, "sessionid=public-bare", "Test/1")
                .unwrap();
        assert!(bare.rebind_session("sessionid=public-bare-next").is_err());
    }

    #[test]
    fn sid_guard_expiry_uses_login_time_plus_max_age() {
        // 官方 Web 端实测样例形态：URL 编码的 `|` 与 60 天有效期
        let cookie = "sessionid=abc; sid_guard=abc%7C1792375077%7C5184000%7CFri%2C+18-Dec-2026+01%3A57%3A57+GMT; sid_tt=abc";
        assert_eq!(sid_guard_expiry(cookie), Some(1792375077 + 5_184_000));
        // 未编码形态同样可解析
        assert_eq!(
            sid_guard_expiry("sid_guard=abc|1792375077|5184000|Fri, 18-Dec-2026 01:57:57 GMT"),
            Some(1792375077 + 5_184_000)
        );
        // 缺失、损坏或非正数一律返回 None，不得推断出错误的到期时间
        assert_eq!(sid_guard_expiry("sessionid=abc"), None);
        assert_eq!(sid_guard_expiry("sid_guard=abc"), None);
        assert_eq!(sid_guard_expiry("sid_guard=abc|0|5184000|x"), None);
        assert_eq!(sid_guard_expiry("sid_guard=abc|1792375077|0|x"), None);
    }

    #[test]
    fn session_initialization_and_identity_are_separate_from_send_authority() {
        let cookie = "sessionid=public-session";
        let context = WebSessionContext::from_session(99191692311, cookie, "Test/1").unwrap();
        assert_eq!(field_int(&context.envelope, 18), Some(1));
        assert!(field_bytes(&context.envelope, 9).is_none());
        assert!(!context.has_identity());
        assert!(context.im_request(99191692311, cookie, 610, b"").is_ok());
        assert!(context.im_request(99191692311, cookie, 100, b"").is_err());
        let response = serde_json::json!({"message":"success","data":{"identity_security_token":"PUBLIC-TOKEN","device_id":"PUBLIC-SERVER-DEVICE"}});
        let device = crate::douyin::device_profile::DeviceProfile::derive("acc_context_device");
        assert!(
            WebSessionContext::from_session_with_device(
                99191692311,
                cookie,
                "Different-UA/1",
                Some(device.clone()),
            )
            .is_err()
        );
        let device_user_agent = device.user_agent.clone();
        let mut bound = WebSessionContext::from_session_with_device(
            99191692311,
            cookie,
            &device_user_agent,
            Some(device),
        )
        .unwrap();
        bound.user_agent = "Different-UA/1".into();
        assert!(bound.validate_session(99191692311, cookie).is_err());
        let identity = context.clone().with_identity(&response).unwrap();
        assert!(identity.has_identity());
        assert!(identity.im_request(99191692311, cookie, 100, b"").is_err());
        assert!(WebSessionContext::from_session(0, cookie, "Test/1").is_err());
        assert!(WebSessionContext::from_session(1, cookie, "bad\nUA").is_err());
        for bad in [
            serde_json::json!({"message":"error","data":{"identity_security_token":"PUBLIC","device_id":"PUBLIC"}}),
            serde_json::json!({"message":"success","data":{"identity_security_token":"","device_id":"PUBLIC"}}),
            serde_json::json!({"message":"success","data":{"identity_security_token":"PUBLIC"}}),
            serde_json::json!({"message":"success","data":{"identity_security_token":"PUBLIC","device_id":12}}),
            serde_json::json!({"message":"success","data":{"error_code":1105,"identity_security_token":"PUBLIC","device_id":"PUBLIC"}}),
        ] {
            assert!(context.clone().with_identity(&bad).is_err());
        }
    }
}
