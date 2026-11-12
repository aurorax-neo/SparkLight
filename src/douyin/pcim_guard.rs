//! PCIM Guard 纯 Rust 计算层。没有网络、浏览器私钥导入或发送能力。
//! 依据官方 5770.1fc7435b.js；材料绑定通过不等于服务端授权已验收。
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePublicKey,
};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// 官方抖音 Web 端 PCIM Guard 服务端 SPKI 公钥 (secp256r1 P-256)
/// Base64: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhNpZQz5X3PEavuSeR14YOHnRYz5whd1GuyQaIhP36D/Zuy+RCyHL8QoBMWkQh20PJAgivwK2eBV/6gqG2QJE6A==
pub const OFFICIAL_SERVER_SPKI_DER: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x84, 0xda, 0x59, 0x43, 0x3e,
    0x57, 0xdc, 0xf1, 0x1a, 0xbe, 0xe4, 0x9e, 0x47, 0x5e, 0x18, 0x38, 0x79, 0xd1, 0x63, 0x3e, 0x70,
    0x85, 0xdd, 0x46, 0xbb, 0x24, 0x1a, 0x22, 0x13, 0xf7, 0xe8, 0x3f, 0xd9, 0xbb, 0x2f, 0x91, 0x0b,
    0x21, 0xcb, 0xf1, 0x0a, 0x01, 0x31, 0x69, 0x10, 0x87, 0x6d, 0x0f, 0x24, 0x08, 0x22, 0xbf, 0x02,
    0xb6, 0x78, 0x15, 0x7f, 0xea, 0x0a, 0x86, 0xd9, 0x02, 0x44, 0xe8,
];

/// 无 Debug/Serialize 或私钥导出接口；只能生成独立密钥。
#[derive(Clone)]
pub struct GuardKey {
    secret: SecretKey,
}

/// 官方 Web SDK `bd_ticket_guard_client_data` 的声明体。
/// 字段顺序必须与官方逐字节一致：version -> iteration-version -> ree-public-key -> web-version。
/// 严禁改用 `serde_json::json!`，该宏在默认配置下会按字母排序，导致指纹与官方不一致。
#[derive(Serialize)]
struct GuardDeclaration<'a> {
    #[serde(rename = "bd-ticket-guard-version")]
    version: u8,
    #[serde(rename = "bd-ticket-guard-iteration-version")]
    iteration: u8,
    #[serde(rename = "bd-ticket-guard-ree-public-key")]
    public: &'a str,
    #[serde(rename = "bd-ticket-guard-web-version")]
    web_version: u8,
}

pub fn guard_declaration_json(public_key_base64: &str) -> Result<String> {
    serde_json::to_string(&GuardDeclaration {
        version: 2,
        iteration: 1,
        public: public_key_base64,
        web_version: 2,
    })
    .context("GUARD_ENCODE_FAILED")
}

impl GuardKey {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::random(&mut rand::rngs::OsRng),
        }
    }
    pub fn derive_for_account(account_id: &str) -> Self {
        use sha2::Digest;
        for counter in 0..256u32 {
            let digest = Sha256::digest(
                format!("sparklight-guard-key:v1:{account_id}:{counter}").as_bytes(),
            );
            if let Ok(secret) = SecretKey::from_slice(&digest) {
                return Self { secret };
            }
        }
        Self::generate()
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let secret = SecretKey::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("GUARD_INVALID_SECRET_KEY"))?;
        Ok(Self { secret })
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| anyhow::anyhow!("GUARD_INVALID_HEX_SECRET"))?;
        Self::from_slice(&bytes)
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.secret.to_bytes());
        out
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.secret.public_key().to_encoded_point(false).as_bytes())
    }
    /// 标准 P-256 SubjectPublicKeyInfo DER，供 TicketGuard CSR 使用。
    pub fn public_key_spki_der(&self) -> Vec<u8> {
        const SPKI_HEADER: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let point = self.secret.public_key().to_encoded_point(false);
        let mut der = Vec::with_capacity(SPKI_HEADER.len() + point.as_bytes().len());
        der.extend_from_slice(&SPKI_HEADER);
        der.extend_from_slice(point.as_bytes());
        der
    }
    pub fn verify_binding(&self, material: &BoundGuardMaterial) -> Result<()> {
        anyhow::ensure!(
            material.public == self.public_key_base64(),
            "GUARD_KEY_PUBLIC_MISMATCH"
        );
        Ok(())
    }
    /// 官方 _processCookie 的公钥初始化声明；不是发送签名，也不是服务端授权。
    pub fn initialization_cookie_value(&self) -> Result<String> {
        Ok(STANDARD.encode(guard_declaration_json(&self.public_key_base64())?.as_bytes()))
    }
    pub fn initialization_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "bd-ticket-guard-ree-public-key",
            HeaderValue::from_str(&self.public_key_base64())
                .map_err(|_| anyhow::anyhow!("GUARD_INVALID_HEADER"))?,
        );
        headers.insert("bd-ticket-guard-web-version", HeaderValue::from_static("2"));
        headers.insert(
            "bd-ticket-guard-web-sign-type",
            HeaderValue::from_static("0"),
        );
        headers.insert("bd-ticket-guard-version", HeaderValue::from_static("2"));
        Ok(headers)
    }
    /// 官方 Android TicketGuardManager 的初始化请求头。
    /// App 端当前使用协议 v3、迭代 v2，并显式上报 TEE 不可用状态。
    pub fn android_initialization_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "bd-ticket-guard-ree-public-key",
            HeaderValue::from_str(&self.public_key_base64())
                .map_err(|_| anyhow::anyhow!("GUARD_INVALID_HEADER"))?,
        );
        headers.insert("bd-ticket-guard-tee-status", HeaderValue::from_static("0"));
        headers.insert("bd-ticket-guard-version", HeaderValue::from_static("3"));
        headers.insert(
            "bd-ticket-guard-display-os-version",
            HeaderValue::from_static("UP1A.231005.007"),
        );
        headers.insert(
            "bd-ticket-guard-iteration-version",
            HeaderValue::from_static("2"),
        );
        Ok(headers)
    }
    /// 只接收预期官方 HTTPS 响应解析出的材料。调用方仍须校验来源/账号身份。
    pub fn bind_response(
        &self,
        json: &[u8],
        uid: u64,
        cookie: &str,
        acquired_at: i64,
    ) -> Result<BoundGuardMaterial> {
        ensure!(
            json.len() <= 32 * 1024 && uid > 0 && acquired_at > 0,
            "GUARD_INVALID_INPUT"
        );
        let data: ServerMaterial = serde_json::from_slice(json)
            .map_err(|_| anyhow::anyhow!("GUARD_INVALID_SERVER_DATA"))?;
        ensure!(
            !data.ticket.is_empty()
                && data.ticket.len() <= 16 * 1024
                && !data.ticket.contains(['&', '\r', '\n']),
            "GUARD_INVALID_TICKET"
        );
        ensure!(
            !data.ts_sign.is_empty() && data.ts_sign.len() <= 16 * 1024,
            "GUARD_INVALID_TS_SIGN"
        );
        ensure!(
            data.ts_sign.starts_with("ts.1") || data.ts_sign.starts_with("ts.2"),
            "GUARD_CERT_BRANCH_UNSUPPORTED"
        );
        let public = self.public_key_base64();
        ensure!(
            data.client_cert.strip_prefix("pub.") == Some(public.as_str()),
            "GUARD_KEY_BINDING_MISMATCH"
        );
        let raw_server_data = String::from_utf8(json.to_vec())
            .unwrap_or_else(|_| serde_json::to_string(&data).unwrap_or_default());
        Ok(BoundGuardMaterial {
            data,
            uid,
            session_hash: strict_session_hash(cookie)?,
            acquired_at,
            public,
            raw_server_data,
        })
    }
    /// 官方响应头载体；拒绝重复头，缺失返回 None，不生成替代材料。
    pub fn bind_response_headers(
        &self,
        headers: &HeaderMap,
        uid: u64,
        cookie: &str,
        acquired_at: i64,
    ) -> Result<Option<BoundGuardMaterial>> {
        let values: Vec<_> = headers
            .get_all("bd-ticket-guard-server-data")
            .iter()
            .collect();
        ensure!(values.len() <= 1, "GUARD_AMBIGUOUS_SERVER_DATA");
        let Some(value) = values.first() else {
            return Ok(None);
        };
        let encoded = value
            .to_str()
            .map_err(|_| anyhow::anyhow!("GUARD_INVALID_SERVER_DATA"))?;
        self.bind_base64(encoded, uid, cookie, acquired_at)
            .map(Some)
    }
    /// 仅解析 bd_ticket_guard_server_data，不读取客户端签名或私钥 Cookie。
    pub fn bind_server_cookie(
        &self,
        response_cookie: &str,
        uid: u64,
        session_cookie: &str,
        acquired_at: i64,
    ) -> Result<Option<BoundGuardMaterial>> {
        ensure!(response_cookie.len() <= 128 * 1024, "GUARD_INVALID_INPUT");
        let values: Vec<_> = response_cookie
            .split(';')
            .filter_map(|part| {
                let (name, value) = part.trim().split_once('=')?;
                (name == "bd_ticket_guard_server_data").then_some(value)
            })
            .collect();
        ensure!(values.len() <= 1, "GUARD_AMBIGUOUS_SERVER_DATA");
        let Some(value) = values.first() else {
            return Ok(None);
        };
        let mut decoded = Vec::new();
        let bytes = value.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                ensure!(i + 2 < bytes.len(), "GUARD_INVALID_ENCODING");
                let high = (bytes[i + 1] as char)
                    .to_digit(16)
                    .context("GUARD_INVALID_ENCODING")?;
                let low = (bytes[i + 2] as char)
                    .to_digit(16)
                    .context("GUARD_INVALID_ENCODING")?;
                decoded.push((high * 16 + low) as u8);
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        // decodeURIComponent 不将 '+' 转为空格，不能使用表单 URL 解码。
        let decoded =
            String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("GUARD_INVALID_ENCODING"))?;
        self.bind_base64(&decoded, uid, session_cookie, acquired_at)
            .map(Some)
    }
    fn bind_base64(
        &self,
        encoded: &str,
        uid: u64,
        cookie: &str,
        acquired_at: i64,
    ) -> Result<BoundGuardMaterial> {
        ensure!(encoded.len() <= 44 * 1024, "GUARD_INVALID_INPUT");
        let json = STANDARD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("GUARD_INVALID_ENCODING"))?;
        self.bind_response(&json, uid, cookie, acquired_at)
    }
    /// 固定发送路径，时间由调用方的已验证时钟提供；不复用缓存签名。
    pub fn sign_send(
        &self,
        material: &BoundGuardMaterial,
        uid: u64,
        cookie: &str,
        timestamp: i64,
        mode: GuardMode<'_>,
    ) -> Result<HeaderMap> {
        self.sign_send_with_trust(material, uid, cookie, timestamp, mode, false)
    }
    pub fn sign_send_with_trust(
        &self,
        material: &BoundGuardMaterial,
        uid: u64,
        cookie: &str,
        timestamp: i64,
        mode: GuardMode<'_>,
        is_trusted: bool,
    ) -> Result<HeaderMap> {
        self.sign_path_with_trust(
            material,
            "/v1/message/send",
            uid,
            cookie,
            timestamp,
            mode,
            is_trusted,
        )
    }
    /// 通用路径签名：用于 /v1/message/send 以及 /passport/token/beat/web/ 等需要 Guard 签名的路径。
    pub fn sign_path(
        &self,
        material: &BoundGuardMaterial,
        path: &str,
        uid: u64,
        cookie: &str,
        timestamp: i64,
        mode: GuardMode<'_>,
    ) -> Result<HeaderMap> {
        self.sign_path_with_trust(material, path, uid, cookie, timestamp, mode, false)
    }
    pub fn sign_path_with_trust(
        &self,
        material: &BoundGuardMaterial,
        path: &str,
        uid: u64,
        cookie: &str,
        timestamp: i64,
        mode: GuardMode<'_>,
        is_trusted: bool,
    ) -> Result<HeaderMap> {
        ensure!(
            uid == material.uid && material.session_hash == strict_session_hash(cookie)?,
            "GUARD_SESSION_CHANGED"
        );
        ensure!(
            material.public == self.public_key_base64(),
            "GUARD_KEY_BINDING_MISMATCH"
        );
        // 本地保守门限，不声明这是平台票据的真实 TTL。
        ensure!(
            timestamp
                .checked_sub(material.acquired_at)
                .is_some_and(|v| (0..=86400 * 30).contains(&v)),
            "GUARD_MATERIAL_STALE"
        );
        let input = format!(
            "ticket={}&path={path}&timestamp={timestamp}",
            material.data.ticket
        );
        let (signature, sign_type) = match mode {
            GuardMode::Ecdsa => {
                let key = SigningKey::from(&self.secret);
                let signature: Signature = key.sign(input.as_bytes());
                (STANDARD.encode(signature.to_der().as_bytes()), "0")
            }
            GuardMode::Hmac { server_spki_der } => {
                let server = PublicKey::from_public_key_der(server_spki_der)
                    .map_err(|_| anyhow::anyhow!("GUARD_INVALID_SERVER_PUBLIC_KEY"))?;
                let shared = diffie_hellman(self.secret.to_nonzero_scalar(), server.as_affine());
                let mut derived = [0u8; 32];
                hkdf::Hkdf::<Sha256>::new(None, shared.raw_secret_bytes())
                    .expand(&[], &mut derived)
                    .map_err(|_| anyhow::anyhow!("GUARD_KDF_FAILED"))?;
                let mut mac = Hmac::<Sha256>::new_from_slice(&derived)
                    .map_err(|_| anyhow::anyhow!("GUARD_HMAC_FAILED"))?;
                mac.update(input.as_bytes());
                derived.fill(0);
                (STANDARD.encode(mac.finalize().into_bytes()), "1")
            }
        };
        let t_trust = if is_trusted { Some(1) } else { None };
        let payload = ClientData {
            ts_sign: &material.data.ts_sign,
            req_content: "ticket,path,timestamp",
            req_sign: &signature,
            timestamp,
            t_trust,
        };
        let value = STANDARD.encode(serde_json::to_vec(&payload).context("GUARD_ENCODE_FAILED")?);
        let mut headers = HeaderMap::new();
        for (name, text) in [
            ("bd-ticket-guard-ree-public-key", material.public.as_str()),
            (
                "bd-ticket-guard-web-version",
                if material.data.ts_sign.starts_with("ts.1") {
                    "1"
                } else {
                    "2"
                },
            ),
            ("bd-ticket-guard-web-sign-type", sign_type),
            ("bd-ticket-guard-version", "2"),
            ("bd-ticket-guard-client-data", value.as_str()),
        ] {
            let mut header =
                HeaderValue::from_str(text).map_err(|_| anyhow::anyhow!("GUARD_INVALID_HEADER"))?;
            header.set_sensitive(true);
            headers.insert(name, header);
        }
        Ok(headers)
    }
}
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerMaterial {
    pub ticket: String,
    pub ts_sign: String,
    pub client_cert: String,
    #[serde(default)]
    pub create_time: Option<i64>,
    #[serde(default)]
    pub log_id: Option<String>,
}
#[derive(Serialize)]
struct ClientData<'a> {
    ts_sign: &'a str,
    req_content: &'a str,
    req_sign: &'a str,
    timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_trust: Option<u8>,
}
#[derive(Clone, Debug)]
pub struct BoundGuardMaterial {
    pub data: ServerMaterial,
    pub uid: u64,
    pub session_hash: String,
    pub acquired_at: i64,
    pub public: String,
    pub raw_server_data: String,
}
impl BoundGuardMaterial {
    pub fn server_data_json(&self) -> Result<String> {
        if !self.raw_server_data.is_empty() {
            return Ok(self.raw_server_data.clone());
        }
        serde_json::to_string(&self.data).context("GUARD_SERIALIZE_SERVER_DATA")
    }
    pub fn compute_crypt_cookie(&self) -> Result<String> {
        compute_ticket_crypt_cookie(&self.public, &self.data.client_cert, &self.raw_server_data)
    }
    pub fn from_saved(
        json: &str,
        uid: u64,
        cookie: &str,
        acquired_at: i64,
        expected_public: &str,
    ) -> Result<Self> {
        let data: ServerMaterial =
            serde_json::from_str(json).context("GUARD_DESERIALIZE_SERVER_DATA")?;
        let cert_pub = data
            .client_cert
            .strip_prefix("pub.")
            .unwrap_or(&data.client_cert);
        ensure!(cert_pub == expected_public, "GUARD_KEY_BINDING_MISMATCH");
        let now = chrono::Utc::now().timestamp();
        ensure!(
            now.saturating_sub(acquired_at) <= 86400 * 30,
            "GUARD_MATERIAL_EXPIRED_BY_ACQUIRED_AT: 当前账号 Guard 签名票据材料已超过有效期，已安全拦截发送以防被平台注销会话；请重新同步凭证"
        );
        if let Some(ct) = data.create_time {
            ensure!(
                ct <= 0 || now.saturating_sub(ct) <= 86400 * 30,
                "GUARD_MATERIAL_EXPIRED_BY_CREATE_TIME: 当前账号 Guard 签名票据已过期，已安全拦截发送以防被平台注销会话；请重新同步凭证"
            );
        }
        if let Some(log_id) = &data.log_id {
            if log_id.len() >= 8 && log_id[..8].chars().all(|c| c.is_ascii_digit()) {
                if let Ok(log_date) = chrono::NaiveDate::parse_from_str(&log_id[..8], "%Y%m%d") {
                    let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
                    let current_date = chrono::Utc::now().with_timezone(&cst).date_naive();
                    ensure!(
                        (current_date - log_date).num_days() <= 30,
                        "GUARD_MATERIAL_EXPIRED_BY_LOG_ID: 当前账号 Guard 签名票据已超过有效期，已安全拦截发送以防被平台注销会话；请重新同步凭证"
                    );
                }
            }
        }
        Ok(Self {
            data,
            uid,
            session_hash: strict_session_hash(cookie)?,
            acquired_at,
            public: expected_public.to_owned(),
            raw_server_data: json.to_owned(),
        })
    }
    pub fn is_stale(&self, now: i64, max_age_secs: i64) -> bool {
        now.checked_sub(self.acquired_at)
            .map_or(true, |age| age > max_age_secs)
    }
    pub fn needs_refresh(&self, now: i64) -> bool {
        if let Some(ct) = self.data.create_time {
            if ct > 0 && now.saturating_sub(ct) > 86400 * 3 {
                return true;
            }
        }
        if now.saturating_sub(self.acquired_at) > 86400 * 3 {
            return true;
        }
        false
    }
    pub fn ticket(&self) -> &str {
        &self.data.ticket
    }
    pub fn public_key(&self) -> &str {
        &self.public
    }
    pub fn acquired_at(&self) -> i64 {
        self.acquired_at
    }
    pub fn validate_freshness(&self, now: i64) -> Result<()> {
        anyhow::ensure!(!self.is_stale(now, 86400 * 30), "GUARD_MATERIAL_STALE");
        Ok(())
    }
}
pub enum GuardMode<'a> {
    Ecdsa,
    Hmac { server_spki_der: &'a [u8] },
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    const COOKIE: &str = "sessionid=public-offline-only";
    fn key(n: u8) -> GuardKey {
        GuardKey {
            secret: SecretKey::from_slice(&[n; 32]).unwrap(),
        }
    }
    fn material(key: &GuardKey, prefix: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"ticket":"offline-ticket","ts_sign":format!("{prefix}.offline"),"client_cert":format!("pub.{}",key.public_key_base64())})).unwrap()
    }
    #[test]
    fn ecdsa_wire_format_and_binding() {
        let key = key(1);
        let declaration = STANDARD
            .decode(key.initialization_cookie_value().unwrap())
            .unwrap();
        let expected = format!(
            "{{\"bd-ticket-guard-version\":2,\"bd-ticket-guard-iteration-version\":1,\"bd-ticket-guard-ree-public-key\":\"{}\",\"bd-ticket-guard-web-version\":2}}",
            key.public_key_base64()
        );
        assert_eq!(declaration, expected.as_bytes());
        let initial = key.initialization_headers().unwrap();
        assert_eq!(initial.len(), 4);
        assert_eq!(initial["bd-ticket-guard-web-sign-type"], "0");
        assert!(!initial.contains_key("bd-ticket-guard-client-data"));
        for prefix in ["ts.1", "ts.2"] {
            let bound = key
                .bind_response(&material(&key, prefix), 99191692311, COOKIE, 1700000000)
                .unwrap();
            let headers = key
                .sign_send(&bound, 99191692311, COOKIE, 1700000001, GuardMode::Ecdsa)
                .unwrap();
            assert_eq!(key.public_key_base64().len(), 88);
            assert_eq!(
                headers["bd-ticket-guard-web-version"],
                if prefix == "ts.1" { "1" } else { "2" }
            );
            assert_eq!(headers["bd-ticket-guard-web-sign-type"], "0");
            assert!(!headers.contains_key("bd-ticket-guard-iteration-version"));
            assert_eq!(headers.len(), 5);
            assert!(headers.values().all(|v| v.is_sensitive()));
            let decoded = STANDARD
                .decode(headers["bd-ticket-guard-client-data"].as_bytes())
                .unwrap();
            let data: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(data["req_content"], "ticket,path,timestamp");
            assert_eq!(data["timestamp"], 1700000001);
            let sig =
                Signature::from_der(&STANDARD.decode(data["req_sign"].as_str().unwrap()).unwrap())
                    .unwrap();
            let public = VerifyingKey::from(&SigningKey::from(&key.secret));
            assert!(data.get("t_trust").is_none());
            public
                .verify(
                    b"ticket=offline-ticket&path=/v1/message/send&timestamp=1700000001",
                    &sig,
                )
                .unwrap();
            assert!(
                public
                    .verify(
                        b"ticket=offline-ticket&path=/other&timestamp=1700000001",
                        &sig
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn token_beat_path_is_signed_with_the_official_five_headers() {
        let key = key(1);
        let bound = key
            .bind_response(&material(&key, "ts.2"), 99191692311, COOKIE, 1700000000)
            .unwrap();
        let headers = key
            .sign_path(
                &bound,
                "/passport/token/beat/web/",
                99191692311,
                COOKIE,
                1700000001,
                GuardMode::Hmac {
                    server_spki_der: OFFICIAL_SERVER_SPKI_DER,
                },
            )
            .unwrap();
        assert_eq!(headers.len(), 5);
        assert!(!headers.contains_key("bd-ticket-guard-iteration-version"));
        assert_eq!(headers["bd-ticket-guard-web-sign-type"], "1");
        assert!(headers.values().all(|value| value.is_sensitive()));
        let data: serde_json::Value = serde_json::from_slice(
            &STANDARD
                .decode(headers["bd-ticket-guard-client-data"].as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["req_content"], "ticket,path,timestamp");
        assert_eq!(data["timestamp"], 1700000001);
        assert!(data.get("t_trust").is_none());
    }
    #[test]
    fn official_pcim_headers_and_node_crypto_match() {
        assert!(PublicKey::from_public_key_der(OFFICIAL_SERVER_SPKI_DER).is_ok());
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("sdk/pcim_guard_baseline.json")).unwrap();
        let scalar = hex::decode(fixture["test_only_scalar_hex"].as_str().unwrap()).unwrap();
        let key = GuardKey {
            secret: SecretKey::from_slice(&scalar).unwrap(),
        };
        assert_eq!(key.public_key_base64(), fixture["public_key_sec1_base64"]);
        let server = STANDARD
            .decode(fixture["server_public_spki_base64"].as_str().unwrap())
            .unwrap();
        let public = VerifyingKey::from(&SigningKey::from(&key.secret));
        for case in fixture["cases"].as_array().unwrap() {
            let raw = serde_json::to_vec(&serde_json::json!({"ticket":fixture["ticket"],"ts_sign":case["ts_sign"],"client_cert":format!("pub.{}",key.public_key_base64())})).unwrap();
            let bound = key.bind_response(&raw, 1, COOKIE, 1700000000).unwrap();
            let hmac = case["mode"] == "hmac";
            let headers = key
                .sign_send(
                    &bound,
                    1,
                    COOKIE,
                    fixture["timestamp"].as_i64().unwrap(),
                    if hmac {
                        GuardMode::Hmac {
                            server_spki_der: &server,
                        }
                    } else {
                        GuardMode::Ecdsa
                    },
                )
                .unwrap();
            for (name, expected) in case["headers"].as_object().unwrap() {
                let expected = expected
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| expected.to_string());
                assert_eq!(headers.get(name).unwrap().to_str().unwrap(), expected);
            }
            let data: serde_json::Value = serde_json::from_slice(
                &STANDARD
                    .decode(headers["bd-ticket-guard-client-data"].as_bytes())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(data["ts_sign"], case["ts_sign"]);
            assert_eq!(data["req_content"], case["input"]["req_content"]);
            assert_eq!(data["timestamp"], case["input"]["timestamp"]);
            assert!(data.get("t_trust").is_none());
            if hmac {
                assert_eq!(data["req_sign"], case["signature_base64"].as_str().unwrap());
            } else {
                for signature in [
                    data["req_sign"].as_str().unwrap(),
                    case["signature_base64"].as_str().unwrap(),
                ] {
                    let signature =
                        Signature::from_der(&STANDARD.decode(signature).unwrap()).unwrap();
                    public
                        .verify(
                            case["input"]["sign_data"].as_str().unwrap().as_bytes(),
                            &signature,
                        )
                        .unwrap();
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_key_session_age_and_material() {
        let a = key(1);
        let b = key(2);
        let raw = material(&a, "ts.2");
        assert!(b.bind_response(&raw, 1, COOKIE, 1700000000).is_err());
        let bound = a.bind_response(&raw, 1, COOKIE, 1700000000).unwrap();
        for (uid, cookie, ts) in [
            (2, COOKIE, 1700000001),
            (1, "sessionid=changed", 1700000001),
            (1, COOKIE, 1699999999),
            (1, COOKIE, 1700000000 + 86400 * 30 + 1),
        ] {
            assert!(
                a.sign_send(&bound, uid, cookie, ts, GuardMode::Ecdsa)
                    .is_err()
            );
        }
        assert!(
            b.sign_send(&bound, 1, COOKIE, 1700000001, GuardMode::Ecdsa)
                .is_err()
        );
        assert!(
            a.sign_send(
                &bound,
                1,
                COOKIE,
                1700000001,
                GuardMode::Hmac {
                    server_spki_der: b"invalid"
                }
            )
            .is_err()
        );
        assert!(
            a.bind_response(&material(&a, "legacy"), 1, COOKIE, 1)
                .is_err()
        );
        assert!(
            a.bind_response(
                br#"{"ticket":"a","ticket":"b","ts_sign":"ts.2.x","client_cert":"pub.x"}"#,
                1,
                COOKIE,
                1
            )
            .is_err()
        );
    }
    #[test]
    fn official_header_and_cookie_carriers_are_equivalent_and_strict() {
        let key = key(1);
        let encoded = STANDARD.encode(material(&key, "ts.2"));
        let mut headers = HeaderMap::new();
        assert!(
            key.bind_response_headers(&headers, 1, COOKIE, 1700000000)
                .unwrap()
                .is_none()
        );
        assert!(
            key.bind_server_cookie(COOKIE, 1, COOKIE, 1700000000)
                .unwrap()
                .is_none()
        );
        headers.insert(
            "bd-ticket-guard-server-data",
            HeaderValue::from_str(&encoded).unwrap(),
        );
        let a = key
            .bind_response_headers(&headers, 1, COOKIE, 1700000000)
            .unwrap()
            .unwrap();
        let escaped = encoded
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let carrier = format!("bd_ticket_guard_server_data={escaped}; Path=/; Secure");
        let b = key
            .bind_server_cookie(&carrier, 1, COOKIE, 1700000000)
            .unwrap()
            .unwrap();
        let sign = |m| {
            key.sign_send(m, 1, COOKIE, 1700000001, GuardMode::Ecdsa)
                .unwrap()
        };
        assert_eq!(sign(&a), sign(&b));
        headers.append(
            "bd-ticket-guard-server-data",
            HeaderValue::from_str(&encoded).unwrap(),
        );
        assert!(
            key.bind_response_headers(&headers, 1, COOKIE, 1700000000)
                .is_err()
        );
        assert!(
            key.bind_server_cookie(
                &format!("{carrier}; bd_ticket_guard_server_data={encoded}"),
                1,
                COOKIE,
                1700000000
            )
            .is_err()
        );
        for value in ["%", "%GG", "%FF", "not-base64!"] {
            assert!(
                key.bind_server_cookie(
                    &format!("bd_ticket_guard_server_data={value}"),
                    1,
                    COOKIE,
                    1700000000
                )
                .is_err()
            );
        }
        // 解析失败没有修改先前已绑定材料。
        assert_eq!(sign(&a), sign(&b));
    }

    #[test]
    fn from_saved_rejects_ancient_create_time() {
        let key = key(1);
        let now = chrono::Utc::now().timestamp();
        let ancient_time = now - 86400 * 35; // 35天前
        let json = serde_json::to_string(&serde_json::json!({
            "ticket": "hash.ancient",
            "ts_sign": "ts.2.test",
            "client_cert": format!("pub.{}", key.public_key_base64()),
            "create_time": ancient_time
        }))
        .unwrap();

        let err = BoundGuardMaterial::from_saved(&json, 1, COOKIE, now, &key.public_key_base64());
        assert!(err.is_err(), "35天前生成的古老票据必须被拒绝以防平台 KICK");
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("EXPIRED_BY_CREATE_TIME")
        );

        let fresh_time = now - 3600; // 1小时前
        let fresh_json = serde_json::to_string(&serde_json::json!({
            "ticket": "hash.fresh",
            "ts_sign": "ts.2.test",
            "client_cert": format!("pub.{}", key.public_key_base64()),
            "create_time": fresh_time
        }))
        .unwrap();
        assert!(
            BoundGuardMaterial::from_saved(&fresh_json, 1, COOKIE, now, &key.public_key_base64())
                .is_ok()
        );
    }
}

fn strict_session_hash(cookie: &str) -> Result<String> {
    use sha2::Digest;
    ensure!(
        cookie.len() <= 128 * 1024 && !cookie.contains(['\r', '\n']),
        "GUARD_INVALID_SESSION"
    );
    let mut fields = std::collections::BTreeMap::new();
    for part in cookie.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        let name = name.trim();
        if matches!(name, "sessionid" | "sessionid_ss" | "sid_tt") {
            ensure!(
                fields.insert(name, value.trim()).is_none(),
                "GUARD_AMBIGUOUS_SESSION"
            );
        }
    }
    ensure!(
        fields.values().any(|v| !v.is_empty()),
        "GUARD_MISSING_SESSION"
    );
    let encoded = serde_json::to_vec(&fields).context("GUARD_SESSION_ENCODING")?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// 将 Cookie 按照抖音官方 Web Guard 规范进行对齐：
/// 1. 移除 `bd_ticket_guard_server_data` 与 `bd_ticket_guard_web_domain`（官方客户端获取 ticket 后会持久化到本地存储并从 Cookie 中移除，若发包残留会被 WAF 判定为非原生环境）；
/// 2. 移除旧的 `bd_ticket_guard_client_data`，动态生成与当前公钥严格一致的官方规范 Cookie 元数据：
///    `{"bd-ticket-guard-version":2,"bd-ticket-guard-iteration-version":1,"bd-ticket-guard-ree-public-key":"<PUBLIC_KEY>","bd-ticket-guard-web-version":2}`；
/// 3. 补齐 `bd_ticket_guard_client_web_domain=2`、`_bd_ticket_crypt_doamin=2`、`__security_server_data_status=1`；
/// 4. 动态计算或安全移除 `_bd_ticket_crypt_cookie`：若提供有效 Guard 材料，强制重算并覆盖匹配的 MD5 哈希；若无材料则移除残留旧值，根除凭证分叉导致的被踢下线。
pub fn public_key_to_spki_pem(public_key_base64: &str) -> Result<String> {
    let raw_bytes = STANDARD
        .decode(public_key_base64)
        .context("GUARD_DECODE_PUBLIC_KEY_BASE64")?;
    ensure!(
        raw_bytes.len() == 65 && raw_bytes[0] == 0x04,
        "GUARD_INVALID_SEC1_UNCOMPRESSED_KEY"
    );
    let spki_der = p256_spki_der(&raw_bytes)?;
    let b64 = STANDARD.encode(&spki_der);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----"
    ))
}

fn p256_spki_der(sec1_uncompressed: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        sec1_uncompressed.len() == 65 && sec1_uncompressed[0] == 0x04,
        "GUARD_INVALID_SEC1_UNCOMPRESSED_KEY"
    );
    // 标准 ECDSA P-256 SPKI DER 固定头部 (26 字节)
    const SPKI_HEADER: [u8; 26] = [
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // SEQUENCE, 19 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, // OID: 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, // OID: 1.2.840.10045.3.1.7 (secp256r1)
        0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused bits
    ];
    let mut spki_der = Vec::with_capacity(91);
    spki_der.extend_from_slice(&SPKI_HEADER);
    spki_der.extend_from_slice(sec1_uncompressed);
    Ok(spki_der)
}

/// 计算抖音前端官方规范的 `_bd_ticket_crypt_cookie`：
/// 公式：MD5(JSON.stringify({ publicKey, cert, serverData }))
/// 注意：必须严格遵从前端对象声明顺序 publicKey -> cert -> serverData
#[derive(Serialize)]
struct CryptCookiePayload<'a> {
    #[serde(rename = "publicKey")]
    public_key: &'a str,
    cert: &'a str,
    #[serde(rename = "serverData")]
    server_data: &'a str,
}

pub fn compute_ticket_crypt_cookie(
    public_key_base64: &str,
    client_cert: &str,
    server_data_json: &str,
) -> Result<String> {
    let pem = public_key_to_spki_pem(public_key_base64)?;
    let payload = CryptCookiePayload {
        public_key: &pem,
        cert: client_cert,
        server_data: server_data_json,
    };
    let payload_bytes = serde_json::to_vec(&payload).context("GUARD_SERIALIZE_CRYPT_PAYLOAD")?;
    let digest = md5::compute(&payload_bytes);
    Ok(format!("{:x}", digest))
}

/// 将 Cookie 按照抖音官方 Web Guard 规范进行对齐
pub fn align_guard_cookie(
    old_cookie: &str,
    public_key_base64: &str,
    material: Option<&BoundGuardMaterial>,
) -> Result<String> {
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
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

    // 移除诱发风控注销的非原生残留字段
    map.remove("bd_ticket_guard_server_data");
    map.remove("bd_ticket_guard_web_domain");

    // 注入与当前公钥对齐的官方 ClientData 元数据；必须复用官方字段顺序。
    let client_data_json = guard_declaration_json(public_key_base64)?;
    let client_data_b64 = STANDARD.encode(client_data_json.as_bytes());
    // 官方 Web SDK 在 Cookie 中使用 encodeURIComponent 存储，对末尾 padding '=' 进行转义
    let client_data_cookie = client_data_b64.replace('=', "%3D");

    map.insert("bd_ticket_guard_client_data".into(), client_data_cookie);
    map.insert("bd_ticket_guard_client_web_domain".into(), "2".into());
    map.insert("_bd_ticket_crypt_doamin".into(), "2".into());
    map.insert("__security_server_data_status".into(), "1".into());

    // 服务端每轮 response 都可能轮转 server_data。旧 crypt cookie 即使曾由浏览器原生生成，
    // 也会与当前公钥及材料形成分叉；只要材料有效就必须按同一三元组强制重算。
    if let Some(mat) = material {
        if let Ok(crypt_hash) = mat.compute_crypt_cookie() {
            map.insert("_bd_ticket_crypt_cookie".into(), crypt_hash);
        }
    } else {
        map.remove("_bd_ticket_crypt_cookie");
    }

    Ok(map
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; "))
}

#[cfg(test)]
mod session_boundary_tests {
    use super::*;
    #[test]
    fn duplicate_and_changed_secondary_session_fields_are_rejected() {
        for cookie in [
            "sessionid=B; sessionid=A",
            "sessionid=A; sessionid=A",
            "sessionid=A; sid_tt=X; sid_tt=Y",
        ] {
            assert!(strict_session_hash(cookie).is_err());
        }
        assert_ne!(
            strict_session_hash("sessionid=A; sid_tt=X").unwrap(),
            strict_session_hash("sessionid=A; sid_tt=Y").unwrap()
        );
        assert_eq!(
            strict_session_hash("sid_tt=X;sessionid=A;theme=dark").unwrap(),
            strict_session_hash("sessionid=A; sid_tt=X;theme=light").unwrap()
        );
        let key = GuardKey::generate();
        let data=serde_json::to_vec(&serde_json::json!({"ticket":"public-test","ts_sign":"ts.2.test","client_cert":format!("pub.{}",key.public_key_base64())})).unwrap();
        assert!(
            key.bind_response(&data, 1, "sessionid=B; sessionid=A", 1)
                .is_err()
        );
        let material = key
            .bind_response(&data, 1, "sessionid=A; sid_tt=X", 1)
            .unwrap();
        assert!(
            key.sign_send(&material, 1, "sessionid=A; sid_tt=Y", 2, GuardMode::Ecdsa)
                .is_err()
        );
        assert!(
            key.sign_send(
                &material,
                1,
                "sessionid=B; sessionid=A; sid_tt=X",
                2,
                GuardMode::Ecdsa
            )
            .is_err()
        );
    }

    #[test]
    fn guard_declaration_matches_official_field_order() {
        // 官方 Web SDK 解码后的 bd_ticket_guard_client_data 逐字节顺序：
        // version -> iteration-version -> ree-public-key -> web-version
        let key = GuardKey::generate();
        let pub_b64 = key.public_key_base64();
        let json = guard_declaration_json(&pub_b64).unwrap();
        let expected = format!(
            "{{\"bd-ticket-guard-version\":2,\"bd-ticket-guard-iteration-version\":1,\"bd-ticket-guard-ree-public-key\":\"{pub_b64}\",\"bd-ticket-guard-web-version\":2}}"
        );
        assert_eq!(json, expected, "声明字段顺序必须与官方逐字节一致");
        assert_eq!(
            key.initialization_cookie_value().unwrap(),
            STANDARD.encode(expected.as_bytes())
        );

        let aligned = align_guard_cookie("sessionid=test_sid", &pub_b64, None).unwrap();
        let cookie_value = aligned
            .split("; ")
            .find_map(|item| item.strip_prefix("bd_ticket_guard_client_data="))
            .expect("必须写入 bd_ticket_guard_client_data");
        assert!(
            cookie_value.ends_with("%3D%3D"),
            "官方以 encodeURIComponent 存储，padding 必须转义为 %3D"
        );
        assert_eq!(
            STANDARD.decode(cookie_value.replace("%3D", "=")).unwrap(),
            expected.as_bytes()
        );
    }

    #[test]
    fn test_align_guard_cookie_cleans_server_data_and_injects_matching_client_data() {
        let key = GuardKey::generate();
        let pub_b64 = key.public_key_base64();
        let raw = "sessionid=test_sid; bd_ticket_guard_server_data=old_sd; bd_ticket_guard_web_domain=old_wd; bd_ticket_guard_client_data=old_cd; other=val";
        let aligned = align_guard_cookie(raw, &pub_b64, None).unwrap();

        assert!(!aligned.contains("bd_ticket_guard_server_data"));
        assert!(!aligned.contains("bd_ticket_guard_web_domain="));
        assert!(aligned.contains("bd_ticket_guard_client_web_domain=2"));
        assert!(aligned.contains("_bd_ticket_crypt_doamin=2"));
        assert!(aligned.contains("__security_server_data_status=1"));
        assert!(aligned.contains("other=val"));
        assert!(aligned.contains("sessionid=test_sid"));

        let dict: std::collections::HashMap<_, _> = aligned
            .split("; ")
            .filter_map(|s| s.split_once('='))
            .collect();
        let cd_raw = dict["bd_ticket_guard_client_data"].replace("%3D", "=");
        let dec_bytes = STANDARD.decode(cd_raw).unwrap();
        let cd_json: serde_json::Value = serde_json::from_slice(&dec_bytes).unwrap();
        assert_eq!(cd_json["bd-ticket-guard-ree-public-key"], pub_b64.as_str());
        assert_eq!(cd_json["bd-ticket-guard-version"], 2);
        assert_eq!(cd_json["bd-ticket-guard-iteration-version"], 1);
        assert_eq!(cd_json["bd-ticket-guard-web-version"], 2);

        // 验证 session_hash 在对齐前后完全一致
        assert_eq!(
            strict_session_hash(raw).unwrap(),
            strict_session_hash(&aligned).unwrap()
        );
    }

    #[test]
    fn test_public_key_to_spki_pem_and_md5_match_browser_ground_truth() {
        let pub_b64 = "BGFaq8io5SwBjFRtksSx4bzQoVHg2hJfd/2ChRFpZadAoYne0osDEDsFKWBA9ed8vgnj3hhuBvnriTMcyLgY01I=";
        let pem = public_key_to_spki_pem(pub_b64).unwrap();
        let expected_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYVqryKjlLAGMVG2SxLHhvNChUeDaEl93/YKFEWllp0Chid7SiwMQOwUpYED153y+CePeGG4G+euJMxzIuBjTUg==\n-----END PUBLIC KEY-----";
        assert_eq!(pem, expected_pem);

        let cert = "pub.BGFaq8io5SwBjFRtksSx4bzQoVHg2hJfd/2ChRFpZadAoYne0osDEDsFKWBA9ed8vgnj3hhuBvnriTMcyLgY01I=";
        let server_data = "{\"ticket\":\"hash.0OUKYBRXYEFUzzsTWuF70kvix4rQZtG0h3VdSgcdhsI=\",\"ts_sign\":\"ts.2.d9787ffcc11e89c9d693e451e8f7efbd59a2ceca1c635aac443c36d30b6cf08fc4fbe87d2319cf05318624ceda14911ca406dedbebeddb2e30fce8d4fa02575d\",\"client_cert\":\"pub.BGFaq8io5SwBjFRtksSx4bzQoVHg2hJfd/2ChRFpZadAoYne0osDEDsFKWBA9ed8vgnj3hhuBvnriTMcyLgY01I=\",\"log_id\":\"202610171656566DA35E4C1EAA37DDB3F7\",\"create_time\":1792227417}";

        let md5_hash = compute_ticket_crypt_cookie(pub_b64, cert, server_data).unwrap();
        assert_eq!(md5_hash, "3f605150b8259e3e9d635033906b031d");

        let material = BoundGuardMaterial::from_saved(
            server_data,
            1,
            "sessionid=test_cookie",
            chrono::Utc::now().timestamp(),
            pub_b64,
        )
        .unwrap();
        // 已有历史 crypt cookie 时必须按当前材料覆盖，避免公钥与哈希分叉
        let aligned_replace = align_guard_cookie(
            "sessionid=test_cookie; _bd_ticket_crypt_cookie=native_hash_123",
            pub_b64,
            Some(&material),
        )
        .unwrap();
        assert!(
            aligned_replace.contains("_bd_ticket_crypt_cookie=3f605150b8259e3e9d635033906b031d")
        );

        // 缺失 _bd_ticket_crypt_cookie 时同样由材料计算补齐
        let aligned_fill =
            align_guard_cookie("sessionid=test_cookie", pub_b64, Some(&material)).unwrap();
        assert!(aligned_fill.contains("_bd_ticket_crypt_cookie=3f605150b8259e3e9d635033906b031d"));

        let cleaned_without_mat = align_guard_cookie(
            "sessionid=test_cookie; _bd_ticket_crypt_cookie=native_hash_123",
            pub_b64,
            None,
        )
        .unwrap();
        assert!(!cleaned_without_mat.contains("_bd_ticket_crypt_cookie"));
    }
}
