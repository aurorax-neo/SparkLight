//! PCIM Guard 纯 Rust 计算层。没有网络、浏览器私钥导入或发送能力。
//! 依据官方 5770.1fc7435b.js；材料绑定通过不等于服务端授权已验收。
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use p256::{ecdh::diffie_hellman, ecdsa::{signature::Signer, Signature, SigningKey}, elliptic_curve::sec1::ToEncodedPoint, pkcs8::DecodePublicKey, PublicKey, SecretKey};
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
pub struct GuardKey { secret: SecretKey }
impl GuardKey {
    pub fn generate() -> Self { Self { secret: SecretKey::random(&mut rand::rngs::OsRng) } }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| anyhow::anyhow!("GUARD_INVALID_SECRET_KEY"))?;
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
    /// 官方 _processCookie 的公钥初始化声明；不是发送签名，也不是服务端授权。
    pub fn initialization_cookie_value(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Declaration {
            #[serde(rename="bd-ticket-guard-version")] version: u8,
            #[serde(rename="bd-ticket-guard-iteration-version")] iteration: u8,
            #[serde(rename="bd-ticket-guard-ree-public-key")] public: String,
            #[serde(rename="bd-ticket-guard-web-version")] web_version: u8,
        }
        let declaration = Declaration { version:2, iteration:1, public:self.public_key_base64(), web_version:2 };
        Ok(STANDARD.encode(serde_json::to_vec(&declaration).context("GUARD_ENCODE_FAILED")?))
    }
    pub fn initialization_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert("bd-ticket-guard-ree-public-key",HeaderValue::from_str(&self.public_key_base64()).map_err(|_|anyhow::anyhow!("GUARD_INVALID_HEADER"))?);
        headers.insert("bd-ticket-guard-web-version",HeaderValue::from_static("2"));
        headers.insert("bd-ticket-guard-web-sign-type",HeaderValue::from_static("0"));
        headers.insert("bd-ticket-guard-version",HeaderValue::from_static("2"));
        Ok(headers)
    }
    /// 只接收预期官方 HTTPS 响应解析出的材料。调用方仍须校验来源/账号身份。
    pub fn bind_response(&self, json: &[u8], uid: u64, cookie: &str, acquired_at: i64) -> Result<BoundGuardMaterial> {
        ensure!(json.len() <= 32 * 1024 && uid > 0 && acquired_at > 0, "GUARD_INVALID_INPUT");
        let data: ServerMaterial = serde_json::from_slice(json).map_err(|_| anyhow::anyhow!("GUARD_INVALID_SERVER_DATA"))?;
        ensure!(!data.ticket.is_empty() && data.ticket.len() <= 16 * 1024 && !data.ticket.contains(['&','\r','\n']), "GUARD_INVALID_TICKET");
        ensure!(!data.ts_sign.is_empty() && data.ts_sign.len() <= 16 * 1024, "GUARD_INVALID_TS_SIGN");
        ensure!(data.ts_sign.starts_with("ts.1") || data.ts_sign.starts_with("ts.2"), "GUARD_CERT_BRANCH_UNSUPPORTED");
        let public = self.public_key_base64();
        ensure!(data.client_cert.strip_prefix("pub.") == Some(public.as_str()), "GUARD_KEY_BINDING_MISMATCH");
        Ok(BoundGuardMaterial { data, uid, session_hash: strict_session_hash(cookie)?, acquired_at, public })
    }
    /// 官方响应头载体；拒绝重复头，缺失返回 None，不生成替代材料。
    pub fn bind_response_headers(&self, headers: &HeaderMap, uid: u64, cookie: &str, acquired_at: i64) -> Result<Option<BoundGuardMaterial>> {
        let values: Vec<_> = headers.get_all("bd-ticket-guard-server-data").iter().collect();
        ensure!(values.len() <= 1, "GUARD_AMBIGUOUS_SERVER_DATA");
        let Some(value) = values.first() else { return Ok(None); };
        let encoded = value.to_str().map_err(|_| anyhow::anyhow!("GUARD_INVALID_SERVER_DATA"))?;
        self.bind_base64(encoded, uid, cookie, acquired_at).map(Some)
    }
    /// 仅解析 bd_ticket_guard_server_data，不读取客户端签名或私钥 Cookie。
    pub fn bind_server_cookie(&self, response_cookie: &str, uid: u64, session_cookie: &str, acquired_at: i64) -> Result<Option<BoundGuardMaterial>> {
        ensure!(response_cookie.len() <= 128 * 1024, "GUARD_INVALID_INPUT");
        let values: Vec<_> = response_cookie.split(';').filter_map(|part| {
            let (name,value) = part.trim().split_once('=')?;
            (name == "bd_ticket_guard_server_data").then_some(value)
        }).collect();
        ensure!(values.len() <= 1, "GUARD_AMBIGUOUS_SERVER_DATA");
        let Some(value) = values.first() else { return Ok(None); };
        let mut decoded = Vec::new(); let bytes = value.as_bytes(); let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                ensure!(i + 2 < bytes.len(), "GUARD_INVALID_ENCODING");
                let high = (bytes[i+1] as char).to_digit(16).context("GUARD_INVALID_ENCODING")?;
                let low = (bytes[i+2] as char).to_digit(16).context("GUARD_INVALID_ENCODING")?;
                decoded.push((high * 16 + low) as u8); i += 3;
            } else { decoded.push(bytes[i]); i += 1; }
        }
        // decodeURIComponent 不将 '+' 转为空格，不能使用表单 URL 解码。
        let decoded = String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("GUARD_INVALID_ENCODING"))?;
        self.bind_base64(&decoded, uid, session_cookie, acquired_at).map(Some)
    }
    fn bind_base64(&self, encoded: &str, uid: u64, cookie: &str, acquired_at: i64) -> Result<BoundGuardMaterial> {
        ensure!(encoded.len() <= 44 * 1024, "GUARD_INVALID_INPUT");
        let json = STANDARD.decode(encoded).map_err(|_| anyhow::anyhow!("GUARD_INVALID_ENCODING"))?;
        self.bind_response(&json, uid, cookie, acquired_at)
    }
    /// 固定发送路径，时间由调用方的已验证时钟提供；不复用缓存签名。
    pub fn sign_send(&self, material: &BoundGuardMaterial, uid: u64, cookie: &str, timestamp: i64, mode: GuardMode<'_>) -> Result<HeaderMap> {
        self.sign_path(material, "/v1/message/send", uid, cookie, timestamp, mode)
    }
    /// 通用路径签名：用于 /v1/message/send 以及 /passport/token/beat/web/ 等需要 Guard 签名的路径。
    pub fn sign_path(&self, material: &BoundGuardMaterial, path: &str, uid: u64, cookie: &str, timestamp: i64, mode: GuardMode<'_>) -> Result<HeaderMap> {
        ensure!(uid == material.uid && material.session_hash == strict_session_hash(cookie)?, "GUARD_SESSION_CHANGED");
        ensure!(material.public == self.public_key_base64(), "GUARD_KEY_BINDING_MISMATCH");
        // 本地保守门限，不声明这是平台票据的真实 TTL。
        ensure!(timestamp.checked_sub(material.acquired_at).is_some_and(|v| (0..=86400 * 30).contains(&v)), "GUARD_MATERIAL_STALE");
        let input = format!("ticket={}&path={path}&timestamp={timestamp}", material.data.ticket);
        let (signature, sign_type) = match mode {
            GuardMode::Ecdsa => {
                let key = SigningKey::from(&self.secret);
                let signature: Signature = key.sign(input.as_bytes());
                (STANDARD.encode(signature.to_der().as_bytes()), "0")
            }
            GuardMode::Hmac { server_spki_der } => {
                let server = PublicKey::from_public_key_der(server_spki_der).map_err(|_| anyhow::anyhow!("GUARD_INVALID_SERVER_PUBLIC_KEY"))?;
                let shared = diffie_hellman(self.secret.to_nonzero_scalar(), server.as_affine());
                let mut derived = [0u8; 32];
                hkdf::Hkdf::<Sha256>::new(None, shared.raw_secret_bytes()).expand(&[], &mut derived).map_err(|_| anyhow::anyhow!("GUARD_KDF_FAILED"))?;
                let mut mac = Hmac::<Sha256>::new_from_slice(&derived).map_err(|_| anyhow::anyhow!("GUARD_HMAC_FAILED"))?;
                mac.update(input.as_bytes());
                derived.fill(0);
                (STANDARD.encode(mac.finalize().into_bytes()), "1")
            }
        };
        let t_trust = Some(1);
        let payload = ClientData { ts_sign: &material.data.ts_sign, req_content: "ticket,path,timestamp", req_sign: &signature, timestamp, t_trust };
        let value = STANDARD.encode(serde_json::to_vec(&payload).context("GUARD_ENCODE_FAILED")?);
        let mut headers = HeaderMap::new();
        for (name, text) in [("bd-ticket-guard-ree-public-key", material.public.as_str()), ("bd-ticket-guard-web-version", if material.data.ts_sign.starts_with("ts.1") { "1" } else { "2" }), ("bd-ticket-guard-web-sign-type", sign_type), ("bd-ticket-guard-version", "2"), ("bd-ticket-guard-client-data", value.as_str())] {
            let mut header = HeaderValue::from_str(text).map_err(|_| anyhow::anyhow!("GUARD_INVALID_HEADER"))?;
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
pub struct BoundGuardMaterial { pub data: ServerMaterial, pub uid: u64, pub session_hash: String, pub acquired_at: i64, pub public: String }
impl BoundGuardMaterial {
    pub fn server_data_json(&self) -> Result<String> {
        serde_json::to_string(&self.data).context("GUARD_SERIALIZE_SERVER_DATA")
    }
    pub fn from_saved(json: &str, uid: u64, cookie: &str, acquired_at: i64, expected_public: &str) -> Result<Self> {
        let data: ServerMaterial = serde_json::from_str(json).context("GUARD_DESERIALIZE_SERVER_DATA")?;
        ensure!(data.client_cert.strip_prefix("pub.") == Some(expected_public), "GUARD_KEY_BINDING_MISMATCH");
        let now = chrono::Utc::now().timestamp();
        ensure!(now.saturating_sub(acquired_at) <= 86400, "GUARD_MATERIAL_EXPIRED_BY_ACQUIRED_AT: 当前账号 Guard 签名票据材料获取已超过 24 小时，已安全拦截发送以防被平台注销会话；请在已登录抖音页面使用油猴脚本(v2.2.3)点击「⚡ 复制 SparkLight 全量凭证」更新导入");
        if let Some(ct) = data.create_time {
            ensure!(ct <= 0 || now.saturating_sub(ct) <= 86400, "GUARD_MATERIAL_EXPIRED_BY_CREATE_TIME: 当前账号 Guard 签名票据已过期（生成时间已超过 24 小时），已安全拦截发送以防被平台注销会话；请在已登录抖音页面使用油猴脚本(v2.2.3)点击「⚡ 复制 SparkLight 全量凭证」更新导入");
        }
        if let Some(log_id) = &data.log_id {
            if log_id.len() >= 8 && log_id[..8].chars().all(|c| c.is_ascii_digit()) {
                if let Ok(log_date) = chrono::NaiveDate::parse_from_str(&log_id[..8], "%Y%m%d") {
                    let current_date = chrono::Utc::now().date_naive();
                    ensure!((current_date - log_date).num_days() <= 1, "GUARD_MATERIAL_EXPIRED_BY_LOG_ID: 当前账号 Guard 签名票据 log_id 显示生成时间早于 1 天前，已安全拦截发送以防被平台注销会话；请在已登录抖音页面使用油猴脚本(v2.2.3)点击「⚡ 复制 SparkLight 全量凭证」更新导入");
                }
            }
        }
        Ok(Self {
            data,
            uid,
            session_hash: strict_session_hash(cookie)?,
            acquired_at,
            public: expected_public.to_owned(),
        })
    }
    pub fn is_stale(&self, now: i64, max_age_secs: i64) -> bool {
        now.checked_sub(self.acquired_at).map_or(true, |age| age > max_age_secs)
    }
    pub fn ticket(&self) -> &str { &self.data.ticket }
    pub fn public_key(&self) -> &str { &self.public }
    pub fn acquired_at(&self) -> i64 { self.acquired_at }
}
pub enum GuardMode<'a> { Ecdsa, Hmac { server_spki_der: &'a [u8] } }

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    const COOKIE: &str = "sessionid=public-offline-only";
    fn key(n: u8) -> GuardKey { GuardKey { secret: SecretKey::from_slice(&[n;32]).unwrap() } }
    fn material(key: &GuardKey, prefix: &str) -> Vec<u8> { serde_json::to_vec(&serde_json::json!({"ticket":"offline-ticket","ts_sign":format!("{prefix}.offline"),"client_cert":format!("pub.{}",key.public_key_base64())})).unwrap() }
    #[test]
    fn ecdsa_wire_format_and_binding() {
        let key=key(1);
        let declaration=STANDARD.decode(key.initialization_cookie_value().unwrap()).unwrap();
        let expected=format!("{{\"bd-ticket-guard-version\":2,\"bd-ticket-guard-iteration-version\":1,\"bd-ticket-guard-ree-public-key\":\"{}\",\"bd-ticket-guard-web-version\":2}}",key.public_key_base64());
        assert_eq!(declaration,expected.as_bytes());
        let initial=key.initialization_headers().unwrap();
        assert_eq!(initial.len(),4);
        assert_eq!(initial["bd-ticket-guard-web-sign-type"],"0");
        assert!(!initial.contains_key("bd-ticket-guard-client-data"));
        for prefix in ["ts.1", "ts.2"] {
            let bound=key.bind_response(&material(&key,prefix),99191692311,COOKIE,1700000000).unwrap();
            let headers=key.sign_send(&bound,99191692311,COOKIE,1700000001,GuardMode::Ecdsa).unwrap();
            assert_eq!(key.public_key_base64().len(),88);
            assert_eq!(headers["bd-ticket-guard-web-version"],if prefix=="ts.1" {"1"}else{"2"});
            assert_eq!(headers["bd-ticket-guard-web-sign-type"],"0");
            assert!(!headers.contains_key("bd-ticket-guard-iteration-version"));
            assert_eq!(headers.len(), 5);
            assert!(headers.values().all(|v|v.is_sensitive()));
            let decoded=STANDARD.decode(headers["bd-ticket-guard-client-data"].as_bytes()).unwrap();
            let data:serde_json::Value=serde_json::from_slice(&decoded).unwrap();
            assert_eq!(data["req_content"],"ticket,path,timestamp");
            assert_eq!(data["timestamp"],1700000001);
            let sig=Signature::from_der(&STANDARD.decode(data["req_sign"].as_str().unwrap()).unwrap()).unwrap();
            let public=VerifyingKey::from(&SigningKey::from(&key.secret));
            assert_eq!(data["t_trust"], 1);
            public.verify(b"ticket=offline-ticket&path=/v1/message/send&timestamp=1700000001",&sig).unwrap();
            assert!(public.verify(b"ticket=offline-ticket&path=/other&timestamp=1700000001",&sig).is_err());
        }
    }
    #[test]
    fn official_pcim_headers_and_node_crypto_match() {
        assert!(PublicKey::from_public_key_der(OFFICIAL_SERVER_SPKI_DER).is_ok());
        let fixture: serde_json::Value = serde_json::from_str(include_str!("sdk/pcim_guard_baseline.json")).unwrap();
        let scalar = hex::decode(fixture["test_only_scalar_hex"].as_str().unwrap()).unwrap();
        let key = GuardKey { secret: SecretKey::from_slice(&scalar).unwrap() };
        assert_eq!(key.public_key_base64(), fixture["public_key_sec1_base64"]);
        let server = STANDARD.decode(fixture["server_public_spki_base64"].as_str().unwrap()).unwrap();
        let public = VerifyingKey::from(&SigningKey::from(&key.secret));
        for case in fixture["cases"].as_array().unwrap() {
            let raw = serde_json::to_vec(&serde_json::json!({"ticket":fixture["ticket"],"ts_sign":case["ts_sign"],"client_cert":format!("pub.{}",key.public_key_base64())})).unwrap();
            let bound = key.bind_response(&raw, 1, COOKIE, 1700000000).unwrap();
            let hmac = case["mode"] == "hmac";
            let headers = key.sign_send(&bound, 1, COOKIE, fixture["timestamp"].as_i64().unwrap(), if hmac { GuardMode::Hmac { server_spki_der: &server } } else { GuardMode::Ecdsa }).unwrap();
            for (name, expected) in case["headers"].as_object().unwrap() {
                let expected = expected.as_str().map(str::to_owned).unwrap_or_else(||expected.to_string());
                assert_eq!(headers.get(name).unwrap().to_str().unwrap(), expected);
            }
            let data: serde_json::Value = serde_json::from_slice(&STANDARD.decode(headers["bd-ticket-guard-client-data"].as_bytes()).unwrap()).unwrap();
            assert_eq!(data["ts_sign"], case["ts_sign"]);
            assert_eq!(data["req_content"], case["input"]["req_content"]);
            assert_eq!(data["timestamp"], case["input"]["timestamp"]);
            assert_eq!(data["t_trust"], 1);
            if hmac {
                assert_eq!(data["req_sign"], case["signature_base64"].as_str().unwrap());
            } else {
                for signature in [data["req_sign"].as_str().unwrap(), case["signature_base64"].as_str().unwrap()] {
                    let signature = Signature::from_der(&STANDARD.decode(signature).unwrap()).unwrap();
                    public.verify(case["input"]["sign_data"].as_str().unwrap().as_bytes(), &signature).unwrap();
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_key_session_age_and_material() {
        let a=key(1);let b=key(2);let raw=material(&a,"ts.2");
        assert!(b.bind_response(&raw,1,COOKIE,1700000000).is_err());
        let bound=a.bind_response(&raw,1,COOKIE,1700000000).unwrap();
        for (uid,cookie,ts) in [(2,COOKIE,1700000001),(1,"sessionid=changed",1700000001),(1,COOKIE,1699999999),(1,COOKIE,1700000000 + 86400 * 30 + 1)] {assert!(a.sign_send(&bound,uid,cookie,ts,GuardMode::Ecdsa).is_err());}
        assert!(b.sign_send(&bound,1,COOKIE,1700000001,GuardMode::Ecdsa).is_err());
        assert!(a.sign_send(&bound,1,COOKIE,1700000001,GuardMode::Hmac{server_spki_der:b"invalid"}).is_err());
        assert!(a.bind_response(&material(&a,"legacy"),1,COOKIE,1).is_err());
        assert!(a.bind_response(br#"{"ticket":"a","ticket":"b","ts_sign":"ts.2.x","client_cert":"pub.x"}"#,1,COOKIE,1).is_err());
    }
    #[test]
    fn official_header_and_cookie_carriers_are_equivalent_and_strict() {
        let key=key(1); let encoded=STANDARD.encode(material(&key,"ts.2"));
        let mut headers=HeaderMap::new();
        assert!(key.bind_response_headers(&headers,1,COOKIE,1700000000).unwrap().is_none());
        assert!(key.bind_server_cookie(COOKIE,1,COOKIE,1700000000).unwrap().is_none());
        headers.insert("bd-ticket-guard-server-data",HeaderValue::from_str(&encoded).unwrap());
        let a=key.bind_response_headers(&headers,1,COOKIE,1700000000).unwrap().unwrap();
        let escaped=encoded.replace('+',"%2B").replace('/',"%2F").replace('=',"%3D");
        let carrier=format!("bd_ticket_guard_server_data={escaped}; Path=/; Secure");
        let b=key.bind_server_cookie(&carrier,1,COOKIE,1700000000).unwrap().unwrap();
        let sign=|m|key.sign_send(m,1,COOKIE,1700000001,GuardMode::Ecdsa).unwrap();
        assert_eq!(sign(&a),sign(&b));
        headers.append("bd-ticket-guard-server-data",HeaderValue::from_str(&encoded).unwrap());
        assert!(key.bind_response_headers(&headers,1,COOKIE,1700000000).is_err());
        assert!(key.bind_server_cookie(&format!("{carrier}; bd_ticket_guard_server_data={encoded}"),1,COOKIE,1700000000).is_err());
        for value in ["%", "%GG", "%FF", "not-base64!"] {
            assert!(key.bind_server_cookie(&format!("bd_ticket_guard_server_data={value}"),1,COOKIE,1700000000).is_err());
        }
        // 解析失败没有修改先前已绑定材料。
        assert_eq!(sign(&a),sign(&b));
    }

    #[test]
    fn from_saved_rejects_ancient_create_time() {
        let key = key(1);
        let now = chrono::Utc::now().timestamp();
        let ancient_time = now - 86400 * 25; // 25天前
        let json = serde_json::to_string(&serde_json::json!({
            "ticket": "hash.ancient",
            "ts_sign": "ts.2.test",
            "client_cert": format!("pub.{}", key.public_key_base64()),
            "create_time": ancient_time
        })).unwrap();

        let err = BoundGuardMaterial::from_saved(&json, 1, COOKIE, now, &key.public_key_base64());
        assert!(err.is_err(), "25天前生成的古老票据必须被拒绝以防平台 KICK");
        assert!(err.unwrap_err().to_string().contains("EXPIRED_BY_CREATE_TIME"));

        let fresh_time = now - 3600; // 1小时前
        let fresh_json = serde_json::to_string(&serde_json::json!({
            "ticket": "hash.fresh",
            "ts_sign": "ts.2.test",
            "client_cert": format!("pub.{}", key.public_key_base64()),
            "create_time": fresh_time
        })).unwrap();
        assert!(BoundGuardMaterial::from_saved(&fresh_json, 1, COOKIE, now, &key.public_key_base64()).is_ok());
    }
}

fn strict_session_hash(cookie: &str) -> Result<String> {
    use sha2::Digest;
    ensure!(cookie.len() <= 128 * 1024 && !cookie.contains(['\r','\n']), "GUARD_INVALID_SESSION");
    let mut fields = std::collections::BTreeMap::new();
    for part in cookie.split(';') {
        let Some((name,value)) = part.trim().split_once('=') else { continue; };
        let name=name.trim();
        if matches!(name,"sessionid"|"sessionid_ss"|"sid_tt") {
            ensure!(fields.insert(name,value.trim()).is_none(), "GUARD_AMBIGUOUS_SESSION");
        }
    }
    ensure!(fields.values().any(|v|!v.is_empty()), "GUARD_MISSING_SESSION");
    let encoded=serde_json::to_vec(&fields).context("GUARD_SESSION_ENCODING")?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

#[cfg(test)]
mod session_boundary_tests {
    use super::*;
    #[test]
    fn duplicate_and_changed_secondary_session_fields_are_rejected() {
        for cookie in ["sessionid=B; sessionid=A","sessionid=A; sessionid=A","sessionid=A; sid_tt=X; sid_tt=Y"] { assert!(strict_session_hash(cookie).is_err()); }
        assert_ne!(strict_session_hash("sessionid=A; sid_tt=X").unwrap(),strict_session_hash("sessionid=A; sid_tt=Y").unwrap());
        assert_eq!(strict_session_hash("sid_tt=X;sessionid=A;theme=dark").unwrap(),strict_session_hash("sessionid=A; sid_tt=X;theme=light").unwrap());
        let key=GuardKey::generate();
        let data=serde_json::to_vec(&serde_json::json!({"ticket":"public-test","ts_sign":"ts.2.test","client_cert":format!("pub.{}",key.public_key_base64())})).unwrap();
        assert!(key.bind_response(&data,1,"sessionid=B; sessionid=A",1).is_err());
        let material=key.bind_response(&data,1,"sessionid=A; sid_tt=X",1).unwrap();
        assert!(key.sign_send(&material,1,"sessionid=A; sid_tt=Y",2,GuardMode::Ecdsa).is_err());
        assert!(key.sign_send(&material,1,"sessionid=B; sessionid=A; sid_tt=X",2,GuardMode::Ecdsa).is_err());
    }
}
