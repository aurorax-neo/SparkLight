//! DTrait 1.0.0.16 中央报文纯计算层；不伪造/采集浏览器特征，不具有发送能力。
use aes::cipher::{BlockEncrypt, KeyInit};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use reqwest::header::HeaderValue;
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPublicKey};
use serde::{Deserialize, Serialize};

pub struct DTraitCipher {
    aes_key: [u8; 16],
    encrypted_key: String,
    version: String,
}
impl Drop for DTraitCipher { fn drop(&mut self) { self.aes_key.fill(0); } }
impl DTraitCipher {
    /// public_pem 应来自已核验官方配置；这里只验证密钥格式，不证明其来源。
    pub fn new(public_pem: &str, version: &str) -> Result<Self> {
        ensure!(public_pem.len() <= 16 * 1024 && !version.is_empty() && version.len() <= 128 && version.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'), "DTRAIT_INVALID_CONFIG");
        let public = RsaPublicKey::from_public_key_pem(public_pem).or_else(|_| RsaPublicKey::from_pkcs1_pem(public_pem)).map_err(|_| anyhow::anyhow!("DTRAIT_INVALID_PUBLIC_KEY"))?;
        ensure!((1024..=4096).contains(&public.n().bits()), "DTRAIT_UNSUPPORTED_KEY_SIZE");
        let mut aes_key = [0u8; 16]; rand::rngs::OsRng.fill_bytes(&mut aes_key);
        // 官方 RSA 加密 AES key 的 32 字符小写 hex 文本，不是原始 16 字节。
        let encrypted = public.encrypt(&mut rand::rngs::OsRng, Pkcs1v15Encrypt, hex::encode(aes_key).as_bytes()).map_err(|_| anyhow::anyhow!("DTRAIT_RSA_FAILED"))?;
        Ok(Self { aes_key, encrypted_key: STANDARD.encode(encrypted), version: version.to_owned() })
    }
    /// 解析 type=trait 官方响应；不把公共配置获取成功等同于账号授权签发。
    pub fn from_server_response(bytes: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Response { message: String, data: Config }
        #[derive(Deserialize)]
        struct Config {
            #[serde(rename="x-tt-session-dtrait-pk1")] public: String,
            #[serde(rename="x-tt-session-dtrait-pk1-version")] version: String,
        }
        ensure!(bytes.len() <= 64 * 1024, "DTRAIT_INVALID_CONFIG");
        let response: Response = serde_json::from_slice(bytes).map_err(|_|anyhow::anyhow!("DTRAIT_INVALID_CONFIG"))?;
        ensure!(response.message == "success", "DTRAIT_CONFIG_REJECTED");
        let pem = STANDARD.decode(response.data.public).map_err(|_|anyhow::anyhow!("DTRAIT_INVALID_PUBLIC_KEY"))?;
        let pem = String::from_utf8(pem).map_err(|_|anyhow::anyhow!("DTRAIT_INVALID_PUBLIC_KEY"))?;
        Self::new(&pem,&response.data.version)
    }
    /// 特征串由调用方提供真实采集结果；本层不能保证特征有效或被服务端接受。
    pub fn central_header(&self, dtrait: &str, path: &str, rewrite: &[(String,String)], timestamp: i64) -> Result<HeaderValue> {
        let plain = central_plaintext(dtrait, path, rewrite, timestamp)?;
        let mut iv = [0u8; 16]; rand::rngs::OsRng.fill_bytes(&mut iv);
        let value = self.header_with_iv(plain.as_bytes(), &iv);
        let mut header = HeaderValue::from_str(&value).map_err(|_| anyhow::anyhow!("DTRAIT_INVALID_HEADER"))?;
        header.set_sensitive(true); Ok(header)
    }
    fn header_with_iv(&self, plain: &[u8], iv: &[u8;16]) -> String {
        format!("{}_{}_{}", self.version, self.encrypted_key, STANDARD.encode(aes_cbc(&self.aes_key,iv,plain)))
    }
}
#[derive(Serialize)]
struct Central<'a> { dtrait: &'a str, timestamp: i64, #[serde(rename="sdkVersion")] sdk_version: &'static str, path: &'a str }
fn central_plaintext(dtrait: &str, path: &str, rewrite: &[(String,String)], timestamp: i64) -> Result<String> {
    ensure!(!dtrait.is_empty() && dtrait.len() <= 64 * 1024 && timestamp > 0 && timestamp <= 9_007_199_254_740_991, "DTRAIT_INVALID_INPUT");
    ensure!(valid_path(path) && rewrite.len() <= 64, "DTRAIT_INVALID_PATH");
    let mut current=path;
    for (from,to) in rewrite {
        ensure!(valid_path(from) && valid_path(to), "DTRAIT_INVALID_REWRITE");
        // 官方规则：前缀命中后替换整个路径，且后续规则继续处理。
        if current.starts_with(from) { current=to; }
    }
    serde_json::to_string(&Central { dtrait, timestamp, sdk_version:"1.0.0.16", path:current }).map_err(|_|anyhow::anyhow!("DTRAIT_JSON_FAILED"))
}
fn valid_path(path: &str) -> bool { path.starts_with('/') && path.len() <= 4096 && !path.contains(['?','#','\r','\n']) }
fn aes_cbc(key: &[u8;16], iv: &[u8;16], plain: &[u8]) -> Vec<u8> {
    let cipher=aes::Aes128::new(key.into());
    let padding=16-plain.len()%16;
    let mut padded=plain.to_vec();padded.resize(plain.len()+padding,padding as u8);
    let mut output=Vec::with_capacity(16+padded.len());output.extend_from_slice(iv);
    let mut previous=*iv;
    for chunk in padded.chunks_exact_mut(16) {
        for (byte,last) in chunk.iter_mut().zip(previous) { *byte ^= last; }
        let mut block=aes::cipher::Block::<aes::Aes128>::default();block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);previous.copy_from_slice(&block);output.extend_from_slice(&block);
    }
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{pkcs8::{EncodePublicKey,LineEnding},RsaPrivateKey};
    fn fixture()->serde_json::Value {serde_json::from_str(include_str!("sdk/pcim_dtrait_baseline.json")).unwrap()}
    fn bytes(v:&serde_json::Value)->Vec<u8>{v.as_array().unwrap().iter().map(|n|n.as_u64().unwrap() as u8).collect()}
    #[test]
    fn official_aes_and_central_headers_match_exactly() {
        let f=fixture();let jobs=f["aesJobs"].as_array().unwrap();
        for job in jobs {
            let key:[u8;16]=bytes(&job["key"]).try_into().unwrap();let iv:[u8;16]=bytes(&job["iv"]).try_into().unwrap();
            let output=aes_cbc(&key,&iv,job["plaintext"].as_str().unwrap().as_bytes());
            assert_eq!(STANDARD.encode(&output[16..]),job["ciphertext"]);
            assert_eq!(&output[..16],&iv);
        }
        let key:[u8;16]=bytes(&jobs[1]["key"]).try_into().unwrap();
        let cipher=DTraitCipher {aes_key:key,encrypted_key:f["rsa_ciphertext"].as_str().unwrap().into(),version:"test-central-v1".into()};
        let plain=central_plaintext("OFFLINE_SYNTHETIC_CENTRAL","/offline/probe",&[],1700000000).unwrap();
        assert_eq!(plain,jobs[1]["plaintext"]);
        assert_eq!(cipher.header_with_iv(plain.as_bytes(),&bytes(&jobs[1]["iv"]).try_into().unwrap()),f["header"]);
        let rewritten=central_plaintext("OFFLINE_SYNTHETIC_CENTRAL","/offline/probe/suffix",&[("/offline".into(),"/first".into()),("/first".into(),"/rewritten".into())],1700000000).unwrap();
        let data:serde_json::Value=serde_json::from_str(&rewritten).unwrap();assert_eq!(data["path"],"/rewritten");
    }
    #[test]
    fn rsa_wraps_hex_key_and_headers_use_fresh_iv() {
        let private=RsaPrivateKey::new(&mut rand::rngs::OsRng,1024).unwrap();
        let pem=private.to_public_key().to_public_key_pem(LineEnding::LF).unwrap();
        let cipher=DTraitCipher::new(&pem,"test-v1").unwrap();
        let clear=private.decrypt(Pkcs1v15Encrypt,&STANDARD.decode(&cipher.encrypted_key).unwrap()).unwrap();
        assert_eq!(clear,hex::encode(cipher.aes_key).as_bytes());
        let a=cipher.central_header("public-test-only","/offline",&[],1700000000).unwrap();
        let b=cipher.central_header("public-test-only","/offline",&[],1700000000).unwrap();
        assert_ne!(a,b);assert!(a.is_sensitive()&&b.is_sensitive());
        use rsa::pkcs1::EncodeRsaPublicKey;
        let pkcs1=private.to_public_key().to_pkcs1_pem(LineEnding::LF).unwrap();
        let response=serde_json::json!({"message":"success","data":{"x-tt-session-dtrait-pk1":STANDARD.encode(pkcs1.as_bytes()),"x-tt-session-dtrait-pk1-version":"test-v1"}});
        let parsed=DTraitCipher::from_server_response(&serde_json::to_vec(&response).unwrap()).unwrap();
        let clear=private.decrypt(Pkcs1v15Encrypt,&STANDARD.decode(&parsed.encrypted_key).unwrap()).unwrap();
        assert_eq!(clear,hex::encode(parsed.aes_key).as_bytes());
        let mut rejected=response.clone();rejected["message"]="error".into();
        assert!(DTraitCipher::from_server_response(&serde_json::to_vec(&rejected).unwrap()).is_err());
        assert!(DTraitCipher::from_server_response(br#"{"message":"success","data":{}}"#).is_err());
    }
    #[test]
    fn rejects_missing_features_invalid_path_and_config() {
        assert!(central_plaintext("","/p",&[],1).is_err());
        assert!(central_plaintext("x","/p?x=1",&[],1).is_err());
        assert!(central_plaintext("x","/p",&[],0).is_err());
        assert!(central_plaintext("x","/p",&[("/p".into(),"https://other".into())],1).is_err());
        assert!(DTraitCipher::new("not-a-key","1").is_err());
    }
}
