use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct SecretBox(XChaCha20Poly1305);

impl SecretBox {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(XChaCha20Poly1305::new(key.into()))
    }

    pub fn from_encoded(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let key = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(raw).context("invalid hex master key")?
        } else {
            STANDARD
                .decode(raw)
                .or_else(|_| URL_SAFE_NO_PAD.decode(raw))
                .context("master key must be 64 hex digits or 32-byte standard base64/base64url")?
        };
        if key.len() != 32 {
            bail!("master key must contain exactly 32 bytes");
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        Ok(Self::new(&key_bytes))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut result = nonce.to_vec();
        result.extend(
            self.0
                .encrypt(XNonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow::anyhow!("encryption failed"))?,
        );
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 40 {
            bail!("invalid encrypted value: too short");
        }
        self.0
            .decrypt(XNonce::from_slice(&ciphertext[..24]), &ciphertext[24..])
            .map_err(|_| anyhow::anyhow!("decryption failed: invalid key or corrupted data"))
    }
}

pub fn mask_cookie(cookie: &str) -> String {
    if cookie.trim().is_empty() {
        return String::new();
    }
    let parts: Vec<String> = cookie
        .split(';')
        .map(|item| {
            let item = item.trim();
            if let Some((k, v)) = item.split_once('=') {
                let v = v.trim();
                let masked_val = if v.len() <= 4 {
                    "***".to_string()
                } else if v.len() <= 8 {
                    format!("{}***", &v[..2])
                } else {
                    format!("{}***{}", &v[..3], &v[v.len().saturating_sub(3)..])
                };
                format!("{}={}", k.trim(), masked_val)
            } else {
                item.to_string()
            }
        })
        .collect();
    parts.join("; ")
}

pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    format!("sk_{}", hex::encode(bytes))
}

pub fn hash_api_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.trim().as_bytes()))
}

pub fn load_or_create_master_key(data_dir: &Path) -> Result<SecretBox> {
    for env_name in ["SPARK_MASTER_KEY", "SPARKLIGHT_MASTER_KEY"] {
        if let Ok(val) = std::env::var(env_name) {
            if !val.trim().is_empty() {
                return SecretBox::from_encoded(&val)
                    .with_context(|| format!("failed to parse master key from {env_name}"));
            }
        }
    }

    fs::create_dir_all(data_dir).context("failed to create data directory")?;
    let key_path = data_dir.join(".master-key");

    if key_path.exists() {
        let mut file = OpenOptions::new()
            .read(true)
            .open(&key_path)
            .context("failed to open existing master key file")?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .context("failed to read master key file")?;
        return SecretBox::from_encoded(content.trim())
            .context("failed to parse existing master key file");
    }

    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let hex_key = hex::encode(key_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .context("failed to create new master key file")?;
        file.write_all(hex_key.as_bytes())
            .context("failed to write master key")?;
    }
    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&key_path)
            .context("failed to create new master key file")?;
        file.write_all(hex_key.as_bytes())
            .context("failed to write master key")?;
    }

    Ok(SecretBox::new(&key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_box_encrypt_decrypt() {
        let key = [42u8; 32];
        let box_ = SecretBox::new(&key);
        let secret = b"my_douyin_cookie_sessionid_123456";
        let ciphertext = box_.encrypt(secret).expect("encrypt");
        assert_ne!(ciphertext, secret);
        let decrypted = box_.decrypt(&ciphertext).expect("decrypt");
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_secret_box_tamper_detection() {
        let key = [99u8; 32];
        let box_ = SecretBox::new(&key);
        let mut ciphertext = box_.encrypt(b"secret").expect("encrypt");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert!(box_.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_mask_cookie() {
        let raw = "sessionid=0123456789abcdef; passport_csrf_token=123456; short=12";
        let masked = mask_cookie(raw);
        assert!(masked.contains("sessionid=012***def"));
        assert!(masked.contains("passport_csrf_token=12***"));
        assert!(masked.contains("short=***"));
    }

    #[test]
    fn test_api_key_generation() {
        let key = generate_api_key();
        assert!(key.starts_with("sk_"));
        let hash = hash_api_key(&key);
        assert_eq!(hash.len(), 64);
    }
}
