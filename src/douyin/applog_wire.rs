//! 抖音设备登记报文封包。
//!
//! 格式来自桌面端 `deviceregister_arm64.node` 的本地反汇编，不是 REA Evidence：
//! JSON 先按 zlib windowBits=31 做 gzip，再用 applog AES-128-CBC。
//! 密文头固定为 `tc\x05\x10\x00\x00`，随后 32 字节随机盐。盐的 SHA-512
//! 与库内 64 字节常量混合后再哈希，得到 16 字节密钥和 16 字节 IV。
//! 明文是原始数据的 SHA-512 拼上原始数据，PKCS7 填充。

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha512};

const HEADER: [u8; 6] = [0x74, 0x63, 0x05, 0x10, 0x00, 0x00];
const MIX: [u8; 64] = [
    0x4d, 0xd4, 0xc2, 0xe6, 0xb8, 0x31, 0x62, 0x09, 0x0e, 0x52, 0xb3, 0xc7, 0xa6, 0x73, 0x3b, 0xa4,
    0x1c, 0xb2, 0x46, 0x2b, 0x82, 0x9a, 0xb5, 0x8a, 0x19, 0x6b, 0x39, 0xdb, 0x57, 0x17, 0x75, 0x24,
    0xf4, 0x9b, 0xaf, 0x7f, 0x08, 0xe8, 0xd6, 0x8d, 0x26, 0xa7, 0x2e, 0x37, 0xc1, 0xa9, 0x5a, 0x2f,
    0x1f, 0x05, 0xa5, 0x18, 0x92, 0xae, 0xf2, 0x94, 0x97, 0x32, 0xb6, 0x2a, 0x38, 0xaa, 0xdd, 0x58,
];

pub fn seal_register_body(json: &[u8]) -> Result<Vec<u8>> {
    let gzipped = gzip(json).context("设备登记报文压缩失败")?;
    let mut salt = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    Ok(encrypt(&salt, &gzipped))
}

pub fn open_register_response(bytes: &[u8]) -> Vec<u8> {
    let trimmed = trim_ascii_start(bytes);
    if trimmed
        .first()
        .is_some_and(|byte| *byte == b'{' || *byte == b'[')
    {
        return bytes.to_vec();
    }
    if bytes.starts_with(&HEADER) {
        if let Ok(plain) = decrypt(bytes) {
            return inflate_if_gzip(&plain).unwrap_or(plain);
        }
    }
    inflate_if_gzip(bytes).unwrap_or_else(|_| bytes.to_vec())
}

fn encrypt(salt: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let (key, iv) = derive_key(salt);
    let digest = Sha512::digest(data);
    let mut plain = Vec::with_capacity(64 + data.len());
    plain.extend_from_slice(&digest);
    plain.extend_from_slice(data);
    let cipher = aes_cbc_encrypt(&key, &iv, &plain);
    let mut out = Vec::with_capacity(HEADER.len() + salt.len() + cipher.len());
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(salt);
    out.extend_from_slice(&cipher);
    out
}

fn decrypt(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < HEADER.len() + 32 + 16 || !bytes.starts_with(&HEADER) {
        bail!("设备登记响应不是 applog 密文");
    }
    let mut salt = [0_u8; 32];
    salt.copy_from_slice(&bytes[HEADER.len()..HEADER.len() + 32]);
    let (key, iv) = derive_key(&salt);
    let plain =
        aes_cbc_decrypt(&key, &iv, &bytes[HEADER.len() + 32..]).context("设备登记响应解密失败")?;
    if plain.len() < 64 {
        bail!("设备登记响应解密后过短");
    }
    let digest = Sha512::digest(&plain[64..]);
    if digest.as_slice() != &plain[..64] {
        bail!("设备登记响应校验失败");
    }
    Ok(plain[64..].to_vec())
}

fn derive_key(salt: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let first = Sha512::digest(salt);
    let mut material = [0_u8; 128];
    material[..64].copy_from_slice(&first);
    material[64..].copy_from_slice(&MIX);
    let second = Sha512::digest(material);
    let mut key = [0_u8; 16];
    let mut iv = [0_u8; 16];
    key.copy_from_slice(&second[..16]);
    iv.copy_from_slice(&second[16..32]);
    (key, iv)
}

fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(key.into());
    let padding = 16 - plain.len() % 16;
    let mut padded = plain.to_vec();
    padded.resize(plain.len() + padding, padding as u8);
    let mut previous = *iv;
    let mut output = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(16) {
        let mut block = aes::cipher::Block::<aes::Aes128>::default();
        for (index, byte) in chunk.iter().enumerate() {
            block[index] = byte ^ previous[index];
        }
        cipher.encrypt_block(&mut block);
        previous.copy_from_slice(&block);
        output.extend_from_slice(&block);
    }
    output
}

fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], cipher_text: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    if cipher_text.is_empty() || cipher_text.len() % 16 != 0 {
        bail!("密文长度不是 16 的倍数");
    }
    let cipher = aes::Aes128::new(key.into());
    let mut previous = *iv;
    let mut output = Vec::with_capacity(cipher_text.len());
    for chunk in cipher_text.chunks_exact(16) {
        let mut block = aes::cipher::Block::<aes::Aes128>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (byte, last) in block.iter_mut().zip(previous) {
            *byte ^= last;
        }
        previous.copy_from_slice(chunk);
        output.extend_from_slice(&block);
    }
    let padding = *output.last().context("密文为空")? as usize;
    if padding == 0 || padding > 16 || output.len() < padding {
        bail!("填充无效");
    }
    if output[output.len() - padding..]
        .iter()
        .any(|byte| *byte as usize != padding)
    {
        bail!("填充无效");
    }
    output.truncate(output.len() - padding);
    Ok(output)
}

fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data).context("写入 gzip 失败")?;
    encoder.finish().context("结束 gzip 失败")
}

fn inflate_if_gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        return Ok(bytes.to_vec());
    }
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .context("解压设备登记响应失败")?;
    Ok(out)
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let offset = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[offset..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_body_roundtrips_and_is_not_plaintext_json() {
        let json = br#"{"magic_tag":"ss_app_log","header":{"display_name":"douyin"}}"#;
        let sealed = seal_register_body(json).unwrap();
        assert!(sealed.starts_with(&HEADER));
        assert!(sealed.len() > HEADER.len() + 32);
        assert_ne!(&sealed[HEADER.len() + 32..], json);
        assert!(serde_json::from_slice::<serde_json::Value>(&sealed).is_err());
        let opened = decrypt(&sealed).unwrap();
        let plain = inflate_if_gzip(&opened).unwrap();
        assert_eq!(plain, json);
    }

    #[test]
    fn plaintext_json_response_is_left_untouched() {
        let raw = br#"{"device_id_str":"7123456789012345"}"#;
        assert_eq!(open_register_response(raw), raw);
    }
}
