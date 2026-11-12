//! 抖音 Android TicketGuard 证书引导。
//!
//! 此模块只处理官方软件 P-256 密钥的 CSR 与证书链请求。TEE 状态始终上报不可用，
//! 不生成、不伪造硬件证明。任何证书、私钥或签名材料都不会进入日志或 Debug 输出。

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use reqwest::{
    Client, Method,
    header::{self, HeaderMap, HeaderValue},
};
use serde::Serialize;
use serde_json::Value;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use super::pcim_guard::GuardKey;

const GET_CLIENT_CERT_URL: &str =
    "https://security.snssdk.com/passport/ticket_guard/get_client_cert/";
const VERIFY_PUB_KEY_URL: &str =
    "https://security.snssdk.com/passport/ticket_guard/verify_pub_key/";
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const PASSPORT_SDK_VERSION: &str = "60760";
const DISPLAY_OS_VERSION: &str = "UP1A.231005.007";
const SUBJECT_DER: &[u8] = &[
    0x30, 0x3b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x00, 0x31, 0x09, 0x30,
    0x07, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x00, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x13, 0x00, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0f, 0x62, 0x64,
    0x2d, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x67, 0x75, 0x61, 0x72, 0x64,
];

#[derive(Clone)]
pub struct TicketGuardChain {
    client_cert_pem: String,
    server_cert_pem: String,
    server_cert_sn: String,
    ree_public_key: String,
}

impl TicketGuardChain {
    pub fn public_key_base64(&self) -> &str {
        &self.ree_public_key
    }

    pub fn server_cert_sn(&self) -> &str {
        &self.server_cert_sn
    }

    pub fn client_cert_header(&self) -> Result<HeaderValue> {
        header_value(
            "bd-ticket-guard-client-cert",
            &STANDARD.encode(self.client_cert_pem.as_bytes()),
        )
    }

    pub fn request_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "bd-ticket-guard-ree-public-key",
            header_value("bd-ticket-guard-ree-public-key", &self.ree_public_key)?,
        );
        headers.insert("bd-ticket-guard-client-cert", self.client_cert_header()?);
        headers.insert(
            "bd-ticket-guard-server-cert-sn",
            header_value("bd-ticket-guard-server-cert-sn", &self.server_cert_sn)?,
        );
        headers.insert("bd-ticket-guard-tee-status", HeaderValue::from_static("0"));
        headers.insert("bd-ticket-guard-version", HeaderValue::from_static("3"));
        headers.insert(
            "bd-ticket-guard-display-os-version",
            HeaderValue::from_static(DISPLAY_OS_VERSION),
        );
        headers.insert(
            "bd-ticket-guard-iteration-version",
            HeaderValue::from_static("2"),
        );
        Ok(headers)
    }

    pub fn validate_attestation(&self) -> Result<()> {
        ensure!(
            self.ree_public_key.len() <= 4096
                && self.server_cert_sn.len() <= 4096
                && self.client_cert_pem.len() <= 64 * 1024
                && self.server_cert_pem.len() <= 64 * 1024,
            "TicketGuard 证书链字段超出安全上限"
        );
        let client_der = pem_der(&self.client_cert_pem, "CERTIFICATE")?;
        let server_der = pem_der(&self.server_cert_pem, "CERTIFICATE")?;
        let client_cert = parse_certificate(&client_der)?;
        let server_cert = parse_certificate(&server_der)?;
        ensure!(
            client_cert.tbs_certificate.subject_pki.raw.as_ref()
                == p256_public_key_der(&self.ree_public_key)?.as_slice(),
            "TicketGuard 客户端证书公钥不匹配"
        );
        validate_server_sn(&self.server_cert_sn, &server_cert)
    }

    pub fn report(&self) -> TicketGuardReport {
        TicketGuardReport {
            client_cert_pem_len: self.client_cert_pem.len(),
            server_cert_pem_len: self.server_cert_pem.len(),
            server_sn_len: self.server_cert_sn.len(),
            client_cert_matches_key: true,
            ..TicketGuardReport::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only() -> Self {
        Self {
            client_cert_pem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
                .to_string(),
            server_cert_pem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
                .to_string(),
            server_cert_sn: "1".to_string(),
            ree_public_key: GuardKey::generate().public_key_base64(),
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct TicketGuardReport {
    pub get_http_status: Option<u16>,
    pub get_top_error: Option<i64>,
    pub get_data_error: Option<i64>,
    pub client_cert_pem_len: usize,
    pub server_cert_pem_len: usize,
    pub server_sn_len: usize,
    pub client_cert_matches_key: bool,
    pub verify_http_status: Option<u16>,
    pub verify_result: Option<i64>,
    pub verify_accepted: bool,
    pub verify_top_error: Option<i64>,
    pub verify_data_error: Option<i64>,
    pub verify_header_present: bool,
    pub verify_body_keys: String,
    pub verify_data_keys: String,
    pub verify_description: Option<String>,
    pub verify_captcha_present: bool,
    pub verify_desc_url_host: Option<String>,
    pub verify_error: Option<String>,
}

pub async fn request_chain(
    client: &Client,
    key: &GuardKey,
    query: &[(String, String)],
) -> Result<(TicketGuardChain, TicketGuardReport)> {
    let csr = build_csr(key)?;
    let form = [
        ("csr".to_string(), STANDARD.encode(csr.as_bytes())),
        ("server_data".to_string(), "1".to_string()),
    ];
    let response = client
        .request(Method::POST, GET_CLIENT_CERT_URL)
        .headers(key.android_initialization_headers()?)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .header("sdk-version", "2")
        .header("passport-sdk-version", PASSPORT_SDK_VERSION)
        .header("x-tt-request-tag", "t=0;n=1")
        .query(query)
        .form(&form)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .context("TicketGuard 客户端证书请求网络失败")?;
    let get_status = response.status();
    let bytes = read_limited_body(response, "TicketGuard 客户端证书").await?;
    let root: Value =
        serde_json::from_slice(&bytes).context("TicketGuard 客户端证书响应不是合法 JSON")?;
    let (top_error, data_error) = response_error_codes(&root);
    let mut report = TicketGuardReport {
        get_http_status: Some(get_status.as_u16()),
        get_top_error: Some(top_error),
        get_data_error: Some(data_error),
        ..TicketGuardReport::default()
    };
    ensure!(
        get_status.is_success(),
        "TicketGuard 客户端证书请求返回 HTTP {get_status}"
    );
    ensure!(
        top_error == 0 && data_error == 0,
        "TicketGuard 客户端证书请求被拒绝（error={top_error} data_error={data_error}）"
    );
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .context("TicketGuard 客户端证书响应缺少 data")?;
    let client_cert_pem =
        string_field(data, "cert").context("TicketGuard 客户端证书响应缺少 cert")?;
    let server_cert_pem =
        string_field(data, "server_cert").context("TicketGuard 服务端证书响应缺少 server_cert")?;
    let server_cert_sn =
        string_field(data, "server_sn").context("TicketGuard 服务端证书响应缺少 server_sn")?;
    ensure!(
        client_cert_pem.len() <= 64 * 1024
            && server_cert_pem.len() <= 64 * 1024
            && server_cert_sn.len() <= 4096,
        "TicketGuard 证书材料超出安全上限"
    );
    let client_der = pem_der(&client_cert_pem, "CERTIFICATE")?;
    let server_der = pem_der(&server_cert_pem, "CERTIFICATE")?;
    let client_cert = parse_certificate(&client_der)?;
    let server_cert = parse_certificate(&server_der)?;
    ensure!(
        client_cert.tbs_certificate.subject_pki.raw.as_ref()
            == key.public_key_spki_der().as_slice(),
        "TicketGuard 客户端证书与软件 P-256 密钥不匹配"
    );
    report.client_cert_pem_len = client_cert_pem.len();
    report.server_cert_pem_len = server_cert_pem.len();
    report.server_sn_len = server_cert_sn.len();
    report.client_cert_matches_key = true;
    validate_server_sn(&server_cert_sn, &server_cert)?;

    let chain = TicketGuardChain {
        client_cert_pem,
        server_cert_pem,
        server_cert_sn,
        ree_public_key: key.public_key_base64(),
    };
    Ok((chain, report))
}

pub async fn verify_public_key(
    client: &Client,
    chain: &TicketGuardChain,
    query: &[(String, String)],
    mut report: TicketGuardReport,
) -> TicketGuardReport {
    let client_cert_header = match chain.client_cert_header() {
        Ok(header) => header,
        Err(error) => {
            report.verify_error = Some(format!("TicketGuard 客户端证书请求头无效：{error}"));
            return report;
        }
    };
    let client_cert_header = match client_cert_header.to_str() {
        Ok(value) => value,
        Err(_) => {
            report.verify_error = Some("TicketGuard 客户端证书请求头不是合法字符串".to_string());
            return report;
        }
    };
    let mut request = client
        .request(Method::POST, VERIFY_PUB_KEY_URL)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .header("sdk-version", "2")
        .header("passport-sdk-version", PASSPORT_SDK_VERSION)
        .query(query)
        .form(&[("bd-ticket-guard-attest-certs", "")]);
    for (name, value) in [
        (
            "bd-ticket-guard-ree-public-key",
            chain.ree_public_key.as_str(),
        ),
        ("bd-ticket-guard-client-cert", client_cert_header),
        ("x-tt-request-tag", "t=0;n=0"),
    ] {
        request = request.header(name, value);
    }
    let verify_response = match request.timeout(Duration::from_secs(20)).send().await {
        Ok(response) => response,
        Err(error) => {
            report.verify_error = Some(format!("TicketGuard 公钥验证网络失败：{error}"));
            return report;
        }
    };
    let verify_status = verify_response.status();
    let verify_header = verify_response
        .headers()
        .get("bd-ticket-guard-verify-public-key-result")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let verify_result = verify_header
        .as_deref()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let verify_body = match read_limited_body(verify_response, "TicketGuard 公钥验证").await {
        Ok(body) => body,
        Err(error) => {
            report.verify_error = Some(format!("TicketGuard 公钥验证读取失败：{error}"));
            return report;
        }
    };
    let verify_root = serde_json::from_slice::<Value>(&verify_body).unwrap_or(Value::Null);
    let (verify_top_error, verify_data_error) = response_error_codes(&verify_root);
    report.verify_http_status = Some(verify_status.as_u16());
    report.verify_result = verify_result;
    report.verify_top_error = Some(verify_top_error);
    report.verify_data_error = Some(verify_data_error);
    report.verify_header_present = verify_header.is_some();
    report.verify_body_keys = verify_root
        .as_object()
        .map(|object| {
            object
                .keys()
                .take(16)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    report.verify_data_keys = verify_root
        .get("data")
        .and_then(Value::as_object)
        .map(|object| {
            object
                .keys()
                .take(16)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let verify_data = verify_root.get("data");
    report.verify_description = verify_data
        .and_then(|data| data.get("description"))
        .and_then(Value::as_str)
        .map(|value| value.chars().take(160).collect());
    report.verify_captcha_present = verify_data
        .and_then(|data| data.get("captcha"))
        .is_some_and(|value| !value.is_null());
    report.verify_desc_url_host = verify_data
        .and_then(|data| data.get("desc_url"))
        .and_then(Value::as_str)
        .and_then(|value| reqwest::Url::parse(value).ok())
        .and_then(|url| url.host_str().map(str::to_string));
    report.verify_accepted = verify_status.is_success() && verify_result == Some(0);
    if !report.verify_accepted {
        report.verify_error = Some(format!(
            "TicketGuard 公钥验证未通过：http={} result={:?} error={} data_error={} body_bytes={}",
            verify_status,
            verify_result,
            verify_top_error,
            verify_data_error,
            verify_body.len()
        ));
    }
    report
}

pub async fn bootstrap(
    client: &Client,
    key: &GuardKey,
    query: &[(String, String)],
) -> Result<(TicketGuardChain, TicketGuardReport)> {
    let (chain, report) = request_chain(client, key, query).await?;
    let report = verify_public_key(client, &chain, query, report).await;
    Ok((chain, report))
}

/// 不携带 Cookie 的证书链探针。空 attestation 仅用于确认软件证书是否被接受，
/// 不代表 TEE 或硬件证明可用。
pub async fn probe(
    client: &Client,
    key: &GuardKey,
) -> Result<(TicketGuardChain, TicketGuardReport)> {
    bootstrap(client, key, &[]).await
}

pub fn build_csr(key: &GuardKey) -> Result<String> {
    let spki = key.public_key_spki_der();
    let basic_constraints = der_sequence(&[
        der_oid(&[0x55, 0x1d, 0x13])?,
        der_bool(true),
        der_octet_string(&der_sequence(&[der_bool(true)])),
    ]);
    let extension_request = der_sequence(&[
        der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e])?,
        der_set(&der_sequence(&[basic_constraints])),
    ]);
    let attributes = der_tagged_constructed(0, &der_sequence(&[extension_request]));
    let request_info = der_sequence(&[der_integer(&[0]), SUBJECT_DER.to_vec(), spki, attributes]);
    let signing_key = SigningKey::from(&p256::SecretKey::from_slice(&key.to_bytes())?);
    let signature: Signature = signing_key.sign(&request_info);
    let signature_der = signature.to_der();
    let signature_algorithm =
        der_sequence(&[der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])?]);
    let certification_request = der_sequence(&[
        request_info,
        signature_algorithm,
        der_bit_string(signature_der.as_bytes()),
    ]);
    Ok(pem_encode("CERTIFICATE REQUEST", &certification_request))
}

fn response_error_codes(root: &Value) -> (i64, i64) {
    let top = root.get("error_code").and_then(Value::as_i64).unwrap_or(0);
    let data = root
        .get("data")
        .and_then(|data| data.get("error_code"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    (top, data)
}

fn string_field(data: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn header_value(name: &str, value: &str) -> Result<HeaderValue> {
    let mut header = HeaderValue::from_str(value).with_context(|| format!("{name} 请求头无效"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn pem_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end).map(|(body, _)| body))
        .context("TicketGuard 证书 PEM 标签无效")?
        .lines()
        .map(str::trim)
        .collect::<String>();
    STANDARD
        .decode(body)
        .context("TicketGuard 证书 PEM 编码无效")
}

fn parse_certificate<'a>(der: &'a [u8]) -> Result<X509Certificate<'a>> {
    let (rest, cert) = X509Certificate::from_der(der).context("TicketGuard 证书 DER 无效")?;
    ensure!(rest.is_empty(), "TicketGuard 证书 DER 存在尾随数据");
    Ok(cert)
}

fn p256_public_key_der(public_key_base64: &str) -> Result<Vec<u8>> {
    let sec1 = STANDARD
        .decode(public_key_base64)
        .context("TicketGuard REE 公钥不是合法 Base64")?;
    super::pcim_guard::public_key_to_spki_pem(public_key_base64)
        .context("TicketGuard REE 公钥无效")?;
    ensure!(
        sec1.len() == 65 && sec1[0] == 0x04,
        "TicketGuard REE 公钥不是 P-256 非压缩点"
    );
    let mut der = Vec::with_capacity(91);
    der.extend_from_slice(&[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]);
    der.extend_from_slice(&sec1);
    Ok(der)
}

fn validate_server_sn(server_sn: &str, cert: &X509Certificate<'_>) -> Result<()> {
    let serial = cert.tbs_certificate.raw_serial_as_string();
    let server_cert_serial = cert.tbs_certificate.serial.to_string();
    let normalized = normalize_serial(server_sn);
    let serial_hex = normalize_serial(&serial);
    let serial_decimal = normalize_serial(&server_cert_serial);
    ensure!(
        !normalized.is_empty()
            && (normalized == serial_hex
                || normalized == serial_decimal
                || normalize_serial(&hex::encode(cert.tbs_certificate.serial.to_bytes_be()))
                    == normalized),
        "TicketGuard 服务端证书序号与 server_sn 不一致"
    );
    Ok(())
}

fn normalize_serial(value: &str) -> String {
    let value = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim_start_matches('0');
    if value.is_empty() {
        return "0".to_string();
    }
    value.to_ascii_lowercase()
}

async fn read_limited_body(response: reqwest::Response, label: &str) -> Result<Vec<u8>> {
    let status = response.status();
    ensure!(status.is_success(), "{label}返回 HTTP {status}");
    if let Some(length) = response.content_length() {
        ensure!(length <= MAX_RESPONSE_BYTES as u64, "{label}响应过大");
    }
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("{label}读取失败"))?;
    ensure!(bytes.len() <= MAX_RESPONSE_BYTES, "{label}响应过大");
    Ok(bytes.to_vec())
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let encoded = &bytes[first..];
    let mut out = Vec::with_capacity(encoded.len() + 1);
    out.push(0x80 | encoded.len() as u8);
    out.extend_from_slice(encoded);
    out
}

fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 1 + std::mem::size_of::<usize>());
    out.push(tag);
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_tagged_constructed(tag: u8, content: &[u8]) -> Vec<u8> {
    der_tag(0xa0 | tag, content)
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    der_tag(0x30, &parts.concat())
}

fn der_set(part: &[u8]) -> Vec<u8> {
    der_tag(0x31, part)
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    der_tag(0x02, bytes)
}

fn der_bool(value: bool) -> Vec<u8> {
    der_tag(0x01, &[if value { 0xff } else { 0x00 }])
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tag(0x04, content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(content.len() + 1);
    payload.push(0);
    payload.extend_from_slice(content);
    der_tag(0x03, &payload)
}

fn der_oid(encoded: &[u8]) -> Result<Vec<u8>> {
    ensure!(!encoded.is_empty(), "TicketGuard OID 为空");
    Ok(der_tag(0x06, encoded))
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::DecodePublicKey;
    use sha2::{Digest, Sha256};

    #[test]
    fn csr_matches_official_shape_and_signature() {
        let key = GuardKey::generate();
        let pem = build_csr(&key).unwrap();
        let der = pem_der(&pem, "CERTIFICATE REQUEST").unwrap();
        assert!(der.starts_with(&[0x30, 0x82]));
        assert!(pem.lines().all(|line| line.len() <= 64));
        assert!(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        let spki = key.public_key_spki_der();
        let position = der
            .windows(spki.len())
            .position(|window| window == spki.as_slice())
            .expect("CSR 必须包含软件密钥 SPKI");
        assert!(position > 0);
        assert!(p256::PublicKey::from_public_key_der(&spki).is_ok());
    }

    #[test]
    fn csr_der_lengths_are_canonical() {
        assert_eq!(der_length(127), vec![0x7f]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(der_length(65_535), vec![0x82, 0xff, 0xff]);
        let subject = der_sequence(&[der_integer(&[0]), SUBJECT_DER.to_vec()]);
        assert_eq!(subject[0], 0x30);
        assert_eq!(subject[1], subject.len() as u8 - 2);
    }

    #[test]
    fn certificate_parser_rejects_non_certificate() {
        assert!(parse_certificate(b"not a certificate").is_err());
    }

    #[test]
    fn spki_is_identical_for_both_encodings() {
        let key = GuardKey::generate();
        let pem =
            super::super::pcim_guard::public_key_to_spki_pem(&key.public_key_base64()).unwrap();
        assert_eq!(
            pem_der(&pem, "PUBLIC KEY").unwrap(),
            key.public_key_spki_der()
        );
    }

    #[test]
    fn sha256_signature_der_is_nonempty() {
        let key = GuardKey::generate();
        let signing_key = SigningKey::from(&p256::SecretKey::from_slice(&key.to_bytes()).unwrap());
        let signature: Signature = signing_key.sign(b"ticket guard");
        let der = signature.to_der();
        assert!(der.as_bytes().len() >= 8);
        assert_eq!(Sha256::digest(b"ticket guard").len(), 32);
    }
}
