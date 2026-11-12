//! 抖音 40.8.0 安卓 IM 发送请求合同。
//!
//! 来源是 `X.1TxS` 与 `PlatformApi.syncPostSDKEncrypt`，不是 Web IM。
//! 四神头不在这个类里生成。TTNet 回调 `onCallToAddSecurityFactor`
//! 最终调用 `ms.bd.c.k3.a(0x03000001, 0, 0, url, headerPairs)`。
//! 该命令还没有稳定返回可复核的签名头，所以这里只构造请求，不发网络。

use anyhow::{Result, ensure};

pub const SEND_URL: &str = "https://imapi.snssdk.com/v1/message/send";
pub const SIGN_COMMAND: u32 = 0x0300_0001;
pub const CONTENT_TYPE: &str = "application/x-protobuf";

/// `libsscronet.so` 里出现过的签名头名字。
/// 它们是原生签名器的字典，不是 Java 层写死在每次 IM 请求上的头。
pub const NATIVE_SECURITY_HEADER_NAMES: &[&str] = &[
    "x-argus",
    "x-gorgon",
    "x-khronos",
    "x-ladon",
    "x-ss-stub",
    "x-tt-token",
    "x-bd-client-key",
    "x-bd-kmsv",
];

#[derive(Clone, Debug)]
pub struct AndroidImDevice {
    pub aid: String,
    pub version_code: String,
    pub device_id: String,
    pub install_id: String,
    pub channel: String,
    pub app_name: String,
    pub os_api: String,
    pub os_version: String,
    pub device_type: String,
    pub device_brand: String,
    pub language: String,
    pub package: String,
    pub version_name: String,
    pub resolution: String,
    pub dpi: String,
    pub host_abi: String,
    pub cpu_support64: String,
    pub ac: String,
}

#[derive(Clone, Debug)]
pub struct AndroidImHeaders {
    pub content_type: String,
    pub request_tag: String,
    pub is_retry: String,
    pub flow_tag: String,
    pub encrypt_key: String,
    pub encrypt_body: String,
    pub body_compress: String,
}

impl AndroidImHeaders {
    pub fn protobuf(request_tag: impl Into<String>) -> Self {
        Self {
            content_type: CONTENT_TYPE.to_string(),
            request_tag: request_tag.into(),
            is_retry: "0".to_string(),
            flow_tag: "old".to_string(),
            encrypt_key: String::new(),
            encrypt_body: String::new(),
            body_compress: "1".to_string(),
        }
    }

    pub fn pairs(&self) -> Vec<(&str, &str)> {
        vec![
            ("Content-Type", self.content_type.as_str()),
            ("x-tt-request-tag", self.request_tag.as_str()),
            ("is-retry", self.is_retry.as_str()),
            ("flow-tag", self.flow_tag.as_str()),
            ("x-tt-e-k", self.encrypt_key.as_str()),
            ("x-tt-e-b", self.encrypt_body.as_str()),
            ("x-metasec-bp-body-compress", self.body_compress.as_str()),
        ]
    }
}

impl AndroidImDevice {
    fn require_official_ids(&self) -> Result<()> {
        ensure!(
            official_id(&self.device_id),
            "IM 发送需要官方 device_id，不能使用空号或 0"
        );
        ensure!(
            official_id(&self.install_id),
            "IM 发送需要官方 install_id，不能使用空号或 0"
        );
        Ok(())
    }
}

pub fn send_url(device: &AndroidImDevice, now_ms: u64) -> Result<String> {
    device.require_official_ids()?;
    ensure!(now_ms > 0, "IM 发送时间戳无效");
    let ts = (now_ms / 1000).to_string();
    let rticket = now_ms.to_string();
    // version_code、manifest_version_code、update_version_code 在 1TxS 里三次都取
    // AppContext.LIZLLL() -> AppContextManager.LIZ()，不是 getUpdateVersionCode()。
    let pairs = [
        ("aid", device.aid.as_str()),
        ("version_code", device.version_code.as_str()),
        ("device_id", device.device_id.as_str()),
        ("iid", device.install_id.as_str()),
        ("channel", device.channel.as_str()),
        ("app_name", device.app_name.as_str()),
        ("os", "android"),
        ("os_api", device.os_api.as_str()),
        ("os_version", device.os_version.as_str()),
        ("device_platform", "android"),
        ("device_type", device.device_type.as_str()),
        ("device_brand", device.device_brand.as_str()),
        ("language", device.language.as_str()),
        ("package", device.package.as_str()),
        ("version_name", device.version_name.as_str()),
        ("resolution", device.resolution.as_str()),
        ("dpi", device.dpi.as_str()),
        ("host_abi", device.host_abi.as_str()),
        ("cpu_support64", device.cpu_support64.as_str()),
        ("ac", device.ac.as_str()),
        ("ssmix", "a"),
        ("manifest_version_code", device.version_code.as_str()),
        ("update_version_code", device.version_code.as_str()),
        ("ts", ts.as_str()),
        ("_rticket", rticket.as_str()),
    ];
    let mut url = String::from(SEND_URL);
    url.push('?');
    for (index, (key, value)) in pairs.iter().enumerate() {
        ensure!(
            !key.is_empty() && !value.is_empty(),
            "IM 查询参数 {key} 为空"
        );
        if index > 0 {
            url.push('&');
        }
        url.push_str(&uri_encode(key));
        url.push('=');
        url.push_str(&uri_encode(value));
    }
    Ok(url)
}

/// 签名器输入是头名和头值交替排列的字符串数组，顺序跟 Retrofit 参数一致。
pub fn signer_header_pairs(headers: &AndroidImHeaders) -> Vec<String> {
    headers
        .pairs()
        .into_iter()
        .flat_map(|(key, value)| [key.to_string(), value.to_string()])
        .collect()
}

pub fn require_security_headers(headers: &[(String, String)]) -> Result<()> {
    ensure!(
        !headers.is_empty(),
        "MetaSec 0x03000001 没有返回签名头，禁止改发安卓 IM"
    );
    let known = headers.iter().any(|(name, value)| {
        !value.is_empty()
            && NATIVE_SECURITY_HEADER_NAMES
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
    });
    ensure!(known, "返回的头不在 sscronet 签名字典里，禁止改发安卓 IM");
    Ok(())
}

fn official_id(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "0" && value.chars().all(|ch| ch.is_ascii_digit())
}

fn uri_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_uri_allowed(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex(byte >> 4));
            out.push(hex(byte & 0x0f));
        }
    }
    out
}

fn is_uri_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'-' | b'!' | b'.' | b'~' | b'\'' | b'(' | b')' | b'*'
        )
}

fn hex(nibble: u8) -> char {
    char::from(b"0123456789ABCDEF"[nibble as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> AndroidImDevice {
        AndroidImDevice {
            aid: "1128".into(),
            version_code: "400801".into(),
            device_id: "123456789".into(),
            install_id: "987654321".into(),
            channel: "update".into(),
            app_name: "aweme".into(),
            os_api: "34".into(),
            os_version: "14".into(),
            device_type: "Pixel Tablet".into(),
            device_brand: "google".into(),
            language: "zh".into(),
            package: "com.ss.android.ugc.aweme".into(),
            version_name: "40.8.0".into(),
            resolution: "2560*1600".into(),
            dpi: "320".into(),
            host_abi: "arm64-v8a".into(),
            cpu_support64: "true".into(),
            ac: "wifi".into(),
        }
    }

    #[test]
    fn send_query_follows_android_40_8_order() {
        let url = send_url(&device(), 1_700_000_123_456).unwrap();
        assert_eq!(
            url,
            "https://imapi.snssdk.com/v1/message/send?aid=1128&version_code=400801&device_id=123456789&iid=987654321&channel=update&app_name=aweme&os=android&os_api=34&os_version=14&device_platform=android&device_type=Pixel%20Tablet&device_brand=google&language=zh&package=com.ss.android.ugc.aweme&version_name=40.8.0&resolution=2560*1600&dpi=320&host_abi=arm64-v8a&cpu_support64=true&ac=wifi&ssmix=a&manifest_version_code=400801&update_version_code=400801&ts=1700000123&_rticket=1700000123456"
        );
    }

    #[test]
    fn local_zero_device_cannot_build_send_url() {
        let mut item = device();
        item.device_id = "0".into();
        assert!(send_url(&item, 1).is_err());
    }

    #[test]
    fn signer_input_and_gate_match_metasec_command() {
        let headers = AndroidImHeaders::protobuf("im-send");
        assert_eq!(SIGN_COMMAND, 0x0300_0001);
        assert_eq!(
            signer_header_pairs(&headers),
            vec![
                "Content-Type",
                "application/x-protobuf",
                "x-tt-request-tag",
                "im-send",
                "is-retry",
                "0",
                "flow-tag",
                "old",
                "x-tt-e-k",
                "",
                "x-tt-e-b",
                "",
                "x-metasec-bp-body-compress",
                "1",
            ]
        );
        assert!(require_security_headers(&[]).is_err());
        assert!(require_security_headers(&[("x-argus".into(), "abc".into())]).is_ok());
        assert!(require_security_headers(&[("cookie".into(), "a=b".into())]).is_err());
    }
}
