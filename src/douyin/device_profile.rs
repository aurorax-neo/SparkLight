//! 账号级设备指纹隔离。
//!
//! 每个账号持有唯一且稳定的浏览器指纹：同一账号跨重启、跨进程一致，不同账号之间不共享
//! 任何可关联字段。指纹由账号 ID 确定性派生，只使用真实存在的浏览器版本与硬件组合，
//! 不随机、不轮换、不伪造检测结果。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 指纹格式版本。任何影响已落库账号观测值的修改都必须递增，避免线上账号中途换指纹。
pub const DEVICE_PROFILE_VERSION: u32 = 1;

const CHROME_MAJORS: [u32; 4] = [139, 140, 141, 142];
const SCREENS: [(u32, u32); 8] = [
    (1920, 1080),
    (2560, 1440),
    (1536, 864),
    (1440, 900),
    (1366, 768),
    (1680, 1050),
    (2560, 1600),
    (3840, 2160),
];
const CORES: [u32; 4] = [4, 8, 12, 16];
const MEMORY_GB: [u32; 3] = [8, 16, 32];
const COLOR_DEPTHS: [u32; 2] = [24, 30];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Windows,
    MacOs,
}

impl Platform {
    fn from_index(index: usize) -> Self {
        if index % 3 == 0 {
            Self::MacOs
        } else {
            Self::Windows
        }
    }

    fn ua_platform(self) -> &'static str {
        match self {
            Self::Windows => "Windows NT 10.0; Win64; x64",
            Self::MacOs => "Macintosh; Intel Mac OS X 10_15_7",
        }
    }

    fn sec_ch_ua_platform(self) -> &'static str {
        match self {
            Self::Windows => "\"Windows\"",
            Self::MacOs => "\"macOS\"",
        }
    }

    fn navigator_platform(self) -> &'static str {
        match self {
            Self::Windows => "Win32",
            Self::MacOs => "MacIntel",
        }
    }

    fn webgl(self, variant: usize) -> (&'static str, &'static str) {
        const WINDOWS: [(&str, &str); 3] = [
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (NVIDIA)",
                "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
            (
                "Google Inc. (AMD)",
                "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            ),
        ];
        const MAC: [(&str, &str); 3] = [
            (
                "Google Inc. (Apple)",
                "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)",
            ),
            (
                "Google Inc. (Apple)",
                "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
            ),
            (
                "Google Inc. (Intel)",
                "ANGLE (Intel, ANGLE Metal Renderer: Intel(R) Iris(TM) Plus Graphics, Unspecified Version)",
            ),
        ];
        match self {
            Self::Windows => WINDOWS[variant % WINDOWS.len()],
            Self::MacOs => MAC[variant % MAC.len()],
        }
    }
}

/// 单个账号独占的浏览器设备指纹。字段全部来自真实浏览器的可观测值。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub version: u32,
    pub user_agent: String,
    pub sec_ch_ua: String,
    pub sec_ch_ua_mobile: String,
    pub sec_ch_ua_platform: String,
    pub accept_language: String,
    pub platform: String,
    pub timezone: String,
    pub locale: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub device_scale_factor: u32,
    pub color_depth: u32,
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub webgl_vendor: String,
    pub webgl_renderer: String,
    /// 稳定设备标识；只用于本地指纹自检，不作为 Cookie 或请求头发送。
    pub device_tag: String,
}

impl DeviceProfile {
    /// 从账号 ID 确定性派生。同一账号永远得到同一指纹，不同账号得到不同指纹。
    pub fn derive(account_seed: &str) -> Self {
        let seed = format!("sparklight-device-v{DEVICE_PROFILE_VERSION}:{account_seed}");
        let digest = Sha256::digest(seed.as_bytes());
        let mut cursor = 0usize;
        let mut next = |modulus: usize| -> usize {
            let byte = digest[cursor % digest.len()] as usize;
            cursor += 1;
            byte % modulus
        };

        let platform = Platform::from_index(next(8));
        let chrome = CHROME_MAJORS[next(CHROME_MAJORS.len())];
        let (screen_width, screen_height) = SCREENS[next(SCREENS.len())];
        let hardware_concurrency = CORES[next(CORES.len())];
        let device_memory = MEMORY_GB[next(MEMORY_GB.len())];
        let color_depth = COLOR_DEPTHS[next(COLOR_DEPTHS.len())];
        let device_scale_factor = if platform == Platform::MacOs { 2 } else { 1 };
        // 视口按浏览器窗口而非整屏取值，保留系统任务栏与浏览器外框的合理差异。
        let viewport_width =
            screen_width.saturating_sub(if platform == Platform::MacOs { 0 } else { 16 });
        let viewport_height = screen_height.saturating_sub(if platform == Platform::MacOs {
            129
        } else {
            141
        });
        let (webgl_vendor, webgl_renderer) = platform.webgl(next(3));

        let device_tag = hex::encode(&Sha256::digest(format!("tag:{seed}").as_bytes())[..8]);

        Self {
            version: DEVICE_PROFILE_VERSION,
            user_agent: format!(
                "Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                platform.ua_platform()
            ),
            sec_ch_ua: format!(
                "\"Google Chrome\";v=\"{chrome}\", \"Chromium\";v=\"{chrome}\", \"Not(A:Brand\";v=\"24\""
            ),
            sec_ch_ua_mobile: "?0".to_string(),
            sec_ch_ua_platform: platform.sec_ch_ua_platform().to_string(),
            accept_language: "zh-CN,zh;q=0.9,en;q=0.8".to_string(),
            platform: platform.navigator_platform().to_string(),
            timezone: "Asia/Shanghai".to_string(),
            locale: "zh-CN".to_string(),
            screen_width,
            screen_height,
            viewport_width,
            viewport_height,
            device_scale_factor,
            color_depth,
            hardware_concurrency,
            device_memory,
            webgl_vendor: webgl_vendor.to_string(),
            webgl_renderer: webgl_renderer.to_string(),
            device_tag,
        }
    }

    /// 与内置 Web Passport 登录会话严格对齐的浏览器指纹（macOS Chrome 140 Apple M1）。
    /// 避免登录成功后引导 Web/IM 上下文时切换操作系统或显卡指纹触发防劫持注销。
    pub fn web_passport_profile(account_seed: &str) -> Self {
        let seed = format!("sparklight-device-v{DEVICE_PROFILE_VERSION}:{account_seed}");
        let device_tag = hex::encode(&Sha256::digest(format!("tag:{seed}").as_bytes())[..8]);
        Self {
            version: DEVICE_PROFILE_VERSION,
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36".to_string(),
            sec_ch_ua: "\"Google Chrome\";v=\"140\", \"Chromium\";v=\"140\", \"Not(A:Brand\";v=\"24\"".to_string(),
            sec_ch_ua_mobile: "?0".to_string(),
            sec_ch_ua_platform: "\"macOS\"".to_string(),
            accept_language: "zh-CN,zh;q=0.9,en;q=0.8".to_string(),
            platform: "MacIntel".to_string(),
            timezone: "Asia/Shanghai".to_string(),
            locale: "zh-CN".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            viewport_width: 1920,
            viewport_height: 945,
            device_scale_factor: 2,
            color_depth: 24,
            hardware_concurrency: 8,
            device_memory: 8,
            webgl_vendor: "Google Inc. (Apple)".to_string(),
            webgl_renderer: "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)".to_string(),
            device_tag,
        }
    }

    /// 拒绝任何不能作为 HTTP 头或与真实浏览器矛盾的指纹，防止把坏指纹写进线上请求。
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == DEVICE_PROFILE_VERSION,
            "设备指纹版本不受支持"
        );
        anyhow::ensure!(
            !self.user_agent.is_empty()
                && self.user_agent.len() <= 512
                && self.user_agent.starts_with("Mozilla/5.0 ("),
            "设备指纹 UA 无效"
        );
        for (name, value) in [
            ("sec-ch-ua", &self.sec_ch_ua),
            ("sec-ch-ua-mobile", &self.sec_ch_ua_mobile),
            ("sec-ch-ua-platform", &self.sec_ch_ua_platform),
            ("accept-language", &self.accept_language),
        ] {
            anyhow::ensure!(
                !value.is_empty() && value.len() <= 256,
                "设备指纹 {name} 无效"
            );
            reqwest::header::HeaderValue::from_str(value)
                .with_context(|| format!("设备指纹 {name} 不是合法 HTTP 头"))?;
        }
        reqwest::header::HeaderValue::from_str(&self.user_agent)
            .context("设备指纹 UA 不是合法 HTTP 头")?;
        anyhow::ensure!(
            self.screen_width >= 1024 && self.screen_height >= 600 && self.viewport_width >= 800,
            "设备指纹屏幕尺寸不合理"
        );
        anyhow::ensure!(
            self.viewport_width <= self.screen_width && self.viewport_height <= self.screen_height,
            "设备指纹视口不得大于屏幕"
        );
        anyhow::ensure!(
            (1..=4).contains(&self.device_scale_factor)
                && (4..=64).contains(&self.device_memory)
                && self.hardware_concurrency >= 2,
            "设备指纹硬件参数不合理"
        );
        anyhow::ensure!(!self.device_tag.trim().is_empty(), "设备指纹标识缺失");
        Ok(())
    }

    /// 请求侧需要与真实浏览器一致的跨站来源串。
    pub fn referer_origin(&self) -> &'static str {
        "https://www.douyin.com/"
    }

    /// 用真实浏览器的主版本号重建 UA，平台段保持本账号指纹不变。
    ///
    /// 无头浏览器默认 UA 携带 `HeadlessChrome` 标识，直接使用会被风控识别；但完全照抄
    /// 账号指纹里的旧版本又会与浏览器实际发送的 `sec-ch-ua` 版本冲突。这里只替换主版本，
    /// 让 UA、客户端提示与浏览器真实版本三者一致。
    pub fn restamp_chrome_major(&self, major: &str) -> String {
        let platform_segment = self
            .user_agent
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(segment, _)| segment)
            .filter(|segment| !segment.is_empty())
            .unwrap_or("Windows NT 10.0; Win64; x64");
        format!(
            "Mozilla/5.0 ({platform_segment}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        )
    }

    /// 账号级迁移：把已观测到的真实浏览器 UA 并入本账号指纹。
    ///
    /// 只用于「账号在真实浏览器里完成过登录」这一事实的落地，保证后续所有请求、上下文与
    /// 身份 Token 使用同一套浏览器身份；账号之间的屏幕、核心数、GPU、设备标识仍各自独立。
    pub fn align_to_user_agent(&mut self, user_agent: &str) -> bool {
        self.align_to_browser_identity(user_agent, "")
    }

    /// 同时对齐真实 UA 与浏览器品牌。
    ///
    /// Brave 等 Chromium 浏览器的 UA 通常不含品牌名，只靠 UA 会把 `sec-ch-ua` 错写成
    /// Google Chrome，导致登录浏览器与后续签名请求的客户端提示不一致。
    pub fn align_to_browser_identity(&mut self, user_agent: &str, browser_name: &str) -> bool {
        if user_agent.is_empty() || user_agent.len() > 512 {
            return false;
        }
        let (sec_ch_ua, mobile, sec_ch_platform) = client_hints_from_user_agent(user_agent);
        let sec_ch_ua =
            client_hints_from_browser_name(user_agent, browser_name).unwrap_or(sec_ch_ua);
        let navigator_platform = if user_agent.contains("Windows") {
            "Win32"
        } else if user_agent.contains("Macintosh") {
            "MacIntel"
        } else {
            "Linux x86_64"
        };
        let changed = self.user_agent != user_agent
            || self.sec_ch_ua != sec_ch_ua
            || self.sec_ch_ua_mobile != mobile
            || self.sec_ch_ua_platform != sec_ch_platform
            || self.platform != navigator_platform;
        if self.user_agent != user_agent {
            self.device_tag = hex::encode(
                &Sha256::digest(format!("tag:{}:{user_agent}", self.device_tag).as_bytes())[..8],
            );
            self.user_agent = user_agent.to_string();
        }
        self.sec_ch_ua = sec_ch_ua;
        self.sec_ch_ua_mobile = mobile;
        self.sec_ch_ua_platform = sec_ch_platform;
        self.platform = navigator_platform.to_string();
        changed
    }
}

fn client_hints_from_browser_name(user_agent: &str, browser_name: &str) -> Option<String> {
    let browser = browser_name.trim().to_ascii_lowercase();
    let brand = if browser.contains("brave") {
        "Brave"
    } else if browser.contains("edg") || browser.contains("edge") {
        "Microsoft Edge"
    } else if browser.contains("chromium") {
        "Chromium"
    } else if browser.contains("chrome") {
        "Google Chrome"
    } else {
        return None;
    };
    let major = user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("141");
    Some(format!(
        "\"{brand}\";v=\"{major}\", \"Chromium\";v=\"{major}\", \"Not(A:Brand\";v=\"24\""
    ))
}

/// 从既有 UA 推导客户端提示三元组，保证 `ua` 与 `sec-ch-ua` 家族、主版本一致。
/// 仅用于升级前已落库、未携带完整设备指纹的历史上下文。
pub fn client_hints_from_user_agent(user_agent: &str) -> (String, String, String) {
    let major = user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .filter(|v| v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty())
        .unwrap_or("141");
    let brand = if user_agent.contains("Brave") {
        "Brave"
    } else {
        "Google Chrome"
    };
    let platform = if user_agent.contains("Windows") {
        "\"Windows\""
    } else if user_agent.contains("Macintosh") {
        "\"macOS\""
    } else {
        "\"Linux\""
    };
    (
        format!("\"{brand}\";v=\"{major}\", \"Chromium\";v=\"{major}\", \"Not(A:Brand\";v=\"24\""),
        "?0".to_string(),
        platform.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_stable_and_distinct_per_account() {
        let a = DeviceProfile::derive("acc_37094b76c50f4e0aa1da3848c3e12534");
        let a2 = DeviceProfile::derive("acc_37094b76c50f4e0aa1da3848c3e12534");
        let b = DeviceProfile::derive("acc_5c3826b8cc194f9eb0c4b4cb4b9d3965");
        assert_eq!(a, a2, "同一账号必须得到完全一致的指纹");
        assert_ne!(a.device_tag, b.device_tag, "不同账号不得共享设备标识");
        assert_ne!(a, b, "不同账号不得共享同一指纹");
        a.validate().unwrap();
        b.validate().unwrap();
    }

    #[test]
    fn every_generated_profile_is_valid_and_self_consistent() {
        let mut seen = std::collections::HashSet::new();
        for index in 0..512u32 {
            let profile = DeviceProfile::derive(&format!("acc_{index:032x}"));
            profile.validate().unwrap();
            assert!(
                profile.user_agent.contains("Chrome/"),
                "UA 必须声明真实 Chrome 版本"
            );
            assert!(
                profile.sec_ch_ua.contains("Chromium"),
                "sec-ch-ua 必须与 UA 家族一致"
            );
            assert!(profile.viewport_width <= profile.screen_width);
            assert!(profile.viewport_height <= profile.screen_height);
            seen.insert(profile.device_tag.clone());
        }
        assert!(seen.len() > 500, "指纹集合必须有足够区分度");
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let good = DeviceProfile::derive("acc_rejected");
        let mut broken = good.clone();
        broken.user_agent = "not-a-browser".into();
        assert!(broken.validate().is_err());
        let mut broken = good.clone();
        broken.screen_width = 100;
        assert!(broken.validate().is_err());
        let mut broken = good.clone();
        broken.viewport_width = broken.screen_width + 1;
        assert!(broken.validate().is_err());
        let mut broken = good.clone();
        broken.version = DEVICE_PROFILE_VERSION + 1;
        assert!(broken.validate().is_err());
        let mut broken = good;
        broken.sec_ch_ua = "bad\nheader".into();
        assert!(broken.validate().is_err());
    }

    #[test]
    fn observed_user_agent_aligns_navigator_platform_without_rotating_device_tag() {
        let mut profile = DeviceProfile::derive("acc_platform_alignment");
        profile.platform = "Win32".into();
        profile.sec_ch_ua_platform = "\"Windows\"".into();
        profile.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36".into();
        let tag = profile.device_tag.clone();
        let observed_user_agent = profile.user_agent.clone();
        assert!(profile.align_to_user_agent(&observed_user_agent));
        assert_eq!(profile.platform, "MacIntel");
        assert_eq!(profile.sec_ch_ua_platform, "\"macOS\"");
        assert_eq!(profile.device_tag, tag);
        profile.validate().unwrap();
    }

    #[test]
    fn observed_brave_browser_name_aligns_client_hints_without_rotating_device_tag() {
        let mut profile = DeviceProfile::derive("acc_browser_brand_alignment");
        let tag = profile.device_tag.clone();
        let observed_user_agent = profile.user_agent.clone();
        assert!(profile.align_to_browser_identity(&observed_user_agent, "Brave/141.0.7390.76"));
        assert!(profile.sec_ch_ua.starts_with("\"Brave\";"));
        assert_eq!(profile.device_tag, tag);
        profile.validate().unwrap();
    }
}
