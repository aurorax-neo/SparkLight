//! 纯 Rust 抖音 App 二维码登录探针。
//!
//! 只请求官方 Passport 接口，不启动浏览器、不保存二维码、不打印任何令牌或 Cookie。
//!
//! 用法：
//!   cargo run --bin login_probe
//!   SPARK_PROBE_WAIT=1 cargo run --bin login_probe

use std::time::Duration;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sparklight::douyin::login::{self, LoginPoll};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    if let Ok(mobile) = std::env::var("SPARK_PROBE_MOBILE") {
        let session = login::start_phone_login("probe_phone_account", "手机号验证码自检", &mobile).await?;
        println!("phone_login_id = {}", session.id);
        println!("mobile_masked  = {}", session.mobile_masked());
        println!("expires_at     = {}", session.expires_at);
        return Ok(());
    }
    let session = login::start("probe_account", "登录环境自检").await?;
    println!("login_id   = {}", session.id);
    println!("expires_at = {}", session.expires_at);
    println!(
        "qrcode     = {} bytes / {}",
        session.qrcode.len(),
        session
            .qrcode
            .split_once(',')
            .map(|(prefix, _)| prefix)
            .unwrap_or("unknown")
    );

    if let Ok(path) = std::env::var("SPARK_PROBE_QR_OUT") {
        let encoded = session
            .qrcode
            .split_once(',')
            .map(|(_, encoded)| encoded)
            .unwrap_or(&session.qrcode);
        let bytes = STANDARD.decode(encoded)?;
        std::fs::write(&path, bytes)?;
        println!("qr_image   = {path}");
    }

    if std::env::var("SPARK_PROBE_WAIT").as_deref() != Ok("1") {
        println!("wait       = disabled");
        return Ok(());
    }

    println!("wait       = enabled");
    loop {
        match login::poll(&session).await? {
            LoginPoll::Pending { status, .. } => {
                println!("status     = {status}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            LoginPoll::Confirmed(confirmed) => {
                println!(
                    "status     = confirmed uid={} cookie_bytes={} native_ready=true",
                    confirmed.record.uid,
                    confirmed.record.cookie.len()
                );
                break;
            }
            LoginPoll::Terminal { status, message } => {
                println!("status     = {status} message={message}");
                break;
            }
        }
    }
    Ok(())
}
