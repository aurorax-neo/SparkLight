//! 只读探针：检查存量账号 Cookie 能否直接通过 App 原生 Passport 接口。
//!
//! 输出不含 Cookie、Token 原文，只报告状态码、关键响应头是否存在和 body 字段名。
//!
//! 用法：
//!   SPARK_DATA_DIR=/path/to/data cargo run --bin native_upgrade_probe

use anyhow::{Context, Result};
use sparklight::crypto::load_or_create_master_key;
use sparklight::douyin::login::{NativeDevice, beat_native_session_observed, check_native_session};
use sqlx::sqlite::SqlitePoolOptions;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = std::env::var("SPARK_DATA_DIR").unwrap_or_else(|_| "/data".into());
    let secret_box = load_or_create_master_key(Path::new(&data_dir))?;
    let db_file = Path::new(&data_dir).join("sparklight.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}?mode=ro", db_file.display()))
        .await?;

    let accounts: Vec<(String, String, Vec<u8>)> =
        sqlx::query_as("SELECT id, alias, encrypted_cookie FROM accounts WHERE status='ACTIVE'")
            .fetch_all(&pool)
            .await?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    for (id, alias, encrypted_cookie) in accounts {
        let cookie = secret_box
            .decrypt(&encrypted_cookie)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .context("Cookie 解密失败")?;
        if let Ok(path) = std::env::var("SPARK_PROBE_COOKIE_OUT") {
            let path = Path::new(&path).join(format!("{id}.cookie"));
            std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
            std::fs::write(&path, &cookie)?;
            println!("wrote cookie file for {alias}: {}", path.display());
            continue;
        }
        let device = NativeDevice::derive(&id);
        println!("\n=== {alias} ({id}) ===");
        println!(
            "cookie keys: sessionid={} d_ticket={} sid_guard={} sid_tt={}",
            has_key(&cookie, "sessionid") || has_key(&cookie, "sessionid_ss"),
            has_key(&cookie, "d_ticket"),
            has_key(&cookie, "sid_guard"),
            has_key(&cookie, "sid_tt"),
        );
        println!("sid_guard expiry: {:?}", sid_guard_expiry(&cookie));

        probe(
            &client,
            &device,
            &cookie,
            "https://aweme.snssdk.com/passport/account/info/v2/?aid=1128&device_platform=android&app_name=aweme",
            "account/info/v2",
        )
        .await?;
        if let Some(native) = sparklight::db::load_native_session(&pool, &secret_box, &id).await? {
            println!(
                "native record: uid={} sid_expiry={:?} last_verified_age={:?} last_beat_age={:?} has_d_ticket={} has_token={} has_ts_sign={}",
                native.uid,
                native.sid_expiry(),
                native
                    .last_verified_at
                    .map(|at| chrono::Utc::now().timestamp() - at),
                native
                    .last_beat_at
                    .map(|at| chrono::Utc::now().timestamp() - at),
                native.d_ticket.as_deref().is_some_and(|v| !v.is_empty()),
                native.x_tt_token.as_deref().is_some_and(|v| !v.is_empty()),
                native.ts_sign.as_deref().is_some_and(|v| !v.is_empty()),
            );
            println!(
                "native check: {}",
                check_native_session(&native).await.message()
            );
            match beat_native_session_observed(&native, "polling").await {
                Ok((http, top_error, data_error, _, diagnostics)) => println!(
                    "native beat: OK http={http} top_error={top_error} data_error={data_error} {}",
                    diagnostics.join(" ")
                ),
                Err(error) => println!(
                    "native beat: ERROR {:#}",
                    error
                        .chain()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" <- ")
                ),
            }
        } else {
            println!("native record: MISSING");
        }
        probe(
            &client,
            &device,
            &cookie,
            "https://aweme.snssdk.com/passport/token/beat/v2/?scene=boot&first_beat=true&aid=1128",
            "token/beat/v2",
        )
        .await?;
    }
    Ok(())
}

async fn probe(
    client: &reqwest::Client,
    device: &NativeDevice,
    cookie: &str,
    url: &str,
    label: &str,
) -> Result<()> {
    let response = client
        .get(url)
        .header(reqwest::header::COOKIE, cookie)
        .header(reqwest::header::USER_AGENT, &device.user_agent)
        .header("sdk-version", "2")
        .header("passport-sdk-version", "60760")
        .header("x-tt-request-tag", "t=0;n=1")
        .send()
        .await
        .with_context(|| format!("{label} 网络失败"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap_or_default();
    let root: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let data_keys = root
        .get("data")
        .and_then(|value| value.as_object())
        .map(|map| map.keys().take(24).cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_default();
    let set_cookie: Vec<String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split('=').next().map(str::to_string))
        .collect();
    println!(
        "{label}: http={} err={} msg={:?} x_tt_token={} data_keys=[{}] set_cookie=[{}]",
        status.as_u16(),
        root.get("error_code")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1),
        root.get("message").and_then(|v| v.as_str()).unwrap_or(""),
        header_present(&headers, "x-tt-token"),
        data_keys,
        set_cookie.join(","),
    );
    Ok(())
}

fn header_present(headers: &reqwest::header::HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.trim().is_empty())
}

fn has_key(cookie: &str, key: &str) -> bool {
    cookie.split(';').any(|part| {
        part.trim()
            .split_once('=')
            .is_some_and(|(name, _)| name.trim() == key)
    })
}

fn sid_guard_expiry(cookie: &str) -> Option<i64> {
    let raw = cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == "sid_guard").then_some(value)
    })?;
    let decoded = percent_decode(raw);
    let mut fields = decoded.split('|');
    let _session = fields.next()?;
    let issued = fields.next()?.parse::<i64>().ok()?;
    let lifetime = fields.next()?.parse::<i64>().ok()?;
    Some(issued.saturating_add(lifetime))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
