//! 108 专用二维码端到端诊断。
//!
//! 使用现有测试账号 Cookie 调用官方扫码与确认接口，再走正式 login::poll。
//! 只打印状态和字段名，不打印 Cookie、二维码 token 或其他凭证。

use anyhow::{Context, Result, ensure};
use reqwest::{Client, header};
use serde_json::Value;
use sparklight::{
    crypto::load_or_create_master_key,
    douyin::login::{
        self, LoginPoll, NativeCheck, NativeDevice, NativeSessionRecord, check_native_session,
    },
};
use sqlx::sqlite::SqlitePoolOptions;
use std::{path::Path, time::Duration};

const APP_PACKAGE_VERSION_CODE: &str = "400801";
const APP_UPDATE_VERSION_CODE: &str = "40809900";
const PASSPORT_SDK_VERSION: &str = "60760";

fn value_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_string(),
        Some(Value::Number(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn common_form(device: &NativeDevice, token: &str, scopes: Option<&str>) -> Vec<(String, String)> {
    let mut form = vec![
        ("aid".to_string(), device.aid.clone()),
        ("app_name".to_string(), device.app_name.clone()),
        (
            "device_platform".to_string(),
            device.device_platform.clone(),
        ),
        ("device_id".to_string(), device.device_id.clone()),
        ("iid".to_string(), device.install_id.clone()),
        ("install_id".to_string(), device.install_id.clone()),
        ("openudid".to_string(), device.openudid.clone()),
        ("cdid".to_string(), device.cdid.clone()),
        ("channel".to_string(), device.channel.clone()),
        ("version_code".to_string(), device.version_code.clone()),
        ("version_name".to_string(), device.app_version.clone()),
        (
            "passport-sdk-version".to_string(),
            PASSPORT_SDK_VERSION.to_string(),
        ),
        ("request_from_account_sdk".to_string(), "1".to_string()),
        ("is_from_ttaccountsdk".to_string(), "1".to_string()),
        ("account_sdk_source".to_string(), "app".to_string()),
        ("is_from_iesaccountsaas".to_string(), "1".to_string()),
        ("account_app_language".to_string(), "zh".to_string()),
        ("language".to_string(), "zh".to_string()),
        ("device_brand".to_string(), "google".to_string()),
        ("device_type".to_string(), "Pixel Tablet".to_string()),
        ("os_version".to_string(), "14".to_string()),
        ("resolution".to_string(), "2560*1600".to_string()),
        (
            "update_version_code".to_string(),
            APP_UPDATE_VERSION_CODE.to_string(),
        ),
        (
            "manifest_version_code".to_string(),
            APP_PACKAGE_VERSION_CODE.to_string(),
        ),
        ("package".to_string(), device.package.clone()),
        ("is_android_pad".to_string(), "1".to_string()),
        ("token".to_string(), token.to_string()),
    ];
    if let Some(scopes) = scopes {
        form.push(("scopes".to_string(), scopes.to_string()));
    }
    form
}

fn scan_form(device: &NativeDevice, token: &str) -> Vec<(String, String)> {
    let mut form = common_form(device, token, None);
    form.extend([
        ("scene".to_string(), "0".to_string()),
        ("source".to_string(), "pad".to_string()),
        ("source_extra".to_string(), "pad".to_string()),
        ("qr_source_aid".to_string(), device.aid.clone()),
        (
            "next_url".to_string(),
            "https://aweme.snssdk.com/passport/mobile/scan_qrcode/".to_string(),
        ),
        ("scan_by".to_string(), device.aid.clone()),
        ("is_from_ucenter_fe_prefetch".to_string(), "1".to_string()),
    ]);
    form
}

fn response_data(root: &Value) -> &Value {
    root.get("data")
        .filter(|value| value.is_object())
        .unwrap_or(root)
}

fn field_present(root: &Value, key: &str) -> bool {
    response_data(root)
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn response_summary(root: &Value) -> String {
    let keys = root
        .as_object()
        .map(|object| {
            object
                .keys()
                .take(24)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let data_keys = root
        .get("data")
        .and_then(Value::as_object)
        .map(|object| {
            object
                .keys()
                .take(24)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    format!(
        "error={} data_error={} message={} description={} has_desc_url={} keys={} data_keys={} has_token={} has_ticket={} has_scopes={} has_auth_state_header={} has_user_data={}",
        value_string(root.get("error_code")),
        value_string(root.get("data").and_then(|data| data.get("error_code"))),
        value_string(root.get("message"))
            .chars()
            .take(80)
            .collect::<String>(),
        value_string(root.get("data").and_then(|data| data.get("description")))
            .chars()
            .take(160)
            .collect::<String>(),
        root.get("data")
            .and_then(|data| data.get("desc_url"))
            .is_some_and(|value| !value.is_null()),
        keys,
        data_keys,
        field_present(root, "token"),
        field_present(root, "ticket"),
        field_present(root, "scopes"),
        false,
        response_data(root)
            .get("user_data")
            .is_some_and(Value::is_object)
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = std::env::var("SPARK_DATA_DIR").unwrap_or_else(|_| "/data".to_string());
    let data_dir = Path::new(&data_dir);
    let secret = load_or_create_master_key(data_dir)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}",
            data_dir.join("sparklight.db").display()
        ))
        .await?;

    let requested = std::env::var("SPARK_ACCOUNT_ID")
        .unwrap_or_else(|_| "acc_37094b76c50f4e0aa1da3848c3e12534".into());
    let (id, alias, uid, sec_uid, nickname, encrypted_cookie): (
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT id,alias,uid,sec_uid,nickname,encrypted_cookie FROM accounts WHERE id=?1",
    )
    .bind(&requested)
    .fetch_optional(&pool)
    .await?
    .context("测试账号不存在")?;
    let (cookie, cookie_source) = if let Ok(cookie) = std::env::var("SPARK_SCANNER_COOKIE") {
        (cookie, "environment")
    } else if let Ok(path) = std::env::var("SPARK_SCANNER_COOKIE_FILE") {
        (
            std::fs::read_to_string(path).context("读取临时扫码账号 Cookie 失败")?,
            "file",
        )
    } else {
        (
            String::from_utf8(secret.decrypt(&encrypted_cookie)?)?,
            "database",
        )
    };
    let cookie = cookie.trim().to_string();
    ensure!(
        cookie
            .split(';')
            .any(|part| part.trim().starts_with("sessionid=")),
        "测试账号缺少 sessionid"
    );
    println!("scanner_cookie_source={cookie_source}");

    let native_probe = NativeSessionRecord {
        device: NativeDevice::derive(&id),
        cookie: cookie.clone(),
        uid,
        sec_uid,
        nickname,
        avatar_url: String::new(),
        mobile: String::new(),
        session_key: None,
        d_ticket: None,
        x_tt_token: None,
        token_encrypted: None,
        ts_sign: None,
        attest_ts_sign: None,
        mfa_token: None,
        guard_key_hex: None,
        guard_server_data: None,
        dtrait_pk1_pem: None,
        dtrait_version: None,
        logged_in_at: chrono::Utc::now().timestamp(),
        last_verified_at: None,
        last_beat_at: None,
    };
    let native_check = check_native_session(&native_probe).await;
    println!(
        "old_cookie_native_check={} message={}",
        match &native_check {
            NativeCheck::Valid(_) => "valid",
            NativeCheck::Expired(_) => "expired",
            NativeCheck::Unconfirmed(_) => "unconfirmed",
        },
        native_check.message()
    );

    let session = login::start(&id, &alias).await?;
    let device = NativeDevice::derive(&id);
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let token = session.qr_token();

    let scan_response = client
        .post("https://api.amemv.com/passport/mobile/scan_qrcode/")
        .form(&scan_form(&device, token))
        .header(header::COOKIE, &cookie)
        .header(header::ACCEPT, "application/json, text/plain, */*")
        .send()
        .await?;
    let scan_status = scan_response.status();
    let scan_auth_state = scan_response
        .headers()
        .get("x-tt-passport-auth-state")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let scan_bytes = scan_response.bytes().await?;
    let scan_root: Value = serde_json::from_slice(&scan_bytes)?;
    let scan_data = response_data(&scan_root);
    println!(
        "scan_http={} {} has_auth_state={}",
        scan_status.as_u16(),
        response_summary(&scan_root),
        scan_auth_state.is_some()
    );

    let scan_token = value_string(scan_data.get("token"));
    let scan_uses_token = if scan_token.is_empty() {
        token
    } else {
        scan_token.as_str()
    };
    let scopes = value_string(scan_data.get("scopes"));
    let ticket = value_string(scan_data.get("ticket"));
    let mut confirm = client
        .post("https://aweme.snssdk.com/passport/open/confirm_qrcode/")
        .form(&{
            let mut form = common_form(&device, scan_uses_token, Some(&scopes));
            form.extend([
                ("decision".to_string(), "1".to_string()),
                ("skip_confirm".to_string(), "false".to_string()),
                ("biz_extra".to_string(), "{}".to_string()),
            ]);
            if !ticket.is_empty() {
                form.push(("ticket".to_string(), ticket.clone()));
            }
            form
        })
        .header(header::COOKIE, &cookie)
        .header(header::ACCEPT, "application/json, text/plain, */*");
    if let Some(auth_state) = scan_auth_state {
        confirm = confirm.header("x-tt-passport-auth-state", auth_state);
    }
    let confirm_response = confirm.send().await?;
    let confirm_status = confirm_response.status();
    let confirm_root: Value = serde_json::from_slice(&confirm_response.bytes().await?)?;
    println!(
        "confirm_http={} has_ticket={} scopes_present={} {}",
        confirm_status.as_u16(),
        !ticket.is_empty(),
        !scopes.is_empty(),
        response_summary(&confirm_root)
    );

    for _ in 0..20 {
        match login::poll(&session).await? {
            LoginPoll::Pending { status, .. } => {
                println!("poll={status}");
                if status == "confirmed" {
                    break;
                }
            }
            LoginPoll::Confirmed(confirmed) => {
                println!(
                    "poll=confirmed uid_present={} cookie_bytes={} native_ready=true",
                    !confirmed.record.uid.is_empty(),
                    confirmed.record.cookie.len()
                );
                return Ok(());
            }
            LoginPoll::Terminal { status, message } => {
                println!("poll={status} message={message}");
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}
