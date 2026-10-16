use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use sparklight::crypto::load_or_create_master_key;
use sqlx::sqlite::SqlitePoolOptions;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = std::env::var("SPARK_DATA_DIR").unwrap_or_else(|_| "/data".into());
    let key_file = Path::new(&data_dir).join(".master-key");
    let db_file = Path::new(&data_dir).join("sparklight.db");

    if !key_file.exists() || !db_file.exists() {
        eprintln!("Database or key file does not exist at {:?}", data_dir);
        return Ok(());
    }

    let secret_box = load_or_create_master_key(Path::new(&data_dir))?;
    let pool = SqlitePoolOptions::new().connect(&format!("sqlite://{}", db_file.display())).await?;

    let accounts: Vec<(String, String, Option<String>, Option<String>, Vec<u8>, String)> =
        sqlx::query_as("SELECT id, alias, uid, nickname, encrypted_cookie, status FROM accounts")
            .fetch_all(&pool)
            .await?;

    let now = Utc::now().timestamp();
    println!("=== SESSIONS AUDIT AT UTC TIMESTAMP: {} ===", now);

    for (id, alias, uid, nickname, enc_cookie, status) in accounts {
        println!("\nAccount: {} ({}) | Status: {}", alias, id, status);
        println!("  UID: {:?}", uid);
        println!("  Nickname: {:?}", nickname);

        if let Ok(cookie_bytes) = secret_box.decrypt(&enc_cookie) {
            if let Ok(cookie_str) = String::from_utf8(cookie_bytes) {
                let mut keys: Vec<&str> = cookie_str
                    .split(';')
                    .filter_map(|p| p.trim().split_once('=').map(|(k, _)| k.trim()))
                    .collect();
                keys.sort();
                keys.dedup();
                println!("  Cookie Total Keys: {}", keys.len());
                println!(
                    "  Key Checks: sessionid={}, passport_assist_user={}, passport_csrf_token={}, s_v_web_id={}, msToken={}, d_ticket={}",
                    keys.contains(&"sessionid") || keys.contains(&"sessionid_ss"),
                    keys.contains(&"passport_assist_user"),
                    keys.contains(&"passport_csrf_token") || keys.contains(&"passport_csrf_token_default"),
                    keys.contains(&"s_v_web_id"),
                    keys.contains(&"msToken"),
                    keys.contains(&"d_ticket")
                );
            }
        }

        let ctx_row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1")
                .bind(&id)
                .fetch_optional(&pool)
                .await?;

        if let Some((enc_ctx,)) = ctx_row {
            if let Ok(ctx_bytes) = secret_box.decrypt(&enc_ctx) {
                if let Ok(ctx) = serde_json::from_slice::<Value>(&ctx_bytes) {
                    println!("  WebContext Found:");
                    let has_guard_secret = ctx.get("guard_secret_hex").and_then(|v| v.as_str()).is_some();
                    println!("    guard_secret_hex: {}", if has_guard_secret { "PRESENT" } else { "NONE" });
                    let guard_acquired_at = ctx.get("guard_acquired_at").and_then(|v| v.as_i64());
                    println!("    guard_acquired_at: {:?} (age: {:?}s)", guard_acquired_at, guard_acquired_at.map(|t| now - t));

                    if let Some(srv_data_str) = ctx.get("guard_server_data").and_then(|v| v.as_str()) {
                        if let Ok(sd) = serde_json::from_str::<Value>(srv_data_str) {
                            let expire_time = sd.get("expire_time").and_then(|v| v.as_i64());
                            println!("    guard_server_data:");
                           let create_time = sd.get("create_time").and_then(|v| v.as_i64());
                           println!("      create_time: {:?} (age: {:?}s)", create_time, create_time.map(|t| now - t));
                            println!("      has_ticket: {}", sd.get("ticket").is_some());
                            println!("      has_ts_sign: {}", sd.get("ts_sign").is_some());
                            println!("      client_cert: {:?}", sd.get("client_cert").map(|v| v.as_str().unwrap_or("")));
                            println!("      expire_time: {:?} (remaining: {:?}s)", expire_time, expire_time.map(|t| t - now));
                        } else {
                            println!("    guard_server_data: [RAW STRING LEN {}]", srv_data_str.len());
                        }
                    } else {
                        println!("    guard_server_data: NONE");
                    }

                    let identity_acquired_at = ctx.get("identity_acquired_at").and_then(|v| v.as_i64());
                    println!("    identity_acquired_at: {:?} (age: {:?}s)", identity_acquired_at, identity_acquired_at.map(|t| now - t));
                    println!("    dtrait_pk1_pem: {}", ctx.get("dtrait_pk1_pem").is_some());
                    println!("    dtrait_version: {:?}", ctx.get("dtrait_version"));
                }
            }
        } else {
            println!("  WebContext: NONE");
        }
    }

    Ok(())
}
