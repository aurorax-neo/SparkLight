//! 只读诊断今日消息历史链路。输出仅包含阶段、长度与固定错误分类。

use anyhow::{Context, Result};
use sparklight::{
    crypto::load_or_create_master_key, douyin::client::DouyinClient,
    douyin::im_auth::sid_guard_expiry,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::{path::Path, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let data_dir = std::env::var("SPARK_DATA_DIR").unwrap_or_else(|_| "/data".into());
    let data_dir = Path::new(&data_dir);
    let secret = load_or_create_master_key(data_dir)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&format!(
            "sqlite://{}?mode=ro",
            data_dir.join("sparklight.db").display()
        ))
        .await?;

    let account_id = std::env::var("SPARK_ACCOUNT_ID")
        .unwrap_or_else(|_| "acc_37094b76c50f4e0aa1da3848c3e12534".into());
    let target_id = std::env::var("SPARK_TARGET_ID")
        .unwrap_or_else(|_| "tgt_2e614530f19d4723a2820e7daaac5ee9".into());

    let (alias, uid, encrypted_cookie, status): (String, String, Vec<u8>, String) =
        sqlx::query_as("SELECT alias,uid,encrypted_cookie,status FROM accounts WHERE id=?1")
            .bind(&account_id)
            .fetch_optional(&pool)
            .await?
            .context("账号不存在")?;
    let (target_uid, conversation_type, target_sec_uid, target_nickname): (
        String,
        i32,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT target_uid,conversation_type,target_sec_uid,target_nickname
         FROM spark_targets WHERE id=?1 AND account_id=?2",
    )
    .bind(&target_id)
    .bind(&account_id)
    .fetch_optional(&pool)
    .await?
    .context("目标不存在或不属于账号")?;

    let cookie = String::from_utf8(secret.decrypt(&encrypted_cookie)?)?;
    let client = DouyinClient::for_account(&pool, &secret, &account_id, &cookie, &alias).await?;
    println!(
        "account={} status={} uid={} target={} type={} sid_expiry={:?}",
        account_id,
        status,
        uid,
        target_nickname,
        conversation_type,
        sid_guard_expiry(&cookie)
    );

    let loaded = client
        .load_web_context(&pool, &secret, &account_id, Some(&uid))
        .await;
    println!(
        "load_context={} snapshot={} history={:?}",
        result_label(&loaded),
        client.web_context_snapshot().is_some(),
        client.im_history_status(Some(&uid))
    );
    let checked = client.check_cookie().await;
    println!("local_check={}", checked.safe_diagnostic());
    if !checked.is_valid() {
        return Ok(());
    }

    let prepared = client.prepare_im_identity(Some(&uid)).await;
    println!("prepare_identity={}", result_label(&prepared));
    let Some(context) = client.web_context_snapshot() else {
        println!("history=CONTEXT_MISSING");
        return Ok(());
    };
    println!(
        "context uid={} has_identity={} has_guard={} captured_age={} identity_age={:?}",
        context.uid,
        context.has_identity(),
        context.guard_secret_hex.is_some() && context.guard_server_data.is_some(),
        chrono::Utc::now().timestamp() - context.captured_at,
        context
            .identity_acquired_at
            .map(|at| chrono::Utc::now().timestamp() - at)
    );

    let peer = target_uid.parse::<u64>().context("目标 UID 无效")?;
    let me = uid.parse::<u64>().context("账号 UID 无效")?;
    let conversation_id = if conversation_type == 2 {
        target_sec_uid
    } else {
        format!("0:1:{}:{}", me.min(peer), me.max(peer))
    };
    let fetched = client
        .fetch_batch_conversation_spark_status(&[sparklight::douyin::client::DouyinTargetParam {
            conv_id: conversation_id.clone(),
            conv_type: conversation_type,
            short_id: None,
        }])
        .await;
    let short_id = fetched
        .as_ref()
        .ok()
        .and_then(|map| map.get(&conversation_id))
        .map(|info| info.short_id);
    println!(
        "conversation={} fetch={} short_id={:?}",
        conversation_id,
        result_label(&fetched),
        short_id
    );
    let Some(short_id) = short_id else {
        return Ok(());
    };

    let history = client
        .check_i_sent_message_today(me, &conversation_id, conversation_type, short_id)
        .await;
    println!("history={}", result_label(&history));
    Ok(())
}

fn result_label<T>(result: &Result<T>) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(_) => "ERROR",
    }
}
