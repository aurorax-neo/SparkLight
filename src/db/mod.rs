pub mod schema;

use crate::model::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{collections::HashMap, time::Duration};

pub async fn init_pool(db_url: &str) -> Result<SqlitePool> {
    let opts: SqliteConnectOptions = db_url
        .parse::<SqliteConnectOptions>()
        .context("invalid database url")?
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(10));

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("failed to connect to sqlite database")?;

    schema::init_schema(&pool).await?;

    Ok(pool)
}

// ----------------- Account Operations -----------------

/// 读取账号独占设备指纹；不存在时按账号 ID 确定性派生并落库。
///
/// 同一账号永远得到同一指纹，不同账号永远得到不同指纹；指纹只在本函数或
/// [`store_device_profile`] 中写入，任何请求路径都不允许临时生成。
pub async fn load_or_create_device_profile(
    pool: &SqlitePool,
    secret: &crate::crypto::SecretBox,
    account_id: &str,
) -> Result<crate::douyin::device_profile::DeviceProfile> {
    if let Some((encrypted,)) = sqlx::query_as::<_, (Vec<u8>,)>(
        "SELECT encrypted_profile FROM account_device_profiles WHERE account_id=?1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?
    {
        let plain = secret.decrypt(&encrypted).context("设备指纹解密失败")?;
        let profile: crate::douyin::device_profile::DeviceProfile =
            serde_json::from_slice(&plain).context("设备指纹解码失败")?;
        profile.validate().context("已落库设备指纹不合法")?;
        // 已落库的客户端提示是真实浏览器观测结果。Brave 的 UA 不含品牌名，
        // 若每次加载都按 UA 重新推导，会把 Brave 错写成 Google Chrome，导致身份 Token
        // 与请求指纹不一致。版本升级只允许通过显式重新登录重新采集。
        return Ok(profile);
    }
    let profile = crate::douyin::device_profile::DeviceProfile::derive(account_id);
    store_device_profile(pool, secret, account_id, &profile).await?;
    Ok(profile)
}

pub async fn store_device_profile(
    pool: &SqlitePool,
    secret: &crate::crypto::SecretBox,
    account_id: &str,
    profile: &crate::douyin::device_profile::DeviceProfile,
) -> Result<()> {
    profile.validate()?;
    let encrypted = secret.encrypt(&serde_json::to_vec(profile)?)?;
    sqlx::query("INSERT INTO account_device_profiles(account_id,encrypted_profile) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_profile=excluded.encrypted_profile")
        .bind(account_id)
        .bind(encrypted)
        .execute(pool)
        .await
        .context("failed to store device profile")?;
    Ok(())
}

/// 登录确认后的单事务落库：账号、独占指纹、Cookie 与 Web 上下文必须一起生效。
///
/// 旧登录态签发的 `account_im_credentials` 与新会话不再兼容，因此必须在同一事务中清理。
/// 任一步失败都回滚，不会留下“账号已更新但指纹/上下文没更新”的混合状态。
pub async fn persist_login_session(
    pool: &SqlitePool,
    secret: &crate::crypto::SecretBox,
    account: &Account,
    device: &crate::douyin::device_profile::DeviceProfile,
    context: &crate::douyin::im_auth::WebSessionContext,
) -> Result<()> {
    device.validate()?;
    anyhow::ensure!(
        context.uid > 0 && !context.session_hash.is_empty() && !context.user_agent.is_empty(),
        "登录会话上下文不完整"
    );
    let encrypted_profile = secret.encrypt(&serde_json::to_vec(device)?)?;
    let encrypted_context = secret.encrypt(&serde_json::to_vec(context)?)?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        INSERT INTO accounts (
            id, alias, sec_uid, uid, nickname, avatar_url,
            encrypted_cookie, status, bark_key_override,
            last_checked_at, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(id) DO UPDATE SET
            alias = excluded.alias,
            sec_uid = excluded.sec_uid,
            uid = excluded.uid,
            nickname = excluded.nickname,
            avatar_url = excluded.avatar_url,
            encrypted_cookie = excluded.encrypted_cookie,
            status = excluded.status,
            bark_key_override = excluded.bark_key_override,
            last_checked_at = excluded.last_checked_at,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&account.id)
    .bind(&account.alias)
    .bind(&account.sec_uid)
    .bind(&account.uid)
    .bind(&account.nickname)
    .bind(&account.avatar_url)
    .bind(&account.encrypted_cookie)
    .bind(&account.status)
    .bind(&account.bark_key_override)
    .bind(account.last_checked_at.map(|time| time.to_rfc3339()))
    .bind(account.created_at.to_rfc3339())
    .bind(account.updated_at.to_rfc3339())
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1")
        .bind(&account.id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO account_device_profiles(account_id,encrypted_profile) VALUES(?1,?2) \
         ON CONFLICT(account_id) DO UPDATE SET encrypted_profile=excluded.encrypted_profile",
    )
    .bind(&account.id)
    .bind(encrypted_profile)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) \
         ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context",
    )
    .bind(&account.id)
    .bind(encrypted_context)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// 原生 App 登录确认后的单事务落库。
///
/// 原生会话始终保存；只有完整取得 Web/IM 身份与 Guard 材料时才写入 Web 上下文。
/// 没有完整 Web 上下文时会清空旧上下文，避免展示“可发送”但实际使用过期票据。
pub async fn persist_native_login_session(
    pool: &SqlitePool,
    secret: &crate::crypto::SecretBox,
    account: &Account,
    device: &crate::douyin::device_profile::DeviceProfile,
    native: &crate::douyin::login::NativeSessionRecord,
    context: Option<&crate::douyin::im_auth::WebSessionContext>,
) -> Result<()> {
    device.validate()?;
    native.validate()?;
    let encrypted_profile = secret.encrypt(&serde_json::to_vec(device)?)?;
    let encrypted_native = secret.encrypt(&serde_json::to_vec(native)?)?;
    let now = Utc::now().to_rfc3339();
    let mut transaction = pool.begin().await?;
    let duplicate_uid: Option<(String,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE uid=?1 AND id<>?2 LIMIT 1")
            .bind(native.uid.trim())
            .bind(&account.id)
            .fetch_optional(&mut *transaction)
            .await?;
    anyhow::ensure!(
        duplicate_uid.is_none(),
        "该抖音 UID 已绑定其他 SparkLight 账号，拒绝重复导入"
    );
    sqlx::query(
        r#"
        INSERT INTO accounts (
            id, alias, sec_uid, uid, nickname, avatar_url,
            encrypted_cookie, status, bark_key_override,
            last_checked_at, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(id) DO UPDATE SET
            alias = excluded.alias,
            sec_uid = excluded.sec_uid,
            uid = excluded.uid,
            nickname = excluded.nickname,
            avatar_url = excluded.avatar_url,
            encrypted_cookie = excluded.encrypted_cookie,
            status = excluded.status,
            bark_key_override = excluded.bark_key_override,
            last_checked_at = excluded.last_checked_at,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&account.id)
    .bind(&account.alias)
    .bind(&account.sec_uid)
    .bind(&account.uid)
    .bind(&account.nickname)
    .bind(&account.avatar_url)
    .bind(&account.encrypted_cookie)
    .bind(&account.status)
    .bind(&account.bark_key_override)
    .bind(account.last_checked_at.map(|time| time.to_rfc3339()))
    .bind(account.created_at.to_rfc3339())
    .bind(account.updated_at.to_rfc3339())
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1")
        .bind(&account.id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO account_device_profiles(account_id,encrypted_profile) VALUES(?1,?2) \
         ON CONFLICT(account_id) DO UPDATE SET encrypted_profile=excluded.encrypted_profile",
    )
    .bind(&account.id)
    .bind(encrypted_profile)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO account_native_sessions(account_id,encrypted_session,logged_in_at,last_checked_at) \
         VALUES(?1,?2,?3,?4) \
         ON CONFLICT(account_id) DO UPDATE SET \
            encrypted_session=excluded.encrypted_session, \
            logged_in_at=excluded.logged_in_at, \
            last_checked_at=excluded.last_checked_at",
    )
    .bind(&account.id)
    .bind(encrypted_native)
    .bind(chrono::DateTime::from_timestamp(native.logged_in_at, 0).unwrap_or_else(Utc::now).to_rfc3339())
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    if let Some(context) = context {
        anyhow::ensure!(
            context.uid > 0
                && context.uid.to_string() == native.uid
                && context.has_identity()
                && context.guard_secret_hex.is_some()
                && context.guard_server_data.is_some(),
            "原生登录的 Web 上下文不完整"
        );
        let encrypted_context = secret.encrypt(&serde_json::to_vec(context)?)?;
        sqlx::query(
            "INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) \
             ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context",
        )
        .bind(&account.id)
        .bind(encrypted_context)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query("DELETE FROM account_web_contexts WHERE account_id=?1")
            .bind(&account.id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn load_native_session(
    pool: &SqlitePool,
    secret: &crate::crypto::SecretBox,
    account_id: &str,
) -> Result<Option<crate::douyin::login::NativeSessionRecord>> {
    let encrypted: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT encrypted_session FROM account_native_sessions WHERE account_id=?1")
            .bind(account_id)
            .fetch_optional(pool)
            .await?;
    let Some((encrypted,)) = encrypted else {
        return Ok(None);
    };
    let plain = secret.decrypt(&encrypted).context("原生登录会话解密失败")?;
    let record: crate::douyin::login::NativeSessionRecord =
        serde_json::from_slice(&plain).context("原生登录会话解码失败")?;
    record.validate().context("已落库原生登录会话无效")?;
    Ok(Some(record))
}

/// 只更新原生会话快照与对应 Cookie，不触碰目标、日志或历史 Web 身份材料。
pub async fn persist_native_session(
    pool: &SqlitePool,
    secret: &crate::crypto::SecretBox,
    account_id: &str,
    record: &crate::douyin::login::NativeSessionRecord,
) -> Result<()> {
    record.validate()?;
    let encrypted_native = secret.encrypt(&serde_json::to_vec(record)?)?;
    let encrypted_cookie = secret.encrypt(record.cookie.as_bytes())?;
    let existing_context: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    let rebound_context = existing_context.and_then(|encrypted| {
        let plain = secret.decrypt(&encrypted).ok()?;
        let mut context =
            serde_json::from_slice::<crate::douyin::im_auth::WebSessionContext>(&plain).ok()?;
        if context.uid.to_string() != record.uid {
            return None;
        }
        match context.rebind_session(&record.cookie) {
            Ok(true) => Some(secret.encrypt(&serde_json::to_vec(&context).ok()?).ok()?),
            _ => None,
        }
    });
    let mut transaction = pool.begin().await?;
    let updated = sqlx::query("UPDATE accounts SET encrypted_cookie=?1, updated_at=?2 WHERE id=?3")
        .bind(encrypted_cookie)
        .bind(Utc::now().to_rfc3339())
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
    anyhow::ensure!(updated.rows_affected() == 1, "原生会话所属账号不存在");
    sqlx::query(
        "INSERT INTO account_native_sessions(account_id,encrypted_session,logged_in_at,last_checked_at) \
         VALUES(?1,?2,?3,?4) \
         ON CONFLICT(account_id) DO UPDATE SET \
            encrypted_session=excluded.encrypted_session, \
            logged_in_at=excluded.logged_in_at, \
            last_checked_at=excluded.last_checked_at",
    )
    .bind(account_id)
    .bind(encrypted_native)
    .bind(
        chrono::DateTime::from_timestamp(record.logged_in_at, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339(),
    )
    .bind(Utc::now().to_rfc3339())
    .execute(&mut *transaction)
    .await?;
    if let Some(encrypted_context) = rebound_context {
        sqlx::query("UPDATE account_web_contexts SET encrypted_context=?1 WHERE account_id=?2")
            .bind(encrypted_context)
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn insert_account(pool: &SqlitePool, account: &Account) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO accounts (
            id, alias, sec_uid, uid, nickname, avatar_url,
            encrypted_cookie, status, bark_key_override,
            last_checked_at, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&account.id)
    .bind(&account.alias)
    .bind(&account.sec_uid)
    .bind(&account.uid)
    .bind(&account.nickname)
    .bind(&account.avatar_url)
    .bind(&account.encrypted_cookie)
    .bind(&account.status)
    .bind(&account.bark_key_override)
    .bind(account.last_checked_at.map(|t| t.to_rfc3339()))
    .bind(account.created_at.to_rfc3339())
    .bind(account.updated_at.to_rfc3339())
    .execute(pool)
    .await
    .context("failed to insert account")?;

    Ok(())
}

pub async fn get_account(pool: &SqlitePool, id: &str) -> Result<Option<Account>> {
    let row = sqlx::query(
        r#"
        SELECT id, alias, sec_uid, uid, nickname, avatar_url,
               encrypted_cookie, status, bark_key_override,
               last_checked_at, created_at, updated_at
        FROM accounts WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("failed to get account")?;

    match row {
        Some(r) => {
            let last_checked: Option<String> = r.try_get("last_checked_at").ok();
            let created: String = r.get("created_at");
            let updated: String = r.get("updated_at");

            Ok(Some(Account {
                id: r.get("id"),
                alias: r.get("alias"),
                sec_uid: r.get("sec_uid"),
                uid: r.get("uid"),
                nickname: r.get("nickname"),
                avatar_url: r.get("avatar_url"),
                encrypted_cookie: r.get("encrypted_cookie"),
                status: r.get("status"),
                bark_key_override: r.get("bark_key_override"),
                last_checked_at: last_checked.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }))
        }
        None => Ok(None),
    }
}

pub async fn find_account_by_uid(pool: &SqlitePool, uid: &str) -> Result<Option<Account>> {
    let row = sqlx::query(
        r#"
        SELECT id, alias, sec_uid, uid, nickname, avatar_url,
               encrypted_cookie, status, bark_key_override,
               last_checked_at, created_at, updated_at
        FROM accounts WHERE uid = ?1 ORDER BY created_at LIMIT 1
        "#,
    )
    .bind(uid)
    .fetch_optional(pool)
    .await
    .context("failed to find account by uid")?;

    match row {
        Some(r) => {
            let last_checked: Option<String> = r.try_get("last_checked_at").ok();
            let created: String = r.get("created_at");
            let updated: String = r.get("updated_at");
            Ok(Some(Account {
                id: r.get("id"),
                alias: r.get("alias"),
                sec_uid: r.get("sec_uid"),
                uid: r.get("uid"),
                nickname: r.get("nickname"),
                avatar_url: r.get("avatar_url"),
                encrypted_cookie: r.get("encrypted_cookie"),
                status: r.get("status"),
                bark_key_override: r.get("bark_key_override"),
                last_checked_at: last_checked.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }))
        }
        None => Ok(None),
    }
}

pub async fn list_accounts(pool: &SqlitePool) -> Result<Vec<Account>> {
    let rows = sqlx::query(
        r#"
        SELECT id, alias, sec_uid, uid, nickname, avatar_url,
               encrypted_cookie, status, bark_key_override,
               last_checked_at, created_at, updated_at
        FROM accounts ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
    .context("failed to list accounts")?;

    let accounts = rows
        .into_iter()
        .map(|r| {
            let last_checked: Option<String> = r.try_get("last_checked_at").ok();
            let created: String = r.get("created_at");
            let updated: String = r.get("updated_at");

            Account {
                id: r.get("id"),
                alias: r.get("alias"),
                sec_uid: r.get("sec_uid"),
                uid: r.get("uid"),
                nickname: r.get("nickname"),
                avatar_url: r.get("avatar_url"),
                encrypted_cookie: r.get("encrypted_cookie"),
                status: r.get("status"),
                bark_key_override: r.get("bark_key_override"),
                last_checked_at: last_checked.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }
        })
        .collect();

    Ok(accounts)
}

pub async fn update_account_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    last_checked_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE accounts
        SET status = ?1, last_checked_at = ?2, updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(status)
    .bind(last_checked_at.to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(pool)
    .await
    .context("failed to update account status")?;

    Ok(())
}

pub async fn update_account_profile(
    pool: &SqlitePool,
    id: &str,
    sec_uid: Option<&str>,
    uid: Option<&str>,
    nickname: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE accounts
        SET sec_uid = COALESCE(?1, sec_uid),
            uid = COALESCE(?2, uid),
            nickname = COALESCE(?3, nickname),
            avatar_url = COALESCE(?4, avatar_url),
            alias = CASE
                WHEN (alias IS NULL OR alias = '抖音账号' OR alias = nickname) AND ?3 IS NOT NULL
                THEN ?3
                ELSE alias
            END,
            updated_at = ?5
        WHERE id = ?6
        "#,
    )
    .bind(sec_uid)
    .bind(uid)
    .bind(nickname)
    .bind(avatar_url)
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(pool)
    .await
    .context("failed to update account profile")?;

    Ok(())
}

pub async fn update_account_cookie(
    pool: &SqlitePool,
    id: &str,
    encrypted_cookie: &[u8],
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE accounts
        SET encrypted_cookie = ?1, updated_at = ?2
        WHERE id = ?3
        "#,
    )
    .bind(encrypted_cookie)
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(&mut *transaction)
    .await
    .context("failed to update account cookie")?;
    sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM account_web_contexts WHERE account_id=?1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    Ok(())
}

pub async fn update_account(
    pool: &SqlitePool,
    id: &str,
    alias: Option<&str>,
    status: Option<&str>,
    bark_key_override: Option<Option<&str>>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    if let Some(alias) = alias {
        sqlx::query("UPDATE accounts SET alias = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(alias)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(status) = status {
        sqlx::query("UPDATE accounts SET status = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(bark_key) = bark_key_override {
        sqlx::query("UPDATE accounts SET bark_key_override = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(bark_key)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn delete_account(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM accounts WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .context("failed to delete account")?;
    Ok(())
}

// ----------------- Target Operations -----------------
/// 只接受北京时间当天的历史检测，不能从资料更新时间推断。
fn current_today_state(r: &sqlx::sqlite::SqliteRow, now: DateTime<Utc>) -> Option<bool> {
    let checked: Option<String> = r.try_get("today_checked_at").ok().flatten();
    let checked = checked.and_then(|s| DateTime::parse_from_rfc3339(&s).ok());
    let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    checked
        .filter(|t| {
            t.with_timezone(&cst).date_naive() == now.with_timezone(&cst).date_naive()
                && t.with_timezone(&Utc) <= now
        })
        .and_then(|_| r.try_get::<i32, _>("is_sparked_today").ok().map(|v| v != 0))
}

/// None 明确使检测失效，不等于“已确认今天未发”。
pub async fn record_target_today_state(
    pool: &SqlitePool,
    id: &str,
    sent: Option<bool>,
    checked_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "UPDATE spark_targets SET is_sparked_today = ?1, today_checked_at = ?2 WHERE id = ?3",
    )
    .bind(if sent == Some(true) { 1 } else { 0 })
    .bind(sent.map(|_| checked_at.to_rfc3339()))
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_target(pool: &SqlitePool, target: &SparkTarget) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO spark_targets (
            id, account_id, target_sec_uid, target_uid, conversation_id, conversation_type,
            target_nickname, remark_name, target_avatar, is_enabled, spark_days, spark_desc, is_sparked_today,
            message_template, last_sent_at, last_status, last_error,
            created_at, updated_at, today_checked_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
        "#
    )
    .bind(&target.id)
    .bind(&target.account_id)
    .bind(&target.target_sec_uid)
    .bind(&target.target_uid)
    .bind(&target.conversation_id)
    .bind(target.conversation_type)
    .bind(&target.target_nickname)
    .bind(&target.remark_name)
    .bind(&target.target_avatar)
    .bind(if target.is_enabled { 1 } else { 0 })
    .bind(target.spark_days)
    .bind(&target.spark_desc)
    .bind(if target.is_sparked_today.unwrap_or(false) { 1 } else { 0 })
    .bind(&target.message_template)
    .bind(target.last_sent_at.map(|t| t.to_rfc3339()))
    .bind(&target.last_status)
    .bind(&target.last_error)
    .bind(target.created_at.to_rfc3339())
    .bind(target.updated_at.to_rfc3339())
    .bind(target.today_checked_at.map(|t| t.to_rfc3339()))
    .execute(pool)
    .await
    .context("failed to insert target")?;

    Ok(())
}

pub async fn list_targets(pool: &SqlitePool, account_id: Option<&str>) -> Result<Vec<SparkTarget>> {
    let query_str = if account_id.is_some() {
        "SELECT * FROM spark_targets WHERE account_id = ?1 ORDER BY created_at DESC"
    } else {
        "SELECT * FROM spark_targets ORDER BY created_at DESC"
    };

    let mut query = sqlx::query(query_str);
    if let Some(acc) = account_id {
        query = query.bind(acc);
    }

    let rows = query
        .fetch_all(pool)
        .await
        .context("failed to list targets")?;

    let targets = rows
        .into_iter()
        .map(|r| {
            let is_enabled_int: i32 = r.get("is_enabled");
            let last_sent: Option<String> = r.try_get("last_sent_at").ok();
            let created: String = r.get("created_at");
            let updated: String = r.get("updated_at");

            SparkTarget {
                id: r.get("id"),
                account_id: r.get("account_id"),
                target_sec_uid: r.get("target_sec_uid"),
                target_uid: r.get("target_uid"),
                conversation_id: r.get("conversation_id"),
                conversation_type: r.try_get::<i32, _>("conversation_type").unwrap_or(1),
                target_nickname: r.get("target_nickname"),
                remark_name: r.try_get("remark_name").ok(),
                target_avatar: r.get("target_avatar"),
                is_enabled: is_enabled_int != 0,
                spark_days: r.get("spark_days"),
                spark_desc: r.try_get("spark_desc").ok(),
                is_sparked_today: current_today_state(&r, Utc::now()),
                today_checked_at: r
                    .try_get::<Option<String>, _>("today_checked_at")
                    .ok()
                    .flatten()
                    .and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                message_template: r.get("message_template"),
                last_sent_at: last_sent.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                last_status: r.get("last_status"),
                last_error: r.get("last_error"),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }
        })
        .collect();

    Ok(targets)
}

pub async fn get_target(pool: &SqlitePool, id: &str) -> Result<Option<SparkTarget>> {
    let row = sqlx::query("SELECT * FROM spark_targets WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("failed to get target")?;

    match row {
        Some(r) => {
            let is_enabled_int: i32 = r.get("is_enabled");
            let last_sent: Option<String> = r.try_get("last_sent_at").ok();
            let created: String = r.get("created_at");
            let updated: String = r.get("updated_at");

            Ok(Some(SparkTarget {
                id: r.get("id"),
                account_id: r.get("account_id"),
                target_sec_uid: r.get("target_sec_uid"),
                target_uid: r.get("target_uid"),
                conversation_id: r.get("conversation_id"),
                target_nickname: r.get("target_nickname"),
                remark_name: r.try_get("remark_name").ok(),
                target_avatar: r.get("target_avatar"),
                conversation_type: r.try_get::<i32, _>("conversation_type").unwrap_or(1),
                is_enabled: is_enabled_int != 0,
                spark_days: r.get("spark_days"),
                spark_desc: r.try_get("spark_desc").ok(),
                message_template: r.get("message_template"),
                is_sparked_today: current_today_state(&r, Utc::now()),
                today_checked_at: r
                    .try_get::<Option<String>, _>("today_checked_at")
                    .ok()
                    .flatten()
                    .and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                last_sent_at: last_sent.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                last_status: r.get("last_status"),
                last_error: r.get("last_error"),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&updated)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }))
        }
        None => Ok(None),
    }
}

pub async fn update_target(pool: &SqlitePool, id: &str, req: &UpdateTargetReq) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    if let Some(enabled) = req.is_enabled {
        sqlx::query("UPDATE spark_targets SET is_enabled = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(if enabled { 1 } else { 0 })
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(nick) = &req.target_nickname {
        sqlx::query("UPDATE spark_targets SET target_nickname = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(nick)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(rem) = &req.remark_name {
        let stored = {
            let trimmed = rem.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        };
        sqlx::query("UPDATE spark_targets SET remark_name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(stored)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(avatar) = &req.target_avatar {
        let stored = {
            let trimmed = avatar.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        };
        sqlx::query("UPDATE spark_targets SET target_avatar = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(stored)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(days) = req.spark_days {
        sqlx::query("UPDATE spark_targets SET spark_days = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(days)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(desc) = &req.spark_desc {
        sqlx::query("UPDATE spark_targets SET spark_desc = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(desc)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }
    if let Some(sparked) = req.is_sparked_today {
        record_target_today_state(pool, id, Some(sparked), Utc::now()).await?;
    }
    if let Some(ctype) = req.conversation_type {
        sqlx::query(
            "UPDATE spark_targets SET conversation_type = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(ctype)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    }
    if let Some(tpl) = &req.message_template {
        sqlx::query(
            "UPDATE spark_targets SET message_template = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(tpl)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn update_target_spark_result(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    spark_days: Option<i32>,
    spark_desc: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    if let Some(days) = spark_days {
        sqlx::query(
            r#"
            UPDATE spark_targets
            SET last_sent_at = ?1, last_status = ?2, spark_days = ?3, spark_desc = COALESCE(?4, spark_desc), is_sparked_today = CASE WHEN ?2 = 'SUCCESS' THEN 1 ELSE is_sparked_today END, today_checked_at = CASE WHEN ?2 = 'SUCCESS' THEN ?6 ELSE today_checked_at END, last_error = ?5, updated_at = ?6
            WHERE id = ?7
            "#
        )
        .bind(&now)
        .bind(status)
        .bind(days)
        .bind(spark_desc)
        .bind(error)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            r#"
            UPDATE spark_targets
            SET last_sent_at = ?1, last_status = ?2, spark_desc = COALESCE(?3, spark_desc), is_sparked_today = CASE WHEN ?2 = 'SUCCESS' THEN 1 ELSE is_sparked_today END, today_checked_at = CASE WHEN ?2 = 'SUCCESS' THEN ?5 ELSE today_checked_at END, last_error = ?4, updated_at = ?5
            WHERE id = ?6
            "#,
        )
        .bind(&now)
        .bind(status)
        .bind(spark_desc)
        .bind(error)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn delete_target(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM spark_targets WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .context("failed to delete target")?;
    Ok(())
}

// ----------------- Log Operations -----------------

pub async fn insert_log(pool: &SqlitePool, log: &SparkLog) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO spark_logs (
            id, account_id, account_alias, target_id, target_nickname,
            action_type, status, message, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&log.id)
    .bind(&log.account_id)
    .bind(&log.account_alias)
    .bind(&log.target_id)
    .bind(&log.target_nickname)
    .bind(&log.action_type)
    .bind(&log.status)
    .bind(&log.message)
    .bind(log.created_at.to_rfc3339())
    .execute(pool)
    .await
    .context("failed to insert log")?;

    Ok(())
}

pub async fn list_logs(
    pool: &SqlitePool,
    limit: i64,
    offset: i64,
    account_id: Option<&str>,
    status: Option<&str>,
) -> Result<Vec<SparkLog>> {
    let mut sql = String::from("SELECT * FROM spark_logs WHERE 1=1");
    if account_id.is_some() {
        sql.push_str(" AND account_id = ?");
    }
    if status.is_some() {
        sql.push_str(" AND status = ?");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    // Dynamic bindings:
    let rows = match (account_id, status) {
        (Some(acc), Some(st)) => {
            sqlx::query(&sql)
                .bind(acc)
                .bind(st)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        }
        (Some(acc), None) => {
            sqlx::query(&sql)
                .bind(acc)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        }
        (None, Some(st)) => {
            sqlx::query(&sql)
                .bind(st)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        }
        (None, None) => {
            sqlx::query(&sql)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        }
    };

    let logs = rows
        .into_iter()
        .map(|r| {
            let created: String = r.get("created_at");
            SparkLog {
                id: r.get("id"),
                account_id: r.get("account_id"),
                account_alias: r.get("account_alias"),
                target_id: r.get("target_id"),
                target_nickname: r.get("target_nickname"),
                action_type: r.get("action_type"),
                status: r.get("status"),
                message: r.get("message"),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }
        })
        .collect();

    Ok(logs)
}

pub async fn count_logs(
    pool: &SqlitePool,
    account_id: Option<&str>,
    status: Option<&str>,
) -> Result<i64> {
    let mut sql = String::from("SELECT COUNT(*) FROM spark_logs WHERE 1=1");
    if account_id.is_some() {
        sql.push_str(" AND account_id = ?1");
    }
    if status.is_some() {
        if account_id.is_some() {
            sql.push_str(" AND status = ?2");
        } else {
            sql.push_str(" AND status = ?1");
        }
    }

    let count: i64 = match (account_id, status) {
        (Some(acc), Some(st)) => {
            sqlx::query_scalar(&sql)
                .bind(acc)
                .bind(st)
                .fetch_one(pool)
                .await?
        }
        (Some(acc), None) => sqlx::query_scalar(&sql).bind(acc).fetch_one(pool).await?,
        (None, Some(st)) => sqlx::query_scalar(&sql).bind(st).fetch_one(pool).await?,
        (None, None) => sqlx::query_scalar(&sql).fetch_one(pool).await?,
    };

    Ok(count)
}

// ----------------- Setting Operations -----------------

pub async fn get_setting(pool: &SqlitePool, key: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT value FROM system_settings WHERE key = ?1")
        .bind(key)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|r| r.get("value")))
}

pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO system_settings (key, value)
        VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        "#,
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_all_settings(pool: &SqlitePool) -> Result<HashMap<String, String>> {
    let rows = sqlx::query("SELECT key, value FROM system_settings")
        .fetch_all(pool)
        .await?;

    let map = rows
        .into_iter()
        .map(|r| (r.get("key"), r.get("value")))
        .collect();

    Ok(map)
}

pub async fn get_system_overview(
    pool: &SqlitePool,
    next_schedule_time: String,
) -> Result<SystemOverview> {
    let total_accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(pool)
        .await?;
    let active_accounts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;
    let expired_accounts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE status = 'EXPIRED'")
            .fetch_one(pool)
            .await?;

    let total_targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spark_targets")
        .fetch_one(pool)
        .await?;
    let active_targets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM spark_targets WHERE is_enabled = 1")
            .fetch_one(pool)
            .await?;

    // 统一按北京时间（UTC+8）统计今日已完成续火花目标数（含系统发送成功及消息历史已确认）
    let now = Utc::now();
    let all_targets = list_targets(pool, None).await.unwrap_or_default();
    let today_sparked_count = all_targets
        .iter()
        .filter(|t| {
            crate::model::system_sent_today(t.last_status.as_deref(), t.last_sent_at, now)
                || t.is_sparked_today == Some(true)
        })
        .count() as i64;

    Ok(SystemOverview {
        total_accounts,
        active_accounts,
        expired_accounts,
        total_targets,
        active_targets,
        today_sparked_count,
        next_schedule_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn today_state_expires_at_cst_midnight_not_utc_midnight() {
        let pool = init_pool("sqlite::memory:").await.unwrap();
        let now = DateTime::parse_from_rfc3339("2026-10-14T16:00:01Z")
            .unwrap()
            .with_timezone(&Utc);
        for (checked, expected) in [
            ("2026-10-14T15:59:59Z", None),
            ("2026-10-14T16:00:00Z", Some(true)),
            ("2026-10-15T00:00:00+08:00", Some(true)),
            ("2026-10-14T16:00:02Z", None),
            ("not-a-date", None),
        ] {
            let row = sqlx::query("SELECT 1 AS is_sparked_today, ?1 AS today_checked_at")
                .bind(checked)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(current_today_state(&row, now), expected, "{checked}");
        }
    }

    #[tokio::test]
    async fn test_db_init_and_account_crud() {
        let pool = init_pool("sqlite::memory:").await.expect("init pool");

        let account = Account {
            id: "acc_test_1".to_string(),
            alias: "测试账号1".to_string(),
            sec_uid: Some("sec_uid_123".to_string()),
            uid: Some("uid_123".to_string()),
            nickname: Some("抖音小助手".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            encrypted_cookie: vec![1, 2, 3, 4, 5],
            status: "ACTIVE".to_string(),
            bark_key_override: None,
            last_checked_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        insert_account(&pool, &account)
            .await
            .expect("insert account");

        let fetched = get_account(&pool, "acc_test_1")
            .await
            .expect("get account")
            .expect("should exist");
        assert_eq!(fetched.alias, "测试账号1");
        assert_eq!(fetched.encrypted_cookie, vec![1, 2, 3, 4, 5]);

        let target = SparkTarget {
            id: "tgt_test_1".to_string(),
            account_id: "acc_test_1".to_string(),
            target_sec_uid: "sec_friend_456".to_string(),
            target_uid: Some("uid_friend_456".to_string()),
            conversation_id: Some("conv_123".to_string()),
            conversation_type: 1,
            target_nickname: "火花好友".to_string(),
            remark_name: None,
            target_avatar: None,
            is_enabled: true,
            spark_days: 5,
            spark_desc: Some("已点亮 5 天".to_string()),
            is_sparked_today: Some(true),
            today_checked_at: None,
            message_template: "🔥".to_string(),
            last_sent_at: None,
            last_status: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        insert_target(&pool, &target).await.expect("insert target");
        let targets = list_targets(&pool, Some("acc_test_1"))
            .await
            .expect("list targets");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_nickname, "火花好友");
        // 旧布尔值没有检测时间，不能当作今日已发。
        assert_eq!(targets[0].is_sparked_today, None);
        let now = Utc::now();
        record_target_today_state(
            &pool,
            &target.id,
            Some(true),
            now - chrono::Duration::days(1),
        )
        .await
        .unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            None
        );
        record_target_today_state(&pool, &target.id, Some(false), now)
            .await
            .unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            Some(false)
        );
        record_target_today_state(&pool, &target.id, Some(true), now)
            .await
            .unwrap();
        assert_eq!(
            list_targets(&pool, None).await.unwrap()[0].is_sparked_today,
            Some(true)
        );
        // 失败发送不能覆盖已经确认的今日消息；检测失败不能保留旧成功。
        update_target_spark_result(&pool, &target.id, "FAILED", None, None, Some("offline"))
            .await
            .unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            Some(true)
        );
        record_target_today_state(&pool, &target.id, None, now)
            .await
            .unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            None
        );
        record_target_today_state(
            &pool,
            &target.id,
            Some(true),
            now + chrono::Duration::days(1),
        )
        .await
        .unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            None
        );
        update_target_spark_result(&pool, &target.id, "SUCCESS", Some(5), None, None)
            .await
            .unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            Some(true)
        );
        // 重复运行迁移不能为遗留状态补猜日期。
        record_target_today_state(&pool, &target.id, None, now)
            .await
            .unwrap();
        schema::init_schema(&pool).await.unwrap();
        assert_eq!(
            get_target(&pool, &target.id)
                .await
                .unwrap()
                .unwrap()
                .is_sparked_today,
            None
        );

        sqlx::query("INSERT INTO account_im_credentials VALUES(?1,?2,?3)")
            .bind(&account.id)
            .bind("conv_123")
            .bind(vec![7_u8, 8])
            .execute(&pool)
            .await
            .unwrap();
        let consumed: Option<(Vec<u8>,)> = sqlx::query_as("DELETE FROM account_im_credentials WHERE account_id=?1 AND conversation_id=?2 RETURNING encrypted_credential")
            .bind(&account.id).bind("conv_123").fetch_optional(&pool).await.unwrap();
        assert_eq!(consumed.unwrap().0, vec![7, 8]);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_im_credentials")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        sqlx::query("INSERT INTO account_im_credentials VALUES(?1,?2,?3)")
            .bind(&account.id)
            .bind("conv_123")
            .bind(vec![7_u8, 8])
            .execute(&pool)
            .await
            .unwrap();
        let secret = crate::crypto::SecretBox::new(&[42; 32]);
        let cookie = "sessionid=db-context-offline";
        let uid = "99191692311";
        let credential =
            crate::douyin::im_auth::test_credential(cookie, "0:1:55696816245:99191692311", 1);
        let context = crate::douyin::im_auth::WebSessionContext::from_credential(&credential);
        let client = crate::douyin::client::DouyinClient::new(cookie, "offline").unwrap();
        client.set_web_context(context.clone()).unwrap();
        client
            .persist_web_context(&pool, &secret, &account.id)
            .await
            .unwrap();
        let encrypted: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
        )
        .bind(&account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let plain = serde_json::to_vec(&context).unwrap();
        assert_ne!(encrypted, plain);
        assert_eq!(secret.decrypt(&encrypted).unwrap(), plain);
        let reloaded = crate::douyin::client::DouyinClient::new(cookie, "offline").unwrap();
        reloaded
            .load_web_context(&pool, &secret, &account.id, Some(uid))
            .await
            .unwrap();
        assert!(
            reloaded
                .load_web_context(&pool, &secret, &account.id, Some("1"))
                .await
                .is_err()
        );
        assert!(
            reloaded
                .load_web_context(
                    &pool,
                    &crate::crypto::SecretBox::new(&[43; 32]),
                    &account.id,
                    Some(uid)
                )
                .await
                .is_err()
        );
        update_account_status(&pool, &account.id, "EXPIRED", Utc::now())
            .await
            .unwrap();
        update_account_cookie(&pool, &account.id, &[9, 10])
            .await
            .unwrap();
        assert_eq!(
            get_account(&pool, &account.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "EXPIRED"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_im_credentials")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_web_contexts")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        // 同会话刷新可重新保存只读身份，但不能恢复已消费的发送凭证。
        client
            .persist_web_context(&pool, &secret, &account.id)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_web_contexts")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );

        // 日志筛选与分页必须按同一绑定顺序执行，不能混用 ?N 与 ?。
        for (index, status) in ["SUCCESS", "FAILED", "SUCCESS"].iter().enumerate() {
            insert_log(
                &pool,
                &SparkLog {
                    id: format!("log_filter_{index}"),
                    account_id: account.id.clone(),
                    account_alias: account.alias.clone(),
                    target_id: None,
                    target_nickname: None,
                    action_type: "CHECK_COOKIE".to_string(),
                    status: status.to_string(),
                    message: "离线日志筛选测试".to_string(),
                    created_at: Utc::now() + chrono::Duration::seconds(index as i64),
                },
            )
            .await
            .unwrap();
        }
        for (account_filter, status_filter, expected) in [
            (None, None, 3),
            (Some(account.id.as_str()), None, 3),
            (None, Some("SUCCESS"), 2),
            (Some(account.id.as_str()), Some("SUCCESS"), 2),
            (Some("missing-account"), None, 0),
            (Some(account.id.as_str()), Some("missing-status"), 0),
        ] {
            assert_eq!(
                count_logs(&pool, account_filter, status_filter)
                    .await
                    .unwrap(),
                expected
            );
            assert_eq!(
                list_logs(&pool, 20, 0, account_filter, status_filter)
                    .await
                    .unwrap()
                    .len(),
                expected as usize
            );
        }
        let filtered_page = list_logs(&pool, 1, 1, Some(&account.id), Some("SUCCESS"))
            .await
            .unwrap();
        assert_eq!(filtered_page.len(), 1);
        assert_eq!(filtered_page[0].id, "log_filter_0");

        // Test cascade delete
        delete_account(&pool, "acc_test_1")
            .await
            .expect("delete account");
        let targets_after = list_targets(&pool, Some("acc_test_1"))
            .await
            .expect("list targets");
        assert_eq!(targets_after.len(), 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM account_web_contexts")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn persist_login_session_updates_account_fingerprint_and_context_together() {
        let pool = init_pool("sqlite::memory:").await.unwrap();
        let secret = crate::crypto::SecretBox::new(&[61; 32]);
        let now = Utc::now();
        let old = Account {
            id: "acc_atomic_login".into(),
            alias: "旧别名".into(),
            sec_uid: None,
            uid: Some("99191692311".into()),
            nickname: None,
            avatar_url: None,
            encrypted_cookie: secret.encrypt(b"sessionid=old").unwrap(),
            status: "EXPIRED".into(),
            bark_key_override: Some("bark-account-key".into()),
            last_checked_at: None,
            created_at: now - chrono::Duration::days(1),
            updated_at: now - chrono::Duration::days(1),
        };
        insert_account(&pool, &old).await.unwrap();
        sqlx::query("INSERT INTO account_im_credentials VALUES(?1,?2,?3)")
            .bind(&old.id)
            .bind("0:1:1:2")
            .bind(vec![1_u8, 2, 3])
            .execute(&pool)
            .await
            .unwrap();

        let device = crate::douyin::device_profile::DeviceProfile::derive(&old.id);
        let cookie = "sessionid=rotated; passport_csrf_token=csrf";
        let context = crate::douyin::im_auth::WebSessionContext::from_session_with_device(
            99191692311,
            cookie,
            &device.user_agent,
            Some(device.clone()),
        )
        .unwrap();
        let updated = Account {
            alias: "新昵称".into(),
            sec_uid: Some("new-sec-uid".into()),
            nickname: Some("新昵称".into()),
            avatar_url: Some("https://example.com/new-avatar.png".into()),
            encrypted_cookie: secret.encrypt(cookie.as_bytes()).unwrap(),
            status: "ACTIVE".into(),
            last_checked_at: Some(now),
            updated_at: now,
            ..old.clone()
        };
        persist_login_session(&pool, &secret, &updated, &device, &context)
            .await
            .unwrap();

        let stored = get_account(&pool, &old.id).await.unwrap().unwrap();
        assert_eq!(stored.alias, "新昵称");
        assert_eq!(stored.sec_uid.as_deref(), Some("new-sec-uid"));
        assert_eq!(stored.status, "ACTIVE");
        assert_eq!(
            stored.bark_key_override.as_deref(),
            Some("bark-account-key")
        );
        assert_eq!(stored.created_at, old.created_at);
        assert_eq!(
            secret.decrypt(&stored.encrypted_cookie).unwrap(),
            cookie.as_bytes()
        );
        assert_eq!(
            load_or_create_device_profile(&pool, &secret, &old.id)
                .await
                .unwrap(),
            device
        );
        let encrypted_context: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
        )
        .bind(&old.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let stored_context: crate::douyin::im_auth::WebSessionContext =
            serde_json::from_slice(&secret.decrypt(&encrypted_context).unwrap()).unwrap();
        assert_eq!(stored_context.session_hash, context.session_hash);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM account_im_credentials WHERE account_id=?1"
            )
            .bind(&old.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn device_profiles_are_stable_and_isolated_per_account() {
        let pool = init_pool("sqlite::memory:").await.unwrap();
        let secret = crate::crypto::SecretBox::new(&[62; 32]);
        let now = Utc::now();
        for (id, alias) in [
            ("acc_device_first", "账号一"),
            ("acc_device_second", "账号二"),
        ] {
            insert_account(
                &pool,
                &Account {
                    id: id.into(),
                    alias: alias.into(),
                    sec_uid: None,
                    uid: None,
                    nickname: None,
                    avatar_url: None,
                    encrypted_cookie: secret.encrypt(b"sessionid=offline-device").unwrap(),
                    status: "ACTIVE".into(),
                    bark_key_override: None,
                    last_checked_at: None,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();
        }

        let first = load_or_create_device_profile(&pool, &secret, "acc_device_first")
            .await
            .unwrap();
        let second = load_or_create_device_profile(&pool, &secret, "acc_device_second")
            .await
            .unwrap();
        assert_ne!(first.device_tag, second.device_tag);
        assert_ne!(first, second);
        assert_eq!(
            load_or_create_device_profile(&pool, &secret, "acc_device_first")
                .await
                .unwrap(),
            first
        );

        let encrypted_profiles: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT encrypted_profile FROM account_device_profiles ORDER BY account_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(encrypted_profiles.len(), 2);
        assert_ne!(encrypted_profiles[0], encrypted_profiles[1]);
        for encrypted in encrypted_profiles {
            assert!(
                !encrypted
                    .windows(first.user_agent.len())
                    .any(|window| window == first.user_agent.as_bytes())
            );
        }
    }
}
