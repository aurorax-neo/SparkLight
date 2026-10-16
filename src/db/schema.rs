use anyhow::{Context, Result};
use sqlx::SqlitePool;

pub async fn init_schema(pool: &SqlitePool) -> Result<()> {
    sqlx::query("PRAGMA journal_mode = WAL;")
        .execute(pool)
        .await
        .context("failed to set journal_mode WAL")?;

    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(pool)
        .await
        .context("failed to enable foreign_keys")?;

    let sql = r#"
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        alias TEXT NOT NULL,
        sec_uid TEXT,
        uid TEXT,
        nickname TEXT,
        avatar_url TEXT,
        encrypted_cookie BLOB NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        bark_key_override TEXT,
        last_checked_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS spark_targets (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        target_sec_uid TEXT NOT NULL,
        target_uid TEXT,
        conversation_id TEXT,
        conversation_type INTEGER NOT NULL DEFAULT 1,
        target_nickname TEXT NOT NULL,
        target_avatar TEXT,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        spark_days INTEGER NOT NULL DEFAULT 0,
        spark_desc TEXT,
        is_sparked_today INTEGER NOT NULL DEFAULT 0,
        today_checked_at TEXT,
        message_template TEXT NOT NULL DEFAULT '🔥',
        last_sent_at TEXT,
        last_status TEXT,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS spark_logs (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        account_alias TEXT NOT NULL,
        target_id TEXT,
        target_nickname TEXT,
        action_type TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS account_im_credentials (
        account_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        encrypted_credential BLOB NOT NULL,
        PRIMARY KEY (account_id, conversation_id),
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS account_web_contexts (
        account_id TEXT PRIMARY KEY,
        encrypted_context BLOB NOT NULL,
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS im_send_attempts (
        account_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        beijing_day TEXT NOT NULL,
        client_message_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK(state IN ('CLAIMED','ACCEPTED','REJECTED','UNKNOWN')),
        message_id TEXT,
        PRIMARY KEY(account_id,conversation_id,beijing_day)
    );

    CREATE INDEX IF NOT EXISTS idx_targets_account_id ON spark_targets (account_id);
    CREATE INDEX IF NOT EXISTS idx_logs_created_at ON spark_logs (created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_logs_account_id ON spark_logs (account_id);
    "#;

    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .context("failed to execute init schema DDL")?;
    // Safe migration: add spark_desc column if not exists
    let _ = sqlx::query("ALTER TABLE spark_targets ADD COLUMN spark_desc TEXT;")
        .execute(pool)
        .await;
    // Safe migration: add is_sparked_today column if not exists
    let _ = sqlx::query("ALTER TABLE spark_targets ADD COLUMN is_sparked_today INTEGER DEFAULT 0;")
        .execute(pool)
        .await;
    // Safe migration: add conversation_type column if not exists
    let _ = sqlx::query("ALTER TABLE spark_targets ADD COLUMN conversation_type INTEGER DEFAULT 1;")
        .execute(pool)
        .await;
    // Safe migration: add remark_name column if not exists
    let _ = sqlx::query("ALTER TABLE spark_targets ADD COLUMN remark_name TEXT;")
        .execute(pool)
        .await;
    // 不回填旧布尔值的日期：旧记录没有足够的“今日已发”证据。
    let columns = sqlx::query_scalar::<_, String>("SELECT name FROM pragma_table_info('spark_targets')")
        .fetch_all(pool).await?;
    if !columns.iter().any(|name| name == "today_checked_at") {
        sqlx::query("ALTER TABLE spark_targets ADD COLUMN today_checked_at TEXT")
            .execute(pool).await.context("failed to add today_checked_at")?;
    }




    Ok(())
}
