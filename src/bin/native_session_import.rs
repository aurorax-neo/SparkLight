//! Import one official Android login into SparkLight without exporting secrets in output.
//!
//! The input JSON is the `NativeSessionRecord` schema. On an existing account, omitted
//! UID/profile fields are filled from the encrypted account row. The importer keeps the
//! native Cookie and X-Tt-Token in one encrypted transaction and tries to rebuild the Web
//! send context unless `--skip-web-bootstrap` is given.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use clap::Parser;
use sparklight::{
    crypto::load_or_create_master_key,
    db,
    douyin::{
        login::{self, NativeCheck},
        native_import,
    },
};
use sqlx::sqlite::SqlitePoolOptions;

#[derive(Debug, Parser)]
#[command(
    name = "native_session_import",
    about = "导入官方 Android 抖音原生会话，并加密保存到 SparkLight"
)]
struct Args {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    input: Option<PathBuf>,
    #[arg(long)]
    account_id: Option<String>,
    #[arg(long)]
    alias: Option<String>,
    #[arg(long)]
    skip_web_bootstrap: bool,
    #[arg(long)]
    verify: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    template: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.template {
        print_template();
        return Ok(());
    }
    let data_dir = args
        .data_dir
        .clone()
        .or_else(|| std::env::var_os("SPARK_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/data"));

    let input = args.input.as_deref().context("缺少 --input 会话文件")?;
    inspect_private_file(input)?;
    let bytes =
        std::fs::read(input).with_context(|| format!("读取会话文件失败：{}", input.display()))?;
    ensure!(bytes.len() <= 256 * 1024, "会话文件超过 256 KiB 安全上限");
    let imported = native_import::parse_import_json(&bytes)?;
    if let Some(account_id) = args.account_id.as_deref() {
        ensure!(
            imported.account_id == account_id,
            "--account-id 与文件中的 account_id 不一致"
        );
    }
    let db_file = data_dir.join("sparklight.db");
    let key_file = data_dir.join(".master-key");
    ensure!(db_file.is_file(), "数据库不存在：{}", db_file.display());
    ensure!(key_file.is_file(), "主密钥不存在：{}", key_file.display());

    let secret_box = load_or_create_master_key(&data_dir)?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}", db_file.display()))
        .await
        .context("打开 SparkLight 数据库失败")?;
    sparklight::db::schema::init_schema(&pool).await?;

    let alias_override = args.alias.as_deref();
    let prepared = native_import::prepare_import(&pool, imported, alias_override, false).await?;
    println!("account_id       = {}", prepared.account_id);
    println!("alias            = {}", prepared.alias);
    println!("uid              = {}", prepared.session.uid);
    println!("cookie_bytes     = {}", prepared.session.cookie.len());
    println!(
        "x_tt_token       = {}",
        prepared.session.x_tt_token.is_some() || prepared.session.token_encrypted.is_some()
    );
    println!("sid_expires_at   = {}", prepared.sid_expires_at);
    if args.dry_run {
        println!("dry_run          = true");
        return Ok(());
    }
    let outcome =
        native_import::import_prepared(&pool, &secret_box, prepared, args.skip_web_bootstrap)
            .await?;

    println!("web_ready        = {}", outcome.web_ready);
    if let Some(warning) = outcome.warning.as_deref() {
        println!("warning          = {warning}");
    }

    if args.verify {
        let imported_session = db::load_native_session(&pool, &secret_box, &outcome.account_id)
            .await?
            .context("导入后无法重新读取原生会话")?;
        match login::check_native_session(&imported_session).await {
            NativeCheck::Valid(profile) => {
                db::update_account_status(&pool, &outcome.account_id, "ACTIVE", Utc::now()).await?;
                println!("native_check     = valid uid={}", profile.uid);
            }
            NativeCheck::Expired(reason) => {
                db::update_account_status(&pool, &outcome.account_id, "EXPIRED", Utc::now())
                    .await?;
                println!("native_check     = expired reason={reason}");
            }
            NativeCheck::Unconfirmed(reason) => {
                println!("native_check     = unconfirmed reason={reason}");
            }
        }
    }
    println!("native_saved     = true");
    Ok(())
}

fn inspect_private_file(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("读取会话文件属性失败：{}", path.display()))?;
    ensure!(metadata.is_file(), "会话输入不是普通文件");
    ensure!(
        metadata.len() <= 256 * 1024,
        "会话文件超过 256 KiB 安全上限"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        ensure!(
            mode & 0o077 == 0,
            "会话文件权限过宽（{:o}），请先执行 chmod 600 {}",
            mode,
            path.display()
        );
    }
    Ok(())
}

fn print_template() {
    let value = native_import::template();
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
    );
}
