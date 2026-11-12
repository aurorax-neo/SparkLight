//! 官方 Android 原生会话导入的共享校验与落库逻辑。
//!
//! 文件导入器和账号管理页使用同一套解析、身份冲突校验和加密保存路径。任何错误
//! 信息都不包含 Cookie、Token 或设备密钥原文。

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    crypto::SecretBox,
    db,
    douyin::{
        device_profile::DeviceProfile,
        login::{self, NativeSessionRecord},
        types::DouyinUserProfile,
    },
    model::Account,
};
use sqlx::SqlitePool;

pub const MAX_IMPORT_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
pub struct NativeImportFile {
    pub account_id: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(flatten)]
    pub session: NativeSessionRecord,
}

#[derive(Debug, Serialize)]
pub struct NativeImportOutcome {
    pub account_id: String,
    pub alias: String,
    pub uid: String,
    pub web_ready: bool,
    pub warning: Option<String>,
    pub sid_expires_at: i64,
}

#[derive(Debug)]
pub struct PreparedNativeImport {
    pub account_id: String,
    pub existing: Option<Account>,
    pub session: NativeSessionRecord,
    pub alias: String,
    pub sid_expires_at: i64,
}

pub fn parse_import_json(bytes: &[u8]) -> Result<NativeImportFile> {
    ensure!(
        bytes.len() <= MAX_IMPORT_BYTES,
        "会话文件超过 256 KiB 安全上限"
    );
    serde_json::from_slice(bytes).context("会话文件不是合法的导入 JSON")
}

pub async fn prepare_import(
    pool: &SqlitePool,
    mut imported: NativeImportFile,
    alias_override: Option<&str>,
    create_if_missing: bool,
) -> Result<PreparedNativeImport> {
    if imported.account_id.trim().is_empty() {
        ensure!(
            create_if_missing,
            "导入文件缺少 account_id；命令行导入只能写入现有账号"
        );
        imported.account_id = format!("acc_{}", uuid::Uuid::new_v4().simple());
    }
    validate_account_id(&imported.account_id)?;
    let existing = db::get_account(pool, &imported.account_id).await?;
    ensure!(
        existing.is_some() || create_if_missing,
        "导入目标账号不存在；网页新增账号可直接导入，命令行需使用现有 account_id"
    );
    hydrate_from_existing(&mut imported.session, existing.as_ref())?;
    normalize_session(&mut imported.session);
    imported.session.validate()?;
    ensure!(
        imported
            .session
            .x_tt_token
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || imported
                .session
                .token_encrypted
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        "导入会话缺少 X-Tt-Token；它无法用于 TokenBeat"
    );
    ensure!(
        has_auth_cookie(&imported.session.cookie),
        "导入 Cookie 缺少 sessionid/sid_tt/sid_guard 等登录凭证"
    );
    let sid_expires_at = imported
        .session
        .sid_expiry()
        .context("导入 Cookie 缺少可解析的 sid_guard，无法确认登录会话绝对有效期")?;
    ensure!(
        sid_expires_at > Utc::now().timestamp(),
        "导入会话已超过 sid_guard 绝对有效期"
    );
    if let Some(owner) = db::find_account_by_uid(pool, imported.session.uid.trim()).await? {
        ensure!(
            owner.id == imported.account_id,
            "该抖音 UID 已绑定其他 SparkLight 账号（{}），拒绝重复导入",
            owner.id
        );
    }

    let alias = alias_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| imported.alias.filter(|value| !value.trim().is_empty()))
        .or_else(|| existing.as_ref().map(|account| account.alias.clone()))
        .unwrap_or_else(|| {
            if imported.session.nickname.trim().is_empty() {
                "抖音账号".to_string()
            } else {
                imported.session.nickname.clone()
            }
        });
    Ok(PreparedNativeImport {
        account_id: imported.account_id,
        existing,
        session: imported.session,
        alias,
        sid_expires_at,
    })
}

pub async fn import_native_session(
    pool: &SqlitePool,
    secret: &SecretBox,
    imported: NativeImportFile,
    alias_override: Option<&str>,
    create_if_missing: bool,
    skip_web_bootstrap: bool,
) -> Result<NativeImportOutcome> {
    let prepared = prepare_import(pool, imported, alias_override, create_if_missing).await?;
    import_prepared(pool, secret, prepared, skip_web_bootstrap).await
}

pub async fn import_prepared(
    pool: &SqlitePool,
    secret: &SecretBox,
    prepared: PreparedNativeImport,
    skip_web_bootstrap: bool,
) -> Result<NativeImportOutcome> {
    let PreparedNativeImport {
        account_id,
        existing,
        mut session,
        alias,
        sid_expires_at,
    } = prepared;
    let now = Utc::now();
    let encrypted_cookie = secret.encrypt(session.cookie.as_bytes())?;
    let mut account = Account {
        id: account_id,
        alias,
        sec_uid: Some(session.sec_uid.clone()),
        uid: Some(session.uid.clone()),
        nickname: Some(session.nickname.clone()),
        avatar_url: Some(session.avatar_url.clone()),
        encrypted_cookie,
        status: "ACTIVE".to_string(),
        bark_key_override: existing
            .as_ref()
            .and_then(|account| account.bark_key_override.clone()),
        last_checked_at: Some(now),
        created_at: existing.as_ref().map_or(now, |account| account.created_at),
        updated_at: now,
    };
    let device = if session.guard_key_hex.is_some() {
        let profile = DeviceProfile::web_passport_profile(&account.id);
        let _ = db::store_device_profile(pool, secret, &account.id, &profile).await;
        profile
    } else {
        match existing.as_ref() {
        Some(_) => db::load_or_create_device_profile(pool, secret, &account.id).await?,
        None => DeviceProfile::derive(&account.id),
        }
    };

    let (mut web_ready, mut warning, mut web_context) = (false, None, None);
    if !skip_web_bootstrap {
        match login::bootstrap_web_context(&session, &device).await {
            Ok((cookie, context, profile)) => {
                session.cookie = cookie;
                apply_profile(&mut session, &mut account, profile);
                web_ready = true;
                web_context = Some(context);
                account.encrypted_cookie = secret.encrypt(session.cookie.as_bytes())?;
            }
            Err(error) => {
                warning = Some(format!(
                    "原生会话可保存，但 Web/IM 发送材料未就绪：{}",
                    compact_error(&error)
                ));
            }
        }
    }

    db::persist_native_login_session(
        pool,
        secret,
        &account,
        &device,
        &session,
        web_context.as_ref(),
    )
    .await?;
    Ok(NativeImportOutcome {
        account_id: account.id,
        alias: account.alias,
        uid: session.uid,
        web_ready,
        warning,
        sid_expires_at,
    })
}

pub fn template() -> Value {
    serde_json::json!({
        "account_id": "",
        "alias": "账号备注",
        "device": {
            "device_id": "官方 Android 客户端 device_id",
            "install_id": "官方 Android 客户端 install_id",
            "openudid": "官方 Android 客户端 openudid",
            "cdid": "官方 Android 客户端 cdid",
            "aid": "1128",
            "app_name": "aweme",
            "app_version": "40.8.0",
            "version_code": "400801",
            "device_platform": "android",
            "channel": "update",
            "package": "com.ss.android.ugc.aweme",
            "user_agent": "与提取 Cookie 的官方 Android 客户端完全一致"
        },
        "cookie": "完整 Cookie；包含 sessionid、sid_tt、sid_guard、d_ticket",
        "uid": "可留空，已有账号会自动补齐",
        "sec_uid": "可留空，已有账号会自动补齐",
        "nickname": "可留空，已有账号会自动补齐",
        "avatar_url": "可留空，已有账号会自动补齐",
        "mobile": "",
        "session_key": null,
        "d_ticket": null,
        "x_tt_token": "官方 App 的 X-Tt-Token",
        "token_encrypted": null,
        "ts_sign": null,
        "attest_ts_sign": null,
        "mfa_token": null,
        "logged_in_at": 0,
        "last_verified_at": null,
        "last_beat_at": null
    })
}

fn validate_account_id(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "account_id 只能包含 ASCII 字母、数字、下划线和短横线"
    );
    Ok(())
}

fn hydrate_from_existing(
    session: &mut NativeSessionRecord,
    existing: Option<&Account>,
) -> Result<()> {
    let Some(existing) = existing else {
        return Ok(());
    };
    if session.uid.trim().is_empty() {
        session.uid = existing.uid.clone().unwrap_or_default();
    }
    if session.sec_uid.trim().is_empty() {
        session.sec_uid = existing.sec_uid.clone().unwrap_or_default();
    }
    if session.nickname.trim().is_empty() {
        session.nickname = existing.nickname.clone().unwrap_or_default();
    }
    if session.avatar_url.trim().is_empty() {
        session.avatar_url = existing.avatar_url.clone().unwrap_or_default();
    }
    if let Some(stored_uid) = existing.uid.as_deref() {
        if !session.uid.is_empty() && session.uid != stored_uid {
            bail!("导入 UID 与现有账号不一致");
        }
    }
    if let Some(stored_sec_uid) = existing.sec_uid.as_deref() {
        if !session.sec_uid.is_empty() && session.sec_uid != stored_sec_uid {
            bail!("导入 sec_uid 与现有账号不一致");
        }
    }
    Ok(())
}

fn normalize_session(session: &mut NativeSessionRecord) {
    if session.logged_in_at <= 0 {
        session.logged_in_at = Utc::now().timestamp();
    }
    if session.d_ticket.is_none() {
        session.d_ticket = cookie_value(&session.cookie, "d_ticket");
    }
    if session.session_key.is_none() {
        session.session_key = cookie_value(&session.cookie, "session_key");
    }
}

fn apply_profile(
    session: &mut NativeSessionRecord,
    account: &mut Account,
    profile: DouyinUserProfile,
) {
    session.uid = nonempty_or(profile.uid, session.uid.clone());
    session.sec_uid = nonempty_or(profile.sec_uid, session.sec_uid.clone());
    session.nickname = nonempty_or(profile.nickname, session.nickname.clone());
    session.avatar_url = nonempty_or(profile.avatar_url, session.avatar_url.clone());
    account.uid = Some(session.uid.clone());
    account.sec_uid = Some(session.sec_uid.clone());
    account.nickname = Some(session.nickname.clone());
    account.avatar_url = Some(session.avatar_url.clone());
}

fn nonempty_or(value: String, fallback: String) -> String {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

fn cookie_value(cookie: &str, key: &str) -> Option<String> {
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name.trim() == key && !value.trim().is_empty()).then(|| value.trim().to_string())
    })
}

fn has_auth_cookie(cookie: &str) -> bool {
    ["sessionid", "sessionid_ss", "sid_tt", "sid_guard"]
        .iter()
        .any(|key| cookie_value(cookie, key).is_some())
}

fn compact_error(error: &anyhow::Error) -> String {
    error
        .to_string()
        .replace(['\r', '\n'], " ")
        .chars()
        .take(240)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn existing_account(secret: &SecretBox) -> Account {
        let now = Utc::now();
        Account {
            id: "acc_native_import".into(),
            alias: "导入测试账号".into(),
            sec_uid: Some("MS4wLjABAAAA-existing".into()),
            uid: Some("123456789".into()),
            nickname: Some("已有昵称".into()),
            avatar_url: Some("https://example.com/avatar.png".into()),
            encrypted_cookie: secret.encrypt(b"sessionid=old").unwrap(),
            status: "EXPIRED".into(),
            bark_key_override: Some("bark-account-key".into()),
            last_checked_at: None,
            created_at: now - Duration::days(1),
            updated_at: now - Duration::days(1),
        }
    }

    fn native_record(account_id: &str) -> NativeSessionRecord {
        let now = Utc::now().timestamp();
        NativeSessionRecord {
            device: crate::douyin::login::NativeDevice::derive(account_id),
            cookie: format!(
                "sessionid=public-session; sid_tt=public-sid; sid_guard=public%7C{now}%7C5184000%7Cfuture; d_ticket=public-d-ticket"
            ),
            uid: "123456789".into(),
            sec_uid: "MS4wLjABAAAA-existing".into(),
            nickname: "已有昵称".into(),
            avatar_url: "https://example.com/avatar.png".into(),
            mobile: String::new(),
            session_key: None,
            d_ticket: None,
            x_tt_token: Some("public-x-tt-token".into()),
            token_encrypted: None,
            ts_sign: None,
            attest_ts_sign: None,
            mfa_token: None,
            guard_key_hex: None,
            guard_server_data: None,
            dtrait_pk1_pem: None,
            dtrait_version: None,
            logged_in_at: now,
            last_verified_at: None,
            last_beat_at: None,
        }
    }

    #[test]
    fn existing_identity_is_hydrated_and_mismatch_is_rejected() {
        let secret = SecretBox::new(&[71; 32]);
        let existing = existing_account(&secret);
        let mut session = native_record(&existing.id);
        session.uid.clear();
        session.sec_uid.clear();
        session.nickname.clear();
        session.avatar_url.clear();

        hydrate_from_existing(&mut session, Some(&existing)).unwrap();
        assert_eq!(session.uid, "123456789");
        assert_eq!(session.sec_uid, "MS4wLjABAAAA-existing");
        session.uid = "987654321".into();
        assert!(
            hydrate_from_existing(&mut session, Some(&existing))
                .unwrap_err()
                .to_string()
                .contains("UID")
        );
    }

    #[tokio::test]
    async fn import_requires_existing_account_and_matching_identity() {
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[73; 32]);
        let existing = existing_account(&secret);
        db::insert_account(&pool, &existing).await.unwrap();

        let missing = NativeImportFile {
            account_id: "acc_missing_target".into(),
            alias: None,
            session: native_record("acc_missing_target"),
        };
        let error = import_native_session(&pool, &secret, missing, None, false, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("目标账号不存在"));

        let mut session = native_record(&existing.id);
        session.uid = "987654321".into();
        let mismatch = NativeImportFile {
            account_id: existing.id,
            alias: None,
            session,
        };
        let error = import_native_session(&pool, &secret, mismatch, None, false, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("UID"));
    }

    #[tokio::test]
    async fn imported_session_is_encrypted_and_persisted() {
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[72; 32]);
        let existing = existing_account(&secret);
        db::insert_account(&pool, &existing).await.unwrap();
        let native = native_record(&existing.id);
        let file = NativeImportFile {
            account_id: existing.id.clone(),
            alias: None,
            session: native.clone(),
        };
        let outcome = import_native_session(&pool, &secret, file, None, false, true)
            .await
            .unwrap();
        assert!(!outcome.web_ready);
        assert_eq!(outcome.account_id, existing.id);
        let stored = db::load_native_session(&pool, &secret, &existing.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.cookie, native.cookie);
        assert_eq!(stored.x_tt_token, native.x_tt_token);
    }

    #[tokio::test]
    async fn new_account_import_generates_id_and_rejects_duplicate_uid() {
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[74; 32]);
        let file = NativeImportFile {
            account_id: String::new(),
            alias: Some("新导入账号".into()),
            session: native_record("new-native-import"),
        };
        let outcome = import_native_session(&pool, &secret, file, None, true, true)
            .await
            .unwrap();
        assert!(outcome.account_id.starts_with("acc_"));
        assert_eq!(outcome.alias, "新导入账号");
        assert!(
            db::get_account(&pool, &outcome.account_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db::load_native_session(&pool, &secret, &outcome.account_id)
                .await
                .unwrap()
                .is_some()
        );

        let duplicate = NativeImportFile {
            account_id: String::new(),
            alias: Some("重复 UID".into()),
            session: native_record("another-native-import"),
        };
        let error = import_native_session(&pool, &secret, duplicate, None, true, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("已绑定其他 SparkLight 账号"));
    }

    #[tokio::test]
    async fn new_account_import_requires_xt_token() {
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[75; 32]);
        let mut session = native_record("missing-token");
        session.x_tt_token = None;
        let file = NativeImportFile {
            account_id: String::new(),
            alias: None,
            session,
        };
        let error = import_native_session(&pool, &secret, file, None, true, true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("X-Tt-Token"));
    }
}
