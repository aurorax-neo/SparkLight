//! 纯 Rust 抖音 App 二维码登录接口。

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::{
    db,
    douyin::{
        device_profile::DeviceProfile,
        login::{self, LoginPoll, PhoneLoginOutcome},
        native_import::{self, NativeImportFile},
    },
    model::Account,
    server::AppState,
};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn bad(message: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "code": 400, "message": message.into() })),
    )
}

fn internal(message: impl Into<String>) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "code": 500, "message": message.into() })),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartLoginReq {
    #[serde(default)]
    pub alias: String,
    /// 为空表示新增账号；有值表示为该账号重新同步登录态。
    #[serde(default)]
    pub account_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationWayReq {
    pub way: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartPhoneLoginReq {
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub account_id: Option<String>,
    pub mobile: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyPhoneLoginReq {
    pub code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordLoginReq {
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub account_id: Option<String>,
    pub mobile: String,
    pub password: String,
}

async fn resolve_target_account(
    state: &AppState,
    raw_account_id: Option<&str>,
    raw_alias: &str,
) -> Result<(String, String), ApiError> {
    let existing = match raw_account_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => Some(
            db::get_account(&state.pool, id)
                .await
                .map_err(|error| internal(error.to_string()))?
                .ok_or_else(|| bad("账号不存在，无法重新登录"))?,
        ),
        None => None,
    };
    let account_id = existing
        .as_ref()
        .map(|account| account.id.clone())
        .unwrap_or_else(|| format!("acc_{}", uuid::Uuid::new_v4().simple()));
    let alias = if raw_alias.trim().is_empty() {
        existing
            .as_ref()
            .map(|account| account.alias.clone())
            .unwrap_or_else(|| "抖音账号".to_string())
    } else {
        raw_alias.trim().to_string()
    };
    Ok((account_id, alias))
}

/// 官方手机版 App 的主登录入口：手机号 + 短信验证码。
pub async fn start_phone_login(
    State(state): State<AppState>,
    Json(req): Json<StartPhoneLoginReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    let (account_id, alias) =
        resolve_target_account(&state, req.account_id.as_deref(), &req.alias).await?;
    let session = login::start_phone_login(&account_id, &alias, &req.mobile)
        .await
        .map_err(|error| bad(format!("发送短信验证码失败：{error}")))?;
    let expires_in = session.expires_at - Utc::now().timestamp();
    let data = json!({
        "login_id": session.id,
        "account_id": session.account_id,
        "mobile_masked": session.mobile_masked(),
        "expires_in": expires_in.max(0)
    });
    state
        .phone_logins
        .lock()
        .await
        .insert(session.id.clone(), session);
    Ok(Json(json!({
        "code": 200,
        "data": data,
        "message": "验证码已发送，请查收短信"
    })))
}

pub async fn verify_phone_login(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VerifyPhoneLoginReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    let session = state
        .phone_logins
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| bad("短信登录会话不存在或已结束，请重新获取验证码"))?;
    if session.is_expired(Utc::now().timestamp()) {
        state.phone_logins.lock().await.remove(&id);
        return Err(bad("验证码已超时，请重新获取"));
    }
    let outcome = login::verify_phone_login(&session, &req.code)
        .await
        .map_err(|error| bad(format!("{error}")))?;
    match outcome {
        PhoneLoginOutcome::Confirmed(confirmed) => {
            state.phone_logins.lock().await.remove(&id);
            let account_id = session.account_id.clone();
            let alias = session.alias.clone();
            let (account, web_ready, message) =
                finalize_login(&state, &account_id, &alias, confirmed).await?;
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": id,
                    "account_id": account.id,
                    "uid": account.uid,
                    "nickname": account.nickname,
                    "status": "done",
                    "done": true,
                    "native_ready": true,
                    "web_ready": web_ready,
                    "identity_ready": web_ready,
                    "guard_ready": web_ready
                },
                "message": message
            })))
        }
        PhoneLoginOutcome::NeedSecondVerify {
            session: updated,
            challenge,
            message,
        } => {
            let challenge = fill_known_profile(&state, &updated.account_id, challenge).await;
            let login_id = updated.id.clone();
            let account_id = updated.account_id.clone();
            state.phone_logins.lock().await.insert(login_id.clone(), updated);
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": login_id,
                    "account_id": account_id,
                    "status": "verifying",
                    "done": false,
                    "challenge": challenge
                },
                "message": message
            })))
        }
    }
}

/// 官方手机版 App 原生登录：手机号 + 登录密码。
pub async fn password_login(
    State(state): State<AppState>,
    Json(req): Json<PasswordLoginReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    let (account_id, alias) =
        resolve_target_account(&state, req.account_id.as_deref(), &req.alias).await?;
    let outcome = login::login_with_password(&account_id, &alias, &req.mobile, &req.password)
        .await
        .map_err(|error| bad(format!("{error}")))?;
    match outcome {
        PhoneLoginOutcome::Confirmed(confirmed) => {
            let (account, web_ready, message) =
                finalize_login(&state, &account_id, &alias, confirmed).await?;
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "account_id": account.id,
                    "uid": account.uid,
                    "nickname": account.nickname,
                    "status": "done",
                    "done": true,
                    "native_ready": true,
                    "web_ready": web_ready,
                    "identity_ready": web_ready,
                    "guard_ready": web_ready
                },
                "message": message
            })))
        }
        PhoneLoginOutcome::NeedSecondVerify {
            session,
            challenge,
            message,
        } => {
            let challenge = fill_known_profile(&state, &session.account_id, challenge).await;
            let login_id = session.id.clone();
            let account_id = session.account_id.clone();
            state.phone_logins.lock().await.insert(login_id.clone(), session);
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": login_id,
                    "account_id": account_id,
                    "status": "verifying",
                    "done": false,
                    "challenge": challenge
                },
                "message": message
            })))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitVerificationReq {
    pub way: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeImportReq {
    pub session: NativeImportFile,
    #[serde(default)]
    pub skip_web_bootstrap: bool,
}

/// 导入同一官方 Android 客户端的完整原生会话，并立即加密落库。
pub async fn import_native_session(
    State(state): State<AppState>,
    Json(req): Json<NativeImportReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    let outcome = native_import::import_native_session(
        &state.pool,
        &state.secret_box,
        req.session,
        None,
        true,
        req.skip_web_bootstrap,
    )
    .await
    .map_err(|error| bad(format!("导入原生会话失败：{error:#}")))?;
    Ok(Json(json!({
        "code": 200,
        "data": {
            "account_id": outcome.account_id,
            "alias": outcome.alias,
            "uid": outcome.uid,
            "native_ready": true,
            "web_ready": outcome.web_ready,
            "sid_expires_at": outcome.sid_expires_at
        },
        "message": if outcome.web_ready {
            "官方原生会话已加密保存，App 登录有效；Web/IM 发送材料仍需执行前校验"
        } else {
            "官方原生会话已加密保存，App 登录有效；Web/IM 发送材料会在后台自动恢复"
        },
        "warning": outcome.warning
    })))
}

/// 创建官方 App 二维码。前端只接收二维码图片和会话 ID。
pub async fn start_login(
    State(state): State<AppState>,
    Json(req): Json<StartLoginReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    reap_expired(&state).await;

    let existing = match req
        .account_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(id) => Some(
            db::get_account(&state.pool, id)
                .await
                .map_err(|error| internal(error.to_string()))?
                .ok_or_else(|| bad("账号不存在，无法重新登录"))?,
        ),
        None => None,
    };
    let account_id = existing
        .as_ref()
        .map(|account| account.id.clone())
        .unwrap_or_else(|| format!("acc_{}", uuid::Uuid::new_v4().simple()));
    let alias = if req.alias.trim().is_empty() {
        existing
            .as_ref()
            .map(|account| account.alias.clone())
            .unwrap_or_else(|| "抖音账号".to_string())
    } else {
        req.alias.trim().to_string()
    };

    if let Some(session) = state
        .logins
        .lock()
        .await
        .values()
        .find(|session| {
            session.account_id == account_id && !session.is_expired(Utc::now().timestamp())
        })
        .cloned()
    {
        return Ok(Json(json!({
            "code": 200,
            "data": {
                "login_id": session.id,
                "account_id": account_id,
                "qrcode": session.qrcode,
                "expires_in": (session.expires_at - Utc::now().timestamp()).max(0)
            },
            "message": "已复用进行中的二维码"
        })));
    }

    let session = login::start(&account_id, &alias)
        .await
        .map_err(|error| bad(format!("获取抖音登录二维码失败：{error}")))?;
    let expires_in = session.expires_at - Utc::now().timestamp();
    let data = json!({
        "login_id": session.id,
        "account_id": account_id,
        "qrcode": session.qrcode,
        "expires_in": expires_in.max(0)
    });
    state
        .logins
        .lock()
        .await
        .insert(session.id.clone(), session);

    Ok(Json(json!({
        "code": 200,
        "data": data,
        "message": "请使用抖音 App 扫码登录"
    })))
}

/// 轮询官方扫码状态；确认后在同一次请求中完成原生会话与 Web IM 上下文的原子落库。
pub async fn login_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let session = state
        .logins
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| bad("登录会话不存在或已结束，请重新发起"))?;
    let now = Utc::now().timestamp();
    if session.is_expired(now) {
        let message = if session.qr_expired(now) && !session.has_verification() {
            "二维码已过期，请重新获取"
        } else {
            "身份验证已超时，请重新获取二维码"
        };
        state.logins.lock().await.remove(&id);
        return Ok(Json(json!({
            "code": 200,
            "data": { "login_id": id, "status": "expired", "done": false },
            "message": message
        })));
    }

    let polled = login::poll(&session)
        .await
        .map_err(|error| bad(format!("查询扫码状态失败：{error}")))?;
    match polled {
        LoginPoll::Pending { status, challenge } => {
            let expires_in = session.session_expires_at() - Utc::now().timestamp();
            let message = match status.as_str() {
                "scanned" => "已扫码，请在手机端确认登录",
                "verifying" => "已扫码，请按手机端提示完成身份验证，系统会继续等待",
                "loading" => "正在确认二维码状态",
                _ => "等待使用抖音 App 扫码",
            };
            let challenge = match challenge {
                Some(challenge) => {
                    Some(fill_known_profile(&state, &session.account_id, challenge.view()).await)
                }
                None => None,
            };
            let data = match challenge {
                Some(challenge) => json!({
                    "login_id": id,
                    "account_id": session.account_id,
                    "status": status,
                    "done": false,
                    "expires_in": expires_in.max(0),
                    "challenge": challenge
                }),
                None => json!({
                    "login_id": id,
                    "account_id": session.account_id,
                    "status": status,
                    "done": false,
                    "expires_in": expires_in.max(0)
                }),
            };
            Ok(Json(json!({
                "code": 200,
                "data": data,
                "message": message
            })))
        }
        LoginPoll::Terminal { status, message } => {
            state.logins.lock().await.remove(&id);
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": id,
                    "account_id": session.account_id,
                    "status": status,
                    "done": false
                },
                "message": message
            })))
        }
        LoginPoll::Confirmed(confirmed) => {
            // 先移除会话，避免并发轮询对同一次扫码重复落库。
            state.logins.lock().await.remove(&id);
            let account_id = session.account_id.clone();
            let alias = session.alias.clone();
            let (account, web_ready, message) =
                finalize_login(&state, &account_id, &alias, confirmed).await?;
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": id,
                    "account_id": account.id,
                    "uid": account.uid,
                    "nickname": account.nickname,
                    "status": "done",
                    "done": true,
                    "native_ready": true,
                    "web_ready": web_ready,
                    "identity_ready": web_ready,
                    "guard_ready": web_ready
                },
                "message": message
            })))
        }
    }
}

async fn finalize_login(
    state: &AppState,
    account_id: &str,
    alias: &str,
    confirmed: login::ConfirmedLogin,
) -> Result<(Account, bool, String), ApiError> {
    let mut target_account_id = account_id.to_string();
    let mut existing = db::get_account(&state.pool, &target_account_id)
        .await
        .map_err(|error| internal(error.to_string()))?;
    if let Ok(all_accounts) = db::list_accounts(&state.pool).await
        && let Some(matched) = all_accounts
            .into_iter()
            .find(|acc| acc.uid.as_deref() == Some(confirmed.record.uid.as_str()))
    {
        target_account_id = matched.id.clone();
        existing = Some(matched);
    }
    let account_id = target_account_id.as_str();
    if let Some(stored_uid) = existing.as_ref().and_then(|account| account.uid.as_deref()) {
        if !stored_uid.trim().is_empty() && stored_uid != confirmed.record.uid {
            return Err(bad("当前扫码账号与目标账号不一致，未保存任何内容"));
        }
    }

    let device = if confirmed.record.guard_key_hex.is_some() {
        let profile = DeviceProfile::web_passport_profile(account_id);
        let _ = db::store_device_profile(&state.pool, &state.secret_box, account_id, &profile).await;
        profile
    } else {
        match existing.as_ref() {
        Some(_) => db::load_or_create_device_profile(&state.pool, &state.secret_box, account_id)
            .await
            .map_err(|error| internal(format!("账号设备指纹读取失败：{error}")))?,
        None => DeviceProfile::derive(account_id),
        }
    };
    device
        .validate()
        .map_err(|error| bad(format!("账号设备指纹无效：{error}")))?;

    let mut native = confirmed.record;
    let bootstrap = login::bootstrap_web_context(&native, &device).await;
    let (final_cookie, web_context, profile, web_ready, warning) = match bootstrap {
        Ok((cookie, context, profile)) => (cookie, Some(context), profile, true, None),
        Err(error) => (
            native.cookie.clone(),
            None,
            native.profile(),
            false,
            Some(format!(
                "原生登录已保存，但 Web/IM 发送材料尚未就绪：{}",
                compact_error(&error)
            )),
        ),
    };
    let profile = crate::douyin::types::DouyinUserProfile {
        uid: nonempty_or(profile.uid, native.uid.clone()),
        sec_uid: nonempty_or(profile.sec_uid, native.sec_uid.clone()),
        nickname: nonempty_or(profile.nickname, native.nickname.clone()),
        avatar_url: nonempty_or(profile.avatar_url, native.avatar_url.clone()),
    };
    native.cookie = final_cookie.clone();
    native.sec_uid = profile.sec_uid.clone();
    native.nickname = profile.nickname.clone();
    native.avatar_url = profile.avatar_url.clone();
    if web_ready {
        native.last_verified_at = Some(Utc::now().timestamp());
    }

    let encrypted_cookie = state
        .secret_box
        .encrypt(final_cookie.as_bytes())
        .map_err(|error| internal(format!("加密原生 Cookie 失败：{error}")))?;
    let now = Utc::now();
    let final_alias = match existing.as_ref() {
        Some(account)
            if !account.alias.trim().is_empty()
                && account.alias != "抖音账号"
                && account.alias != profile.nickname =>
        {
            account.alias.clone()
        }
        _ if !alias.trim().is_empty() && alias != "抖音账号" => alias.to_string(),
        _ => profile.nickname.clone(),
    };
    let account = Account {
        id: account_id.to_string(),
        alias: final_alias,
        sec_uid: Some(profile.sec_uid.clone()),
        uid: Some(profile.uid.clone()),
        nickname: Some(profile.nickname.clone()),
        avatar_url: Some(profile.avatar_url.clone()),
        encrypted_cookie,
        status: "ACTIVE".to_string(),
        bark_key_override: existing
            .as_ref()
            .and_then(|account| account.bark_key_override.clone()),
        last_checked_at: Some(now),
        created_at: existing
            .as_ref()
            .map(|account| account.created_at)
            .unwrap_or(now),
        updated_at: now,
    };
    db::persist_native_login_session(
        &state.pool,
        &state.secret_box,
        &account,
        &device,
        &native,
        web_context.as_ref(),
    )
    .await
    .map_err(|error| internal(format!("登录会话原子保存失败：{error}")))?;

    let message = if web_ready {
        "抖音 App 登录成功，原生会话与 Web 发送材料已保存".to_string()
    } else {
        warning.unwrap_or_else(|| "抖音 App 登录已保存，Web 发送材料待恢复".to_string())
    };
    Ok((account, web_ready, message))
}

/// 发送下行短信验证码。响应只包含投递状态，不返回二维码或验证票据。
pub async fn send_verification_code(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VerificationWayReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    if let Some(phone_session) = active_phone_login(&state, &id).await? {
        let (delivery, message) = login::prepare_phone_second_verify(&phone_session, req.way.trim())
            .await
            .map_err(|error| bad(error.to_string()))?;
        return Ok(Json(json!({
            "code": 200,
            "data": {
                "login_id": id,
                "status": "verifying",
                "done": false,
                "delivery": delivery
            },
            "message": message
        })));
    }
    let session = active_login(&state, &id).await?;
    let message = login::send_verification_code(&session, req.way.trim())
        .await
        .map_err(|error| bad(error.to_string()))?;
    Ok(Json(json!({
        "code": 200,
        "data": { "login_id": id, "status": "verifying", "done": false },
        "message": message
    })))
}

/// 准备上行短信挑战，返回短信内容和号码，不返回内部票据。
pub async fn prepare_up_sms(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VerificationWayReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    if let Some(phone_session) = active_phone_login(&state, &id).await? {
        let (delivery, message) = login::prepare_phone_second_verify(&phone_session, req.way.trim())
            .await
            .map_err(|error| bad(error.to_string()))?;
        return Ok(Json(json!({
            "code": 200,
            "data": {
                "login_id": id,
                "status": "verifying",
                "done": false,
                "delivery": delivery
            },
            "message": message
        })));
    }
    let session = active_login(&state, &id).await?;
    let delivery = login::prepare_up_sms_verification(&session, req.way.trim())
        .await
        .map_err(|error| bad(error.to_string()))?;
    Ok(Json(json!({
        "code": 200,
        "data": {
            "login_id": id,
            "status": "verifying",
            "done": false,
            "delivery": delivery
        },
        "message": "请使用绑定手机发送短信，完成后回到这里确认"
    })))
}

/// 提交二次验证。成功后服务端立即换票，前端继续轮询确认账号资料落库。
pub async fn submit_verification(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SubmitVerificationReq>,
) -> Result<impl IntoResponse, ApiError> {
    state.engine.record_manual_action();
    if let Some(phone_session) = active_phone_login(&state, &id).await? {
        let way = req.way.trim();
        let outcome = login::submit_phone_second_verify(
            &phone_session,
            way,
            req.code.as_deref(),
            req.password.as_deref(),
        )
        .await
        .map_err(|error| bad(error.to_string()))?;
        return match outcome {
            PhoneLoginOutcome::Confirmed(confirmed) => {
                let account_id = phone_session.account_id.clone();
                let alias = phone_session.alias.clone();
                let (account, web_ready, message) =
                    finalize_login(&state, &account_id, &alias, confirmed).await?;
                state.phone_logins.lock().await.remove(&id);
                Ok(Json(json!({
                    "code": 200,
                    "data": {
                        "login_id": id,
                        "account_id": account.id,
                        "uid": account.uid,
                        "nickname": account.nickname,
                        "status": "done",
                        "done": true,
                        "native_ready": true,
                        "web_ready": web_ready,
                        "identity_ready": web_ready,
                        "guard_ready": web_ready
                    },
                    "message": message
                })))
            }
            PhoneLoginOutcome::NeedSecondVerify {
                session: updated,
                challenge,
                message,
            } => {
                let challenge = fill_known_profile(&state, &updated.account_id, challenge).await;
                state.phone_logins.lock().await.insert(id.clone(), updated);
                Ok(Json(json!({
                    "code": 200,
                    "data": {
                        "login_id": id,
                        "account_id": phone_session.account_id,
                        "status": "verifying",
                        "done": false,
                        "challenge": challenge
                    },
                    "message": message
                })))
            }
        };
    }
    let session = active_login(&state, &id).await?;
    let way = req.way.trim();
    let polled =
        login::submit_verification(&session, way, req.code.as_deref(), req.password.as_deref())
            .await
            .map_err(|error| bad(error.to_string()))?;
    match polled {
        LoginPoll::Confirmed(confirmed) => {
            state.logins.lock().await.remove(&id);
            let account_id = session.account_id.clone();
            let alias = session.alias.clone();
            let (account, web_ready, message) =
                finalize_login(&state, &account_id, &alias, confirmed).await?;
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": id,
                    "account_id": account.id,
                    "uid": account.uid,
                    "nickname": account.nickname,
                    "status": "done",
                    "done": true,
                    "native_ready": true,
                    "web_ready": web_ready,
                    "identity_ready": web_ready,
                    "guard_ready": web_ready
                },
                "message": message
            })))
        }
        LoginPoll::Pending { status, challenge } => {
            let challenge = match challenge {
                Some(challenge) => {
                    Some(fill_known_profile(&state, &session.account_id, challenge.view()).await)
                }
                None => None,
            };
            Ok(Json(json!({
                "code": 200,
                "data": {
                    "login_id": id,
                    "account_id": session.account_id,
                    "status": status,
                    "done": false,
                    "challenge": challenge
                },
                "message": "身份验证仍在进行，系统会继续等待"
            })))
        }
        LoginPoll::Terminal { status, message } => Ok(Json(json!({
            "code": 200,
            "data": {
                "login_id": id,
                "account_id": session.account_id,
                "status": status,
                "done": false
            },
            "message": message
        }))),
    }
}

async fn active_login(state: &AppState, id: &str) -> Result<login::LoginSession, ApiError> {
    let session = state
        .logins
        .lock()
        .await
        .get(id)
        .cloned()
        .ok_or_else(|| bad("登录会话不存在或已结束，请重新发起"))?;
    if session.is_expired(Utc::now().timestamp()) {
        state.logins.lock().await.remove(id);
        return Err(bad("身份验证已超时，请重新获取二维码"));
    }
    Ok(session)
}

async fn active_phone_login(
    state: &AppState,
    id: &str,
) -> Result<Option<login::PhoneLoginSession>, ApiError> {
    let Some(session) = state.phone_logins.lock().await.get(id).cloned() else {
        return Ok(None);
    };
    if session.is_expired(Utc::now().timestamp()) {
        state.phone_logins.lock().await.remove(id);
        return Err(bad("二次验证会话已超时，请重新发起登录"));
    }
    Ok(Some(session))
}

fn compact_error(error: &anyhow::Error) -> String {
    format!("{error:#}").chars().take(180).collect::<String>()
}

fn nonempty_or(candidate: String, fallback: String) -> String {
    if candidate.trim().is_empty() {
        fallback
    } else {
        candidate
    }
}

async fn fill_known_profile(
    state: &AppState,
    account_id: &str,
    mut challenge: login::LoginChallengeView,
) -> login::LoginChallengeView {
    let login::LoginChallengeView::TwoStep {
        avatar_url,
        profile_name,
        ..
    } = &mut challenge
    else {
        return challenge;
    };
    if avatar_url.is_some() && profile_name.is_some() {
        return challenge;
    }
    let Ok(Some(account)) = db::get_account(&state.pool, account_id).await else {
        return challenge;
    };
    if avatar_url.is_none() {
        *avatar_url = account
            .avatar_url
            .filter(|url| url.starts_with("https://") && url.len() <= 2048);
    }
    if profile_name.is_none() {
        *profile_name = account
            .nickname
            .filter(|name| !name.trim().is_empty())
            .or_else(|| {
                let alias = account.alias.trim();
                if alias.is_empty() || alias == "抖音账号" {
                    None
                } else {
                    Some(account.alias)
                }
            });
    }
    challenge
}

pub async fn cancel_login(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    state.logins.lock().await.remove(&id);
    state.phone_logins.lock().await.remove(&id);
    Ok(Json(json!({ "code": 200, "message": "已取消登录" })))
}

async fn reap_expired(state: &AppState) {
    let now = Utc::now().timestamp();
    state
        .logins
        .lock()
        .await
        .retain(|_, session| !session.is_expired(now));
    state
        .phone_logins
        .lock()
        .await
        .retain(|_, session| !session.is_expired(now));
}
