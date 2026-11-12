use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde_json::json;

use crate::{
    db,
    douyin::client::DouyinClient,
    model::{Account, AccountDto, UpdateAccountReq},
    server::AppState,
};

struct NativeSessionStatus {
    ready: bool,
    sid_expires_at: Option<i64>,
    last_verified_at: Option<i64>,
    last_beat_at: Option<i64>,
}

/// 原生登录状态必须来自可解密、可校验的会话快照，不能只看数据表是否存在一行。
async fn native_session_status(
    state: &AppState,
    account_id: &str,
) -> Result<NativeSessionStatus, sqlx::Error> {
    let native = db::load_native_session(&state.pool, &state.secret_box, account_id)
        .await
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let Some(native) = native else {
        return Ok(NativeSessionStatus {
            ready: false,
            sid_expires_at: None,
            last_verified_at: None,
            last_beat_at: None,
        });
    };
    let sid_expires_at = native.sid_expiry();
    Ok(NativeSessionStatus {
        ready: sid_expires_at.is_some_and(|expiry| expiry > Utc::now().timestamp()),
        sid_expires_at,
        last_verified_at: native.last_verified_at,
        last_beat_at: native.last_beat_at,
    })
}

/// 只读本地存储，不请求平台、不消费一次性发送凭证。
async fn local_im_history_status(
    state: &AppState,
    account: &Account,
    cookie: &str,
) -> Result<(&'static str, Option<i64>), sqlx::Error> {
    let encrypted: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
    )
    .bind(&account.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(encrypted) = encrypted else {
        return Ok(("MISSING", None));
    };
    let context = state.secret_box.decrypt(&encrypted).ok().and_then(|bytes| {
        serde_json::from_slice::<crate::douyin::im_auth::WebSessionContext>(&bytes).ok()
    });
    Ok(context.map_or(("INVALID", None), |context| {
        context.history_status(account.uid.as_deref(), cookie, Utc::now().timestamp())
    }))
}
pub async fn list_accounts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let accounts = db::list_accounts(&state.pool).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code": 500, "message": e.to_string()})),
        )
    })?;

    let mut dtos = Vec::with_capacity(accounts.len());
    for acc in accounts {
        let plaintext = state
            .secret_box
            .decrypt(&acc.encrypted_cookie)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();

        let targets = db::list_targets(&state.pool, Some(&acc.id))
            .await
            .unwrap_or_default();
        let total_targets = targets.len() as i64;
        let active_targets = targets.iter().filter(|t| t.is_enabled).count() as i64;
        let display_alias = acc.alias.clone();
        let (im_status, im_expires) = local_im_history_status(&state, &acc, &plaintext)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"message":"IM 凭证状态读取失败"})),
                )
            })?;
        let native = native_session_status(&state, &acc.id).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code":500,"message":"原生登录会话状态读取失败"})),
            )
        })?;
        // 历史 Web 上下文只在原生会话有效时才有意义。旧 Web Cookie 单独存在时
        // 不能继续对外显示 AVAILABLE，否则会让界面看起来仍然可以执行发送。
        let (im_status, im_expires) = if native.ready {
            (im_status, im_expires)
        } else {
            ("MISSING", None)
        };

        dtos.push(AccountDto {
            id: acc.id,
            alias: display_alias,
            sec_uid: acc.sec_uid,
            uid: acc.uid,
            nickname: acc.nickname,
            avatar_url: acc.avatar_url,
            native_ready: native.ready,
            native_sid_expires_at: native.sid_expires_at,
            native_last_verified_at: native.last_verified_at,
            native_last_beat_at: native.last_beat_at,
            status: acc.status,
            bark_key_override: acc.bark_key_override,
            targets_count: total_targets,
            active_targets_count: active_targets,
            im_history_status: im_status.into(),
            im_history_expires_at: im_expires,
            last_checked_at: acc.last_checked_at,
            created_at: acc.created_at,
            updated_at: acc.updated_at,
        });
    }

    Ok(Json(json!({
        "code": 200,
        "data": dtos
    })))
}
pub async fn get_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let acc = db::get_account(&state.pool, &id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code": 404, "message": "账号不存在"})),
            )
        })?;

    let plaintext = state
        .secret_box
        .decrypt(&acc.encrypted_cookie)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    let targets = db::list_targets(&state.pool, Some(&acc.id))
        .await
        .unwrap_or_default();
    let total_targets = targets.len() as i64;
    let active_targets = targets.iter().filter(|t| t.is_enabled).count() as i64;
    let (im_status, im_expires) = local_im_history_status(&state, &acc, &plaintext)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code":500,"message":"IM 凭证状态读取失败"})),
            )
        })?;
    let native = native_session_status(&state, &acc.id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code":500,"message":"原生登录会话状态读取失败"})),
        )
    })?;
    let (im_status, im_expires) = if native.ready {
        (im_status, im_expires)
    } else {
        ("MISSING", None)
    };

    let dto = AccountDto {
        id: acc.id,
        alias: acc.alias,
        sec_uid: acc.sec_uid,
        uid: acc.uid,
        nickname: acc.nickname,
        avatar_url: acc.avatar_url,
        native_ready: native.ready,
        native_sid_expires_at: native.sid_expires_at,
        native_last_verified_at: native.last_verified_at,
        native_last_beat_at: native.last_beat_at,
        status: acc.status,
        bark_key_override: acc.bark_key_override,
        targets_count: total_targets,
        active_targets_count: active_targets,
        im_history_status: im_status.into(),
        im_history_expires_at: im_expires,
        last_checked_at: acc.last_checked_at,
        created_at: acc.created_at,
        updated_at: acc.updated_at,
    };

    Ok(Json(json!({
        "code": 200,
        "data": dto
    })))
}

pub async fn update_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAccountReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    db::get_account(&state.pool, &id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code": 404, "message": "账号不存在"})),
            )
        })?;

    if let Some(alias) = req.alias.as_deref() {
        if !alias.trim().is_empty() {
            db::update_account(&state.pool, &id, Some(alias.trim()), None, None)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"code": 500, "message": e.to_string()})),
                    )
                })?;
        }
    }

    if let Some(status) = req.status.as_deref() {
        db::update_account(&state.pool, &id, None, Some(status), None)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code": 500, "message": e.to_string()})),
                )
            })?;
    }

    if let Some(bark_key) = req.bark_key_override {
        let key_opt = if bark_key.trim().is_empty() {
            None
        } else {
            Some(bark_key.trim())
        };
        db::update_account(&state.pool, &id, None, None, Some(key_opt))
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code": 500, "message": e.to_string()})),
                )
            })?;
    }

    Ok(Json(json!({
        "code": 200,
        "message": "账号更新成功"
    })))
}

pub async fn delete_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let login_ids = {
        let mut logins = state.logins.lock().await;
        let ids = logins
            .iter()
            .filter(|(_, session)| session.account_id == id)
            .map(|(login_id, _)| login_id.clone())
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|login_id| logins.remove(&login_id))
            .collect::<Vec<_>>()
    };
    for mut session in login_ids {
        session.shutdown().await;
    }
    db::delete_account(&state.pool, &id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code": 500, "message": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "code": 200,
        "message": "账号及关联目标已删除"
    })))
}

pub async fn check_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let account = db::get_account(&state.pool, &id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code": 404, "message": "账号不存在"})),
            )
        })?;

    tracing::info!(
        account_alias = %account.alias,
        "用户手动检测 App 原生会话，严格保持静默，不触发 Bark 推送"
    );
    let checked = match state.engine.check_native_account(&account, false).await {
        Ok(checked) => checked,
        Err(error) => {
            tracing::warn!(
                account_alias = %account.alias,
                error = %error,
                "App 原生会话检测异常，未清除现有账号状态"
            );
            crate::douyin::login::NativeCheck::Unconfirmed(
                "App 原生会话检测异常，保留现有登录态".to_string(),
            )
        }
    };
    let (is_valid, confirmed, check_state, message) = match checked {
        crate::douyin::login::NativeCheck::Valid(_) => (
            true,
            true,
            "valid",
            "抖音 App 原生会话有效，账号登录态已确认",
        ),
        crate::douyin::login::NativeCheck::Expired(reason) => {
            tracing::info!(account_alias = %account.alias, reason = %reason, "抖音明确返回登录会话失效");
            (
                false,
                true,
                "expired",
                "抖音明确返回登录会话失效，请重新扫码",
            )
        }
        crate::douyin::login::NativeCheck::Unconfirmed(reason) => {
            tracing::warn!(account_alias = %account.alias, reason = %reason, "抖音登录态本次未确认");
            let has_native = db::load_native_session(&state.pool, &state.secret_box, &account.id)
                .await
                .ok()
                .flatten()
                .is_some();
            (
                false,
                false,
                "unconfirmed",
                if has_native {
                    "本次未确认 App 原生登录态；网络、限流或协议异常不会清除现有会话"
                } else {
                    "当前账号尚未导入 App 原生会话；旧 Web Cookie 不能作为登录有效性的确认依据，请扫码或导入官方 Android 原生会话"
                },
            )
        }
    };

    let latest = db::get_account(&state.pool, &id)
        .await
        .unwrap_or(Some(account))
        .unwrap();

    Ok(Json(json!({
        "code": 200,
        "data": {
            "is_valid": is_valid,
            "confirmed": confirmed,
            "check_state": check_state,
            "status": latest.status,
            "nickname": latest.nickname,
            "avatar_url": latest.avatar_url,
            "last_checked_at": latest.last_checked_at,
        },
        "message": message
    })))
}

pub async fn sync_friends(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let account = db::get_account(&state.pool, &id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code": 404, "message": "账号不存在"})),
            )
        })?;

    let existing_targets = db::list_targets(&state.pool, Some(&account.id))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code":500,"message":e.to_string()})),
            )
        })?;
    // 在任何网络操作前撤销旧检测；请求失败也不能继续冒充刷新成功。
    for target in &existing_targets {
        db::record_target_today_state(&state.pool, &target.id, None, Utc::now())
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"message":e.to_string()})),
                )
            })?;
    }
    let plaintext = state
        .secret_box
        .decrypt(&account.encrypted_cookie)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": format!("解密失败: {e}")})),
            )
        })?;
    let cookie_str = String::from_utf8(plaintext).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code": 500, "message": "Cookie 无效"})),
        )
    })?;

    let client = DouyinClient::for_account(
        &state.pool,
        &state.secret_box,
        &account.id,
        &cookie_str,
        &account.alias,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": e.to_string()})),
        )
    })?;
    client
        .load_web_context(
            &state.pool,
            &state.secret_box,
            &account.id,
            account.uid.as_deref(),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"code":400,"message":"账号 Web 上下文无效，停止同步"})),
            )
        })?;

    let (uid, sec_uid) = match (&account.uid, &account.sec_uid) {
        (Some(u), Some(s)) => (u.as_str(), s.as_str()),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"code": 400, "message": "账号未完成初始化检测，缺少 UID / SecUID"})),
            ));
        }
    };

    if !client.check_cookie().await.is_valid() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"code":400,"message":"当前登录态未确认，已停止同步"})),
        ));
    }
    client.verified_sender_uid(Some(uid)).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"code":400,"message":"当前 Cookie 与账号不符，已停止同步"})),
        )
    })?;
    client.acquire_im_identity(Some(uid)).await.map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"code":400,"message":"IM 身份凭证获取失败，已停止同步，未自动重试"})),
        )
    })?;
    client
        .persist_im_session(
            &state.pool,
            &state.secret_box,
            &account.id,
            &account.encrypted_cookie,
            Some(uid),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::CONFLICT,
                Json(json!({"code":409,"message":"账号会话已变化或 IM 凭证保存失败，请重新同步"})),
            )
        })?;

    let mut friends = client
        .fetch_following_friends(uid, sec_uid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": format!("获取关注/好友列表失败: {e}")})),
            )
        })?;

    let my_uid_num: u64 = uid.parse().unwrap_or(0);
    let mut confirmed = 0;
    let history_available = client.im_history_status(account.uid.as_deref()).0 == "AVAILABLE";
    let target_count = existing_targets.len();
    for target in existing_targets {
        let matched_pos = friends.iter().position(|f| {
            if target.conversation_type == 2 {
                f.target_type == Some(2)
                    && (f.sec_uid == target.target_sec_uid
                        || target
                            .conversation_id
                            .as_deref()
                            .is_some_and(|cid| f.conversation_id.as_deref() == Some(cid)))
            } else {
                f.sec_uid == target.target_sec_uid
                    || target
                        .target_uid
                        .as_deref()
                        .filter(|id| !id.is_empty())
                        .is_some_and(|id| f.uid == id)
            }
        });
        if let Some(pos) = matched_pos {
            let matched = &friends[pos];
            let update_req = crate::model::UpdateTargetReq {
                conversation_type: None,
                is_enabled: None,
                target_nickname: Some(matched.nickname.clone()),
                remark_name: matched.remark_name.clone(),
                target_avatar: if matched.avatar_url.is_empty() {
                    None
                } else {
                    Some(matched.avatar_url.clone())
                },
                spark_days: matched.spark_days,
                spark_desc: matched.spark_desc.clone(),
                is_sparked_today: None,
                message_template: None,
            };
            db::update_target(&state.pool, &target.id, &update_req)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"code":500,"message":e.to_string()})),
                    )
                })?;
        }

        let checked_at = Utc::now();
        let today_sent = if crate::model::system_sent_today(
            target.last_status.as_deref(),
            target.last_sent_at,
            checked_at,
        ) {
            Some(true)
        } else if !history_available || client.risk_limited() || my_uid_num == 0 {
            None
        } else {
            let conv_id = if target.conversation_type == 2 {
                target
                    .conversation_id
                    .clone()
                    .unwrap_or_else(|| target.target_sec_uid.clone())
            } else if let Some(other) = target
                .target_uid
                .as_deref()
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id > 0)
            {
                format!("0:1:{}:{}", my_uid_num.min(other), my_uid_num.max(other))
            } else {
                String::new()
            };
            if conv_id.is_empty() {
                None
            } else {
                // 统一通过 cmd610 获取真实短 ID，不能把逻辑群 ID 猜成 short ID。
                match client
                    .check_i_sent_message_today(my_uid_num, &conv_id, target.conversation_type, 0)
                    .await
                {
                    Ok(sent) => Some(sent),
                    Err(_) => {
                        tracing::warn!(target_id = %target.id, "今日消息历史未确认，已清除旧检测状态");
                        None
                    }
                }
            }
        };
        db::record_target_today_state(&state.pool, &target.id, today_sent, checked_at)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"code":500,"message":e.to_string()})),
                )
            })?;
        if today_sent.is_some() {
            confirmed += 1;
        }
        if let Some(pos) = matched_pos {
            friends[pos].is_sparked_today = today_sent;
        }
    }
    let unconfirmed = target_count - confirmed;
    Ok(Json(json!({
        "code": 200,
        "data": friends,
        "today_status": { "confirmed": confirmed, "unconfirmed": unconfirmed, "im_history_status": client.im_history_status(account.uid.as_deref()).0 },
        "message": if unconfirmed > 0 {
            if !history_available {
                format!("资料已同步，{unconfirmed} 个目标未确认：IM 历史凭证缺失或过期，仅更新 Cookie 无法恢复续火")
            } else { format!("资料已同步，{unconfirmed} 个目标的今日发送状态未确认") }
        } else { format!("成功获取 {} 位好友/关注对象", friends.len()) }
    })))
}

pub async fn run_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let summary = state
        .engine
        .execute_single_account(&id, true, false)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "code": 200,
        "data": summary,
        "message": match summary.status {
            crate::scheduler::ExecutionStatus::Success => "账号续火花任务正常结束",
            crate::scheduler::ExecutionStatus::PartialFailed => "账号续火花任务部分失败",
            crate::scheduler::ExecutionStatus::Failed => "账号续火花任务执行失败",
        }
    })))
}
