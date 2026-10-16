use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde_json::json;

use crate::{
    crypto::mask_cookie,
    db,
    douyin::client::DouyinClient,
    model::{Account, AccountDto, CreateAccountReq, UpdateAccountReq},
    server::AppState,
};

/// 只读本地存储，不请求平台、不消费一次性发送凭证。
async fn local_im_history_status(state: &AppState, account: &Account, cookie: &str) -> Result<(&'static str, Option<i64>), sqlx::Error> {
    let encrypted: Option<Vec<u8>> = sqlx::query_scalar("SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1")
        .bind(&account.id).fetch_optional(&state.pool).await?;
    let Some(encrypted) = encrypted else { return Ok(("MISSING", None)); };
    let context = state.secret_box.decrypt(&encrypted).ok().and_then(|bytes|
        serde_json::from_slice::<crate::douyin::im_auth::WebSessionContext>(&bytes).ok());
    Ok(context.map_or(("INVALID", None), |context|
        context.history_status(account.uid.as_deref(), cookie, Utc::now().timestamp())))
}

pub async fn list_accounts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let accounts = db::list_accounts(&state.pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

    let mut dtos = Vec::with_capacity(accounts.len());
    for acc in accounts {
        let plaintext = state.secret_box.decrypt(&acc.encrypted_cookie)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        let masked = mask_cookie(&plaintext);

        let targets = db::list_targets(&state.pool, Some(&acc.id)).await.unwrap_or_default();
        let total_targets = targets.len() as i64;
        let active_targets = targets.iter().filter(|t| t.is_enabled).count() as i64;
        let display_alias = acc.alias.clone();
        let (im_status, im_expires) = local_im_history_status(&state, &acc, &plaintext).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":"IM 凭证状态读取失败"}))))?;

        dtos.push(AccountDto {
            id: acc.id,
            alias: display_alias,
            sec_uid: acc.sec_uid,
            uid: acc.uid,
            nickname: acc.nickname,
            avatar_url: acc.avatar_url,
            masked_cookie: masked,
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

pub async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie_raw = req.cookie.trim();
    if cookie_raw.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": "Cookie 不能为空"}))));
    }

    let (cleaned_cookie, guard_opt) = crate::douyin::client::parse_credential_payload(cookie_raw);
    if !cleaned_cookie.contains("sessionid=") && !cleaned_cookie.contains("sessionid_ss=") && !cleaned_cookie.contains("sid_tt=") {
        return Err((StatusCode::BAD_REQUEST, Json(json!({
            "code": 400,
            "message": "添加失败：Cookie 中缺少关键凭证 sessionid！由于浏览器 HttpOnly 安全限制，通过控制台 document.cookie 无法获取此凭证。请在 Network(网络) 标签页右键任意请求「复制为 cURL」后直接粘贴进来！"
        }))));
    }

    // Encrypt cookie before storing
    let encrypted = state.secret_box.encrypt(cleaned_cookie.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": format!("加密 Cookie 失败: {e}")}))))?;

    // Probe cookie validity immediately
    let initial_alias = if req.alias.trim().is_empty() { "抖音账号" } else { req.alias.trim() };
    let client = DouyinClient::new(&cleaned_cookie, initial_alias)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": format!("Cookie 格式无效: {e}")}))))?;
    let check_res = client.check_cookie().await;
    let (status, sec_uid, uid, nickname, avatar_url) = match check_res {
        crate::douyin::types::CheckCookieResult::Valid(profile) => (
            "ACTIVE".to_string(),
            Some(profile.sec_uid),
            Some(profile.uid),
            Some(profile.nickname),
            Some(profile.avatar_url),
        ),
        crate::douyin::types::CheckCookieResult::Expired(_)
        | crate::douyin::types::CheckCookieResult::NeedVerify(_)
        | crate::douyin::types::CheckCookieResult::NetworkError(_) => (
            "EXPIRED".to_string(),
            None,
            None,
            None,
            None,
        ),
    };

    // If alias is empty, automatically use Douyin nickname as alias
    let final_alias = if req.alias.trim().is_empty() {
        nickname.clone().unwrap_or_else(|| "抖音账号".to_string())
    } else {
        req.alias.trim().to_string()
    };

    let id = format!("acc_{}", uuid::Uuid::new_v4().simple());
    let account = Account {
        id: id.clone(),
        alias: final_alias,
        sec_uid,
        uid,
        nickname,
        avatar_url,
        encrypted_cookie: encrypted,
        status,
        bark_key_override: req.bark_key_override.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        last_checked_at: Some(Utc::now()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    db::insert_account(&state.pool, &account).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;
    if let (Some((priv_key, srv_data)), Some(u)) = (guard_opt, account.uid.as_deref()) {
        if let Ok(uid_num) = u.parse::<u64>() {
            if let Ok(mut ctx) = crate::douyin::im_auth::WebSessionContext::from_session(uid_num, &cleaned_cookie, crate::douyin::client::DEFAULT_USER_AGENT) {
                ctx.guard_secret_hex = Some(priv_key);
                ctx.guard_server_data = Some(srv_data);
                ctx.guard_acquired_at = Some(chrono::Utc::now().timestamp());
                if let Ok(enc_ctx) = state.secret_box.encrypt(&serde_json::to_vec(&ctx).unwrap_or_default()) {
                    sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
                        .bind(&id).bind(enc_ctx).execute(&state.pool).await.ok();
                }
            }
        }
    }

    Ok(Json(json!({
        "code": 200,
        "data": {
            "id": account.id,
            "alias": account.alias,
            "status": account.status,
            "nickname": account.nickname,
            "avatar_url": account.avatar_url,
            "masked_cookie": mask_cookie(cookie_raw),
        },
        "message": "账号创建成功"
    })))
}

pub async fn get_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let acc = db::get_account(&state.pool, &id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"code": 404, "message": "账号不存在"}))))?;

    let plaintext = state.secret_box.decrypt(&acc.encrypted_cookie)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let masked = mask_cookie(&plaintext);

    let targets = db::list_targets(&state.pool, Some(&acc.id)).await.unwrap_or_default();
    let total_targets = targets.len() as i64;
    let active_targets = targets.iter().filter(|t| t.is_enabled).count() as i64;
    let (im_status, im_expires) = local_im_history_status(&state, &acc, &plaintext).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":"IM 凭证状态读取失败"}))))?;

    let dto = AccountDto {
        id: acc.id,
        alias: acc.alias,
        sec_uid: acc.sec_uid,
        uid: acc.uid,
        nickname: acc.nickname,
        avatar_url: acc.avatar_url,
        masked_cookie: masked,
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
    let existing = db::get_account(&state.pool, &id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"code": 404, "message": "账号不存在"}))))?;

    if let Some(alias) = req.alias.as_deref() {
        if !alias.trim().is_empty() {
            db::update_account(&state.pool, &id, Some(alias.trim()), None, None).await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;
        }
    }

    if let Some(status) = req.status.as_deref() {
        db::update_account(&state.pool, &id, None, Some(status), None).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;
    }

    if let Some(bark_key) = req.bark_key_override {
        let key_opt = if bark_key.trim().is_empty() { None } else { Some(bark_key.trim()) };
        db::update_account(&state.pool, &id, None, None, Some(key_opt)).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;
    }

    if let Some(new_cookie) = req.cookie.as_deref() {
        let trimmed = new_cookie.trim();
        if !trimmed.is_empty() {
            let (cleaned_cookie, guard_opt) = crate::douyin::client::parse_credential_payload(trimmed);
            if !cleaned_cookie.contains("sessionid=") && !cleaned_cookie.contains("sessionid_ss=") && !cleaned_cookie.contains("sid_tt=") {
                return Err((StatusCode::BAD_REQUEST, Json(json!({
                    "code": 400,
                    "message": "更新失败：Cookie 中缺少关键凭证 sessionid！由于浏览器 HttpOnly 安全限制，请在 Network 面板右键任意请求「复制为 cURL」后粘贴。"
                }))));
            }
            let cleaned_cookie = validate_account_cookie(&state,&existing,&cleaned_cookie).await?;
            let encrypted = state.secret_box.encrypt(cleaned_cookie.as_bytes())
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": format!("加密 Cookie 失败: {e}")}))))?;
            db::update_account_cookie(&state.pool, &id, &encrypted).await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;
            if let (Some((priv_key, srv_data)), Some(u)) = (guard_opt, existing.uid.as_deref()) {
                if let Ok(uid_num) = u.parse::<u64>() {
                    let mut ctx = match sqlx::query_scalar::<_, Vec<u8>>("SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1")
                        .bind(&id).fetch_optional(&state.pool).await {
                        Ok(Some(bytes)) => state.secret_box.decrypt(&bytes).ok()
                            .and_then(|b| serde_json::from_slice::<crate::douyin::im_auth::WebSessionContext>(&b).ok())
                            .unwrap_or_else(|| crate::douyin::im_auth::WebSessionContext::from_session(uid_num, &cleaned_cookie, crate::douyin::client::DEFAULT_USER_AGENT).unwrap()),
                        _ => crate::douyin::im_auth::WebSessionContext::from_session(uid_num, &cleaned_cookie, crate::douyin::client::DEFAULT_USER_AGENT).unwrap(),
                    };
                    ctx.uid = uid_num;
                    ctx.session_hash = crate::douyin::im_auth::session_hash(&cleaned_cookie).unwrap_or_default();
                    ctx.guard_secret_hex = Some(priv_key);
                    ctx.guard_server_data = Some(srv_data);
                    ctx.guard_acquired_at = Some(chrono::Utc::now().timestamp());
                    if let Ok(enc_ctx) = state.secret_box.encrypt(&serde_json::to_vec(&ctx).unwrap_or_default()) {
                        sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
                            .bind(&id).bind(enc_ctx).execute(&state.pool).await.ok();
                    }
                }
            }

            let updated = db::get_account(&state.pool, &id).await.unwrap_or(Some(existing)).unwrap();
            state.engine.check_account_cookie(&updated).await.ok();
        }
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
    db::delete_account(&state.pool, &id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

    Ok(Json(json!({
        "code": 200,
        "message": "账号及关联目标已删除"
    })))
}

pub async fn check_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let account = db::get_account(&state.pool, &id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"code": 404, "message": "账号不存在"}))))?;

    let is_valid = state.engine.check_account_cookie(&account).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

    let latest = db::get_account(&state.pool, &id).await.unwrap_or(Some(account)).unwrap();

    Ok(Json(json!({
        "code": 200,
        "data": {
            "is_valid": is_valid,
            "status": latest.status,
            "nickname": latest.nickname,
            "avatar_url": latest.avatar_url,
            "last_checked_at": latest.last_checked_at,
        },
        "message": if is_valid { "Cookie 有效，个人信息已同步" } else { "登录态检查未通过，请查看日志；网络或协议异常不会直接判定失效" }
    })))
}

pub async fn sync_friends(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let account = db::get_account(&state.pool, &id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"code": 404, "message": "账号不存在"}))))?;

    let existing_targets = db::list_targets(&state.pool, Some(&account.id)).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":e.to_string()}))))?;
    // 在任何网络操作前撤销旧检测；请求失败也不能继续冒充刷新成功。
    for target in &existing_targets {
        db::record_target_today_state(&state.pool, &target.id, None, Utc::now()).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":e.to_string()}))))?;
    }
    let plaintext = state.secret_box.decrypt(&account.encrypted_cookie)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": format!("解密失败: {e}")}))))?;
    let cookie_str = String::from_utf8(plaintext)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": "Cookie 无效"}))))?;

    let client = DouyinClient::new(&cookie_str, &account.alias)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": e.to_string()}))))?;
    client.load_web_context(&state.pool,&state.secret_box,&account.id,account.uid.as_deref()).await
        .map_err(|_| (StatusCode::BAD_REQUEST,Json(json!({"code":400,"message":"账号 Web 上下文无效，停止同步"}))))?;

    let (uid, sec_uid) = match (&account.uid, &account.sec_uid) {
        (Some(u), Some(s)) => (u.as_str(), s.as_str()),
        _ => return Err((StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": "账号未完成初始化检测，缺少 UID / SecUID"})))),
    };

    if !client.check_cookie().await.is_valid() {
        return Err((StatusCode::BAD_REQUEST,Json(json!({"code":400,"message":"当前登录态未确认，已停止同步"}))));
    }
    client.verified_sender_uid(Some(uid)).map_err(|_| (StatusCode::BAD_REQUEST,Json(json!({"code":400,"message":"当前 Cookie 与账号不符，已停止同步"}))))?;
    client.acquire_im_identity(Some(uid)).await.map_err(|_| (StatusCode::BAD_REQUEST,Json(json!({"code":400,"message":"IM 身份凭证获取失败，已停止同步，未自动重试"}))))?;
    client.persist_im_session(&state.pool,&state.secret_box,&account.id,&account.encrypted_cookie,Some(uid)).await
        .map_err(|_| (StatusCode::CONFLICT,Json(json!({"code":409,"message":"账号会话已变化或 IM 凭证保存失败，请重新同步"}))))?;

    let mut friends = client.fetch_following_friends(uid, sec_uid).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": format!("获取关注/好友列表失败: {e}")}))))?;

    let my_uid_num: u64 = uid.parse().unwrap_or(0);
    let mut confirmed = 0;
    let history_available = client.im_history_status(account.uid.as_deref()).0 == "AVAILABLE";
    let target_count = existing_targets.len();
    for target in existing_targets {
        let matched_pos = friends.iter().position(|f| {
            if target.conversation_type == 2 {
                f.target_type == Some(2) && (f.sec_uid == target.target_sec_uid
                    || target.conversation_id.as_deref().is_some_and(|cid| f.conversation_id.as_deref() == Some(cid)))
            } else {
                f.sec_uid == target.target_sec_uid
                    || target.target_uid.as_deref().filter(|id| !id.is_empty()).is_some_and(|id| f.uid == id)
            }
        });
        if let Some(pos) = matched_pos {
            let matched = &friends[pos];
            let update_req = crate::model::UpdateTargetReq {
                conversation_type: None, is_enabled: None,
                target_nickname: Some(matched.nickname.clone()),
                remark_name: matched.remark_name.clone(),
                target_avatar: if matched.avatar_url.is_empty() { None } else { Some(matched.avatar_url.clone()) },
                spark_days: matched.spark_days, spark_desc: matched.spark_desc.clone(),
                is_sparked_today: None, message_template: None,
            };
            db::update_target(&state.pool, &target.id, &update_req).await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":e.to_string()}))))?;
        }

        let checked_at = Utc::now();
        let today_sent = if crate::model::system_sent_today(target.last_status.as_deref(), target.last_sent_at, checked_at) {
            Some(true)
        } else if !history_available || client.risk_limited() || my_uid_num == 0 {
            None
        } else {
            let conv_id = if target.conversation_type == 2 {
                target.conversation_id.clone().unwrap_or_else(|| target.target_sec_uid.clone())
            } else if let Some(other) = target.target_uid.as_deref().and_then(|id| id.parse::<u64>().ok()).filter(|id| *id > 0) {
                format!("0:1:{}:{}", my_uid_num.min(other), my_uid_num.max(other))
            } else {
                String::new()
            };
            if conv_id.is_empty() { None } else {
                // 统一通过 cmd610 获取真实短 ID，不能把逻辑群 ID 猜成 short ID。
                match client.check_i_sent_message_today(my_uid_num, &conv_id, target.conversation_type, 0).await {
                    Ok(sent) => Some(sent),
                    Err(_) => {
                        tracing::warn!(target_id = %target.id, "今日消息历史未确认，已清除旧检测状态");
                        None
                    }
                }
            }
        };
        db::record_target_today_state(&state.pool, &target.id, today_sent, checked_at).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":e.to_string()}))))?;
        if today_sent.is_some() { confirmed += 1; }
        if let Some(pos) = matched_pos { friends[pos].is_sparked_today = today_sent; }
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
    let summary = state.engine.execute_single_account(&id, true).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

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

#[derive(serde::Deserialize)]
pub struct SyncBrowserReq {
    pub cookie: String,
}

pub async fn sync_from_browser(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SyncBrowserReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean = req.cookie.trim();
    if clean.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"code": 400, "message": "Cookie 内容不能为空"}))));
    }

    let (cleaned_cookie, guard_opt) = crate::douyin::client::parse_credential_payload(clean);
    if !cleaned_cookie.contains("sessionid=") && !cleaned_cookie.contains("sessionid_ss=") && !cleaned_cookie.contains("sid_tt=") {
        return Err((StatusCode::BAD_REQUEST, Json(json!({
            "code": 400,
            "message": "同步失败：Cookie 中缺少关键凭证 sessionid！请使用右侧「油猴全自动脚本」在抖音网页端一键复制全量凭证后粘贴。"
        }))));
    }

    let account=db::get_account(&state.pool,&id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"code":500,"message":"账号查询失败"}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND,Json(json!({"code":404,"message":"账号不存在"}))))?;
    let expected_uid = account.uid.as_deref().filter(|uid| uid.parse::<u64>().is_ok_and(|id| id > 0))
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(json!({"code":400,"message":"账号身份尚未绑定，未同步"}))))?;
    let client = DouyinClient::new(&cleaned_cookie, &account.alias)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({"code":400,"message":"浏览器会话格式无效"}))))?;
    client.sync_browser_session(&state.pool, &state.secret_box, &id, &account.encrypted_cookie, expected_uid).await
        .map_err(|_| (StatusCode::CONFLICT, Json(json!({"code":409,"message":"浏览器会话或 IM 身份验证失败，或账号已被更新；原会话未覆盖，未发送且未重试"}))))?;
    if let (Some((priv_key, srv_data)), Some(u)) = (guard_opt, account.uid.as_deref()) {
        if let Ok(uid_num) = u.parse::<u64>() {
            if let Ok(mut ctx) = crate::douyin::im_auth::WebSessionContext::from_session(uid_num, &cleaned_cookie, crate::douyin::client::DEFAULT_USER_AGENT) {
                ctx.guard_secret_hex = Some(priv_key);
                ctx.guard_server_data = Some(srv_data);
                ctx.guard_acquired_at = Some(chrono::Utc::now().timestamp());
                if let Ok(enc_ctx) = state.secret_box.encrypt(&serde_json::to_vec(&ctx).unwrap_or_default()) {
                    sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
                        .bind(&id).bind(enc_ctx).execute(&state.pool).await.ok();
                }
            }
        }
    }
    let history = client.im_history_status(Some(expected_uid));
    Ok(Json(json!({
        "code": 200,
        "message": "浏览器会话与 IM 身份已同步；尚无发送授权，未发送消息",
        "data": {"im_history_status":history.0,"im_history_expires_at":history.1,"send_authorization_status":"MISSING","send_requests":0}
    })))
}

#[derive(serde::Deserialize)]
pub struct ImportImCredentialReq {
    pub captured_at: i64,
    pub cookie: String,
    pub body: Vec<u8>,
    pub user_agent: String,
    pub headers: std::collections::BTreeMap<String, String>,
}

/// 仅导入当前账号官方浏览器签发的发送凭证；此接口不发送消息。
pub async fn import_im_credential(
    State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<ImportImCredentialReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let bad = |message: String| (StatusCode::BAD_REQUEST, Json(json!({"code":400,"message":message})));
    let internal = |_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code":500,"message":"IM 凭证加密保存失败"})));
    let account = db::get_account(&state.pool, &id).await.map_err(|_| bad("账号查询失败".into()))?
        .ok_or_else(|| bad("账号不存在".into()))?;
    let expected_uid = account.uid.as_deref().and_then(|uid| uid.parse::<u64>().ok()).filter(|uid| *uid > 0)
        .ok_or_else(|| bad("账号缺少有效 UID，禁止导入".into()))?;
    let cookie = crate::douyin::client::extract_clean_cookie(&req.cookie);
    let mut credential = crate::douyin::im_auth::ImSendCredential::from_capture(expected_uid, &cookie, req.body, req.user_agent, req.headers)
        .map_err(|e| bad(e.to_string()))?;
    credential.captured_at = req.captured_at;
    credential.validate(expected_uid, &cookie, &credential.conversation_id, credential.conversation_type).map_err(|e| bad(e.to_string()))?;
    let client = DouyinClient::new(&cookie, &account.alias).map_err(|_| bad("Cookie 格式无效".into()))?;
    let context = crate::douyin::im_auth::WebSessionContext::from_credential(&credential);
    client.set_web_context(context.clone()).map_err(|_| bad("Web 上下文无效".into()))?;
    match client.check_cookie().await {
        crate::douyin::types::CheckCookieResult::Valid(profile) if profile.uid == expected_uid.to_string() => {},
        _ => return Err(bad("当前 Cookie 无效、需安全验证或身份不符，未保存任何凭证".into())),
    }
    let cookie=client.get_current_cookie();
    credential.validate(expected_uid,&cookie,&credential.conversation_id,credential.conversation_type).map_err(|e| bad(e.to_string()))?;
    let encrypted_cookie = state.secret_box.encrypt(cookie.as_bytes()).map_err(internal)?;
    let encoded = serde_json::to_vec(&credential).map_err(|_| bad("IM 凭证编码失败".into()))?;
    let encrypted = state.secret_box.encrypt(&encoded).map_err(internal)?;
    let encrypted_context = state.secret_box.encrypt(&serde_json::to_vec(&context).map_err(|_| bad("Web 上下文编码失败".into()))?).map_err(internal)?;
    let mut transaction = state.pool.begin().await.map_err(|_| bad("无法保存 IM 凭证".into()))?;
    sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1").bind(&id).execute(&mut *transaction).await.map_err(|_| bad("无法清理旧 IM 凭证".into()))?;
    sqlx::query("INSERT INTO account_im_credentials(account_id, conversation_id, encrypted_credential) VALUES(?1,?2,?3) ON CONFLICT(account_id,conversation_id) DO UPDATE SET encrypted_credential=excluded.encrypted_credential")
        .bind(&id).bind(&credential.conversation_id).bind(encrypted).execute(&mut *transaction).await.map_err(|_| bad("无法保存 IM 凭证".into()))?;
    sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
        .bind(&id).bind(encrypted_context).execute(&mut *transaction).await.map_err(|_| bad("无法保存 Web 上下文".into()))?;
    sqlx::query("UPDATE accounts SET encrypted_cookie=?1,status='ACTIVE',last_checked_at=?2,updated_at=?2 WHERE id=?3")
        .bind(encrypted_cookie).bind(Utc::now().to_rfc3339()).bind(&id).execute(&mut *transaction).await.map_err(|_| bad("无法保存账号凭证".into()))?;
    transaction.commit().await.map_err(|_| bad("无法提交 IM 凭证".into()))?;
    Ok(Json(json!({"code":200,"message":"官方 IM 凭证已加密保存，未发送消息","data":{"uid":expected_uid.to_string(),"conversation_id":credential.conversation_id,"short_id":credential.short_id.to_string()}})))
}

async fn validate_account_cookie(state: &AppState, account: &Account, cookie: &str) -> Result<String,(StatusCode,Json<serde_json::Value>)> {
    let bad=|message:&str| (StatusCode::BAD_REQUEST,Json(json!({"code":400,"message":message})));
    let client=DouyinClient::new(cookie,&account.alias).map_err(|_| bad("Cookie 格式无效"))?;
    client.load_web_context(&state.pool,&state.secret_box,&account.id,account.uid.as_deref()).await.map_err(|_| bad("Web 上下文加载失败"))?;
    let checked=client.check_cookie().await;
    if !checked.is_valid() { return Err(bad(checked.error_message().unwrap_or("会话检测失败，未保存 Cookie"))); }
    client.verified_sender_uid(account.uid.as_deref()).map_err(|_| bad("Cookie 不属于当前账号，未保存"))?;
    Ok(client.get_current_cookie())
}
