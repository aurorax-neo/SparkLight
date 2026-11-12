use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::{
    db,
    douyin::{
        client::{DouyinClient, DouyinTargetParam},
        types::{DouyinFriend, SparkConversationInfo},
    },
    model::{Account, CreateTargetReq, SparkTarget, UpdateTargetReq},
    server::AppState,
    template::{self, SparkTemplateItem},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

const ACCOUNT_BATCH_CACHE_TTL: Duration = Duration::from_secs(12);

fn internal_err(e: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"code": 500, "message": e.to_string()})),
    )
}

struct CachedAccountBatch {
    client: Arc<DouyinClient>,
    uid: u64,
    spark_map: HashMap<String, SparkConversationInfo>,
    fetched_at: Instant,
}

fn account_refresh_locks() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn account_batch_cache() -> &'static Mutex<HashMap<String, CachedAccountBatch>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedAccountBatch>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_account_refresh_lock(account_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = account_refresh_locks().lock().unwrap();
    locks
        .entry(account_id.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

#[derive(Deserialize)]
pub struct ListTargetsQuery {
    pub account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchTargetItem {
    #[serde(default)]
    target_sec_uid: String,
    #[serde(default)]
    target_uid: Option<String>,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default)]
    conversation_type: Option<i32>,
    #[serde(default)]
    target_nickname: String,
    #[serde(default)]
    target_avatar: Option<String>,
    #[serde(default)]
    spark_days: Option<i32>,
    #[serde(default)]
    spark_desc: Option<String>,
    #[serde(default)]
    message_template: Option<String>,
}

#[derive(Deserialize)]
pub struct BatchCreateTargetsReq {
    pub account_id: String,
    pub targets: Vec<BatchTargetItem>,
}

pub async fn list_targets(
    State(state): State<AppState>,
    Query(query): Query<ListTargetsQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let targets = db::list_targets(&state.pool, query.account_id.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "code": 200,
        "data": targets
    })))
}

pub async fn create_target(
    State(state): State<AppState>,
    Json(req): Json<CreateTargetReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let account = db::get_account(&state.pool, &req.account_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"code": 400, "message": "所属账号不存在"})),
            )
        })?;

    let sec_uid = req.target_sec_uid.trim().to_string();
    if sec_uid.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": "好友 SecUID 不能为空"})),
        ));
    }
    let existing_all = db::list_targets(&state.pool, Some(&account.id))
        .await
        .unwrap_or_default();
    if let Some(prev) = existing_all.iter().find(|t| {
        t.target_sec_uid == sec_uid
            || (req.target_uid.as_deref().is_some()
                && t.target_uid.as_deref() == req.target_uid.as_deref())
    }) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({"code": 400, "message": format!("该目标已存在（{}），已以 UID 去重", prev.target_nickname)}),
            ),
        ));
    }

    let conv_type = req.conversation_type.unwrap_or(1);
    let mut nickname = req.target_nickname.trim().to_string();
    let mut remark_name: Option<String> = None;
    let mut avatar = trimmed_opt(req.target_avatar);
    let mut spark_days = req.spark_days.unwrap_or(0);
    let mut spark_desc = req.spark_desc.clone();
    let mut target_uid = trimmed_opt(req.target_uid);
    let mut conversation_id = trimmed_opt(req.conversation_id);
    let mut conversation_type = conv_type;

    if let Some(live) = find_live_friend(
        &state,
        &account,
        &sec_uid,
        target_uid.as_deref(),
        conversation_id.as_deref(),
        conversation_type,
    )
    .await
    {
        apply_live_friend(
            &live,
            &mut nickname,
            &mut remark_name,
            &mut avatar,
            &mut spark_days,
            &mut spark_desc,
            &mut target_uid,
            &mut conversation_id,
            &mut conversation_type,
        );
    }

    if nickname.is_empty() {
        nickname = probe_nickname(&state, &account, &sec_uid)
            .await
            .unwrap_or_else(|| "抖音好友".to_string());
    }

    let id = format!("tgt_{}", uuid::Uuid::new_v4().simple());
    let target = SparkTarget {
        id: id.clone(),
        account_id: account.id,
        target_sec_uid: sec_uid,
        target_uid,
        conversation_id,
        conversation_type,
        target_nickname: nickname,
        remark_name,
        target_avatar: avatar,
        is_enabled: true,
        spark_days,
        spark_desc,
        // 客户端提交的火花状态不是当前账号今日发送的证据。
        is_sparked_today: None,
        today_checked_at: None,
        message_template: match req.message_template.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            Some(tpl) => tpl,
            None => db::get_setting(&state.pool, "spark_default_template")
                .await
                .ok()
                .flatten()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "🔥".to_string()),
        },
        last_sent_at: None,
        last_status: None,
        last_error: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    db::insert_target(&state.pool, &target).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code": 500, "message": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "code": 200,
        "data": target,
        "message": "续火花目标添加成功"
    })))
}

pub async fn batch_create_targets(
    State(state): State<AppState>,
    Json(req): Json<BatchCreateTargetsReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let account = db::get_account(&state.pool, &req.account_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"code": 400, "message": "所属账号不存在"})),
            )
        })?;

    let existing = db::list_targets(&state.pool, Some(&account.id))
        .await
        .unwrap_or_default();
    let live_friends = load_live_friends(&state, &account).await;
    let default_template = db::get_setting(&state.pool, "spark_default_template")
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "🔥".to_string());

    let mut added_count = 0;
    let mut skipped_count = 0;
    let mut failed_count = 0;
    for t_req in req.targets {
        let sec_uid = t_req.target_sec_uid.trim().to_string();
        if sec_uid.is_empty() {
            failed_count += 1;
            continue;
        }
        let matched_existing = existing.iter().find(|t| {
            t.target_sec_uid == sec_uid
                || (t_req.target_uid.as_deref().is_some()
                    && t.target_uid.as_deref() == t_req.target_uid.as_deref())
        });
        if let Some(prev) = matched_existing {
            if !t_req.target_nickname.trim().is_empty() {
                let mut days = t_req.spark_days;
                let mut desc = t_req.spark_desc.clone();
                if let Some(live) = live_friends.iter().find(|f| {
                    friend_matches(
                        &sec_uid,
                        t_req.target_uid.as_deref(),
                        t_req.conversation_id.as_deref(),
                        t_req.conversation_type.unwrap_or(1),
                        f,
                    )
                }) {
                    days = live.spark_days;
                    desc = live.spark_desc.clone();
                }
                let update_req = crate::model::UpdateTargetReq {
                    conversation_type: None,
                    is_enabled: None,
                    target_nickname: Some(t_req.target_nickname.trim().to_string()),
                    remark_name: live_friends
                        .iter()
                        .find(|f| {
                            friend_matches(
                                &sec_uid,
                                t_req.target_uid.as_deref(),
                                t_req.conversation_id.as_deref(),
                                t_req.conversation_type.unwrap_or(1),
                                f,
                            )
                        })
                        .and_then(|l| l.remark_name.clone()),
                    target_avatar: trimmed_opt(t_req.target_avatar).or_else(|| {
                        live_friends
                            .iter()
                            .find(|f| {
                                friend_matches(
                                    &sec_uid,
                                    t_req.target_uid.as_deref(),
                                    t_req.conversation_id.as_deref(),
                                    t_req.conversation_type.unwrap_or(1),
                                    f,
                                )
                            })
                            .map(|l| l.avatar_url.clone())
                    }),
                    spark_days: days,
                    spark_desc: desc,
                    is_sparked_today: None,
                    message_template: None,
                };
                db::update_target(&state.pool, &prev.id, &update_req)
                    .await
                    .ok();
            }
            skipped_count += 1;
            continue;
        }

        let mut conversation_type = t_req.conversation_type.unwrap_or(1);
        let mut nickname = t_req.target_nickname.trim().to_string();
        let mut remark_name = None;
        let mut avatar = trimmed_opt(t_req.target_avatar);
        let mut spark_days = t_req.spark_days.unwrap_or(0);
        let mut spark_desc = t_req.spark_desc.clone();
        let mut target_uid = trimmed_opt(t_req.target_uid);
        let mut conversation_id = trimmed_opt(t_req.conversation_id);
        if let Some(live) = live_friends.iter().find(|f| {
            friend_matches(
                &sec_uid,
                target_uid.as_deref(),
                conversation_id.as_deref(),
                conversation_type,
                f,
            )
        }) {
            apply_live_friend(
                live,
                &mut nickname,
                &mut remark_name,
                &mut avatar,
                &mut spark_days,
                &mut spark_desc,
                &mut target_uid,
                &mut conversation_id,
                &mut conversation_type,
            );
        }
        if nickname.is_empty() {
            nickname = "抖音好友".to_string();
        }

        let target = SparkTarget {
            id: format!("tgt_{}", uuid::Uuid::new_v4().simple()),
            account_id: account.id.clone(),
            target_sec_uid: sec_uid,
            target_uid,
            conversation_id,
            conversation_type,
            target_nickname: nickname,
            remark_name,
            target_avatar: avatar,
            is_enabled: true,
            spark_days,
            spark_desc,
            is_sparked_today: None,
            today_checked_at: None,
            message_template: t_req
                .message_template
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default_template.clone()),
            last_sent_at: None,
            last_status: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        if db::insert_target(&state.pool, &target).await.is_ok() {
            added_count += 1;
        } else {
            failed_count += 1;
        }
    }

    let message = if added_count == 0 && skipped_count > 0 && failed_count == 0 {
        "所选好友已在续火花列表中，未重复添加".to_string()
    } else if added_count == 0 && failed_count > 0 {
        "添加失败，请稍后重试".to_string()
    } else {
        format!("已添加 {added_count} 个，跳过已存在 {skipped_count} 个")
    };

    Ok(Json(json!({
        "code": 200,
        "added_count": added_count,
        "skipped_count": skipped_count,
        "message": message
    })))
}

pub async fn update_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateTargetReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let req = UpdateTargetReq {
        is_sparked_today: None,
        ..req
    };
    db::update_target(&state.pool, &id, &req)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "code": 200,
        "message": "续火花目标更新成功"
    })))
}

pub async fn delete_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    db::delete_target(&state.pool, &id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code": 500, "message": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "code": 200,
        "message": "目标已删除"
    })))
}

pub async fn get_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let target = db::get_target(&state.pool, &id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code":500,"message":"目标读取失败"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code":404,"message":"目标不存在"})),
            )
        })?;
    Ok(Json(json!({"code":200,"data":target})))
}

/// 只更新当前目标，不同步好友列表，也不修改同账号其他目标。
pub async fn refresh_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let internal = |_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"code":500,"message":"目标刷新失败"})),
        )
    };
    let target = db::get_target(&state.pool, &id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code":404,"message":"目标不存在"})),
            )
        })?;
    let account = db::get_account(&state.pool, &target.account_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code":404,"message":"所属账号不存在"})),
            )
        })?;
    let checked_at = Utc::now();
    let system_sent = crate::model::system_sent_today(
        target.last_status.as_deref(),
        target.last_sent_at,
        checked_at,
    );
    db::record_target_today_state(&state.pool, &id, system_sent.then_some(true), checked_at)
        .await
        .map_err(internal)?;
    let result = refresh_target_history(&state, &account, &target).await;
    let completed_at = Utc::now();
    let current = db::get_target(&state.pool, &id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"code":404,"message":"目标已删除"})),
            )
        })?;
    let sent = refreshed_today_state(
        &current,
        checked_at,
        completed_at,
        result.as_ref().ok().copied(),
    );
    let message = match result {
        Ok(_) => "当前目标的火花与今日发送状态已更新",
        Err(message) => message,
    };
    db::record_target_today_state(&state.pool, &id, sent, completed_at)
        .await
        .map_err(internal)?;
    let latest = db::get_target(&state.pool, &id).await.map_err(internal)?;
    let account_status = match sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT encrypted_context FROM account_web_contexts WHERE account_id=?1",
    )
    .bind(&account.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| internal(anyhow::Error::from(e)))?
    {
        Some(bytes) => state
            .secret_box
            .decrypt(&bytes)
            .ok()
            .and_then(|b| {
                serde_json::from_slice::<crate::douyin::im_auth::WebSessionContext>(&b).ok()
            })
            .map(|c| {
                let cookie = state
                    .secret_box
                    .decrypt(&account.encrypted_cookie)
                    .ok()
                    .and_then(|v| String::from_utf8(v).ok())
                    .unwrap_or_default();
                c.history_status(account.uid.as_deref(), &cookie, completed_at.timestamp())
            })
            .unwrap_or(("INVALID", None)),
        None => ("MISSING", None),
    };
    Ok(Json(
        json!({"code":200,"data":latest,"confirmed":sent.is_some(),"message":message,
        "im_history_status":account_status.0,"im_history_expires_at":account_status.1}),
    ))
}

fn refreshed_today_state(
    target: &SparkTarget,
    started: chrono::DateTime<Utc>,
    completed: chrono::DateTime<Utc>,
    history: Option<bool>,
) -> Option<bool> {
    if crate::model::system_sent_today(
        target.last_status.as_deref(),
        target.last_sent_at,
        completed,
    ) {
        return Some(true);
    }
    let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    if started.with_timezone(&cst).date_naive() != completed.with_timezone(&cst).date_naive() {
        return None;
    }
    history
}

async fn refresh_target_history(
    state: &AppState,
    account: &Account,
    target: &SparkTarget,
) -> Result<bool, &'static str> {
    if account.status != "ACTIVE" {
        return Err("所属账号未启用，未查询当前目标");
    }
    let account_lock = get_account_refresh_lock(&account.id);
    let (client, uid, conversation, info) = {
        let _guard = account_lock.lock().await;
        let expected_uid = account
            .uid
            .as_deref()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .ok_or("当前账号身份不符，已停止刷新")?;
        let conversation = if target.conversation_type == 2 {
            target
                .conversation_id
                .clone()
                .unwrap_or_else(|| target.target_sec_uid.clone())
        } else {
            let other = target
                .target_uid
                .as_deref()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0 && *v != expected_uid)
                .ok_or("当前目标缺少有效会话身份")?;
            let cid = format!("0:1:{}:{}", expected_uid.min(other), expected_uid.max(other));
            if target
                .conversation_id
                .as_deref()
                .is_some_and(|stored| stored != cid)
            {
                return Err("当前目标会话与账号不符");
            }
            cid
        };

        let cached = if !cfg!(test) {
            account_batch_cache()
                .lock()
                .unwrap()
                .get(&account.id)
                .and_then(|entry| {
                    if entry.fetched_at.elapsed() < ACCOUNT_BATCH_CACHE_TTL
                        && entry.uid == expected_uid
                    {
                        entry
                            .spark_map
                            .get(&conversation)
                            .cloned()
                            .map(|info| (entry.client.clone(), entry.uid, info))
                    } else {
                        None
                    }
                })
        } else {
            None
        };

        if let Some((client, uid, info)) = cached {
            (client, uid, conversation, info)
        } else {
            let fresh_account = db::get_account(&state.pool, &account.id)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| account.clone());
            if fresh_account.status != "ACTIVE" {
                return Err("所属账号未启用，未查询当前目标");
            }
            let cookie = state
                .secret_box
                .decrypt(&fresh_account.encrypted_cookie)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or("账号 Cookie 无法读取，未查询当前目标")?;
            let client = Arc::new(
                DouyinClient::for_account(
                    &state.pool,
                    &state.secret_box,
                    &fresh_account.id,
                    &cookie,
                    &fresh_account.alias,
                )
                .await
                .map_err(|_| "账号会话无法初始化")?,
            );
            client
                .load_web_context(
                    &state.pool,
                    &state.secret_box,
                    &fresh_account.id,
                    fresh_account.uid.as_deref(),
                )
                .await
                .map_err(|_| "IM 凭证无效，当前目标今日状态未确认")?;
            if !client.check_cookie().await.is_valid() {
                return Err("当前账号登录态未确认，已停止刷新");
            }
            let uid = client
                .verified_sender_uid(fresh_account.uid.as_deref())
                .map_err(|_| "当前账号身份不符，已停止刷新")?;
            client
                .acquire_im_identity(fresh_account.uid.as_deref())
                .await
                .map_err(|_| "IM 身份凭证获取失败，已停止当前目标刷新，未自动重试")?;
            client
                .persist_im_session(
                    &state.pool,
                    &state.secret_box,
                    &fresh_account.id,
                    &fresh_account.encrypted_cookie,
                    fresh_account.uid.as_deref(),
                )
                .await
                .map_err(|_| "账号会话已变化或 IM 凭证保存失败，请重新刷新当前目标")?;

            let mut batch_params = vec![DouyinTargetParam {
                conv_id: conversation.clone(),
                conv_type: target.conversation_type,
                short_id: None,
            }];
            if !cfg!(test)
                && let Ok(account_targets) = db::list_targets(&state.pool, Some(&fresh_account.id)).await
            {
                for sibling in account_targets {
                    let sib_cid = if sibling.conversation_type == 2 {
                        sibling
                            .conversation_id
                            .clone()
                            .unwrap_or_else(|| sibling.target_sec_uid.clone())
                    } else if let Some(other) = sibling
                        .target_uid
                        .as_deref()
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|v| *v > 0 && *v != uid)
                    {
                        format!("0:1:{}:{}", uid.min(other), uid.max(other))
                    } else {
                        continue;
                    };
                    if !batch_params.iter().any(|p| p.conv_id == sib_cid) {
                        batch_params.push(DouyinTargetParam {
                            conv_id: sib_cid,
                            conv_type: sibling.conversation_type,
                            short_id: None,
                        });
                    }
                }
            }
            let mut spark_map = client
                .fetch_available_conversation_spark_status(&batch_params)
                .await
                .map_err(|_| "当前目标火花状态查询失败，未刷新其他目标")?;
            let info = spark_map
                .get(&conversation)
                .cloned()
                .or_else(|| spark_map.remove(&conversation))
                .ok_or("未返回当前目标会话，保留火花数据")?;
            if !cfg!(test) {
                account_batch_cache().lock().unwrap().insert(
                    fresh_account.id.clone(),
                    CachedAccountBatch {
                        client: client.clone(),
                        uid,
                        spark_map,
                        fetched_at: Instant::now(),
                    },
                );
            }
            (client, uid, conversation, info)
        }
    };

    let remark_opt = if target.conversation_type == 1 {
        let other = target
            .target_uid
            .as_deref()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        info.aliases
            .iter()
            .find(|(u, _)| *u == other)
            .map(|(_, a)| a.clone())
    } else {
        None
    };
    db::update_target(
        &state.pool,
        &target.id,
        &UpdateTargetReq {
            target_nickname: None,
            remark_name: remark_opt,
            is_enabled: None,
            conversation_type: None,
            target_avatar: None,
            spark_days: Some(info.days),
            spark_desc: Some(info.desc),
            is_sparked_today: None,
            message_template: None,
        },
    )
    .await
    .map_err(|_| "当前目标火花数据保存失败")?;
    client
        .check_i_sent_message_today(uid, &conversation, target.conversation_type, info.short_id)
        .await
        .map_err(|_| "当前目标消息历史未确认完整，未刷新其他目标")
}

pub async fn test_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let result = state
        .engine
        .execute_single_target(&id, false)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?;

    let is_already_sent =
        result.message.contains("今日已确认发送") || result.message.contains("今日已发送");
    let is_pending = result.is_pending();
    let display_success = result.success || is_already_sent;
    let message = if result.success {
        "火花互动测试成功"
    } else if is_pending {
        "服务端已接收，正在等待抖音消息历史同步"
    } else if is_already_sent {
        "今日火花已在抖音点亮，无需重复续火"
    } else {
        "火花互动测试未成功"
    };

    Ok(Json(json!({
        "code": 200,
        "data": {
            "success": display_success,
            "state": result.state,
            "pending": is_pending,
            "message": result.message,
            "spark_days": result.spark_days,
            "raw_response": result.raw_response,
        },
        "message": message
    })))
}

fn trimmed_opt(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn friend_matches(
    sec_uid: &str,
    uid: Option<&str>,
    conv_id: Option<&str>,
    conv_type: i32,
    friend: &DouyinFriend,
) -> bool {
    if conv_type == 2 || friend.target_type == Some(2) {
        friend.target_type == Some(2)
            && (friend.sec_uid == sec_uid
                || friend.conversation_id.as_deref() == Some(sec_uid)
                || conv_id.is_some_and(|id| {
                    friend.sec_uid == id || friend.conversation_id.as_deref() == Some(id)
                }))
    } else {
        friend.sec_uid == sec_uid || uid.is_some_and(|id| !id.is_empty() && friend.uid == id)
    }
}

fn apply_live_friend(
    live: &DouyinFriend,
    nickname: &mut String,
    remark_name: &mut Option<String>,
    avatar: &mut Option<String>,
    spark_days: &mut i32,
    spark_desc: &mut Option<String>,
    target_uid: &mut Option<String>,
    conversation_id: &mut Option<String>,
    conversation_type: &mut i32,
) {
    if !live.nickname.trim().is_empty() {
        *nickname = live.nickname.clone();
    }
    *remark_name = live.remark_name.clone();
    if !live.avatar_url.is_empty() {
        *avatar = Some(live.avatar_url.clone());
    }
    if let Some(days) = live.spark_days {
        *spark_days = days;
    }
    if live.spark_desc.is_some() {
        *spark_desc = live.spark_desc.clone();
    }
    if !live.uid.is_empty() {
        *target_uid = Some(live.uid.clone());
    }
    if let Some(cid) = &live.conversation_id {
        *conversation_id = Some(cid.clone());
    }
    if let Some(kind) = live.target_type {
        *conversation_type = kind;
    }
}

async fn load_live_friends(state: &AppState, account: &Account) -> Vec<DouyinFriend> {
    let (Some(uid), Some(sec)) = (account.uid.as_deref(), account.sec_uid.as_deref()) else {
        return Vec::new();
    };
    let Ok(plain) = state.secret_box.decrypt(&account.encrypted_cookie) else {
        return Vec::new();
    };
    let cookie = String::from_utf8_lossy(&plain).to_string();
    let Ok(client) = DouyinClient::for_account(
        &state.pool,
        &state.secret_box,
        &account.id,
        &cookie,
        &account.alias,
    )
    .await
    else {
        return Vec::new();
    };
    if client
        .load_web_context(
            &state.pool,
            &state.secret_box,
            &account.id,
            account.uid.as_deref(),
        )
        .await
        .is_err()
    {
        return Vec::new();
    }
    client
        .fetch_following_friends(uid, sec)
        .await
        .unwrap_or_default()
}

async fn find_live_friend(
    state: &AppState,
    account: &Account,
    sec_uid: &str,
    uid: Option<&str>,
    conv_id: Option<&str>,
    conv_type: i32,
) -> Option<DouyinFriend> {
    load_live_friends(state, account)
        .await
        .into_iter()
        .find(|f| friend_matches(sec_uid, uid, conv_id, conv_type, f))
}

async fn probe_nickname(state: &AppState, account: &Account, sec_uid: &str) -> Option<String> {
    let plain = state.secret_box.decrypt(&account.encrypted_cookie).ok()?;
    let cookie = String::from_utf8(plain).ok()?;
    let client = DouyinClient::for_account(
        &state.pool,
        &state.secret_box,
        &account.id,
        &cookie,
        &account.alias,
    )
    .await
    .ok()?;
    client
        .load_web_context(
            &state.pool,
            &state.secret_box,
            &account.id,
            account.uid.as_deref(),
        )
        .await
        .ok()?;
    if !client.check_cookie().await.is_valid()
        || client.verified_sender_uid(account.uid.as_deref()).is_err()
    {
        return None;
    }
    let profile_url = format!(
        "https://www.douyin.com/aweme/v1/web/user/profile/other/?aid=6383&device_platform=webapp&sec_user_id={sec_uid}"
    );
    let name = client.get_profile_by_url(&profile_url).await.ok()?;
    let name = name.trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

#[derive(Deserialize)]
pub struct SaveTemplatesReq {
    pub default_template: Option<String>,
    pub custom_templates: Option<Vec<SparkTemplateItem>>,
}

#[derive(Deserialize)]
pub struct PreviewTemplateReq {
    pub template: String,
    pub target_name: Option<String>,
    pub spark_days: Option<i32>,
}

#[derive(Deserialize)]
pub struct ApplyTemplateReq {
    pub template: String,
    pub account_id: Option<String>,
    pub target_ids: Option<Vec<String>>,
    #[serde(default)]
    pub set_as_default: bool,
}

pub async fn get_templates(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let default_template = db::get_setting(&state.pool, "spark_default_template")
        .await
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "🔥".to_string());
    let custom_templates: Vec<SparkTemplateItem> =
        db::get_setting(&state.pool, "spark_custom_templates")
            .await
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
    let custom_contents: std::collections::HashSet<&str> = custom_templates
        .iter()
        .map(|item| item.content.trim())
        .collect();
    let presets: Vec<SparkTemplateItem> = template::builtin_templates()
        .into_iter()
        .filter(|preset| !custom_contents.contains(preset.content.trim()))
        .collect();
    Ok(Json(json!({
        "code": 200,
        "data": {
            "default_template": default_template,
            "presets": presets,
            "custom_templates": custom_templates,
            "variables": template::supported_variables(),
        }
    })))
}

pub async fn save_templates(
    State(state): State<AppState>,
    Json(req): Json<SaveTemplatesReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    if let Some(default_tpl) = req.default_template {
        let clean = default_tpl.trim();
        let final_tpl = if clean.is_empty() { "🔥" } else { clean };
        db::set_setting(&state.pool, "spark_default_template", final_tpl)
            .await
            .map_err(internal_err)?;
    }
    if let Some(custom_list) = req.custom_templates {
        let mut seen_contents = std::collections::HashSet::new();
        let sanitized: Vec<SparkTemplateItem> = custom_list
            .into_iter()
            .filter(|item| !item.name.trim().is_empty() && !item.content.trim().is_empty())
            .take(50)
            .map(|mut item| {
                item.builtin = false;
                item.name = item.name.trim().to_string();
                item.content = item.content.trim().to_string();
                item.description = item.description.trim().to_string();
                if item.id.trim().is_empty() {
                    item.id = format!("custom_{}", uuid::Uuid::new_v4().simple());
                }
                item
            })
            .filter(|item| seen_contents.insert(item.content.clone()))
            .collect();
        let json_str = serde_json::to_string(&sanitized).map_err(internal_err)?;
        db::set_setting(&state.pool, "spark_custom_templates", &json_str)
            .await
            .map_err(internal_err)?;
    }
    get_templates(State(state)).await
}

pub async fn preview_template(
    State(state): State<AppState>,
    Json(req): Json<PreviewTemplateReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let raw = if req.template.trim().is_empty() {
        "🔥"
    } else {
        req.template.trim()
    };
    let (quote, is_fallback) = if template::template_needs_yiyan(raw) {
        match template::fetch_random_yiyan().await {
            Ok(q) => (Some(q), false),
            Err(_) => (Some(template::fallback_yiyan()), true),
        }
    } else {
        (None, false)
    };
    let name = req
        .target_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("好友");
    let days = req.spark_days.unwrap_or(30).max(1);
    let rendered = template::render_with_context(raw, name, days, quote.as_ref());
    Ok(Json(json!({
        "code": 200,
        "data": {
            "rendered": rendered,
            "quote": quote,
            "is_fallback": is_fallback,
        },
        "message": "模板预览生成成功"
    })))
}

pub async fn apply_template(
    State(state): State<AppState>,
    Json(req): Json<ApplyTemplateReq>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let clean_tpl = req.template.trim();
    if clean_tpl.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"code": 400, "message": "模板内容不能为空"})),
        ));
    }
    if req.set_as_default {
        db::set_setting(&state.pool, "spark_default_template", clean_tpl)
            .await
            .map_err(internal_err)?;
    }
    let targets = db::list_targets(&state.pool, req.account_id.as_deref())
        .await
        .map_err(internal_err)?;
    let filter_ids: Option<std::collections::HashSet<String>> = req
        .target_ids
        .map(|ids| ids.into_iter().collect());
    let mut updated_count = 0usize;
    for target in targets {
        if let Some(ref allowed) = filter_ids
            && !allowed.contains(&target.id)
        {
            continue;
        }
        db::update_target(
            &state.pool,
            &target.id,
            &UpdateTargetReq {
                conversation_type: None,
                is_enabled: None,
                target_nickname: None,
                remark_name: None,
                target_avatar: None,
                spark_days: None,
                spark_desc: None,
                is_sparked_today: None,
                message_template: Some(clean_tpl.to_string()),
            },
        )
        .await
        .map_err(internal_err)?;
        updated_count += 1;
    }
    Ok(Json(json!({
        "code": 200,
        "data": {
            "updated_count": updated_count,
            "template": clean_tpl,
        },
        "message": format!("已将模板应用到 {updated_count} 个续火花目标")
    })))
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use crate::{crypto::SecretBox, notify::bark::BarkNotifier, scheduler::SparkEngine};
    use std::sync::Arc;

    #[tokio::test]
    async fn disabled_refresh_changes_only_selected_target_without_network_or_send() {
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[23; 32]);
        let engine = Arc::new(SparkEngine::new(
            pool.clone(),
            secret.clone(),
            BarkNotifier::new("http://127.0.0.1:1".into(), None),
            "09:30".into(),
            0,
            0,
            1,
        ));
        let state = AppState::new(
            pool.clone(),
            secret.clone(),
            engine,
            Arc::new("offline".into()),
            std::env::temp_dir(),
        );
        let now = Utc::now();
        for id in ["account-a", "account-b"] {
            db::insert_account(
                &pool,
                &Account {
                    id: id.into(),
                    alias: id.into(),
                    uid: Some("99191692311".into()),
                    sec_uid: None,
                    nickname: None,
                    avatar_url: None,
                    encrypted_cookie: secret
                        .encrypt(format!("sessionid=PUBLIC-{id}").as_bytes())
                        .unwrap(),
                    status: "DISABLED".into(),
                    bark_key_override: None,
                    last_checked_at: None,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();
        }
        for (id, account_id) in [
            ("selected", "account-a"),
            ("sibling", "account-a"),
            ("other-account", "account-b"),
        ] {
            db::insert_target(
                &pool,
                &SparkTarget {
                    id: id.into(),
                    account_id: account_id.into(),
                    target_sec_uid: "public-peer".into(),
                    target_uid: Some("55696816245".into()),
                    conversation_id: Some("0:1:55696816245:99191692311".into()),
                    conversation_type: 1,
                    target_nickname: id.into(),
                    remark_name: None,
                    target_avatar: None,
                    is_enabled: false,
                    spark_days: 7,
                    spark_desc: None,
                    is_sparked_today: Some(true),
                    today_checked_at: Some(now),
                    message_template: "public".into(),
                    last_sent_at: None,
                    last_status: None,
                    last_error: None,
                    created_at: now,
                    updated_at: now,
                },
            )
            .await
            .unwrap();
        }
        let sibling =
            serde_json::to_value(db::get_target(&pool, "sibling").await.unwrap()).unwrap();
        let other =
            serde_json::to_value(db::get_target(&pool, "other-account").await.unwrap()).unwrap();
        let response = refresh_target(State(state.clone()), Path("selected".into()))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["confirmed"], false);
        assert!(json["message"].as_str().unwrap().contains("所属账号未启用"));
        assert!(json["data"]["is_sparked_today"].is_null());
        assert_eq!(
            serde_json::to_value(db::get_target(&pool, "sibling").await.unwrap()).unwrap(),
            sibling
        );
        assert_eq!(
            serde_json::to_value(db::get_target(&pool, "other-account").await.unwrap()).unwrap(),
            other
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM spark_logs")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        db::update_target_spark_result(&pool, "selected", "SUCCESS", None, None, None)
            .await
            .unwrap();
        let response = refresh_target(State(state), Path("selected".into()))
            .await
            .unwrap()
            .into_response();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["data"]["is_sparked_today"], true);
        let mut target = db::get_target(&pool, "selected").await.unwrap().unwrap();
        assert_eq!(
            refreshed_today_state(&target, now, Utc::now(), Some(false)),
            Some(true)
        );
        target.last_status = None;
        target.last_sent_at = None;
        assert_eq!(
            refreshed_today_state(&target, now, now, Some(false)),
            Some(false)
        );
        let before = chrono::DateTime::parse_from_rfc3339("2026-10-15T15:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let after = before + chrono::Duration::seconds(2);
        assert_eq!(
            refreshed_today_state(&target, before, after, Some(false)),
            None
        );
    }
}
