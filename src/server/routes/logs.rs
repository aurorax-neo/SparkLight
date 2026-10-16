use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{db, server::AppState};

#[derive(Deserialize)]
pub struct ListLogsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub account_id: Option<String>,
    pub status: Option<String>,
}

pub async fn list_logs(
    State(state): State<AppState>,
    Query(query): Query<ListLogsQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let account_id = query.account_id.as_deref().filter(|s| !s.trim().is_empty());
    let status = query.status.as_deref().filter(|s| !s.trim().is_empty());

    let logs = db::list_logs(&state.pool, limit, offset, account_id, status).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

    let total = db::count_logs(&state.pool, account_id, status).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"code": 500, "message": e.to_string()}))))?;

    Ok(Json(json!({
        "code": 200,
        "data": {
            "items": logs,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    })))
}
