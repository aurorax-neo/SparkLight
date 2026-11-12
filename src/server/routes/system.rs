use axum::{Json, extract::State, response::IntoResponse};
use serde::Deserialize;
use serde_json::json;

use crate::{db, server::AppState};

#[derive(Deserialize)]
pub struct RunAllReq {
    pub force_resend: Option<bool>,
}

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "name": "SparkLight",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

pub async fn overview(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, Json<serde_json::Value>)> {
    let schedule_time = state.engine.schedule_time.read().await.clone();
    let data = db::get_system_overview(&state.pool, schedule_time)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "code": 200,
        "data": data
    })))
}

pub async fn run_all(
    State(state): State<AppState>,
    Json(req): Json<RunAllReq>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, Json<serde_json::Value>)> {
    state.engine.record_manual_action();
    let force = req.force_resend.unwrap_or(false);
    let summary = state
        .engine
        .execute_all_accounts(force, false)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"code": 500, "message": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "code": 200,
        "data": summary,
        "message": summary.completion_message()
    })))
}
