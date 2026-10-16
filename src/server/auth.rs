use std::sync::Arc;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;

pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(val) = headers.get("X-API-Key").or_else(|| headers.get("x-api-key")) {
        if let Ok(s) = val.to_str() {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }

    if let Some(val) = headers.get("Authorization").or_else(|| headers.get("authorization")) {
        if let Ok(s) = val.to_str() {
            let s = s.trim();
            if let Some(token) = s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")) {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    None
}

pub async fn auth_middleware(
    State(expected_key): State<Arc<String>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let path = req.uri().path();
    // Allow public healthcheck and static frontend routes
    if path == "/api/v1/system/health" || !path.starts_with("/api/") {
        return Ok(next.run(req).await);
    }

    let key = extract_api_key(req.headers());
    match key {
        Some(k) if k == *expected_key => Ok(next.run(req).await),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "code": 401,
                "message": "Unauthorized: invalid or missing API key"
            })),
        )),
    }
}
