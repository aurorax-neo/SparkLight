use std::sync::Arc;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;

use sparklight::{
    crypto::SecretBox,
    db,
    notify::bark::BarkNotifier,
    scheduler::SparkEngine,
    server::{create_router, AppState},
};

#[tokio::test]
async fn test_api_key_auth_and_cookie_encryption() {
    let pool = db::init_pool("sqlite::memory:").await.unwrap();
    let secret_box = SecretBox::new(&[17u8; 32]);
    let notifier = BarkNotifier::new("https://api.day.app".into(), None);
    let engine = Arc::new(SparkEngine::new(
        pool.clone(),
        secret_box.clone(),
        notifier,
        "09:30".into(),
        5,
        15,
        3,
    ));

    let valid_api_key = "sk_test_1234567890abcdef".to_string();
    let state = AppState {
        pool: pool.clone(),
        secret_box: secret_box.clone(),
        engine,
        api_key: Arc::new(valid_api_key.clone()),
    };

    let router = create_router(state);

    // 1. Health check should be public
    let res = router
        .clone()
        .oneshot(Request::builder().uri("/api/v1/system/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 2. Protected overview without API key should return 401
    let res = router
        .clone()
        .oneshot(Request::builder().uri("/api/v1/system/overview").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 3. Protected overview with wrong key should return 401
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/system/overview")
                .header("X-API-Key", "sk_wrong_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 4. Protected overview with valid X-API-Key should return 200
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/system/overview")
                .header("X-API-Key", &valid_api_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 5. Protected overview with Authorization: Bearer should return 200
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/system/overview")
                .header("Authorization", format!("Bearer {}", valid_api_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], 200);
}
