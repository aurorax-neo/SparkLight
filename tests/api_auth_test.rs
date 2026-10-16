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

#[tokio::test]
async fn test_manual_check_account_does_not_trigger_bark() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let pool = db::init_pool("sqlite::memory:").await.unwrap();
    let secret_box = SecretBox::new(&[17u8; 32]);
    let notifier = BarkNotifier::new(format!("http://127.0.0.1:{port}"), Some("test_bark_key".into()));
    let engine = Arc::new(SparkEngine::new(
        pool.clone(),
        secret_box.clone(),
        notifier,
        "09:30".into(),
        5,
        15,
        3,
    ));

    let valid_api_key = "sk_test_manual_check_123".to_string();
    let state = AppState {
        pool: pool.clone(),
        secret_box: secret_box.clone(),
        engine,
        api_key: Arc::new(valid_api_key.clone()),
    };

    let router = create_router(state);

    let account = sparklight::model::Account {
        id: "acc_manual_check_test".into(),
        alias: "手动检测测试账号".into(),
        sec_uid: None,
        uid: Some("12345678".into()),
        nickname: Some("测试昵称".into()),
        avatar_url: None,
        encrypted_cookie: vec![9, 8, 7], // 无效加密数据，解密必失败
        status: "ACTIVE".into(),
        bark_key_override: Some("custom_account_bark_key".into()),
        last_checked_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    db::insert_account(&pool, &account).await.unwrap();

    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/accounts/acc_manual_check_test/check")
                .header("X-API-Key", &valid_api_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], 200);
    assert_eq!(json["data"]["is_valid"], false);

    let accept_result = tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept()).await;
    assert!(accept_result.is_err(), "手动检测有效性严禁向 Bark 发送通知");
}
