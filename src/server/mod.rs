pub mod auth;
pub mod routes;

use axum::{
    Json, Router,
    http::{StatusCode, header},
    middleware,
    response::IntoResponse,
    routing::{any, get, post},
};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

use crate::{
    crypto::SecretBox,
    douyin::login::{LoginSession, PhoneLoginSession},
    scheduler::SparkEngine,
};

/// 正在进行中的原生二维码登录会话表；键为登录会话 ID。
pub type LoginRegistry = Arc<Mutex<HashMap<String, LoginSession>>>;

/// 官方手机版「手机号 + 短信验证码」登录会话表。
pub type PhoneLoginRegistry = Arc<Mutex<HashMap<String, PhoneLoginSession>>>;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub secret_box: SecretBox,
    pub engine: Arc<SparkEngine>,
    pub api_key: Arc<String>,
    /// 数据目录：主密钥、数据库默认位置等持久状态都放在这里。
    pub data_dir: Arc<PathBuf>,
    pub logins: LoginRegistry,
    pub phone_logins: PhoneLoginRegistry,
}

impl AppState {
    pub fn new(
        pool: SqlitePool,
        secret_box: SecretBox,
        engine: Arc<SparkEngine>,
        api_key: Arc<String>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            pool,
            secret_box,
            engine,
            api_key,
            data_dir: Arc::new(data_dir),
            logins: Arc::new(Mutex::new(HashMap::new())),
            phone_logins: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let protected_routes = Router::new()
        .route("/api/v1/system/overview", get(routes::system::overview))
        .route("/api/v1/system/run-all", post(routes::system::run_all))
        .route("/api/v1/accounts", get(routes::accounts::list_accounts))
        .route(
            "/api/v1/accounts/{id}",
            get(routes::accounts::get_account)
                .put(routes::accounts::update_account)
                .delete(routes::accounts::delete_account),
        )
        .route(
            "/api/v1/accounts/{id}/check",
            post(routes::accounts::check_account),
        )
        .route(
            "/api/v1/accounts/{id}/sync-friends",
            post(routes::accounts::sync_friends),
        )
        .route(
            "/api/v1/accounts/{id}/run",
            post(routes::accounts::run_account),
        )
        .route(
            "/api/v1/accounts/login/start",
            post(routes::login::start_login),
        )
        .route(
            "/api/v1/accounts/native-import",
            post(routes::login::import_native_session),
        )
        .route(
            "/api/v1/accounts/login/{id}",
            get(routes::login::login_status),
        )
        .route(
            "/api/v1/accounts/login/phone",
            post(routes::login::start_phone_login),
        )
        .route(
            "/api/v1/accounts/login/phone/{id}/verify",
            post(routes::login::verify_phone_login),
        )
        .route(
            "/api/v1/accounts/login/password",
            post(routes::login::password_login),
        )
        .route(
            "/api/v1/accounts/login/{id}/cancel",
            post(routes::login::cancel_login),
        )
        .route(
            "/api/v1/accounts/login/{id}/verify/send",
            post(routes::login::send_verification_code),
        )
        .route(
            "/api/v1/accounts/login/{id}/verify/up-sms",
            post(routes::login::prepare_up_sms),
        )
        .route(
            "/api/v1/accounts/login/{id}/verify/submit",
            post(routes::login::submit_verification),
        )
        .route(
            "/api/v1/targets",
            get(routes::targets::list_targets).post(routes::targets::create_target),
        )
        .route(
            "/api/v1/targets/batch",
            post(routes::targets::batch_create_targets),
        )
        .route(
            "/api/v1/targets/templates",
            get(routes::targets::get_templates).put(routes::targets::save_templates),
        )
        .route(
            "/api/v1/targets/templates/preview",
            post(routes::targets::preview_template),
        )
        .route(
            "/api/v1/targets/templates/apply",
            post(routes::targets::apply_template),
        )
        .route(
            "/api/v1/targets/{id}",
            get(routes::targets::get_target)
                .put(routes::targets::update_target)
                .delete(routes::targets::delete_target),
        )
        .route(
            "/api/v1/targets/{id}/test",
            post(routes::targets::test_target),
        )
        .route(
            "/api/v1/targets/{id}/refresh",
            post(routes::targets::refresh_target),
        )
        .route("/api/v1/logs", get(routes::logs::list_logs))
        .route(
            "/api/v1/settings",
            get(routes::settings::get_settings).put(routes::settings::update_settings),
        )
        .route(
            "/api/v1/settings/test-bark",
            post(routes::settings::test_bark),
        )
        .route("/api/{*path}", any(api_not_found))
        .layer(middleware::from_fn_with_state(
            state.api_key.clone(),
            auth::auth_middleware,
        ));

    let public_routes = Router::new().route("/api/v1/system/health", get(routes::system::health));

    let router = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors);

    if Path::new("frontend/dist/index.html").exists() {
        let serve_dir = ServeDir::new("frontend/dist")
            .not_found_service(ServeFile::new("frontend/dist/index.html"));
        router
            .fallback_service(serve_dir)
            // 防止浏览器在新版本部署后继续复用旧 index.html 与旧资源映射。
            .layer(SetResponseHeaderLayer::overriding(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-cache"),
            ))
            .with_state(state)
    } else {
        router.with_state(state)
    }
}

async fn api_not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "code": 404,
            "message": "接口不存在或已移除"
        })),
    )
}

/// 每分钟回收超时二维码会话。
pub fn start_login_reaper(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let now = chrono::Utc::now().timestamp();
            let expired = {
                let mut sessions = state.logins.lock().await;
                let keys = sessions
                    .iter()
                    .filter(|(_, session)| session.is_expired(now))
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                keys.into_iter()
                    .filter_map(|key| sessions.remove(&key))
                    .collect::<Vec<_>>()
            };
            drop(expired);
        }
    });
}
