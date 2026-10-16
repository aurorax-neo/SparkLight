pub mod auth;
pub mod routes;

use std::{path::Path, sync::Arc};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::SqlitePool;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};

use crate::{
    crypto::SecretBox,
    scheduler::SparkEngine,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub secret_box: SecretBox,
    pub engine: Arc<SparkEngine>,
    pub api_key: Arc<String>,
}

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let protected_routes = Router::new()
        .route("/api/v1/system/overview", get(routes::system::overview))
        .route("/api/v1/system/launch-brave", post(routes::system::launch_brave))
        .route("/api/v1/system/run-all", post(routes::system::run_all))
        .route("/api/v1/accounts", get(routes::accounts::list_accounts).post(routes::accounts::create_account))
        .route("/api/v1/accounts/{id}", get(routes::accounts::get_account).put(routes::accounts::update_account).delete(routes::accounts::delete_account))
        .route("/api/v1/accounts/{id}/check", post(routes::accounts::check_account))
        .route("/api/v1/accounts/{id}/sync-cookie", post(routes::accounts::sync_from_browser))
        .route("/api/v1/accounts/{id}/im-credential", post(routes::accounts::import_im_credential))
        .route("/api/v1/accounts/{id}/sync-friends", post(routes::accounts::sync_friends))
        .route("/api/v1/accounts/{id}/run", post(routes::accounts::run_account))
        .route("/api/v1/targets", get(routes::targets::list_targets).post(routes::targets::create_target))
        .route("/api/v1/targets/batch", post(routes::targets::batch_create_targets))
        .route("/api/v1/targets/{id}", get(routes::targets::get_target).put(routes::targets::update_target).delete(routes::targets::delete_target))
        .route("/api/v1/targets/{id}/test", post(routes::targets::test_target))
        .route("/api/v1/targets/{id}/refresh", post(routes::targets::refresh_target))
        .route("/api/v1/logs", get(routes::logs::list_logs))
        .route("/api/v1/settings", get(routes::settings::get_settings).put(routes::settings::update_settings))
        .route("/api/v1/settings/test-bark", post(routes::settings::test_bark))
        .layer(middleware::from_fn_with_state(state.api_key.clone(), auth::auth_middleware));

    let public_routes = Router::new()
        .route("/api/v1/system/health", get(routes::system::health));

    let router = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors);

    if Path::new("frontend/dist/index.html").exists() {
        let serve_dir = ServeDir::new("frontend/dist")
            .not_found_service(ServeFile::new("frontend/dist/index.html"));
        router.fallback_service(serve_dir).with_state(state)
    } else {
        router.with_state(state)
    }
}
