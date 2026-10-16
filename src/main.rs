use std::{net::SocketAddr, sync::Arc};
use anyhow::{Context, Result};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sparklight::{
    config::AppConfig,
    crypto::{self, load_or_create_master_key},
    db,
    notify::bark::BarkNotifier,
    scheduler::{start_daily_scheduler, SparkEngine},
    server::{create_router, AppState},
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sparklight=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!(">>> SparkLight 抖音多账号续火花服务启动中...");

    let config = AppConfig::from_env().context("加载配置失败")?;
    tracing::info!(data_dir = %config.data_dir.display(), "数据存储路径已就绪");

    // Load or create XChaCha20Poly1305 master key
    let master_key = load_or_create_master_key(&config.data_dir)
        .context("加载或生成主加密密钥失败")?;
    tracing::info!("主加密密钥初始化成功 (XChaCha20Poly1305)");

    // Initialize SQLite pool and run migrations
    let pool = db::init_pool(&config.db_url).await
        .context("初始化 SQLite 数据库失败")?;
    tracing::info!(db = %config.db_url, "SQLite 数据库初始化与迁移完成");

    // Load or generate API Key
    let api_key = match config.api_key {
        Some(k) => {
            db::set_setting(&pool, "api_key", &k).await?;
            k
        }
        None => match db::get_setting(&pool, "api_key").await? {
            Some(existing) if !existing.trim().is_empty() => existing,
            _ => {
                let new_key = crypto::generate_api_key();
                db::set_setting(&pool, "api_key", &new_key).await?;
                println!("\n============================================================");
                println!(" SparkLight 已生成系统管理 API Key: {}", new_key);
                println!(" 请在控制台登录或请求头中携带: X-API-Key: {}", new_key);
                println!("============================================================\n");
                new_key
            }
        },
    };

    // Load settings from database or fallback to config
    let saved_settings = db::get_all_settings(&pool).await.unwrap_or_default();
    let bark_server = saved_settings
        .get("bark_server")
        .cloned()
        .unwrap_or(config.bark_server);
    let bark_key = saved_settings
        .get("bark_key")
        .cloned()
        .or(config.bark_key);
    let schedule_time = saved_settings
        .get("spark_time")
        .cloned()
        .unwrap_or(config.spark_time);
    let min_delay = saved_settings
        .get("min_delay_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(config.min_delay_secs);
    let max_delay = saved_settings
        .get("max_delay_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(config.max_delay_secs);
    let max_retries = saved_settings
        .get("max_retries")
        .and_then(|v| v.parse().ok())
        .unwrap_or(config.max_retries);

    let notifier = BarkNotifier::new(bark_server, bark_key);
    let engine = Arc::new(SparkEngine::new(
        pool.clone(),
        master_key.clone(),
        notifier,
        schedule_time.clone(),
        min_delay,
        max_delay,
        max_retries,
    ));

    // Start background daily scheduler
    start_daily_scheduler(engine.clone());
    sparklight::scheduler::start_heartbeat_worker(engine.clone());
    tracing::info!(schedule_time = %schedule_time, max_retries = %max_retries, "每日定时检测与续火花调度器已激活");

    let app_state = AppState {
        pool,
        secret_box: master_key,
        engine,
        api_key: Arc::new(api_key.clone()),
    };

    let app = create_router(app_state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .context("无效的监听地址或端口")?;

    tracing::info!("SparkLight Web API 服务正在监听: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await
        .with_context(|| format!("绑定端口失败: {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Axum 服务运行异常")?;

    tracing::info!("SparkLight 服务已正常关闭");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
