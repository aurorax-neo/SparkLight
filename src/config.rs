use std::path::PathBuf;
use anyhow::Result;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub db_url: String,
    pub api_key: Option<String>,
    pub bark_server: String,
    pub bark_key: Option<String>,
    pub spark_time: String,
    pub min_delay_secs: u64,
    pub max_delay_secs: u64,
    pub max_retries: u32,
    pub proxy_url: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let host = std::env::var("SPARK_HOST")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        let port = std::env::var("SPARK_PORT")
            .or_else(|_| std::env::var("PORT"))
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let data_dir = std::env::var("SPARK_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));

        let db_path = data_dir.join("sparklight.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

        let api_key = std::env::var("SPARK_API_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let bark_server = std::env::var("SPARK_BARK_SERVER")
            .unwrap_or_else(|_| "https://api.day.app".to_string());

        let bark_key = std::env::var("SPARK_BARK_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let spark_time = std::env::var("SPARK_SCHEDULE_TIME")
            .unwrap_or_else(|_| "09:30".to_string());

        let min_delay_secs = std::env::var("SPARK_MIN_DELAY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let max_delay_secs = std::env::var("SPARK_MAX_DELAY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);

        let max_retries = std::env::var("SPARK_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        let proxy_url = std::env::var("SPARK_PROXY")
            .or_else(|_| std::env::var("HTTP_PROXY"))
            .or_else(|_| std::env::var("http_proxy"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(Self {
            host,
            port,
            data_dir,
            db_url,
            api_key,
            bark_server,
            bark_key,
            spark_time,
            min_delay_secs,
            max_delay_secs,
            max_retries,
            proxy_url,
        })
    }
}
