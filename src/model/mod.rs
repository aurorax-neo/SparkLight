use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Account {
    pub id: String,
    pub alias: String,
    pub sec_uid: Option<String>,
    pub uid: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    #[serde(skip)]
    pub encrypted_cookie: Vec<u8>,
    pub status: String, // "ACTIVE", "EXPIRED", "DISABLED"
    pub bark_key_override: Option<String>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDto {
    pub id: String,
    pub alias: String,
    pub sec_uid: Option<String>,
    pub uid: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub masked_cookie: String,
    pub status: String,
    pub bark_key_override: Option<String>,
    pub targets_count: i64,
    pub active_targets_count: i64,
    /// 本地只读 IM 材料状态，不代表平台接受或可发送。
    pub im_history_status: String,
    pub im_history_expires_at: Option<i64>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountReq {
    pub alias: String,
    pub cookie: String,
    pub bark_key_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAccountReq {
    pub alias: Option<String>,
    pub cookie: Option<String>,
    pub status: Option<String>,
    pub bark_key_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SparkTarget {
    pub id: String,
    pub account_id: String,
    pub target_sec_uid: String,
    pub target_uid: Option<String>,
    pub conversation_id: Option<String>,
    pub conversation_type: i32, // 1 = 单聊, 2 = 群聊
    pub target_nickname: String,
    pub remark_name: Option<String>,
    pub target_avatar: Option<String>,
    pub is_enabled: bool,
    pub spark_days: i32,
    pub spark_desc: Option<String>,
    pub is_sparked_today: Option<bool>,
    /// 消息历史检测的时间；不能使用资料的 updated_at 代替。
    pub today_checked_at: Option<DateTime<Utc>>,
    pub message_template: String,
    pub last_sent_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTargetReq {
    pub account_id: String,
    pub target_sec_uid: String,
    pub target_uid: Option<String>,
    pub conversation_id: Option<String>,
    pub conversation_type: Option<i32>,
    pub target_nickname: String,
    pub remark_name: Option<String>,
    pub target_avatar: Option<String>,
    pub spark_days: Option<i32>,
    pub spark_desc: Option<String>,
    pub is_sparked_today: Option<bool>,
    pub message_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTargetReq {
    pub conversation_type: Option<i32>,
    pub is_enabled: Option<bool>,
    pub target_nickname: Option<String>,
    pub remark_name: Option<String>,
    pub target_avatar: Option<String>,
    pub spark_days: Option<i32>,
    pub spark_desc: Option<String>,
    pub is_sparked_today: Option<bool>,
    pub message_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SparkLog {
    pub id: String,
    pub account_id: String,
    pub account_alias: String,
    pub target_id: Option<String>,
    pub target_nickname: Option<String>,
    pub action_type: String, // "CHECK_COOKIE", "SEND_SPARK", "REFRESH_COOKIE"
    pub status: String,      // "SUCCESS", "FAILED"
    pub message: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemSetting {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsReq {
    pub bark_server: Option<String>,
    pub bark_key: Option<String>,
    pub spark_time: Option<String>,
    pub min_delay_secs: Option<u64>,
    pub max_delay_secs: Option<u64>,
    pub max_retries: Option<u32>,
    pub proxy_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemOverview {
    pub total_accounts: i64,
    pub active_accounts: i64,
    pub expired_accounts: i64,
    pub total_targets: i64,
    pub active_targets: i64,
    pub today_sparked_count: i64,
    pub next_schedule_time: String,
}

pub fn system_sent_today(status: Option<&str>, sent_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    let cst = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    status == Some("SUCCESS") && sent_at.is_some_and(|sent| {
        sent <= now && sent.with_timezone(&cst).date_naive() == now.with_timezone(&cst).date_naive()
    })
}

#[cfg(test)]
mod today_tests {
    use super::*;
    #[test]
    fn system_success_requires_nonfuture_cst_today() {
        let now = DateTime::parse_from_rfc3339("2026-10-14T16:00:01Z").unwrap().with_timezone(&Utc);
        assert!(system_sent_today(Some("SUCCESS"), Some(now), now));
        assert!(!system_sent_today(Some("SUCCESS"), Some(now + chrono::Duration::seconds(1)), now));
        assert!(!system_sent_today(Some("SUCCESS"), Some(now - chrono::Duration::seconds(2)), now));
        assert!(!system_sent_today(Some("FAILED"), Some(now), now));
        assert!(!system_sent_today(Some("SUCCESS"), None, now));
    }
}
