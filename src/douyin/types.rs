use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DouyinUserProfile {
    pub uid: String,
    pub sec_uid: String,
    pub nickname: String,
    pub avatar_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DouyinFriend {
    pub uid: String,
    pub sec_uid: String,
    pub nickname: String,
    pub avatar_url: String,
    pub spark_days: Option<i32>,
    pub spark_desc: Option<String>,
    pub is_sparked_today: Option<bool>,
    pub target_type: Option<i32>, // 1 = 单聊, 2 = 群聊
    pub conversation_id: Option<String>,
    pub remark_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkConversationInfo {
    pub days: i32,
    pub desc: String,
    pub is_sparked_today: bool,
    pub short_id: u64,
    pub conv_name: Option<String>,
    /// 会话参与者备注：(uid, alias)。1v1 里对方那条才是我给对方的抖音备注。
    pub aliases: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckCookieResult {
    Valid(DouyinUserProfile),
    Expired(String),
    NeedVerify(String),
    NetworkError(String),
}

impl CheckCookieResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, CheckCookieResult::Valid(_))
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            CheckCookieResult::Valid(_) => None,
            CheckCookieResult::Expired(msg) => Some(msg),
            CheckCookieResult::NeedVerify(msg) => Some(msg),
            CheckCookieResult::NetworkError(msg) => Some(msg),
        }
    }

    /// 日志仅接受固定分类，绝不写入第三方响应或调用方错误正文。
    pub fn safe_diagnostic(&self) -> &'static str {
        match self {
            Self::Valid(_) => "SESSION_VALID: 当前登录身份已确认",
            Self::Expired(_) => "SESSION_EXPIRED: 登录会话已失效，已停止账号任务",
            Self::NeedVerify(_) => "SESSION_VERIFY_REQUIRED: 当前会话需要安全验证，已停止账号任务",
            Self::NetworkError(message) => match message.split(':').next() {
                Some("SESSION_LIMITED") => "SESSION_LIMITED: 当前会话被限流，登录态未确认；未自动重试",
                Some("SESSION_PROTOCOL") => "SESSION_PROTOCOL: 响应协议异常，登录态未确认；未自动重试",
                Some("SESSION_BUSINESS") => "SESSION_BUSINESS: 业务响应未成功，登录态未确认；未自动重试",
                Some("SESSION_NETWORK") => "SESSION_NETWORK: 网络请求未完成，登录态未确认；未自动重试",
                _ => "SESSION_UNCONFIRMED: 登录态检测未完成；未自动重试",
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendSparkResult {
    pub success: bool,
    pub message: String,
    pub spark_days: Option<i32>,
    pub raw_response: Option<String>,
}

impl SendSparkResult {
    pub fn failure(message: &str) -> Self {
        Self { success: false, message: message.to_string(), spark_days: None, raw_response: None }
    }

    pub fn is_fatal_failure(&self) -> bool {
        !self.success && super::client::is_fatal_send_error(-1, &self.message)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeartbeatResult {
    Alive,
    Expired(String),
    Error(String),
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn diagnostic_is_fixed_and_does_not_echo_sensitive_details() {
        for code in ["SESSION_LIMITED","SESSION_PROTOCOL","SESSION_BUSINESS","SESSION_NETWORK","SESSION_UNCONFIRMED"] {
            let result=CheckCookieResult::NetworkError(format!("{code}: public-fixture-secret"));
            assert!(result.safe_diagnostic().starts_with(code));
            assert!(!result.safe_diagnostic().contains("public-fixture-secret"));
        }
        assert!(CheckCookieResult::NetworkError("arbitrary public fixture".into()).safe_diagnostic().starts_with("SESSION_UNCONFIRMED"));
        assert!(CheckCookieResult::Expired("public fixture".into()).safe_diagnostic().starts_with("SESSION_EXPIRED"));
    }
}
