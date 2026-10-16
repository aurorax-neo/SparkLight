use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::{Local, Utc};
use rand::Rng;
use sqlx::SqlitePool;
use tokio::sync::{RwLock, Mutex, watch};

use crate::{
    crypto::SecretBox,
    db,
    douyin::client::DouyinClient,
    model::{Account, SparkLog, SparkTarget},
    notify::bark::BarkNotifier,
};

struct RunningGuard(Arc<AtomicBool>);
impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct SparkEngine {
    pub pool: SqlitePool,
    pub secret_box: SecretBox,
    pub notifier: BarkNotifier,
    pub schedule_time: Arc<RwLock<String>>,
    delay_settings: watch::Sender<(u64,u64)>,
    pub(crate) settings_update_lock: Arc<Mutex<()>>,
    pub max_retries: Arc<AtomicU32>,
    pub is_running: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    Success,
    PartialFailed,
    Failed,
}

/// 只持久化固定分类；未知错误和凭证材料不得进入调度诊断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionDiagnostic {
    WebContextMissing,
    WebContextExpired,
    WebContextInvalid,
    SendCredentialMissing,
    SendCredentialInvalid,
    IdentityRefreshFailed,
    ConversationUnknown,
    HistoryUnknown,
    SessionUnconfirmed,
    AccountStopped,
}

impl ExecutionDiagnostic {
    fn code(self) -> &'static str {
        match self {
            Self::WebContextMissing => "WEB_CONTEXT_MISSING",
            Self::WebContextExpired => "WEB_CONTEXT_EXPIRED",
            Self::WebContextInvalid => "WEB_CONTEXT_INVALID",
            Self::SendCredentialMissing => "SEND_CREDENTIAL_MISSING",
            Self::SendCredentialInvalid => "SEND_CREDENTIAL_INVALID",
            Self::IdentityRefreshFailed => "IM_IDENTITY_REFRESH_FAILED",
            Self::ConversationUnknown => "CONVERSATION_STATUS_UNKNOWN",
            Self::HistoryUnknown => "MESSAGE_HISTORY_UNKNOWN",
            Self::SessionUnconfirmed => "SESSION_UNCONFIRMED",
            Self::AccountStopped => "ACCOUNT_EXECUTION_STOPPED",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::WebContextMissing => "缺少当前账号的官方 Web IM 上下文，已停止账号任务；未因此尝试发送或重试",
            Self::WebContextExpired => "官方 Web IM 上下文已过期，已停止账号任务；未因此尝试发送或重试",
            Self::WebContextInvalid => "账号 Web 上下文无法装载或校验，已停止账号任务；未因此尝试发送或重试",
            Self::SendCredentialMissing => "缺少当前目标的官方 IM 发送凭证，已停止账号任务；未因此尝试发送或重试",
            Self::SendCredentialInvalid => "官方 IM 发送凭证无法校验，已停止账号任务；未因此尝试发送或重试",
            Self::IdentityRefreshFailed => "IM 身份 Token 续取失败或身份变化，已停止；未消费发送授权、未发送且未重试",
            Self::ConversationUnknown => "目标会话状态未确认，已停止账号任务；未因此尝试发送或重试",
            Self::HistoryUnknown => "今日发送历史未确认完整，已停止账号任务；未因此尝试发送或重试",
            Self::SessionUnconfirmed => "当前账号登录会话未确认有效，已停止账号任务",
            Self::AccountStopped => "账号任务异常终止；详细错误已省略以保护凭证",
        }
    }

    fn classify(error: &anyhow::Error) -> Self {
        // load_web_context 是可选装载；缺失/过期也可能到后续 IM 查询才报错。
        for cause in error.chain() {
            match cause.to_string().as_str() {
                "缺少官方 Web IM 上下文，需同步当前账号凭证，禁止请求" => return Self::WebContextMissing,
                "官方 IM 上下文已过期，请重新同步，禁止请求" => return Self::WebContextExpired,
                _ => {}
            }
        }
        error.downcast_ref::<Self>().copied().unwrap_or(Self::AccountStopped)
    }
}

impl std::fmt::Display for ExecutionDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}
impl std::error::Error for ExecutionDiagnostic {}

#[derive(Debug, serde::Serialize)]
pub struct ExecutionSummary {
    pub account_id: String,
    pub account_alias: String,
    pub cookie_status: String,
    pub total_targets: usize,
    pub success_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
    pub status: ExecutionStatus,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct BatchSummary {
    pub total_accounts: usize,
    pub active_accounts: usize,
    pub accounts: Vec<ExecutionSummary>,
    pub status: ExecutionStatus,
    pub successful_accounts: usize,
    pub failed_accounts: usize,
    pub partial_failed_accounts: usize,
}

impl ExecutionSummary {
    fn stopped(account: &Account, diagnostic: ExecutionDiagnostic) -> Self {
        Self {
            account_id: account.id.clone(),
            account_alias: account.alias.clone(),
            cookie_status: account.status.clone(),
            total_targets: 0,
            success_count: 0,
            failed_count: 0,
            skipped_count: 0,
            status: ExecutionStatus::Failed,
            error_code: Some(diagnostic.code().into()),
            message: Some(diagnostic.message().into()),
        }
    }
}

impl BatchSummary {
    fn from_accounts(accounts: Vec<ExecutionSummary>, active_accounts: usize) -> Self {
        let successful_accounts = accounts.iter().filter(|s| s.status == ExecutionStatus::Success).count();
        let failed_accounts = accounts.iter().filter(|s| s.status == ExecutionStatus::Failed).count();
        let partial_failed_accounts = accounts.iter().filter(|s| s.status == ExecutionStatus::PartialFailed).count();
        let status = if failed_accounts + partial_failed_accounts == 0 {
            ExecutionStatus::Success
        } else if failed_accounts == accounts.len() {
            ExecutionStatus::Failed
        } else {
            ExecutionStatus::PartialFailed
        };
        Self { total_accounts: accounts.len(), active_accounts, accounts, status,
            successful_accounts, failed_accounts, partial_failed_accounts }
    }

    pub fn completion_message(&self) -> &'static str {
        match self.status {
            ExecutionStatus::Success => "全量续火花正常结束",
            ExecutionStatus::PartialFailed => "全量续火花部分失败",
            ExecutionStatus::Failed => "全量续火花执行失败",
        }
    }
}

fn target_conversation_id(account: &Account, target: &SparkTarget) -> Result<String> {
    if target.conversation_type == 2 {
        return Ok(target.conversation_id.clone().unwrap_or_else(|| target.target_sec_uid.clone()));
    }
    let sender = account.uid.as_deref().and_then(|uid| uid.parse::<u64>().ok()).filter(|uid| *uid > 0).context("账号 UID 无效，禁止发送")?;
    let peer = target.target_uid.as_deref().and_then(|uid| uid.parse::<u64>().ok()).filter(|uid| *uid > 0).context("目标 UID 无效，禁止发送")?;
    Ok(format!("0:1:{}:{}", sender.min(peer), sender.max(peer)))
}

// force_resend 仅保留调用兼容性，不能越过真实当日已发门禁。
fn skip_sent_today(sent: bool, _force_resend: bool) -> bool { sent }

/// 手动验收只发一次；自动任务仅对非致命错误重试。
async fn send_with_retry<F, Fut>(max_attempts: u32, delay: Duration, mut send: F) -> (crate::douyin::types::SendSparkResult, u32)
where F: FnMut() -> Fut, Fut: std::future::Future<Output = crate::douyin::types::SendSparkResult> {
    let max_attempts = max_attempts.max(1);
    for attempt in 1..=max_attempts {
        let result = send().await;
        if result.success || result.is_fatal_failure() || attempt == max_attempts {
            return (result, attempt);
        }
        tokio::time::sleep(delay).await;
    }
    unreachable!()
}
impl SparkEngine {
    pub fn new(
        pool: SqlitePool,
        secret_box: SecretBox,
        notifier: BarkNotifier,
        schedule_time: String,
        min_delay_secs: u64,
        max_delay_secs: u64,
        max_retries: u32,
    ) -> Self {
        Self {
            pool,
            secret_box,
            notifier,
            schedule_time: Arc::new(RwLock::new(schedule_time)),
            delay_settings: watch::channel((min_delay_secs,max_delay_secs.max(min_delay_secs))).0,
            settings_update_lock: Arc::new(Mutex::new(())),
            max_retries: Arc::new(AtomicU32::new(max_retries)),
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn delay_range(&self) -> (u64,u64) { *self.delay_settings.borrow() }

    pub(crate) fn set_delay_range(&self,min:u64,max:u64) {
        self.delay_settings.send_if_modified(|range| {
            if *range==(min,max) {false} else {*range=(min,max);true}
        });
    }

    /// 修改延迟时唤醒现有等待，以已等待时长抵扣新延迟。
    async fn prepare_target_delay(&self,client:&DouyinClient,account:&Account,target:&SparkTarget) -> Result<()> {
        self.load_send_credential(client,account,target).await?;
        self.wait_target_delay().await;
        Ok(())
    }

    async fn wait_target_delay(&self) {
        let started=tokio::time::Instant::now();
        let mut settings=self.delay_settings.subscribe();
        loop {
            let (min,max)=*settings.borrow_and_update();
            let seconds=if max>min {rand::thread_rng().gen_range(min..=max)} else {min};
            let remaining=Duration::from_secs(seconds).saturating_sub(started.elapsed());
            tokio::select! {
                biased;
                changed=settings.changed()=>if changed.is_err() {return;},
                _=tokio::time::sleep(remaining)=> {
                    if settings.has_changed().unwrap_or(false) {continue;}
                    return;
                },
            }
        }
    }

    /// 检查账号并保存已观察到的 Cookie 更新；不据此判定会话延寿。
    /// `notify_on_failure`: 是否在检测失败（失效/安全验证/解密异常）时向 Bark 发送推送告警。
    /// 前台手动操作（手动点击检测有效性、更新保存账号、手动触发等）必须设为 false，确保静默测试；后台定时任务与巡检设为 true。
    pub async fn check_account_cookie(&self, account: &Account, notify_on_failure: bool) -> Result<bool> {
        let plaintext_cookie = match self.secret_box.decrypt(&account.encrypted_cookie) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    let err_msg = "Cookie 解密后不是有效的 UTF-8 文本";
                    self.record_log(&account.id, &account.alias, None, None, "CHECK_COOKIE", "FAILED", err_msg).await.ok();
                    db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                    if notify_on_failure {
                        self.notifier.send_cookie_expired_alert(&account.alias, account.nickname.as_deref(), err_msg, account.bark_key_override.as_deref()).await.ok();
                    }
                    return Ok(false);
                }
            },
            Err(_) => {
                let err_msg = "Cookie 解密失败（错误详情已省略）";
                self.record_log(&account.id, &account.alias, None, None, "CHECK_COOKIE", "FAILED", &err_msg).await.ok();
                db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                if notify_on_failure {
                    self.notifier.send_cookie_expired_alert(&account.alias, account.nickname.as_deref(), err_msg, account.bark_key_override.as_deref()).await.ok();
                }
                return Ok(false);
            }
        };

        let client = DouyinClient::new(&plaintext_cookie, &account.alias)?;
        client.load_web_context(&self.pool,&self.secret_box,&account.id,account.uid.as_deref()).await
            .context(ExecutionDiagnostic::WebContextInvalid)?;
        let check_res = client.check_cookie().await;

        // Cookie 变化不等于续期；只保存已观察到的更新。
        if client.is_cookie_changed() && matches!(&check_res,crate::douyin::types::CheckCookieResult::Valid(profile) if account.uid.as_deref().is_none_or(|uid| uid==profile.uid)) {
            let refreshed_cookie = client.get_current_cookie();
            if let Ok(new_encrypted) = self.secret_box.encrypt(refreshed_cookie.as_bytes()) {
                db::update_account_cookie(&self.pool, &account.id, &new_encrypted).await.ok();
                client.persist_web_context(&self.pool,&self.secret_box,&account.id).await.ok();
                self.record_log(
                    &account.id,
                    &account.alias,
                    None,
                    None,
                    "REFRESH_COOKIE",
                    "SUCCESS",
                    "已观察到 Cookie 更新并加密保存，但未证实延长会话有效期",
                ).await.ok();
                tracing::info!(account = %account.alias, "已观察到 Cookie 更新并保存，但未证实延长会话有效期");
            }
        }

        match check_res {
            crate::douyin::types::CheckCookieResult::Valid(profile) => {
                if account.uid.as_deref().is_some_and(|uid| uid != profile.uid) {
                    let _=client.verified_sender_uid(account.uid.as_deref());
                    db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                    self.record_log(&account.id, &account.alias, None, None, "CHECK_COOKIE", "FAILED", "Cookie 身份与所属账号不符，禁止发送且保留原账号资料").await?;
                    return Ok(false);
                }
                db::update_account_status(&self.pool, &account.id, "ACTIVE", Utc::now()).await?;
                db::update_account_profile(
                    &self.pool,
                    &account.id,
                    Some(&profile.sec_uid),
                    Some(&profile.uid),
                    Some(&profile.nickname),
                    Some(&profile.avatar_url),
                ).await?;
                client.persist_web_context(&self.pool,&self.secret_box,&account.id).await.ok();
                self.record_log(
                    &account.id,
                    &account.alias,
                    None,
                    None,
                    "CHECK_COOKIE",
                    "SUCCESS",
                    &format!("账号状态正常，已更新资料（昵称: {}）", profile.nickname),
                ).await.ok();
                Ok(true)
            }
            crate::douyin::types::CheckCookieResult::Expired(reason) => {
                db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                self.record_log(&account.id, &account.alias, None, None, "CHECK_COOKIE", "FAILED", "Cookie 已失效，已停止账号任务").await.ok();
                if notify_on_failure {
                    self.notifier.send_cookie_expired_alert(&account.alias, account.nickname.as_deref(), &reason, account.bark_key_override.as_deref()).await.ok();
                }
                Ok(false)
            }
            crate::douyin::types::CheckCookieResult::NeedVerify(reason) => {
                db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                self.record_log(&account.id, &account.alias, None, None, "CHECK_COOKIE", "FAILED", "当前账号需要安全验证，已停止账号任务").await.ok();
                if notify_on_failure {
                    self.notifier.send_cookie_expired_alert(&account.alias, account.nickname.as_deref(), &format!("需要安全验证: {reason}"), account.bark_key_override.as_deref()).await.ok();
                }
                Ok(false)
            }
            result @ crate::douyin::types::CheckCookieResult::NetworkError(_) => {
                self.record_log(&account.id, &account.alias, None, None, "CHECK_COOKIE", "FAILED", result.safe_diagnostic()).await.ok();
                Ok(false)
            }
        }
    }

    /// Execute spark tasks for a single account with retry mechanism and Bark alert
    /// 把抖音昵称、备注和火花状态写回已有目标。风控时只落库已经拿到的部分。
    async fn persist_live_profiles(&self, client: &DouyinClient, account: &Account) {
        let (Some(uid), Some(sec)) = (account.uid.as_deref(), account.sec_uid.as_deref()) else {
            return;
        };
        let Ok(friends) = client.fetch_following_friends(uid, sec).await else {
            tracing::warn!(account = %account.alias, "自动同步好友资料失败，保留库内数据");
            return;
        };
        if client.risk_limited() {
            tracing::warn!(account = %account.alias, "同步过程中遇到风控，仅落库已成功返回的资料");
        }
        let Ok(targets) = db::list_targets(&self.pool, Some(&account.id)).await else {
            return;
        };
        for target in targets {
            let matched = friends.iter().find(|f| {
                if target.conversation_type == 2 {
                    f.target_type == Some(2)
                        && (f.sec_uid == target.target_sec_uid
                            || f.conversation_id.as_deref() == Some(target.target_sec_uid.as_str())
                            || target.conversation_id.as_ref().is_some_and(|id| {
                                f.conversation_id.as_deref() == Some(id.as_str()) || f.sec_uid == *id
                            }))
                } else {
                    f.sec_uid == target.target_sec_uid
                        || target.target_uid.as_ref().is_some_and(|id| f.uid == *id)
                }
            });
            let Some(matched) = matched else { continue };
            if matched.nickname.trim().is_empty() {
                continue;
            }
            let _ = db::update_target(
                &self.pool,
                &target.id,
                &crate::model::UpdateTargetReq {
                    conversation_type: None,
                    is_enabled: None,
                    target_nickname: Some(matched.nickname.clone()),
                    remark_name: Some(matched.remark_name.clone().unwrap_or_default()),
                    target_avatar: if matched.avatar_url.is_empty() { None } else { Some(matched.avatar_url.clone()) },
                    spark_days: matched.spark_days,
                    spark_desc: matched.spark_desc.clone(),
                    is_sparked_today: None,
                    message_template: None,
                },
            )
            .await;
        }
    }

    pub async fn execute_single_account(&self, account_id: &str, force_resend: bool) -> Result<ExecutionSummary> {
        let account = db::get_account(&self.pool, account_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("账号不存在"))?;
        let result = self.execute_account(&account, force_resend).await;
        self.finish_account_execution(&account, result).await
    }

    async fn finish_account_execution(&self, account: &Account, result: Result<ExecutionSummary>) -> Result<ExecutionSummary> {
        let diagnostic = match &result {
            Err(error) => Some(ExecutionDiagnostic::classify(error)),
            Ok(summary) => summary.error_code.as_deref().and_then(|code| {
                [ExecutionDiagnostic::WebContextMissing, ExecutionDiagnostic::WebContextExpired,
                    ExecutionDiagnostic::WebContextInvalid, ExecutionDiagnostic::SendCredentialMissing,
                    ExecutionDiagnostic::SendCredentialInvalid, ExecutionDiagnostic::ConversationUnknown,
                    ExecutionDiagnostic::HistoryUnknown, ExecutionDiagnostic::SessionUnconfirmed,
                    ExecutionDiagnostic::AccountStopped].into_iter().find(|d| d.code() == code)
            }),
        };
        if let Some(diagnostic) = diagnostic {
            self.record_log(&account.id, &account.alias, None, None, "ACCOUNT_EXECUTION", "FAILED",
                &diagnostic.to_string()).await.context("账号停止诊断持久化失败")?;
        }
        // 不把未知错误原文传给调用方/批量容器日志。
        result.map_err(|error| ExecutionDiagnostic::classify(&error).into())
    }

    async fn execute_account(&self, account: &Account, force_resend: bool) -> Result<ExecutionSummary> {
        let account_id = account.id.as_str();
        if account.status == "DISABLED" {
            bail!("账号已被禁用");
        }

        let is_valid = self.check_account_cookie(account, !force_resend).await?;
        if !is_valid {
            let mut summary = ExecutionSummary::stopped(account, ExecutionDiagnostic::SessionUnconfirmed);
            summary.cookie_status = db::get_account(&self.pool, account_id).await?.context("账号不存在")?.status;
            return Ok(summary);
        }

        let account = db::get_account(&self.pool, account_id).await?.context("账号不存在")?;
        let plaintext_cookie = self.secret_box.decrypt(&account.encrypted_cookie)
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();

        let client = DouyinClient::new(&plaintext_cookie, &account.alias)?;
        client.load_web_context(&self.pool,&self.secret_box,&account.id,account.uid.as_deref()).await
            .context(ExecutionDiagnostic::WebContextInvalid)?;
        match client.check_cookie().await {
            crate::douyin::types::CheckCookieResult::Valid(_) => { client.verified_sender_uid(account.uid.as_deref()).context(ExecutionDiagnostic::SessionUnconfirmed)?; }
            _ => return Err(ExecutionDiagnostic::SessionUnconfirmed.into()),
        }
        self.prepare_im_identity(&client,&account).await?;
        let targets = db::list_targets(&self.pool, Some(&account.id)).await?;
        let enabled_targets: Vec<SparkTarget> = targets.into_iter().filter(|t| t.is_enabled).collect();

        let mut success_count = 0;
        let mut failed_count = 0;
        let mut skipped_count = 0;
        let mut stopped = false;
        let my_uid_num: u64 = account.uid.as_deref().and_then(|u| u.parse().ok()).unwrap_or(0);
        let mut targets_to_query = Vec::new();
        for t in &enabled_targets {
            if t.conversation_type == 2 {
                let cid = t.conversation_id.clone().unwrap_or_else(|| t.target_sec_uid.clone());
                targets_to_query.push(crate::douyin::client::DouyinTargetParam {
                    conv_id: cid.clone(),
                    conv_type: 2,
                    short_id: None,
                });
            } else if let Some(t_uid) = t.target_uid.as_deref().and_then(|u| u.parse::<u64>().ok()) {
                if my_uid_num > 0 {
                    let min_u = my_uid_num.min(t_uid);
                    let max_u = my_uid_num.max(t_uid);
                    let conv_id = format!("0:1:{min_u}:{max_u}");
                    targets_to_query.push(crate::douyin::client::DouyinTargetParam {
                        conv_id,
                        conv_type: 1,
                        short_id: None,
                    });
                }
            }
        }

        let live_spark_map = if !targets_to_query.is_empty() {
            client.fetch_available_conversation_spark_status(&targets_to_query).await
                .context(ExecutionDiagnostic::ConversationUnknown)?
        } else {
            std::collections::HashMap::new()
        };
        let retries_allowed = self.max_retries.load(Ordering::Relaxed).max(1);

        let target_result: Result<()> = async {
        for target in &enabled_targets {
            let (conv_id, short_id) = if target.conversation_type == 2 {
                let cid = target.conversation_id.clone().unwrap_or_else(|| target.target_sec_uid.clone());
                let sid = live_spark_map.get(&cid).map(|i| i.short_id).unwrap_or(0);
                (cid, sid)
            } else {
                let t_uid = target.target_uid.as_deref().and_then(|u| u.parse::<u64>().ok()).unwrap_or(0);
                let min_u = my_uid_num.min(t_uid);
                let max_u = my_uid_num.max(t_uid);
                let cid = format!("0:1:{min_u}:{max_u}");
                let sid = live_spark_map.get(&cid).map(|i| i.short_id).unwrap_or(0);
                (cid, sid)
            };

            let checked_at = Utc::now();
            db::record_target_today_state(&self.pool, &target.id, None, checked_at).await?;
            // 只认定当前账号在北京时间今天的成功发送，拒绝未来时间。
            let mut i_sent_today = crate::model::system_sent_today(
                target.last_status.as_deref(), target.last_sent_at, checked_at,
            );

            if !i_sent_today && my_uid_num > 0 && !conv_id.is_empty() {
                // 长批次可能跨过身份缓存期限，必须先刷新再读取目标历史。
                self.prepare_im_identity(&client,&account).await?;
                i_sent_today = client.check_i_sent_message_today(my_uid_num, &conv_id, target.conversation_type, short_id).await.context(ExecutionDiagnostic::HistoryUnknown)?;
            }

            db::record_target_today_state(&self.pool, &target.id, Some(i_sent_today), checked_at).await?;
            let spark_days_update = live_spark_map.get(&conv_id).map(|i| i.days);
            let spark_desc_update = live_spark_map.get(&conv_id).map(|i| i.desc.clone());
            let _ = db::update_target(&self.pool, &target.id, &crate::model::UpdateTargetReq {
                conversation_type: None,
                is_enabled: None,
                target_nickname: None,
                remark_name: None,
                target_avatar: None,
                spark_days: spark_days_update,
                spark_desc: spark_desc_update,
                is_sparked_today: None,
                message_template: None,
            }).await;

            let beijing_day_str = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive().to_string();
            let has_claim: bool = sqlx::query_scalar("SELECT COUNT(*) FROM im_send_attempts WHERE account_id=?1 AND conversation_id=?2 AND beijing_day=?3")
                .bind(&account.id).bind(&conv_id).bind(&beijing_day_str).fetch_one(&self.pool).await.unwrap_or(0) > 0;
            if has_claim || skip_sent_today(i_sent_today,force_resend) {
                skipped_count += 1;
                tracing::info!(target = %target.target_nickname, "今日已有发送占用或已在抖音发送，无需重复续火");
                continue;
            }

            self.prepare_target_delay(&client,&account,target).await?;
            self.prepare_im_identity(&client,&account).await?;
            self.load_send_credential(&client, &account, target).await?;

            let (result, attempt) = send_with_retry(retries_allowed, Duration::from_secs(3), || {
                client.send_spark_message(
                    target.conversation_id.as_deref(), target.conversation_type,
                    &target.target_sec_uid, target.target_uid.as_deref(), &target.message_template,
                )
            }).await;
            let postcheck = self.verify_send_session(&client,&account,Some(target),"SEND_POSTCHECK").await;

            if result.success {
                success_count += 1;
                let (real_days, spark_desc) = if let Some(t_uid) = target.target_uid.as_deref().and_then(|u| u.parse::<u64>().ok()) {
                    let min_u = my_uid_num.min(t_uid);
                    let max_u = my_uid_num.max(t_uid);
                    let conv_id = format!("0:1:{min_u}:{max_u}");
                    if let Some(info) = live_spark_map.get(&conv_id) {
                        (Some(info.days), Some(info.desc.clone()))
                    } else {
                        (result.spark_days, target.spark_desc.clone())
                    }
                } else {
                    (result.spark_days, target.spark_desc.clone())
                };
                let new_days = real_days.unwrap_or(target.spark_days);
                db::update_target_spark_result(
                    &self.pool,
                    &target.id,
                    "SUCCESS",
                    Some(new_days),
                    spark_desc.as_deref(),
                    None,
                ).await.ok();

                self.record_log(
                    &account.id,
                    &account.alias,
                    Some(&target.id),
                    Some(&target.target_nickname),
                    "SEND_SPARK",
                    "SUCCESS",
                    &result.message,
                ).await.ok();
            } else {
                failed_count += 1;
                db::update_target_spark_result(
                    &self.pool,
                    &target.id,
                    "FAILED",
                    None,
                    None,
                    Some(&result.message),
                ).await.ok();

                let fail_log_msg = format!("尝试 {attempt} 次后失败: {}", result.message);
                self.record_log(
                    &account.id,
                    &account.alias,
                    Some(&target.id),
                    Some(&target.target_nickname),
                    "SEND_SPARK",
                    "FAILED",
                    &fail_log_msg,
                ).await.ok();

                // 手动测试操作（force_resend == true）直接在网页前端提示结果，严禁向 Bark 发送推送通知打扰用户
                if !force_resend {
                    let alert_body = format!(
                        "对好友「{}」自动续火花尝试 {} 次后失败！\n原因: {}",
                        target.target_nickname, attempt, result.message
                    );
                    self.notifier.send_notification(
                        account.bark_key_override.as_deref(),
                        "【抖音火花助手】续火花最终失败告警",
                        &alert_body,
                        None,
                    ).await.ok();
                }
            }
            if result.is_fatal_failure() || client.sending_blocked() || postcheck.is_err() {
                stopped = true;
                client.clear_send_credential();
                skipped_count += enabled_targets.len() - success_count - failed_count - skipped_count;
                tracing::warn!(account = %account.id, "会话或鉴权失败，停止当前账号剩余发送");
                break;
            }
        }
        Ok(())
        }.await;
        let diagnostic = target_result.as_ref().err().map(ExecutionDiagnostic::classify);
        if diagnostic.is_some() {
            stopped = true;
            skipped_count = enabled_targets.len() - success_count - failed_count;
        }

        // Check if cookies changed during spark sending
        if target_result.is_ok() && client.is_cookie_changed() {
            let refreshed_cookie = client.get_current_cookie();
            if let Ok(new_encrypted) = self.secret_box.encrypt(refreshed_cookie.as_bytes()) {
                db::update_account_cookie(&self.pool, &account.id, &new_encrypted).await.ok();
                client.persist_web_context(&self.pool,&self.secret_box,&account.id).await.ok();
                self.record_log(
                    &account.id,
                    &account.alias,
                    None,
                    None,
                    "REFRESH_COOKIE",
                    "SUCCESS",
                    "互动流程中已观察到 Cookie 更新并加密保存，但未证实延长会话有效期",
                ).await.ok();
            }
        }
        client.persist_web_context(&self.pool, &self.secret_box, &account.id).await.ok();

        let cookie_status=db::get_account(&self.pool,&account.id).await?.context("执行后账号不存在")?.status;
        Ok(ExecutionSummary {
            account_id: account.id,
            account_alias: account.alias,
            cookie_status,
            total_targets: enabled_targets.len(),
            success_count,
            failed_count,
            skipped_count,
            status: if failed_count == 0 && !stopped { ExecutionStatus::Success }
                else if success_count > 0 { ExecutionStatus::PartialFailed } else { ExecutionStatus::Failed },
            error_code: diagnostic.map(|d| d.code().to_string()),
            message: diagnostic.map(|d| d.message().to_string()),
        })
    }

    /// Execute spark renewal for all active accounts sequentially
    pub async fn execute_all_accounts(&self, force_resend: bool) -> Result<BatchSummary> {
        if self.is_running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            bail!("已有续火花任务正在执行中，请勿重复触发");
        }

        let _guard = RunningGuard(self.is_running.clone());

        let accounts = db::list_accounts(&self.pool).await?;
        let mut summaries = Vec::new();
        let mut active_accounts = 0;

        for account in accounts {
            if account.status == "DISABLED" {
                continue;
            }
            active_accounts += 1;

            match self.execute_single_account(&account.id, force_resend).await {
                Ok(summary) => summaries.push(summary),
                Err(e) => {
                    let diagnostic = ExecutionDiagnostic::classify(&e);
                    tracing::error!(account = %account.id, error_code = diagnostic.code(), "账号任务失败");
                    summaries.push(ExecutionSummary::stopped(&account, diagnostic));
                }
            }

            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        Ok(BatchSummary::from_accounts(summaries, active_accounts))
    }

    /// 手动单目标测试：验证所属账号身份，仅一次发送，立即复查同一客户端凭证。
    pub async fn execute_single_target(&self, target_id: &str) -> Result<crate::douyin::types::SendSparkResult> {
        let target = db::get_target(&self.pool, target_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("续火花目标不存在"))?;

        let account = db::get_account(&self.pool, &target.account_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("对应账号不存在"))?;
        let result = self.execute_target_inner(&account, &target, true).await;
        if let Err(error) = &result {
            self.finish_account_execution(&account, Err(anyhow::anyhow!(ExecutionDiagnostic::classify(error)))).await?;
        }
        result
    }

    async fn execute_target(&self, account: &Account, target: &SparkTarget) -> Result<crate::douyin::types::SendSparkResult> {
        self.execute_target_inner(account, target, false).await
    }
    async fn execute_target_inner(&self, account: &Account, target: &SparkTarget, force: bool) -> Result<crate::douyin::types::SendSparkResult> {
        anyhow::ensure!(account.status != "DISABLED", "账号已被禁用");

        let cid = target_conversation_id(account,target)?;
        let day = Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive().to_string();
        let claim: Option<String> = sqlx::query_scalar("SELECT state FROM im_send_attempts WHERE account_id=?1 AND conversation_id=?2 AND beijing_day=?3")
            .bind(&account.id).bind(&cid).bind(day).fetch_optional(&self.pool).await?;
        if let Some(state) = claim {
            if !force {
                return Ok(crate::douyin::types::SendSparkResult::failure(if state=="ACCEPTED" {
                    "PCIM_INIT_DAY_CLAIM: 北京时间今日已确认发送，已跳过；禁止发送重试"
                } else { "PCIM_INIT_DAY_CLAIM: 当日已有未确认发送占用，未发起任何平台请求；禁止发送重试" }));
            }
        }
        let plaintext_cookie = self.secret_box.decrypt(&account.encrypted_cookie)
            .map_err(|e| anyhow::anyhow!("解密Cookie失败: {e}"))?;
        let cookie_str = String::from_utf8(plaintext_cookie)
            .map_err(|_| anyhow::anyhow!("无效的UTF-8 Cookie"))?;

        let client = DouyinClient::new(&cookie_str, &account.alias)?;
        client.load_web_context(&self.pool,&self.secret_box,&account.id,account.uid.as_deref()).await
            .context(ExecutionDiagnostic::WebContextInvalid)?;
        let before_profile = self.verify_send_session(&client, &account, Some(&target), "SEND_PREFLIGHT").await?;
        self.prepare_im_identity(&client,&account).await?;
        let conversation_id=target_conversation_id(account,target)?;
        let uid=client.verified_sender_uid(account.uid.as_deref())?;
        let checked_at=Utc::now();
        let sent=client.check_i_sent_message_today(uid,&conversation_id,target.conversation_type,0).await
            .context(ExecutionDiagnostic::HistoryUnknown)?;
        db::record_target_today_state(&self.pool,&target.id,Some(sent),checked_at).await?;
        if (!force && sent) || (!force && crate::model::system_sent_today(target.last_status.as_deref(),target.last_sent_at,Utc::now())) {
            return Ok(crate::douyin::types::SendSparkResult { success:false,message:"北京时间今日已发送，已跳过；未消费发送授权".into(),spark_days:None,raw_response:None });
        }
        self.prepare_im_identity(&client,&account).await?;
        self.load_send_credential_force(&client, &account, &target, force).await?;
        let (result, attempts) = send_with_retry(1, Duration::ZERO, || {
            client.send_spark_message(
                target.conversation_id.as_deref(), target.conversation_type,
                &target.target_sec_uid, target.target_uid.as_deref(), &target.message_template,
            )
        }).await;
        // 在任何后续 IM 请求之前复查刚刚执行发送的同一客户端、同一会话。
        let postcheck = self.verify_send_session(&client, &account, Some(&target), "SEND_POSTCHECK").await;
        if result.is_fatal_failure() || client.sending_blocked() {
            client.clear_send_credential();
        }

        if client.is_cookie_changed() {
            let refreshed = client.get_current_cookie();
            if let Ok(new_enc) = self.secret_box.encrypt(refreshed.as_bytes()) {
                db::update_account_cookie(&self.pool, &account.id, &new_enc).await.ok();
            }
        }
        client.persist_web_context(&self.pool, &self.secret_box, &account.id).await.ok();

        if result.success {
            let new_days = target.spark_days;
            let spark_desc = target.spark_desc.clone();
            db::update_target_spark_result(
                &self.pool,
                &target.id,
                "SUCCESS",
                Some(new_days),
                spark_desc.as_deref(),
                None,
            ).await.ok();

            self.record_log(
                &account.id,
                &account.alias,
                Some(&target.id),
                Some(&target.target_nickname),
                "SEND_SPARK",
                "SUCCESS",
                &result.message,
            ).await.ok();
        } else {
            db::update_target_spark_result(
                &self.pool,
                &target.id,
                "FAILED",
                None,
                None,
                Some(&result.message),
            ).await.ok();

            self.record_log(
                &account.id,
                &account.alias,
                Some(&target.id),
                Some(&target.target_nickname),
                "SEND_SPARK",
                "FAILED",
                &format!("手动单目标尝试 {attempts} 次后失败: {}", result.message),
            ).await.ok();

            // 手动测试操作（force == true）直接在网页前端提示结果，严禁向 Bark 发送推送通知打扰用户
            if !force {
                self.notifier.send_notification(
                    account.bark_key_override.as_deref(),
                    "【抖音火花助手】续火花失败",
                    &format!("对好友「{}」续火花尝试失败: {}", target.target_nickname, result.message),
                    None,
                ).await.ok();
            }
        }
        if let Err(e) = postcheck {
            tracing::warn!(account = %account.id, error = %e, "发送后登录态复查未通过");
        }
        tracing::info!(account = %account.id, sender_uid = %before_profile.uid, target_uid = ?target.target_uid, success = result.success, attempts, "单目标发送结束");

        Ok(result)
    }

    async fn prepare_im_identity(&self,client:&DouyinClient,account:&Account) -> Result<()> {
        client.prepare_im_identity(account.uid.as_deref()).await.context(ExecutionDiagnostic::IdentityRefreshFailed)?;
        let current=db::get_account(&self.pool,&account.id).await?.context(ExecutionDiagnostic::SessionUnconfirmed)?;
        let original=String::from_utf8(self.secret_box.decrypt(&account.encrypted_cookie)?)?;
        let stored=String::from_utf8(self.secret_box.decrypt(&current.encrypted_cookie)?)?;
        anyhow::ensure!(current.status=="ACTIVE" && current.uid==account.uid
            && (stored==original || stored==client.get_current_cookie()),ExecutionDiagnostic::SessionUnconfirmed);
        client.persist_im_session(&self.pool,&self.secret_box,&account.id,&current.encrypted_cookie,account.uid.as_deref()).await
            .context(ExecutionDiagnostic::IdentityRefreshFailed)
    }

    async fn load_send_credential(&self, client: &DouyinClient, account: &Account, target: &SparkTarget) -> Result<()> {
        self.load_send_credential_force(client, account, target, false).await
    }
    async fn load_send_credential_force(&self, client: &DouyinClient, account: &Account, target: &SparkTarget, force: bool) -> Result<()> {
        let result: Result<()> = async {
            client.clear_send_credential();
            let current = db::get_account(&self.pool,&account.id).await?.context(ExecutionDiagnostic::SessionUnconfirmed)?;
            let original = String::from_utf8(self.secret_box.decrypt(&account.encrypted_cookie)?)?;
            let stored = String::from_utf8(self.secret_box.decrypt(&current.encrypted_cookie)?)?;
            anyhow::ensure!(current.status=="ACTIVE" && current.uid==account.uid
                && (stored==original || stored==client.get_current_cookie()),ExecutionDiagnostic::SessionUnconfirmed);
            client.configure_pcim_initial_force(self.pool.clone(),current.encrypted_cookie,account,target,force)
        }.await;
        result.map_err(|error| {
            let diagnostic = error.downcast_ref::<ExecutionDiagnostic>().copied()
                .unwrap_or(ExecutionDiagnostic::SendCredentialInvalid);
            diagnostic.into()
        })
    }


    async fn verify_send_session(
        &self, client: &DouyinClient, account: &Account, target: Option<&SparkTarget>, action: &str,
    ) -> Result<crate::douyin::types::DouyinUserProfile> {
        let checked = client.check_cookie().await;
        let profile = match checked {
            crate::douyin::types::CheckCookieResult::Valid(profile) => {
                if let Err(e) = client.verified_sender_uid(account.uid.as_deref()) {
                    db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                    self.record_log(&account.id, &account.alias, target.map(|t| t.id.as_str()), target.map(|t| t.target_nickname.as_str()), action, "FAILED", ExecutionDiagnostic::SessionUnconfirmed.message()).await?;
                    return Err(e);
                }
                profile
            }
            failure => {
                if !matches!(failure, crate::douyin::types::CheckCookieResult::NetworkError(_)) {
                    db::update_account_status(&self.pool, &account.id, "EXPIRED", Utc::now()).await?;
                }
                let message = ExecutionDiagnostic::SessionUnconfirmed.message();
                self.record_log(&account.id, &account.alias, target.map(|t| t.id.as_str()), target.map(|t| t.target_nickname.as_str()), action, "FAILED", &message).await?;
                bail!("{message}");
            }
        };
        db::update_account_status(&self.pool, &account.id, "ACTIVE", Utc::now()).await?;
        self.record_log(&account.id, &account.alias, target.map(|t| t.id.as_str()), target.map(|t| t.target_nickname.as_str()), action, "SUCCESS", &format!("同一客户端会话凭证有效，确认 uid={}", profile.uid)).await?;
        Ok(profile)
    }

    async fn record_log(
        &self,
        account_id: &str,
        account_alias: &str,
        target_id: Option<&str>,
        target_nickname: Option<&str>,
        action_type: &str,
        status: &str,
        message: &str,
    ) -> Result<()> {
        let log = SparkLog {
            id: uuid::Uuid::new_v4().to_string(),
            account_id: account_id.to_string(),
            account_alias: account_alias.to_string(),
            target_id: target_id.map(|s| s.to_string()),
            target_nickname: target_nickname.map(|s| s.to_string()),
            action_type: action_type.to_string(),
            status: status.to_string(),
            message: message.to_string(),
            created_at: Utc::now(),
        };

        db::insert_log(&self.pool, &log).await
    }
}

pub fn start_daily_scheduler(engine: Arc<SparkEngine>) {
    tokio::spawn(async move {
        tracing::info!("每日续火花调度器已启动");
        let mut last_executed_date: Option<String> = None;

        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            let now = Local::now();
            let today_str = now.format("%Y-%m-%d").to_string();
            let current_time_str = now.format("%H:%M").to_string();

            let target_time = {
                let guard = engine.schedule_time.read().await;
                guard.clone()
            };

            if current_time_str == target_time {
                if last_executed_date.as_deref() != Some(&today_str) {
                    tracing::info!(time = %current_time_str, date = %today_str, "触发每日自动续火花任务");
                    last_executed_date = Some(today_str);

                    let engine_clone = engine.clone();
                    tokio::spawn(async move {
                        match engine_clone.execute_all_accounts(false).await {
                            Err(_) => tracing::error!("每日自动续火花执行失败（任务未完成）"),
                            Ok(summary) => match summary.status {
                                ExecutionStatus::Failed => tracing::error!(failed_accounts = summary.failed_accounts, "每日自动续火花执行失败"),
                                ExecutionStatus::PartialFailed => tracing::warn!(failed_accounts = summary.failed_accounts, partial_failed_accounts = summary.partial_failed_accounts, "每日自动续火花部分失败"),
                                ExecutionStatus::Success => tracing::info!("每日自动续火花正常结束"),
                            },
                        }
                    });
                }
            }
        }
    });
}

impl SparkEngine {
    /// 定期巡检活跃账号状态并保存 Cookie 变化；未证实延长会话有效期。
    pub async fn heartbeat_all_active_accounts(&self) -> Result<()> {
        let accounts = db::list_accounts(&self.pool).await?;
        let sync_profiles = claim_profile_sync();
        for account in accounts {
            if account.status != "ACTIVE" {
                continue;
            }
            if !self.check_account_cookie(&account, true).await.unwrap_or(false) { continue; }
            if !sync_profiles {
                continue;
            }
            let Ok(plain) = self.secret_box.decrypt(&account.encrypted_cookie) else {
                continue;
            };
            let Ok(cookie) = String::from_utf8(plain) else {
                continue;
            };
            let Ok(client) = DouyinClient::new(&cookie, &account.alias) else {
                continue;
            };
            if client.load_web_context(&self.pool,&self.secret_box,&account.id,account.uid.as_deref()).await.is_err() { continue; }
            self.persist_live_profiles(&client, &account).await;
            if client.risk_limited() {
                tracing::warn!("自动资料同步遇到风控，本轮剩余账号不再请求");
                break;
            }
        }
        Ok(())
    }
}

pub fn start_heartbeat_worker(engine: Arc<SparkEngine>) {
    tokio::spawn(async move {
        tracing::info!("抖音 Web 登录态巡检已启用（每 300 秒检查；不保证延长会话有效期）");
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            if let Err(e) = engine.heartbeat_all_active_accounts().await {
                tracing::debug!(error = %e, "定时心跳维持异常");
            }
        }
    });
}

fn claim_profile_sync() -> bool {
    use std::sync::atomic::{AtomicI64, Ordering};
    static LAST: AtomicI64 = AtomicI64::new(0);
    let now = Utc::now().timestamp();
    let prev = LAST.load(Ordering::Relaxed);
    if prev != 0 && now.saturating_sub(prev) < 6 * 3600 {
        return false;
    }
    LAST.store(now, Ordering::Relaxed);
    true
}


#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::douyin::types::SendSparkResult;

    #[tokio::test]
    async fn fatal_auth_and_session_errors_never_retry() {
        for message in ["unexepcted session length", "unexpected session length", "invalid auth token", "HTTP错误: 401", "HTTP错误: 403", "conversation not found", "需要安全验证", "发送身份不符，禁止发送", "PCIM_INIT_UNCONFIRMED: 未确认发送成功或当日已占用；禁止发送重试"] {
            let calls = AtomicU32::new(0);
            let (result, attempts) = send_with_retry(5, Duration::ZERO, || {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::ready(SendSparkResult::failure(message))
            }).await;
            assert!(!result.success);
            assert_eq!(attempts, 1, "{message}");
            assert_eq!(calls.load(Ordering::Relaxed), 1, "{message}");
        }
    }

    #[tokio::test]
    async fn manual_send_budget_is_one_even_for_nonfatal_errors() {
        let calls = AtomicU32::new(0);
        let (_, attempts) = send_with_retry(1, Duration::ZERO, || {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(SendSparkResult::failure("HTTP错误: 500"))
        }).await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn nonfatal_errors_respect_automatic_retry_budget() {
        let calls = AtomicU32::new(0);
        let (_, attempts) = send_with_retry(3, Duration::ZERO, || {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(SendSparkResult::failure("HTTP错误: 500"))
        }).await;
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(attempts, 3);
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use crate::douyin::im_auth::{WebSessionContext, test_credential};

    const COOKIE: &str = "sessionid=offline-secret-cookie; msToken=offline-secret-token";
    const CONVERSATION: &str = "0:1:55696816245:99191692311";

    async fn fixture() -> (SparkEngine, Account, SparkTarget) {
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[19; 32]);
        let engine = SparkEngine::new(pool, secret, BarkNotifier::new("http://127.0.0.1:1".into(), None), "08:00".into(), 0, 0, 5);
        let now = Utc::now();
        let account = Account {
            id: "offline-account".into(), alias: "离线账号".into(), sec_uid: None,
            uid: Some("99191692311".into()), nickname: None, avatar_url: None,
            encrypted_cookie: engine.secret_box.encrypt(COOKIE.as_bytes()).unwrap(),
            status: "ACTIVE".into(), bark_key_override: None, last_checked_at: None,
            created_at: now, updated_at: now,
        };
        db::insert_account(&engine.pool, &account).await.unwrap();
        let target = SparkTarget {
            id: "offline-target".into(), account_id: account.id.clone(), target_sec_uid: "offline-peer".into(),
            target_uid: Some("55696816245".into()), conversation_id: Some(CONVERSATION.into()),
            conversation_type: 1, target_nickname: "离线目标".into(), remark_name: None, target_avatar: None,
            is_enabled: true, spark_days: 0, spark_desc: None, is_sparked_today: None, today_checked_at: None,
            message_template: "offline-secret-message".into(), last_sent_at: None, last_status: None, last_error: None,
            created_at: now, updated_at: now,
        };
        db::insert_target(&engine.pool, &target).await.unwrap();
        (engine, account, target)
    }

    #[tokio::test]
    async fn all_accounts_load_native_without_captured_credentials() {
        let (engine,account,mut target)=fixture().await;
        let client=DouyinClient::new(COOKIE,"offline native").unwrap();
        engine.load_send_credential(&client,&account,&target).await.unwrap();
        target.message_template="other".into();
        engine.load_send_credential(&client,&account,&target).await.unwrap();
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM account_im_credentials").fetch_one(&engine.pool).await.unwrap();assert_eq!(count,0);
        for force in [true,false] {assert!(skip_sent_today(true,force));assert!(!skip_sent_today(false,force));}
    }

    async fn assert_diagnostic(engine: &SparkEngine, account: &Account, expected: ExecutionDiagnostic) {
        let logs: Vec<SparkLog> = sqlx::query_as("SELECT * FROM spark_logs WHERE account_id=? ORDER BY created_at")
            .bind(&account.id).fetch_all(&engine.pool).await.unwrap();
        assert_eq!(logs.len(), 1, "停止只记录一次账号诊断，不伪造发送日志");
        assert_eq!(logs[0].action_type, "ACCOUNT_EXECUTION");
        assert_eq!(logs[0].status, "FAILED");
        assert_eq!(logs[0].message, expected.to_string());
        assert!(logs[0].target_id.is_none());
        let serialized = serde_json::to_string(&logs).unwrap();
        for secret in ["offline-secret", "fake-token", "fake-signature", "test-conversation-ticket", "bd-ticket-guard", "identity_security"] {
            assert!(!serialized.contains(secret), "诊断泄露材料: {secret}");
        }
        let target = db::get_target(&engine.pool, "offline-target").await.unwrap().unwrap();
        assert!(target.last_sent_at.is_none());
        assert!(target.last_status.is_none());
        assert!(target.last_error.is_none());
    }

    fn summary(account: &Account, status: ExecutionStatus) -> ExecutionSummary {
        let mut summary = ExecutionSummary::stopped(account, ExecutionDiagnostic::AccountStopped);
        summary.status = status;
        summary.error_code = None;
        summary.message = None;
        summary
    }

    #[tokio::test]
    async fn two_account_batch_reports_all_partial_and_no_failures() {
        let (_, account, _) = fixture().await;
        for (statuses, expected, successful, failed, partial) in [
            ([ExecutionStatus::Failed, ExecutionStatus::Failed], ExecutionStatus::Failed, 0, 2, 0),
            ([ExecutionStatus::Success, ExecutionStatus::Failed], ExecutionStatus::PartialFailed, 1, 1, 0),
            ([ExecutionStatus::Success, ExecutionStatus::Success], ExecutionStatus::Success, 2, 0, 0),
            ([ExecutionStatus::Success, ExecutionStatus::PartialFailed], ExecutionStatus::PartialFailed, 1, 0, 1),
        ] {
            let mut accounts: Vec<_> = statuses.into_iter().map(|status| summary(&account, status)).collect();
            accounts[1].account_id = "second-account".into();
            let batch = BatchSummary::from_accounts(accounts, 2);
            assert_eq!(batch.status, expected);
            assert_eq!((batch.total_accounts, batch.active_accounts), (2, 2));
            assert_eq!((batch.successful_accounts, batch.failed_accounts, batch.partial_failed_accounts), (successful, failed, partial));
            assert_eq!(serde_json::to_value(&batch).unwrap()["status"], match expected {
                ExecutionStatus::Success => "SUCCESS", ExecutionStatus::PartialFailed => "PARTIAL_FAILED", ExecutionStatus::Failed => "FAILED",
            });
            assert_eq!(batch.completion_message().contains("正常"), expected == ExecutionStatus::Success);
        }
    }

    #[tokio::test]
    async fn optional_context_load_missing_and_expired_im_failures_are_persisted_safely() {
        for expired in [false, true] {
            let (engine, account, _) = fixture().await;
            let client = DouyinClient::new(COOKIE, &account.alias).unwrap();
            let result = if expired {
                let mut context = WebSessionContext::from_credential(&test_credential(COOKIE, CONVERSATION, 1));
                context.captured_at -= 601;
                let encrypted = engine.secret_box.encrypt(&serde_json::to_vec(&context).unwrap()).unwrap();
                sqlx::query("INSERT INTO account_web_contexts VALUES(?,?)").bind(&account.id).bind(encrypted).execute(&engine.pool).await.unwrap();
                // 装载本身不校验 IM 时效，直到后续 IM 请求才拒绝；无需网络。
                client.load_web_context(&engine.pool, &engine.secret_box, &account.id, account.uid.as_deref()).await.unwrap();
                context.im_request(99191692311, COOKIE, 610, &[]).map(|_| ())
            } else {
                // 缺失上下文是可选装载成功，必须覆盖后续 ensure/fetch 错误。
                client.load_web_context(&engine.pool, &engine.secret_box, &account.id, account.uid.as_deref()).await.unwrap();
                client.web_im("https://imapi.douyin.com/v2/conversation/get_info_list", 610, &[]).await.map(|_| ())
            };
            let expected = if expired { ExecutionDiagnostic::WebContextExpired } else { ExecutionDiagnostic::WebContextMissing };
            let result = result.context(ExecutionDiagnostic::ConversationUnknown).map(|_| unreachable!());
            assert!(engine.finish_account_execution(&account, result).await.is_err());
            assert_diagnostic(&engine, &account, expected).await;
            assert_eq!(db::get_account(&engine.pool, &account.id).await.unwrap().unwrap().status, "ACTIVE");
        }
    }

    #[tokio::test]
    async fn invalid_native_binding_stops_before_retry_and_persists_diagnostic() {
        let (engine, account, mut target) = fixture().await;target.is_enabled=false;
        let client = DouyinClient::new(COOKIE, &account.alias).unwrap();
        let calls = AtomicU32::new(0);
        let result: Result<ExecutionSummary> = async {
            engine.load_send_credential(&client, &account, &target).await?;
            // 与生产调用顺序一致：装载失败不得进入发送重试循环。
            send_with_retry(5, Duration::ZERO, || {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::ready(crate::douyin::types::SendSparkResult::failure("不应执行"))
            }).await;
            unreachable!()
        }.await;
        assert!(engine.finish_account_execution(&account, result).await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_diagnostic(&engine, &account, ExecutionDiagnostic::SendCredentialInvalid).await;
    }

    #[tokio::test]
    async fn public_single_account_persists_early_context_load_failure() {
        let (engine, account, _) = fixture().await;
        let encrypted = engine.secret_box.encrypt(b"offline-secret-malformed-context").unwrap();
        sqlx::query("INSERT INTO account_web_contexts VALUES(?,?)").bind(&account.id).bind(encrypted).execute(&engine.pool).await.unwrap();
        let error = engine.execute_single_account(&account.id, false).await.unwrap_err();
        assert_eq!(ExecutionDiagnostic::classify(&error), ExecutionDiagnostic::WebContextInvalid);
        assert_diagnostic(&engine, &account, ExecutionDiagnostic::WebContextInvalid).await;
        assert_eq!(db::get_account(&engine.pool, &account.id).await.unwrap().unwrap().status, "ACTIVE");
    }

    #[tokio::test]
    async fn real_batch_persists_both_account_stops_without_send_attempts() {
        let (engine, account, _) = fixture().await;
        let mut second = account.clone();
        second.id = "second-account".into();
        second.alias = "第二离线账号".into();
        db::insert_account(&engine.pool, &second).await.unwrap();
        for account in [&account, &second] {
            let encrypted = engine.secret_box.encrypt(b"offline-secret-invalid-context").unwrap();
            sqlx::query("INSERT INTO account_web_contexts VALUES(?,?)").bind(&account.id).bind(encrypted).execute(&engine.pool).await.unwrap();
        }
        let batch = engine.execute_all_accounts(false).await.unwrap();
        assert_eq!(batch.status, ExecutionStatus::Failed);
        assert_eq!(batch.failed_accounts, 2);
        assert_eq!(batch.successful_accounts, 0);
        assert_eq!(batch.accounts.len(), 2);
        for summary in &batch.accounts {
            assert_eq!(summary.error_code.as_deref(), Some("WEB_CONTEXT_INVALID"));
            assert_eq!(summary.failed_count, 0, "账号停止不是失败的发送尝试");
        }
        assert_diagnostic(&engine, &account, ExecutionDiagnostic::WebContextInvalid).await;
        assert_diagnostic(&engine, &second, ExecutionDiagnostic::WebContextInvalid).await;
        assert!(!engine.is_running.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn partial_account_preserves_real_send_counts_when_later_target_stops() {
        let (engine, account, _) = fixture().await;
        let mut partial = summary(&account, ExecutionStatus::PartialFailed);
        partial.total_targets = 2;
        partial.success_count = 1;
        partial.skipped_count = 1;
        partial.error_code = Some(ExecutionDiagnostic::HistoryUnknown.code().into());
        partial.message = Some(ExecutionDiagnostic::HistoryUnknown.message().into());
        let partial = engine.finish_account_execution(&account, Ok(partial)).await.unwrap();
        assert_eq!((partial.success_count, partial.failed_count, partial.skipped_count), (1, 0, 1));
        assert_eq!(partial.status, ExecutionStatus::PartialFailed);
        assert_diagnostic(&engine, &account, ExecutionDiagnostic::HistoryUnknown).await;
    }

    #[tokio::test]
    async fn unknown_error_is_never_persisted_verbatim() {
        let (engine, account, _) = fixture().await;
        let error = anyhow::anyhow!("sessionid=offline-secret; bd-ticket-guard=offline-secret; unknown failure");
        let result = engine.finish_account_execution(&account, Err(error)).await;
        assert!(result.is_err());
        assert_diagnostic(&engine, &account, ExecutionDiagnostic::AccountStopped).await;
    }

    #[tokio::test]
    async fn changed_delay_wakes_existing_wait_and_clones_share_range() {
        let (engine,_,_)=fixture().await;
        engine.set_delay_range(1024,1024);
        let copy=engine.clone();
        let waiting=tokio::spawn(async move {copy.wait_target_delay().await;});
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        engine.set_delay_range(0,0);
        assert_eq!(engine.clone().delay_range(),(0,0));
        tokio::time::timeout(Duration::from_secs(1),waiting).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pending_setting_change_wins_when_old_timer_is_also_ready() {
        let (engine,_,_)=fixture().await;engine.set_delay_range(1,1);
        let copy=engine.clone();let mut waiting=tokio::spawn(async move {copy.wait_target_delay().await;});
        tokio::time::sleep(Duration::from_millis(20)).await;
        // 当前线程阻塞使旧计时器与修改通知在下一次轮询时同时就绪。
        std::thread::sleep(Duration::from_millis(1100));engine.set_delay_range(1024,1024);
        assert!(tokio::time::timeout(Duration::from_millis(30),&mut waiting).await.is_err());
        engine.set_delay_range(0,0);tokio::time::timeout(Duration::from_secs(1),waiting).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn invalid_target_stops_before_long_random_delay_without_network() {
        let (engine,account,mut target)=fixture().await;target.is_enabled=false;
        engine.set_delay_range(1024,1024);
        let client=DouyinClient::new(COOKIE,"offline").unwrap();
        let error=tokio::time::timeout(Duration::from_secs(1),engine.prepare_target_delay(&client,&account,&target)).await.unwrap().unwrap_err();
        assert_eq!(ExecutionDiagnostic::classify(&error),ExecutionDiagnostic::SendCredentialInvalid);
        let logs:(i64,)=sqlx::query_as("SELECT count(*) FROM spark_logs").fetch_one(&engine.pool).await.unwrap();
        assert_eq!(logs.0,0);
    }
    #[tokio::test]
    async fn manual_existing_claim_stops_before_client_creation_or_network() {
        for state in ["UNKNOWN","ACCEPTED"] {
            let (engine,mut account,target)=fixture().await;
            let day=Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8*3600).unwrap()).date_naive().to_string();
            sqlx::query("INSERT INTO im_send_attempts(account_id,conversation_id,beijing_day,client_message_id,state) VALUES(?1,?2,?3,'fixture-claim',?4)")
                .bind(&account.id).bind(CONVERSATION).bind(day).bind(state).execute(&engine.pool).await.unwrap();
            account.encrypted_cookie=vec![]; // 若进入解密/网络流程，测试必须失败。
            let result=engine.execute_target(&account,&target).await.unwrap();
            assert!(!result.success);assert!(result.message.starts_with("PCIM_INIT_DAY_CLAIM:"));
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM spark_logs").fetch_one(&engine.pool).await.unwrap();assert_eq!(count,0);
        }
    }

    #[tokio::test]
    async fn check_account_cookie_respects_notify_on_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pool = db::init_pool("sqlite::memory:").await.unwrap();
        let secret = SecretBox::new(&[19; 32]);
        let notifier = BarkNotifier::new(format!("http://127.0.0.1:{port}"), Some("test-key".into()));
        let engine = SparkEngine::new(pool, secret, notifier, "08:00".into(), 0, 0, 5);

        let account = Account {
            id: "bad-cookie-account".into(),
            alias: "测试账号".into(),
            sec_uid: None,
            uid: Some("12345".into()),
            nickname: None,
            avatar_url: None,
            encrypted_cookie: vec![0, 1, 2], // 错误的加密数据，解密必失败
            status: "ACTIVE".into(),
            bark_key_override: None,
            last_checked_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_account(&engine.pool, &account).await.unwrap();

        // 1. 静默检测（notify_on_failure = false）：必须不向 Bark 发送任何网络请求
        let is_valid = engine.check_account_cookie(&account, false).await.unwrap();
        assert!(!is_valid);
        let accept_result = tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(accept_result.is_err(), "静默检测严禁向 Bark 发送请求");

        // 2. 后台巡检/告警模式（notify_on_failure = true）：必须向 Bark 触发告警
        let is_valid = engine.check_account_cookie(&account, true).await.unwrap();
        assert!(!is_valid);
        let accept_result = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
        assert!(accept_result.is_ok(), "后台检测失败时应向 Bark 发送告警");
    }
}
