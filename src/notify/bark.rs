use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

#[derive(Clone)]
pub struct BarkNotifier {
    client: Client,
    pub default_server: String,
    pub default_key: Option<String>,
    pub manual_silence_timestamp: Arc<AtomicI64>,
    pub scheduler_alert_enabled: Arc<AtomicBool>,
}

#[derive(Serialize)]
struct BarkPayload<'a> {
    device_key: &'a str,
    title: &'a str,
    body: &'a str,
    group: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    level: &'a str,
}

impl BarkNotifier {
    pub fn new(default_server: String, default_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build bark reqwest client");

        Self {
            client,
            default_server,
            default_key,
            manual_silence_timestamp: Arc::new(AtomicI64::new(0)),
            scheduler_alert_enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_silence_timestamp(&mut self, timestamp: Arc<AtomicI64>) {
        self.manual_silence_timestamp = timestamp;
    }

    pub fn set_scheduler_alert_enabled(&self, enabled: bool) {
        self.scheduler_alert_enabled
            .store(enabled, Ordering::Relaxed);
    }

    pub async fn send_notification(
        &self,
        key_override: Option<&str>,
        title: &str,
        body: &str,
        jump_url: Option<&str>,
    ) -> Result<()> {
        if !self.scheduler_alert_enabled.load(Ordering::Relaxed) {
            tracing::info!(
                "Bark 推送已物理硬拦截：当前非每日定时任务执行期，严禁向 Bark 发送任何告警通知"
            );
            return Ok(());
        }

        let last = self.manual_silence_timestamp.load(Ordering::Relaxed);
        if last > 0 {
            let now = chrono::Utc::now().timestamp();
            let diff = now - last;
            if (-60..=1800).contains(&diff) {
                tracing::info!(
                    diff_secs = diff,
                    "Bark 推送已物理拦截：处于前台手动操作静默期 (30分钟窗口内)"
                );
                return Ok(());
            }
        }

        let target_key = key_override
            .filter(|k| !k.trim().is_empty())
            .or(self.default_key.as_deref().filter(|k| !k.trim().is_empty()));

        let key = match target_key {
            Some(k) => k,
            None => {
                tracing::info!("Bark 推送已跳过: 未配置全局或账号独立 Bark Key");
                return Ok(());
            }
        };

        let server = self.default_server.trim_end_matches('/');
        let push_url = format!("{server}/push");

        let payload = BarkPayload {
            device_key: key,
            title,
            body,
            group: "抖音火花助手",
            url: jump_url,
            level: "active",
        };

        let res = self
            .client
            .post(&push_url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("failed to send Bark push to {push_url}"))?;

        let status = res.status();
        if !status.is_success() {
            bail!("Bark 服务返回错误状态码: {status}");
        }

        let json = res.json::<Value>().await.ok();
        if let Some(json) = json {
            if let Some(code) = json.get("code").and_then(|c| c.as_i64()) {
                if code != 200 {
                    let msg = json
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("未知原因");
                    bail!("Bark 推送失败 (code={code}): {msg}");
                }
            }
        }

        tracing::info!(title = %title, "Bark 通知发送成功");
        Ok(())
    }

    pub async fn send_cookie_expired_alert(
        &self,
        account_alias: &str,
        nickname: Option<&str>,
        reason: &str,
        key_override: Option<&str>,
    ) -> Result<()> {
        if !self.scheduler_alert_enabled.load(Ordering::Relaxed) {
            tracing::info!(
                "Bark 失效告警已物理硬拦截：当前非每日定时任务执行期，严禁向 Bark 发送任何告警通知"
            );
            return Ok(());
        }

        let last = self.manual_silence_timestamp.load(Ordering::Relaxed);
        if last > 0 {
            let now = chrono::Utc::now().timestamp();
            let diff = now - last;
            if (-60..=1800).contains(&diff) {
                tracing::info!(
                    diff_secs = diff,
                    "Bark 失效告警已物理拦截：处于前台手动操作静默期 (30分钟窗口内)"
                );
                return Ok(());
            }
        }
        let display_name = nickname.unwrap_or("未命名账号");
        let title = "【抖音火花助手】账号凭证失效";
        let body = format!(
            "账号「{account_alias}」（{display_name}）登录凭证已失效！\n原因: {reason}\n请前往 SparkLight 控制台重新填入有效 Cookie。"
        );

        self.send_notification(key_override, title, &body, None)
            .await
    }

    /// 登录会话临近到期提醒。平台不提供无交互滑动续期，`sid_guard` 到期后必须重新登录同步。
    pub async fn send_cookie_expiring_alert(
        &self,
        account_alias: &str,
        nickname: Option<&str>,
        remaining_days: i64,
        key_override: Option<&str>,
    ) -> Result<()> {
        if !self.scheduler_alert_enabled.load(Ordering::Relaxed) {
            tracing::info!(
                "Bark 到期提醒已物理硬拦截：当前非每日定时任务执行期，严禁向 Bark 发送任何告警通知"
            );
            return Ok(());
        }
        let last = self.manual_silence_timestamp.load(Ordering::Relaxed);
        if last > 0 {
            let now = chrono::Utc::now().timestamp();
            let diff = now - last;
            if (-60..=1800).contains(&diff) {
                tracing::info!(
                    diff_secs = diff,
                    "Bark 到期提醒已物理拦截：处于前台手动操作静默期 (30分钟窗口内)"
                );
                return Ok(());
            }
        }
        let display_name = nickname.unwrap_or("未命名账号");
        let title = "【抖音火花助手】登录凭证即将到期";
        let body = format!(
            "账号「{account_alias}」（{display_name}）登录凭证约 {remaining_days} 天后到期。\n抖音网页端登录会话由服务端固定有效期，无法自动续期；请在到期前重新登录并同步一次凭证，避免续火花中断。"
        );

        self.send_notification(key_override, title, &body, None)
            .await
    }

    pub async fn test_push(server: &str, key: &str) -> Result<()> {
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        let server = server.trim_end_matches('/');
        let push_url = format!("{server}/push");

        let payload = BarkPayload {
            device_key: key,
            title: "【抖音火花助手】测试推送",
            body: "恭喜！Bark 推送服务配置成功，您将能正常收到 Cookie 失效与续火花告警通知。",
            group: "抖音火花助手",
            url: None,
            level: "active",
        };

        let res = client
            .post(&push_url)
            .json(&payload)
            .send()
            .await
            .context("failed to reach Bark server")?;

        if !res.status().is_success() {
            bail!("Bark 返回 HTTP 状态: {}", res.status());
        }

        let json = res.json::<Value>().await.ok();
        if let Some(json) = json {
            if let Some(code) = json.get("code").and_then(|c| c.as_i64()) {
                if code != 200 {
                    let msg = json
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("未知");
                    bail!("Bark 响应失败 (code={code}): {msg}");
                }
            }
        }

        Ok(())
    }
}
