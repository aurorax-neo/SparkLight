//! 浏览器提供 Cookie，Rust 验证并原子同步只读 IM 身份；不生成或导入发送签名。
use super::*;

impl DouyinClient {
    pub async fn sync_browser_session(
        &self,
        pool: &sqlx::SqlitePool,
        secret: &crate::crypto::SecretBox,
        account_id: &str,
        original_cookie: &[u8],
        expected_uid: &str,
    ) -> Result<()> {
        anyhow::ensure!(expected_uid.parse::<u64>().is_ok_and(|uid| uid > 0), "BROWSER_SYNC_UID_REQUIRED");
        anyhow::ensure!(matches!(self.check_cookie().await, CheckCookieResult::Valid(_)), "BROWSER_SYNC_PROFILE_FAILED");
        self.verified_sender_uid(Some(expected_uid)).map_err(|_| anyhow::anyhow!("BROWSER_SYNC_IDENTITY_MISMATCH"))?;
        self.prepare_im_identity(Some(expected_uid)).await.map_err(|_| anyhow::anyhow!("BROWSER_SYNC_IM_IDENTITY_FAILED"))?;
        self.commit_browser_session(pool, secret, account_id, original_cookie, expected_uid).await
    }

    async fn commit_browser_session(
        &self, pool: &sqlx::SqlitePool, secret: &crate::crypto::SecretBox,
        account_id: &str, original_cookie: &[u8], expected_uid: &str,
    ) -> Result<()> {
        let uid = self.verified_sender_uid(Some(expected_uid))?;
        let cookie = self.get_current_cookie();
        let context = self.web_context.lock().unwrap().clone().context("BROWSER_SYNC_CONTEXT_MISSING")?;
        anyhow::ensure!(!self.sending_blocked() && context.identity_is_current(uid, &cookie, chrono::Utc::now().timestamp()), "BROWSER_SYNC_CONTEXT_INVALID");
        let encrypted_cookie = secret.encrypt(cookie.as_bytes())?;
        let encrypted_context = secret.encrypt(&serde_json::to_vec(&context)?)?;
        let mut tx = pool.begin().await?;
        let changed = sqlx::query("UPDATE accounts SET encrypted_cookie=?1, status='ACTIVE', last_checked_at=?2, updated_at=?2 WHERE id=?3 AND encrypted_cookie=?4 AND uid=?5 AND status IN ('ACTIVE','EXPIRED')")
            .bind(encrypted_cookie).bind(chrono::Utc::now().to_rfc3339()).bind(account_id)
            .bind(original_cookie).bind(expected_uid).execute(&mut *tx).await?;
        anyhow::ensure!(changed.rows_affected() == 1, "BROWSER_SYNC_SESSION_CHANGED");
        // 即使 Cookie 字符串相同，也不得把旧请求签名当作新会话的发送授权。
        sqlx::query("DELETE FROM account_im_credentials WHERE account_id=?1")
            .bind(account_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO account_web_contexts(account_id,encrypted_context) VALUES(?1,?2) ON CONFLICT(account_id) DO UPDATE SET encrypted_context=excluded.encrypted_context")
            .bind(account_id).bind(encrypted_context).execute(&mut *tx).await?;
        tx.commit().await?;
        self.clear_send_credential();
        Ok(())
    }
}
