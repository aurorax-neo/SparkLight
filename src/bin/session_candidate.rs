//! 该候选真实提交结果未知，且随后出现会话异常；禁止再次运行。
//! 保留生产 im_send_attempts、固定发送标记及验收证据，不得重置。
fn main() -> anyhow::Result<()> {
    anyhow::bail!("SESSION_CANDIDATE_DISABLED: 未验证发送候选已停用；保留 UNKNOWN 记录，禁止再次提交")
}
