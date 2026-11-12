//! TicketGuard 证书链只读探针。
//!
//! 只访问官方 security.snssdk.com，不读取 Cookie、不登记设备、不伪造 TEE。
//! 输出仅包含 HTTP 状态、错误码、证书长度与验证头结果。

use anyhow::Result;
use sparklight::douyin::{pcim_guard::GuardKey, ticket_guard};

#[tokio::main]
async fn main() -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("com.ss.android.ugc.aweme/400801 (Linux; U; Android 14; zh_CN; SM-S9280; Build/UP1A.231005.007)")
        .build()?;
    let key = GuardKey::generate();
    match ticket_guard::probe(&client, &key).await {
        Ok((chain, report)) => {
            chain.validate_attestation()?;
            println!(
                "get=http:{} top_error={:?} data_error={:?} client_pem={} server_pem={} server_sn={} key_match={}",
                report.get_http_status.unwrap_or(0),
                report.get_top_error,
                report.get_data_error,
                report.client_cert_pem_len,
                report.server_cert_pem_len,
                report.server_sn_len,
                report.client_cert_matches_key
            );
            println!(
                "verify=http:{} result={:?} header={} top_error={:?} data_error={:?} body_keys=[{}] data_keys=[{}] description={:?} captcha={} desc_url_host={:?} accepted={} error={:?}",
                report.verify_http_status.unwrap_or(0),
                report.verify_result,
                report.verify_header_present,
                report.verify_top_error,
                report.verify_data_error,
                report.verify_body_keys,
                report.verify_data_keys,
                report.verify_description,
                report.verify_captcha_present,
                report.verify_desc_url_host,
                report.verify_accepted,
                report.verify_error
            );
        }
        Err(error) => {
            println!("ticket_guard=REJECTED error={error:#}");
        }
    }
    Ok(())
}
