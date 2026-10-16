use sparklight::douyin::client::DouyinClient;
use sparklight::douyin::types::HeartbeatResult;

#[tokio::test]
async fn test_douyin_heartbeat_token_beat() {
    // 1. Test with an invalid/mock cookie to verify that Douyin returns Expired
    let mock_cookie = "sessionid=0123456789abcdef0123456789abcdef; passport_csrf_token=1234567890abcdef1234567890abcdef;";
    let client = DouyinClient::new(mock_cookie, "TestMockHeartbeat").expect("create client");

    let beat_res = client.token_beat().await;
    println!("Mock Heartbeat response: {:?}", beat_res);

    match beat_res {
        HeartbeatResult::Expired(reason) => {
            println!("Verified: Expired cookie correctly identified by Douyin token_beat: {}", reason);
            assert!(reason.contains("过期") || reason.contains("401") || reason.contains("error") || reason.contains("未登录") || reason.contains("失效") || reason.contains("EXPIRED"));
        }
        HeartbeatResult::Alive => {
            panic!("Mock invalid cookie should not be alive");
        }
        HeartbeatResult::Error(err) => {
            println!("Network or parse notice: {}", err);
        }
    }
}
