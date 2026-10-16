use sparklight::douyin::client::DouyinClient;

#[tokio::test]
async fn test_live_spark_to_12345678() {
    let cookie_path = "/Users/wunk/.pi-desktop/scratch/101793e7-2a24-4a6d-9886-f47b18b81c83/extracted_douyin_cookie.txt";
    if let Ok(cookie) = std::fs::read_to_string(cookie_path) {
        if let Ok(client) = DouyinClient::new(&cookie, "BraveBrowserAccount") {
            let check_res = client.check_cookie().await;
            println!("Check Cookie Result: {:?}", check_res);
            if check_res.is_valid() {
                let target_sec_uid = "MS4wLjABAAAAHIIA6pLfrur1ZeDU-5HPB3V4fy8XQk10b0XPV2GCRM4";
                let target_uid = "99191692311";
                let spark_res = client.send_spark_message(None, 1, target_sec_uid, Some(target_uid), "🔥").await;
                println!("Live Spark Send Result: {:?}", spark_res);
            }
        }
    }
}
#[tokio::test]
async fn test_live_fetch_friends_spark_status() {
    let cookie_path = "/Users/wunk/.pi-desktop/scratch/101793e7-2a24-4a6d-9886-f47b18b81c83/extracted_douyin_cookie.txt";
    if let Ok(cookie) = std::fs::read_to_string(cookie_path) {
        if let Ok(client) = DouyinClient::new(&cookie, "BraveBrowserAccount") {
            let my_uid = "55696816245";
            let my_sec_uid = "MS4wLjABAAAArYLRyFRLUyHWGK3DLv8RRrQHjj-iyas-5c99EThh1Ew";
            let friends = client.fetch_following_friends(my_uid, my_sec_uid).await.expect("fetch friends");
            println!("=== FETCHED {} FRIENDS ===", friends.len());
            for f in &friends {
                if f.nickname == "秋初安." || f.spark_days.unwrap_or(0) > 0 || f.spark_desc.as_deref().unwrap_or("") != "未点亮" {
                    println!("FRIEND: {} -> days: {:?}, desc: {:?}", f.nickname, f.spark_days, f.spark_desc);
                }
            }
            let qiu = friends.iter().find(|f| f.nickname == "秋初安.");
            assert!(qiu.is_some());
            let qiu_friend = qiu.unwrap();
            println!("秋初安 exact spark_days: {:?}, spark_desc: {:?}", qiu_friend.spark_days, qiu_friend.spark_desc);
            assert_eq!(qiu_friend.spark_days, Some(62));
            assert_eq!(qiu_friend.spark_desc.as_deref(), Some("已点亮 62 天"));
        }
    }
}

#[tokio::test]
async fn test_live_group_spark_and_sent_check() {
    let cookie_path = "/Users/wunk/.pi-desktop/scratch/101793e7-2a24-4a6d-9886-f47b18b81c83/extracted_douyin_cookie.txt";
    if let Ok(cookie) = std::fs::read_to_string(cookie_path) {
        if let Ok(client) = DouyinClient::new(&cookie, "BraveBrowserAccount") {
            let my_uid = 55696816245;
            let group_conv_id = "7635702399042159110";
            let group_short_id = 7635702399042159110;

            // 1. Check whether I sent a message to group today
            let has_sent = client.check_i_sent_message_today(my_uid, group_conv_id, 2, group_short_id).await;
            println!("Group 9.30有缘人 has_sent_today: {:?}", has_sent);

            // 2. Check 1v1 conversation for 秋初安 (I have not sent message today)
            let qiu_sent = client.check_i_sent_message_today(my_uid, "0:1:55696816245:63126473949", 1, 7671605302336258619).await;
            println!("秋初安 has_sent_today: {:?}", qiu_sent);
            assert!(!qiu_sent.expect("history query confirmed"));

            // 3. Send test message to group
            let send_res = client.send_spark_message(Some(group_conv_id), 2, group_conv_id, None, "🔥").await;
            println!("Group Send Result: {:?}", send_res);
            assert!(send_res.success);
        }
    }
}

#[tokio::test]
async fn test_live_check_chunfeng() {
    let cookie_path = "/Users/wunk/.pi-desktop/scratch/101793e7-2a24-4a6d-9886-f47b18b81c83/extracted_douyin_cookie.txt";
    if let Ok(cookie) = std::fs::read_to_string(cookie_path) {
        if let Ok(client) = DouyinClient::new(&cookie, "BraveBrowserAccount") {
            let my_uid = 55696816245;
            let friends = client.fetch_following_friends("55696816245", "MS4wLjABAAAArYLRyFRLUyHWGK3DLv8RRrQHjj-iyas-5c99EThh1Ew").await.unwrap();
            let cf = friends.iter().find(|f| f.nickname == "春风不语").unwrap();
            println!("春风不语 Friend details: uid={}, sec_uid={}, spark_days={:?}, spark_desc={:?}", cf.uid, cf.sec_uid, cf.spark_days, cf.spark_desc);
            let t_uid: u64 = cf.uid.parse().unwrap();
            let min_u = my_uid.min(t_uid);
            let max_u = my_uid.max(t_uid);
            let conv_id = format!("0:1:{min_u}:{max_u}");
            println!("春风不语 conv_id: {}", conv_id);

            let param = sparklight::douyin::client::DouyinTargetParam {
                conv_id: conv_id.clone(),
                conv_type: 1,
                short_id: None,
            };
            let map = client.fetch_batch_conversation_spark_status(&[param]).await.expect("conversation query confirmed");
            let short_id = map.get(&conv_id).map(|i| i.short_id).unwrap_or(0);
            println!("春风不语 short_id: {}, info: {:?}", short_id, map.get(&conv_id));

            let sent_today = client.check_i_sent_message_today(my_uid, &conv_id, 1, short_id).await;
            println!("春风不语 sent_today: {:?}", sent_today);
        }
    }
}
