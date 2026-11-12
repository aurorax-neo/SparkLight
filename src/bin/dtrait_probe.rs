//! 只读探针：试探 `/service/2/dtrait/` 的报文结构。
//!
//! 设备登记返回的 `dtrait_pk1/pk2/version` 是换取 dtrait_token 的材料；
//! 该端点对裸 JSON 一律返回 `param invalid`，说明它和设备登记一样需要
//! applog 封包。这里用同一套 `seal_register_body` 依次试几种结构并打印回包。

use anyhow::Result;
use serde_json::{Value, json};

use sparklight::douyin::applog_wire;

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = std::env::var("SPARK_DATA_DIR").unwrap_or_else(|_| "/data".into());
    let path = std::path::Path::new(&data_dir).join("native_device_registry.json");
    let raw = std::fs::read_to_string(&path)?;
    let registry: Value = serde_json::from_str(&raw)?;
    let entry = registry
        .as_object()
        .and_then(|map| map.values().next())
        .cloned()
        .unwrap_or(Value::Null);
    let device_id = entry.get("device_id").and_then(Value::as_str).unwrap_or("");
    let install_id = entry.get("install_id").and_then(Value::as_str).unwrap_or("");
    let token = entry.get("device_token").and_then(Value::as_str).unwrap_or("");
    let pk1 = entry.get("dtrait_pk1").and_then(Value::as_str).unwrap_or("");
    let pk2 = entry.get("dtrait_pk2").and_then(Value::as_str).unwrap_or("");
    let ver = entry.get("dtrait_version").and_then(Value::as_str).unwrap_or("");
    println!(
        "material device_id_len={} iid_len={} token_len={} pk1_len={} pk2_len={} ver={:?}",
        device_id.len(),
        install_id.len(),
        token.len(),
        pk1.len(),
        pk2.len(),
        ver
    );

    let now = chrono::Utc::now().timestamp_millis();
    let header = json!({
        "aid": 1128,
        "app_name": "aweme",
        "package": "com.ss.android.ugc.aweme",
        "channel": "update",
        "app_version": "40.8.0",
        "version_code": 400801,
        "device_id": device_id,
        "install_id": install_id,
        "device_model": "23043RP34C",
        "device_brand": "Xiaomi",
        "device_manufacturer": "Xiaomi",
        "os": "Android",
        "os_version": "14",
        "os_api": 34,
        "resolution": "2880x1800",
        "is_android_pad": 1,
    });

    let shapes = vec![
        (
            "magic+header+events",
            json!({"magic_tag": "ss_app_log", "_gen_time": now, "header": header, "events": []}),
        ),
        (
            "magic+header+dtrait",
            json!({
                "magic_tag": "ss_app_log",
                "_gen_time": now,
                "header": header,
                "dtrait": {"dtrait_pk1": pk1, "dtrait_pk2": pk2, "dtrait_version": ver}
            }),
        ),
        (
            "header+dtrait_pk",
            json!({
                "header": header,
                "dtrait_pk1": pk1,
                "dtrait_pk2": pk2,
                "dtrait_version": ver
            }),
        ),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    for (label, body) in shapes {
        let plain = serde_json::to_vec(&body)?;
        let wire = applog_wire::seal_register_body(&plain)?;
        let query = [
            ("aid", "1128"),
            ("app_name", "aweme"),
            ("device_id", device_id),
            ("iid", install_id),
            ("version_code", "400801"),
            ("channel", "update"),
            ("package", "com.ss.android.ugc.aweme"),
        ];
        let response = client
            .post("https://log.snssdk.com/service/2/dtrait/")
            .query(&query)
            .header("Content-Type", "application/octet-stream;tt-data=a")
            .header("sdk-version", "2")
            .header("x-tt-dt", token)
            .header(
                "User-Agent",
                "com.ss.android.ugc.aweme/400801 (Linux; U; Android 14; zh_CN; Xiaomi Pad 6; Build/UKQ1.231003.002)",
            )
            .body(wire)
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        let decoded = applog_wire::open_register_response(&bytes);
        let text = String::from_utf8_lossy(&decoded);
        println!("{label}: http={status} body={}", &text[..text.len().min(400)]);
    }
    Ok(())
}
