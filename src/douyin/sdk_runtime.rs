//! 受限离线适配：官方输入构造不等于完整签名，生产签名能力默认拒绝。
use anyhow::{Context as _, Result, ensure};
use rquickjs::{Context, Runtime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub const INPUT_FRAGMENT_SHA256: &str =
    "cf3a88ad944446482a0908cf5d9951eb55ec23652fa4a9d9895e89f4619fd9c5";
const INPUT_FRAGMENT: &str = include_str!("sdk/ticket_input.js");
const MAX_SOURCE: usize = 8 * 1024 * 1024;

fn runtime() -> Result<(Runtime, Context)> {
    let rt = Runtime::new().map_err(|_| anyhow::anyhow!("无法创建内嵌 JS 引擎"))?;
    rt.set_memory_limit(32 * 1024 * 1024);
    rt.set_max_stack_size(512 * 1024);
    let deadline = Instant::now() + Duration::from_secs(2);
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
    let ctx = Context::full(&rt).map_err(|_| anyhow::anyhow!("无法创建隔离 JS 上下文"))?;
    Ok((rt, ctx))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TicketInput {
    pub req_content: String,
    pub sign_data: String,
    pub timestamp: i64,
}

/// 只执行已锁定官方片段；不持有密钥、不产生 HTTP 头、不开放网络或文件接口。
/// 此处显式给时间，绝不伪装成 SDK 的可信服务器时间。
pub fn official_ticket_input(path: &str, ticket: &str, timestamp: i64) -> Result<TicketInput> {
    ensure!(
        path.starts_with('/') && !path.contains(['?', '#', '\r', '\n']) && path.len() <= 2048,
        "签名路径无效"
    );
    ensure!(
        !ticket.is_empty() && ticket.len() <= 8192 && timestamp > 0,
        "缺少有效输入或时间"
    );
    ensure!(
        hex::encode(Sha256::digest(INPUT_FRAGMENT.as_bytes())) == INPUT_FRAGMENT_SHA256,
        "官方输入片段摘要不符"
    );
    let (_rt, ctx) = runtime()?;
    let args = serde_json::to_string(
        &serde_json::json!([{"url":format!("https://imapi.douyin.com{path}")},ticket,path,null,null,timestamp]),
    )?;
    let script = format!("var n6; {INPUT_FRAGMENT}\nJSON.stringify(n6(...{args}))");
    let json: String = ctx
        .with(|ctx| ctx.eval(script))
        .map_err(|_| anyhow::anyhow!("官方输入构造执行失败"))?;
    serde_json::from_str(&json).context("官方输入输出不兼容")
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ProbeResult {
    pub loaded: bool,
    pub dependency: &'static str,
    pub production_enabled: bool,
}

/// 仅供显式离线命令使用；调用者需先核实来源清单，再以固定摘要二次校验。
/// 禁止宿主网络、进程、文件、计时器、DOM、持久化和浏览器私钥。
pub fn probe_source(source: &[u8], expected_sha256: &str) -> Result<ProbeResult> {
    ensure!(
        source.len() <= MAX_SOURCE && !source.is_empty(),
        "SDK 资源大小无效"
    );
    ensure!(
        hex::encode(Sha256::digest(source)) == expected_sha256,
        "SDK 摘要不符，禁止执行"
    );
    let source = std::str::from_utf8(source).context("SDK 不是 UTF-8 JavaScript")?;
    let (_rt, ctx) = runtime()?;
    ctx.with(|ctx| {
        ctx.eval::<(), _>(
            r#"
            var window=globalThis,self=globalThis,global=globalThis;
            function denied(){throw new Error('SDK_HOST_DENIED');}
            var fetch=denied,XMLHttpRequest=denied,setTimeout=denied,setInterval=denied;
        "#,
        )
        .map_err(|_| anyhow::anyhow!("隔离环境初始化失败"))?;
        match ctx.eval::<(), _>(source) {
            Ok(()) => Ok(ProbeResult {
                loaded: true,
                dependency: "加载完成不代表入口或签名可用",
                production_enabled: false,
            }),
            Err(_) => {
                // 不返回任意异常文本，避免 SDK 意外将材料放入异常信息。
                let value = ctx.catch();
                let message = value
                    .as_object()
                    .and_then(|o| o.get::<_, String>("message").ok())
                    .unwrap_or_default();
                let dependency = if message.contains("SDK_HOST_DENIED") {
                    "宿主能力被拒绝"
                } else if message.contains("Request") {
                    "Request"
                } else if message.contains("document") {
                    "DOM/document"
                } else if message.contains("atob") {
                    "atob"
                } else if message.contains("performance") {
                    "performance"
                } else if message.contains("interrupted") {
                    "执行超时"
                } else {
                    "其他运行依赖或不兼容，需进一步适配"
                };
                Ok(ProbeResult {
                    loaded: false,
                    dependency,
                    production_enabled: false,
                })
            }
        }
    })
}

#[derive(Clone, Copy, Debug)]
pub enum SigningCapability {
    DynamicRequest,
    TicketGuard,
    Renewal,
}

/// 没有经授权验证的完整适配器，始终在网络前拒绝；不返回空头或伪造签名。
pub fn require_production_capability(capability: SigningCapability) -> Result<()> {
    anyhow::bail!(match capability {
        SigningCapability::DynamicRequest =>
            "动态请求签名未验证：已定位 BDMS 离线入口，缺少合法初始化、引擎一致性及服务端接受",
        SigningCapability::TicketGuard =>
            "Ticket Guard 未验证：可信时间已局部验证，缺少合法新密钥绑定与匹配的服务端签发材料",
        SigningCapability::Renewal =>
            "凭证续期未验证：未建立合法续期流程，禁止用本地 refresh 冒充续期",
    })
}

pub(crate) fn validate_captured_send_endpoint(raw: &str) -> Result<()> {
    let url = url::Url::parse(raw).context("发送地址无效")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("imapi.douyin.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/v1/message/send"
            && url.query().is_none()
            && url.fragment().is_none(),
        "官方发送凭证仅允许绑定的 HTTPS 发送路径，不允许跨路径或追加查询复用"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_fragment_matches_node_baseline() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("sdk/ticket_input_baseline.json")).unwrap();
        for case in fixtures["cases"].as_array().unwrap() {
            let input = &case["input"];
            let result = official_ticket_input(
                input["path"].as_str().unwrap(),
                input["ticket"].as_str().unwrap(),
                input["timestamp"].as_i64().unwrap(),
            )
            .unwrap();
            assert_eq!(serde_json::to_value(result).unwrap(), case["expected"]);
        }
        let a = official_ticket_input("/v1/message/send", "offline-ticket", 1700000000).unwrap();
        let b = official_ticket_input(
            "/v1/message/get_by_conversation",
            "offline-ticket",
            1700000000,
        )
        .unwrap();
        assert_ne!(a.sign_data, b.sign_data);
    }
    #[test]
    fn unavailable_capabilities_never_return_fake_signatures() {
        for c in [
            SigningCapability::DynamicRequest,
            SigningCapability::TicketGuard,
            SigningCapability::Renewal,
        ] {
            assert!(require_production_capability(c).is_err());
        }
    }
    #[test]
    fn captured_headers_cannot_cross_path_or_query() {
        assert!(
            validate_captured_send_endpoint("https://imapi.douyin.com/v1/message/send").is_ok()
        );
        for u in [
            "http://imapi.douyin.com/v1/message/send",
            "https://imapi.douyin.com/v1/message/get_by_conversation",
            "https://imapi.douyin.com/v1/message/send?a=1",
            "https://evil.example/v1/message/send",
            "https://imapi.douyin.com/v1/message/send#fragment",
            "https://user@imapi.douyin.com/v1/message/send",
            "https://imapi.douyin.com:444/v1/message/send",
        ] {
            assert!(validate_captured_send_endpoint(u).is_err());
        }
    }
    #[test]
    fn sandbox_denies_network_and_unknown_hash_before_execution() {
        let source = b"fetch('https://www.douyin.com/')";
        assert!(probe_source(source, &"0".repeat(64)).is_err());
        let result = probe_source(source, &hex::encode(Sha256::digest(source))).unwrap();
        assert!(!result.loaded && !result.production_enabled);
        assert_eq!(result.dependency, "宿主能力被拒绝");
    }
    #[test]
    fn sandbox_limits_infinite_execution() {
        let source = b"while(true){}";
        let result = probe_source(source, &hex::encode(Sha256::digest(source))).unwrap();
        assert!(!result.loaded && !result.production_enabled);
    }
    #[test]
    fn invalid_input_is_rejected() {
        assert!(official_ticket_input("/p?x=1", "offline", 1).is_err());
        assert!(official_ticket_input("/p", "", 1).is_err());
        assert!(official_ticket_input("/p", "offline", 0).is_err());
    }
}
