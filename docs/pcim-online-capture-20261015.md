# PCIM 在线发送核验与授权缺口

## 本轮实际结果

持续授权见 `pcim-browser-send-authorization.md`。只操作账号 12345678（99191692311）到目标 55696816245，不重新登录，不使用日常浏览器，不修改旧 UNKNOWN。

- `pcim-online-01`：发送构造被外层拦截 3 次，实际提交 0。15 秒放行窗口可能过期，但当时未记录足够信息区分过期与 fetch 分支，不能确定归因。
- `pcim-online-02`：2026-10-15 19:51:35 CST，官方研究浏览器实际提交 1 次，无自动重试提交；HTTP 200，cmd100，外层/内层状态及 check_code 均为 0。
- 服务端消息编号 `7696860945675519546`，客户端 UUID `fbe6cacf-d51a-46ee-b53f-7783da2ff2fa`。
- 发送前后浏览器 UID 均确认。随后独立 Rust 只读探针按 UUID 查询，确认消息编号、发送人、目标、原模板正文、类型 7、北京时间日期全部匹配，并再次核验身份；探针发送 0、生产写入 0。
- 生产目标刷新从今日未发送变为已发送。旧 Rust 尝试仍为 UNKNOWN、message_id=null；不据此重分类旧尝试。
- 已关闭研究聊天页；保留原个人页。未导出 Cookie、token、ticket、签名或私钥。曾被挡住的本地失败消息在未来重开页面后的行为仍未知，应先安装发送阻断。

## 纠正离线结论

实际在线请求是 `https://imapi.douyin.com/v1/message/send`，SDK `0.1.8`，build `0d50935:feat/pc-im-group`，SESSION_AUTH=1、顶层 token 为空，但 protobuf headers 有 identity_security_token（204 字节）、device_id（19 字节）、identity_aid（空）。HTTP XHR 边界有 Guard 头及 x-tt-session-dtrait（820 字节）。

因此：离线捕获缺身份字段/Guard，不代表在线成功请求无需这些材料；SESSION_AUTH 与身份 token、Guard 可同时存在。当前证据是主动插桩 XHR 边界及响应，未获取完整浏览器最终网络头，不宣称被动全量网络抓包。存在某头也不能单凭一次成功证明该头对所有分支强制必需。

## 本地修复（未部署）

`src/douyin/im_auth.rs`：
1. `request_body` 只生成一个新 UUID，同时写入发送体字段 8 和扩展 `s:client_message_id`；移除所有旧 UUID 副本，保留其他扩展且不修改原凭证。
2. `from_capture` 保留精确白名单 `x-tt-session-dtrait`，继续进行长度/HTTP 格式校验；不接收 Cookie、Authorization 或近似名称，不擅自将 DTrait 设为所有分支必需。

两项回归测试先在旧实现失败，再修复通过。最终 `cargo test --offline --lib`：118 通过；`cargo check --offline --tests`、`cargo build --offline --bin sparklight` 均通过。身份过期重取、条件原子消费、失败不重试等既有测试通过。没有导入或重放本轮浏览器签名，候选 CLI 保持禁用。

## 可复用静态证据与剩余缺口

PCIM `5770.1fc7435b.js`：P-256 未压缩公钥 65 字节编码为 88 字节 Base64；ECDSA/SHA256 或 ECDH→HKDF→HMAC 分支；client-data 编码含 ts_sign、req_content、req_sign、timestamp。签名材料来自服务器 Cookie/响应更新并与本地密钥绑定，不可用任意新密钥替换。主发送链会先获取/缓存服务器身份 token，再合并进 cmd100 headers。

新取得个人页实际加载的公共 DTrait `@byted/uc-secure-dtrait-core/1.0.0.16/dist/index.umd.production.js`，87576 字节，SHA256 `cf35e851627219261e00c1362b40611ad9cbdc9ea5c394ce2cc6561450c969ca`。REA 单目录静态解析成功：父证据 `ev_4e03a66726a67ab29e2f56042a2330b031202860b773497433f0c9ad9f0ab89c`，1 个 JS、0 解析失败；混淆/动态语义仍未解析，不代表运行时等价。其在个人页加载已观察，但尚未证明与已关闭聊天页所执行版本完全相同。

**总目标仍未完成：**纯 Rust 尚无经验证的 Guard 服务器材料与独立密钥绑定/刷新闭环，DTrait 混淆核心尚无经过对照验证的独立实现。已有身份自动重取和会话 ticket 获取不能替代完整发送授权。两项局部修复不解决 `SEND_CREDENTIAL_MISSING`，故本轮不以局部修复冒充恢复发布，也不追加盲试发送。

## 证据位置

会话 scratch `pcim-trace/`：`online-attempt-01*.json`、`online-attempt-02*.json`、`online-02-history-read-*.json`、`*-before.log`、`final-*.log`、`dtrait-public/`。只读探针为 scratch `sdk-isolated/src/bin/pcim_history_read.rs`。

生产只读刷新记录：`data/.pcim-online-01-preflight.json*`（首个错误路由 HTTP405，修正为 `/api/v1` 后查询成功）、`data/.pcim-online-02-postcheck.json*`。未改动生产代码、调度或模板。
