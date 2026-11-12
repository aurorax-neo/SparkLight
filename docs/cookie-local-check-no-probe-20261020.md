# Cookie 本地检测与原生登录持久化修复（2026-10-20）

## 结论

账号管理中的“检测有效性”已改为抖音 App 原生会话校验，不再用裸 Cookie 请求 Web 接口。
网络错误、限流、非 JSON 响应和未知协议结果统一返回“未确认”，不会误判账号失效，也不会
覆盖仍可恢复的登录材料。

首次登录和重新登录由 Rust 直接调用抖音 App Passport：

- `get_qrcode` 获取官方登录二维码。
- `check_qrconnect` 轮询扫码与确认状态。
- 确认后保存账号级 Cookie、`X-Tt-Token`、`d_ticket`、`session_key` 和设备参数。
- 需要 Web/IM 身份时由 Rust 继续完成原生引导，不启动外部浏览器、扩展或截图辅助程序。

## 持久化策略

- 每个账号持久化独立设备参数和 Cookie Jar，服务重启后保持同一设备身份。
- 原生会话每 30 分钟节流校验一次。
- App TokenBeat 与 Web 身份 Token 每 6 小时维护。
- 只有服务端明确返回 `session_expired`、`session_drop` 或 `login_required` 时才标记失效。
- 续期过程采用整体成功或整体保留：任何一步身份或会话校验失败都不保存半套凭证。

## 有效期边界

`sid_guard` 含服务端签发的固定绝对到期时间，客户端不能本地延长单个 Cookie。App 体感长期
不登录依靠的是会话、账号 Token、身份 Token 和设备信任多层滚动维护；平台主动吊销、账号
风控、设备信任失效或绝对期限到期后，仍需重新扫码一次。

## 验证

```bash
cargo fmt
cargo check --all-targets
cargo test --all-targets
cd frontend && npm run build
```

页面实测覆盖：

- 添加账号只显示 App 二维码，不提供浏览器 Cookie、截图或扩展安装入口。
- 二维码由 Rust 服务端申请并以内嵌 PNG 返回。
- 服务启动与登录准备链路不产生浏览器子进程。
