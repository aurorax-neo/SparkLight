# 抖音登录态寿命与续期机制分析（2026-10-19，含 10-19 晚修正）

## 结论（修正版）

不存在"永不失效的单个 Cookie"，但存在官方**多层票据 + 滚动续期**机制。App 体感
"一直不用重新登录"，靠的不是 Cookie 长命，而是四个层次叠加：

| 层 | 载体 | 生命周期 | 是否自动续 |
| --- | --- | --- | --- |
| 会话层 | `sessionid` / `sid_guard` / `sid_tt` / `uid_tt` | `sid_guard` 内嵌绝对到期，60 天 | 否，服务端签名固定 |
| 账号 Token 层 | `X-Tt-Token`（App）/ `x_tt_token`（Web） | 约 10 分钟 | 是，由客户端 SDK 维护 |
| 身份层 | `bd-ticket-guard-identity-token` | 不透明、远长于 10 分钟 | 是，token beat 下发 |
| 设备层 | `ttwid` / `odin_tt` / `d_ticket` / `passport_assist_user` | 180 天 | 活跃即被重签 |

真正决定"要不要重新登录"的是**设备层是否还被认为是同一台受信设备**，而不是
`sessionid` 还剩几天。设备层只要活着，平台就能在不打扰用户的情况下重新签发会话。

## 证据零：真实浏览器 Cookie 库的分层寿命（2026-10-19 实测）

直接读取本机日常使用浏览器（已登录账号）的 Cookie 数据库，只统计寿命、不导出值：

| Cookie | 到期 | 剩余 |
| --- | --- | --- |
| `sessionid` / `sid_tt` / `uid_tt` | 2026-12-18 | 59 天 |
| `sid_guard` | 2027-04-17 | 179 天 |
| `ttwid` / `odin_tt` / `d_ticket` / `passport_assist_user` / `login_time` | 2027-04-17 | 179 天 |
| `x_tt_token` | 创建 06:28 到期 06:38 | **10 分钟** |

`x_tt_token` 只有 10 分钟寿命却在浏览器里长期存在，说明只要浏览器活跃，它在被
持续重签。这正是"体感不过期"的来源。

## 证据零点五：Web 端 token beat 的真实响应

使用完整浏览器 Cookie（含 `ttwid` / `odin_tt` / `bd_ticket_guard_client_data`）
请求 `GET https://www.douyin.com/passport/token/beat/web/?scene=boot&aid=6383`：

- HTTP 200，`{"error_code":0,"error_name":"success"}`。
- 响应头含 `bd-ticket-guard-identity-token`（202 字节）与 `bd-ticket-guard-sec-ts`。
- 响应头**不含** `Set-Cookie`。

同一轮 `GET /passport/account/info/v2/?aid=6383&is_from_ttaccountsdk=1` 同样 200、
同样无 `Set-Cookie`，仅返回 `bd-ticket-guard-*` 结果码。

对照结论：`token beat` 不是续 Cookie 的接口，而是**下发身份票据**的接口。Cookie 由
身份票据 + 设备票据在需要时重新签发，这就是 App 与 Web 都不弹登录框的原因。

注意与历史记录的冲突：`docs/pcim-full-chain-reconstruction-guide.md` 记录过服务端
裸调该接口被 403 并触发 24 小时会话阻断。本次带完整设备 Cookie 调用返回 200，
说明 403 的触发条件是**设备指纹不完整**，而不是"不能调用"。

2026-10-19 晚再次对真实聊天页抓包确认：浏览器实际发出的 Web 请求包含完整
`msToken`、`a_bogus`、Guard 请求头和当前 URL 指纹；未发送 `X-Tt-Token` 请求头，
响应也没有 `Set-Cookie`，服务端跟踪头明确显示 `token_chk_res=miss_token`。因此
`X-Tt-Token` 是 App 请求头层，不能直接搬到 Web；Web 必须由页面 securitySDK 在同一
浏览器上下文内完成签名与票据维护。

## 证据一：macOS 抖音客户端 8.7.0

- 官方安装包：`douyin-v8.7.0-darwin-universal.dmg`，SHA-256
  `e7497898416c9c00f05bc8d583e67d8f08849823383c80510bd6f21a68099b8a`（app.asar）。
- 结构为 Electron：`Contents/Resources/app.asar` 21 MB，主进程入口为加壳原生
  `__META-INF__/darwinarm64.node`。
- `node_modules/@annie/electron/dist/es/main/session/index.js` 使用
  `session.fromPartition("persist:annie-session")`，说明业务页面运行在固定持久
  分区中，Cookie 由 Chromium Cookie 库统一管理。
- 桌面端 JS 层不存在 `x-bogus`、`a_bogus`、`msToken`、`bd-ticket-guard-*`
  生成逻辑；这些签名由 douyin.com 下发的 Web JS 在页面内计算。
- 结论：桌面端与浏览器共用同一会话模型，不提供额外续期能力。

## 证据二：`sid_guard` 实测与历史时间线

对线上两个账号直接请求
`https://www.douyin.com/passport/account/info/v2/?aid=6383`：

- HTTP 200，`Set-Cookie` 响应头为空，服务端不下发新的 `sid_guard`。
- 存储中 `sid_guard` 的 `max_age` 均为 60 天。

历史数据库对比（`login_ts` 只在人工重新登录时变化）：

| 时间 | 用户37127ceb8c2d7 login_ts | 12345678 login_ts |
| --- | --- | --- |
| 2026-10-16 备份 | 1792158847 | 1792148276 |
| 2026-10-17 07:00 备份 | 1792158847（未变） | 1792147877（未变） |
| 2026-10-17 19:36 备份 | 1792227362（重新登录） | 1792227418（重新登录） |
| 2026-10-19 10:20 备份 | 1792371978（重新登录） | 1792227418（未变） |
| 当前 | 1792371978 | 1792375077（重新登录） |

自动巡检、发送、心跳期间 `login_ts` 从未推进，可确认平台不接受无交互滑动续期。

## 证据三：Android 官方客户端（64 位，`com.ss.android.ugc.aweme`）

- 包名：`aweme_douyinweb1_64_v5072_400701`，55 个 DEX，SHA-256
  `46a0ca8064f49a7d5a13a3bdf1769dec0daa9dd7204cc1e254e0d91b81b85c2c`。
- 关键类（jadx 反编译classes26.dex，JDK 27）：
  - `com/ss/android/token/TTTokenManager`：token 生命周期中枢，含
    `TokenBlocker`（`will notifyTokenBeatSceneStart` / `TTNetTokenBeatBlockerBridge`）。
  - `com/ss/android/account/token/TTTokenInterceptor`：拦截全部护照域请求，注入
    `X-Tt-Token`，并把响应头的新 token 立刻落盘。
  - `X/0v33`（TokenFactory，7420 行）：`addRequestHeader` 组装 `X-Tt-Token`、
    `x-tt-passport-mfa-token`、`sdk-version`、`passport-sdk-version`；
    常量 `/passport/token/beat/v2/`、`token_fresh`、`token_missing`、`beat_disabled`。
  - `X/0v36->run()`：诊断事件 `passport_load_login_token`，字段直接暴露双凭据模型：
    `sessionid`、`xtttoken_location`、`has_tssign`、`token_contains_sessionid`、
    `csrf_token_location`、`is_login_v2`。
- 设备级静默认证链路（DEX 字符串表实测命中）：
  `/passport/device/one_login/`、`/passport/device/trust_users/`、
  `/passport/device/send_push/`、`/passport/open/silent_auth/`、
  `/passport/complex_env/one_login/`、`/passport/auth/one_login/`。
- `flow_silent_auth_expire_ts`、`flow_silent_auth_expire_task_cd`、
  `flow_silent_auth_not_expired_launch_enable` 表明静默认证有**独立过期时间与后台刷新任务**，
  后台会主动刷新而不是等用户操作。
- `keep_login`、`login_token`、`integrate_login_token`、`passport_load_login_token`、
  `passport_login_token_update` 属于"保持登录"分支。
- `X-Tt-Token` 在 token 缺失时由 token beat 补齐；服务端仅在明确返回
  `session_expired` 时才让客户端登出。
- 结论：移动端**不是**只依赖 `sid_guard`，而是"会话 + 账号 Token + 身份 Token +
  设备信任"四层结构，会话到期可由设备信任静默重签。

## 与 SparkLight 现状的差距

SparkLight 目前只搬了**最外层、最短命**的一层（`sessionid` / `sid_guard` 静态快照）：

- 没有维护 `X-Tt-Token` / `x_tt_token` 滚动层，短期票据永远是旧的。
- 没有参与 token beat，平台无法确认设备活跃。
- 请求出口 IP 与真实浏览器不同，同一份 Cookie 在两处使用，容易被判为会话劫持。

这三条共同解释了"隔一段时间就必须更新 Cookie"，也解释了 10-16 的 `KICK`。

## 仍存在的风险点：`identity_security_token`

- 官方身份 Token 为 204 字符不透明串，没有可解析的 `exp` 字段。
- 生产代码在已有身份时只刷新本地 `identity_acquired_at`，不会重新请求官方接口，
  因此本地永远不会判定身份过期。
- 实测 2026-10-17 备份中的身份 Token 在 2026-10-19 仍可成功发送，说明其真实有效期
  远长于 SDK 侧 10 分钟缓存，但服务端真实 TTL 未知。
- 若该 Token 在 60 天会话期内提前失效，纯 Rust TokenBeat 会在下一轮巡检中尝试重新获取；
  若原生会话已被平台绝对失效，则仍需要人工重新扫码。

## 可行方案与 2026-10-20 修正

1. 会话轮换自动重绑：已完成并线上验证。
2. **纯 Rust App 二维码协议**：
   `src/douyin/login.rs` + `src/server/routes/login.rs`。添加或重新登录账号时，服务端
   直接请求抖音 App `get_qrcode` 并在页面展示二维码，确认后保存原生 Cookie、
   `X-Tt-Token`、`d_ticket`、`session_key`。2026-10-20 实测证明，普通 Rust
   客户端复刻 CSR 后仍无法通过新设备 TicketGuard/TEE 校验，官方返回 `4044`；
   这不是版本过低，纯软件也无法生成真实 Android 硬件证明。
3. **长期维护入口**：对同一账号在官方 Android 客户端已经建立并受信任的会话，
   使用 `native_session_import` 将 Cookie、Token 与设备参数整体加密导入。导入后由
   纯 Rust App TokenBeat 每 6 小时维护，不需要浏览器、扩展或每日复制 Cookie。
4. 到期前 7 天 Bark 预警：已在 `warn_on_session_expiry` 实现。
5. 分层低频续期：App 原生会话每 30 分钟节流校验，App TokenBeat 与 Web 身份 Token
   每 6 小时维护；网络、限流和非 JSON 响应只标记“未确认”，不覆盖仍可恢复的登录态。
   二者均失败时保留旧材料，等待下一周期或重新导入。
6. 身份 Token 定期续取：页面上下文同时刷新 Cookie、`bd-ticket-guard-identity-token`
   与 Guard 材料；任何 UID、会话或业务校验失败都整体放弃，不覆盖旧凭证
   （fail-closed）。
7. 设备指纹一致性：`src/douyin/device_profile.rs` 由账号 ID 确定性派生指纹，加密落库，
   同一账号跨重启保持一致、不同账号拥有不同设备标识与环境参数。PCIM 初始化报文不再写死共享的 MacIntel/2560x1440
   字段，而是逐账号读取已持久化指纹。
8. 已删除的旧方案：`sparklight-extension/`、`tools/*brave*.cjs`、
   `tools/sparklight_extractor.user.js`、`/api/v1/accounts/{id}/sync-cookie` 与
   `/api/v1/system/launch-brave` 全部移除，仓库内不再存在从用户日常浏览器复制 Cookie 的路径。

## 边界

`sid_guard` 内嵌的 60 天绝对到期由服务端签名固定，客户端无法本地延长，这一点不变。
TokenBeat 只能在官方会话仍受信任时维护票据，不能保证账号永久不重新登录。当前可验证
的长期路径是导入官方 Android 原生会话后持续 TokenBeat；绝对到期、长期不活跃、异地
登录、账号风控或平台主动吊销仍可能要求重新登录。
