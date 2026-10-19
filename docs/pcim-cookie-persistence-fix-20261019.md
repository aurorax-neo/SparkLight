# 抖音登录 Cookie 持久化修复（2026-10-19）

## 一、问题现象

1. 手动点击「续火花」后，账号 Cookie 立即被平台吊销，账号转为 EXPIRED。
2. 失效账号的 `sid_guard` 仍显示剩余 50 多天，说明不是自然到期，而是被服务端主动注销。
3. 账号管理页手动点击「检测有效性」时仍有 Bark 推送。

## 二、根因

### 1. 请求头携带了官方不存在的 Guard 字段（主因）

提交 `98ceab2` 把 `bd-ticket-guard-iteration-version: 1` 放进了 HTTP 请求头。
真实浏览器抓包（Brave，已登录态）显示，`/passport/token/beat/web/` 请求头只含 5 个 Guard 字段：

```
bd-ticket-guard-ree-public-key
bd-ticket-guard-web-version
bd-ticket-guard-web-sign-type
bd-ticket-guard-version
bd-ticket-guard-client-data
```

`iteration-version` 只存在于 `bd_ticket_guard_client_data` Cookie 内，请求头中携带会被判为伪造客户端。

### 2. `bd_ticket_guard_client_data` 字段顺序与官方不一致

`align_guard_cookie` 使用 `serde_json::json!` 宏生成声明体。该宏在未启用 `preserve_order`
时使用 `BTreeMap`，键会按字母序输出：

```
{"bd-ticket-guard-iteration-version":1,"bd-ticket-guard-ree-public-key":"...","bd-ticket-guard-version":2,"bd-ticket-guard-web-version":2}
```

官方浏览器真实 Cookie 解码后的顺序是：

```
{"bd-ticket-guard-version":2,"bd-ticket-guard-iteration-version":1,"bd-ticket-guard-ree-public-key":"...","bd-ticket-guard-web-version":2}
```

`GuardKey::initialization_cookie_value` 用结构体序列化（顺序正确），`align_guard_cookie`
用宏（顺序错误），两条路径产出不一致。

### 3. 服务端轮转 `server_data` 后 `_bd_ticket_crypt_cookie` 未同步重算

官方公式（已在真实浏览器数据上逐字节验证）：

```
_bd_ticket_crypt_cookie =
    MD5(JSON.stringify({
        publicKey : <客户端 EC 公钥 SPKI PEM，单行 124 字符 base64>,
        cert      : <bd_ticket_guard_server_data.client_cert>,
        serverData: <bd_ticket_guard_server_data 原始字符串>,
    }))
```

依据来源：`90775.0c663da7.js` 模块 636269 的 `jT`（MD5）、`processCookie` 中的 `eW`。

旧实现保留浏览器原生 `_bd_ticket_crypt_cookie`，而 Guard 材料会被新一轮响应覆盖，
导致哈希与材料分叉。

## 三、修复内容

| 文件 | 变更 |
| --- | --- |
| `src/douyin/pcim_guard.rs` | 初始化与签名请求头移除 `bd-ticket-guard-iteration-version`；新增 `guard_declaration_json` 统一官方字段序；`align_guard_cookie` 改为 `Result` 并在有材料时强制重算 `_bd_ticket_crypt_cookie`，无材料时删除旧值 |
| `src/douyin/client.rs` | 新增 `repair_bound_guard_cookie`，发网前用已保存且账号绑定的材料本地修复历史 Cookie；`refresh_guard_ticket` 复用官方字段序且只转义 padding |
| `src/douyin/web.rs` | 收到新 `bd-ticket-guard-server-data` 时，材料、公钥与 `_bd_ticket_crypt_cookie` 原子对齐后再标记 Cookie 变化 |
| `src/scheduler/mod.rs` | 检测前执行本地对齐；新增登录会话临期预警 |
| `src/douyin/im_auth.rs` | 新增 `sid_guard_expiry`，由 `login_ts + max_age` 推导绝对到期时间 |
| `src/notify/bark.rs` | 新增到期前提醒，复用「仅定时任务期 + 30 分钟手动静默窗口」双重硬拦截 |

新增回归测试：

- `guard_declaration_matches_official_field_order`：字段序与 `%3D` 转义逐字节比对。
- `guard_cookie_repair_and_rotation_recompute_matching_material_hash`：材料轮转后哈希必须跟随重算。
- `sid_guard_expiry_uses_login_time_plus_max_age`：到期时间推导与异常输入拒绝。

## 四、真实验证证据

1. 用真实浏览器（Brave，已登录态）读取 `s_sdk_crypt_sdk.ec_publicKey`、`client_cert`、
   `bd_ticket_guard_server_data`，按官方公式重算得到 `c7a4e3...`，与浏览器 Cookie
   `_bd_ticket_crypt_cookie=c7a4e3fcce3e7b27b8997729d3d459ec` 完全一致。
2. 单独变体比对确认：去掉 SPKI 头、去掉 `pub.` 前缀、改用 raw base64 公钥都会得到不同哈希，
   证明公式三个输入都不可或缺。
3. `bd-ticket-guard-client-data` 请求头解码结构与 `ClientData` 结构体字段序一致
   （`ts_sign`、`req_content`、`req_sign`、`timestamp`、`t_trust`）。
4. 线上 108 两个账号修复前后对照（`tools/verify_guard_alignment_108.py`）：

```
用户37127ceb8c2d7 uid=55696816245 ACTIVE
  cookie hash : ef19de143438100ff27aefdf853ef1c1
  rehash(key) : ef19de143438100ff27aefdf853ef1c1
  ALIGNED     : True

12345678 uid=99191692311 EXPIRED
  cookie hash : 3f605150b8259e3e9d635033906b031d
  rehash(key) : 3f605150b8259e3e9d635033906b031d
  ALIGNED     : True
```

5. 手动点击「检测有效性」接口复测：ACTIVE 账号返回 `is_valid=true`；两次调用日志均为
   `严格保持静默，不触发 Bark 推送`，无任何 Bark 出站记录。

## 五、能力边界（必须明确）

抖音网页端 `sessionid` / `sid_guard` 为服务端签发的固定有效期凭证：

```
sid_guard=<sid>|1792375077|5184000|Fri, 18-Dec-2026 01:57:57 GMT
```

`5184000` 秒即 60 天。真实浏览器 `/passport/token/beat/web/` 响应不含 `Set-Cookie`，
不会滑动续期。因此：

- Guard 票据：可由系统自动维护，不再需要人工更新。
- 登录会话：无法无交互延长，到期必须重新登录同步一次。

新逻辑在剩余不足 7 天时通过定时任务发送一次提醒，把「被动断签」变成「计划内重新同步」。

## 六、运维动作

- 镜像：`sparklight:before-expiry-warn-20261019-103714` 为本次变更前的回滚点。
- 数据备份：`/opt/docker/sparklight/data_backup_20261019-103714`。
- 对照脚本：`tools/verify_guard_alignment_108.py`，`exit=0` 表示全部账号自洽。
- 失效账号 `99191692311` 的登录态已被平台吊销，需重新登录后同步凭证，不能靠旧 Cookie 恢复。
