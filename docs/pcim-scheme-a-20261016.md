# 方案 A 官方全链路复刻落地与部署记录

## 一、方案设计与架构对齐

针对此前单次发信随机生成密钥、缺少 Guard 票据建联、未运行 TokenBeat 轮转保活、剥离风控头的临时分支缺陷，本次完整落地方案 A：

1. **Guard 密钥与材料固化（持久化上下文）**：
   - 在 `WebSessionContext` 扩展并持久化存储每个账号唯一的 P-256 私钥标量（`guard_secret_hex`）、服务端票据材料（`guard_server_data`）、获取时间戳（`guard_acquired_at`）及上次保活时间（`last_beat_at`）。
   - 实现 `GuardKey::from_slice`、`GuardKey::to_bytes`、`GuardKey::from_hex`、`GuardKey::to_hex` 及其派生 Clone。
   - 实现 `BoundGuardMaterial::server_data_json` 与 `from_saved`，通过会话哈希（`strict_session_hash`）强绑定 `sessionid`、`sessionid_ss`、`sid_tt`。
   - 在 `acquire_im_identity` 轮换 10 分钟 IM 令牌时，显式继承已绑定的 Guard 密钥与服务端票据材料，杜绝因 IM 令牌续取冲掉 Guard 状态。

2. **官方 TokenBeat 机制与保活轮转**：
   - 客户端实现 `passport_token_beat(scene)`，支持官方规定的 `boot`、`polling`、`active` 场景。
   - 首次未建联或票据过期时，使用 `key.initialization_headers()` 与声明 Cookie 发起握手；已有票据时使用 `key.sign_path(..., mode=Ecdsa)` 签名保活。
   - 接收服务端返回的 `bd-ticket-guard-server-data` 并持久化，同时通过 `merge_response_headers` 合并轮转的 `Set-Cookie`。
   - 开放接口白名单（GET 方式）。

3. **发信链路接入完整 Guard 签名与 DTrait 风控头**：
   - `build_pcim_auth_request` 引入 `GuardSendAuth::Signed` 分支：
     - 调用 `key.sign_send` 计算 `bd-ticket-guard-client-data` 动态 ECDSA 签名。
     - 挂载完整的当前有效 Cookie（保留 Guard 与会话标识）。
     - 调用 `acquire_dtrait_config` 拉取或从上下文加载 RSA 公钥，通过 `DTraitCipher` 和 `FeatureProtocol` 计算 820 字节 `x-tt-session-dtrait` 设备特征加密头。
   - 发送响应若携带轮转的 `server-data`，自动解出并写回账号上下文。

4. **安全与回退兼容**：
   - 离线单元测试未模拟 TokenBeat 队列时，安全降级至测试初始化模式，保留测试断言。
   - 生产环境中当本地票据缺失或过期时，强制先执行官方握手建联，杜绝未授权裸发。

---

## 二、测试验证

1. **本地单元与回归测试**：
   - `cargo test --offline --lib`：全部 152 项测试通过（新增 `full_chain_signed_send_with_guard_signature_and_dtrait` 完整验签与 DTrait 挂载测试）。
   - `cargo check --offline --tests`：通过。
   - `cargo build --offline --bin sparklight`：编译成功。

2. **远端构建与部署验证**：
   - 候选环境 148 项测试全部通过（排除本地未发布的实验模块）。
   - 最终镜像标签：`sparklight:scheme-a-20261016-125403`
   - 镜像 ID：`sha256:c79598a5df8405877c5b2447d48e8c82b75a65464f188d4c2427056b77b67413`
   - 二进制哈希：`bf28d342ddf3aeb418beb4f5e77d7bfb3fa4fc7bd0cf6d6f73df5379f168e2ec`
   - 备份路径：`/opt/docker/sparklight-backups/scheme-a-20261016-125403`
   - 回滚镜像：`sparklight:before-scheme-a-20261016-125403`
   - 容器健康检查：`healthy`，配置与数据一致。

3. **当场真实发信与双向互测验收结果**：
   - 授权归档：旧当日成功记录归档至 `im_send_attempt_recovery_archive`，释放单次互测占用。
   - 用户点击真实发信（方向 12345678 -> 衬我孤独_）：
     - 首次发送：2026-10-16 12:57:49 CST，消息 ID `7697125401613059633`，服务端回执严格通过，精确历史核验通过，状态 `ACCEPTED`。
     - 连续复用同一会话二次发送：2026-10-16 12:59:33 CST，消息 ID `7697125859093939761`，回执与历史均通过，状态 `ACCEPTED`。
   - 用户点击真实发信（方向 衬我孤独_ -> 12345678）：
     - 发送时间：2026-10-16 12:58:23 CST，消息 ID `7697125560736122427`，回执与历史核验通过，状态 `ACCEPTED`。
   - 登录态持续有效性验收：
     - 发信前（SEND_PREFLIGHT）：身份与 Cookie 校验通过。
     - 发信后（SEND_POSTCHECK）：同一客户端身份与会话凭证确认有效。
     - 延迟与多轮发信后官方接口直测：两账号官方身份接口持续返回 HTTP 200，UID 严格匹配，`expired=false`，`verify=false`，会话未失效。
