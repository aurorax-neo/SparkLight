# SparkLight 部署运维与方案完全指南

---

## 一、 系统架构与 Scheme A 全链签名体系

SparkLight 是专为抖音网页版/PC IM 会话隔离、自动化与手动续火花设计的轻量独立系统。系统基于纯 Rust 原生 HTTP 协议栈开发，二维码登录、TokenBeat、Web/IM 身份获取与发信请求均由 Rust 直接完成，不依赖外部浏览器、Puppeteer 或 Playwright。

### 1. 核心挑战：平台反爬与 KICK 踢下线排查复盘

在早期的开发与逆向过程中，直接向发信接口发起请求曾频繁触发平台下发 20 字节风控阻断响应：
```json
{"decision": "KICK"}
```
一旦收到该指令，平台服务端会在后台直接将会话（Cookie）判定为被恶意第三方脚本劫持，并立即吊销 Cookie 与会话状态，导致账号变为失效状态。

通过在真实浏览器环境中对正常发信过程进行全生命周期、逐字段的对照分析，锁定了触发风控的四大根本原因：

1. **未签名公钥裸奔（Initial 模式）**：
   抖音官方 Web IM 要求所有消息必须由合法注册的设备公私钥进行 HMAC/ECDSA 签名。此前系统在本地缺少 Guard 密钥票据时，临时生成未登记的随机公私钥并发起未签名请求，直接撞上平台的会话防劫持模型。
2. **缺少必要的 URL 风控参数**：
   浏览器官方发信请求的 URL 携带有由 `s_v_web_id` 派生的 `verifyFp`、`fp` 以及高熵动态 `msToken`，纯路径请求会被平台风控网关直接阻断。
3. **缺少运行环境扩展指纹（Protobuf Field 15）**：
   官方外层 Protobuf 报文的 Field 15 扩展列表中携带了 19 项标准前端运行环境特征（如 `browser_platform`、`browser_version`、`screen_width`、`screen_height`、`timezone_name`、`cookie_enabled` 等），缺少这些字段直接暴露了脚本环境。
4. **缺少内层高精度时间戳（Field 5）**：
   消息层扩展字段中缺少 `s:stime` 毫秒级浮点时间标记。

### 2. Scheme A 根治方案落地

针对上述排查结论，系统完成了完整的官方全链路对齐：
- **Guard 私钥与票据随 Cookie 一同托管**：登录后的纯 Rust Web/IM 引导按官方流程取得 ECDSA P-256 私钥和平台签发的 Ticket Guard 票据，加密持久化至 Rust 后端复用；
- **全流程强制 Signed 真实签名**：发信时 100% 调用真实的 `sign_send` 签名链路，请求头携带合法的 `bd-ticket-guard-client-data`（包含真实 `ts_sign`、`req_sign` 和 `t_trust: 1`）；
- **动态装配 URL 参数与运行指纹**：自动提取 `s_v_web_id` 组装 `verifyFp` 与 `fp`，动态生成合规格式的 `msToken`，并将 19 项设备运行环境特征完整注入 Protobuf Field 15；
- **验收结果**：连续执行多轮真实发信，均收到平台官方下发的 127 字节标准 Protobuf 回执，消息即时送达聊天窗口，会话保持持续有效（ACTIVE），彻底终结了 KICK 掉线顽疾。

---

## 二、 应用内 App 二维码登录与原生会话导入

系统不提供浏览器 Cookie 复制入口，也不读取用户日常浏览器资料。服务端直接对接抖音 App Passport；新设备若被 TicketGuard/TEE 拒绝，可导入官方 Android 客户端的完整原生会话。

### 1. 登录机制
- **不安装浏览器和扩展**：服务端直接调用抖音 App `get_qrcode`、`check_qrconnect` 官方接口并在页面展示二维码；
- **新设备边界**：抖音对新设备要求真实 Android TEE/KeyStore 设备证明。纯 Rust 可以复刻普通 Passport 请求，但不能伪造硬件证明；`4044`、`verify_result=1330`、`error=18000` 都不是版本过低；
- **原生会话导入**：对已受信任的官方 Android 会话，使用 `native_session_import` 加密导入 Cookie、`X-Tt-Token`、`d_ticket` 与设备参数；
- **账号独占设备参数**：原生 `device_id`、`install_id`、`openudid`、`cdid` 按账号 ID 确定性派生并加密保存，不跨账号共享；
- **登录即持久化**：原生会话保存后，由纯 Rust TokenBeat 持续更新票据，并尝试获取 Web/IM 身份和 Guard 材料；
- **安全降级**：App 原生登录成功但 Web/IM 材料未就绪时仍保存原生会话，状态明确标记 `web_ready=false`，后台按六小时节流恢复，不伪装为可发送。

### 2. 标准操作流程
1. 账号管理页点击「添加账号」，填写别名（可留空）并点击「获取登录二维码」；
2. 使用抖音 App 扫描页面二维码并在手机端确认；
3. 服务端轮询官方状态，确认后自动保存并建立 Web/IM 发送上下文；
4. 若新设备被官方 TicketGuard 拒绝，可在「添加账号」中直接选择「导入原生会话」，无需先创建账号；网页导入会按 UID 查重，详见 [原生会话导入说明](native-session-import.md)；
5. 导入后账号显示为「App 原生会话已保存」，后台自动 TokenBeat。

### 3. 登录相关接口
| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/accounts/login/start` | 申请官方二维码，返回 `login_id`、`qrcode`、`expires_in` |
| GET | `/api/v1/accounts/login/{id}` | 轮询官方扫码状态并在确认后原子落库 |
| POST | `/api/v1/accounts/login/{id}/cancel` | 放弃当前二维码会话 |

## 三、 目标管理与功能优化

### 1. 好友头像与备注名自动同步
- **数据更新**：后端 `UpdateTargetReq` 与数据库持久化逻辑全面支持 `target_avatar` 与 `remark_name`；
- **会话备注提取**：在好友同步与批量添加时，自动解析 IM 会话返回的参与者扩展信息中的专属备注名，并抓取官方高清头像链接写入数据库；
- **前台展示优化**：目标列表优先高亮展示好友备注名，并在旁展示抖音原生昵称；在编辑目标弹窗中提供备注名修改输入框；头像自带防盗链与加载失败平滑降级。

### 2. 监控开关与手动测试解耦
- **监控开关定义**：目标卡片上的「监控开关」仅控制每日定时后台自动化调度是否处理该目标（禁用时自动跳过）；
- **手动测试无阻断**：关闭监控（`is_enabled = 0`）绝不禁用手动点击「续火花」测试，用户随时可以在前台发起实发验证；
- **静默测试机制**：所有前台手动点击的测试操作，结果均直接通过网页 Toast/弹窗呈现，**100% 屏蔽 Bark 通知**，杜绝手机收到调试扰民推送。仅在后台定时任务执行异常或账号登录态真实失效时向移动设备发送告警。

---

## 四、 生产环境部署与运维

### 1. Docker Compose 编排启动

Docker 与宿主机裸机运行都支持二维码协议、原生会话导入、TokenBeat 与自动续期，不需要浏览器运行时。

在宿主机上准备 `docker-compose.yml`：
```yaml
version: '3.8'

services:
  sparklight:
    image: sparklight:latest
    container_name: sparklight
    restart: always
    ports:
      - "11090:8080"
    environment:
      - RUST_LOG=info
      - TZ=Asia/Shanghai
      - SPARK_HOST=0.0.0.0
      - SPARK_PORT=8080
      - SPARK_DATA_DIR=/data
      - SPARK_SCHEDULE_TIME=09:03
    volumes:
      - ./data:/data
```

启动与管理命令：
```bash
# 启动（后台运行并重新构建）
docker compose up -d --build

# 查看运行状态
docker compose ps

# 实时跟踪日志
docker compose logs -f

# 停止容器
docker compose down
```

镜像本身不安装浏览器或扩展，并内置 `/usr/local/bin/native_session_import`。容器需要访问抖音官方 HTTPS 接口；新设备扫码被 `4044` 拒绝时使用导入器，具体命令见 [原生会话导入说明](native-session-import.md)。

### 2. 数据安全与持久化
- **数据目录**：挂载在 `./data` 目录下的 `sparklight.db` 保存全部账号、目标、调度与日志记录；
- **主密钥文件**：首次启动时系统会在数据目录生成 `.master-key`，所有账号凭证与 Guard 私钥均由该密钥通过 XChaCha20Poly1305 加密，文件权限严格为 `0600`，请务必妥善备份该密钥文件；
- **密钥安全**：如需迁移容器或主机，只需将 `./data` 目录整体迁移即可无缝恢复所有配置与会话。
