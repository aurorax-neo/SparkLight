# SparkLight - 抖音多账号隔离与每日续火花系统

SparkLight 是一款专为多抖音账号隔离维护、好友续火花对象管理与凭证健康监测设计的高性能轻量化系统。后端采用纯 Rust 原生开发（Axum + Tokio + SQLite + reqwest），前端采用 React 18 + TypeScript + TailwindCSS 现代化管理控制台。二维码协议、TokenBeat、Web/IM 身份获取、原生会话导入与发信请求全部由 Rust 进程完成，不依赖 Brave、Chrome、ScriptCat、Puppeteer 或 Playwright。

---

## 核心特性

- **纯 Rust 原生协议栈，无外部浏览器依赖**：
  登录态巡检、好友关系同步、身份票据获取与发信互动均由 Rust 协议栈驱动；添加账号时直接在页面内展示抖音 App 官方二维码，确认后保存原生 Cookie、`X-Tt-Token`、`d_ticket`、`session_key` 与账号级设备参数。原生校验每 30 分钟节流，App TokenBeat 与 Web 身份 Token 每 6 小时维护，网络或协议异常只标记“未确认”，不会清空仍可恢复的登录态。
- **Scheme A 官方全链签名体系（严格按官方链路签名，降低 KICK 风险）**：
  - **Guard 私钥与服务端票据持久化**：Rust 在登录后的 Web/IM 引导阶段获取并加密保存账号对应的 P-256 Guard 私钥与官方服务端票据；
  - **100% 真实签名发送（Signed 模式）**：发信时使用该真实私钥对票据材料进行 ECDSA/HMAC 计算，携带完整的 `bd-ticket-guard-client-data`、`ts_sign`、`req_sign` 与 `t_trust: 1` 标识，彻底杜绝未签名公钥裸奔触发的风控下线；
  - **Protobuf 运行指纹全量对齐**：外层报文扩展头完整注入 19 项官方浏览器环境特征（如 `browser_platform`、`browser_version`、`screen_width`、`screen_height`、`timezone_name`、`cookie_enabled` 等），消息层注入高精度 `s:stime` 浮点时间戳；
  - **动态参数与 Client-Hints 补齐**：自动提取 `s_v_web_id` 构建 `verifyFp` 与 `fp`，动态派生高熵 `msToken`，补全现代浏览器 Client-Hints 与安全请求头。
- **应用内扫码与官方原生会话导入，无需安装浏览器或扩展**：
  - 添加账号时由 Rust 直接请求抖音 App `get_qrcode` 官方接口，并在管理页展示二维码；受信任设备可直接完成登录；
  - 抖音对新设备启用 TicketGuard/TEE 设备证明，纯软件无法生成真实 Android 硬件证明。被 `4044` 拒绝时，使用 `native_session_import` 导入同一账号在官方 Android 客户端已建立的原生会话，再由纯 Rust TokenBeat 持续维护；
  - TokenBeat、身份 Token、Guard 私钥与票据材料均由 Rust 请求和加密落库，不复制日常浏览器 Cookie；
  - **账号级设备指纹隔离**：指纹由账号 ID 确定性派生并加密持久化，同一账号永久一致、不同账号必然不同，杜绝多账号共用指纹导致的风控关联。
- **好友头像与备注名（remark_name）智能同步**：
  - 一键同步关注好友列表，自动解析会话扩展中的真实备注名（`remark_name`）与高清头像链接并更新入库；
  - 目标列表中优先高亮显示备注名并括注抖音原生昵称；支持在编辑弹窗中自定义修改备注名，头像自带防盗链处理与加载失败自动降级。
- **监控开关与手动测试完全解耦**：
  - 目标列表的「监控开关」仅控制每日后台定时自动化调度（禁用时后台跳过该目标）；
  - 关闭监控**绝不禁用**手动续火花测试，用户可随时在界面上发起实发测试验证。
- **静默手动测试（告别手机推送打扰）**：
  - 所有前台手动点击的测试操作（包括手动续火花、账号检测等），结果直接在网页端 Toast/弹窗呈现，**100% 屏蔽 Bark 通知**；
  - 仅在后台定时任务执行异常或登录态真实失效时向移动设备发送告警。
- **多账号网络会话强隔离与高等级加密存储**：
  - 账号凭证与私钥落地数据库前统一经过 **XChaCha20Poly1305** 高强度 AEAD 算法加密；
  - 主加密密钥持久化于 `.master-key`，文件权限严格限制为 `0600`（仅所有者读写）；
  - 控制台与接口全链路对 Cookie 执行脱敏掩码展示，严防敏感凭证泄露。

---

## 账号登录与凭证同步流程

系统不提供浏览器 Cookie 复制入口，也不读取用户日常浏览器资料。服务端直接对接抖音 App Passport；新设备若被 TicketGuard/TEE 拒绝，可导入官方 Android 客户端的原生会话。

### 第 1 步：发起登录
1. 在账号管理页点击「添加账号」，填写别名（可留空，登录后自动取抖音昵称）；
2. 点击「获取登录二维码」，服务端会向抖音申请该账号独占设备参数对应的官方二维码。

### 第 2 步：使用抖音 App 确认
1. 使用抖音 App 扫描页面中的二维码；
2. 在手机端确认登录，页面会实时显示已扫码、等待确认、成功或过期状态。

### 第 3 步：自动同步
1. Rust 服务端收到官方确认后解析 UID、`sec_uid`、昵称、头像、Cookie 与原生令牌；
2. 会话、账号独占设备参数、Web/IM 身份和 Guard 材料在同一事务内加密落库，账号立即变为「登录正常」；若 Web 发送材料暂未恢复，会明确显示待恢复，而不是伪装为可发送。

### 已失效账号的重新登录
账号卡片右侧的登录按钮可重新获取二维码。若抖音明确返回 `4044` TicketGuard 设备证明拒绝，可在「添加账号」中直接导入同一官方 Android 客户端建立的原生会话；新账号无需先扫码，服务端会按 UID 查重。详见 [原生会话导入说明](docs/native-session-import.md)。导入成功后由 App TokenBeat 自动维护，不需要重新复制 Cookie。

---

## 攻坚历程与架构演进（从 KICK 到 Signed 成功）

### 1. 早期痛点与 KICK 踢线根因
在早期探索阶段，系统发信曾偶发出现 `{"decision": "KICK"}` 异常导致用户抖音账号被迫下线。经抓包与协议层深度比对，定位出以下核心原因：
- **临时随机私钥缺陷**：在旧链路中，由于未能捕获浏览器已登录的 Guard 私钥，后端回退到由 Rust 本地随机生成 P-256 临时私钥对并向服务端发送裸公钥；这触发了服务端的会话劫持与异常环境风控模型，导致服务端判定凭证泄露并直接吊销 Cookie。
- **环境指纹与 Header 缺失**：缺少发信报文外层 Protobuf 扩展头中要求的 19 项设备参数（屏幕尺寸、时区、浏览器特征等），以及现代浏览器 Client-Hints 和高精度 `s:stime`。
- **旧工具链局限**：早期尝试的控制台脚本受限于浏览器安全机制无法读取 HttpOnly Cookie；而本地 Python 助手仅能读取浏览器 Cookie 数据库，无法获取 LocalStorage 中存储的 Guard 密钥与票据，导致凭据链条残缺。

### 2. Scheme A 突破与全面闭环
为了从根本上解决凭证健康与稳定发送问题，系统实施了 Scheme A 官方签名体系重构：
1. **Guard 私钥与票据持久化**：登录后的纯 Rust Web/IM 引导按官方流程取得 P-256 Guard 私钥与 Ticket Guard 票据，再加密持久化复用；
2. **全流程 Signed 签名**：每次发信时均通过真实私钥进行 HMAC/ECDSA 计算，携带真实 `bd-ticket-guard-client-data`、`ts_sign`，将发信模式彻底升级为 100% `Signed`；
3. **报文指纹严格对齐**：完整补齐 Protobuf 19 项环境特征扩展头，动态派生高精度时间戳与安全令牌；
4. **边界说明**：`sid_guard` 仍存在官方绝对有效期。系统通过原生 TokenBeat、Web TokenBeat、Cookie 轮换重绑和 Guard 票据自愈最大化静默可用时间，但不能承诺账号永久不需要重新登录。

---

## 功能说明

### 1. 账号管理
- **多账号隔离**：每个账号拥有独立的网络客户端、Cookie 密文与会话上下文；
- **健康检测**：随时检测 Cookie 有效性，自动同步账号昵称与头像；
- **独立推送**：支持为指定账号配置专属 Bark 推送 Key，未配置时自动继承系统全局 Key。

### 2. 续火花目标管理
- **好友一键同步**：点击「同步好友」自动拉取并解析互关好友的备注名、昵称、头像与火花天数；
- **备注名智能同步**：自动识别好友真实备注名（`remark_name`）并高亮展示；支持手动修改；
- **监控开关解绑**：开关仅控制后台定时调度；关闭监控后，**手动续火花测试依然完全可用**；
- **自定义互动内容**：支持为每个目标设置专属互动模板或表情（默认 🔥）。

### 3. 定时调度与告警
- **每日定时执行**：支持设置每日自动化续火时间（如 08:30）；
- **静默手动测试**：所有手动发起的检测与续火花操作，结果直接在前端反馈，**不触发 Bark 手机推送**；
- **自动化告警**：定时任务执行失败或账号异常失效时，自动触发 Bark 告警推送到移动设备。

---

## 项目架构

```text
SparkLight/
├── Cargo.toml                  # Rust 后端依赖与工程配置
├── Cargo.lock                  # 锁定依赖确定性版本
├── Dockerfile                  # 容器化构建定义
├── docker-compose.yml          # Docker Compose 编排服务
├── src/
│   ├── main.rs                 # 服务入口与优雅停机
│   ├── config.rs               # 环境变量与配置管理
│   ├── crypto.rs               # XChaCha20Poly1305 加密与凭据脱敏
│   ├── db/                     # SQLite 数据库模型与 CRUD
│   ├── douyin/                 # 纯 Rust 抖音协议栈
│   │   ├── client.rs           # 核心客户端接口
│   │   ├── device_profile.rs   # 账号级确定性设备指纹
│   │   ├── login.rs            # 纯 Rust App 二维码登录、原生校验与 TokenBeat
│   │   ├── pcim_guard.rs       # P-256 密钥对、签名与票据绑定
│   │   ├── pcim_init.rs        # PCIM 消息报文装配与严格 ACK 解析
│   │   ├── pcim_dtrait.rs      # DTrait 820 字节加密设备指纹
│   │   ├── pcim_features.rs    # 特征序列化与哈希运算
│   │   └── web.rs              # Web 请求统一网关与安全控制
│   ├── notify/                 # Bark 推送客户端 (支持全局与账号独立 Key)
│   ├── scheduler/              # 每日定时调度器与手动发信引擎
│   └── server/                 # Axum Web 接口、API Key 鉴权与前端静态资源托管
├── frontend/                   # React 18 + TypeScript + TailwindCSS 控制台
│   ├── src/
│   │   ├── pages/LoginPage.tsx # 安全登录页
│   │   ├── pages/AccountsPage.tsx # 账号管理与 App 二维码登录
│   │   ├── pages/TargetsPage.tsx  # 目标管理、头像展示与备注编辑
│   │   ├── pages/DashboardPage.tsx# 系统状态大盘
│   │   ├── pages/LogsPage.tsx  # 交互与调度审计日志
│   │   └── pages/SettingsPage.tsx # 定时时间与 Bark 配置
│   └── dist/                   # 预构建前端静态资源 (由 Rust 自动托管)
├── tools/                      # 离线分析与验收脚本（不参与运行时）
└── tests/
    └── api_auth_test.rs        # 接口鉴权与加密集成测试
```

---

## 启动与部署

### 方式一：Docker Compose 容器化运行

在项目根目录下执行：

```bash
docker compose up -d --build
```

查看运行状态与日志：
```bash
docker compose ps
docker compose logs -f
```

容器将持久化挂载 `./data` 目录用于存储 SQLite 数据库与加密主密钥。默认开放映射端口为 `11090`，可通过 `http://<服务器IP>:11090` 访问。

容器镜像不安装浏览器或扩展。受信任设备可直接在 Web 控制台扫码；新设备被 `4044` 拒绝时，镜像内置的 `native_session_import` 可导入官方 Android 原生会话。

---

### 方式二：宿主机直接编译运行

#### 1. 编译前端（若已存在 `frontend/dist` 可跳过）
```bash
cd frontend && npm install && npm run build && cd ..
```

#### 2. 编译并启动后端服务
```bash
cargo run --release
```

登录与续期不需要图形环境，也不需要安装浏览器。服务只需能访问抖音官方 HTTPS 接口。

服务启动后将监听配置的端口。首次启动时将在终端打印生成的系统管理 API Key：
```text
============================================================
 SparkLight 已生成系统管理 API Key: sk_...
 请在控制台登录或请求头中携带: X-API-Key: sk_...
============================================================
```
在浏览器中打开服务地址，输入该 API Key 即可登录使用。

---

## 单元测试与门禁检查

运行全部离线单元测试与协议解析测试：

```bash
cargo test --offline --lib
cargo check --offline
cargo check --offline --tests
```

所有离线测试均在独立模拟沙箱中 100% 通过验证。
