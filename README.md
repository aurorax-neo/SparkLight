# SparkLight - 抖音多账号隔离与每日续火花系统

SparkLight 是一款专为多抖音账号隔离维护、好友续火花对象管理与凭证健康监测设计的高性能轻量化系统。后端采用纯 Rust 原生开发（Axum + Tokio + SQLite + reqwest），前端采用 React 18 + TypeScript + TailwindCSS 现代化管理控制台。系统全程由 Rust 原生 HTTP/Protobuf 协议栈驱动，**无须常驻任何无头浏览器（Puppeteer / Playwright）**，内存占用极低，运行毫秒级响应。

---

## 核心特性

- **纯 Rust 原生协议栈，告别重量级浏览器依赖**：
  系统所有登录态巡检、好友关系同步、会话票据获取与发信互动请求均由纯 Rust 原生协议栈驱动，内存占用低（常驻仅数十兆），毫秒级极速响应，无需部署 Chromium 等重量级运行时。
- **Scheme A 官方全链签名体系（彻底杜绝 KICK 踢下线）**：
  - **正牌私钥与服务端票据持久化**：系统自主加密持有账号在真实浏览器中绑定的 P-256 签名私钥与官方服务端签发的 Ticket Guard 票据；
  - **100% 真实签名发送（Signed 模式）**：发信时使用该真实私钥对票据材料进行 ECDSA/HMAC 计算，携带完整的 `bd-ticket-guard-client-data`、`ts_sign`、`req_sign` 与 `t_trust: 1` 标识，彻底杜绝未签名公钥裸奔触发的风控下线；
  - **Protobuf 运行指纹全量对齐**：外层报文扩展头完整注入 19 项官方浏览器环境特征（如 `browser_platform`、`browser_version`、`screen_width`、`screen_height`、`timezone_name`、`cookie_enabled` 等），消息层注入高精度 `s:stime` 浮点时间戳；
  - **动态参数与 Client-Hints 补齐**：自动提取 `s_v_web_id` 构建 `verifyFp` 与 `fp`，动态派生高熵 `msToken`，补全现代浏览器 Client-Hints 与安全请求头。
- **油猴全自动凭证提取助手（UserScript v2.2.0）**：
  - 提供专属 UserScript 脚本（`tools/sparklight_extractor.user.js`），支持 Tampermonkey 与 ScriptCat；
  - 在已登录的抖音网页版页面右下角常驻悬浮胶囊按钮，利用扩展特权能力一键聚合提取全量 HttpOnly Cookie（包含核心 `sessionid`、`passport_assist_user` 等）与 LocalStorage 中的官方 Guard 签名私钥和票据；
  - **100% 纯本地复制**：不产生任何外部网络请求，一键打包写入剪贴板，返回控制台一次粘贴即可完成导入；彻底废除控制台命令、本机 Python 助手及手动抓包等繁琐易错手段。
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

## 凭证一键提取与导入流程（油猴脚本 v2.2.0）

系统全面采用油猴全自动脚本一键提取全量凭证，无需打开开发者工具抓包，无需复制 cURL 命令。

### 第 1 步：安装油猴脚本
1. 在电脑浏览器（Chrome / Brave / Edge 等）安装任意用户脚本管理器扩展（推荐 **Tampermonkey** 或 **ScriptCat**）；
2. 在扩展中「添加新脚本」，将本项目中的 `tools/sparklight_extractor.user.js`（或在 SparkLight 控制台「全自动凭证提取助手」中点击「复制油猴脚本代码」）粘贴并保存。

### 第 2 步：一键提取并复制
1. 打开或刷新已登录的抖音网页版页面（`https://www.douyin.com/`）；
2. 页面右下角会自动出现悬浮胶囊按钮：**`⚡ 复制 SparkLight 全量凭证`**；
3. 点击该按钮，脚本自动聚合全量 HttpOnly Cookie 与 Guard 签名私钥，写入系统剪贴板并弹出成功提示。

### 第 3 步：一次粘贴导入
1. 返回 SparkLight 控制台，在「添加账号」或「更新凭证」输入框中直接粘贴（Cmd+V / Ctrl+V）；
2. 系统自动识别全量凭证对象，将 Cookie 与 Guard 密钥材料加密绑定入库。

#### 导入凭证对象格式（sparklight_credential 规范）
导出的凭证为标准 JSON 对象，格式如下（系统仅在内存解密，落库全程加密）：
```json
{
  "type": "sparklight_credential",
  "version": "2.2.0",
  "extracted_at": "2026-10-16T12:00:00.000Z",
  "uid": "12345678901",
  "nickname": "示例用户",
  "cookie": "sessionid=***; passport_assist_user=***; ...",
  "guard_private_key": "3081...",
  "guard_server_data": "{\"ticket\":\"***\",\"expire_time\":...}"
}
```

---

## 攻坚历程与架构演进（从 KICK 到 Signed 成功）

### 1. 早期痛点与 KICK 踢线根因
在早期探索阶段，系统发信曾偶发出现 `{"decision": "KICK"}` 异常导致用户抖音账号被迫下线。经抓包与协议层深度比对，定位出以下核心原因：
- **临时随机私钥缺陷**：在旧链路中，由于未能捕获浏览器已登录的 Guard 私钥，后端回退到由 Rust 本地随机生成 P-256 临时私钥对并向服务端发送裸公钥；这触发了服务端的会话劫持与异常环境风控模型，导致服务端判定凭证泄露并直接吊销 Cookie。
- **环境指纹与 Header 缺失**：缺少发信报文外层 Protobuf 扩展头中要求的 19 项设备参数（屏幕尺寸、时区、浏览器特征等），以及现代浏览器 Client-Hints 和高精度 `s:stime`。
- **旧工具链局限**：早期尝试的控制台脚本受限于浏览器安全机制无法读取 HttpOnly Cookie；而本地 Python 助手仅能读取浏览器 Cookie 数据库，无法获取 LocalStorage 中存储的 Guard 密钥与票据，导致凭据链条残缺。

### 2. Scheme A 突破与全面闭环
为了从根本上解决凭证健康与稳定发送问题，系统实施了 Scheme A 官方签名体系重构：
1. **浏览器正牌私钥与票据复用**：利用油猴脚本特权直接提取浏览器已完成验证的真实 P-256 签名私钥与 Ticket Guard 票据，并实现 30 天超长有效期安全持久化复用；
2. **全流程 Signed 签名**：每次发信时均通过真实私钥进行 HMAC/ECDSA 计算，携带真实 `bd-ticket-guard-client-data`、`ts_sign`，将发信模式彻底升级为 100% `Signed`；
3. **报文指纹严格对齐**：完整补齐 Protobuf 19 项环境特征扩展头，动态派生高精度时间戳与安全令牌；
4. **实测验收**：在真实多账号互发场景下进行了多轮验证，发信成功率达 100%，会话稳定常青，彻底消除 KICK 下线风险。

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
│   │   ├── pages/AccountsPage.tsx # 账号管理与凭证提取指引
│   │   ├── pages/TargetsPage.tsx  # 目标管理、头像展示与备注编辑
│   │   ├── pages/DashboardPage.tsx# 系统状态大盘
│   │   ├── pages/LogsPage.tsx  # 交互与调度审计日志
│   │   └── pages/SettingsPage.tsx # 定时时间与 Bark 配置
│   └── dist/                   # 预构建前端静态资源 (由 Rust 自动托管)
├── tools/
│   └── sparklight_extractor.user.js # 官方推荐：油猴全自动凭证提取脚本 (v2.2.0)
└── tests/
    └── api_auth_test.rs        # 接口鉴权与加密集成测试
```

---

## 启动与部署

### 方式一：Docker Compose 容器化部署（推荐）

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

---

### 方式二：裸机直接编译运行

#### 1. 编译前端（若已存在 `frontend/dist` 可跳过）
```bash
cd frontend && npm install && npm run build && cd ..
```

#### 2. 编译并启动后端服务
```bash
cargo run --release
```

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
