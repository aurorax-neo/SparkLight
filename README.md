# SparkLight - 抖音多账号隔离与每日续火花系统

SparkLight 是一款专为多抖音账号隔离维护、好友续火花对象管理与凭证健康监测设计的高性能自动化系统。后端采用纯 Rust 原生开发（Axum + Tokio + SQLite），前端采用 React + TypeScript + TailwindCSS 现代化工作台，前后端分离，安全可控。

> 2026-10-15 工程收口：当前证据不足以可靠交付自动 Cookie／后台会话续期及纯 Rust 无人值守签名，已停止该未验证路线，生产 SDK 门禁保持关闭。108 已部署账号失败诊断、真实批次结果与日期状态修复，但缺少合法 Web IM 上下文／发送凭证时仍安全停止，不代表自动发送能力恢复。详见 [收口与部署报告](docs/renewal-closeout-and-deployment-20261015.md)。

---

## 🌟 核心特性

- **纯 Rust 原生后端，零浏览器依赖**：系统所有 Cookie 检测、好友会话拉取与续火花互动请求均由纯 Rust 原生 HTTP 协议栈实现，无需任何 Playwright / Puppeteer / 无头浏览器常驻。
- **强制独立登录页与鉴权守卫**：未登录状态严禁渲染任何内部业务界面与数据，输入管理 API Key 经过服务端真实验证通过后方可进入控制台。
- **多账号网络会话强隔离**：为每个抖音账号构建独立的客户端连接与 Cookie 容器，各账号互不串扰、互不影响。
- **高等级安全加密存储**：
  - 账号 Cookie 落地 SQLite 数据库前统一经过 **XChaCha20Poly1305** 高强度 AEAD 算法加密；
  - 主加密密钥持久化于 `.master-key`，文件权限严格限制为 `0600`（仅所有者读写）；
  - 控制台与接口全链路对 Cookie 明文执行脱敏掩码展示，严防敏感凭证泄露。
- **全接口 API Key 认证与敏感显示处理**：
  - Axum 中间件全局校验请求头 `X-API-Key` 或 `Authorization: Bearer <key>`；
  - 设置页面中 API Key 与 Bark Key 默认以密码密文形式隐藏，支持一键切换明文/密文与安全复制。
- **服务端 Cookie 更新保存**：只在响应校验通过后合并 `Set-Cookie`；拒绝删除/清空关键登录凭证。更新不代表账号一定有效，也不保证延长登录期限。
- **Web 请求风控保护**：统一接口白名单、实时 Cookie、浏览器身份、来源头及响应校验；遇到验证、限流或协议异常停止同会话请求，不以重建客户端绕过停发。
- **精细化续火花对象管理**：
  - 支持一键从抖音接口同步好友/关注列表并多选批量导入；
  - 支持手动输入好友 SecUID 与自定义打招呼消息（默认 `🔥`）；
  - 支持单账号、单目标立即测试发送与互动状态追踪。
- **Bark 实时告警推送**：
  - 支持全局 Bark 推送服务地址与 Device Key；
  - 支持多账号配置专属独立的 Bark Key 进行消息分流；
  - 当定时巡检发现 Cookie 失效或触发平台风控验证时，第一时间推送告警至 iOS 设备。
- **每日定时任务与请求间隔**：
  - 内置每日调度；发送仍须具备当前账号、目标会话的有效官方凭证。
  - 同会话请求串行并至少间隔 350 毫秒，目标之间保留配置的随机延迟；不保证免于平台风控。
- **Brave 调试辅助工具**：
  - 提供 `tools/open_brave.sh` 脚本与前端一键启动快捷入口，以系统默认配置调起 `/Applications/Brave Browser.app` 打开抖音，仅用于人工登录与复制 Cookie。

---

## 🍪 抖音 Cookie 获取方法与代码

推荐在浏览器（如系统中的 Brave 浏览器）登录抖音后，通过以下两种便捷方式获取有效 Cookie：

### 方式一：Network (网络) 面板一键复制 cURL 粘贴（推荐最快、100% 完整）

> **特别注意**：由于现代浏览器安全规范，核心登录凭证 `sessionid` 具有 **`HttpOnly`** 标记，任何网页 JS 脚本都**无法**通过 `document.cookie` 读取到它。如果仅复制 `document.cookie`，将缺少关键的 `sessionid` 凭证导致提示“Cookie 已失效”。

最快、最完整的获取方式如下：
1. 在浏览器登录抖音网页版（`https://www.douyin.com/`）；
2. 按 `F12`（Mac 为 `Command + Option + I`）打开开发者工具，切换到 **Network (网络)** 标签页；
3. 刷新页面或点击任意关注/好友私信；
4. 找到任意发送到 `douyin.com` 的网络请求，**鼠标右键 ➔ 复制 ➔ 复制为 cURL (bash)**（或 Copy as cURL）；
5. **直接粘贴到 SparkLight 控制台的“添加账号”输入框中**（SparkLight 系统已内置智能 cURL 解析器，会自动秒级提取出包含 `sessionid` 的完整 Cookie）。

---

### 方式二：浏览器控制台同步助手脚本（在页面弹窗一键同步）

在已登录抖音的控制台运行 SparkLight 控制台专用脚本，页面中央将弹出「SparkLight 凭证同步面板」：
- 面板支持自动检测剪贴板捕获的 cURL 或手动填入 `sessionid`；
- 点击「🚀 一键上传同步」即可秒级更新到后台，无需手动复制粘贴。

## 🏗️ 架构概览

```
SparkLight/
├── Cargo.toml                  # Rust 后端依赖与工程配置
├── Dockerfile                  # 容器化构建定义
├── docker-compose.yml          # Docker Compose 编排服务
├── src/
│   ├── main.rs                 # 服务启动与优雅停机
│   ├── config.rs               # 环境变量与配置装配
│   ├── crypto.rs               # XChaCha20Poly1305 加解密与脱敏规则
│   ├── db/                     # SQLite 数据库模型与 CRUD 操作
│   ├── douyin/                 # 纯 Rust 抖音客户端（隔离连接、凭证检测、响应 Cookie 更新保存、受限互动）
│   ├── notify/                 # Bark 推送客户端 (支持全局与账号独立 Key)
│   ├── scheduler/              # 每日定时调度器与手动执行引擎
│   ├── server/                 # Axum Web 服务、API Key 鉴权中间件与路由
│   └── util.rs                 # 本地 Brave 浏览器启动封装
├── frontend/                   # React 18 + TypeScript + TailwindCSS 控制台
│   ├── src/
│   │   ├── pages/LoginPage.tsx # 独立安全登录页（未授权守卫拦截）
│   │   ├── pages/DashboardPage.tsx
│   │   ├── pages/AccountsPage.tsx
│   │   ├── pages/TargetsPage.tsx
│   │   ├── pages/LogsPage.tsx
│   │   └── pages/SettingsPage.tsx # 敏感密钥隐藏与脱敏处理
│   └── dist/                   # 构建产物 (后端自动托管静态资源)
├── tools/
│   └── open_brave.sh           # 默认配置启动 Brave 浏览器脚本
└── tests/
    └── api_auth_test.rs        # 接口鉴权与加密集成测试
```

---

## 🚀 启动与部署

### 本地启动

```bash
# 1. 编译前端
cd frontend && npm install && npm run build && cd ..

# 2. 编译并运行后端
cargo run --release
```

服务默认监听 `http://127.0.0.1:8080`，启动时终端将输出本次自动生成的 API Key：
```text
============================================================
 SparkLight 已生成系统管理 API Key: sk_...
 请在控制台登录或请求头中携带: X-API-Key: sk_...
============================================================
```

浏览器打开 `http://127.0.0.1:8080`，直接进入独立登录页面，输入 API Key 即可进入工作台。

---

### Docker 容器化部署

```bash
docker compose up -d --build
```

查看日志与状态：
```bash
docker compose ps
docker compose logs -f
```

---

## 🧪 单元测试

仅运行离线库测试与编译检查；集成目录包含真实消息测试，不应直接执行全部 `cargo test`：

```bash
cargo test --lib
cargo check
cargo check --tests
```

## Web 接口覆盖与能力边界

- 已统一覆盖：Passport 身份、自身/他人资料、好友关系、关注分页、IM 用户备注，以及 IM 会话信息（610）、消息历史（301）和发送（100）。
- 账号 Cookie、只读 Web 上下文、一次性发送凭证分别加密保存。上下文绑定 UID、会话和真实 UA；Cookie 替换清除旧上下文/发送凭证。导入官方凭证的接口需要管理 API Key，导入本身不发送消息。
- 只读 IM 上下文有效期为采集后 10 分钟，只能用于 301/610；不包含发送体、会话 Ticket 或路径签名。发送需要对应目标的官方凭证，消费一次后不可复用。
- “今日已发送”仅由当前账号在北京时间当天的出站消息确认；历史截断、缺少真实短 ID、记录不完整均视为未知，不据此重复发送。异常火花响应不覆盖现有状态。
- 验证/失效会话冷却 24 小时，限流/协议异常及发送结果未知冷却 30 分钟；同会话状态在进程内共享，重启不保留冷却。网络查询失败不自动认定 Cookie 失效。
- 尚未实现通用动态 `a_bogus`、`msToken`、浏览器指纹或每路径 SDK 签名；不伪造或跨接口借用签名。未登记的域名/路径不携带凭证请求。
- 官方 IM 材料目前仍需人工同步，尚不能无人值守自动续凭证。因此不能宣称全部接口已与官方 Web 完全等价，也不能保证每天自动续火成功。
- 本轮验证为离线回归、编译和部署完整性检查；没有进行全部抖音接口线上验收。

## 官方 SDK 研究与更新边界

- 官方静态资源来源、版本、SHA-256 和入口固定在 `src/douyin/sdk/manifest.json`；执行证据、可重跑命令及阻碍见 [docs/sdk-evidence.md](docs/sdk-evidence.md)。
- Rust 内嵌 QuickJS 可离线执行锁定的官方 `ticket/path/timestamp` 输入构造片段，已与原始 SDK 的 Node.js 执行基准对照；这不是完整签名，不代表服务端接受。
- `sdk_audit` 是与业务服务分离的显式维护命令，支持资源获取、校验、隔离探针及候选门禁。正常请求不下载或自动执行候选；当前生产 SDK 状态为 `disabled`。
- 完整动态签名、按路径 Ticket Guard 签名及无人值守续凭证仍未验证启用。研究工具可使用 Node.js，但生产不启动浏览器、Node.js 或外部签名服务；已捕获的发送凭证只允许用于固定 HTTPS 发送路径，拒绝追加查询和跨路径复用。
