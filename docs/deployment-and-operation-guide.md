# SparkLight 部署运维与方案完全指南

---

## 一、 系统架构与 Scheme A 全链签名体系

SparkLight 是专为抖音网页版/PC IM 会话隔离、自动化与手动续火花设计的轻量独立系统。系统基于纯 Rust 原生 HTTP 协议栈开发，无头浏览器零常驻，摆脱了传统自动化工具对高内存消耗和重量级浏览器驱动的依赖。

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
- **正牌私钥与票据随 Cookie 一同托管**：借助油猴脚本将浏览器中已建立合法认证的 ECDSA P-256 私钥和平台签发的 Ticket Guard 票据完整导出并持久化至 Rust 后端，有效期支持 30 天超长复用；
- **全流程强制 Signed 真实签名**：发信时 100% 调用真实的 `sign_send` 签名链路，请求头携带合法的 `bd-ticket-guard-client-data`（包含真实 `ts_sign`、`req_sign` 和 `t_trust: 1`）；
- **动态装配 URL 参数与运行指纹**：自动提取 `s_v_web_id` 组装 `verifyFp` 与 `fp`，动态生成合规格式的 `msToken`，并将 19 项设备运行环境特征完整注入 Protobuf Field 15；
- **验收结果**：连续执行多轮真实发信，均收到平台官方下发的 127 字节标准 Protobuf 回执，消息即时送达聊天窗口，会话保持持续有效（ACTIVE），彻底终结了 KICK 掉线顽疾。

---

## 二、 凭证一键全自动提取（油猴脚本 v2.2.0）

为了彻底解决传统方式易错且无法获取浏览器私钥的痛点，系统全面启用油猴全自动脚本方案。

### 1. 脚本机制
- **脚本源码**：`tools/sparklight_extractor.user.js`（或在控制台「全自动凭证提取助手」中一键复制）；
- **扩展特权提取**：利用用户脚本扩展的 `@grant GM_cookie` 与 `@grant GM.cookie` 特权，同时以多种匹配策略穿透浏览器沙箱，静默抓取包括 HttpOnly（如 `sessionid`、`passport_assist_user`）在内的全套 Cookie；
- **提取私钥与票据**：自动读取 LocalStorage 中存储的加密 SDK 密钥对与 ServerData 票据，在本地完成格式解析；
- **100% 纯本地复制**：不产生任何外部网络上传请求，提取后直接以一体化结构（`sparklight_credential`）写入系统剪贴板。

### 2. 标准操作流程
1. 在浏览器安装 **Tampermonkey** 或 **ScriptCat** 扩展；
2. 新建脚本并粘贴脚本代码保存；
3. 打开或刷新已登录的抖音网页版页面（`https://www.douyin.com/`）；
4. 点击页面右下角悬浮胶囊按钮 **`⚡ 复制 SparkLight 全量凭证`**；
5. 回到 SparkLight 控制台，在添加账号或更新凭证输入框中直接粘贴（Cmd+V / Ctrl+V）即可。

### 3. 凭证格式规范（脱敏示例）
系统导出的凭证对象为规范的 JSON 结构：
```json
{
  "type": "sparklight_credential",
  "version": "2.2.0",
  "extracted_at": "2026-10-16T12:00:00.000Z",
  "uid": "12345678901",
  "nickname": "示例昵称",
  "cookie": "sessionid=***; passport_assist_user=***; ...",
  "guard_private_key": "3081...",
  "guard_server_data": "{\"ticket\":\"***\",\"expire_time\":...}"
}
```

---

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

### 2. 数据安全与持久化
- **数据目录**：挂载在 `./data` 目录下的 `sparklight.db` 保存全部账号、目标、调度与日志记录；
- **主密钥文件**：首次启动时系统会在数据目录生成 `.master-key`，所有账号凭证与 Guard 私钥均由该密钥通过 XChaCha20Poly1305 加密，文件权限严格为 `0600`，请务必妥善备份该密钥文件；
- **密钥安全**：如需迁移容器或主机，只需将 `./data` 目录整体迁移即可无缝恢复所有配置与会话。
