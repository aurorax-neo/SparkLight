# PCIM 初始化公钥分支：动态实抓与独立 Rust 验收

## 已验证结论

指定账号 UID 99191692311 → UID 55696816245、原模板的 PCIM 发送，可在没有旧 Guard ticket/ts_sign/client_cert、没有 client-data 签名、没有 DTrait 请求头的初始化公钥分支成功。此结论来自真实动态抓取与独立 Rust 验收，不是静态推断，也不推论所有账号或接口都不需要 Guard。

### 动态证据

- 独立隐私浏览器上下文只导入现有研究账号登录 Cookie，未复制 Guard Cookie、密钥或签名缓存；不重新登录。
- 原函数断点与函数挂钩确认：`getKeysInfoWithOrigin → _initCookie → _processServerCookie` 返回空 ticket/ts_sign/client_cert；未观察到材料写入。
- 官方 UI 发起 IM 身份获取成功，只携带初始化公钥头，无 client-data。
- `runtime-send-02`：一次 OPTIONS 预检、一次 POST；服务端外层/内层/check_code 均0，消息ID `7696916217378948657`，UUID `84fd7313-e4c5-4dc5-8cf5-307417d2bbe2`。
- CDP Network 实际 POST 头仅含四个 Guard 初始化头；无 client-data、DTrait。身份前后检查通过。
- 独立 Rust 只读历史核验上述 ID/UUID/发送人/目标/原文/类型/北京时间日期全部通过。
- `runtime-send-01` 的门禁把预检计入额度、随后拒绝消息请求，不能当作服务端拒绝；保留记录，不重跑。
- `runtime-presend-01` 的六次 SDK 请求被拦截，实际发送0。研究发送不设人工次数上限，但每次单独记账、禁止自动重试出网。

### REA 与调试覆盖

- Guard单文件REA父证据：`ev_47ecf2b5018220afba46de7b52a5621335a58a4723f259bcd749df74bd3c5622`。语法解析成功，语义图因堆内存限制不完整。
- REA浏览器列表：`ev_82fa537cc625c5c31c33144f941ce50f5c711872364087fc85ed35547057494a`。
- REA被动页面：`ev_9acccdb98f262ae68fbcb9a7df9681f68324342b9733101d5a008b97e36c1706`。仅连接窗口观测，未覆盖之前请求；来源过滤排除了CDN脚本，不能据此声称完整运行时图。
- 主动CDP断点/Network/WS与函数挂钩记录是独立的主动调试证据，不冒充REA被动记录。真实原函数断点映射到PCIM `5770.1fc7435b.js`，SHA256 `19584d9b6099b1eb538cb8b30695d47eedf86f2358b03a9f29c3d1de7db851f3`。

## 独立 Rust 真发验收

`rust-initial-01` 完全由 Rust 获取身份、cmd610 会话票据、构造请求、生成独立P256公钥并提交。未调用浏览器、Node或签名服务发消息，未借用浏览器签名/私钥/证书。

- 状态：`VERIFIED`
- 消息ID：`7696921162286204465`
- UUID：`292bbb38-eb76-44e4-8146-72bb89d84a68`
- HTTP200；严格回包解析通过；仅提交1次。
- 身份前检、完整当日历史预检、身份后检、准确UUID/ID/发送人/目标/原文/类型/日期历史核验全部通过。
- 当日已发送事实记录为true；本次属于明确授权的新研究验收，不清除或重试旧UNKNOWN。
- 生产写入0；本次验收暂未接入生产调度。

## 协议修正依据

预加载门禁内零发送捕获确认SDK `0.1.8`、build `0d50935:feat/pc-im-group`、inbox_type=0、identity_security_aid为空字符串；正文为aweType700/type0/richTextInfos空数组/原text；ext中的s:client_message_id与field8 UUID一致。Rust未伪造浏览器特征，只保留必要已验证字段；省略s:stime等字段的最小构造已被上述Rust真发验证。

## 生产接入与验收（2026-10-16）

已将初始化公钥分支接入生产调度的 `load_send_credential → send_spark_message`，仅开放指定账号、目标、类型1和原模板。无需捕获式一次性发送凭证，不依赖浏览器、Node或签名服务。

- 原子日占用：单条 INSERT SELECT 校验账号 ACTIVE、加密 Cookie、目标绑定、启用状态和模板，提交前写入 UNKNOWN；已有同日记录一律阻止，不覆盖旧记录。
- 失败或未知属于 fatal，不重试、不回退；只有严格 ACK、身份后检和精确 UUID/消息ID历史均通过，才 CAS 更新为 ACCEPTED。
- 当日历史已发即跳过，强制执行也不能绕过限定分支去重。旧 Guard 材料仅在内存请求中隔离，不改写持久 Cookie。
- 排队后复核 Cookie、身份、历史及请求；数据库事务不跨网络持锁。
- 中断遗留的测试锁接口已补齐。工作区141项库测试通过；选择性发布包及远端镜像各137项通过（排除未发布浏览器同步的4项）。离线 tests 检查和二进制构建通过。

### 108 发布

- 地址：`10.96.1.108:11090`。
- 镜像：`sparklight:pcim-initial-20261016-003144`。
- 回滚镜像：`sparklight:before-pcim-initial-20261016-003144`。
- 备份：`/opt/docker/sparklight-backups/pcim-initial-20261016-003144`。
- 二进制 SHA256：`1f9886418b25ef4d3b80f9f40bdeea17e883c7977adeef66dd82e6afd1d69e61`。
- 保留生产前端 dist；未部署浏览器同步及无关前端变更。未迁移或恢复数据库，调度仍为14:25，设置哈希不变。已有日占用表仅增加幂等建表声明。

### 生产自动路径真发

北京时间已进入2026-10-16，前检未发现今日已发或今日占用。确认该账号只有获授权目标后，通过生产账号运行接口调用与定时任务共用的自动执行路径一次；未调用全账号任务或研究CLI。

- 结果：HTTP200，账号 ACTIVE，SUCCESS，成功1、失败0、跳过0、目标总数1。
- 消息ID：`7696934512772711985`。
- UUID：`5a38d95f-6366-4b6e-9f38-5f556ba1b576`。
- 2026-10-16仅新增1条 ACCEPTED；严格ACK、身份后检与精确历史核验均为成功必需条件。
- 2026-10-15旧 UNKNOWN及其UUID原样保留；其他目标发送状态、调度和前端哈希未变。
- 健康检查 healthy、数据库 quick_check=ok、foreign_key_check无错误。生产 SEND_SPARK 成功日志与消息ID一致。
- 未再次触发发送；线上去重不通过第二次发送请求测试，封闭测试覆盖今日已发、并发日占用与UNKNOWN不重试。

部署与验收证据位于会话scratch `pcim-production-release/`，远端对应 `/opt/docker/sparklight-pcim-initial-release/`；研究证据仍在 `pcim-rust-parity/`。一次性启动标记不删除、不重置。凭证未输出到日志，临时研究浏览器已关闭。

本次限定生产路径已完成，无剩余实施阻塞；不推广为其他账号或平台接口均支持此分支，也不据此结算旧UNKNOWN。
