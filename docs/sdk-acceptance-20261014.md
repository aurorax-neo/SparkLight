# 2026-10-14：隔离签名与续期目标验收

目标契约：`.pi/goal/突破纯-rust-官方签名与续期阻碍并完成限定账号验收-20261014-1903.md`。本记录只描述该契约批准后的操作，历史成功发送和 Tab 修复部署不是本轮签名验收。

## 当前结果

**部分实现，完整目标未达到。** 已突破准确 `a_bogus` 离线入口定位，完成 22 例完整官方 BDMS 基准；Rust 可信时间模块已获真实响应接受并完成同客户端身份后检。独立 Ticket Guard 新公钥尚未取得服务端匹配签发材料，自动续期未验收。生产签名门禁不变，没有发送消息或部署。

## 实际账号操作

仅使用 `12345678`，UID `99191692311`。通过现有独立 Chrome DevTools 页面核对身份，再只读取该 MCP 配置当前 Douyin 会话 Cookie，权限 0600 暂存。未读取其他账号或日常浏览器材料，未导出浏览器私钥，未替换浏览器密钥、Cookie 或存储。临时 Rust 程序位于会话 scratch，未接入生产数据库或调度器。

1. 官方浏览器 GET `/passport/account/info/v2/?aid=6383`：HTTP 200、`message=success`、UID 匹配；无跳转、可见验证或 401/403/429。
2. Rust 隔离客户端身份预检：HTTP 200、JSON、UID 匹配，约 136 ms。剔除旧 Ticket Guard Cookie，不携带旧证书、ticket 或路径签名。
3. 一次新公钥候选请求：Rust 随机生成 P-256 密钥，以官方 `_processCookie` 结构编码客户端 Cookie，并携带官方公钥／版本头，请求已见消费端点 `/passport/account/info/v2/`。发送前以独占创建标记锁住尝试。HTTP 200、正确 UID，约 107 ms，但 **没有 `bd-ticket-guard-server-data` 或新签发 Cookie，服务端材料数 0、新公钥匹配 false**；不能当作注册成功。新私钥未导出到文件。
4. 该响应安全数值：`bd-ticket-guard-result=1103`、TEE result 1103、static ts/sign 1102、key-sign-result 2。官方源码仅将 1103 排除于一类失败诊断集合，没有足够语义证明接受；业务成功不是安全签名成功。未把这些值解释成 Cookie 失效或验证码。
5. 官方浏览器的 `trustedTimeService.requestServerTimestamp()` 一次：成功，来源 `trusted/active_sync`，没有借用其签名材料。
6. Rust 官方时间 POST `/passport/user_info/get_sec_ts/?aid=6383&is_from_ttaccountsdk=1` 一次：HTTP 200，107 ms，响应头 `bd-ticket-guard-ts` 存在，响应体 33 字节，没有服务端签发材料。
7. 新模块真实接受检查：同一路径再请求一次，将实际 HTTPS 响应送入 `TrustedTimeAnchor::from_response`，HTTP 200、约 111 ms，锚点接受；错误 UID／会话调用均被拒绝。随后同一 Rust 客户端 GET 账号信息，HTTP 200、success、UID 仍为 `99191692311`。这不是凭证续期后检。
8. 其他浏览器操作只检查配置／类型、官方函数源码、发送锁和不调用 send 的 XHR open/abort；发送页 `__sparkLock=true` 保留。读取性能记录不等于发起新请求，也不是 REA 被动捕获。

所有临时平台程序不跟随重定向、不用代理、不重试；风险停止标记在请求前检查。没有执行 `/passport/web/one_login/`、退出、重新登录、验证码、获取服务器证书 POST、身份令牌刷新、IM 请求或任何消息发送。真实操作没有同步至远端业务数据。

## 独立公钥签发与续期：前阶段阻碍及继续调查

当前页面 `securitySDK.secureProxy.config.web_protect` 实际包含四项配置：常规 Cookie 消费方、扩展消费方、header `onlyProviderPathList:["/passport/web/one_login/"]`，以及后追加的身份令牌消费方。后追加项确实把 `/passport/safe/get_identity_security_token/` 配置为 Cookie 消费端点，并禁止签名缓存；因此旧静态文件中“仅见排除上报列表”不能推导当前运行时无保护。

已见的明确 `web_protect` header 签发提供方属于 **登录流程**。非登录消费请求没有取得独立新公钥材料，时间同步也没有签发。契约明确禁止主动重新登录；不能调用 one_login、换用其他账号、导出旧浏览器私钥或新密钥配旧证书来完成该项。其他 `login` scene 的 web_record_status/set 不能替代 `web_protect`，更不能跨 scene／路径套用材料。

这不是证明平台所有版本不存在非登录登记或续期流程；是在当前资源、配置和授权范围内没有已核实可执行的另一签发链。因此不猜接口、不批量探测、不以本地 refresh 冒充续期，不启用生产自动签名。

## 准确 a_bogus：已突破的离线部分

资源：清单所列 `bdms_1.0.1.19_fix.js`，147530 字节，SHA-256 `a0e46f84476d63a1fa57bdcb47223e0e545c6ce0c3dacdd2818180dfa087909e`。完整原始字节未修改。准确入口不是 `frontierSign`：

```text
bdms.init({aid:6383,paths:[...],pageId:1})
  → 已替换的 XHR open/header 暂存
  → XHR send / fetch(string) 拦截
  → 签名输入包装（VM 程序 103）
  → 核心（VM 程序 150）
  → 追加 a_bogus
  → 保存的原始网络末端（研究工具在这里始终抛错）
```

- 字符串在压缩 VM 表中：原 JS 载荷字节 `[92106,130886)`，摘要 `d89629ffec92a2663683a1eecae23adf5156b3c17bf49a72267bf8b8b5581d8d`。Base64 解码后取 8 字节头，头后数据按官方 XOR 序列恢复，再 raw DEFLATE；解包 86939 字节，摘要 `35db5ad892b1ff278fc376a8778d90741d634ff56a7fedcdad91bef95ee31a2a`。字符串表 1001 项、程序 796 项，`a_bogus` 为字符串索引 220、解包字节 `[2440,2448)`。这些是数据偏移，不能当作 JS 字节偏移。
- 程序 150 实际显式输入为 `[1,0,8,query,字符串body或空字符串,navigator.userAgent,pageId,aid,"1.0.1.19-fix.01"]`；还有环境与内部状态，不是纯 query 哈希。
- XHR 输入使用 `URL.searchParams.toString()`；fetch(string) 使用 `URL.search.slice(1)`。因此 `%20/+` 的差异必须按入口处理，不能从最终 URL 删除签名后反推原始输入。
- 已有 `a_bogus`：本版 XHR 跳过生成，fetch(string) 追加第二个；本项目不以此支持签名复用。
- aid-only 初始化不够，必须有匹配 paths；路径排除有效。固定研究环境下改 query/body 改变签名，XHR `%20/+` 等价，fetch 不等价。GET/POST 方法和匹配范围内 pathname 单独变化可得到相同值，不声称协议绑定了未绑定的维度。
- Glue 将 `enablePathList` 转接为 BDMS `paths`；WebMSSDK 的 `frontierSign` 是 `X-Bogus`，runtime `webSignUrl` 为 `x-secsdk-web-signature`，三者不得互换。

正式工具 `tools/sdk_abogus_baseline.cjs` 执行完整已校验官方字节，固定 22 例公开合成输入；每例单独 VM、固定公开时间／随机种子、无真实 Cookie、无计时器执行、所有最终请求拒绝。基准 `src/douyin/sdk/abogus_baseline.json` 只存输入及结果摘要，不存账号签名。两次运行一致，22 例与独立调查原始官方执行结果逐项一致。

QuickJS 研究探针在 32 MiB／512 KiB／2 秒约束下可执行整个 BDMS 并产生 192 字符输出，但与同环境 Node 固定基准的摘要不一致。差异尚未解释前不具备引擎等价验收。合成环境本身也不是真实浏览器指纹；不允许伪造被平台接受的指纹结论。`fetch(Request)`、FormData、完整页面 SDK 叠加链未验收。

## 可信时间模块

`src/douyin/sdk_time.rs` 只解析调用方交入的同一受控 HTTPS 响应，不自行发送请求、不产生签名、不持有私钥、不改变业务白名单、未接入生产。它绑定 UID／会话，精确 POST URL，成功 HTTP，单一整数时间头，响应年龄不超过 2 秒；无可信材料时直接失败。锚点不序列化，使用单调时钟推进、一小时过期，拒绝本地时钟回拨或明显跳变，没有本地时间回退。调用方仍须保证来源是真实响应，不可把其公开构造函数当作外部输入认证器。

官方父文件 `90775.0c663da7.js` 中计算片段 `[169999,170115)`、年龄与过期片段 `[170532,171172)`，摘要由 `tools/sdk_time_baseline.cjs` 锁定。五个官方执行样例与 Rust 对照通过；Rust 的回拨／跳变和格式检查是额外 fail-closed 设计，不声称官方所有回退行为完全相同。

## 复跑范围

```bash
cargo test --lib
cargo check
cargo check --tests
node tools/sdk_official_baseline.cjs "$SDK_DIR/90775.0c663da7.js"
node tools/sdk_ecdsa_baseline.cjs "$SDK_DIR/90775.0c663da7.js" --check
node tools/sdk_time_baseline.cjs "$SDK_DIR/90775.0c663da7.js"
node tools/sdk_abogus_baseline.cjs "$SDK_DIR/bdms_1.0.1.19_fix.js" --check
```

Node 只用于离线研究，不进入 Docker；不运行全量测试或任何历史实发脚本。临时账号探针不作为可重跑维护入口交付，避免误重复平台操作。

## 契约状态

1. 动态签名：**未满足**。准确离线入口／输入关系已确认，但 Rust 引擎一致性、真实合法初始化与服务端新签名接受尚未通过。
2. 独立 Ticket Guard：**未满足**。新公钥候选请求返回正确 UID，但材料数 0，不能假定绑定成功；明确提供方涉及被禁止的重新登录流程。
3. 凭证续期：**未满足**。没有服务端新材料签发或刷新；可信时间成功不是续期。
4. 一次限定实发：**未满足，未执行**。签名初始化前置条件未通过，未进入今日发送历史检查或发送阶段；没有断言今天未发，也没有新消息 ID。新增一次实发额度未消费。
5. 安全回归：最终命令结果另附于本节末，不以此前运行代替本轮检查。
6. 可维护与如实交付：保持禁用、证据分层、固定官方基准及更新完整性门禁；生产不引入 Node/浏览器/外部签名服务。
7. 条件部署：**未部署**。没有通过完整服务端验收的业务能力；可信时间局部模块不单独触发生产部署。没有远端写入／重启，不声称做过部署备份或前后数据比对；既有后台业务未被本轮关闭，其活动不能算本轮主动测试。

## 压缩上下文后的 Ticket Guard 专项核对

本轮用户收窄范围为新公钥签发匹配及自动续期，明确禁止消息发送和部署；旧条件授权不在本轮使用，生产签名门禁不变。

- 本轮仅检查现有独立 Chrome DevTools 的 SDK 函数源码、公开路径配置与既有 performance 记录，未主动发起平台 HTTP 请求、调用 refresh/start 或读写账号密钥。初步检测到 captcha 命名节点后，按布局及计算样式复核，可见节点数 0；没有据隐藏节点宣称出现验证码。
- `secureProxy.config` 仍只有 `web_protect`，四项配置中的明确 header 提供方仍为 `/passport/web/one_login/`；身份令牌路径是 Cookie 消费方且禁签名缓存，不能从配置推导它会签发新公钥材料。
- 核对锁定父文件 `eL` 字节 `[45540,45678)`（SHA-256 `983e22be5b607f3d21df1e293b3df72e104b8b36d9f955a75f3c63c14c70f39d`）及 `eq` `[46016,46222)`（`a646c2068fb8c05e1e7346b8b6012ae29d41cc14cf4e472ce90fe4fed76b50d0`）：官方将公钥原始点编码为 Base64，`pub.` 材料与该编码匹配。之前隔离候选使用相同的未压缩 P-256 点编码；没有证据将材料数 0 解释为已知编码错误，也未据此重试。
- `_processServerCookie` 实际会检查服务端 `client_cert` 与本地密钥，不匹配时清理／重建本地状态；处理器返回成功或账号 GET 业务成功均不等于服务端接受新密钥。
- `refresh` 实际清除 crypt/sign/store 本地状态，再执行 `start`；`start` 初始化密钥、Cookie 与存储检查。未见该链主动执行账号凭证续期请求；不能将本地重建视为新材料签发或会话延寿。
- 已下载八个 client-entry 与 runtime 的有界检索表明：`/passport/token/beat/web` 在已见配置中是消费方；`/passport/user/web_record_status/set/` 的提供方配置属于 `login` scene，不可替代 `web_protect`。当前页面没有保留这几条路径的 performance 记录；此缺失不证明平台不存在其他流程。

**该阶段验收未通过，研究继续**：此前未取得新材料，不能执行匹配材料后的 Rust 只读接受与真实刷新后检；材料有效期也不能推测。只见登录 provider 不能证明消费响应不会非登录更新材料，下文记录后续官方调用链与 TokenBeat 实测，纠正以该列表作为停止依据的判断。可信时间局部验收保留；消息发送、部署和生产门禁变更继续禁止。

源码大窗口保存在会话 scratch 的 `ticket-guard-*-source*`、`ticket-guard-key-match.txt` 与 `ticket-guard-nonlogin-paths.json`，只包含公开官方字节。浏览器工具拒绝将结果保存到 scratch 后，改用有界摘要，没有改写为项目临时文件。

### 专项最终检查与清理

- `cargo test --lib`：**67 通过，0 失败**；`cargo check`、`cargo check --tests` 通过。未运行全量测试或任何实发集成测试。
- 官方输入构造、ECDSA 双向验签、可信时间及 22 例 BDMS 四组离线基准通过；相关 Node 语法检查与 Rust 格式检查通过。既有 a_bogus 环境检测差异不因离线基准通过而算作生产接受。
- `sdk_audit check` 对四个锁定原资源通过；`activate` 非零退出，保留 no approved known pin／missing adapter 门禁；篡改父资源的 ECDSA 基准非零退出。`cargo tree -e normal` 无 p256。
- 详细日志写入会话 scratch 的 `ticket-guard-final-checks/`，只返回摘要。已删除 `sdk-isolated/cookie.json` 与 `registration-response-headers.json`；`isolated-binding.json` 未生成，以上三个敏感路径已确认不存在。保留非敏感一次尝试标记，防止误重跑。
- 本轮没有新的登记／刷新网络尝试，无新材料、无刷新后接受记录；**新公钥签发匹配及自动续期仍未验收**。没有发送、部署或放宽生产能力门禁。

## Cookie 自动续期优先核对：非登录 TokenBeat 已发现并复现

**结论：官方有活动驱动的非登录保活，Rust 已取得业务接受；登录 Cookie 实际续期仍未证明。Ticket Guard 更新与登录 Cookie 续期不是可以互换的验收项。研究继续，不将仅见登录 provider 作为停止理由。**

### 官方资源与实际执行

- Chrome DevTools 读取当前限定账号页面已缓存的 Webpack 工厂，捕获公开模块到 scratch，未导出私钥。`PassportBrowserClient` 经源码核对属于监控客户端，不是会话刷新客户端，已纠正该入口误判。
- 发现模块 `195587.initTokenBeat`。原始资源 `https://lf-douyin-pc-web.douyinstatic.com/obj/douyin-pc-web/ies/douyin_web/async/20165.09aff41b.js`，3328 字节，SHA-256 `e06751bdd7fe30fd2e6657b2e7170da87857e1293bcf83ed8dc02a4564db5173`。请求为带凭据 GET `/passport/token/beat/web/`，aid 6383，scene 为 boot／polling／active；业务版本 2.4.9，Passport SDK 3.4.9，Web 设备参数和官方请求插件。
- 默认 600000 ms 活动轮询。无活动则停止，活动后恢复；401 停止并通知掉线。代码没有 Cookie 到期判断，不直接写 sessionid。整份原始资源离线执行四例通过：启动／停止／恢复、活动轮询、401 停止、普通失败无立即重试。计时器／请求使用公开离线替身，不宣称完整 SDK／平台执行。
- 用官方参数插件及真实浏览器信息构造不交付草稿，输出参数名／类型。实测 CAPTCHA 参数为 4.0.26，不能按页面脚本版本手填。官方排序函数和 SHA-256 的公开固定输入与 Rust 对照通过。不是 a_bogus 或 Ticket Guard 签名接受。
- 浏览器一次身份预检 HTTP 200／UID 99191692311，随后一次 TokenBeat HTTP 200、message success、data.error_code 0，148 字符；没有验证／重试／登录。该次使用官方构造的参数草稿再通过页面 XHR 交付，不声称调用了未改写的完整 initTokenBeat。
- 浏览器 8 个 HttpOnly 会话 Cookie（sessionid、sessionid_ss、sid_tt、sid_guard、sid_ucp_v1、ssid_ucp_v1、uid_tt、uid_tt_ss）只存摘要／长度／到期元数据。前后值摘要、创建时间和到期时间均未变；到期时间变化 0。sessionid 客户端剩余约 59.5 天不是服务端 TTL 证明。
- 隔离 Rust 新增 `sdk-isolated/src/bin/cookie_beat_probe.rs`，限定两个端点、无代理／重定向／重试，网络前独占锁住尝试。读取限定 MCP 会话、剔除旧 Guard 材料，独立随机 P-256 公钥，真实环境输入，Rust 重新生成 p_ts／p_no，不借用浏览器签名、私钥或旧证书。一次同客户端身份预检 → TokenBeat → 身份后检均 HTTP 200，前后 UID 正确、保活错误码 0。
- Rust 保活响应 **Set-Cookie 0、服务端匹配材料 0**；无新绑定文件。bd-ticket-guard-result／TEE 为 1103，static sign／ts 为 1102，key-sign-result 2、sec-result 1101。这些值不具备充分的独立签名接受语义，业务成功不算新公钥绑定。浏览器 Cookie 再快照仍未变化。

### Ticket Guard 与 Cookie 续期分离

- `secureProxy.getTimeProvider()` 当前为 success／trusted，锚点 fresh、signable；这是正确的观察入口，不把误查不存在的顶层 trustedTimeService 解释成时间失效。
- TokenBeat 被实际 hooks 判定为 `web_protect` Cookie consumer，needProxy true，provider 空，needUpdateTs false；updateData／login／trusted time enabled 为 true。
- 原始 hooks 片段父资源仍为 90775 锁定版本，字节 `[192429,203021)`，SHA-256 `342476d535883617dc7b57054f965b2c2b4175e7464a8cae01fc0525a94c6a76`。两组公开替身对照通过：无 ticket 时只携带公钥，不调用签名；消费响应若有 server-data，会解析／诊断／确认存储，但 header `setSignValueAsync` 还依赖 provider scene。Cookie server-data 另由 `_processServerCookie` 解码、匹配本地公钥并入库。不得据 provider 列表断言消费响应不能签发。
- `bd_ticket_guard_regenerate_keys_time` 在本地生成密钥时写入；generate_ticket_time 用于新材料诊断。它们不是 sessionid 到期续期计时器。`refresh`、时间同步、匹配旧材料存储都不是登录 Cookie 延寿。
- 追加公开资源及页面已加载模块的有界检索尚未找到独立 session/refresh 或 token/renew、临近到期刷新条件。expires_in 命中为 OAuth，max-age 为通用 Cookie 工具／验证码探测，sessionId 为监控或播放器会话。该有界负结果不能排除服务端在特定条件下刷新，也不能证明后台 TTL 不变。

### REA 与验证范围

REA 父证据 `ev_4d9ac133c91831e271fd79bc97e4193e9bd223c247f9578f68bb00f5610f13b3`：7 个公开捕获模块的分析副本，解析 5712 AST 节点，无解析失败；语义仍有 1035 个 unknown，不声称完整动态解析。工厂捕获文本不是原始 bundle 字节切片。完整证据导出 scratch `cookie-renewal/rea-evidence.json`；仅静态分析，不称 REA 被动运行捕获。

新增 Rust scratch 测试 3 通过：公开 p_no 对照、风险响应停止、公钥格式／错误密钥拒绝。官方原始 TokenBeat 基准 4 例、原始 hooks 2 例重复检查通过。只执行指定 scratch bin 测试，未执行消息或全量集成测试。生产代码及签名门禁没有启用或改写。

**当前继续项**：补齐完整动态签名调用栈与真实浏览器环境、匹配新公钥的非登录服务端材料；寻找并观测真正的新 Cookie／材料签发或有效期延长，才可宣称自动续期。保活业务接受这一局部结果已落地，但不因此启用生产自动续期。

## 压缩后续查：公开密码学对齐与续期边界

本阶段不重新扫描历史、不调用登录／退出／refresh／start，不发消息、不部署、不改生产路径。没有新增主动平台 HTTP；浏览器仅执行配置查询、宿主探针和 localhost 公开测试。下列日志与向量存放在会话 scratch 的 `cookie-renewal/`。

### ECDH／HKDF／HMAC 独立验证

- 官方原始证书解析／P-256 ECDH 片段和捕获的 HKDF／HMAC 公开模块，与 Node 标准库的 2 个公开用例重新比对通过。母资源 SHA-256 固定，片段范围与摘要写入 `ecdh-hmac-baseline.json`；DER 长度整数桥接、模块捕获来源和完整 SDK 范围限制保留。
- 隔离 Rust `ecdh_hmac_offline` 离线测试 **3 通过、0 失败**：ECDH 共享秘密、空 salt／info 的 HKDF-SHA256 32 字节输出、HMAC-SHA256 及反向协商一致；错公钥／坏 SPKI／修改路径、ticket、时间及 KDF context 的负例通过。
- 独立浏览器 localhost 安全上下文的原生 WebCrypto **2 用例通过**，共享秘密／HKDF／HMAC 与 Rust、Node、官方片段一致；反向协商、错公钥及坏 SPKI 检查通过。只使用公开标量 1／2 的测试密钥，结果为 `browser-ecdh-hmac-result.json`。初始 about:blank 缺安全上下文，尚未执行密码学运算即失败；改用 localhost 后通过。
- 这些只验收公开离线互操作，不验收平台证书信任、客户端绑定、真实账号签名或服务器接受。

### Cookie 会话、Guard 材料与可信时间不是同一更新入口

- 实际配置再次确认：TokenBeat、accountinfo 为 `web_protect`／Cookie consumer，needProxy／needSetCache 为 true、provider 为空；可信时间接口 needProxy 为 false。配置查询没有执行请求处理器或主动时间同步。
- 完整锁定原始 `_processServerCookie` 方法的 **4 个公开合成用例通过**：无 Cookie、匹配公钥标记、不匹配标记、畸形材料。匹配／存储／监控依赖使用明确替代宿主，不能当作密码学证书校验或实际签发。
- 不匹配材料仍可能被记录，同时进入不匹配处理；因此“材料曾存入”不等于“新密钥绑定成功”。该方法仅处理 Guard Cookie，没有续写 sessionid／sessionid_ss／sid_tt／sid_guard。Cookie 材料处理在读取 Guard 密钥／ticket／证书／签名时调用，不能等同于 sessionid 到期刷新。
- 原始可信时间失败处理器 **5 个用例通过**：启用可信时间且结果为 1105（含字符串形式）时强制 ensureFresh；1103／1102 或禁用时不触发。该动作是可信时间恢复，不是 Cookie 续期或 Guard 续签。对应 `time-failure-baseline.json`。
- 原始 TokenBeat **4 用例**、响应 hooks **2 用例**重跑通过。消费方可能接收非登录新材料的可能性保留；现有成功 TokenBeat 无材料不能证明所有触发条件下都不会签发。后端会话有效期是否延长仍未知。

### 标准宿主已局部修正，完整动态签名仍未对齐

- 只修改 scratch 的 `sdk-isolated/src/bin/quickjs_probe.rs` 和编码桥接：修复 URL host／端口、空参数、重复参数 set／delete、查询串同步、畸形 URL 拒绝，以及 Base64 错误处理、空白／无 padding／尾位处理和 UTF-8 孤立代理项。原生浏览器公开 URL 基准与 **14 个编码用例通过**。
- 修正后完整原始 BDMS 仍输出 192 字符，SHA-256 `1d1f76857c2dce8acfea7b1b6a84b0496acfa3da6e635dd5c11f4dee1c14f748`；先前非等价 synthetic iframe 为 `7b34173a9d7df2ef97b61528841b885adce438a8531f2afe26edd48a74f3fce7`。标准语义修正未消除差异，不得宣称真实环境对齐。
- 未改写 Error.stack、stackTraceLimit、引擎身份或反自动化分支。账号页脱敏探针的原生栈为 3 行、stackTraceLimit 10，无 Node Module／loopback 模式；这是探针栈，**不是签名器内部调用栈**。完整 Request／Headers／DOM／location 桥接和实际内部栈仍缺验证。
- 当前浏览器 Guard 参考使用 ECDH／HMAC、可信时间 t_trust=1；旧参考签名仅在浏览器内观察形状，未导出私钥或重放。sid_guard 结构元数据声明 60 天，不代表 TokenBeat 已延长该期限。

### 证据与门禁

复用 REA parent `ev_4d9ac133c91831e271fd79bc97e4193e9bd223c247f9578f68bb00f5610f13b3` 的摘要成功；7 个公开分析副本、5712 AST 节点、0 解析失败，仍有 1035 项语义未知。主动浏览器探针不是 REA 被动运行时证据。

本阶段只执行指定 scratch bin 测试／运行和公开 Node 基准，没有重跑项目全量／在线测试；此前 67 项库测试与两项编译检查的结果不冒充本阶段新执行。生产批准列表仍为空，发送锁 `__sparkLock` 与 `__cookieResearchSendGuard` 已检查有效。续期研究仍未完成：缺少真实会话延寿、新密钥匹配签发与真实环境签名接受，不因登录 provider 列表而终止调查。

清理核实：已删除本阶段重新创建的 `sdk-isolated/cookie.json` 和 `cookie-renewal/browser-environment.json`，删除账号页 `__cookieRenewResearch`，恢复独立研究页为 about:blank；四个本地服务 18767／18768／18769／18770 通过 PID 命令身份核对后停止。未清除真实浏览器 Cookie／SDK 状态／发送锁。两项 scratch bin 的 `cargo check --offline` 与新增 JavaScript 语法检查通过。公开向量、日志和已消费尝试标记继续保留。
