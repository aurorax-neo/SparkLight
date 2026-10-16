# 官方 Web SDK：执行证据、更新流程与当前阻碍

## 结论与交付范围

2026-10-15 最终工程收口：当前证据不足以可靠交付自动会话续期／纯 Rust 无人值守签名，停止该未验证路线，获批 SDK 集合仍为空。108 已部署的仅为执行诊断与今日状态修复，不是 SDK 激活或自动发送恢复；详见 [最终结论与部署验收](renewal-closeout-and-deployment-20261015.md)。以下研究记录保留其原阶段范围。

本轮未取得可启用的完整生产签名适配器，**SDK 研究没有部署，没有完全对齐或线上新签名验收通过的结论**。三类能力当前均不允许生产自动生成。已完成纯 Rust 资源校验／候选门禁、受限 QuickJS 执行层、官方签名输入片段一致性、公开测试密钥下 ECDSA 双向验签、ECDH／HKDF／HMAC 官方片段—Node—Rust—浏览器公开向量对照、22 例完整 BDMS 离线基准及真实 Rust 可信时间局部验收。非登录 TokenBeat 保活已局部验收，但会话延寿、独立新公钥匹配签发和自动续期未验收。最新实际操作与边界见 `docs/sdk-acceptance-20261014.md`；既有人工同步流程不变。

2026-10-15 离线续接见 [内部栈与消费方更新证据](sdk-offline-continuation-20261015.md)：新增签名器 VM704/705 实际栈读取与调用入口差异对照、33 例材料覆盖/错配清理/存储确认用例；主执行者独立重跑通过。70 库测试与两项 check 通过，生产激活仍拒绝。仅离线研究完成，不代表真实会话延寿、匹配新密钥签发或服务端接受。

| 能力 | 实际证据 | 状态与缺失条件 |
| --- | --- | --- |
| 动态请求签名 | 已定位完整原始 BDMS 的 `init({aid,paths,pageId}) → XHR.send / fetch(string)` 拦截入口，22 例公开离线基准通过；明确区分 `a_bogus`、`X-Bogus`、`x-secsdk-web-signature`，XHR 与 fetch 的 query 处理不同。 | **未启用**。QuickJS 与 Node 输出存在环境检测差异，不伪造引擎等价或真实指纹；合法初始化及 Rust 生成请求的服务端接受未验收。 |
| 按路径 Ticket Guard | 官方输入构造、ECDSA 离线互操作通过；当前浏览器参考分支为 ECDH／HKDF／HMAC，公开向量由官方片段、Node、Rust 和浏览器 WebCrypto 一致验证。Rust 可信时间取得真实官方响应，同客户端身份后检通过。隔离新公钥候选请求返回正确 UID，但服务端材料数 0。 | **完整签名未启用**。公开离线密码学一致不代表平台签发或证书信任；缺少与新公钥匹配的服务端 `ticket/ts_sign/client_cert` 和有效期证据；不得导出浏览器私钥或新密钥配旧证书。 |
| 凭证续期 | 官方活动驱动非登录 TokenBeat 已在浏览器与隔离 Rust 返回 HTTP 200、业务成功、身份正确。浏览器会话 Cookie 元数据未变化；Rust 无 Set-Cookie、无新 Guard 材料。Cookie 会话、Guard Cookie／响应头材料、可信时间和服务器证书各有不同更新入口。 | **保活局部通过；自动续期未验收、禁用**。Cookie 或后端会话延寿未证明；消费方也可能收到新材料，不能因 header provider 涉及登录而排除非登录续签。`refresh/start`、服务器证书获取和成功巡检均不能代替合法签发或会话延寿证据。 |

这些是当前已搜索资源和执行路径内的结论，不是“所有官方版本均不可运行”或“必须依赖浏览器”的证明。

## 官方资源身份

来源均从获授权账号 `12345678` 的官方页面 script/resource 列表观察，2026-10-14 通过公开 HTTPS 下载，并通过独立 Rust `fetch` 命令重新获取、比对一致。完整 URL、文件大小、入口、版本与 SHA-256 在 `src/douyin/sdk/manifest.json`，不含账号材料。

| 文件 | 版本 | SHA-256 |
| --- | --- | --- |
| `90775.0c663da7.js` | chunk 90775.0c663da7；内含 SDK 容器版本 3.3.20 | `ef38b30991af9aab6f2ff9a849991c38799a9cc5fcedd3ede006a8eeba90995d` |
| `webmssdk.es5.js` | 1.0.0.20 | `3c138a74319cf36dd5a63920ecd4624875593c306f2ac68f157a68c465381075` |
| `bdms_1.0.1.19_fix.js` | 1.0.1.19-fix.01 | `a0e46f84476d63a1fa57bdcb47223e0e545c6ce0c3dacdd2818180dfa087909e` |
| `sdk-glue.js` | 1.0.0.64-fix.01 | `0ccf4a589b80bdda1a46efddf84a31ba9ca4826f4ac8a46661c35471d30d16c8` |

### 静态证据（不等于运行）

对 `90775.0c663da7.js`：
- `getBdTicketGuardHeader` → `secureProxy.getBdTicketGuardHeader` → `n4` → `getKeysInfoWithOrigin`／`signWithKeysInfo`。`n4` 检查 ticket、公钥、path，并获取可信时间或本地时间。
- 输入构造 `n6` 的 **UTF-8 字节范围 `[191914,192384)`**，加 `;\n` 后片段 SHA-256 为 `cf3a88ad944446482a0908cf5d9951eb55ec23652fa4a9d9895e89f4619fd9c5`；以原文保存于 `src/douyin/sdk/ticket_input.js`。原始源码字符偏移与字节偏移不同，以字节范围为准。
- `generateCertHeader` 的 `n_` 分支需要 `ecPrivateKey/ecPublicKey/tsSign/ticket/path`；内部返回 privateKey 的结构不能被直接当作可公开日志或 API 返回值。本项目未调用此真实浏览器接口、未导出其密钥。
- `refresh` 只是本地状态重建；`get_client_cert` 为带凭证 POST。来源只用于判断依赖，本轮没有新增业务端点白名单，也没有请求该 POST。
- IndexedDB／跨存储 iframe、WebCrypto、服务端证书、可信时间是已见依赖；“均必须在浏览器运行”没有证据，不作此断言。
- 对上述四个原始文件作字面搜索未发现 `WebAssembly` 字符串；这不排除动态加载，未凭空新增 Wasm 引擎。

REA 静态分析父证据：`ev_d43c68683e47b1f6d63154fe351fb1ddc4acf41ebfedb99faf768c834ca3e56d`。解析一个 243451 字节资源、72040 AST 节点；混淆语义阶段耗尽约 1 GiB worker 堆，覆盖 **partial**。未重复运行扩大分析，也未将未发现当作不存在。上述关键判断另以原始源码和实际执行复核。

### 实际执行与局限

- **官方页面入口**：`byted_acrawler.frontierSign({})`，临时阻止 fetch/XHR，返回 `X-Bogus:string`，阻止网络调用数 0。值未输出；此探针不证明输入绑定或 HTTP 动态签名。
- **Node.js 研究探针**：早期原始 BDMS 因宿主接口不完整停止；后续已允许 XHR open/header 暂存并只阻断最终网络末端，完整官方字节生成 `a_bogus`，22 例公开离线基准通过。研究替身、固定时间与随机种子不代表真实浏览器环境，不证明服务端接受。
- **Rust QuickJS**：生产依赖探针仍为严格拒绝宿主接口模式，不能从加载结论推断完整入口可用。隔离研究探针已能执行完整 BDMS，但环境检测差异未作为生产等价解决；不伪造检测结果、不启用生产动态签名。32 MiB 内存、512 KiB 栈、2 秒中断限制保留。
- **官方输入片段一致性**：父文件摘要→字节范围→片段摘要→官方原文 Node.js vm 执行→两例固定输出→QuickJS 对照，全部通过。输入仅含 `offline-ticket`、固定时间和路径，不含真实材料。此项只覆盖输入构造；新增 ECDSA 离线互操作另见下节，仍不覆盖 HMAC、可信时间、完整 SDK 或服务端接受。
- **获授权只读验证**：仅账号 12345678，`GET /passport/account/info/v2/?aid=6383`，HTTP 200、JSON、UID 匹配 `99191692311`、未跳转，未检测到 401/403/429、验证头或对应风险码；未记录 Cookie、响应中的 session_key 等值。页面 SDK 配置确认 Passport 与发送路径均可能需要 Ticket Guard。这是官方浏览器路径的可用证据，不是 Rust 新签名的证据。
- 没有发送消息、调用手动续火花／批量执行／账号发送任务；没有重跑历史实发脚本；没有读取日常 Brave／其他账号 Cookie。

## 可重跑维护与候选验证

下列命令从项目根目录执行。`SDK_DIR` 必须是维护者选择的全新 scratch 目录，不是账号数据目录。生产 Docker 仍只构建 `--bin sparklight`，不加入 Node.js／浏览器／外部签名服务。

```bash
export SDK_DIR="$PI_SCRATCH_DIR/sdk-candidate-$(date +%Y%m%d-%H%M%S)"
cargo run --bin sdk_audit -- fetch src/douyin/sdk/manifest.json "$SDK_DIR"
cargo run --bin sdk_audit -- check src/douyin/sdk/manifest.json "$SDK_DIR"
cargo run --bin sdk_audit -- probe src/douyin/sdk/manifest.json "$SDK_DIR"
node tools/sdk_official_baseline.cjs "$SDK_DIR/90775.0c663da7.js"
node tools/sdk_dependency_probe.cjs "$SDK_DIR/webmssdk.es5.js" "$SDK_DIR/bdms_1.0.1.19_fix.js" "$SDK_DIR/sdk-glue.js"
cargo test --lib douyin::sdk_registry::tests
cargo test --lib douyin::sdk_runtime::tests
cargo test --lib
cargo check
cargo check --tests
```

`node` 两条只用于研究验证，不是生产启动或编译要求；不允许执行全量 `cargo test` 或实发集成测试。Node.js vm 是可信官方研究资源的依赖探针，不是通用不可信代码的系统安全沙箱。

### 跟进官方更新

1. 仅在授权官方页面检查 script/resource 的 URL／版本，不采集账号值。现有版本检查是显式维护操作，**不是自动发现最新版本服务**。
2. 对同 URL 的内容变化，锁定 `fetch/check` 会拒绝摘要或大小差异；保留旧目录和旧清单。新 URL／版本先建立独立候选清单，不能改写生产批准 pin。
3. 候选清单受 schema/ABI、精确静态来源、大小／摘要、能力声明限制。`check` 只证明字节一致，绝不表示发布者认证、运行兼容或生产签名可用。
4. 显式 `probe` 在隔离引擎执行同一字节快照；适配器升级只改资源／适配模块和测试，不散改账号／调度器。新版本必须建立其自己的官方执行基准，不能把旧字节偏移硬套到新 SDK。
5. 对照官方执行与必要的授权只读接受证据，确认输入绑定、时间／有效期、错误停止和合法初始化条件。未通过时保持 disabled，不能以清单自报 `supported` 启用。
6. 当前 `activate` 按预期报 `no approved known pin; missing adapter`；固定批准 pin 集合为空。候选失败保持已有 pin，单元测试以合成资源证明旧 pin 与回退选择；实际生产回退是现有人工同步流程。**没有虚构已验证可签名旧版本。**
7. 只有全部生产依赖和验证条件满足后才考虑部署；备份数据库、镜像及配置，部署后核对数据和健康。当前条件不满足，故本轮没有远端变更、重启或部署诱发任务。

## 验证记录

- `cargo test --lib`：本次跟进 **62 通过，0 失败**（此前 59 项，加 3 项离线 ECDSA 测试）；包括 13 项资源管理、6 项运行适配、发送路径一次消费及既有账号隔离／风险停止／未知发送不重试回归。
- `cargo check`、`cargo check --tests`：通过。未执行任何实发集成测试。
- `sdk_audit fetch/check/probe`：已实际运行；4 个资源两次公开获取摘要一致。`activate` 已实际验证非零退出，未启用。
- `sdk_official_baseline.cjs`：父资源、字节范围、片段、两例官方执行全部匹配；QuickJS 结果与该基准匹配。
- 中途曾发现未声明片段变量及字符／字节偏移错误，均已修复并重跑。资源限制插入宏内部导致的编译错误亦已修复；以上仅记录最终通过结果，不将失败轮次算作成功。
- 命令级负向验证：公开资源副本同长度单字节篡改后，`sdk_audit check` 以 SHA-256 mismatch 非零退出；完整原始候选 `activate` 仍因 no approved known pin／missing adapter 非零退出。
- 现有生产服务健康端点返回 `{"name":"SparkLight","status":"ok","version":"0.1.0"}`；这是现有版本健康检查，不是本轮部署后验收。

## 验收对应与未完成项

1. **可追溯结论：满足交付条件**。来源、摘要、入口、依赖、静态／执行／未知分列；没有将未证实能力标为可用。
2. **更新闭环：满足当前安全禁用范围**。有检查、完整性校验、候选验证、禁用回退及内容变更／不兼容门禁测试；不存在可签名生产旧版可供回退。
3. **纯 Rust 与安全边界：满足已完成范围**。内嵌引擎，无生产 Node/浏览器依赖；新完整签名未接入。既有凭证额外绑定固定发送 URL，不可跨路径／追加 query；账号、会话、过期、一次消费仍受原有验证。
4. **回归：满足**。上述安全命令与官方片段基准通过，但不包含完整 SDK 签名一致性或服务端接受验收。
5. **授权与部署：阻碍分支已执行；线上新能力验收未满足**。一次必要只读验证未越界；合法新密钥登记和续期链尚未验证，因此不部署、不启用、不宣称完成线上验收。远端原有后台巡检未由本轮关闭或核查，不能声称其完全没有活动。

既有代码包含需显式调用的本地 macOS「打开 Brave」管理辅助功能，本轮未调用、未改动；生产 Docker 不具备该路径。新增签名／维护代码不启动浏览器或外部进程。原有两个账号／九个目标／设置／加密密钥／前端及 Compose 本轮没有远端写入，未执行部署前后数据一致性比对，不能将仅健康检查当作该项验收证据。

## 本次跟进：独立初始化链与离线 ECDSA

### 已执行的离线对照

新增 `tools/sdk_ecdsa_baseline.cjs`、`src/douyin/sdk/ecdsa_offline_baseline.json` 和仅 `cfg(test)` 编译的 `sdk_ecdsa_tests.rs`。`p256 = 0.13.2` 只作为开发测试依赖，主服务无新增签名入口。

- 官方父文件仍为上述 `90775.0c663da7.js`。工具先核对完整 SHA-256，再核对三段 UTF-8 字节范围和各自摘要：PEM 解析 `[35909,36314)`、异步辅助 `[36984,37526)`、ECDSA 实现 `[41200,41991)`；摘要保存在公开基准中。
- 原始 `ey` 函数实际执行 WebCrypto ECDSA P-256/SHA-256，将 64 字节 `r || s` 转成 ASN.1 DER。宿主仅提供标准 WebCrypto、TextEncoder、atob 及等价的字节转十六进制桥接；没有浏览器指纹替身、网络、账号存储或真实私钥。
- 测试密钥是明确公开的标量 **1**；票据为 `offline-ticket`，时间为固定历史值。公开基准不是账号凭证，绝不能用于实际会话或配平台证书。
- 两例官方签名由 Rust 与 Node 验证；两例 Rust 确定性签名由 Node 反向验证。ECDSA 随机性意味着不比较两种实现的签名字节；固定 Rust 向量只用于回归。
- 负向测试覆盖路径／票据／时间修改、错误密钥、签名修改、原始格式误作 DER、截断、尾随字节和非法 Base64。生产能力仍为 disabled。

复跑命令：

```bash
node tools/sdk_ecdsa_baseline.cjs "$SDK_DIR/90775.0c663da7.js" --check
cargo test --lib douyin::sdk_ecdsa_tests
```

`--generate-public-fixture` 仅供首次建立全新公开研究基准，使用独占创建，不覆盖已有文件；正常回归只运行 `--check`，不会改写基准。工具只执行已核验的官方片段，不代表执行完整 SDK。

### 客户端绑定与服务器证书必须区分

以下为锁定父文件的静态调用证据，尚非独立会话的服务端验收：

1. `_getCertificatePem` / `_initCert` 在本地生成或恢复 P-256 密钥；`initPubKey` 输出公钥，名称不代表已向平台登记。
2. `_processCookie` 将公钥及版本信息编码进 `bd_ticket_guard_client_data`；header 分支携带 `bd-ticket-guard-ree-public-key`。
3. `_processServerCookie` 处理 `bd_ticket_guard_server_data`；响应分支读取 `bd-ticket-guard-server-data` 并调用 `setSignValueAsync`。存在 `client_cert` 与本地公钥匹配检查，包括 `pub.<base64公钥>` 格式。
4. `getServerCert → ta → ts` 的 `get_client_cert` POST 读取 **服务器** `server_cert/server_sn`，供 ECDH 分支使用，不能当作上述客户端绑定已完成的证据。
5. 当前已做一次限定账号的隔离新公钥候选请求，正确身份响应但无匹配服务端材料；这不算登记成功。公钥原始点 Base64 与官方编码一致，未发现足以纠正后重试的已知格式错误。未替换浏览器存储或密钥。

公开配置资源 `client-entry~e6d6c854.ab65ee19.js`（SHA-256 `39d98257080e99aeadecf459796bb7f00cb8a26644044a521387f81205fbd929`）列出 Passport 与 IM 消费路径、header provider `/passport/web/one_login/`。身份令牌接口虽在该静态排除上报列表出现，当前运行时后追加配置将其列为 Cookie 消费方并禁缓存；静态邻接不能替代运行时结论。`web_record_status/set` 的提供方属于另一 `login` scene，不可混用。

### 浏览器观察与三类签名协议

- 复用账号 12345678 的既有官方页面，仅检查名称／类型／状态。页面 SDK 可用，可信时间状态 success、来源 trusted；未读取或导出私钥。本次继续操作没有发送业务请求；此前跟进已调用官方时间同步一次。
- 官方时间函数实际采用带凭据的 **POST XHR** `/passport/user_info/get_sec_ts/`，从响应头 `bd-ticket-guard-ts` 更新服务器时间，不是 GET JSON。此前错误探针因非 JSON 停止，不将其当作 Cookie 过期证据。
- 此前跟进在临时阻止网络时用浏览器既有密钥签两个路径，输出类型／长度及 `t_trust=1`，签名随路径变化；未把值写入项目。它不证明 Rust 独立密钥可用。
- `frontierSign({})` 返回的是 `X-Bogus`；另一份官方资源 `runtime_bundler_34.js`（197074 字节，SHA-256 `d54bb80b5d09d9d2b389996d5ef992b5ed5df79a429a1912f4a0f8559b886949`）的 `webSignUrl` 探针添加 `uifid/timestamp/x-secsdk-web-signature`，没有生成 `a_bogus`。这些公开跟进资源未加入生产批准清单。
- 早期有界字面搜索未定位入口；后续已解析 BDMS 压缩 VM 表并确认完整官方拦截链。最新入口、输入语义、22 例基准与覆盖限制见专项验收记录；不再将旧搜索未发现描述为当前事实。

### 当前交付边界

离线入口／密码学对照与可信时间局部能力已落实，独立新公钥匹配签发和自动续期仍未验收。当前用户明确禁止发送和部署；没有新增生产端点、批准 pin、自动签名或自动续期。最新专项核对未主动发起平台请求、调用浏览器 refresh/start、导出私钥或改写远端业务。

### 本次最终检查

- `cargo test --lib`：62 通过，0 失败。
- `cargo check`、`cargo check --tests`：均通过；未执行全量或实发集成测试。
- 官方输入构造基准：2 例通过；ECDSA 官方片段→Rust 验签／Rust→Node 验签：各 2 例通过。
- `rustfmt --check`（新增测试文件）、`node --check`（新增工具）：通过。
- `cargo tree -e normal`：不存在 `p256`，密码学互操作依赖只参与测试。
- 官方父资源单字节篡改：工具非零退出；对已有公开基准再次执行生成：拒绝覆盖；两次检查后基准 SHA-256 不变。
- 基准固化中曾误插入编辑操作头，已修正并重新完成 JSON 解析、双向验签和全部上述回归；没有将错误中间状态算作通过。

### 最新专项回归

`cargo test --lib`：67 通过，0 失败；`cargo check` 与 `cargo check --tests` 通过。四组官方离线基准（输入、ECDSA、可信时间、22 例 BDMS）和相关 Node 语法／Rust 格式检查通过。旧 62 项记录为历史检查，不替代本次结果。日志位于会话 scratch 的 `ticket-guard-final-checks/`，未运行全量测试或实发集成测试。
