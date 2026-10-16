# 2026-10-15：离线续期链与签名器内部栈证据

本阶段只执行固定公开资源、公开合成输入及独立 localhost 浏览器对照。禁止重新登录、发送、部署、平台材料签发或新平台业务请求。旧账号页面未参与本阶段主动测试；不对其后台活动作零请求承诺。

## 签名器内部栈：新增观测

原始 BDMS `bdms_1.0.1.19_fix.js`，147530 字节，SHA-256 `a0e46f84476d63a1fa57bdcb47223e0e545c6ce0c3dacdd2818180dfa087909e`。

`build_stack_probe.cjs` 对四处唯一锚点插入只读记录：暴露程序表、记录真实 `.stack` 读取、记录 VM705 原始 host 调用后的参数与结果、记录 VM704 原始返回。每处原始字节范围、片段、摘要、替换文本保存在 `stack-provenance.json`。观测版本 SHA-256 `f17948dc467a9f732a84438be42a7dc6c975a9b934c17e30735354858cfeefa3`。没有改写 Error、stackTraceLimit、程序字节码、检测结果或引擎身份。

已观测调用链仍为 `bdms.init → XHR.send → 签名 VM → VM704/705 → 最终网络拒绝`。本轮捕获的是这条签名调用内的栈读取，不是普通 `new Error()` 探针：

- 两种启动方式各读取两次 VM704 PC55 的真实栈。
- 主动 `evaluate_script` 启动：每个栈 10 行，含工具的 `pptr:` 调用帧，不含 loopback 地址；VM705 共 60 次 test，全部 false；VM704 两次 false。
- 页面自身 `setTimeout` 启动：每个栈 8 行，无 `pptr:` 帧，含 `http://127.0.0.1:18772/`；VM705 PC24 两次命中，共 10 次 test 后提前结束；VM704 两次 true。
- 每种启动方式均使用全新 iframe 按原版／观测版／原版复跑，三组输出长度均为 192，各自组内 SHA 完全一致。主动执行组摘要 `07bac2dcf8797ff044ec2751b20905f83d3262ae04450ffb80835810a5a65bb2`；页面任务组 `5ef243469b5dee6aa62d2566e2cfb207c44fbceb33c6b565a8ea1978ac42fe08`。

**推断边界：** 原生栈文本及调用入口确实参与内部检测；不同入口同时改变栈和输出，是依赖证据，不是排除其他变量后的完整因果证明。两组同一公开向量的观测前后输出一致，不保证所有向量都没有观测扰动。插入本身会改变源码列偏移；主动执行不是 REA 被动捕获。

这是函数局部的合成浏览器宿主：固定时间、随机数、UA、伪 DOM 与阻断请求。只将测试 XHR/fetch 显式桥接到全局，防止原始 SDK 钩子与测试请求落在不同对象；location 等全局桥接仍不完整。它不是授权账号页面的真实签名器环境，也没有建立 QuickJS／Node／浏览器相等或服务端接受。本阶段没有以修栈、修检测结果或铺设完整 DOM 来追求一致，也没有修改 Rust 宿主。

### 失败与修正记录

最初三组因局部 XHR 与全局 XHR 分离而没有 a_bogus，结果读取报 TypeError；桥接同一测试请求对象后才成功。随后断言错误预设所有 VM705 调用均 false，页面任务对照使断言失败；核查原始落盘记录后修正断言，明确页面任务 PC24=true、VM704=true，而非修改执行结果。失败不计为成功样例。

独立页 5 的 12 条、页 6 的 5 条 DevTools 请求记录均只指向 localhost；页 6 Resource Timing 四条也只指向 localhost。iframe CSP `connect-src 'none'`，合成 XHR/fetch 最终拒绝，native fallback attempts=0。记录见 `browser-network-verification.json`，不将代码内自报的 platformRequests=0 单独作为证据。

## 各类生命周期必须分开

- **Cookie 会话值、浏览器 expiry 与后端会话 TTL：** 本阶段无真实 Cookie 输入或平台交付，未证明任何延长；历史零 Set-Cookie 仅表示当次未证明，不表示不存在非登录更新。
- **Ticket Guard Cookie／响应材料：** 消费侧处理与登录 provider 配置是两条证据链；本地存储、字段接收、标记或本地公钥匹配不等于服务端签发、证书信任或账号绑定。
- **可信时间：** 1105 分支请求 ensureFresh，是时间恢复；1103、1102 和 disabled 不触发。它不延长 Cookie 或 Guard 材料寿命。
- **服务端证书：** get_client_cert 用于服务端证书。公开 ECDH/HKDF/HMAC 互操作证明密码学算法连接正确，不证明平台证书信任、独立新密钥签发或会话续期。
- **TokenBeat：** 仅保活。boot／activity／poll／401 停止等离线行为通过，不据此推导 Cookie 更新或后端 TTL。

## 当前阶段已执行检查

日志统一保存在 `$PI_SCRATCH_DIR/offline-continuation-20261015/`，不将大日志放进项目。

```sh
D="$PI_SCRATCH_DIR/offline-continuation-20261015"
node "$D/build_stack_probe.cjs"
# python3 "$D/stack_server.py"：只监听 127.0.0.1:18772
# 在新的独立浏览器上下文打开 http://127.0.0.1:18772/，页面自身执行。
# 主动执行对照保存在 browser-stack-active-eval-result.json。
node "$D/verify_stack.cjs"
node tools/sdk_abogus_baseline.cjs "$PI_SCRATCH_DIR/official-sdk/bdms_1.0.1.19_fix.js" --check
node "$PI_SCRATCH_DIR/cookie-renewal/tokenbeat_baseline.cjs"
node "$PI_SCRATCH_DIR/cookie-renewal/time_failure_baseline.cjs"
node "$PI_SCRATCH_DIR/cookie-renewal/ecdh_hmac_baseline.cjs"
cargo test --offline --lib
cargo check --offline
cargo check --offline --tests
cargo run --offline --quiet --bin sdk_audit -- check src/douyin/sdk/manifest.json "$PI_SCRATCH_DIR/official-sdk"
cargo run --offline --quiet --bin sdk_audit -- activate src/douyin/sdk/manifest.json "$PI_SCRATCH_DIR/official-sdk"
```

结果：新栈断言通过；BDMS 22 例通过；TokenBeat 4 例通过；1105 时间失败分支 5 例通过；公开官方 ECDH/HMAC 2 例及非法证书对照通过；库测试 70 通过、0 失败；两项 check 通过。四资源 audit check 成功；activate 按预期退出 1：`no approved known pin; missing adapter`。`KNOWN_RELEASES` 仍为空，生产版本 disabled。未运行完整 cargo test、实网测试、发送、部署或远程重启。

## 消费方非登录更新：新增 33 例

父 SDK `90775.0c663da7.js` SHA-256 为 `ef38b30991af9aab6f2ff9a849991c38799a9cc5fcedd3ede006a8eeba90995d`。本轮执行 11 段摘要锁定的原始方法与 hooks；完整字节范围在 scratch `renewal/sources.json`，逐例结果在 `renewal/material-baseline.json`。

1. **响应与 Cookie 更新门槛不同。** 原始 hooks 在满足 needProxy/needUpdateTs 等配置后，响应有 truthy ticket 和 provider scene 即调用 setter，并不要求 ts_sign/client_cert 完整。ticket-only 是整条 sign JSON 替换，会丢失旧 ts_sign，但独立旧 cert 槽仍可保留。Cookie 分支的 ts_sign-only 材料也可写入。响应 result=7 的例子仍先更新材料，再处理失败。它证明本地消费分支，不证明任何端点实际投递该材料。
2. **错配清理受开关控制。** 原始 `_clearNotMatchedPubKey` `[113300,114126)`，摘要 `a51bc8c5a1133c8c65d5d12b8dbcce7acb71ffc6e2ff16365db8a0f084d945da`。开关关闭时错配旧 key 不妨碍新 sign/cert 存储；开启时删除 key、清运行态和 ECDH cache，但仍保存新原始 sign/cert。方法默认 false 不能推出所有真实部署配置均为 false。
3. **存储确认不是材料验证。** 原始 `confirmStorageState` `[140835,141608)`，摘要 `14031de0e670765b61ae38907485e7af6f2a6efcd65ed60dc17c4e7b218f899f`。只检查 local/iframe 任一处的 truthy key + truthy scene sign；即使 `{}`、文本 `null`、非 JSON、缺 cert 或错配，仍可能 is_storage=1。
4. **外层 setter true 不是持久化保证。** 原始 `setSignValueAsync` `[130867,131146)`，摘要 `338cabf36287ca0607d34b31426202ee41357b7330356889431971d36055f8a6`。外层 await 后无条件 true，未转交内层 false；测试覆盖非法 JSON、写入失败、禁用 sign 持久化时内存/存储分离。

关键内层 `_signValueWithIframe` `[129648,130565)` 摘要 `670dea8617112fd9bb1bc0de4ad60b4ba0bbd17f493b7ebf65f52f5120b14d8a`。这些方法是直接由固定父字节提取，不以 REA 静态语法关系代替运行证据。

宿主限制：存储、Cookie、iframe、monitor、time 均用明确的内存替身；公钥摘要只使用 synthetic 公共标签，DER 匹配排除，未验证证书信任、真实公钥派生或存储竞态。混淆 eq 的文本分支不等于完整证书验证；没有确定恢复公开名称 isClientCertMatchPubKey 的映射。真实配置、合法材料生产策略、账号绑定与平台接受仍未知，不能把上述行为称作续期。

复现：`node "$PI_SCRATCH_DIR/offline-continuation-20261015/renewal/verify_all.cjs"`。新增 33 例（正向 13、负向/不完整输入 20），旧 Cookie 4 例及 hooks 2 例全部通过；主执行者另行重跑同命令，结果一致。父字节/11 片段/原副本交叉校验及语法检查通过，旧文件摘要不变。离线 guard 拒绝网络并限制写入本阶段目录；这是防误用保护，不是恶意 JS 安全沙箱。

## 六项阶段验收

1. **已满足：生命周期与消费方分支。** 分开记录 Cookie 会话、Guard 材料、可信时间、服务端证书；新增非登录 Cookie/响应消费与不完整材料覆盖证据。TokenBeat 仍仅保活。
2. **已满足：新增 BDMS 依赖。** 真实内部栈读取与 VM705 PC24 命中、VM704 返回已捕获；区分普通探针、主动工具栈、页面任务及真实账号环境。
3. **已满足：宿主修正约束。** 只修正测试页 XHR/fetch 对象分离；原版/观测版/复跑正向对照及消费方非法输入对照通过。无 Rust 宿主变更、栈伪造、检测改写或完整 DOM 扩张；引擎不等价仍明确保留。
4. **已满足：实际回归。** 新栈、新消费方及受影响离线基线已执行；70 库测试与两项 check 通过。无全量或实网测试。
5. **已满足：证据边界与门禁。** 观测、推断、未知分离；获批集合空，activate 预期拒绝，未验证能力保持 disabled。
6. **已满足：留档与清理。** 大结果在 scratch；独立测试页 5/6 已关闭，身份核验后停止 PID37543，18772 端口关闭。已知敏感临时路径不存在，无新增真实凭证输入；一次性标记保留。见 cleanup-result.json。

这里的“已满足”仅针对本次离线研究合同。**真实 Cookie/后端会话延寿、匹配独立新密钥签发、跨引擎签名一致与服务端接受，仍未满足，且不在本轮线上验收范围内。** 未修复或部署此前新增目标弹窗的今日状态残留问题；相关用户改动保持原状。
