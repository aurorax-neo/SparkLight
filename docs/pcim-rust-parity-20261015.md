# PCIM Rust 计算层复刻与验证
> **归档与演进说明**：本文档记录了 2026-10-15 Rust 纯算法层（Guard P-256、DTrait 820 字节、特征哈希）的逆向与测试对照。后续系统在此基础上，正式演进并确立了 **Scheme A 官方全链路复刻方案（油猴脚本 v2.2.0 一键导入正牌私钥与票据，100% Signed 模式发送）**，已全面部署上线并完成实机双向发信验收。最新指南请参阅 [deployment-and-operation-guide.md](deployment-and-operation-guide.md)。


## 已实现，尚未接入发送

- `pcim_guard.rs`：P-256 公钥编码、公钥声明 Cookie/头、ECDSA DER/SHA256、ECDH→HKDF-SHA256→HMAC、client-data JSON/Base64、响应头与 URL 编码 Cookie 材料解析。检查 UID、全部会话 Cookie 字段、本地公钥匹配、重复材料和本地600秒门限。该门限不是已证明的服务器TTL。无浏览器私钥导入/导出接口，没有网络请求能力。
- `pcim_dtrait.rs`：官方中央 JSON 属性顺序、整路径链式前缀重写、AES128-CBC/PKCS7、RSAES-PKCS1-v1_5 包装 AES key 的32字符hex文本、版本/RSA密文/IV与密文拼接；兼容SPKI与PKCS1公钥，解析type=trait服务器配置。
- `pcim_features.rs`：官方v0字段映射、布尔位图、按编号排序的大端32位记录、Murmur3、中央/边缘Base64。公开接口只接收归一化bool/u32；未实现任意JS值的强制转换/异常半写入API，更未实现真实浏览器特征采集。

新组件不是完整授权适配器，生产发送仍使用原有授权检查；候选CLI保持禁用。没有导入或重放官方浏览器成功请求的签名，没有修改旧UNKNOWN。

## 对照证据

PCIM Guard源SHA256：`19584d9b6099b1eb538cb8b30695d47eedf86f2358b03a9f29c3d1de7db851f3`。`tools/pcim_guard_baseline.cjs`从原文件AST提取rP/r_/rw/rk/rS/rT，在离线VM运行输入及头选择，用Node密码学生成公开向量；两版本×两算法4组。HMAC报文逐字节一致；ECDSA双方签名使用同公钥跨实现验签（随机ECDSA不要求签名字节相同）。首次对照暴露测试时钟只覆盖Date.now而未覆盖new Date，修正测试时钟后通过。

DTrait公开源SHA256：`cf35e851627219261e00c1362b40611ad9cbdc9ea5c394ce2cc6561450c969ca`，REA父证据 `ev_4e03a66726a67ab29e2f56042a2330b031202860b773497433f0c9ad9f0ab89c`，本轮复用模块视图。离线解码555函数、831字符串，原始UMD加载探针13项、特征协议探针13组通过。AES底层使用Node桥接，不宣称浏览器WebCrypto全流程测试。

Rust验证6组AES密文、中央header逐字节一致、RSA本地加解密、13组官方特征内部状态编码及归一化写入/Unicode哈希。空/失败/非法值状态向量用于编码对照，不代表完整JS输入转换或真实采集器等价；合成值仅用于离线测试，未用于平台请求。

一次独立代码复核发现重复会话Cookie歧义，已修复：新Guard边界拒绝重复sessionid/sessionid_ss/sid_tt，哈希绑定全部存在的会话字段，次级字段变化也拒绝。复核范围为当时Guard/DTrait计算层；后续特征层没有追加独立复核。

最终 `cargo test --offline --lib` 129项通过；`cargo check --offline --tests`、`cargo build --offline --bin sparklight`通过。既有未用研究结构警告未移除。

## 真实只读配置验证

新独立探针 `scratch/sdk-isolated/src/bin/pcim_config_read.rs` 一次执行：授权账号99191692311身份→`/passport/ticket_guard/get_client_cert/?aid=6383&type=trait&sdk_version=1.0.25&is_from_ttaccountsdk=1`→身份，最多3请求，无重试/重定向。

结果：business_success=true、rust_config_parsed=true、identity_postcheck=true，返回中央公钥/版本等字段；请求3、发送0、生产写入0、未替换Guard绑定公钥。不保存响应原文/配置公钥或凭证，仅保存字段名和结果。配置取得不等于Guard账号票据签发。

## 尚未解决

1. Rust持有的独立密钥，仍需获得服务器为其绑定的ticket/ts_sign/client_cert并验证刷新。不能用新密钥搭配浏览器旧证书。旧注册/TokenBeat探针已包括公钥声明，不能将该声明视为新缺失项重新尝试。
2. 旧注册探针未对Cookie做URL解码，原始响应已清理，无法重新确认是否漏解析；不能据此宣称服务器绝不签发，也不能据此重分类旧结果。
3. 真实采集输入包括浏览器/设备特征；当前Rust完成的是归一化特征编码，不制造缺失特征或把离线合成值用于发送。
4. 未完成真实Rust发送验收，未部署本轮后端组件。108保留 `sparklight:im-button-20261015-204112` 前端修复。

完整临时证据位于会话scratch `pcim-rust-parity/`，含Guard/DTrait脚本、反汇编、测试日志、配置读取标记及结果、源文件哈希。公开回归向量位于 `src/douyin/sdk/pcim_*_baseline.json`。

## 压缩中断后的只读续查

- 未进行平台请求、消息发送、重新登录或108部署；没有重跑已消耗探针。后续真发仍须独立记账、至多一次、禁用自动重试。
- 已下载PCIM `5770.1fc7435b.js` 字符偏移160650附近：消费者响应也可处理 `bd-ticket-guard-server-data`，故不能断言仅登录能够签发。是否实际签发取决于服务端，客户端更新分支不构成签发证明。
- 字符偏移61433附近的证书接口读取 `server_cert/server_sn`，不能替代账号绑定的 `ticket/ts_sign/client_cert`。偏移95950附近的初始化公钥Cookie声明在旧TokenBeat探针中已实现；该探针结果 `server_material_count=0`、`matches_new_public_key=false`。不得把重复同一请求当作新方案。
- 已下载公开PCIM模块的提供方配置引用扫描仅找到3处（均在5770）；结果在scratch `pcim-rust-parity/provider-config-occurrences.json`。这不是对所有动态配置或服务端入口的穷尽证明。
- `7750.7e9c1cf7.js` 字符偏移300附近及成功浏览器记录使用SDK `0.1.8` / `0d50935:feat/pc-im-group`；当前只读初始化使用另一SDK标识。差异已确认，但没有证据说明改标识能补齐授权，因此未修改已验证只读路径。

### 真实特征适配结论

只读分析依据scratch `pcim-rust-parity/dtrait/functions.json`、`FEATURE-PROTOCOL.md`及原始UMD。以下fn编号对应已解码函数：

- bool组fn307依赖DOM、图片、navigator、TouchEvent、RTCPeerConnection；上游失败可能整组省略，不能逐项补false。
- str字段包含CSS/系统字体(fn329–341)、DOM矩形(fn310)、Canvas(fn264)、音频(fn257–262)、字体与emoji(fn491–521)、媒体支持(fn372/376–378)、navigator/Intl/screen(fn343)、语音(fn417)、SVG(fn428)、WebGL(fn439–451)、WebCrypto自测及耗时(fn549/554)。str11/12来自JS数学计算(fn313)。
- 缺失语义分为成功值、明确默认值、失败省略及undefined序列化异常；并非统一补零。特别是CSS内部吞异常返回undefined，外层保留undefined字段，写入字符串编码时可能抛错；UMD末尾又无条件访问window。未发现官方独立无浏览器运行模式。
- 中央通常记录原串Murmur3值，边缘再hash该数的十进制字符串；WebGL厂商/渲染器还有内部预哈希。原生系统参数不能冒充这些浏览器采样结果。
- 可构造格式有效的部分协议，不代表服务端接受；没有使用伪造浏览器特征执行线上请求。

### 当前执行边界

缺少可验证的非登录新公钥票据签发路径，同时尚未验证无浏览器真实特征的服务端接受性。现有证据不足以安全接通自动发送，保留 `SEND_CREDENTIAL_MISSING` 门禁。此结论是当前实现与证据的明确缺口，不是宣称Rust不可能实现或服务端只能登录签发。独立Rust真发验收和后端部署仍未完成。
