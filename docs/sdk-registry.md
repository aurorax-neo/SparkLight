# SDK 资源登记与离线校验

模块：`src/douyin/sdk_registry.rs`。只处理调用方传入的清单和资源字节；不下载、不落盘、不执行 JavaScript、不签名、不发送请求。

## 清单格式

必填字段：

- `schema_version: 1`、`adapter_abi: 1`。
- `resources`：非空数组，每项包含 `name`、`url`、`version`、`sha256`、`size`、`entrypoint`。
- `capabilities`：包含 `dynamic_request`、`ticket_guard`、`renewal`，值只能为 `unsupported` 或 `offline_only`。这些是候选的声明，不是生产权限。
- `evidence`：非空字符串数组，每条去除首尾空白后仍须非空；内容只作记录，不构成可信证明。

清单、资源项、能力对象均拒绝未知字段。版本和入口不能为空；入口仅作为元数据，不解析、不调用。资源名只允许 ASCII 字母、数字、点、下划线、连字符，拒绝单点、任何 `..`、路径分隔符、编码路径和重复名。单资源大小上限为 8 MiB，摘要必须是 64 位小写十六进制 SHA-256。

源地址仅允许本轮官方网页实际引用的精确静态前缀：`lf-douyin-pc-web.douyinstatic.com/obj/douyin-pc-web/ies/douyin_web/`、`lf-c-flwb.bytetos.com/obj/rc-client-security/c-webmssdk/`、同域 `/obj/rc-client-security/web/glue/`、`p-pc-weboff.byteimg.com/tos-cn-i-9r5gewecjs/`。要求 HTTPS，可显式指定标准端口 `:443`；拒绝 userinfo、query、fragment、其他端口、百分号编码、反斜杠、点路径段及空白。白名单不等于版本获批。清单最多 1 MiB、16 个资源、合计 32 MiB；单资源必须非空且不超过 8 MiB。

## API 与信任边界

1. `ValidatedManifest::parse(json: &[u8])`：反序列化并检查结构、源地址和字段约束。
2. `manifest.verify_resource(name, bytes)`：精确校验长度和摘要，返回只读 `ResourceMetadata`；通过只表示字节与清单一致。
3. `manifest.verify_candidate(&[(name, bytes), ...])`：要求全部声明资源各提供一次，生成不可变 `ValidatedCandidate`。元数据、能力声明、证据仅提供只读访问器；没有公开构造器、反序列化器或修改器。
4. `SdkRegistry::new()`：当前状态为稳定禁用回退 `disabled`。
5. `registry.evaluate_candidate(&candidate)`：匹配编译期 `KnownRelease` 固定 pins；匹配时校验全部资源身份、版本、入口、大小、源地址和实际摘要。优先已知 release，再检查稳定回退；空 pins 绝不是通配符。评估不改变状态。
6. `registry.activate_candidate(&candidate)`：当前始终返回包含 `missing adapter` 的错误。没有已批准 pin 时还会说明 `no approved known pin`；失败保留当前 release，不执行资源、不升级权限。

`KNOWN_RELEASES` 当前刻意为空，稳定回退没有资源。不能将清单自报 hash、匹配的本地字节或证据字符串自动学习为 approved pin。生产环境没有已验证 SDK 版本或适配器，因此所有实际候选均为 `UnverifiedCandidate`，不存在签名或续火花能力。未来增加资源 pin 也不能单独解除缺失适配器的启用门禁。

## 测试与接入

模块内 13 项测试覆盖内置清单、内容变更、摘要错误、长度与总量上限、未知 schema/ABI/字段、精确源白名单及规范化绕过、资源名路径逃逸和重名、空字段与摘要格式、候选完整性、自报新 hash 不获批准、固定 pin 匹配、稳定回退、旧 pin 保持及 supported 权限越权。pin 测试仅使用 abc 合成字节，明确不是官方版本，测试 pin 不进入生产 allowlist。

只运行库测试：`cargo test --lib douyin::sdk_registry::tests`。不要使用不带 `--lib` 的命令，以免运行实发集成测试。维护命令和官方执行基准见 [SDK 证据与更新流程](sdk-evidence.md)。

局限：仅提供内存中的资源一致性校验与候选评估，不持有可执行资源，不提供缓存、下载器、持久化 pin、发布者认证或生产适配器。调用方若以后消费资源，必须使用再次核验后的同一字节快照，不能仅凭历史元数据执行可变文件。

## 显式维护命令

`cargo run --bin sdk_audit -- <check|probe|fetch|activate> <manifest.json> <resource-directory>`。主服务 `sparklight` 不调用此命令，不读取候选目录，也不下载 SDK。

- `check`：读取有界快照，按清单核对每个资源的完整大小与摘要；不执行。
- `probe`：完整校验候选后，将同一快照交给 Rust 内嵌 QuickJS，32 MiB 内存、512 KiB 栈、2 秒中断；没有宿主网络、文件、进程、DOM、持久化、私钥或定时器执行能力。仅报告加载依赖，不代表签名或兼容性验证通过。
- `fetch`：只创建全新目录，从锁定官方 HTTPS URL 下载公开资源，不携带账号凭证、不使用代理、不跟随重定向。验证通过才写入，不覆盖旧版本；任一资源变化则返回错误，目录中此前已通过的文件可保留用于诊断，不能视为完整候选。
- `activate`：当前必定拒绝，保持 `disabled`；测试中验证固定旧 pin 与回退不因失败候选变化。生产完整签名适配器尚未验证，不能以清单权限声明解除门禁。
