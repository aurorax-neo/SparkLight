# IM 身份续取修复与发送授权阻碍（2026-10-15）

## 状态

部分完成，尚未部署。自动身份 token 续取已在本地实现，真实只读续取成功；合法独立发送授权生成仍未建立，因此未执行真实发送，没有 message ID。

## 根因与修复

- 原调度未调用身份获取；只读上下文时间不等于身份 token 获取时间。新增可缺省的 identity_acquired_at，未知、过期、未来时间或账号/会话不符均不使用缓存。
- 自动任务在历史查询前及发送前调用共用续取；发送入口同样检查。失败或身份变化置发送停止状态，使用固定诊断，不打印凭证、不自动重试。
- 原 set_send_credential 会以捕获上下文覆盖当前 token。现在检查 token、服务端 device ID、aid 和 UA 匹配，不允许把新 token 拼接旧 HTTP 鉴权，不延长一次性授权寿命。
- 授权先读取并校验，最终提交前按账号、会话及原密文条件删除；避免校验失败时提前删除或误删替换材料。发送失败后不再按会话无条件删除新授权。
- 完整今日历史结论绑定发送方、会话类型和北京时间日期；最终提交前复查，跨日、已发或缺少完整历史则停止。单目标入口也先检查完整历史，已发跳过。

## 验证

- 91 项离线库测试通过，测试编译及后端构建通过。
- 新增 9 项测试涵盖自动续取后匹配合成授权单次 mock 发送、失败、身份变化、旧授权拒绝、旧数据缺省、未来/过期时间、发送入口自动续取、授权不提前消费、跨日与条件消费。
- mock 使用合成授权与合成历史，不能证明平台可签发或接受独立授权；测试传输仅 cfg(test) 启用，不回退真实网络。
- 授权账号 12345678（99191692311）真实只读验证：原上下文 EXPIRED、身份不在有效期；经同一 Rust prepare_im_identity 成功获取，前后 UID 一致；指定目标完整北京时间今日历史 sent_today=false。
- 探针生产数据库写入 0、发送请求 0、发送授权创建 0；临时 Cookie/密钥/加密上下文文件已删除，尝试标记保留，未重跑。
- 最后只读核对：108 容器仍 running healthy，启动时间 2026-10-15T05:01:45.481587008Z，源文件保持原发布版本；指定账号发送凭证仍为 0。

## 未解决的真实阻碍

account_im_credentials 的材料由捕获导入生成，不能由身份 GET 自动创建；调度原先 DELETE RETURNING 一次性取走，过期捕获也不能重用。当前未发现已验证的纯 Rust 合法新密钥绑定、匹配服务端签发及完整发送保护实现，批准的 SDK 集仍为空。

公开普通 IM 源码表明身份 token 在 protobuf headers，会话 ticket 另来自 conversation/GetTicket，发送路径受 Cookie Guard 保护；未能据此证明当前强制的三个 HTTP Ticket Guard 头是所有场景必填，也不能据此删校验、无保护发送或重放旧签名。不能用身份 token 替代独立授权。

按“链路修通后部署并真实发一条”的前提，本次未部署部分实现，未触发账号运行或发送接口；真实发送验收未完成。没有重新登录，没有主动测试其他账号或目标。

## 证据

scratch 目录 im-auto-refresh-fix-20261015：library-tests-reviewed.log、check-tests-reviewed.log、build-reviewed.log、live-read-result.json、live-read-attempted.json、production-final.log、result.json。真实只读续取发生在最终跨日/授权消费修正前；最终版本只执行离线回归与构建，未重复平台请求。

## 后续授权部署（14:19 CST）

用户随后明确要求部署新版。复测 91 项库测试、测试编译和后端构建通过后，仅发布 client.rs、im_auth.rs、web.rs、im_identity_tests.rs、scheduler/mod.rs 五个文件，未发布其他本地变更。

- 备份：`/opt/docker/sparklight-backups/im-auto-refresh-20261015-141756`。
- 回滚镜像：`sparklight:before-im-auto-refresh-20261015-141756`。
- 新容器启动：`2026-10-15T06:19:50.486550954Z`，running healthy，首页 HTTP 200。
- 发布文件哈希匹配；前端、无关后端、部署配置、依赖及密钥哈希保持一致。
- 切换前后 accounts、spark_targets、system_settings、account_web_contexts、account_im_credentials 一致；发送日志数量未增加，SQLite 完整性 ok，外键错误 0。
- 定时设置仍为 13:51，未补跑当天任务、未调用刷新或发送接口；新版本未再次主动请求抖音。
- 线上旧任务最终记录 SEND_CREDENTIAL_MISSING，说明之前 13:51 确有触发但缺少发送授权。新版部署不改变独立授权生成尚未建立的事实。
- 临时部署包与脚本已删除，备份、构建日志及 verification.json 保留。验收证据位于 scratch `im-auto-refresh-deploy-20261015/`。
