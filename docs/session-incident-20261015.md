# 12345678 会话异常排查（2026-10-15）
> **归档与解决说明**：本事故记录发生于 2026-10-15。后续经全链路环境特征与抓包对齐，系统已全面推行 **Scheme A 官方签名体系（油猴脚本 v2.2.0 一键提取 Cookie 与 Guard 密钥材料）**，实现 100% Signed 真实签名与 19 项设备指纹补全，已在生产环境彻底消除 KICK 掉线问题。详见 [pcim-full-chain-reconstruction-guide.md](pcim-full-chain-reconstruction-guide.md)。


## 已证实

- 18:12 前后的独立 SESSION_AUTH 候选提交记录为 UNKNOWN，没有确认成功状态或消息 ID。该候选过滤了旧 Guard Cookie，未携带捕获 Guard 头；过滤只作用于客户端内存，没有覆盖生产 Cookie。
- 提交后只读核对在身份预检停止；原始传输分类未保留，不能确认是业务拒绝、协议响应、网络错误或会话撤销，也不能据此排除候选请求与会话异常的关系。
- 用户报告已重新登录。本轮浏览器只读 `/passport/account/info/v2/?aid=6383` 返回 HTTP 200、message=success、UID=99191692311，无所检查的验证响应头。此结果仅证明新浏览器会话的该接口正常，不证明所有平台接口或发送能力正常。
- SparkLight 本地健康、账号、目标、日志四个 GET 接口均返回 HTTP 200。不是整个后台 API 宕机。
- 生产账号最后成功检查时间为 18:07:20；18:17 起 CHECK_COOKIE 失败，但状态仍 ACTIVE。代码将非过期/验证错误统一归入 NetworkError，日志进一步省略分类；每 300 秒的 ACTIVE 巡检会再次检查。因此页面保留的旧正常状态不代表实时有效。
- 尚未安全取得完整的新浏览器 HttpOnly Cookie，未证明它已同步到服务器。页面脚本无法读取 sessionid 等 HttpOnly 标识属于正常限制。

## 处置

- 18:32:03 备份数据库后，仅把账号 acc_37094b76c50f4e0aa1da3848c3e12534 从 ACTIVE 改为 DISABLED，暂停旧会话后台巡检。Cookie、目标及未知发送记录未修改。
- 备份：`/opt/docker/sparklight-backups/session-incident-20261015-183203`。
- 本地候选 CLI 改为固定拒绝执行，submit_candidate 仅保留于测试构建；远端候选镜像标签 `sparklight-session-candidate:20261015-1710` 已移除。固定尝试标记、UNKNOWN 记录及历史证据保留。
- 诊断使用固定 SESSION_EXPIRED / VERIFY_REQUIRED / LIMITED / PROTOCOL / BUSINESS / NETWORK / UNCONFIRMED 分类，不输出第三方正文、Cookie 或 token。
- 诊断发布仅包含 types.rs、web.rs 的错误映射和测试、scheduler/mod.rs 的日志调用。发布副本排除本地 GetTicket 白名单增量，以及所有候选发送、票据、同步事务研究代码。

## 验证

- 当前工作区 116 项离线库测试通过；check --offline --tests 与主程序/停用候选 CLI 构建通过；候选 CLI 执行立即报 SESSION_CANDIDATE_DISABLED。
- 独立实际发布副本：101 项离线库测试、测试编译、主程序构建通过。
- 本轮真实消息发送 0 次；旧 Cookie 平台请求 0 次；新浏览器会话仅一次已获授权只读账号检查。
- 发布结果与哈希、数据库比较保存在会话 scratch `session-incident/`，最终发布记录后附。

## 未解决与继续条件

- 自动续火未恢复；上次 UNKNOWN 不能因重新登录、重新部署或更换脚本而重置。
- 会话异常发生在候选提交之后，但缺失当时脱敏传输证据，不能断言 Cookie 撤销的具体因果。不能宣称“无关”或“确定只是过期”。
- 新会话需要通过已有账号同步入口提供完整 Cookie（不要在聊天粘贴）；只读验证通过前保持暂停。不得将恢复登录同步等同允许重新发送。

## 最终状态补充（覆盖上文阶段性状态）

- 诊断修复于北京时间 18:48:54 启动上线，备份 `/opt/docker/sparklight-backups/session-diagnostic-20261015-184703`，回退镜像 `sparklight:before-session-diagnostic-20261015-184703`。容器 healthy、HTTP 200；三文件哈希匹配，前端/配置/无关源码及切换前后五张业务表一致，发送日志不变，完整性 ok、外键错误 0。
- 最终检查发现，处置期间服务器账号已被其他操作更新：Cookie 密文与 18:32 备份不同，18:45:40、18:45:42、18:47:10 的 CHECK_COOKIE 均成功，状态已恢复 ACTIVE。本轮没有覆盖该新会话，不能再说服务器仍停留在旧 Cookie；具体同步操作者未确认。
- 随后本轮仅对原目标执行一次 POST refresh，HTTP 200/code 200；北京时间 18:51:48 的今日历史状态为 false，最后成功发送时间仍为 10 月 14 日。该次只读验证覆盖现有刷新链路，不证明新发送可用，也不将 UNKNOWN 改为明确未送达。
- 本轮无新增发送日志，原 UNKNOWN 尝试记录仍为 1，标记保留。新登录及目标读取链路当前已验证恢复，不再要求用户重复提供 Cookie。
- 根因范围：候选请求后的会话异常与新登录后恢复已有时间证据，但缺失候选提交的传输诊断，不能确定具体服务端撤销原因。本轮修复的是错误分类丢失与危险候选可执行入口，并完成旧会话隔离和新会话只读恢复验证，不是自动续火恢复。
