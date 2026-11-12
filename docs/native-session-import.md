# 官方 Android 原生会话导入

## 适用边界

抖音新设备首次登录会校验 TicketGuard/TEE 设备证明。纯 Rust 服务端可以复刻普通
Passport 请求，但不能从 Android KeyStore 取得官方硬件证明链，因此新设备扫码可能被
官方以 `4044` 拒绝。实测公钥验证还可能返回 `verify_result=1330`、`error=18000`。
这些都不是应用版本过低，也不能通过修改版本号绕过。

可自动维护的路径是：在一台已被抖音信任的官方 Android 客户端上完成一次登录，将
该客户端的原生会话导入 SparkLight。导入成功后，SparkLight 使用同一设备参数和
`X-Tt-Token` 执行 App TokenBeat、原生会话校验与 Web/IM 材料维护，不再需要浏览器、
浏览器扩展或每日重新复制 Cookie。

`sid_guard` 仍有服务端签名固定的绝对有效期。导入器会拒绝已经过期的会话，也不会
承诺突破官方绝对有效期；到期或平台主动吊销后仍需重新登录。

## 导入文件

生成模板：

```bash
target/debug/native_session_import --template
```

文件字段必须来自同一个官方 Android 客户端会话，不能拼接不同账号或不同设备的数据：

| 字段 | 要求 |
| --- | --- |
| `account_id` | 网页新增账号可留空，由服务端生成；命令行导入必须填写现有账号 ID |
| `device` | 与登录 Cookie、Token 对应的 Android `device_id`、`install_id`、`openudid`、`cdid` 和 UA |
| `cookie` | 含 `sessionid`、`sid_tt`、`sid_guard`、`d_ticket` 的完整原生 Cookie |
| `x_tt_token` | 官方 App 签发的 `X-Tt-Token`；也可改用 `token_encrypted` |
| `uid` / `sec_uid` | 已有账号可留空并自动补齐；填写时必须与数据库一致 |
| `logged_in_at` | 可省略或填 `0`，导入时自动补齐 |

不要提交、粘贴到聊天工具或写入日志。导入文件在磁盘上必须只允许当前用户读取。

## 宿主机运行

网页新增账号可直接在「添加账号」中选择「导入原生会话」，无需先扫码或预先创建账号。
服务端会按抖音 UID 查重，同一 UID 已属于其他 SparkLight 账号时拒绝导入。

```bash
chmod 600 native-session.json
target/debug/native_session_import \
  --data-dir /path/to/sparklight-data \
  --input native-session.json \
  --dry-run \
  --skip-web-bootstrap

target/debug/native_session_import \
  --data-dir /path/to/sparklight-data \
  --input native-session.json \
  --verify
```

`--dry-run` 只校验并展示非敏感摘要，不写入数据库。首次正式导入建议先加
`--skip-web-bootstrap`，确认原生会话落库后，再由后台 TokenBeat 和定时巡检恢复
Web/IM 材料；不加该参数时，导入器会在落库前尝试建立 Web 发送上下文，失败不会影响
原生会话保存。

## 108 容器内运行

镜像已包含 `/usr/local/bin/native_session_import`：

```bash
docker cp ./native-session.json sparklight:/tmp/native-session.json
docker exec -u 0 sparklight chown sparklight:sparklight /tmp/native-session.json
docker exec -u 0 sparklight chmod 600 /tmp/native-session.json

docker exec sparklight native_session_import \
  --data-dir /data \
  --input /tmp/native-session.json \
  --dry-run \
  --skip-web-bootstrap

docker exec sparklight native_session_import \
  --data-dir /data \
  --input /tmp/native-session.json \
  --skip-web-bootstrap \
  --verify

docker exec sparklight unlink /tmp/native-session.json
```

导入器要求 `.master-key` 已存在，并将 Cookie、Token、Android 设备参数和后续轮转结果
使用该密钥整体加密。不要单独复制 `sparklight.db` 而不迁移 `.master-key`。

## 验证结果

成功后应满足：

1. 账号管理页显示“App 原生会话已保存”。
2. 手动点击“检测登录态”返回 `valid`；手动检测始终静默，不触发 Bark。
3. 日志出现 App 原生 TokenBeat 成功，且后续会话快照被重新加密保存。
4. 网络异常、限流或协议未确认只保留旧会话，不会覆盖为失效。

只有官方明确返回登录过期时，账号才进入失效状态。
