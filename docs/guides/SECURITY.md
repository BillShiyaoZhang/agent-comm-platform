# Platform 运行与安全配置

本页描述当前仓库的运维边界；身份协议见 [Registry 所有权](../architecture/REGISTRY_SECURITY.md) 和 [消息升级](MESSAGE_UPGRADE.md)。

## 入口与权限

- 在 HTTPS 反向代理后运行 HTTP API。独立 Compose 仅在内部网络暴露 8080；需要发布 TCP/UDP 45041 才能使用 libp2p。
- 设置 `PLATFORM_ADMIN_TOKEN`，保护管理操作。真实值通过部署环境传入，不提交到配置样例。
- 管理 API 只接受 `X-Admin-Token` 请求头；URL 中的 `token` 参数不再用于认证。管理响应禁止缓存。管理台将存储、转发和历史保留策略写入数据目录的 `admin-policies.yaml`，以临时文件加重命名方式更新并设置权限 `0600`（Windows 应另行配置账户 ACL）；不会把环境变量中的令牌写入该文件。转发策略立即生效并在重启后保留；存储策略变更还清空 Registry 并触发重启。
- 管理台将输入的令牌保存在当前浏览器标签的 `sessionStorage`，刷新标签时继续使用；关闭标签或在管理台退出登录会清除该会话的令牌。浏览器会话存储不替代 HTTPS、访问控制和可信终端。
- 独立 TLS 可同时设置 `api.tls_cert` 和 `api.tls_key`；证书缺失或无效时拒绝启动，不会退回明文服务。
- HTTP 限流默认使用实际连接来源。反向代理部署需将 `api.trusted_proxy_cidrs` 收窄到可信代理地址/网段，并由最外层代理覆盖 `X-Real-IP`。不信任客户端的 `X-Forwarded-For`，不要将不受信任的容器放入该代理网段。
- HTTP 签名和 libp2p 身份验证由现役代码实现。新增写入口必须继续经过存储层的身份校验，不能绕过验证直接入库。
- Registry 所有权、MQ 收件人权限和本机 agent 的工具执行授权是不同边界。平台的注册记录不授予控制 agent 的权限。

## 容量与数据维护

按业务规模配置 `max_msgs_per_urn`、`default_ttl_days` 和 `history_retention_days`，观察磁盘、拒绝请求和清理情况。调整 `store_user_data` / `forward_to_storage_platforms` 前了解现有 MQ 策略及未读队列处理方式。

MQ 单次读取最多 500 封且总计约 4 MiB，确认后再次读取后续批次；单次 ACK 最多 1000 个 ID。发送者设置的有效期不能超过平台默认 TTL，也不能使用负数或已过期时间。每个 URN 最多 4 个订阅，平台总计最多 1024 个订阅。Registry 每种地址列表最多 64 个，每个地址最多 2048 字节；旧时间戳的有效签名不能覆盖更新的记录。

管理端 MQ 列表按页读取且只显示元数据；单条密文由详情接口按收件人和消息 ID 获取。旧列表接口限制为 100 条及 2 MiB 存储信封预算。删除单条消息和清空队列会立即影响收件人可取回的内容，实际删除记录到管理审计。

限流器最多保留 10000 个活动来源，空闲来源会回收；超限的新来源共享一个限流桶。Relay 的时长和字节额度作用于每条中继连接，预约有效期独立管理。这些限制减少单请求/单连接消耗，部署仍需配置磁盘容量、网络层限流和监控。

备份配置、`admin-policies.yaml`、身份密钥和数据库；复制 SQLite 数据文件时协调写入并包含需要的 WAL 文件。恢复应使用匹配的配置、管理策略覆盖文件和密钥，避免意外生成新平台身份。健康检查、管理审计以及真实两端消息验证共同用于确认服务状态。

## 验证入口

`go test ./...` 覆盖 API 权限、签名所有权、MQ 配额/去重、审计和配置。SDK 的 `tools/test_helper_platform.py` 用隔离的本机进程验证 helper 与 Platform 的收发和恢复。此类测试不替代真实部署的证书、域名、备份恢复和授权 agent 的业务结果检查。

`node --test tests/admin_*.test.cjs` 验证管理台的转义、配置容量显示和令牌会话。构建最低使用 Go 1.26.8；定期运行 `govulncheck ./...`，并在 Linux 部署时使用 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 检查生产目标。
