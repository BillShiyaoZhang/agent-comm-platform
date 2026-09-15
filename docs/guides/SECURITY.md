# Platform 运行与安全配置

本页描述当前仓库的运维边界；身份协议见 [Registry 所有权](../architecture/REGISTRY_SECURITY.md) 和 [消息升级](MESSAGE_UPGRADE.md)。

## 入口与权限

- 在 HTTPS 反向代理后运行 HTTP API。独立 Compose 仅在内部网络暴露 8080；需要发布 TCP/UDP 45041 才能使用 libp2p。
- 设置 `PLATFORM_ADMIN_TOKEN`，保护管理操作。真实值通过部署环境传入，不提交到配置样例。
- HTTP 签名和 libp2p 身份验证由现役代码实现。新增写入口必须继续经过存储层的身份校验，不能绕过验证直接入库。
- Registry 所有权、MQ 收件人权限和本机 agent 的工具执行授权是不同边界。平台的注册记录不授予控制 agent 的权限。

## 容量与数据维护

按业务规模配置 `max_msgs_per_urn`、`default_ttl_days` 和 `history_retention_days`，观察磁盘、拒绝请求和清理情况。调整 `store_user_data` / `forward_to_storage_platforms` 前了解现有 MQ 策略及未读队列处理方式。

备份配置、身份密钥和数据库；复制 SQLite 数据文件时协调写入并包含需要的 WAL 文件。恢复应使用匹配的配置和密钥，避免意外生成新平台身份。健康检查、管理审计以及真实两端消息验证共同用于确认服务状态。

## 验证入口

`go test ./...` 覆盖 API 权限、签名所有权、MQ 配额/去重、审计和配置。SDK 的 `tools/test_helper_platform.py` 用隔离的本机进程验证 helper 与 Platform 的收发和恢复。此类测试不替代真实部署的证书、域名、备份恢复和授权 agent 的业务结果检查。
