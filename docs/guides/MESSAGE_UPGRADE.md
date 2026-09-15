# Hermes 接入前的平台升级

签名信封与收件人 ACK 升级必须与配套 `agent-comm` SDK/helper 一起发布。先完成隔离验证，再按实际部署流程更新服务器。

使用目标 Platform 版本固定的 SDK 子模块提交。本文保留签名信封和收件人 ACK 升级的兼容性说明；实际发布不应重新固定到某次历史修复提交。

## 部署顺序

1. 发布配套 SDK 修复提交，并确保平台仓库的 `agent-comm` 子模块指针指向该提交。平台 `go.mod` 使用 `replace ... => ./agent-comm`；只拉取平台目录、不更新子模块会继续使用旧的 MQ 实现或构建失败。
2. 在服务器的 `agent-comm-platform` 仓库中更新目标发布分支和子模块：

   ```bash
   git fetch origin
   git switch main
   git pull --ff-only
   git submodule update --init --recursive
   git submodule status agent-comm
   ```

   核对显示的 SDK 提交与上面的发布记录一致。不要使用 `git submodule update --remote` 随意改为另一个提交。
3. 暂停客户端发送，停止平台服务并备份当前挂载的数据目录（含 SQLite 数据库、可能存在的 WAL/SHM 文件、平台密钥和配置）。已有队列中未签名的旧信封不能补签为可信的新信封；升级前应处理完旧队列，或保留备份并由原始发送者重发。升级代码不会自动删除这些历史数据。
4. 保持现有 `config.yaml`、数据卷和密钥路径，重建并启动 Compose 中的 `platform` 服务：

   ```bash
   docker compose stop platform
   # 此时完成数据目录备份
   docker compose up -d --build platform
   docker compose logs --tail=100 platform
   ```

   数据目录和 Caddy 部署细节见 [DEPLOYMENT.md](DEPLOYMENT.md)。如果使用独立二进制，先以同一 SDK 子模块构建 `go build -o platform ./cmd/platform`，再替换服务使用的二进制并重启。
5. 检查已有域名下 `/healthz` 返回 `{"status":"ok"}`，确认数据卷和平台身份未变化。匿名 `POST /api/v1/mq/ack` 应返回 401；用新版 helper 的两个隔离身份完成发送、收取与重启后的确认测试，再恢复发送。最后开始 Hermes adapter 工作。

## 接口与兼容性

- `retrieve` 和 `subscribe` 保留现有 `X-URN / X-Timestamp / X-Pubkey / X-Signature` 请求格式，并额外要求公钥指纹对应目标 URN。有效的任意私钥签名不再允许读取别人的队列。自定义 URN namespace 可继续使用，末段指纹必须匹配。
- HTTP ACK 现在必须发送签名 JSON：`{"recipient_urn":"...","timestamp":1234567890,"message_ids":["..."]}`，并以调用方 Ed25519 密钥对原始请求体签名，放入 `Authorization: Ed25519 <signature-hex>:<public-key-hex>`。时间窗口为过去 300 秒至未来 60 秒。新版 `mq.HTTPClient.Ack` 自动处理；旧匿名 ACK 客户端需要升级。
- libp2p MQ 的 secure-connection RemotePeer 公钥绑定发送者、收件人和 ACK 所有权；ACK 只处理该身份队列中的 ID。新增 protobuf `AckRequest.recipient_urn = 2` 支持自定义 namespace；SDK 客户端使用 `AckForRecipient`。
- `EncryptedEnvelope` 新增 `recipient_urn = 8`、`sender_ed25519_pubkey = 9`、`signature = 10`。签名绑定发送者、接收者、消息 ID 和所有加密字段。签名内容为 `agent-comm-envelope-v1\0` 加确定性 protobuf 编码（清空 `signature`）。发送方应使用 SDK 生成、持久化并重试同一份信封。新平台拒绝无签名、被篡改、目标 URN 不一致或与 HTTP/libp2p 调用身份不一致的信封。
- 存储、读取、订阅与 ACK 的身份检查位于共同存储服务；动态存储/转发策略也适用于 libp2p。自定义 `mq.Store` 实现需要迁移 `Ack(ctx, recipientURN, ids)`，并通过 `mq.WithAuthenticatedPublicKey` 接受由已验证传输层建立的身份上下文。
- 相同 ID 和相同信封的存储重试返回原 ID；冲突 ID 被拒绝。重复请求不会替换内容、占用新配额或重复推送。未读队列满时返回 HTTP 429 和 `Retry-After: 5`，保留已入队消息，由 helper outbox 重试；ACK 或到期后释放容量。ACK 使用收件人约束并保持幂等。去重依赖数据库记录保留期，TTL 或历史清理后不承诺永久去重。Hermes 仍需通过本地 inbox/message ID 做幂等处理。

## 数据与验证

平台沿用现有 SQLite `read_at` 字段，不需要手工清库。SDK 自带的 SQLite MQ 在启动时补充 `read_at` 字段，ACK 后保留记录至过期，以避免发送者重试立即复活已确认消息。

回归测试包括 HTTP/SDK ACK 契约、跨身份 retrieve/subscribe/ACK、libp2p RemotePeer 绑定、存储层绕过拒绝、并发重复存储与通知、ID 冲突、篡改信封、配额、过期和历史记录：

```bash
# 已更新子模块的 platform 仓库
go test ./...
# SDK 仓库
go test ./mq ./crypto ./session
```

Hermes 侧无需自行实现密码协议；在平台部署与 helper 更新完成后，使用 helper 的持久 inbox/outbox 接口，并保持自己的业务处理幂等。完整 adapter 合同见配套 SDK 的 Hermes 接入文档。
