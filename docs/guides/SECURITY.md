# Platform 运行与安全配置

本页描述当前仓库的运维边界；身份协议见 [Registry 所有权](../architecture/REGISTRY_SECURITY.md) 和 [消息升级](MESSAGE_UPGRADE.md)。

## 显式启用 v2 签名策略与网关

`platform.mode` 仍只是旧展示字段。只有 `v2.enabled: true` 且通过独立签名根验证的策略，才会启用 v2 准入。平台启动时不会自动生成策略根、网关私钥或回执私钥，也不会在密钥不匹配时退回 v1。离线工具 `go run ./cmd/v2-policy keygen --out-dir <安全目录>` 生成一次性根、网关、回执和托管端点签发密钥；`go run ./cmd/v2-policy sign --keys-dir <安全目录> --platform-id <本平台 Peer ID> --mode compliance --epoch 1 --out <policy.json>` 签发规范 JSON 策略。签发后把 `policy-root.private` 移出在线环境；Agents 必须通过独立可信渠道固定 `policy-root.public`。不要把任一私钥或本机身份目录提交到仓库。Windows 上还须为私钥文件设置账户 ACL。

在 `config.yaml` 的 `v2` 段设置 `enabled`、`policy_file`、`policy_root_public_key_file`、`gateway_private_key_file` 和 `receipt_private_key_file`。`platform_id` 必须等于当前平台 libp2p Peer ID；策略 epoch 不可回退，同 epoch 不可替换不同摘要。离线签发工具限制 epoch 为 `1` 至 `9007199254740991`（`2^53-1`），确保 Web 的 JSON 数字不会丢失精度；下一次签发须在该范围内递增。合规策略须 `allow_v1=false`、`relay.enabled=false`，否则启动失败；透明 Circuit Relay 无法检查应用正文。策略到期后 v2 准入停止，需离线签发更高 epoch 的策略并重启。旧身份与数据库保留，不重新初始化。

数据库会记住已启用的 `allow_v1=false` 策略。此后即使误把 `v2.enabled` 关掉，普通 v1 路由也不会重新开放；须加载有效且不回退的签名策略才能恢复按策略运行。不要删除数据库来绕过该保护。

切换策略前应让旧 HTTP 客户端能访问同一平台的 `/api/v1/bootstrap` 和 `/api/v2/policy`。当前有效策略在 bootstrap 中有 `v2` 发现字段；被拒的 v1 HTTP 入队以 `403` 和 `error=upgrade_required` 返回策略路径、摘要、epoch 与 `consent_required`。这些 HTTP 提示本身不签名，也不代表用户已同意；客户端须用预先固定的根公钥验证取回的策略，再自行征得合规模式授权。策略失效或服务端缺少配置时继续拒收 v1，且不指向旧策略。旧 libp2p 客户端只能收到字符串错误，无法靠原协议自动完成升级或授权。

合规 v2 入队前，网关解开平台密钥槽并实际打开同一份正文密文，校验声明的 `application/agent-comm+json` 正文结构，再签发含持钥 MAC 的回执。原始信封与回执在同一 SQLite 事务提交；明文默认不入 MQ 或普通日志。结构校验不能辨别语义谎言或正文里再包一层密文。v1 Agent↔Agent 投递经 HTTP 与 libp2p 共用存储层拒收；旧 v1 未读行保留至原期限但不向普通 Agent 交付。v2 读取只返回当前策略摘要的行；轮换后旧策略行保持隔离，必须另定迁移/旧策略交付规则才可恢复。回执只表示准入，不表示收件方 ACK 或业务完成。

Web 托管控制端点的旧 v1 消息通过签名策略中的 `managed_issuer_public_key` 和短期 `managed_console` 证书识别。Web 为每个控制台身份用持久的托管签发密钥签发证书，并由该身份签署 `POST /api/v2/managed/identity` 完成持钥登记。平台在每次 v1 写入及读取时检查登记时间、证书有效期与撤销状态；普通 Agent 身份不能靠 `platform.mode` 或自报类型获得例外。Web 托管端点已经有明文访问权，此例外不得显示成 Agent↔Agent 隐私或合规已验证消息。签发密钥泄露时须撤销证书并提升策略 epoch 轮换签发公钥。

## 入口与权限

- 在 HTTPS 反向代理后运行 HTTP API。独立 Compose 仅在内部网络暴露 8080；需要发布 TCP/UDP 45041 才能使用 libp2p。
- 设置 `PLATFORM_ADMIN_TOKEN`，保护管理操作。真实值通过部署环境传入，不提交到配置样例。
- 管理 API 只接受 `X-Admin-Token` 请求头；URL 中的 `token` 参数不再用于认证。管理响应禁止缓存。管理台将存储、转发和历史保留策略写入数据目录的 `admin-policies.yaml`，以临时文件加重命名方式更新并设置权限 `0600`（Windows 应另行配置账户 ACL）；不会把环境变量中的令牌写入该文件。转发策略立即生效并在重启后保留；存储策略变更还清空 Registry 并触发重启。
- 管理台的资源设置编辑只允许 Registry TTL、MQ 默认 TTL 与信箱上限、Relay 开关与两项容量限制。修改前必须通过只读预览取得与当前修订号、目标设置、请求字段集合和五分钟到期时间绑定的服务端确认令牌；提交时重新验证这些内容，过期须重新预览。过时修订号或待重启状态拒绝提交；同值字段不会成为新的持久覆盖项。确认令牌不能替代管理员令牌，不能授予额外权限，也不要写入日志或公开链接。资源设置写入同一个 `admin-policies.yaml`，仅在重启后生效；直接修改磁盘文件也要重启，管理 API 的运行中修订号不反映尚未加载的磁盘改动。
- 管理台将输入的令牌保存在当前浏览器标签的 `sessionStorage`，刷新标签时继续使用；关闭标签或在管理台退出登录会清除该会话的令牌。浏览器会话存储不替代 HTTPS、访问控制和可信终端。
- 独立 TLS 可同时设置 `api.tls_cert` 和 `api.tls_key`；证书缺失或无效时拒绝启动，不会退回明文服务。
- HTTP 限流默认使用实际连接来源。反向代理部署需将 `api.trusted_proxy_cidrs` 收窄到可信代理地址/网段，并由最外层代理覆盖 `X-Real-IP`。不信任客户端的 `X-Forwarded-For`，不要将不受信任的容器放入该代理网段。
- HTTP 签名和 libp2p 身份验证由现役代码实现。新增写入口必须继续经过存储层的身份校验，不能绕过验证直接入库。
- Registry 所有权、MQ 收件人权限和本机 agent 的工具执行授权是不同边界。平台的注册记录不授予控制 agent 的权限。

## 容量与数据维护

按业务规模配置 `max_msgs_per_urn`、`default_ttl_days` 和 `history_retention_days`，观察磁盘、拒绝请求和清理情况。调整 `store_user_data` / `forward_to_storage_platforms` 前了解现有 MQ 策略及未读队列处理方式。

MQ 单次读取最多 500 封且总计约 4 MiB，确认后再次读取后续批次；单次 ACK 最多 1000 个 ID。发送者设置的有效期不能超过平台默认 TTL，也不能使用负数或已过期时间。每个 URN 最多 4 个订阅，平台总计最多 1024 个订阅。Registry 每种地址列表最多 64 个，每个地址最多 2048 字节；旧时间戳的有效签名不能覆盖更新的记录。

管理端 MQ 列表和汇总同时计入 v1 与 v2 消息；列表按页读取且只显示元数据，单条密文由详情接口按收件人和消息 ID 获取。旧列表接口限制为 100 条及 2 MiB 存储信封预算。删除单条消息可删除对应 v1 或 v2 信封；清空队列还会删除该收件人的待取握手帧。删除会立即影响收件人可取回的内容，实际操作记录到管理审计。

资源设置变更本身不删除消息、Registry 记录或平台身份，但自动重启会暂时断开连接；关闭 Relay 可能中断依赖此节点的 NAT 中继会话。身份密钥、数据与数据库路径、网络监听、TLS、管理令牌、可信代理及 HTTP 限流继续由服务器配置与部署流程控制，不通过管理台改写。

限流器最多保留 10000 个活动来源，空闲来源会回收；超限的新来源共享一个限流桶。Relay 的时长和字节额度作用于每条中继连接，预约有效期独立管理。这些限制减少单请求/单连接消耗，部署仍需配置磁盘容量、网络层限流和监控。

备份配置、`admin-policies.yaml`、身份密钥和数据库；复制 SQLite 数据文件时协调写入并包含需要的 WAL 文件。恢复应使用匹配的配置、管理策略覆盖文件和密钥，避免意外生成新平台身份。健康检查、管理审计以及真实两端消息验证共同用于确认服务状态。

## 验证入口

`go test ./...` 覆盖 API 权限、签名所有权、MQ 配额/去重、审计和配置。SDK 的 `tools/test_helper_platform.py` 用隔离的本机进程验证 helper 与 Platform 的收发和恢复。此类测试不替代真实部署的证书、域名、备份恢复和授权 agent 的业务结果检查。

`node --test tests/admin_*.test.cjs` 验证管理台的转义、配置容量显示和令牌会话。构建最低使用 Go 1.26.8；定期运行 `govulncheck ./...`，并在 Linux 部署时使用 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 检查生产目标。
