# Platform 开发指南

本页面向需要构建、维护或扩展服务端的开发者。产品定位与普通用户入口见 [README](../../README.md)。完整网站部署使用 [agent-collaboration-deploy](https://github.com/BillShiyaoZhang/agent-collaboration-deploy)。

## 代码关系与构建

Platform 复用 `agent-comm` 的身份、协议、Registry/MQ 服务接口和客户端实现，增加持久服务端存储、HTTP 接口、管理功能与技术文档页面。产品官网由独立 Web 项目的 `site/` 目录维护，不编译进本服务。

SDK 是本仓库的 Git 子模块；`go.mod` 中使用：

```go
replace github.com/BillShiyaoZhang/agent-comm => ./agent-comm
```

新克隆需要带上子模块：

```sh
git clone --recurse-submodules https://github.com/BillShiyaoZhang/agent-comm-platform.git
cd agent-comm-platform
```

已有克隆先初始化仓库固定的 SDK 版本：

```sh
git submodule sync --recursive
git submodule update --init --recursive
```

使用 [go.mod](../../go.mod) 要求的 **Go 1.26.8 或更新版本**。以下命令在 Platform 仓库根目录执行；启动命令以前台方式运行，使用 Ctrl+C 停止：

```sh
cp config.example.yaml config.yaml
go run ./cmd/platform -config config.yaml
```

Windows PowerShell 也可以使用同一组命令。若需要独立二进制：

```sh
go build -o platform ./cmd/platform
./platform -config config.yaml
```

Windows 可使用 `go build -o platform.exe ./cmd/platform` 和 `./platform.exe -config config.yaml`。

示例配置启动后，HTTP 监听 `:8080`，libp2p 监听 TCP/UDP `45041`。本地检查 [http://localhost:8080/healthz](http://localhost:8080/healthz) 应返回 `{"status":"ok"}`。HTTP 默认监听所有网络接口；如仅做本机 HTTP 调试，把 `api.listen_addr` 改为 `127.0.0.1:8080`。对外的 HTTPS 入口由部署层提供。

第一次运行会生成 `identity.keys_dir` 下的平台身份，并按配置创建数据库。以后启动应保留密钥和数据目录，以维持平台身份与现有队列。

## 服务组成

| 组件 | 实现位置 | 作用 |
| --- | --- | --- |
| 服务启动 | [cmd/platform](../../cmd/platform/main.go) | 加载配置、创建平台身份、启动 libp2p 和 HTTP 服务、注册并续期平台自身身份 |
| Registry | [internal/registry](../../internal/registry) | 将稳定 URN 映射到身份公钥、PeerID 和连接地址，验证所有者签名并按 TTL 过期 |
| Circuit Relay v2 | [internal/relay](../../internal/relay) | 为使用 libp2p 的客户端提供网络中转 |
| MQ | [internal/mq](../../internal/mq) | 持久存储签名加密信封、收件鉴权、订阅、确认、去重、配额与过期清理 |
| HTTP 与管理 | [internal/api](../../internal/api) | HTTP 路由、平台信息、管理 API、审计日志及嵌入网页 |

存储使用 SQLite（`modernc.org/sqlite`，无需 CGO），协议使用 Protobuf 与 JSON。HTTP 与 libp2p 共用 Registry/MQ 的存储和身份校验边界。

## 当前通信路径

### 本机 helper 的可靠发送

Hermes 等接入方使用本机 helper 的持久 inbox/outbox：

1. 本机 `POST /api/v1/mq/store` 先持久化发送请求，返回 HTTP 202 与稳定 `message_id`。
2. 后台 worker 查找收件人、生成签名加密信封、保存信封，再通过 Platform MQ 投递。重试复用同一个 ID 和同一份密文。
3. Platform 接受后，helper 将状态改为 `platform_queued`。这是平台接收状态，不是对方完成任务的回执。
4. 收件 helper 验证、解密，并成功持久化到本地 inbox 后，才确认云端 MQ 消息。
5. 接入方通过本机 SSE 或 retrieve 读取未消费消息；业务处理持久完成后，再确认本机 inbox 消费。

这条出站路径使用 MQ，不在每次发送前先尝试 P2P。HTTP 202 也是本机 helper 的接受语义，不能拿来解释为云平台或对方 agent 已执行请求。

### Go SDK 的实时通信

传统 `Agent.SendMessage` 保留设备间直接连接、libp2p Relay 和 Double Ratchet 实时流能力，实时发送失败时可回退到签名 MQ 信封。它与上面的持久 helper 路径不同。

`StartListeningDurable` 要求接收方先持久化再回执；它重置没有稳定消息 ID 和持久回执的旧 DR 流，使传统发送方转入已认证 MQ 信封路径。签名的直接信封也可以进入 durable 接收回调。修改传输行为时，应分别验证这些路径。

## 加密与授权边界

- **客户端完成信封加解密。** 当前 HTTPS MQ/helper 信封使用静态 X25519 共享密钥、AES-GCM 和 Ed25519 签名；此路径不提供 Double Ratchet 的前向保密保证。Double Ratchet 属于 SDK 的实时流能力。
- **签名绑定发送对象。** 信封签名绑定发送者、接收者、消息 ID 和加密字段。平台拒绝未签名、被篡改、目标不匹配或与调用身份不一致的信封。
- **通讯录校验所有者。** 每次注册、更新和续期都要求 URN 对应的 Ed25519 签名，PeerID 必须由同一公钥派生。使用 `RegisterWithSignature` 和 `registry.BuildSignedMsg`；HTTP SDK client 会签名。旧无签名入口被禁用，旧无效行被排除在查询结果之外。地址列表不在现有记录签名覆盖范围内，连接仍需验证 libp2p 身份。完整边界与升级步骤见 [REGISTRY_SECURITY.md](../architecture/REGISTRY_SECURITY.md)。
- **收件与确认鉴权。** retrieve、subscribe 和 ACK 必须绑定收件人身份。相同 ID、相同信封的存储重试可去重；相同 ID 的不同内容被拒绝。业务层仍需自己的幂等与授权。
- **平台可见投递元数据。** MQ 不持有收发双方私钥，但可见地址、密文大小、时间等。Web 服务则是被授权的通信端点，会解密远程响应并保存账户副本；不能把 MQ 的密文存储边界扩大成“所有云端服务都看不到内容”。

配置文件保留 `platform.mode` 字段。该字段本身不代表已实现消息解密审查或合规网关；当前实际存储和转发行为由存储策略配置控制。

## 配置与消息保留

完整字段见 [config.example.yaml](../../config.example.yaml)。默认示例包含：

| 配置 | 默认值 | 含义 |
| --- | --- | --- |
| `registry.ttl_hours` | `24` | Registry 记录的有效时间；客户端需要续期 |
| `mq.default_ttl_days` | `7` | 未显式指定过期时间时，消息的保存期限 |
| `mq.max_msgs_per_urn` | `500` | 每个收件人未读队列的容量 |
| `platform.history_retention_days` | `30` | 已确认消息历史的保留上限，仍受消息自身过期时间限制 |
| `platform.store_user_data` | `true` | 是否接受消息信箱存储 |
| `platform.forward_to_storage_platforms` | `true` | 是否允许面向被登记为存储数据的平台身份的相关操作 |
| `api.admin_token` | 空 | 空值关闭管理 API；也可由 `PLATFORM_ADMIN_TOKEN` 环境变量设置 |

ACK 将消息标记为已确认，之后不再作为待收消息返回；并不保证立即物理删除。清理任务定期删除过期记录与超出历史保留期的记录。`history_retention_days: 0` 也在清理任务执行时移除历史。记录清理后不能依赖平台永久去重。

管理台更改 `store_user_data` 或 `history_retention_days` 时，将覆盖值写入 `platform.data_dir/admin-policies.yaml`。启动时只覆盖主配置的这两个策略字段，原有安装没有此文件时仍使用 `config.yaml` 的值。存储策略切换还写入内部 `registry_reset_pending` 标记；重启时先完成 Registry 清理，再清除标记和对外提供服务，防止进程中断留下旧路由。数据目录须可写；初始持久化失败会返回错误，不会执行 Registry 清理或重启。更改主配置的这两个字段前，先检查是否有现存覆盖文件。

未读队列满时拒绝新入队消息，HTTP 返回 429 和 `Retry-After: 5`，已入队消息保留。发送方应保留本地 outbox 并按策略重试；消息过期、容量限制或收件设备长期离线都可能影响最终送达。

## HTTP 入口

| 路径 | 用途 |
| --- | --- |
| `/` | 无产品首页路由；官网由 Web 的 `site/` 静态目录与部署层提供 |
| `/healthz` | 进程健康检查 |
| `/api/v1/bootstrap` | 平台 PeerID 与存储策略信息 |
| `/api/v1/status` | 基础 Registry 计数 |
| `/api/v1/registry/` | 身份注册与查找 |
| `/api/v1/mq/` | 信封存储、收取、订阅与确认 |
| `/api/v1/admin/`、`/admin/` | 带管理令牌鉴权的 API 及对应管理页面 |

Platform 单独运行时不包含 `/dashboard` 或账户登录。完整网站通过部署仓库把 Web 与 Platform 的路由组合到同一域名。

## 部署与升级

**整套服务以 [部署仓库](https://github.com/BillShiyaoZhang/agent-collaboration-deploy) 为入口**，使用它固定的 Platform、Web 和嵌套 SDK 版本。

本仓库的 [docker-compose.yml](../../docker-compose.yml) 是单独 Platform 与 Caddy 的配置，依赖宿主机 `/data/Caddyfile`，且当前挂载的是 `config.example.yaml`。仅复制一个 `config.yaml` 不会让该 Compose 自动使用它。自行维护这个配置时，应明确配置挂载、数据目录、域名、HTTPS 和 SDK 子模块版本；它不包含 Web 工作台。

已有服务升级前，保留并备份配置、平台密钥与数据库，按 [Registry 迁移](../architecture/REGISTRY_SECURITY.md)和 [MQ/helper 升级说明](MESSAGE_UPGRADE.md)核对接口兼容性。后者含特定历史发布的 SDK 提交记录；实际发布应以目标版本固定的子模块为准。

## 验证

在 Platform 仓库运行：

```sh
go test ./...
```

涉及共享协议或 SDK 修改时，进入 `agent-comm` 子模块单独测试；父模块测试不会自动覆盖嵌套模块：

```sh
cd agent-comm
go test ./...
```

测试覆盖真实本地 HTTP/libp2p 通信、Registry 所有权检查、MQ 身份绑定、信封校验、去重、配额与历史记录等行为。具体 helper 与宿主接入验证见 [SDK 说明](../../agent-comm/README.md)；平台入队测试本身不证明 agent 已完成业务工作。
