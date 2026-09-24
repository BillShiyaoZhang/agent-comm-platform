# Platform HTTP API（云端）

本页供编写 Platform 客户端、排查 HTTP 互操作问题的开发者使用，描述当前服务端的 `/api/v1/` 和显式启用的 `/api/v2/` 接口。普通 Agent 接入优先使用 [Agent Comm SDK 与本机 helper](../../agent-comm/docs/README.md)：helper 也有 `/api/v1/mq/...` 路径，但它是**设备上的另一套接口**，请求体和认证不能与本页互换。English: [Platform HTTP API](API_EN.md)。

以下是当前实现的手写接口参考，不是自动生成的 OpenAPI 规范。部署时以实际域名或反向代理的 HTTPS 基地址为准，例如 `https://agent-communication.online`。服务端可单独监听 HTTP，但公开使用时应配置 HTTPS 入口；见[运行与安全配置](SECURITY.md)。

## 接口速查

| 方法与路径 | 用途 | 认证 |
| --- | --- | --- |
| `GET /healthz` | 存活检查 | 无 |
| `GET /api/v1/bootstrap` | Platform Peer ID、是否存储用户数据 | 无 |
| `GET /api/v1/status` | 当前 Registry URN 数量 | 无 |
| `POST /api/v1/registry/register` | 注册或续租 URN | Ed25519 原始请求体签名 + JSON 内的注册签名 |
| `GET /api/v1/registry/resolve?urn=...` | 查询一个 URN | 无 |
| `GET /api/v1/registry/list` | 列出现存、有效的 URN | 无 |
| `POST /api/v1/mq/store` | 存储签名加密信封 | Ed25519 原始请求体签名 |
| `GET /api/v1/mq/retrieve` | 获取收件人未读消息的一批 | 收件人读取签名头 |
| `GET /api/v1/mq/subscribe` | 订阅新消息的 SSE 流 | 收件人读取签名头 |
| `POST /api/v1/mq/ack` | 将指定消息标记为已读 | Ed25519 原始请求体签名 |

管理端点见[下文](#管理接口)。libp2p Registry、Relay 与 MQ 协议不属于这套 HTTP API。

## 请求签名

### 写请求：`Authorization`

对 `register`、`store`、`ack`，先确定**实际发送的 UTF-8 JSON 字节**，用调用者的 Ed25519 私钥签这些原始字节，并发送：

```http
Content-Type: application/json
Authorization: Ed25519 <64 字节签名的 hex>:<32 字节公钥的 hex>
```

服务端验的是请求体字节，而不是解析后重新序列化的 JSON。签名后更改空格、字段顺序或内容都会使验证失败。中间件允许的请求体上限是 20 MiB；MQ 信封另有更小的限制。签名公钥还须与具体操作的 URN 匹配：注册时等于 JSON 的 `ed25519_pubkey`；存储时属于信封 `sender_urn`；确认时属于 `recipient_urn`。

`register` **另有一份身份记录签名**，放在 JSON 的 `signature` 字段中。它是 URN 所有者对身份记录的签名，与 `Authorization` 中的 HTTP 请求体签名用途不同。构造方式见下一节。

### 读取与订阅：收件人签名头

`retrieve` 和 `subscribe` 都不使用上面的请求体签名。设置：

```http
X-URN: <收件人 URN>
X-Timestamp: <Unix 秒数，十进制>
X-Pubkey: <收件人 Ed25519 公钥的 hex>
X-Signature: <签名的 hex>
```

签名输入是 `UTF-8("mq-retrieve|" + urn + "|")` 后面紧跟 **8 字节大端序** Unix 秒数；用与 URN 对应的 Ed25519 私钥签名。两种接口使用相同的 `mq-retrieve|` 前缀。时间须在服务器当前时间的过去 300 秒至未来 60 秒之间。服务端同时检查公钥与 URN 的指纹关系。参考实现：[SDK 的 HTTP MQ 客户端](../../agent-comm/mq/client.go)。

## Registry

### `POST /api/v1/registry/register`

JSON 字段：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `urn` | string | 由 `ed25519_pubkey` 派生的自认证 URN；允许自定义命名空间，但指纹必须匹配 |
| `peer_id` | string | 从同一 Ed25519 公钥派生、采用规范字符串编码的 libp2p Peer ID |
| `addrs`, `relay_addrs` | string[] | 直连及 Relay 多地址提示；每组最多 64 项，单项最多 2048 字节 |
| `x25519_pubkey` | base64 string | 32 字节 X25519 公钥 |
| `ed25519_pubkey` | base64 string | 32 字节 Ed25519 公钥；须与 `Authorization` 中的公钥相同 |
| `stores_user_data` | boolean | 此身份声明的存储策略；被签名绑定 |
| `timestamp` | integer | Unix 秒数；须在过去 300 秒至未来 60 秒内 |
| `signature` | base64 string | 64 字节身份记录签名 |

Go 的 `[]byte` 经 JSON 编码后是 **base64 字符串**。身份记录签名的输入是：`UTF-8(urn + "|" + peer_id + "|" + hex(x25519_pubkey) + "|" + (stores_user_data ? "1" : "0") + "|")`，后接 `timestamp` 的 **8 字节大端序** 表示；用同一 Ed25519 私钥签名。SDK 提供 [`registry.BuildSignedMsg`](../../agent-comm/registry/client.go) 和 `HTTPClient.RegisterWithPolicy`。地址列表不在身份记录签名内，只能作为路由提示；连接时仍应验证 peer 身份。

成功：`200 {"ok":true}`。缺少身份签名、公钥或时间戳，或 HTTP 签名公钥与字段不一致时返回 `401`；字段、身份所有权、过期时间戳、地址限制、旧于现存有效记录的时间戳等校验失败返回 `400`。重复发布有效的新记录会续租；Registry TTL 由部署配置决定（默认 24 小时）。

### `GET /api/v1/registry/resolve?urn=<URL 编码的 URN>`

成功返回 `200`，包含 `found:true`、`urn`、`peer_id`、`addrs`、`relay_addrs`、公钥、`signature`、`timestamp`、`stores_user_data` 及 `expires_at`。二进制字段仍为 base64，`expires_at` 是**十进制 Unix 秒数字符串**。未找到、已过期或未通过所有权验证时返回 `404 {"found":false}`。缺少 `urn` 返回 `400`；安全策略禁止解析目标时返回 `403`。解析结果应由客户端再次验证身份记录签名。

### `GET /api/v1/registry/list`

返回 `200 {"urns":["..."],"count":1}`；仅列出现存、未过期且通过身份校验的记录。失败时可能返回 `500`。

## MQ（云端加密信箱）

MQ 保存的是 SDK protobuf `EncryptedEnvelope` 的序列化字节。信封含发送者和收件人 URN、消息 ID、密文及信封签名；请用配套 SDK 构造与校验，不能把本机 helper 的明文 `text` 请求体直接提交给 Platform。Platform 校验信封签名与调用身份，但不解密业务正文。

### `POST /api/v1/mq/store`

```json
{"recipient_urn":"<URN>","expiry_unix":0,"payload_proto":"<base64 protobuf EncryptedEnvelope>"}
```

`expiry_unix` 是 Unix 秒数；`0` 使用平台默认 TTL（默认 7 天）。有效的将来时间不得超出默认 TTL，超出的值会被截短；负数或已过期值会被拒绝。信封不得超过 1 MiB，消息 ID 不得超过 256 字节。成功返回 `200 {"ok":true,"message_id":"..."}`，表示**已存储**，不等于收件人已读取、ACK 或完成业务处理。

HTTP 签名公钥须对应信封发送者；信封签名及 `recipient_urn` 也须有效。关闭存储时返回 `400`，转发策略阻止目标时返回 `403`，身份不匹配时返回 `401`，无效信封/时间等返回 `400`。未读队列满时返回 `429` 且 `Retry-After: 5`（默认每个 URN 上限 500 条）；服务端限流也可能返回 `429`。用相同 ID、同一收件人及同一信封重试是幂等的；同 ID 不同内容会冲突。去重仅在原数据库记录仍存在时有效。

### `GET /api/v1/mq/retrieve`

带[收件人签名头](#读取与订阅收件人签名头)。成功返回：

```json
{"messages":[{"message_id":"...","payload_proto":"<base64 protobuf EncryptedEnvelope>"}],"count":1}
```

每次最多取 500 条未读消息，总负载约 4 MiB。**读取不会删除或确认消息**；处理后调用 `ack`，再读取下一批。空队列返回 `{"messages":[],"count":0}`。缺少 `X-URN` 返回 `400`，缺少/无效签名头返回 `401`，存储层校验或读取失败可能返回 `400`/`500`。

### `GET /api/v1/mq/subscribe`

使用与 `retrieve` 相同的签名头，成功后以 `text/event-stream` 返回 SSE。新的消息通过 `data: {"message_id":"...","payload_proto":"<base64 ...>"}` 事件发送；注释帧用于初始连接及约每 30 秒的保活。订阅是即时通知，仍应以 `retrieve` 和显式 `ack` 处理未读消息；慢客户端可能错过通知帧。每个 URN 最多 4 个并发订阅，平台最多 1024 个；超过时返回 `429` 和 `Retry-After: 5`。

### `POST /api/v1/mq/ack`

```json
{"recipient_urn":"<收件人 URN>","timestamp":1730000000,"message_ids":["<消息 ID>"]}
```

请求体须按[写请求签名](#写请求authorization)签署；`timestamp` 也是 Unix 秒，允许过去 300 秒至未来 60 秒；一次最多 1000 个 ID。成功返回 `200 {"ok":true,"deleted":N}`，其中历史字段名 `deleted` 实际表示**本次标记为已读的条数**：数据库设置 `read_at`，按历史保留期和有效期稍后清理，默认历史保留 30 天。重复 ACK 不再增加计数。收件人和签名公钥不匹配返回 `401`，无效 ID 列表返回 `400`。

## 管理接口

`/api/v1/admin/...` 仅供 Platform 管理员使用，统一要求 `X-Admin-Token: <配置的管理令牌>`。未配置管理令牌返回 `403`；令牌错误或缺失返回 `401`。管理响应带 `Cache-Control: no-store`。不要把令牌放入 URL；管理 API 应限制在可信网络。参见[运行与安全配置](SECURITY.md)。

| 方法与路径 | 查询参数 | 返回或作用 |
| --- | --- | --- |
| `GET /api/v1/admin/overview` | 无 | 运行时间、内存、连接、Registry、MQ、存储策略等概览；`restart_pending` 指示管理设置重启待完成，`registry_ttl_hours` 和 `mq_max_msgs_per_urn` 供管理台准确显示配置容量 |
| `GET /api/v1/admin/registry` | 无 | `entries`、`count` |
| `DELETE /api/v1/admin/registry` | `urn` 必填 | 删除指定注册记录；`{"ok":true}` |
| `GET /api/v1/admin/mq` | 无 | `queues`、`count`，只统计未读队列 |
| `GET /api/v1/admin/mq/summary` | 无 | `pending`、`history`、`expired` 的 `messages`、`bytes`、`queues`；三类互不重叠，`expired` 指未读且已过期 |
| `GET /api/v1/admin/mq/messages/page` | `urn` 必填；`status` 为 `pending`（默认）或 `history`；`limit` 1–200（默认 25）；`offset` 0–1000000（默认 0） | `{entries,total,limit,offset}`；列表仅含 ID、发送方、大小和时间等元数据，不返回密文载荷；无效参数返回 `400` |
| `GET /api/v1/admin/mq/messages/detail` | `urn`、`id` 必填 | 返回此收件箱中单条消息的元数据及 `payload`（密文十六进制）；不在此箱内返回 `404` |
| `GET /api/v1/admin/mq/messages` | `urn` 必填；`status` 为 `pending` 或 `history` | 兼容旧客户端的详情数组；最多前 100 条且载荷总预算 2 MiB；其他 `status` 按 `pending` 处理，新客户端应使用分页接口 |
| `DELETE /api/v1/admin/mq/messages` | `urn`、`id` 必填 | 仅删除此收件箱中的指定消息；`{ok:true,deleted:0或1}`，重复删除安全且审计实际删除 |
| `DELETE /api/v1/admin/mq/clear` | `urn` 必填 | 删除指定收件人的未读与已读历史消息，返回 `deleted` 数量 |
| `GET /api/v1/admin/config` | 无 | 脱敏配置，管理令牌显示为 `******` |
| `GET /api/v1/admin/config/editable` | 无 | 当前生效的六项可编辑资源设置、`revision`、`restart_pending` 及字段元数据 `fields`（类型、取值范围、重启要求和影响说明） |
| `POST /api/v1/admin/config/editable/preview` | JSON `{ "expected_revision": "...", "changes": {"mq.max_msgs_per_urn": 1000} }` | 只读预览；返回变更前后值、影响说明、`affected` 当前计数、`restart_required`、`confirmation_token` 及其 Unix 秒到期时间 `confirmation_expires_at`；有实际变化时才需重启 |
| `PUT /api/v1/admin/config/editable` | JSON `{ "expected_revision": "...", "changes": {...}, "confirmation_token": "..." }` | 经预览确认后写入有变化的设置并触发重启；返回 `ok`、`changed`、`restart_pending`、`settings`；无变化也须先预览确认，但不会重启 |
| `PUT /api/v1/admin/config/storage` | JSON `{ "store_user_data": true或false }` | 将存储策略设置为明确目标；值未变时 `changed:false`，变更时清空 Registry 并重启；响应含 `restart_pending` |
| `POST /api/v1/admin/config/toggle-storage` | 无 | 切换 `store_user_data`，清空 Registry 并触发 Platform 重启 |
| `PUT /api/v1/admin/config/forwarding` | JSON `{ "forward_to_storage_platforms": true或false }` | 将转发策略设置为明确目标；响应含 `changed`，变更立即生效并持久化 |
| `POST /api/v1/admin/config/toggle-forwarding` | 无 | 兼容旧客户端的转发策略切换；变更立即生效并持久化 |
| `POST /api/v1/admin/config/set-retention` | `days` 为 0–36500 的整数 | 设置已读历史保留天数；`0` 表示下一次清理时移除历史 |
| `GET /api/v1/admin/peers` | 无 | 连接中的非 Registry peer；不提供远端存储策略判定 |
| `GET /api/v1/admin/logs` | 可选 `limit`（1–500，默认 100）、`offset`（非负，默认 0）、`level`、`source`、`search` | `entries`、`total`、`limit`、`offset`；`search` 匹配消息文本 |

变更存储策略、删除消息或队列、驱逐 Registry 记录会影响线上状态，按[部署和备份指南](DEPLOYMENT.md)操作。三项管理策略 `store_user_data`、`forward_to_storage_platforms`、`history_retention_days` 原子写入 `platform.data_dir/admin-policies.yaml`，重启时覆盖主配置的对应字段；旧覆盖文件缺少转发策略时仍使用主配置。写入失败返回 `500`，运行策略保持原值。存储策略变更成功后，重启完成前再次调用存储策略接口或 `set-retention` 返回 `409` 与 `restart_pending:true`，不会覆盖待恢复的策略；转发策略可独立更新，并保留待重启标记。

资源设置编辑只允许以下六项；表中的取值范围约束**新提交的管理值**。旧主配置中不在新管理范围内的值不会仅因升级而被改写，例如原有 `mq.max_msgs_per_urn: 0` 仍按旧行为运行，但管理台不能提交 `0` 为新目标。六项设置在重启后生效，配置本身不会删除现有消息、注册记录或平台身份。重启会短暂断开连接，关闭 Relay 还会影响依赖它的 NAT 连通性和现有中继会话。

| 设置键 | 允许值 | 生效与影响 |
| --- | --- | --- |
| `registry.ttl_hours` | 整数 1–8760 | 以后注册或续期时使用新 TTL；已有记录的过期时间不追溯修改 |
| `mq.default_ttl_days` | 整数 1–3650 | 以后入队消息的默认及最长 TTL；已有消息的到期时间不追溯修改 |
| `mq.max_msgs_per_urn` | 整数 1–100000 | 以后写入时检查每个收件人未读队列上限；已有消息不因降低上限而删除 |
| `relay.enabled` | 布尔值 | 启停 Relay 服务；关闭可能影响经此平台中继的连接 |
| `relay.max_reservations` | 整数 1–100000 | 调整 Relay 预约容量 |
| `relay.max_circuit_duration` | Go 时长字符串，10 秒至 24 小时，如 `"2m"` | 调整每条 Relay circuit 的时长上限 |

`GET /config/editable` 的 `revision` 是当前进程已加载的六项设置的非语义标识；直接修改磁盘上的主配置或覆盖文件，须重启后才会进入该修订号。客户端应先读 `revision`，再调用 `preview`，核对返回的 `changes` 和 `affected`（`registry_entries`、`mq_queues`、`mq_messages`、`connected_peers`、`mq_queues_at_or_above_target_limit`），最后在 `confirmation_expires_at` 前原样提交相同的 `changes` 字段集合、目标值与 `confirmation_token`。确认令牌由服务器签发，绑定当前修订号、目标设置、请求字段集合和到期时间，五分钟后失效；过期时重新预览。同值字段不会被写成新的覆盖项。预览计数是当时快照，不保证提交时仍相同。旧修订号返回 `409`；缺少、不匹配或已过期的确认令牌返回 `400`。待重启期间预览和提交返回 `409` 与 `restart_pending:true`。六项设置和三项管理策略保存在同一 `admin-policies.yaml` 中；主配置继续保持只读。`platform.mode` 只是显示标签，`libp2p.external_addrs`、`registry.http_enabled`、`mq.http_enabled` 当前没有运行效果；身份、数据路径、监听、TLS、管理令牌、代理信任和 HTTP 限流仍由服务器配置管理。

## 通用响应与排错

`GET /healthz` 返回 `200 {"status":"ok"}`；`GET /api/v1/bootstrap` 返回 `peer_id`、`stores_user_data`，当已加载的签名 v2 策略与数据库固定的当前 epoch/摘要一致时，额外返回 `v2` 发现对象；`GET /api/v1/status` 返回 `registry_urns`。这些只能说明 HTTP 处理器可用或提供计数，不能证明双 Agent 消息流程成功。

客户端应先看 HTTP 状态码：`400` 请求字段/消息无效、`401` 签名或管理令牌验证失败、`403` 安全策略或禁用的管理接口、`404` Registry 未找到、`429` 容量或速率限制、`500` 服务端错误。**错误体格式不统一**：部分是 `{"error":"..."}`，部分是纯文本 `http.Error`；不要要求所有错误都可按 JSON 解析。方法不匹配通常是 `405`。时间签名失败时，先检查客户端与服务器的时钟。

更多行为和验证依据：[Registry 所有权](../architecture/REGISTRY_SECURITY.md) · [消息协议升级](MESSAGE_UPGRADE.md) · [平台代码结构](../architecture/OVERVIEW.md)。

## 显式启用的 v2 策略与信箱

只有部署了[签名策略与密钥](SECURITY.md#显式启用-v2-签名策略与网关)后，下列 `/api/v2/` 路径才可用。v2 规范 JSON 字节和密码学格式由 [SDK v2 包](../../agent-comm/v2/types.go)定义；HTTP JSON 中的 `policy`、`envelope`、`receipt`、`frame` 和 `certificate` 均为这些**原始字节的 base64**，不是解析后再生成的对象。POST 请求沿用 v1 的 `Authorization: Ed25519 <签名 hex>:<公钥 hex>`，签名覆盖实际发送的 JSON 请求体字节。

| 方法与路径 | 请求与响应 | 身份 |
| --- | --- | --- |
| `GET /api/v2/policy` | `{ "policy": "<base64>" }`；响应含 `ETag: "<policy_hash>"`，Agent 须用带外固定的根公钥验签，并固定最高 epoch | 无 |
| `POST /api/v2/mq/store` | `{ "recipient_urn": "...", "expiry_unix": 123, "envelope": "<base64>" }` → `{ "ok": true, "message_id": "...", "receipt": "<base64>" }` | 信封发送者 |
| `GET /api/v2/mq/retrieve` | `{ "messages": [{ "message_id": "...", "envelope": "<base64>", "receipt": "<base64>" }], "count": 1 }`；与 v1 相同的 `X-URN`、`X-Timestamp`、`X-Pubkey`、`X-Signature` 读取签名头 | 收件者 |
| `POST /api/v2/mq/ack` | `{ "recipient_urn": "...", "timestamp": 123, "message_ids": ["..."] }` → `{ "ok": true, "deleted": 1 }` | 收件者 |
| `POST /api/v2/handshake/store` | `{ "frame": "<base64>" }` → `{ "ok": true, "frame_id": "..." }`；只准入签名、当前策略绑定的 Init/Accept/Finished 固定格式帧 | 帧发送者 |
| `POST /api/v2/handshake/retrieve` | `{ "recipient_urn": "...", "limit": 100 }` → `{ "frames": [{ "frame_id": "...", "frame": "<base64>" }], "count": 1 }` | 收件者 |
| `POST /api/v2/handshake/ack` | `{ "recipient_urn": "...", "frame_ids": ["..."] }` → `{ "ok": true, "deleted": 1 }` | 收件者 |
| `POST /api/v2/managed/identity` | `{ "certificate": "<base64>" }` → `{ "ok": true, "urn": "...", "expires_at": 123 }`；证书由策略指定的 Web 签发密钥签署，请求体由证书中的控制台身份密钥签署 | Web 控制台身份 |
| `POST /api/v2/managed/revoke` | 签发者签署 `{version,platform_id,serial,revoked_at,signature}`，撤销证书序号 | 策略指定的 Web 签发者 |

`compliance` 入队必须成功打开平台密钥槽和同一份正文密文，回执结果为 `decrypted-admitted` 并包含绑定原始信封的持钥 MAC；`private` 回执为 `accepted-uninspected`。相同 ID、相同原始信封的重试返回原回执；相同 ID 的不同字节返回 `409`。超额返回 `429`。策略/准入冲突返回 `409`，v1 非托管端点在 `allow_v1=false` 时返回 `403`。Web 托管端点须先登记有效证书；旧 v1 行只有在写入当时已登记的托管身份参与时才可取回。当前实现没有 v2 SSE，也不会把旧 v1 或旧 v2 策略行升级为当前合规消息。

普通 v1 HTTP 入队被当前签名策略禁止时，`403` 响应为固定 JSON 格式，例如：

```json
{"error":"upgrade_required","message":"v1 delivery is disabled; verify the signed v2 policy and upgrade before retrying","consent_required":true,"policy_url":"/api/v2/policy","policy_hash":"<64 位 SHA-256 hex>","policy_epoch":2,"policy_mode":"compliance","platform_id":"<平台 Peer ID>"}
```

`/api/v1/bootstrap` 的 `v2` 对象也提供同名策略地址、摘要、epoch、模式、平台 ID，以及 `upgrade_required`、`consent_required` 布尔值。`consent_required:true` 只表示切换到合规模式前客户端必须取得用户授权，**不表示平台已经取得或记录了授权**。错误体和 bootstrap 本身未签名，只用于发现：客户端必须读取 `policy_url` 的原始策略字节，以独立固定的根公钥验签并核对摘要、平台 ID、epoch、有效期，然后由本地客户端处理用户选择。有效策略不可提供时，v1 仍拒收；错误体的 `consent_required` 为 `null` 且不附策略地址/摘要，bootstrap 不附 `v2` 对象。旧 HTTP 客户端可显示 403 错误体，但不会自动升级或代用户同意。旧 libp2p MQ 协议只有字符串错误（现以 `upgrade_required:` 开头），没有机器可读的 HTTP 状态或可信策略地址；需升级客户端或通过已知 HTTPS 平台地址另行发现策略。
