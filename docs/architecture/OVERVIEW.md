# Platform 代码结构与请求路径

## 仓库边界

Platform 是 Go 服务端。SDK 的公用协议和 libp2p 处理器由 `agent-comm/` 子模块提供；网站、账户和远程工作台属于独立 Web 仓库，整套服务发布属于部署仓库。

```text
agent-comm-platform/
├── cmd/platform/         # 服务启动与组装
├── internal/
│   ├── api/              # HTTP 路由、管理接口、审计与嵌入式管理页面
│   ├── auth/             # HTTP 签名验证
│   ├── config/           # 配置加载与保存
│   ├── registry/         # SQLite 目录存储和 HTTP 接口
│   ├── mq/               # SQLite 信箱、策略和 HTTP/SSE 接口
│   └── relay/            # libp2p Relay 服务
├── agent-comm/           # 固定提交的共享 SDK 子模块
├── docs/                 # 架构、指南与维护说明
├── config.example.yaml   # 配置样例
├── Dockerfile            # 单服务镜像入口
└── docker-compose.yml    # 单独部署 Platform 的组合配置
```

`go.mod` 用本地 `replace` 指向子模块。SDK 的提交必须与 Platform 一起审核、测试和更新；不能只更新 Git 指针而省略 SDK 发布。

## 一次请求经过哪些模块

1. [cmd/platform/main.go](../../cmd/platform/main.go) 加载配置、身份密钥、数据库及 libp2p host，组装服务。
2. HTTP 请求进入 [internal/api](../../internal/api/server.go)，路由到 Registry 或 MQ。需要身份的入口通过签名验证绑定调用方。
3. libp2p 流由 SDK 的 `registry.Server`、`mq.Server` 处理，使用相同的服务端存储实现。Relay 只转发网络流。
4. [Registry](../../internal/registry/store.go) 在写入边界校验 URN、PeerID、公钥和记录签名；[MQ](../../internal/mq/store.go) 校验签名信封、调用身份、消息 ID、额度与保存期限。

## 数据和安全边界

平台保存身份记录、加密信封、传递所需元数据以及管理/审计信息。密钥和数据库位置由配置决定。消息过期、ACK 和历史清理影响保存与去重期限；平台收下信封不证明 agent 已完成任务。

本机 helper 的可靠发送路径使用 HTTPS MQ。传统 Go SDK 还提供单独的 P2P/Double Ratchet 路径。两者的加密方式和确认含义见 [开发指南](../guides/DEVELOPMENT.md)。

早期设计中的**代持接收方密钥**和完整联邦路由没有实现。显式配置 v2 签名策略后，HTTP v2 MQ 实现指定网关私钥解密、正文认证与签名回执，并将原始信封和回执原子保存；v1 HTTP/libp2p MQ 共享存储层按该策略拒绝普通 Agent 间旧协议。透明 Relay 在合规 v2 下必须关闭。配置中的 `platform.mode` 仍只是显示字段，不能作为密码学模式已经启用的依据。详情见[开发指南](../guides/DEVELOPMENT.md)与[安全配置](../guides/SECURITY.md)。

## 修改与验证

服务端私有实现保持在 `internal/`，进程入口保持在 `cmd/platform/`。共享协议应先修改 SDK 并验证双方兼容性。运行 `go test ./...` 验证 Platform，再在 `agent-comm/` 中单独运行 SDK 测试；父模块不会递归运行嵌套 Go 模块。
