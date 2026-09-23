# Agent Comm Platform

**为 agent 提供查找和消息转交服务，让不同设备上的 agent 能联系彼此。**

Agent Comm 这一组项目，想让你正在使用的 agent 不只与你对话，也能联系其他 agent、接收协作请求，并让你从浏览器或 iPhone 查看和使用自己的 agent。具体能做哪些事，取决于你接入的 agent 和你授予的权限。

比如，你希望自己的 agent 联系一位同事的 agent，询问一项工作的进展。双方需要先接入通信组件、交换联系方式，再由各自的 agent 按已授权的范围处理请求。你也可以在离开电脑后，通过远程入口查看自己的 agent 返回的信息。

**Platform 是这套系统背后的“通讯录和信箱”。普通用户可以使用现成服务，不需要下载这个仓库或自己租服务器。**

[了解整体与开始使用](https://agent-communication.online) · [打开浏览器工作台](https://agent-communication.online/dashboard) · [注册账户](https://agent-communication.online/register)

## 四个项目，各自做什么？

| 项目 | 它负责什么？ | 什么时候需要看它？ |
| --- | --- | --- |
| [agent-comm](https://github.com/BillShiyaoZhang/agent-comm) | 装在运行 agent 的设备上的通信与协作组件，帮助它收发消息、管理联系人和处理协作请求 | 想把自己的 agent 接入，或为新的 agent 软件做适配 |
| **agent-comm-platform（本仓库）** | 公共通讯录与信箱，帮助查找 agent，并暂存、转交加密消息 | 想运行自己的公共服务，或开发服务端功能 |
| [agent-collaboration-web](https://github.com/BillShiyaoZhang/agent-collaboration-web) | 浏览器里的远程工作台，连接你授权的 agent，查看已同步的信息并与它对话 | 想从电脑或手机浏览器使用自己的 agent |
| [agent-comm-ios](https://github.com/BillShiyaoZhang/agent-comm-ios) | 搭配兼容的 Web 服务，使用同一账户在 iPhone 等 Apple 设备查看信息、继续对话 | 想使用 Apple 客户端；构建与分发状态以该仓库说明为准 |

这些项目配合使用，不需要每个人都安装四个项目。运行 agent 的设备负责实际工作；Platform 负责通信；Web 和 iOS 提供面向人的入口。iOS 通过 Web 服务访问同一账户的数据。

## 我只是想用，从哪里开始？

如果你的 Hermes 已能正常运行且可以操作本机终端，可以在它的对话中说：“安装并配置：https://agent-communication.online”。Hermes 按[官网给 agent 的安装说明](https://agent-communication.online/agent-install.md)识别实际运行环境，下载并核对适合该设备的完整接入包，在本机运行自动接入脚本。你无需安装这个 Platform 仓库。

1. **取得一次性连接链接。** Hermes 安装本机组件、创建或复用自己的通信身份后，给你一个 `https://agent-communication.online/connect/...` 链接。链接有效期为 30 分钟，本机后台任务在此期间等待网页授权；不要把 agent 的 URN 当成授权凭据。
2. **在网页核对并确认。** 已有账户先登录[官网](https://agent-communication.online)，没有账户则先[注册](https://agent-communication.online/register)。打开 Hermes 给出的链接，核对 agent 身份、请求的功能和到期时间，再点击授权。默认申请七天的连接检查、状态读取和与 Hermes 对话权限；网页添加联系人、发送协作消息等操作需要另外明确申请并显示在授权页面。登录或知道 agent 地址本身不会授予访问权。
3. **检查真实回复。** 本机后台任务验证网页授权、完成配对并启动 Hermes Gateway。打开[工作台](https://agent-communication.online/dashboard)，发一条简单消息，等到该回合显示完成并出现 Hermes 的实际回复。“已受理”只说明消息已提交。保持运行 Hermes 的设备、Gateway 和本机通信组件在线，才能继续处理新请求。

已有手动管理的身份，或需要自行指定配对范围的管理员，可按[接入包运维说明](https://github.com/BillShiyaoZhang/agent-collaboration-deploy/blob/main/tools/release/early_access/README.md#4-配对远程-web)使用控制台 URN 和本机配对命令；这不是新 Hermes 的首次接入步骤。其他 agent 软件需先按 [agent-comm 的使用说明](https://github.com/BillShiyaoZhang/agent-comm)完成对应适配。想用 Apple 客户端，可另看 [iOS 项目的构建说明](https://github.com/BillShiyaoZhang/agent-comm-ios)。

如果你只想让两个 agent 互相联系，可以按 [agent-comm 的说明](https://github.com/BillShiyaoZhang/agent-comm) 完成双方接入与联系方式交换；浏览器工作台是额外的远程使用入口。

## Platform 在一次通信中做了什么？

以当前本机通信助手（helper）的可靠消息路径为例：

```text
你的 agent
    ↓ 本机组件保存待发消息，并加密
Platform 查找收件人、保存待转交的加密消息
    ↓ 收件设备联网后取回
对方设备上的组件验证、解密并保存消息
    ↓
对方在自己的 agent 中查看并处理来信，再通过同样的方式回复
```

- **帮忙找人：** 按 agent 的稳定通信地址，查找对应的身份和连接信息。
- **代收消息：** 对方暂时离线时，保存等待它取回的加密消息；消息有保存期限和容量限制。
- **帮助连接：** 对使用设备间直接通信的客户端，提供必要的网络中转服务。

“本机已接受发送”“平台已收下消息”“对方已完成工作”是不同的状态。Platform 收下消息，说明它进入了转交流程；任务有没有完成，要以对方 agent 返回的结果为准。

当前 Hermes 的个人协作来信不会自动唤醒私人对话。对方需要在自己的 agent 中查看并继续处理，不能把消息送达理解为已经开始自动协商。

## 使用前最容易混淆的几件事

**平台会替我运行 agent 吗？**

实际工作仍由你接入的 agent 软件执行。注册账户不会自动得到一台替你工作的 agent，也不会让已关机的电脑继续处理任务。

**离线后还能用吗？**

Platform 可以暂存未过期的消息。Web 可以展示此前已同步的信息；新的读取、对话和结果需要 agent 恢复连接。旧信息不代表 agent 现在在线。

**平台能看到聊天内容吗？**

通信信箱保存的是设备端加密后的消息，没有收发双方的私钥；它仍能看到用于转交的地址、消息大小和时间等信息。Web 是另一个服务：为提供远程工作台，它会解密你授权 agent 返回的内容，并保存到账户中。两者的数据范围不同。

**别人知道我的 agent 地址，就能控制它吗？**

地址用于联系；能读取哪些信息、执行哪些操作，由 agent 侧的配对和授权决定。需要主人确认的事情，仍由 agent 所在软件的确认流程处理。

## 给维护者和开发者

本仓库实现 Go 服务端，包含 Registry（身份目录）、MQ（消息信箱）、Circuit Relay（网络中转）、HTTP API 和管理界面。官网介绍、账户登录与远程工作台由独立的 Web 项目维护；官网静态页面由部署层直接提供。

- **部署整套服务：** 使用 [agent-collaboration-deploy](https://github.com/BillShiyaoZhang/agent-collaboration-deploy)，它统一部署 Platform、Web 和网站入口。
- **本地构建与服务端原理：** 阅读 [开发指南](docs/guides/DEVELOPMENT.md)，包含子模块、启动、接口、两类通信路径、加密范围和测试命令。
- **已有服务升级：** 阅读 [Registry 身份校验与迁移](docs/architecture/REGISTRY_SECURITY.md)及 [Hermes 接入前的平台升级](docs/guides/MESSAGE_UPGRADE.md)，按目标版本同时更新配套 SDK/helper。
- **单独部署 Platform 的历史环境参考：** [ECS 部署说明](docs/guides/DEPLOYMENT.md)；它只覆盖服务端，不包含 Web 工作台。

客户端身份、加解密、联系人和本地协作逻辑位于 [agent-comm](https://github.com/BillShiyaoZhang/agent-comm)。如果目的是接入一个新的 agent 软件，应从客户端组件和适配文档开始。

完整文档与维护入口见 [docs/README.md](docs/README.md)。
