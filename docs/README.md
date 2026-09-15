# Platform 文档

产品说明与使用入口见 [项目 README](../README.md)。本仓库维护公共 Registry、加密信箱与 libp2p Relay；部署整套服务使用独立的 [部署仓库](https://github.com/BillShiyaoZhang/agent-collaboration-deploy)。

## 开发与运行

- [开发指南](guides/DEVELOPMENT.md)：初始化子模块、构建、接口和验证。
- [单独部署 Platform](guides/DEPLOYMENT.md)：本仓库 Docker/Compose 配置。
- [运行与安全配置](guides/SECURITY.md)：管理令牌、网络入口与数据维护。
- [消息协议升级](guides/MESSAGE_UPGRADE.md)：已有队列、签名信封及 ACK 兼容性。

## 架构与维护

- [代码结构与请求路径](architecture/OVERVIEW.md)。
- [Registry 所有权与迁移](architecture/REGISTRY_SECURITY.md)。
- [目录整理依据](maintenance/REORGANIZATION.md)。

文档与实现一起修改。现役行为写入架构/指南；尚未实现的设想应明确标注，不能作为已发布能力介绍。
