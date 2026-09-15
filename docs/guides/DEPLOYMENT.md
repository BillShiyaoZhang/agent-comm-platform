# 单独部署 Platform

本指南对应本仓库的 Dockerfile 和 Compose。包含 Web、官网和下载入口的整套部署使用 [agent-collaboration-deploy](https://github.com/BillShiyaoZhang/agent-collaboration-deploy)。

## 准备源码与配置

```sh
git clone --recurse-submodules https://github.com/BillShiyaoZhang/agent-comm-platform.git
cd agent-comm-platform
git submodule update --init --recursive
```

安装 Docker 和 Compose，并准备已有挂载目录 `/data`。本仓库配置不会替你分区或格式化磁盘。使用 [config.example.yaml](../../config.example.yaml) 作为独立部署的配置起点；当前 Compose 将它只读挂载到容器 `/etc/platform/config.yaml`。

核对配置中的数据库、密钥目录与外部地址。平台镜像以 UID 10001 运行，挂载目录须允许该用户读写。设置独立的 `PLATFORM_ADMIN_TOKEN`，不要将真实令牌写入仓库。

## 网络入口

- Caddy 发布 TCP 80/443 和 UDP 443，为 HTTP API 提供 HTTPS。
- Platform 发布 TCP/UDP 45041，供 libp2p 使用。
- 8080 仅在 Compose 网络内提供，不需要公网开放。

将 [Caddyfile.example](../../Caddyfile.example) 的配置调整为自己的域名后放到 `/data/Caddyfile`。域名解析应指向服务器。按实际环境配置入站规则，不要直接复制其他部署的公网地址或 PeerID。

## 启动和检查

在仓库根目录运行：

```sh
docker compose config --quiet
docker compose up -d --build
docker compose logs --tail=100 platform caddy
```

通过配置的 HTTPS 域名检查 `/healthz`。管理入口需要配置的管理令牌。再使用匹配版本的 helper 和两个隔离身份完成发送、取回和 ACK 验证；健康检查只证明进程可用。

## 升级与数据

保留配置、平台身份和数据卷；更新前停止写入并备份 SQLite 数据库及其 WAL/SHM 文件。按照 [消息协议升级](MESSAGE_UPGRADE.md) 和 [Registry 迁移](../architecture/REGISTRY_SECURITY.md) 检查兼容性。使用目标版本固定的 SDK 子模块重建镜像。

不要用删除卷的方式执行普通升级。验证与回滚使用自己的备份流程，生产数据不放入 Git。
