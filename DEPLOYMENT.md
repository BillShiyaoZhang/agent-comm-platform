# Agent Comm Platform - 阿里云 ECS 部署指南

本指南定义了使用 Docker 将 **Agent Comm Platform** 部署到 **阿里云 ECS（云服务器 ECS）** 实例的步骤、环境配置与安全组规则要求。

---

## 1. ECS 实例选型建议

对于典型的 P2P 寻址目录（Registry）与离线信箱（MQ）存储服务，平台对资源消耗非常低：
*   **配置规格**：**1 vCPU / 2GB 内存** 即可满足需求（例如：ECS 突发性能实例 `ecs.t6` 或共享型实例 `ecs.g6`）。
*   **操作系统**：推荐选择 **Alibaba Cloud Linux 3**（官方优化版本）或 **Ubuntu 22.04 LTS**。
*   **公网网络**：为 ECS 实例绑定一个**弹性公网 IP（EIP）**或使用固定公网 IP。

---

## 2. ECS 安全组配置 (防火墙端口开放)

平台同时运行了 HTTP 接口服务和 libp2p P2P 网络协议，您必须在阿里云安全组中放行以下端口：

### 配置步骤：
1. 登录 **阿里云 ECS 管理控制台**。
2. 在左侧导航栏中，选择 **网络与安全** > **安全组**。
3. 选择实例所在的地域，找到关联的安全组，点击 **管理规则**。
4. 在 **入方向** 标签页下，点击 **添加规则**，配置以下三个端口：

| 优先级 | 策略 | 协议类型 | 端口范围 | 授权对象 | 描述 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | 允许 | **TCP** | `8080` | `0.0.0.0/0` | HTTP REST API 访问端口（Registry & MQ 服务） |
| 1 | 允许 | **TCP** | `45041` | `0.0.0.0/0` | libp2p TCP 基础流通信端口 |
| 1 | 允许 | **UDP** | `45041` | `0.0.0.0/0` | libp2p UDP/QUIC 流量（用于打洞及 NAT 穿透） |

> [!WARNING]
> 请务必同时开放 `45041` 端口的 **TCP** 和 **UDP** 协议。如果 UDP 协议被封禁，libp2p 节点将无法通过 QUIC 完成 NAT 穿透打洞。

---

## 3. ECS 挂载独立数据盘 (数据持久化)

为了防止系统盘重装或容器销毁导致数据丢失（特别是 `/data/keys` 中的平台身份密钥和 SQLite 数据库），强烈建议将数据保存在独立的阿里云数据盘（云盘）上，并挂载至 `/data` 目录。

### 数据盘分区、格式化与挂载步骤：
通过 SSH 登录您的 ECS 实例，执行以下命令：

1. 确认挂载的数据盘设备名称（通常为 `/dev/vdb`）：
   ```bash
   fdisk -l
   ```
2. 在该数据盘上创建 `ext4` 文件系统：
   ```bash
   mkfs.ext4 /dev/vdb
   ```
3. 创建挂载点目录 `/data`：
   ```bash
   mkdir -p /data
   ```
4. 挂载磁盘至该目录：
   ```bash
   mount /dev/vdb /data
   ```
5. 配置开机自动挂载。将挂载信息写入 `/etc/fstab`：
   ```bash
   echo '/dev/vdb /data ext4 defaults 0 0' >> /etc/fstab
   ```

---

## 4. 在 ECS 上安装 Docker 与 Docker Compose

### 针对 Alibaba Cloud Linux 3 操作系统：
在终端执行以下命令进行安装：

```bash
# 1. 更新 DNF 缓存
dnf makecache

# 2. 安装 Docker 社区版
dnf install -y docker

# 3. 启动 Docker 服务并设置为开机自启
systemctl start docker
systemctl enable docker

# 4. 下载并安装 Docker Compose 插件
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
```

---

## 5. 配置文件设置 (`config.yaml`)

将 `config.example.yaml` 复制到您的 ECS 挂载目录 `/data/config.yaml`。

### 修改公网 IP 广播声明
由于云服务器（ECS）处于 VPC 内网中，容器无法自动感知它的公网 EIP。您**必须**手动在 `config.yaml` 里的 `libp2p.external_addrs` 中配置您 ECS 实例的公网 IP。否则，其他公网上的 Agent 将无法定位和连接您的平台：

```yaml
# /data/config.yaml
platform:
  mode: "privacy"      # "privacy" | "compliance" (合规审计模式)
  data_dir: "/data"

identity:
  keys_dir: "/data/keys"

libp2p:
  listen_addrs:
    - "/ip4/0.0.0.0/tcp/45041"
    - "/ip4/0.0.0.0/udp/45041/quic-v1"
  external_addrs:
    - "/ip4/<您的ECS公网IP>/tcp/45041"
    - "/ip4/<您的ECS公网IP>/udp/45041/quic-v1"
```

---

## 6. 使用 Docker Compose 运行服务

在您的 ECS 服务器上（例如在 `/data` 目录）创建 `docker-compose.yml` 文件：

```yaml
services:
  platform:
    image: agent-comm-platform:latest
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "45041:45041"
      - "45041:45041/udp"
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/platform/config.yaml:ro
      - ./keys:/data/keys
      - .:/data
    restart: unless-stopped
```

### 启动平台：
```bash
docker-compose up --build -d
```

通过健康检查接口验证是否启动成功：
```bash
curl http://localhost:8080/healthz
# 期望输出: {"status":"ok"}
```
