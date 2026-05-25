# Agent Comm Platform - Alibaba Cloud ECS Deployment Guide

This guide defines the step-by-step setup and configuration requirements for deploying the **Agent Comm Platform** to an **Alibaba Cloud ECS (云服务器 ECS)** instance.

---

## 1. ECS Instance Recommendations (选型建议)

For typical P2P lighthouse and offline MQ storage loads, the platform is lightweight:
*   **Specifications**: **1 vCPU / 2GB RAM** (e.g., ECS burstable instance `ecs.t6` or general purpose `ecs.g6`) is sufficient.
*   **Operating System**: **Alibaba Cloud Linux 3** (recommended) or **Ubuntu 22.04 LTS**.
*   **Network**: Map an **Elastic IP (EIP)** or public static IP to the ECS instance.

---

## 2. ECS Security Group Configuration (安全组配置)

The platform requires specific inbound ports to be open for client REST access and libp2p P2P traffic.

### How to configure on Alibaba Cloud:
1. Log in to the **Alibaba Cloud ECS Console**.
2. In the left navigation pane, select **Network & Security** > **Security Groups**.
3. Select the region, locate your security group, and click **Manage Rules**.
4. In the **Inbound (入方向)** tab, click **Add Rule (添加规则)** to configure the following ports:

| Priority | Action | Protocol | Port Range | Source | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Allow | **TCP** | `8080` | `0.0.0.0/0` | HTTP REST API (Registry & MQ) |
| 1 | Allow | **TCP** | `45041` | `0.0.0.0/0` | libp2p TCP stream traffic |
| 1 | Allow | **UDP** | `45041` | `0.0.0.0/0` | libp2p UDP/QUIC hole punching |

> [!WARNING]
> You **must** open port `45041` for both **TCP and UDP**. If UDP is blocked, libp2p cannot establish hole-punched QUIC connections, failing NAT traversal.

---

## 3. ECS Persistent Data Disk Mount (数据盘挂载)

To prevent data loss (cryptographic keys in `/data/keys` and SQLite databases) when the system disk is reinstalled, store `/data` on a separate Alibaba Cloud data disk (云盘).

### Formatting and Mounting a Cloud Disk:
Log in to your ECS instance via SSH and run:

1. Locate the unformatted cloud disk (typically `/dev/vdb`):
   ```bash
   fdisk -l
   ```
2. Create an `ext4` filesystem on the disk:
   ```bash
   mkfs.ext4 /dev/vdb
   ```
3. Create the `/data` mount point:
   ```bash
   mkdir -p /data
   ```
4. Mount the disk:
   ```bash
   mount /dev/vdb /data
   ```
5. Ensure automatic mount on reboot by editing `/etc/fstab`:
   ```bash
   echo '/dev/vdb /data ext4 defaults 0 0' >> /etc/fstab
   ```

---

## 4. Install Docker & Docker Compose on ECS

### For Alibaba Cloud Linux 3:
Execute the following commands to install Docker:

```bash
# 1. Update DNF repositories
dnf makecache

# 2. Install Docker
dnf install -y docker

# 3. Start and enable Docker daemon
systemctl start docker
systemctl enable docker

# 4. Download Docker Compose binary
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
```

---

## 5. Configuration Setup (`config.yaml`)

Copy `config.example.yaml` to `/data/config.yaml` on your ECS instance.

### Edit Public IP Advertisement
Because your ECS instance sits behind Alibaba Cloud's NAT, the container is unaware of its public EIP. You **must** manually declare your ECS Instance's Public IP under `libp2p.external_addrs` so client agents can locate your node:

```yaml
# /data/config.yaml
platform:
  mode: "privacy"      # "privacy" | "compliance"
  data_dir: "/data"

identity:
  keys_dir: "/data/keys"

libp2p:
  listen_addrs:
    - "/ip4/0.0.0.0/tcp/45041"
    - "/ip4/0.0.0.0/udp/45041/quic-v1"
  external_addrs:
    - "/ip4/<YOUR_ECS_PUBLIC_IP>/tcp/45041"
    - "/ip4/<YOUR_ECS_PUBLIC_IP>/udp/45041/quic-v1"
```

---

## 6. Run via Docker Compose

Create a `docker-compose.yml` file on your ECS instance (e.g., at `/data/docker-compose.yml`):

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

### Start the Service:
```bash
docker-compose up --build -d
```

Verify startup via healthcheck:
```bash
curl http://localhost:8080/healthz
# Expected output: {"status":"ok"}
```
