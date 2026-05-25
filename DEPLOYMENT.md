# Agent Comm Platform Deployment Guide

This guide defines the setup and configuration requirements for deploying the **Agent Comm Platform** to cloud infrastructure (such as AWS, GCP, Azure, or private VPS) using Docker.

---

## 1. Port Configurations (Security Groups / Firewalls)

The platform exposes both a REST HTTP API and a libp2p network interface. You must expose the following ports in your cloud firewall/security groups:

| Port | Protocol | Purpose | Description |
| :--- | :--- | :--- | :--- |
| **`8080`** | **TCP** | HTTP REST API | Used for Registry address resolution, list queries, and MQ mailbox storage & retrieval. |
| **`45041`** | **TCP** | P2P Control/Data | Used for native libp2p registry lookup streams and circuit relay connection endpoints. |
| **`45041`** | **UDP** | P2P QUIC Data | Used for high-performance QUIC multiplexing and P2P hole-punching fallback. |

> [!IMPORTANT]
> Both **TCP** and **UDP** traffic must be allowed on port `45041` for `go-libp2p` and QUIC v1 transport to work properly.

---

## 2. Persistent Storage Volumes

The platform generates and persists SQLite databases and cryptographic keys inside `/data`. 

### Why persistence is required:
1. **Cryptographic Identity (`/data/keys`)**: On first boot, the platform generates a unique Ed25519 and X25519 keypair. This keypair dictates the server's stable PeerID and `urn:hermes:platform:<fingerprint>`. Losing this folder on container restart will regenerate the identity, breaking active connections with client agents.
2. **SQLite Databases**: `/data/registry.db` and `/data/mq.db` contain the active registry entries and pending offline messages.

### Configuration:
Mount a host directory or persistent cloud storage volume (like AWS EBS, GCP Persistent Disk, or local volume) to `/data` inside the container.

---

## 3. Configuration Mapping (`config.yaml`)

Copy `config.example.yaml` to `config.yaml` and mount it to `/etc/platform/config.yaml`.

### Critical Settings for Cloud Deployment:

#### 1. Libp2p External Addresses
By default, the platform will listen on all interfaces. However, in cloud VPCs, the container only sees its private container IP. You **must** manually declare your server's public IP under `libp2p.external_addrs` so other clients on the internet know where to dial:

```yaml
libp2p:
  listen_addrs:
    - "/ip4/0.0.0.0/tcp/45041"
    - "/ip4/0.0.0.0/udp/45041/quic-v1"
  external_addrs:
    - "/ip4/<YOUR_PUBLIC_IP>/tcp/45041"
    - "/ip4/<YOUR_PUBLIC_IP>/udp/45041/quic-v1"
```

#### 2. Mode Configuration
Select your operation mode depending on local compliance guidelines:
* `"privacy"`: End-to-end encrypted envelope caching. The platform does not possess the keys to decrypt client envelopes.
* `"compliance"`: The platform acts as a decryption gateway for content scanning and archiving before forwarding.

---

## 4. Run Protocols

### Option A: Deployment via Docker Compose

Use the following `docker-compose.yml` configuration:

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
      - platform_data:/data
    restart: unless-stopped

volumes:
  platform_data:
```

### Option B: Deployment via Raw Docker Command

Run the following command on your cloud host (assuming `config.yaml` is prepared at `/srv/platform/config.yaml`):

```bash
docker run -d \
  --name agent-comm-platform \
  -p 8080:8080 \
  -p 45041:45041/tcp \
  -p 45041:45041/udp \
  -v /srv/platform/config.yaml:/etc/platform/config.yaml:ro \
  -v platform_data:/data \
  --restart unless-stopped \
  agent-comm-platform:latest
```

---

## 5. Production Optimization Notes (Dockerfile)

If building the image in cloud pipelines (e.g., GitHub Actions, AWS CodeBuild) outside of China, optimize the [Dockerfile](file:///c:/Users/zhang/Developer/agent-comm-platform/Dockerfile) by removing proxies and choosing appropriate runtime bases:

```dockerfile
# 1. Builder Stage
FROM golang:1.25.0 AS builder
WORKDIR /src
COPY go.mod go.sum ./
# Note: Remove GOPROXY if building in networks with direct internet access
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /platform ./cmd/platform

# 2. Runtime Stage
# Using distroless provides standard security/vulnerability protections
FROM gcr.io/distroless/static-debian12
COPY --from=builder /platform /platform
EXPOSE 45041 8080
ENTRYPOINT ["/platform", "-config", "/etc/platform/config.yaml"]
```
