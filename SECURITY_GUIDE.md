# Agent Comm Platform 安全加固与 HTTPS 配置指南

本指南旨在为您提供一步步在阿里云 ECS 上部署 HTTPS 以及保障 **Agent Comm Platform** 平台安全的实施步骤。您可以根据开发和运维进度，逐项进行配置。

---

## 1. 阿里云安全组与 SSH 网络层加固

首先在网络边界上收紧权限，只暴露必要的服务端口。

### 1.1 阿里云安全组规则调整
登录阿里云 ECS 控制台，进入实例关联的**安全组**，修改**入方向**规则：

| 动作 | 协议类型 | 端口范围 | 授权对象 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| **允许** | TCP | `80` | `0.0.0.0/0` | HTTP 基础端口（用于 Let's Encrypt 证书申请挑战） |
| **允许** | TCP | `443` | `0.0.0.0/0` | HTTPS 流量入口（核心 Web 服务） |
| **允许** | TCP | `45041` | `0.0.0.0/0` | libp2p 基础流通信 |
| **允许** | UDP | `45041` | `0.0.0.0/0` | libp2p QUIC/UDP 打洞通信 |
| **删除/限制** | TCP | `8080` | `0.0.0.0/0` | **删除此规则**。不再允许公网直接访问裸端口 `8080` |

> [!WARNING]
> 一旦删除了安全组里的 `8080` 规则，公网上的任何请求都只能通过 `80` 或 `443` 并经由反向代理转发给 Go 服务，从而强制使用了 HTTPS。

### 1.2 SSH 登录安全加固
ECS 的 22 端口是互联网扫描器最常攻击的目标。建议进行以下加固：
1. **强制使用密钥对登录**：在阿里云控制台为 ECS 绑定 SSH 密钥对，并禁用密码登录。
2. **禁用密码登录**（修改主机 `/etc/ssh/sshd_config`）：
   ```bash
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```
   修改后执行 `systemctl restart sshd` 重启 SSH 服务。
3. **更改默认 SSH 端口**（可选）：将 22 端口改为非常规端口（如 22022），并在安全组中仅限您的固定公网 IP 访问该端口。

---

## 2. 部署 Caddy 实现自动化 HTTPS (推荐)

Caddy 会监听 80 和 443 端口，当收到指向 `agent-communication.online` 的请求时，它会自动向 Let's Encrypt 申请 SSL 证书，并负责之后的自动续期，无需手动干预。

### 2.1 创建 `Caddyfile`
在您的部署目录（如 `/data`）下，新建一个名为 `Caddyfile` 的文件：

```caddy
# /data/Caddyfile
agent-communication.online {
    # 开启 gzip / zstd 压缩，优化传输性能
    encode gzip zstd

    # 将所有 HTTPS 流量代理到内部的 platform 容器的 8080 端口
    reverse_proxy platform:8080

    # 还可以加入安全响应头（可选）
    header {
        # 启用 HSTS (强制客户端使用 HTTPS)
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        # 防框架劫持
        X-Frame-Options "DENY"
        # 防 XSS 嗅探
        X-Content-Type-Options "nosniff"
        # 隐藏 Server 标识
        -Server
    }
}
```

### 2.2 更新 `docker-compose.yml`
将您的 `docker-compose.yml` 修改为以下内容。更新后的配置中，`platform` 服务移除了对宿主机的 `8080` 端口映射，仅通过 `expose` 让 Caddy 容器在同一个 Docker 网络内部访问。

```yaml
# /data/docker-compose.yml
services:
  platform:
    image: agent-comm-platform:latest
    build:
      context: .
      dockerfile: Dockerfile
    # 不再将 8080 映射 to 主机的 0.0.0.0:8080
    expose:
      - "8080"
    ports:
      - "45041:45041"
      - "45041:45041/udp"
    volumes:
      - ./config.yaml:/etc/platform/config.yaml:ro
      - ./keys:/data/keys
      - .:/data
    restart: unless-stopped

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp" # 启用 HTTP/3 支持
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - platform

volumes:
  platform_data:
  caddy_data:
  caddy_config:
```

---

## 3. 主机与 Docker 安全加固

### 3.1 容器以非 root 用户运行
默认情况下，Docker 容器内的进程以 `root` 权限运行。如果 Go 程序存在漏洞，攻击者可能借此拿到 ECS 宿主机的权限。
建议在 `Dockerfile` 中将运行用户切换为非 root 用户：

```dockerfile
# 示例 Dockerfile 优化片段
FROM alpine:latest

# 创建一个非特权用户 platformuser
RUN adduser -D -u 10001 platformuser

# 复制编译好的二进制文件...
COPY --from=builder /app/platform /usr/local/bin/platform

# 修改挂载点和文件的所有者
WORKDIR /data
RUN chown -R platformuser:platformuser /data

# 切换为非 root 用户运行
USER platformuser

ENTRYPOINT ["/usr/local/bin/platform"]
```

### 3.2 限制容器资源使用
为防止因异常流量或内存泄漏导致整个 ECS 宿主机死机，在 `docker-compose.yml` 中可以限制内存和 CPU：

```yaml
  platform:
    # ... 其他配置 ...
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M
```

---

## 4. 应用代码层安全加固 (Go Web API)

### 4.1 引入 HTTP 限流器 (Rate Limiter)
防止恶意客户端通过高频的 REST 请求压垮您的 Registry 存储或 MQ 邮箱。
您可以在 `internal/api/server.go` 中封装限流中间件。

**Go 代码限流实现方案：**
```go
import (
	"golang.org/x/time/rate"
	"net/http"
	"sync"
)

type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	return limiter
}

// limitMiddleware 限制每个 IP 每秒最多请求数
func limitMiddleware(limiter *IPRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		
		// 如果使用了反向代理（如 Caddy），需要获取真实客户端 IP
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		}

		if !limiter.GetLimiter(ip).Allow() {
			http.Error(w, `{"error":"Too Many Requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

### 4.2 认证与内容验证
- **节点签名校验**：由于 libp2p 协议原生支持非对称密钥体系，您可以在 HTTP 路由层 design 一个验证机制，要求 Agent 在 POST 注册表单或发送信件时，将 Payload 使用自身的私钥签名，并在 `Authorization` 响应头中附带签名。Go 接收端提取公钥并验签后才予以放行，防止身份假冒。

---

## 5. 数据自动备份与容灾

您的核心数据保存在 `/data` 下（包括 SQLite 数据库、Agent 私钥等）。数据丢失是最大的安全隐患。

### 5.1 阿里云云盘自动快照
1. 打开 **阿里云 ECS 控制台**。
2. 在左侧菜单栏中选择 **存储与快照** > **快照** > **自动快照策略**。
3. 创建一个每日凌晨执行的快照策略，保留时间设置为 7 天至 30 天。
4. 将该快照策略**绑定**到挂载至 `/data` 目录的云盘上。

---

## 6. 后续检查清单 (Checklist)

在配置完成后，可以通过以下手段进行自测：
- [ ] 尝试在本地浏览器或命令行访问 `http://agent-communication.online:8080`，确认已被安全组拦截，无法打开。
- [ ] 尝试访问 `https://agent-communication.online/healthz`，确认能顺利看到 `{"status":"ok"}`，且浏览器地址栏有小锁标志（SSL 证书生效）。
- [ ] 用命令测试 HTTP 是否自动重定向到了 HTTPS：`curl -I http://agent-communication.online`，应返回 `301 Moved Permanently` 到 `https://...`。
- [ ] 查看 Caddy 日志以确保证书申请正常：`docker-compose logs caddy`。
