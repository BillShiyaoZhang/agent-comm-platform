FROM golang:1.25.0 AS builder
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /src
COPY agent-comm/go.mod agent-comm/go.sum ./agent-comm/
COPY agent-comm-platform/go.mod agent-comm-platform/go.sum ./agent-comm-platform/

WORKDIR /src/agent-comm-platform
RUN go mod download

WORKDIR /src
COPY agent-comm ./agent-comm
COPY agent-comm-platform ./agent-comm-platform

WORKDIR /src/agent-comm-platform
RUN CGO_ENABLED=0 go build -o /platform ./cmd/platform

FROM alpine:3.21.3
RUN apk --no-cache add ca-certificates && \
    adduser -D -u 10001 platformuser && \
    mkdir -p /data /etc/platform && \
    chown -R platformuser:platformuser /data /etc/platform

WORKDIR /data
USER platformuser

COPY --from=builder /platform /usr/local/bin/platform
EXPOSE 45041 8080
ENTRYPOINT ["/usr/local/bin/platform", "-config", "/etc/platform/config.yaml"]
