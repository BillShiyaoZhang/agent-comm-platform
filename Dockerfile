FROM golang:1.25.0 AS builder
ENV GOPROXY=https://goproxy.cn,direct
ENV GOTOOLCHAIN=auto
WORKDIR /src/agent-comm-platform

# Copy the go.mod/sum files to their correct relative paths to allow caching of dependency downloads
COPY agent-comm/go.mod agent-comm/go.sum ./agent-comm/
COPY go.mod go.sum ./

RUN go mod download

# Copy the actual source files
COPY agent-comm ./agent-comm
COPY . ./

RUN CGO_ENABLED=0 go build -o /platform ./cmd/platform

FROM alpine:3.21.3
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk --no-cache add ca-certificates && \
    adduser -D -u 10001 platformuser && \
    mkdir -p /data /etc/platform && \
    chown -R platformuser:platformuser /data /etc/platform

WORKDIR /data
USER platformuser

COPY --from=builder /platform /usr/local/bin/platform
EXPOSE 45041 8080
ENTRYPOINT ["/usr/local/bin/platform", "-config", "/etc/platform/config.yaml"]
