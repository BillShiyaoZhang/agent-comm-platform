FROM golang:1.25.0 AS builder
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /platform ./cmd/platform

FROM scratch
COPY --from=builder /platform /platform
EXPOSE 45041 8080
ENTRYPOINT ["/platform", "-config", "/etc/platform/config.yaml"]
