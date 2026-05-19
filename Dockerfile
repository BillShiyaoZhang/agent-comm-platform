FROM golang:1.22 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /platform ./cmd/platform

FROM gcr.io/distroless/static-debian12
COPY --from=builder /platform /platform
EXPOSE 45041 8080
ENTRYPOINT ["/platform", "-config", "/etc/platform/config.yaml"]
