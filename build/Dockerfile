
FROM registry.apk-group.net/mirror/golang:1.23 AS builder

ENV GOPROXY="https://swap-repository.apk-group.net/go,direct"
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build \
    -ldflags="-s -w -X main.version=$(date +%Y%m%d-%H%M%S)" \
    -trimpath \
    -o asset_discovery_backend \
    cmd/asset_discovery/main.go

FROM registry.apk-group.net/mirror/alpine:3.21.3 AS runtime

RUN apk add --no-cache \
    tzdata \
    iputils \
    nmap \
    openssl \
    ca-certificates && \
    update-ca-certificates

ENV TZ=Asia/Tehran

RUN mkdir -p \
    /etc/siem/certs \
    /etc/siem/asset_discovery \
    /usr/share/siem/asset_discovery

RUN openssl req -x509 -nodes -days 365 \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=SIEM/CN=localhost" \
    -newkey rsa:2048 \
    -keyout /etc/siem/certs/key.pem \
    -out /etc/siem/certs/cert.pem \
    -addext "subjectAltName=DNS:localhost,DNS:asset_discovery_backend,IP:127.0.0.1"

RUN addgroup -g 1001 -S siem && \
    adduser -u 1001 -S siem -G siem

WORKDIR /usr/share/siem/asset_discovery

COPY --from=builder --chown=siem:siem /app/asset_discovery_backend .

RUN chmod +x asset_discovery_backend && \
    chown -R siem:siem /etc/siem /usr/share/siem

USER siem

EXPOSE 2030

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:2030/health || exit 1

ENTRYPOINT ["./asset_discovery_backend"]
CMD ["--config", "/etc/siem/asset_discovery/config.yml"]