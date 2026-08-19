# syntax=docker/dockerfile:1

FROM golang:1.21-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/oidc-reverse-proxy .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/oidc-reverse-proxy /oidc-reverse-proxy

# The app reads config.json (and any cert/key files it references) from the
# working directory, so mount them into /app, e.g.:
#   docker run -v $(pwd)/config.json:/app/config.json ...
WORKDIR /app

ENTRYPOINT ["/oidc-reverse-proxy"]
