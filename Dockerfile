FROM golang:1.25.3-alpine3.22 AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o receiver ./cmd/receiver

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 tracker && \
    adduser -D -u 1000 -G tracker tracker

WORKDIR /app
COPY --from=builder --chown=tracker:tracker /build/receiver /app/receiver

USER tracker
EXPOSE 36000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 36000 || exit 1

ENTRYPOINT ["/app/receiver"]
