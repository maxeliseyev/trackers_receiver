# Multi-stage build for trackers-receiver
# Stage 1: Build
FROM golang:1.25.3-alpine3.22 AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static binary
# -ldflags="-s -w" to strip debug info and reduce size
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION:-dev} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o receiver \
    ./cmd/receiver

# Stage 2: Runtime
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 tracker && \
    adduser -D -u 1000 -G tracker tracker

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/receiver /app/receiver

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Set ownership
RUN chown -R tracker:tracker /app

# Switch to non-root user
USER tracker

# Expose port
EXPOSE 36000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 36000 || exit 1

# Run the application
ENTRYPOINT ["/app/receiver"]
