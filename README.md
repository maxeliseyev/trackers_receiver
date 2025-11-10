# Trackers Receiver

High-performance TCP server for receiving GPS/GLONASS tracker data via EGTS protocol.

**Status:** 🟢 Production Ready (Redis) | **Progress:** 85% Complete

## Overview

This server receives telemetry data from vehicle tracking devices using the **EGTS (Era Glonass Telematics Standard)** protocol. It parses binary packets, validates data integrity using CRC checksums, and stores the data in Redis for further processing.

**Target Capacity:** 100,000+ concurrent connections

## Features

### ✅ Implemented

- **EGTS Protocol Support**: Full implementation of EGTS packet parsing
  - Transport Layer Header parsing with CRC8 validation
  - Service Layer Records with CRC16 validation
  - All standard subrecord types (position, sensors, state, etc.)
  - Response packet generation

- **High Performance Architecture**:
  - Worker pool for connection management (CPU * 2 workers)
  - Buffered job queue (10k capacity)
  - Backpressure handling
  - Redis integration with connection pooling
  - MessagePack serialization

- **Production Features**:
  - ✅ Graceful shutdown (SIGINT/SIGTERM)
  - ✅ Rate limiting with IP blocking
  - ✅ Exponential backoff for malicious IPs
  - ✅ Whitelist support
  - ✅ Comprehensive metrics
  - ✅ Health checks
  - ✅ Thread-safe operations

### 🚧 In Progress

- Integration tests
- Structured logging (zerolog/slog)
- Prometheus metrics endpoint

## Quick Start

### Prerequisites

- Go 1.21+
- Redis 6.0+

### Configuration

Set environment variables:

```bash
export SERVER_PORT=6000
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_DB=0
export REDIS_QUEUE=tracker_data
```

### Running

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o bin/receiver ./cmd/receiver

# Run
./bin/receiver
```

## Documentation

- **[DOCS.md](DOCS.md)** - Complete documentation index
- **[PROJECT_STATUS.md](PROJECT_STATUS.md)** - Current status, progress, and roadmap ⭐
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Architecture and migration strategy

## Supported Protocols

### Current: EGTS (In Development)

EGTS (Era Glonass Telematics Standard) is a Russian federal standard for vehicle tracking and telematics. This server implements:

- **Packet Types**: APPDATA, RESPONSE, ECHO
- **Position Data**: GPS coordinates, speed, direction, odometer
- **Extended Data**: Satellite info (HDOP, VDOP, PDOP), number of satellites
- **Sensors**: Digital/analog sensors, liquid level sensors, counters
- **State Data**: Vehicle state, motion sensor, power supply status

### Future Protocols

The following protocols are planned for future implementation **after** EGTS is fully completed and tested:

- **Galileosky** - Binary protocol with tag-based structure
- **Teltonika** - AVL Data protocol (Codec 8/8 Extended)
- **Wialon IPS** - Text-based protocol
- **H02** - Simple text protocol for Chinese trackers

See [FUTURE_PROTOCOLS.md](FUTURE_PROTOCOLS.md) for detailed specifications and implementation plans.
