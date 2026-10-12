# Trackers Receiver

TCP server that receives telemetry from vehicle trackers over EGTS (GOST R 54619-2011),
converts navigation records to MessagePack documents and pushes them to Redis lists.

## How it works

- Each tracker connection is served by its own goroutine for as long as the tracker stays
  connected. Connections beyond `SERVER_MAX_CONNECTIONS` are closed right after accept.
- Every packet is checked against its header CRC8 and body CRC16 and acknowledged with
  `EGTS_PT_RESPONSE`.
- Records containing `SR_POS_DATA` become documents; `SR_EXT_POS_DATA`, `SR_STATE_DATA`,
  `SR_LIQUID_LEVEL_SENSOR` and `SR_ABS_CNTR_DATA` in the same record are merged in.
  `SR_TERM_IDENTITY` provides the IMEI/IMSI.
- Each document is `LPUSH`ed to both the charger and fasttrack queues, which are trimmed to
  their configured maximum length. The format matches the previous Python receiver.

- New connections are rate limited per source IP, and an IP that keeps sending malformed
  data is blocked, with the block doubling on each repeat (up to 24 h). An IP that sent a
  valid packet within the last hour is exempt: carrier NAT addresses and retranslators carry
  many trackers, sometimes next to a device sending garbage. If the receiver sits behind a
  load balancer, add its address to `RATE_LIMIT_WHITELIST`.

Not implemented yet: routed headers (`RTE=1`), encryption and compression, structured
logging, a metrics endpoint.

## Configuration

Environment variables (a `.env` file is loaded if present, see `.env.example`):

| Variable | Default | |
|---|---|---|
| `SERVER_PORT` | `36000` | |
| `SERVER_READ_TIMEOUT` | `600` | seconds to wait for the next packet |
| `SERVER_WRITE_TIMEOUT` | `30` | seconds |
| `SERVER_MAX_CONNECTIONS` | `10000` | concurrent tracker connections; needs a matching `nofile` limit |
| `REDIS_HOST` | `localhost` | |
| `REDIS_PORT` | `6379` | |
| `REDIS_PASSWORD` | | |
| `REDIS_DB` | `0` | |
| `REDIS_POOL_SIZE` | `100` | |
| `REDIS_MAX_RETRIES` | `3` | |
| `QUEUE_CHARGER_NAME` | `charger` | |
| `QUEUE_CHARGER_MAX_LEN` | `2999999` | |
| `QUEUE_FASTTRACK_NAME` | `fasttrack` | |
| `QUEUE_FASTTRACK_MAX_LEN` | `2999999` | |
| `RATE_LIMIT_ENABLED` | `true` | |
| `RATE_LIMIT_MAX_PER_WINDOW` | `300` | new connections per unknown IP per window |
| `RATE_LIMIT_WINDOW` | `10` | seconds |
| `RATE_LIMIT_BLOCK_DURATION` | `60` | seconds, first block |
| `RATE_LIMIT_WHITELIST` | `127.0.0.1,::1` | comma-separated IPs that are never limited |

## Running

Requires Go 1.25 and Redis.

```bash
make test               # unit tests
make test-integration   # needs Redis on localhost:6379
make build && ./bin/receiver
make docker-up          # receiver via docker-compose (Redis is external)
```
