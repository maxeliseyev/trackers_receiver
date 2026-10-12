# Trackers Receiver

TCP server that receives telemetry from vehicle trackers over EGTS (GOST R 54619-2011),
converts navigation records to MessagePack documents and pushes them to Redis lists.

## How it works

- Each accepted connection is queued and served by a fixed pool of workers
  (`2 × CPU`, between 4 and 32). A worker owns its connection until the tracker disconnects.
- Every packet is checked against its header CRC8 and body CRC16 and acknowledged with
  `EGTS_PT_RESPONSE`.
- Records containing `SR_POS_DATA` become documents; `SR_EXT_POS_DATA`, `SR_STATE_DATA`,
  `SR_LIQUID_LEVEL_SENSOR` and `SR_ABS_CNTR_DATA` in the same record are merged in.
  `SR_TERM_IDENTITY` provides the IMEI/IMSI.
- Each document is `LPUSH`ed to both the charger and fasttrack queues, which are trimmed to
  their configured maximum length. The format matches the previous Python receiver.

Not implemented yet: routed headers (`RTE=1`), encryption and compression, structured
logging, a metrics endpoint. A per-IP rate limiter exists in `internal/server` but is not
enabled in `cmd/receiver`.

## Configuration

Environment variables (a `.env` file is loaded if present, see `.env.example`):

| Variable | Default | |
|---|---|---|
| `SERVER_PORT` | `36000` | |
| `SERVER_READ_TIMEOUT` | `600` | seconds to wait for the next packet |
| `SERVER_WRITE_TIMEOUT` | `30` | seconds |
| `SERVER_MAX_CONNECTIONS` | `10000` | connections that may wait for a free worker |
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

## Running

Requires Go 1.25 and Redis.

```bash
make test               # unit tests
make test-integration   # needs Redis on localhost:6379
make build && ./bin/receiver
make docker-up          # receiver via docker-compose (Redis is external)
```
