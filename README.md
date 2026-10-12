# Trackers Receiver

TCP server that receives telemetry from vehicle trackers over EGTS (GOST R 54619-2011),
converts navigation records to MessagePack documents and pushes them to Redis lists.

## How it works

- Each tracker connection is served by its own goroutine for as long as the tracker stays
  connected. Connections beyond `SERVER_MAX_CONNECTIONS` are closed right after accept.
- Every packet is checked against its header CRC8 and body CRC16 and acknowledged with
  `EGTS_PT_RESPONSE`.
- Every record is confirmed. Each `SR_POS_DATA` becomes a document; the `SR_EXT_POS_DATA`,
  `SR_STATE_DATA`, `SR_AD_SENSORS_DATA`, `SR_LIQUID_LEVEL_SENSOR`, `SR_ABS_AN_SENS_DATA` and
  `SR_ABS_CNTR_DATA` that follow it are merged in.
- `SR_TERM_IDENTITY` provides the IMEI/IMSI and is answered with `EGTS_SR_RESULT_CODE`;
  terminals are not authenticated.
- Each document is `LPUSH`ed to both the charger and fasttrack queues, which are trimmed to
  their configured maximum length.

### Compatibility with the Python receiver

Consumers decode the documents with the Python receiver's `utils/pack.py`, so the documents
reproduce its output key for key, including its quirks: dates as `{"__dt__": isoformat}`,
the misspelt `det_dtatus`, `level_l` as the raw value times 10, `"1"` instead of the value
for `ans_<n>`, raw IMEI/IMSI bytes. `make test-parity` runs the Python receiver's code on
the same packets and compares the decoded documents.

Where the Python receiver contradicts GOST, this one follows GOST:

- latitude and longitude are negative in the southern and western hemispheres (`LAHS`, `LOHS`);
- `RDF` of `SR_LIQUID_LEVEL_SENSOR` is bit 3, not bit 4;
- `SR_EXT_POS_DATA` and `SR_STATE_DATA` sent before the record's first `SR_POS_DATA` are
  kept instead of being dropped;
- packets with CRC errors are skipped instead of processed, so the tracker resends them.

- New connections are rate limited per source IP, and an IP that keeps sending malformed
  data is blocked, with the block doubling on each repeat (up to 24 h). An IP that sent a
  valid packet within the last hour is exempt: carrier NAT addresses and retranslators carry
  many trackers, sometimes next to a device sending garbage. Behind HAProxy set
  `USE_HAPROXY=true`: limits then apply to the client address from the PROXY header.

Not implemented yet: routed headers (`RTE=1`), encryption and compression, structured
logging, a metrics endpoint.

## Configuration

Environment variables (a `.env` file is loaded if present, see `.env.example`). Variables
shared with the Python receiver keep its names and defaults, so its deployments can switch
images without changes.

| Variable | Default | |
|---|---|---|
| `SERVER_PORT` | `36000` | |
| `USE_HAPROXY` | `false` | expect a PROXY protocol v1 header (HAProxy `send-proxy`) on every connection |
| `CONNECTION_TIMEOUT` | `600` | seconds to wait for the next packet |
| `SERVER_WRITE_TIMEOUT` | `30` | seconds |
| `SERVER_MAX_CONNECTIONS` | `10000` | concurrent tracker connections; needs a matching `nofile` limit |
| `REDIS_HOST` | `localhost` | |
| `REDIS_PORT` | `6379` | |
| `REDIS_PASSWORD` | | |
| `REDIS_DB` | `0` | |
| `REDIS_POOL_SIZE` | `100` | |
| `REDIS_MAX_RETRIES` | `3` | |
| `CHARGER_QUEUE` | `charger` | |
| `CHARGER_QUEUE_MAX_LEN` | `99999` | |
| `FASTTRACK_QUEUE` | `fasttrack` | |
| `FASTTRACK_QUEUE_MAX_LEN` | `99999` | |
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
PYTHON_RECEIVER_SRC=../gazpromneft_receiver/src make test-parity
make build && ./bin/receiver
make docker-up          # receiver via docker-compose (Redis is external)
```
