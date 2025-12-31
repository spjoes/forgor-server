# Forgor Coordination Server

A zero-knowledge, E2E encrypted coordination server for the Forgor password manager.

## Features

- **Zero-Knowledge Architecture**: Server never sees plaintext vault data - all keys are on-device only
- **Multi-Vault Support**: Host unlimited independent vaults (family, friends, etc.) with complete isolation
- **Multi-Device Sync**: Each vault can sync across multiple devices (laptop, phone, etc.)
- **Cryptographic Security**: Ed25519 signatures, X25519 key exchange, XChaCha20-Poly1305 encryption
- **Append-Only Membership Log**: Signed, tamper-evident membership changes
- **Production-Ready**: Rate limiting, request logging, graceful shutdown, SQLite with WAL

## Security Model

The coordination server is **untrusted**:
- All vault data is encrypted client-side before transmission
- Membership changes require Ed25519 signatures from the vault owner
- Device identity is cryptographically bound
- Event chains are validated with per-device counters and prev_hash
- Nonce tracking prevents replay attacks

> Please Note: "untrusted" does NOT mean unsafe. It only means that you are responsible for the coordination server you connect to. There is no official coordination server. Anyone can make a fake coordination server to hijack your data. Please be cautious and only connect to coordination servers you trust. It is recommended everyone host their own locally.

## Quick Start

```bash
# Build
go build -o forgor-server ./cmd/forgor-server

# Run with defaults (port 8080, SQLite at forgor.db)
./forgor-server

# Run with custom settings
./forgor-server -addr :9090 -db /path/to/forgor.db -log-level debug
```

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Bind address (host:port) |
| `-db` | `forgor.db` | SQLite database path |
| `-log-level` | `info` | Log level (debug, info, warn, error) |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FORGOR_BIND_ADDR` | `:8080` | Bind address |
| `FORGOR_DB_PATH` | `forgor.db` | Database path |
| `FORGOR_LOG_LEVEL` | `info` | Log level |
| `FORGOR_RATE_LIMIT_RPS` | `10.0` | Requests per second per IP |
| `FORGOR_RATE_LIMIT_BURST` | `50` | Rate limit burst size |
| `FORGOR_MAX_BODY_SIZE` | `10485760` | Max request body (10MB) |
| `FORGOR_READ_TIMEOUT_SEC` | `30` | HTTP read timeout |
| `FORGOR_WRITE_TIMEOUT_SEC` | `60` | HTTP write timeout |

## API Endpoints

### Device Registration
- `POST /v1/devices/register` - Register a device bundle
- `GET /v1/devices/{device_id}` - Get device bundle

### Invites
- `POST /v1/vaults/{vault_id}/invites` - Create an invite
- `GET /v1/invites?device_id=...` - List invites for a device
- `POST /v1/invites/{invite_id}/claim` - Claim an invite
- `GET /v1/invite_claims?created_by_device_id=...` - List claims for invites

### Membership
- `POST /v1/vaults/{vault_id}/member_events` - Create member_add/member_remove
- `GET /v1/vaults/{vault_id}/member_events?since_seq=...` - List member events
- `GET /v1/vaults/{vault_id}/members` - Get current members (derived view)

### Sync Events
- `POST /v1/vaults/{vault_id}/events` - Push encrypted event
- `GET /v1/vaults/{vault_id}/events?since_seq=...` - Pull events

### Key Rotation
- `POST /v1/vaults/{vault_id}/key_updates` - Create key update
- `GET /v1/key_updates?device_id=...` - List key updates for device
- `POST /v1/vaults/{vault_id}/key_update_acks` - Acknowledge key update

### Snapshots
- `POST /v1/vaults/{vault_id}/snapshots` - Create snapshot
- `GET /v1/vaults/{vault_id}/snapshots/latest` - Get latest snapshot

### Health
- `GET /health` - Health check