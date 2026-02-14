# starknet-keyring-proxy

Hardened signer service for Starknet agent session keys.

## Features

- Session transaction signing endpoint (`/v1/sign/session-transaction`)
- HMAC request authentication
- Per-client authorization (`client -> allowed keyIds`)
- Nonce replay protection with TTL
- `validUntil` max-window enforcement
- Chain-id allowlisting
- Optional multi-key routing via `keyId` (backward compatible default key)
- Selector denylist + session self-call block
- Structured JSON audit logs

## Development

```bash
cp .env.example .env
npm install
npm run dev
```

## Transport & mTLS

- `KEYRING_TRANSPORT=http` (default) for local development.
- `KEYRING_TRANSPORT=https` requires:
  - `KEYRING_TLS_CERT_PATH`
  - `KEYRING_TLS_KEY_PATH`
- `KEYRING_MTLS_REQUIRED=true` additionally requires:
  - `KEYRING_TLS_CA_PATH`

Production recommendation:

```bash
KEYRING_TRANSPORT=https
KEYRING_MTLS_REQUIRED=true
KEYRING_TLS_CERT_PATH=./certs/server.crt
KEYRING_TLS_KEY_PATH=./certs/server.key
KEYRING_TLS_CA_PATH=./certs/ca.crt
```

## Replay Protection Modes

- `memory` (default): single-instance replay protection (good for local/dev).
- `redis`: distributed replay protection for multi-instance production deployments.

When using Redis:

```bash
KEYRING_REPLAY_STORE=redis
KEYRING_REDIS_URL=redis://localhost:6379
KEYRING_REDIS_NONCE_PREFIX=starknet-keyring-proxy:nonce:
```

## Client AuthZ

Two modes are supported:

1. Backward-compatible single client:
- set `KEYRING_HMAC_SECRET`
- optional `KEYRING_DEFAULT_AUTH_CLIENT_ID` (defaults to `default`)

2. Multi-client (recommended):
- set `KEYRING_AUTH_CLIENTS_JSON`
- each client can have its own `hmacSecret` and `allowedKeyIds`

Example:

```bash
KEYRING_DEFAULT_AUTH_CLIENT_ID=mcp-default
KEYRING_AUTH_CLIENTS_JSON=[{"clientId":"mcp-default","hmacSecret":"not-a-real-hmac-secret-change-me-0001","allowedKeyIds":["default"]},{"clientId":"mcp-ops","hmacSecret":"not-a-real-hmac-secret-change-me-0002","allowedKeyIds":["ops"]}]
```

## API

- `GET /health` (no auth)
- `POST /v1/sign/session-transaction` (HMAC auth)
  - Optional auth header: `X-Keyring-Client-Id` (defaults to configured default client)
  - Optional request field: `keyId`
  - If omitted, proxy uses `KEYRING_DEFAULT_KEY_ID`

See `docs/api-spec.yaml` for request/response schema.

## Security model

- Private keys remain in this process only; clients submit unsigned payloads.
- Requests require HMAC + nonce + timestamp.
- Replay defense is one-time nonce consumption (`memory` or `redis` backend).
- Requests are bounded by configured chain ids and `validUntil` horizon.
- Signer rejects owner/admin-like selectors and self-target calls.
