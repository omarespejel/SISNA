# starknet-keyring-proxy

Hardened signer service for Starknet agent session keys.

## Features

- Session transaction signing endpoint (`/v1/sign/session-transaction`)
- HMAC request authentication
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

## Replay Protection Modes

- `memory` (default): single-instance replay protection (good for local/dev).
- `redis`: distributed replay protection for multi-instance production deployments.

When using Redis:

```bash
KEYRING_REPLAY_STORE=redis
KEYRING_REDIS_URL=redis://localhost:6379
KEYRING_REDIS_NONCE_PREFIX=starknet-keyring-proxy:nonce:
```

## API

- `GET /health` (no auth)
- `POST /v1/sign/session-transaction` (HMAC auth)
  - Optional request field: `keyId`
  - If omitted, proxy uses `KEYRING_DEFAULT_KEY_ID`

See `docs/api-spec.yaml` for request/response schema.

## Security model

- Private keys remain in this process only; clients submit unsigned payloads.
- Requests require HMAC + nonce + timestamp.
- Replay defense is one-time nonce consumption (`memory` or `redis` backend).
- Requests are bounded by configured chain ids and `validUntil` horizon.
- Signer rejects owner/admin-like selectors and self-target calls.
