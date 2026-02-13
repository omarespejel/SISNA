# starknet-keyring-proxy

Hardened signer service for Starknet agent session keys.

## Features

- Session transaction signing endpoint (`/v1/sign/session-transaction`)
- HMAC request authentication
- Nonce replay protection with TTL
- Selector denylist + session self-call block
- Structured JSON audit logs

## Development

```bash
cp .env.example .env
npm install
npm run dev
```

## API

- `GET /health` (no auth)
- `POST /v1/sign/session-transaction` (HMAC auth)

See `docs/api-spec.yaml` for request/response schema.

## Security model

- Private keys remain in this process only; clients submit unsigned payloads.
- Requests require HMAC + nonce + timestamp.
- Signer rejects owner/admin-like selectors and self-target calls.
