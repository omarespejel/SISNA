# SISNA Signer

Hardened signer boundary for Starknet agent session keys.

This repository is the signing service component of the SISNA stack (Sign In with Starknet Agent).

## Scope

What this service does:
- Holds Starknet session signing keys outside the MCP/agent runtime
- Signs session transactions via a hardened API boundary
- Enforces auth/policy/replay controls before signing
- Produces auditable signing events

What this service does not do (yet):
- Full SISNA auth flow (nonce challenge, verification receipts, full server auth protocol)
- On-chain identity registry orchestration by itself

## Features

- Session transaction signing endpoint (`/v1/sign/session-transaction`)
- HMAC request authentication
- Per-client authorization (`client -> allowed keyIds`)
- Nonce replay protection with TTL
- Configurable rate limiting (memory or Redis)
- `validUntil` max-window enforcement
- Chain-id allowlisting
- Optional multi-key routing via `keyId` (backward compatible default key)
- Selector denylist + session self-call block
- Inbound/outbound leak scanner (`block` or `warn`)
- Structured JSON audit logs

## Development

```bash
cp .env.example .env
npm install
npm run dev
```

`NODE_ENV=production` now enforces:
- `KEYRING_TRANSPORT=https`
- `KEYRING_MTLS_REQUIRED=true`

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
- Prefix defaults still use `starknet-keyring-proxy:*` for backward compatibility and can be overridden.

When using Redis:

```bash
KEYRING_REPLAY_STORE=redis
KEYRING_REDIS_URL=redis://localhost:6379
KEYRING_REDIS_NONCE_PREFIX=starknet-keyring-proxy:nonce:
```

## Rate Limiting

Use rate limiting before production rollout.

```bash
KEYRING_RATE_LIMIT_ENABLED=true
KEYRING_RATE_LIMIT_BACKEND=redis
KEYRING_RATE_LIMIT_WINDOW_MS=60000
KEYRING_RATE_LIMIT_MAX_REQUESTS=120
KEYRING_REDIS_RATE_LIMIT_PREFIX=starknet-keyring-proxy:ratelimit:
```

Behavior:
- Keyed by `clientId + accountAddress + keyId`
- Exceeds budget returns `429`
- Response includes `x-ratelimit-remaining` and `x-ratelimit-reset-ms`
- Redis key prefix is configurable via `KEYRING_REDIS_RATE_LIMIT_PREFIX`

## Leak Scanner

Leak scanner detects common secret-exfiltration payloads at proxy boundary.

```bash
KEYRING_LEAK_SCANNER_ENABLED=true
KEYRING_LEAK_SCANNER_ACTION=block
```

Actions:
- `block`: fail request/response when patterns are detected
- `warn`: log only

Patterns include:
- `STARKNET_PRIVATE_KEY`, `SESSION_PRIVATE_KEY`, `KEYRING_HMAC_SECRET`
- JSON/kv private key fields
- PEM private key markers

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
KEYRING_AUTH_CLIENTS_JSON=[{"clientId":"mcp-default","hmacSecret":"0123456789abcdef0123456789abcdef","allowedKeyIds":["default"]},{"clientId":"mcp-ops","hmacSecret":"abcdef0123456789abcdef0123456789","allowedKeyIds":["ops"]}]
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
- Optional rate limiting and leak scanning provide additional abuse resistance.

## Operational runbook

- mTLS cert rotation/rollback: `docs/MTLS_RUNBOOK.md`
- signer security proof demo: `docs/SECURITY_PROOF_DEMO.md`

## Security Proof Demo

Run the reproducible proof script:

```bash
chmod +x demo/run-security-proof.sh
./demo/run-security-proof.sh
```

It generates artifacts under `demo/artifacts/<timestamp>/` with:

- happy-path signature proof
- replay rejection proof
- selector-deny policy proof

Live Sepolia e2e proof (request id -> signer log -> tx hash):

```bash
export DEMO_SEPOLIA_RPC_URL=...
export DEMO_ACCOUNT_ADDRESS=0x...
export DEMO_TOKEN_ADDRESS=0x...        # token contract with transfer(recipient, u256)
export DEMO_RECIPIENT_ADDRESS=0x...
export DEMO_AMOUNT_RAW=1
export SESSION_PRIVATE_KEY=0x...       # session key registered on DEMO_ACCOUNT_ADDRESS
export KEYRING_HMAC_SECRET=0123456789abcdef0123456789abcdef

chmod +x demo/run-e2e-sepolia-proof.sh
./demo/run-e2e-sepolia-proof.sh
```

The script now runs a mandatory preflight gate first and emits:
- `preflight-sepolia-readiness.json`
- `preflight-sepolia-readiness.txt`

Preflight verifies:
- Sepolia chain id
- account/token deployment visibility
- session-account entrypoint presence (`compute_session_message_hash`)
- fee-token minimum balance (default `STRK`, configurable)

MCP production guard proof (from sibling `starknet-agentic` repo):

```bash
chmod +x demo/mcp-prod-guard.sh
./demo/mcp-prod-guard.sh
```
