# SISNA

Hardened signer boundary for Starknet agent session keys.

SISNA is a reference implementation of a simple idea:

**Don't let your agent hold signing keys. Isolate signing behind a hardened boundary with strict policy, auth, and auditability.**

If prompt-injection hits your agent runtime, the signer boundary should still refuse unauthorized or malformed execution.

This repo exists to make that concrete: a security-first signer service you can run, verify, and integrate.

## Send Your Agent

SISNA follows a GitHub-native, agentic workflow inspired by Starkclaw's BYOA model.

**Give your AI coding agent this single instruction:**

> Clone https://github.com/omarespejel/SISNA, read BYOA.md, and execute the protocol. You are an OpenClaw agent.

That's it. The agent will self-identify, claim scoped issues, open focused PRs, review peers, and coordinate through GitHub.

Works with Claude Code, Codex, Cursor, or any agent that can run `gh` workflows.

## What This Service Does

- Holds Starknet session signing keys outside MCP/agent runtime
- Signs session transactions through a hardened API boundary
- Enforces auth, replay protection, rate limiting, and policy checks before signing
- Emits auditable signing events with trace context

## What This Service Does Not Do (Yet)

- Full SISNA auth protocol (challenge/verification receipts end-to-end)
- On-chain identity registry orchestration on its own

## Features

- Session transaction signing endpoint (`POST /v1/sign/session-transaction`)
- HMAC request authentication (`X-Keyring-*` headers)
- Per-client authorization (`clientId -> allowed keyIds`)
- Nonce replay protection with TTL (memory or Redis backend)
- Configurable rate limiting (memory or Redis)
- `validUntil` max-window enforcement
- Chain-id allowlisting
- Optional multi-key routing via `keyId` (with default key fallback)
- Selector denylist + session self-call block
- Inbound/outbound leak scanner (`block` or `warn`)
- Structured JSON logs for auditability

## Security Model (No Hand-Waving)

SISNA is a defense-in-depth boundary:

1. **Key isolation**
   - private keys stay in signer process only
   - clients send unsigned payloads
2. **Request authentication**
   - HMAC + timestamp + nonce
   - optional client ID routing and per-client key authorization
3. **Replay resistance**
   - nonce one-time consumption with TTL
   - memory backend for local/dev, Redis backend for distributed deployments
4. **Execution policy enforcement**
   - chain-id allowlist
   - `validUntil` horizon check
   - denied selectors and self-target protections
5. **Operational abuse controls**
   - request rate limits
   - leak scanner on inbound/outbound payload surfaces

The point is not "the agent is trustworthy".
The point is "the signer boundary is strict enough to reject unsafe requests even when upstream logic is wrong".

## Development

```bash
cp .env.example .env
npm install
npm run dev
```

Run tests:

```bash
npm test
```

Build:

```bash
npm run build
npm start
```

## Transport and mTLS

- `KEYRING_TRANSPORT=http` for local development
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
# Explicit acknowledgement for current in-process key custody mode.
# Keep false by default and only set true when you accept this risk.
KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION=true
```

Production guard:
- `NODE_ENV=production` fails startup unless
  `KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION=true` is explicitly set.
- This guard prevents silently running with in-process private keys.
- Target end-state is external KMS/HSM-backed signing mode.

## Replay Protection Modes

- `memory` (default): single-instance replay protection (good for local/dev)
- `redis`: distributed replay protection for multi-instance production deployments

Redis example:

```bash
KEYRING_REPLAY_STORE=redis
KEYRING_REDIS_URL=redis://localhost:6379
KEYRING_REDIS_NONCE_PREFIX=starknet-keyring-proxy:nonce:
```

## Rate Limiting

```bash
KEYRING_RATE_LIMIT_ENABLED=true
KEYRING_RATE_LIMIT_BACKEND=redis
KEYRING_RATE_LIMIT_WINDOW_MS=60000
KEYRING_RATE_LIMIT_MAX_REQUESTS=120
KEYRING_REDIS_RATE_LIMIT_PREFIX=starknet-keyring-proxy:ratelimit:
```

Behavior:
- keyed by `clientId + accountAddress + keyId`
- over-budget requests return `429`
- response includes `x-ratelimit-remaining` and `x-ratelimit-reset-ms`

## Leak Scanner

```bash
KEYRING_LEAK_SCANNER_ENABLED=true
KEYRING_LEAK_SCANNER_ACTION=block
```

Actions:
- `block`: fail request/response when patterns are detected
- `warn`: log only

## Client AuthZ Modes

1. Backward-compatible single client:
- set `KEYRING_HMAC_SECRET`
- optional `KEYRING_DEFAULT_AUTH_CLIENT_ID` (defaults to `default`)

2. Multi-client (recommended):
- set `KEYRING_AUTH_CLIENTS_JSON`
- each client can have distinct `hmacSecret` and `allowedKeyIds`

Example:

```bash
KEYRING_DEFAULT_AUTH_CLIENT_ID=mcp-default
KEYRING_AUTH_CLIENTS_JSON=[{"clientId":"mcp-default","hmacSecret":"replace-me-0001","allowedKeyIds":["default"]},{"clientId":"mcp-ops","hmacSecret":"replace-me-0002","allowedKeyIds":["ops"]}]
```

## API

- `GET /health` (no auth)
- `POST /v1/sign/session-transaction` (HMAC auth)
  - optional header: `X-Keyring-Client-Id`
  - optional request field: `keyId`

See `docs/api-spec.yaml` for schema.

## Connected Repositories

SISNA is part of a multi-repo stack:

1. [`keep-starknet-strange/starkclaw`](https://github.com/keep-starknet-strange/starkclaw)
   - mobile/runtime integration client
   - consumes SISNA signer path via `apps/mobile/lib/signer/**`

2. [`keep-starknet-strange/starknet-agentic`](https://github.com/keep-starknet-strange/starknet-agentic)
   - canonical session-account contract lineage
   - contract semantics that signer payloads must respect

Integration rule of thumb:
- API/policy changes in SISNA must be mirrored in Starkclaw signer client and verified against session-account constraints.

## Repo Layout

- `src/`: signer service implementation
- `test/`: policy/auth/transport tests
- `docs/api-spec.yaml`: API contract
- `scripts/security/audit-gate.mjs`: dependency audit gating logic
- `security/`: allowlists and security policy artifacts
- `BYOA.md`: agent coordination protocol
- `agents.md`: role/ownership guidance for multi-agent work

## Agentic-Native Development

This repository is structured for high-signal, reviewable agent collaboration:

- GitHub issues/PRs are the coordination bus
- small vertical slices over giant refactors
- tests first for security-sensitive behavior
- explicit blocker escalation with trade-offs

Start with `BYOA.md` and `agents.md`.

## Contributing

1. Pick or open a focused issue
2. Keep PRs small and verifiable
3. Run `npm test` before opening PR
4. Never log or commit secrets

## Security

This is security-sensitive software.

- Do not run with real production secrets until your deployment posture is validated
- Treat signer boundary failures as high-severity incidents
- Report vulnerabilities privately and responsibly

## License

MIT. See `LICENSE`.
