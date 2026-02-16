# Security Backlog

This file tracks the remaining hardening work after the current CI/auth/policy upgrades.

## Open Critical Item

1. External key custody backend (KMS/HSM or remote signer boundary)
   - Canonical issue: [#20](https://github.com/omarespejel/SISNA/issues/20)
   - Current status: in progress by design, not yet implemented
   - Current mitigation:
     - `NODE_ENV=production` requires explicit acknowledgement via
       `KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION=true`
     - TLS + mTLS are mandatory in production mode
     - Redis (if enabled in production) must use `rediss://`

## Recently Completed Hardening

1. Replay store failure mode: fail-closed (`503`) behavior.
2. Rate limiter failure mode: fail-closed (`503`) behavior.
3. Header and nonce length limits in auth middleware.
4. Request body size limits and policy validation bounds.
5. Security headers via `helmet` and `x-powered-by` disabled.
6. Catch-all JSON 404 handler.
7. Redis client sharing across nonce + rate-limit stores.
8. Production guardrails for transport/mTLS/Redis TLS/in-process custody acknowledgement.
9. Async structured audit logging (`pino`).
10. Workflow and CI hardening (CodeQL, dependency review, pinned actions, spec conformance).

## Release Policy

- New production deployments should treat issue #20 as a tracked risk acceptance until resolved.
- Any release note should include the current status of external signer/KMS migration.
