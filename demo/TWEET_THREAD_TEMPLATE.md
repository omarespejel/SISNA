# Tweet Thread Template (Signer Security Proof)

## Post 1

We moved Starknet agent signing behind a dedicated keyring proxy boundary.

Today we are publishing proof artifacts, not just claims:

- happy-path signing
- replay attack rejection
- admin selector policy denial
- production config guard (no direct key in proxy mode)

Repo: https://github.com/starknet-innovation/starknet-keyring-proxy

## Post 2

Replay attack proof:

Same nonce + timestamp + signature payload sent twice.

Result:
- first request: `200`
- second request: `401 replayed nonce`

Artifact: `demo/artifacts/<run>/results.json`

## Post 3

Policy denial proof:

Tried to sign `set_agent_id` through session route.

Result:
- `422 denied selector`

This blocks session-key escalation paths at signer boundary.

## Post 4

Production guard proof:

`NODE_ENV=production` + `STARKNET_SIGNER_MODE=proxy` + direct private key present => startup fail.

Expected error:
`STARKNET_PRIVATE_KEY must not be set in production when STARKNET_SIGNER_MODE=proxy`

## Post 5

How to reproduce in one command:

`./demo/run-security-proof.sh`

Runbook:
`docs/SECURITY_PROOF_DEMO.md`

## Post 6 (optional e2e)

Live e2e proof script:

`./demo/run-e2e-sepolia-proof.sh`

This outputs:
- signer `requestId`
- on-chain `txHash`
- correlated signer audit log entry
