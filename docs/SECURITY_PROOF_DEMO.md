# Security Proof Demo

This demo produces concrete evidence for the signer boundary:

1. Happy path signing returns a 4-felt signature.
2. Replay attack (same nonce/timestamp/signature) is rejected.
3. Policy bypass attempt (`set_agent_id`) is rejected.
4. (Optional) Live Sepolia tx with request-id -> signer-log -> tx-hash correlation.

## Quick Run

From repo root:

```bash
chmod +x demo/run-security-proof.sh
./demo/run-security-proof.sh
```

Artifacts are written under `demo/artifacts/<timestamp>/`:

- `summary.txt`
- `results.json`
- `proxy.log`

## Optional Environment Overrides

```bash
PORT=8545
HOST=127.0.0.1
PROXY_BASE_URL=http://127.0.0.1:8545
KEYRING_HMAC_SECRET=0123456789abcdef0123456789abcdef
KEYRING_CLIENT_ID=default
SESSION_PRIVATE_KEY=0x1
DEMO_OUT_DIR=demo/artifacts/my-run
```

## Production Key Custody Guard Evidence

Manual check (from this repo):

```bash
npm run build
NODE_ENV=production \
KEYRING_TRANSPORT=https \
KEYRING_TLS_CERT_PATH=/tmp/server.crt \
KEYRING_TLS_KEY_PATH=/tmp/server.key \
KEYRING_TLS_CA_PATH=/tmp/ca.crt \
KEYRING_MTLS_REQUIRED=true \
KEYRING_HMAC_SECRET=0123456789abcdef0123456789abcdef \
SESSION_PRIVATE_KEY=0x1 \
node dist/index.js
```

Expected error:

`NODE_ENV=production requires explicit KEYRING_ALLOW_INSECURE_IN_PROCESS_KEYS_IN_PRODUCTION=true until external KMS/HSM signer mode is enabled`

## Optional End-to-End Tx Evidence

If you want a chain transaction hash in the thread, run:

```bash
export DEMO_SEPOLIA_RPC_URL=...
export DEMO_ACCOUNT_ADDRESS=0x...
export DEMO_TOKEN_ADDRESS=0x...
export DEMO_RECIPIENT_ADDRESS=0x...
export DEMO_AMOUNT_RAW=1
export SESSION_PRIVATE_KEY=0x...
export KEYRING_HMAC_SECRET=0123456789abcdef0123456789abcdef
./demo/run-e2e-sepolia-proof.sh
```

This flow now runs a hard preflight before signing/sending:
- chain id must be Sepolia
- account and token contracts must be deployed
- account must expose `compute_session_message_hash` entrypoint
- fee token balance must satisfy minimum threshold

Preflight artifacts:
- `preflight-sepolia-readiness.json`
- `preflight-sepolia-readiness.txt`

Output artifact (`e2e-sepolia-proof.json`) includes:

- proxy `requestId`
- `txHash`
- matched signer audit log line (if proxy log path is available)

Keep this optional if you do not want to expose tx details publicly.
