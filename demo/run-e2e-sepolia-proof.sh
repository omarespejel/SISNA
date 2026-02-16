#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required env var: ${name}" >&2
    exit 1
  fi
}

require_env "DEMO_SEPOLIA_RPC_URL"
require_env "DEMO_ACCOUNT_ADDRESS"
require_env "DEMO_TOKEN_ADDRESS"
require_env "DEMO_RECIPIENT_ADDRESS"
require_env "SESSION_PRIVATE_KEY"
require_env "KEYRING_HMAC_SECRET"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8654}"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://${HOST}:${PORT}}"
KEYRING_CLIENT_ID="${KEYRING_CLIENT_ID:-default}"
DEMO_OUT_DIR="${DEMO_OUT_DIR:-demo/artifacts/$(date -u +%Y%m%dT%H%M%SZ)}"
PROXY_LOG_PATH="${DEMO_OUT_DIR}/proxy.log"

mkdir -p "$DEMO_OUT_DIR"

echo "[e2e] running sepolia readiness preflight"
node demo/preflight-sepolia-readiness.mjs \
  --rpc-url "${DEMO_SEPOLIA_RPC_URL}" \
  --account-address "${DEMO_ACCOUNT_ADDRESS}" \
  --token-address "${DEMO_TOKEN_ADDRESS}" \
  --out-dir "${DEMO_OUT_DIR}"

export HOST PORT
export KEYRING_TRANSPORT="${KEYRING_TRANSPORT:-http}"
export KEYRING_MTLS_REQUIRED="${KEYRING_MTLS_REQUIRED:-false}"
export KEYRING_HMAC_SECRET
export KEYRING_DEFAULT_AUTH_CLIENT_ID="$KEYRING_CLIENT_ID"
export SESSION_PRIVATE_KEY
export KEYRING_ALLOWED_CHAIN_IDS="${KEYRING_ALLOWED_CHAIN_IDS:-0x534e5f5345504f4c4941}"
export KEYRING_REPLAY_STORE="${KEYRING_REPLAY_STORE:-memory}"
export KEYRING_RATE_LIMIT_ENABLED="${KEYRING_RATE_LIMIT_ENABLED:-false}"
export KEYRING_LEAK_SCANNER_ENABLED="${KEYRING_LEAK_SCANNER_ENABLED:-false}"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[e2e] building keyring proxy"
npm run build >/dev/null

echo "[e2e] starting keyring proxy at ${PROXY_BASE_URL}"
node dist/index.js >"$PROXY_LOG_PATH" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "${PROXY_BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -fsS "${PROXY_BASE_URL}/health" >/dev/null 2>&1; then
  echo "[e2e] proxy failed to start; see ${PROXY_LOG_PATH}" >&2
  exit 1
fi

echo "[e2e] executing sepolia transfer and collecting correlation artifact"
node demo/e2e-sepolia-proof.mjs \
  --rpc-url "${DEMO_SEPOLIA_RPC_URL}" \
  --account-address "${DEMO_ACCOUNT_ADDRESS}" \
  --token-address "${DEMO_TOKEN_ADDRESS}" \
  --recipient-address "${DEMO_RECIPIENT_ADDRESS}" \
  --amount-raw "${DEMO_AMOUNT_RAW:-1}" \
  --proxy-url "${PROXY_BASE_URL}" \
  --client-id "${KEYRING_CLIENT_ID}" \
  --secret "${KEYRING_HMAC_SECRET}" \
  --out-dir "${DEMO_OUT_DIR}" \
  --proxy-log-path "${PROXY_LOG_PATH}"

echo "[e2e] done"
echo "[e2e] artifacts: ${DEMO_OUT_DIR}"
