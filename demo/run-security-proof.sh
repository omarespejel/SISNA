#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "node is required" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

PORT="${PORT:-8545}"
HOST="${HOST:-127.0.0.1}"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://${HOST}:${PORT}}"
KEYRING_HMAC_SECRET="${KEYRING_HMAC_SECRET:-0123456789abcdef0123456789abcdef}"
KEYRING_CLIENT_ID="${KEYRING_CLIENT_ID:-default}"
SESSION_PRIVATE_KEY="${SESSION_PRIVATE_KEY:-0x1}"
DEMO_OUT_DIR="${DEMO_OUT_DIR:-demo/artifacts/$(date -u +%Y%m%dT%H%M%SZ)}"
PROXY_LOG_PATH="${DEMO_OUT_DIR}/proxy.log"

mkdir -p "$DEMO_OUT_DIR"

export PORT HOST
export KEYRING_TRANSPORT="${KEYRING_TRANSPORT:-http}"
export KEYRING_MTLS_REQUIRED="${KEYRING_MTLS_REQUIRED:-false}"
export KEYRING_HMAC_SECRET
export KEYRING_DEFAULT_AUTH_CLIENT_ID="$KEYRING_CLIENT_ID"
export SESSION_PRIVATE_KEY
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

echo "[demo] building keyring proxy"
npm run build >/dev/null

echo "[demo] starting keyring proxy (${PROXY_BASE_URL})"
node dist/index.js >"$PROXY_LOG_PATH" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "${PROXY_BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -fsS "${PROXY_BASE_URL}/health" >/dev/null 2>&1; then
  echo "[demo] proxy failed to start; see ${PROXY_LOG_PATH}" >&2
  exit 1
fi

echo "[demo] running security proof scenarios"
KEYRING_HMAC_SECRET="$KEYRING_HMAC_SECRET" \
KEYRING_CLIENT_ID="$KEYRING_CLIENT_ID" \
DEMO_OUT_DIR="$DEMO_OUT_DIR" \
node demo/security-proof.mjs --proxy-url "$PROXY_BASE_URL" --client-id "$KEYRING_CLIENT_ID" --secret "$KEYRING_HMAC_SECRET"

echo "[demo] done"
echo "[demo] artifacts: ${DEMO_OUT_DIR}"
echo "[demo] proxy log: ${PROXY_LOG_PATH}"
