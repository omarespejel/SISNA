#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENTIC_DIR="${AGENTIC_DIR:-${ROOT_DIR}/../starknet-agentic}"
MCP_DIR="${AGENTIC_DIR}/packages/starknet-mcp-server"
OUT_DIR="${DEMO_OUT_DIR:-${ROOT_DIR}/demo/artifacts/$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_FILE="${OUT_DIR}/mcp-prod-guard.txt"

if [[ ! -d "${MCP_DIR}" ]]; then
  echo "MCP directory not found: ${MCP_DIR}" >&2
  echo "Set AGENTIC_DIR to your starknet-agentic path." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "[demo] building MCP server at ${MCP_DIR}"
(
  cd "${MCP_DIR}"
  npm run build >/dev/null
)

echo "[demo] validating production guard (proxy mode + private key present)"
set +e
CMD_OUTPUT="$(
  cd "${MCP_DIR}" && \
  NODE_ENV=production \
  STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io/rpc/v0_8 \
  STARKNET_ACCOUNT_ADDRESS=0x123 \
  STARKNET_SIGNER_MODE=proxy \
  KEYRING_PROXY_URL=http://127.0.0.1:8545 \
  KEYRING_HMAC_SECRET=0123456789abcdef0123456789abcdef \
  STARKNET_PRIVATE_KEY=0x1 \
  node dist/index.js 2>&1
)"
STATUS=$?
set -e

{
  echo "exit_status=${STATUS}"
  echo "---"
  echo "${CMD_OUTPUT}"
} >"${OUT_FILE}"

if [[ "${STATUS}" -eq 0 ]]; then
  echo "Expected non-zero exit status for production guard, got 0." >&2
  echo "See ${OUT_FILE}" >&2
  exit 1
fi

if [[ "${CMD_OUTPUT}" != *"STARKNET_PRIVATE_KEY must not be set in production when STARKNET_SIGNER_MODE=proxy"* ]]; then
  echo "Expected production guard error message was not found." >&2
  echo "See ${OUT_FILE}" >&2
  exit 1
fi

echo "[demo] production guard proof passed"
echo "[demo] artifact: ${OUT_FILE}"
