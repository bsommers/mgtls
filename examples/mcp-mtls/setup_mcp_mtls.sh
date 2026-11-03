#!/usr/bin/env bash
set -euo pipefail

# Provision CA, MCP Server/Client Certificates & MCP Target Bundle
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STORE_DIR="${SCRIPT_DIR}/.mgtls-mcp"
TARGET_OUT="${SCRIPT_DIR}/generated-mcp"

MGTLS_BIN="${MGTLS_BIN:-}"
if [[ -z "${MGTLS_BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
    MGTLS_BIN="${REPO_ROOT}/bin/mgtls"
  else
    MGTLS_BIN="go run ${REPO_ROOT}/cmd/mgtls"
  fi
fi

echo "==> [1/5] Initializing store at ${STORE_DIR}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" init

echo "==> [2/5] Creating Root CA and AI Agent Intermediate CA"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-root-ca \
  --cn "Acme Corp Root CA" \
  --algo ed25519 \
  --days 3650

${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-intermediate-ca \
  --parent corp-root-ca \
  --cn "Acme Corp AI Agent Intermediate CA" \
  --algo ecdsa-p256 \
  --days 1825

echo "==> [3/5] Issuing MCP Server Certificate (mcp-srv)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name mcp-srv \
  --ca corp-intermediate-ca \
  --cn "localhost" \
  --role server \
  --dns "localhost,mcp.internal" \
  --ip "127.0.0.1,::1" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [4/5] Issuing MCP Client Certificate (mcp-client)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name mcp-client \
  --ca corp-intermediate-ca \
  --cn "claude-agent-client" \
  --role client \
  --dns "claude-agent.internal" \
  --uri "spiffe://corp.internal/agent/claude-desktop" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [5/5] Generating MCP Target Bundle in ${TARGET_OUT}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" target generate \
  --type mcp \
  --name mcp-mtls-bundle \
  --ca corp-intermediate-ca \
  --server-cert mcp-srv \
  --client-cert mcp-client \
  --host localhost \
  --port 8444 \
  --mtls \
  --out "${TARGET_OUT}"

echo "[PASS] MCP Server & Client mTLS bundle generated."
