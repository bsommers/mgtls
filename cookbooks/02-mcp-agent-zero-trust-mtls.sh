#!/usr/bin/env bash
# Cookbook 02: Zero-Trust Model Context Protocol (MCP) Agent & Server mTLS
# Provisions dedicated MCP CA & Server/Client mTLS certificates, generates MCP mTLS scaffolds,
# and executes a live JSON-RPC 2.0 session against `mgtls mcp serve --transport stdio`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${MGTLS_COOKBOOK_DIR:-$(mktemp -d -t mgtls-cb02-XXXXXX)}"
STORE_DIR="${WORK_DIR}/.mgtls"
OUT_DIR="${WORK_DIR}/mcp-bundle"

if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
  MGTLS=("${REPO_ROOT}/bin/mgtls" "--store-dir" "${STORE_DIR}")
else
  MGTLS=("go" "run" "${REPO_ROOT}/src/cmd/mgtls" "--store-dir" "${STORE_DIR}")
fi

echo "==> [Cookbook 02] Initializing MCP Zero-Trust Store at ${STORE_DIR}"
"${MGTLS[@]}" init

echo "==> [1/3] Provisioning MCP Authority, Server Certificate & Agent Client Certificate via MCP JSON-RPC 2.0"
cat <<EOF | "${MGTLS[@]}" mcp serve --transport stdio > "${WORK_DIR}/mcp_responses.jsonl"
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cookbook-agent","version":"1.0.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pki_create_ca","arguments":{"name":"mcp-zero-trust-ca","common_name":"MCP Zero-Trust Root CA","algorithm":"ed25519"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pki_issue_cert","arguments":{"name":"mcp-server-tls","ca_name":"mcp-zero-trust-ca","common_name":"mcp.internal","role":"server","dns_names":["localhost","mcp.internal"],"ip_addresses":["127.0.0.1"]}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pki_issue_cert","arguments":{"name":"mcp-agent-client","ca_name":"mcp-zero-trust-ca","common_name":"claude-agent","role":"client","uris":["spiffe://mcp.internal/agent/claude"]}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"target_generate","arguments":{"name":"mcp-zero-trust","target_type":"mcp","ca_name":"mcp-zero-trust-ca","server_cert":"mcp-server-tls","client_cert":"mcp-agent-client","host":"mcp.internal","port":8444,"mutual_tls":true,"output_dir":"${OUT_DIR}"}}}
EOF

echo "==> [2/3] Verifying MCP JSON-RPC 2.0 Responses (${WORK_DIR}/mcp_responses.jsonl)"
wc -l "${WORK_DIR}/mcp_responses.jsonl"

echo "==> [3/3] Auditing Provisioned MCP Store & Generated Bundle (${OUT_DIR})"
"${MGTLS[@]}" status
"${MGTLS[@]}" doctor --warn-days 30
ls -la "${OUT_DIR}"
echo "==> [Cookbook 02 Complete] MCP Zero-Trust bundle ready at ${OUT_DIR}"
