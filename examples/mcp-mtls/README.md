# Model Context Protocol (MCP) Server & Client Mutual TLS Example with `mgtls`

This example demonstrates two ways `mgtls` integrates with the **Model Context Protocol (MCP)**:

1. **`mgtls` as an MCP Server itself (`mgtls mcp serve`)**: AI agents (Claude Desktop, Cursor, Windsurf, custom orchestrators) can invoke `mgtls` tools (`pki_create_ca`, `pki_issue_cert`, `ssh_create_ca`, `ssh_sign_cert`, `acme_obtain`, `target_generate`, `profile_apply`, `store_status`) over `stdio` or over an mTLS-protected HTTPS JSON-RPC 2.0 endpoint.
2. **Securing any custom Python/TypeScript MCP Server with mTLS**: Provisioning dedicated X.509 Server and Client certificates (`mcp-srv`, `mcp-client`) so remote MCP tool calls require cryptographic client authentication (`ssl.CERT_REQUIRED`).

## Files in This Example

| File | Description |
| :--- | :--- |
| [`mcp_server.py`](file:///home/bill/src/sysadmin/mgtls/examples/mcp-mtls/mcp_server.py) | Standalone Python HTTPS JSON-RPC 2.0 MCP Server enforcing TLS 1.3 + client certificate verification (`ssl.CERT_REQUIRED`) and exposing `initialize`, `tools/list`, and `tools/call` (`whoami_mtls`). |
| [`claude_desktop_config.json`](file:///home/bill/src/sysadmin/mgtls/examples/mcp-mtls/claude_desktop_config.json) | Example MCP client configuration showing both `mgtls mcp serve` (`stdio` transport) and a remote mTLS MCP server bridge (`curl` with `--cacert`, `--cert`, `--key`). |
| [`setup_mcp_mtls.sh`](file:///home/bill/src/sysadmin/mgtls/examples/mcp-mtls/setup_mcp_mtls.sh) | Script that provisions the CA hierarchy, MCP server/client mTLS certificates, and `mcp` target scaffolding bundle, and tests `mgtls mcp serve` with a JSON-RPC request. |

## Quickstart

### 1. Provision MCP mTLS Certificates & Target Bundle

```bash
./setup_mcp_mtls.sh
```

### 2. Run the Built-in `mgtls` MCP Server over HTTPS + mTLS

```bash
mgtls --store-dir .mgtls-mcp mcp serve \
  --transport http \
  --addr 127.0.0.1:8444 \
  --tls-cert .mgtls-mcp/certs/mcp-srv/fullchain.pem \
  --tls-key .mgtls-mcp/certs/mcp-srv/key.pem \
  --client-ca .mgtls-mcp/certs/mcp-srv/ca-chain.pem
```

> The HTTP transport requires authentication: `--client-ca` (as above) or a bearer token via `MGTLS_MCP_TOKEN`/`--token-file`.

### 3. Run the Custom Python MCP mTLS Server

```bash
python3 mcp_server.py \
  --cert .mgtls-mcp/certs/mcp-srv/fullchain.pem \
  --key .mgtls-mcp/certs/mcp-srv/key.pem \
  --ca .mgtls-mcp/certs/mcp-srv/ca-chain.pem \
  --port 8444
```

### 4. Invoke an MCP JSON-RPC Tool Call over mTLS

```bash
curl --silent --show-error --fail \
  --cacert .mgtls-mcp/certs/mcp-srv/ca-chain.pem \
  --cert .mgtls-mcp/certs/mcp-client/cert.pem \
  --key .mgtls-mcp/certs/mcp-client/key.pem \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami_mtls","arguments":{}}}' \
  https://localhost:8444/mcp | jq .
```
