#!/usr/bin/env python3
"""
Model Context Protocol (MCP) JSON-RPC 2.0 Server Protected by Mutual TLS (mTLS).

Uses only the Python standard library (http.server + ssl) so it can run in any
environment without third-party dependencies. Enforces ssl.CERT_REQUIRED and
exposes peer X.509 certificate metadata to MCP tools.
"""

from __future__ import annotations

import argparse
import http.server
import json
import ssl
from typing import Any


class MCPMtlsHandler(http.server.BaseHTTPRequestHandler):
    """JSON-RPC 2.0 handler implementing Model Context Protocol over mTLS."""

    server_version = "mgtls-mcp-server/1.0"

    def _peer_cert_summary(self) -> dict[str, Any]:
        ssl_sock = self.connection
        if not hasattr(ssl_sock, "getpeercert"):
            return {"authenticated": False}
        cert = ssl_sock.getpeercert() or {}
        subject = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
        issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
        return {
            "authenticated": bool(cert),
            "common_name": subject.get("commonName", "unknown"),
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.get("serialNumber"),
            "not_after": cert.get("notAfter"),
        }

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._write_json(200, {"status": "ok", "protocol": "mcp-jsonrpc-2.0", "mtls": True})
            return
        self._write_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_len)
        try:
            req = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            self._write_json(
                400,
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}},
            )
            return

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "mgtls-remote-mcp-example", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            }
            self._write_json(200, {"jsonrpc": "2.0", "id": req_id, "result": result})
            return

        if method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "whoami_mtls",
                        "description": "Return the authenticated MCP client X.509 certificate identity",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
            self._write_json(200, {"jsonrpc": "2.0", "id": req_id, "result": result})
            return

        if method == "tools/call":
            tool_name = params.get("name")
            if tool_name == "whoami_mtls":
                peer_info = self._peer_cert_summary()
                result = {
                    "content": [
                        {"type": "text", "text": json.dumps(peer_info, indent=2)}
                    ],
                    "isError": False,
                }
                self._write_json(200, {"jsonrpc": "2.0", "id": req_id, "result": result})
                return
            self._write_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                },
            )
            return

        self._write_json(
            200,
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}},
        )

    def _write_json(self, status_code: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run MCP JSON-RPC 2.0 server over strict mTLS")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8444, help="Bind port")
    parser.add_argument("--cert", required=True, help="Server certificate / fullchain.pem")
    parser.add_argument("--key", required=True, help="Server private key (key.pem)")
    parser.add_argument("--ca", required=True, help="Client CA bundle (ca-chain.pem)")
    args = parser.parse_args()

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    ssl_ctx.load_verify_locations(cafile=args.ca)

    httpd = http.server.HTTPServer((args.host, args.port), MCPMtlsHandler)
    httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"MCP mTLS Server listening on https://{args.host}:{args.port}/mcp")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
