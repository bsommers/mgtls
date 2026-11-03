#!/usr/bin/env python3
"""
FastAPI Mutual TLS (mTLS) Client Example using httpx.

Demonstrates:
1. Authenticated mTLS GET request to /mtls/whoami using client certificate + key + CA chain.
2. Negative test verifying that connections without a client certificate are rejected during TLS handshake.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys

import httpx


def create_mtls_ssl_context(ca_path: str, cert_path: str, key_path: str) -> ssl.SSLContext:
    """Create a TLS 1.3 capable SSLContext with client certificate and custom CA trust."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def main() -> int:
    parser = argparse.ArgumentParser(description="mTLS httpx client for FastAPI")
    parser.add_argument("--url", default="https://localhost:8443/mtls/whoami", help="Target HTTPS endpoint")
    parser.add_argument("--ca", required=True, help="Path to CA bundle (ca-chain.pem)")
    parser.add_argument("--cert", required=True, help="Path to client certificate (cert.pem)")
    parser.add_argument("--key", required=True, help="Path to client private key (key.pem)")
    parser.add_argument("--verify-reject-without-cert", action="store_true", help="Also verify unauthenticated rejection")
    args = parser.parse_args()

    ssl_ctx = create_mtls_ssl_context(args.ca, args.cert, args.key)
    with httpx.Client(verify=ssl_ctx, http2=False, timeout=10.0) as client:
        response = client.get(args.url)
        response.raise_for_status()
        payload = response.json()
        print("[PASS] mTLS handshake and authentication succeeded:")
        print(json.dumps(payload, indent=2))

    if args.verify_reject_without_cert:
        no_cert_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
        try:
            with httpx.Client(verify=no_cert_ctx, timeout=5.0) as unauth_client:
                unauth_client.get(args.url)
            print("[FAIL] Server unexpectedly accepted connection without client certificate!", file=sys.stderr)
            return 1
        except httpx.HTTPError as exc:
            print(f"[PASS] Connection without client certificate was rejected as expected: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
