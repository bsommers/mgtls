#!/usr/bin/env python3
"""
FastAPI Mutual TLS (mTLS) Server Example for mgtls.

Enforces TLS 1.2/1.3 client certificate authentication (ssl.CERT_REQUIRED)
at the Uvicorn transport layer and extracts peer certificate attributes
(Subject DN, Issuer DN, Serial Number, Validity, and SANs) inside FastAPI routes.
"""

from __future__ import annotations

import argparse
import ssl
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request

app = FastAPI(
    title="mgtls FastAPI Mutual TLS Service",
    version="1.0.0",
    description="Zero-trust FastAPI service requiring X.509 client certificate authentication.",
)


def extract_peer_certificate(request: Request) -> dict[str, Any]:
    """Extract the verified client X.509 certificate dictionary from the ASGI SSL transport."""
    transport = request.scope.get("transport")
    if transport is None:
        return {}
    ssl_object = transport.get_extra_info("ssl_object")
    if ssl_object is None:
        return {}
    peer_cert = ssl_object.getpeercert()
    return peer_cert or {}


def flatten_dn(rdn_sequence: tuple[ Any, ... ]) -> dict[str, str]:
    """Flatten Python ssl.getpeercert() RDN tuple structure into a readable key-value dictionary."""
    result: dict[str, str] = {}
    for rdn in rdn_sequence:
        for attr_key, attr_val in rdn:
            result[attr_key] = attr_val
    return result


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Health check endpoint (still protected by transport-level mTLS handshake)."""
    return {"status": "ok", "tls_mode": "strict-mtls"}


@app.get("/mtls/whoami")
async def mtls_whoami(request: Request) -> dict[str, Any]:
    """Return authenticated client identity parsed from the verified X.509 client certificate."""
    peer_cert = extract_peer_certificate(request)
    if not peer_cert:
        raise HTTPException(
            status_code=401,
            detail="No verified client certificate found on TLS transport",
        )

    subject = flatten_dn(peer_cert.get("subject", ()))
    issuer = flatten_dn(peer_cert.get("issuer", ()))
    san_entries = [
        {"type": san_type, "value": san_val}
        for san_type, san_val in peer_cert.get("subjectAltName", ())
    ]

    return {
        "authenticated": True,
        "client_common_name": subject.get("commonName", "unknown"),
        "subject": subject,
        "issuer": issuer,
        "serial_number": peer_cert.get("serialNumber"),
        "not_before": peer_cert.get("notBefore"),
        "not_after": peer_cert.get("notAfter"),
        "subject_alt_names": san_entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run FastAPI server with strict mTLS")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8443, help="Bind port")
    parser.add_argument("--cert", required=True, help="Path to server certificate or fullchain.pem")
    parser.add_argument("--key", required=True, help="Path to server private key (key.pem)")
    parser.add_argument("--ca", required=True, help="Path to CA bundle for verifying client certificates")
    args = parser.parse_args()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=args.cert,
        ssl_keyfile=args.key,
        ssl_ca_certs=args.ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


if __name__ == "__main__":
    main()
