# FastAPI Mutual TLS (mTLS) Example with `mgtls`

This example demonstrates end-to-end Mutual TLS (mTLS) authentication between a **Python FastAPI / Uvicorn** server and an **`httpx`** client using a 2-tier Certificate Authority hierarchy (**Root CA → Intermediate CA → Server & Client Leaf Certificates**) provisioned by `mgtls`.

## Architecture

```
┌───────────────────────────┐
│       corp-root-ca        │  (Offline / Trust Anchor, Ed25519)
└─────────────┬─────────────┘
              │ signs
              ▼
┌───────────────────────────┐
│   corp-intermediate-ca    │  (Issuing Intermediate CA, ECDSA P-256)
└──────┬─────────────┬──────┘
       │ signs       │ signs
       ▼             ▼
┌─────────────┐ ┌──────────────┐
│fastapi-srv  │ │fastapi-client│
│ (Role:srv)  │ │ (Role:client)│
└──────┬──────┘ └──────┬───────┘
       │               │
       └───────┬───────┘
       TLS 1.3 + Client Cert
       Handshake on :8443
```

## Files in This Example

| File | Description |
| :--- | :--- |
| [`server.py`](file:///home/bill/src/sysadmin/mgtls/examples/fastapi-mtls/server.py) | FastAPI application & Uvicorn SSL/mTLS runner (`ssl.CERT_REQUIRED`) that inspects the peer X.509 certificate from the ASGI transport (`peercert`). |
| [`client.py`](file:///home/bill/src/sysadmin/mgtls/examples/fastapi-mtls/client.py) | `httpx` client script that performs both positive mTLS authentication (presenting `client.crt` + `client.key`) and negative testing (omitting client certificate). |
| [`setup_and_test.sh`](file:///home/bill/src/sysadmin/mgtls/examples/fastapi-mtls/setup_and_test.sh) | End-to-end automation script that calls `mgtls` to create the Root CA, Intermediate CA, Server Certificate, Client Certificate, and `fastapi` target bundle, and verifies the certificate chain. |

## Quickstart

### 1. Provision PKI & Target Artifacts

```bash
./setup_and_test.sh
```

### 2. Install Python Dependencies

```bash
pip install fastapi uvicorn httpx cryptography
```

### 3. Start the FastAPI mTLS Server

```bash
python3 server.py \
  --cert .mgtls-fastapi/certs/fastapi-srv/fullchain.pem \
  --key .mgtls-fastapi/certs/fastapi-srv/key.pem \
  --ca .mgtls-fastapi/certs/fastapi-srv/ca-chain.pem \
  --port 8443
```

### 4. Run the mTLS Client

```bash
python3 client.py \
  --url https://localhost:8443/mtls/whoami \
  --ca .mgtls-fastapi/certs/fastapi-srv/ca-chain.pem \
  --cert .mgtls-fastapi/certs/fastapi-client/cert.pem \
  --key .mgtls-fastapi/certs/fastapi-client/key.pem
```
