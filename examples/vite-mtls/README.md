# Vite HTTPS & Mutual TLS (mTLS) Dev/Preview Server Example with `mgtls`

This example demonstrates how to configure a **Vite** development and preview server (`vite.config.ts`) with Node.js native TLS (`node:tls` / `node:https`) enforcing **Mutual TLS client certificate verification** (`requestCert: true`, `rejectUnauthorized: true`), along with a custom Vite middleware plugin that inspects `req.socket.getPeerCertificate()` and returns the authenticated client's X.509 identity at `/__mtls/whoami`.

## Files in This Example

| File | Description |
| :--- | :--- |
| [`vite.config.ts`](file:///home/bill/src/sysadmin/mgtls/examples/vite-mtls/vite.config.ts) | Vite configuration enabling HTTPS + strict mTLS on both `server.https` and `preview.https`, plus an mTLS identity inspection plugin and upstream mTLS proxy agent. |
| [`setup_vite_mtls.sh`](file:///home/bill/src/sysadmin/mgtls/examples/vite-mtls/setup_vite_mtls.sh) | Script that invokes `mgtls` to provision the Root CA, Intermediate CA, Vite server certificate, browser/CLI client certificate (including `.p12` bundle for browser import), and `vite` target bundle. |

## Quickstart

### 1. Provision Certificates & Vite Target Bundle

```bash
./setup_vite_mtls.sh
```

### 2. Import the Client Certificate or Test via `curl`

For browser testing, import `.mgtls-vite/certs/vite-client/bundle.p12` into your OS/browser certificate store and trust `.mgtls-vite/ca/corp-root-ca/cert.pem`.

For CLI testing against the Vite dev server on `https://localhost:5173/__mtls/whoami`:

```bash
curl --silent --show-error --fail \
  --cacert .mgtls-vite/certs/vite-srv/ca-chain.pem \
  --cert .mgtls-vite/certs/vite-client/cert.pem \
  --key .mgtls-vite/certs/vite-client/key.pem \
  https://localhost:5173/__mtls/whoami | jq .
```
