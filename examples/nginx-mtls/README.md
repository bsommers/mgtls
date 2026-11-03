# NGINX TLS 1.3 & Mutual TLS (mTLS) Reverse Proxy Example with `mgtls`

This example demonstrates how to deploy an **NGINX Reverse Proxy** terminating TLS 1.2/1.3 with strict Mutual TLS client certificate validation (`ssl_verify_client on`) and forwarding authenticated X.509 client identity headers (`$ssl_client_s_dn`, `$ssl_client_i_dn`, `$ssl_client_serial`, `$ssl_client_fingerprint`) to upstream backend services.

## Files in This Example

| File | Description |
| :--- | :--- |
| [`nginx.conf`](file:///home/bill/src/sysadmin/mgtls/examples/nginx-mtls/nginx.conf) | Complete production-hardened NGINX configuration with TLS 1.3, `ssl_verify_client on`, `ssl_verify_depth 3`, `/mtls-status` diagnostic endpoint, and upstream proxy identity headers. |
| [`setup_nginx_mtls.sh`](file:///home/bill/src/sysadmin/mgtls/examples/nginx-mtls/setup_nginx_mtls.sh) | Script that invokes `mgtls` to create the Root CA, Intermediate CA, NGINX server certificate, client certificate, CRL, and `nginx` target bundle. |

## Quickstart

### 1. Generate Certificates & NGINX Target Bundle

```bash
./setup_nginx_mtls.sh
```

### 2. Test NGINX Configuration Syntax

```bash
nginx -t -c "$(pwd)/nginx.conf" -p "$(pwd)"
```

### 3. Test Authenticated mTLS Request

```bash
curl --silent --show-error --fail \
  --cacert .mgtls-nginx/certs/nginx-srv/ca-chain.pem \
  --cert .mgtls-nginx/certs/nginx-client/cert.pem \
  --key .mgtls-nginx/certs/nginx-client/key.pem \
  https://localhost:8443/mtls-status | jq .
```
