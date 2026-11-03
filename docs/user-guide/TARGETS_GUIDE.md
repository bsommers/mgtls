# Target Frameworks & Server Scaffolding Guide — `mgtls`

`mgtls target generate` eliminates manual certificate wiring by provisioning the required CA, Server certificate, and Client mTLS certificate, then rendering drop-in configuration files, application entrypoints, client harnesses, and verification scripts.

```bash
# List all 7 supported target templates
mgtls target list
```

| Target ID | Platform / Stack | Default Port | Generated Artifacts |
| :--- | :--- | :--- | :--- |
| `fastapi` | Python FastAPI + Uvicorn + `httpx` | `8443` | `server.py`, `client.py`, `run-uvicorn.sh`, `verify.sh` |
| `springboot` | Spring Boot 3.2+ SSL Bundles + `RestClient` | `8443` | `application-tls.yml`, `MtlsConfig.java`, `verify.sh` |
| `mcp` | Model Context Protocol Server & Client (TS / FastMCP / NGINX) | `8443` | `mcp-server-mtls.ts`, `fastmcp_mtls.py`, `mcp-client-config.json`, `verify.sh` |
| `nginx` | NGINX TLS 1.3 + Strict mTLS Reverse Proxy | `8443` | `nginx-mtls.conf`, `verify.sh` |
| `vite` | Vite 5/6 Local HTTPS & mTLS Development Server | `5173` | `vite.config.ts`, `verify.sh` |
| `proxmox` | Proxmox VE (`pveproxy-ssl.pem` / `pvenode cert set`) | `8006` | `deploy-proxmox-cert.sh`, `verify.sh` |
| `openssh` | OpenSSH User & Host CA Fleet Bundle | `22` | `sshd_config.d/mgtls-ca.conf`, `ssh_config.d/mgtls.conf`, `authorized_principals`, `known_hosts`, `deploy-sshd-ca.sh` |

---

## 1. Python FastAPI mTLS Server + `httpx` Client (`--target fastapi`)

### Generate the FastAPI mTLS Bundle

```bash
mgtls target generate \
  --target fastapi \
  --name fastapi-orders \
  --domain api.internal \
  --port 8443 \
  --mtls \
  --output-dir ./deployments/fastapi-orders
```

### Generated Architecture & Code

1. **`server.py`**: FastAPI application with an `/healthz` endpoint and an authenticated `/whoami` endpoint, plus a ` ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)` launcher configured with ` ssl.CERT_REQUIRED`, `tls.TLSVersion.TLSv1_2`, and the issuing CA chain.
2. **`client.py`**: Asynchronous `httpx.AsyncClient` and synchronous `httpx.Client` preconfigured with the CA bundle (`verify=CA_CERT`) and client mTLS keypair (`cert=(CLIENT_CERT, CLIENT_KEY)`).
3. **`run-uvicorn.sh`**: Uvicorn CLI startup script passing `--ssl-keyfile`, `--ssl-certfile`, `--ssl-ca-certs`, and `--ssl-cert-reqs 2` (`ssl.CERT_REQUIRED`).

```python
# Excerpt from generated client.py
import ssl
import httpx

ssl_ctx = ssl.create_default_context(cafile="/path/to/ca-chain.pem")
ssl_ctx.load_cert_chain(
    certfile="/path/to/fastapi-orders-client/cert.pem",
    keyfile="/path/to/fastapi-orders-client/key.pem",
)

with httpx.Client(verify=ssl_ctx, base_url="https://api.internal:8443") as client:
    resp = client.get("/whoami")
    print(resp.json())
```

### Run & Verify
```bash
# Terminal 1: Start FastAPI with mTLS enforcement
./deployments/fastapi-orders/run-uvicorn.sh

# Terminal 2: Verify mTLS handshake via curl or client.py
./deployments/fastapi-orders/verify.sh
python3 ./deployments/fastapi-orders/client.py
```

---

## 2. Spring Boot 3 REST API mTLS (`--target springboot`)

Spring Boot 3.1+ introduced declarative **SSL Bundles** (`spring.ssl.bundle.pem`), allowing PEM certificates and private keys to be loaded directly without manual `keytool` JKS/PKCS#12 conversions. `mgtls` generates both PEM SSL bundle configurations and a `.p12` bundle.

### Generate the Spring Boot 3 Bundle

```bash
mgtls target generate \
  --target springboot \
  --name spring-payments \
  --domain payments.internal \
  --port 8443 \
  --mtls \
  --output-dir ./deployments/spring-payments
```

### Generated `application-tls.yml`

```yaml
server:
  port: 8443
  ssl:
    bundle: "mgtls-server"
    client-auth: need

spring:
  ssl:
    bundle:
      pem:
        mgtls-server:
          keystore:
            certificate: "file:/abs/path/certs/spring-payments-server/fullchain.pem"
            private-key: "file:/abs/path/certs/spring-payments-server/key.pem"
          truststore:
            certificate: "file:/abs/path/ca/root-ca/ca-chain.pem"
        mgtls-client:
          keystore:
            certificate: "file:/abs/path/certs/spring-payments-client/cert.pem"
            private-key: "file:/abs/path/certs/spring-payments-client/key.pem"
          truststore:
            certificate: "file:/abs/path/ca/root-ca/ca-chain.pem"
```

### Generated `MtlsConfig.java` (`RestClient` + X.509 Principal Security)

```java
@Configuration
public class MtlsConfig {
    @Bean
    public RestClient mtlsRestClient(RestClient.Builder builder, SslBundles sslBundles) {
        SslBundle clientBundle = sslBundles.getBundle("mgtls-client");
        SSLContext sslContext = clientBundle.createSslContext();
        // Wires JDK HttpClient with mutual TLS SSLContext
        HttpClient httpClient = HttpClient.newBuilder().sslContext(sslContext).build();
        return builder
            .baseUrl("https://payments.internal:8443")
            .requestFactory(new JdkClientHttpRequestFactory(httpClient))
            .build();
    }
}
```

---

## 3. MCP Server & Client mTLS (`--target mcp`)

Secure remote Model Context Protocol (MCP) servers over SSE or Streamable HTTP with mutual TLS so only cryptographically authorized AI agents can list or invoke tools.

### Generate the MCP mTLS Bundle

```bash
mgtls target generate \
  --target mcp \
  --name mcp-prod \
  --domain mcp.internal \
  --port 8443 \
  --mtls \
  --output-dir ./deployments/mcp-prod
```

### Generated Artifacts

1. **`mcp-server-mtls.ts` (TypeScript / Node.js `node:https`)**:
   Configures `https.createServer` with `requestCert: true`, `rejectUnauthorized: true`, and `minVersion: "TLSv1.2"`, verifying the client certificate's Subject CN and SPIFFE URI before dispatching MCP JSON-RPC requests.
2. **`fastmcp_mtls.py` (Python FastMCP / Uvicorn mTLS)**:
   Configures FastMCP over HTTPS with Uvicorn `ssl_cert_reqs=ssl.CERT_REQUIRED`.
3. **`mcp-client-config.json`**:
   Ready-to-use MCP client configuration referencing the client certificate, private key, and CA trust bundle, plus instructions for running `mgtls mcp serve --http :8443 --tls-cert ... --tls-key ... --client-ca ...`.

---

## 4. NGINX TLS 1.3 & mTLS Reverse Proxy (`--target nginx`)

Place an NGINX reverse proxy in front of any internal HTTP service (or stdio/HTTP MCP server) to terminate TLS 1.2/1.3, enforce client certificate verification, and forward the authenticated client Subject DN to the upstream service.

### Generate the NGINX mTLS Bundle

```bash
mgtls target generate \
  --target nginx \
  --name nginx-gateway \
  --domain gateway.internal \
  --port 8443 \
  --mtls \
  --output-dir ./deployments/nginx-gateway
```

### Generated `nginx-mtls.conf` Highlights

```nginx
server {
    listen 8443 ssl http2;
    server_name gateway.internal;

    ssl_certificate         /abs/path/certs/nginx-gateway-server/fullchain.pem;
    ssl_certificate_key     /abs/path/certs/nginx-gateway-server/key.pem;
    ssl_client_certificate  /abs/path/ca/root-ca/ca-chain.pem;

    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header X-SSL-Client-S-DN   $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Serial $ssl_client_serial;
    }
}
```

---

## 5. Vite Local HTTPS & mTLS Development Server (`--target vite`)

Run local frontend development and preview servers over trusted HTTPS or full mutual TLS without browser security warnings.

### Generate the Vite HTTPS/mTLS Bundle

```bash
mgtls target generate \
  --target vite \
  --name vite-web \
  --domain dev.internal \
  --port 5173 \
  --mtls \
  --output-dir ./deployments/vite-web
```

### Generated `vite.config.ts`

```typescript
import fs from 'node:fs';
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    host: 'dev.internal',
    port: 5173,
    https: {
      key: fs.readFileSync('/abs/path/certs/vite-web-server/key.pem'),
      cert: fs.readFileSync('/abs/path/certs/vite-web-server/fullchain.pem'),
      ca: fs.readFileSync('/abs/path/ca/root-ca/ca-chain.pem'),
      requestCert: true,
      rejectUnauthorized: true,
    },
  },
});
```

---

## 6. Proxmox VE (`pveproxy-ssl.pem` / `pvenode cert set`) TLS Automation (`--target proxmox`)

Replace the untrusted default Proxmox VE self-signed web console certificate on port `8006` with a certificate signed by your internal Root/Intermediate CA (or ACME), complete with node hostname and management IP SANs.

### Generate the Proxmox VE Deployment Bundle

```bash
mgtls target generate \
  --target proxmox \
  --name pve01 \
  --domain pve01.internal \
  --port 8006 \
  --output-dir ./deployments/pve01
```

### Generated `deploy-proxmox-cert.sh` Workflow

The generated script supports two official Proxmox VE mechanisms:

1. **CLI Method (`pvenode` — Recommended on Proxmox VE 6/7/8/9)**:
   ```bash
   pvenode cert set \
     /abs/path/certs/pve01-server/fullchain.pem \
     /abs/path/certs/pve01-server/key.pem \
     --force 1 --restart 1
   ```
2. **Cluster Filesystem (`pmxcfs`) Method**:
   Copies `fullchain.pem` to `/etc/pve/local/pveproxy-ssl.pem` (`0640 root:www-data`), copies `key.pem` to `/etc/pve/local/pveproxy-ssl.key` (`0600 root:www-data`), installs the Root CA into `/usr/local/share/ca-certificates/mgtls-root-ca.crt`, runs `update-ca-certificates`, and executes `systemctl reload-or-restart pveproxy spiceproxy`.
