package targets

var targetTemplates = map[string]map[string]string{
	"fastapi": {
		"app.py": `# FastAPI + Uvicorn TLS/mTLS Application ({{.Name}})
# Host: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
# CA Cert: {{.CACertPath}} (Bundle: {{.LocalCACertPath}})
# Server Cert: {{.ServerCertPath}} (Bundle: {{.LocalServerCertPath}})
# Server Key: {{.ServerKeyPath}} (Bundle: {{.LocalServerKeyPath}})

import ssl
from fastapi import FastAPI, Request

app = FastAPI(title="mgtls FastAPI Service - {{.Name}}")


@app.get("/healthz")
async def healthz(request: Request):
    return {
        "status": "ok",
        "service": "{{.Name}}",
        "host": "{{.Host}}",
        "port": {{.Port}},
        "mtls_required": {{if .MutualTLS}}True{{else}}False{{end}},
    }


def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile="{{.ServerCertPath}}", keyfile="{{.ServerKeyPath}}")
    ctx.load_verify_locations(cafile="{{.CACertPath}}")
    ctx.verify_mode = {{if .MutualTLS}}ssl.CERT_REQUIRED{{else}}ssl.CERT_OPTIONAL{{end}}
    return ctx
`,
		"run_server.sh": `#!/usr/bin/env bash
set -euo pipefail
# Run FastAPI Uvicorn server with TLS/mTLS
# Source CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

HOST="{{.Host}}"
PORT="{{.Port}}"
CA_CERT="{{.LocalCACertPath}}"
SERVER_CERT="{{.LocalServerCertPath}}"
SERVER_KEY="{{.LocalServerKeyPath}}"

exec uvicorn app:app \
  --host "${HOST}" \
  --port "${PORT}" \
  --ssl-keyfile "${SERVER_KEY}" \
  --ssl-certfile "${SERVER_CERT}" \
  --ssl-ca-certs "${CA_CERT}" \
  --ssl-cert-reqs {{if .MutualTLS}}2{{else}}1{{end}}
`,
		"client_mtls.py": `# Python httpx mTLS Client for {{.Name}} ({{.Host}}:{{.Port}})
# CA Cert: {{.CACertPath}}
# Client Cert: {{.ClientCertPath}} (Bundle: {{.LocalClientCertPath}})
# Client Key: {{.ClientKeyPath}} (Bundle: {{.LocalClientKeyPath}})

import ssl
import httpx


def fetch_health() -> dict:
    ctx = ssl.create_default_context(cafile="{{.CACertPath}}")
    ctx.load_cert_chain(certfile="{{.ClientCertPath}}", keyfile="{{.ClientKeyPath}}")
    with httpx.Client(verify=ctx, timeout=10.0) as client:
        resp = client.get("https://{{.Host}}:{{.Port}}/healthz")
        resp.raise_for_status()
        return resp.json()


if __name__ == "__main__":
    print(fetch_health())
`,
		"verify_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify FastAPI TLS/mTLS endpoint at https://{{.Host}}:{{.Port}}/healthz
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/healthz"
`,
	},
	"springboot": {
		"application-tls.yml": `# Spring Boot 3.2+ SSL Bundle Configuration ({{.Name}})
# Host: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
# Source CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
# Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

server:
  address: "{{.Host}}"
  port: {{.Port}}
  ssl:
    bundle: "mgtls-server"
    client-auth: {{if .MutualTLS}}need{{else}}want{{end}}
    enabled-protocols:
      - TLSv1.3
      - TLSv1.2

spring:
  ssl:
    bundle:
      pem:
        mgtls-server:
           reload-on-update: true
          keystore:
            certificate: "{{.ServerCertPath}}"
            private-key: "{{.ServerKeyPath}}"
          truststore:
            certificate: "{{.CACertPath}}"
        mgtls-client:
          keystore:
            certificate: "{{.ClientCertPath}}"
            private-key: "{{.ClientKeyPath}}"
          truststore:
            certificate: "{{.CACertPath}}"
`,
		"MtlsSecurityConfig.java": `// Spring Security X.509 mTLS Configuration for {{.Name}} ({{.Host}}:{{.Port}})
// CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class MtlsSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService())
            );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_MTLS_CLIENT"));
    }
}
`,
		"MtlsRestClientConfig.java": `// Spring Boot 3 RestClient with mTLS Bundle for {{.Name}} (https://{{.Host}}:{{.Port}})
// CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}
package com.example.security;

import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class MtlsRestClientConfig {

    @Bean
    public RestClient mtlsRestClient(RestClient.Builder builder, RestClientSsl ssl) {
        return builder
            .baseUrl("https://{{.Host}}:{{.Port}}")
            .apply(ssl.fromBundle("mgtls-client"))
            .build();
    }
}
`,
		"verify_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Spring Boot 3 mTLS endpoint at https://{{.Host}}:{{.Port}}/actuator/health
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/actuator/health"
`,
	},
	"mcp": {
		"mcp_server_mtls.ts": `// Model Context Protocol (MCP) TypeScript Server over HTTPS/mTLS ({{.Name}})
// Endpoint: https://{{.Host}}:{{.Port}}/mcp | MutualTLS: {{.MutualTLS}}
// CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

import https from "node:https";
import fs from "node:fs";

const tlsOptions: https.ServerOptions = {
  ca: fs.readFileSync("{{.CACertPath}}"),
  cert: fs.readFileSync("{{.ServerCertPath}}"),
  key: fs.readFileSync("{{.ServerKeyPath}}"),
  requestCert: true,
  rejectUnauthorized: {{if .MutualTLS}}true{{else}}false{{end}},
  minVersion: "TLSv1.2",
};

const server = https.createServer(tlsOptions, (req, res) => {
  const socket = req.socket as import("node:tls").TLSSocket;
  if ({{if .MutualTLS}}!socket.authorized{{else}}false{{end}}) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "mTLS client certificate required" }));
    return;
  }
  const peer = socket.getPeerCertificate();
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      jsonrpc: "2.0",
      protocol: "mcp",
      service: "{{.Name}}",
      host: "{{.Host}}",
      port: {{.Port}},
      clientSubject: peer?.subject?.CN ?? "anonymous",
    })
  );
});

server.listen({{.Port}}, "{{.Host}}", () => {
  console.log("MCP mTLS server listening on https://{{.Host}}:{{.Port}}/mcp");
});
`,
		"mcp_server_mtls.py": `# Model Context Protocol (MCP) Python FastMCP / Starlette mTLS Server ({{.Name}})
# Endpoint: https://{{.Host}}:{{.Port}}/mcp | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

import ssl
import uvicorn

def build_mcp_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile="{{.ServerCertPath}}", keyfile="{{.ServerKeyPath}}")
    ctx.load_verify_locations(cafile="{{.CACertPath}}")
    ctx.verify_mode = {{if .MutualTLS}}ssl.CERT_REQUIRED{{else}}ssl.CERT_OPTIONAL{{end}}
    return ctx

if __name__ == "__main__":
    uvicorn.run(
        "mcp_app:app",
        host="{{.Host}}",
        port={{.Port}},
        ssl_keyfile="{{.ServerKeyPath}}",
        ssl_certfile="{{.ServerCertPath}}",
        ssl_ca_certs="{{.CACertPath}}",
        ssl_cert_reqs={{if .MutualTLS}}ssl.CERT_REQUIRED{{else}}ssl.CERT_OPTIONAL{{end}},
    )
`,
		"mcp_client_config.json": `{
  "mcpServers": {
    "{{.Name}}": {
      "url": "https://{{.Host}}:{{.Port}}/mcp",
      "transport": "streamable-http",
      "tls": {
        "mutualTLS": {{if .MutualTLS}}true{{else}}false{{end}},
        "caFile": "{{.CACertPath}}",
        "certFile": "{{.ClientCertPath}}",
        "keyFile": "{{.ClientKeyPath}}",
        "localBundle": {
          "ca": "{{.LocalCACertPath}}",
          "cert": "{{.LocalClientCertPath}}",
          "key": "{{.LocalClientKeyPath}}"
        }
      },
      "env": {
        "NODE_EXTRA_CA_CERTS": "{{.CACertPath}}",
        "MCP_CLIENT_CERT": "{{.ClientCertPath}}",
        "MCP_CLIENT_KEY": "{{.ClientKeyPath}}"
      }
    }
  }
}
`,
		"nginx_mcp_sidecar.conf": `# NGINX mTLS Termination Sidecar for MCP Server ({{.Name}})
# Listens on {{.Host}}:{{.Port}} and proxies to local MCP SSE/Streamable-HTTP backend
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

server {
    listen {{.Port}} ssl;
    server_name {{.Host}};

    ssl_certificate     "{{.ServerCertPath}}";
    ssl_certificate_key "{{.ServerKeyPath}}";
    ssl_client_certificate "{{.CACertPath}}";
    ssl_verify_client {{if .MutualTLS}}on{{else}}optional{{end}};
    ssl_protocols TLSv1.2 TLSv1.3;

    location /mcp {
        proxy_pass {{index .Extra "upstream_url"}};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-MCP-Client-Verify $ssl_client_verify;
        proxy_set_header X-MCP-Client-S-DN $ssl_client_s_dn;
        proxy_buffering off;
        proxy_cache off;
    }
}
`,
		"verify_mcp_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify MCP Server mTLS handshake and JSON-RPC health at https://{{.Host}}:{{.Port}}/mcp
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  -H "Accept: application/json, text/event-stream" \
  "https://{{.Host}}:{{.Port}}/mcp"
`,
	},
	"nginx": {
		"nginx-mtls.conf": `# Hardened NGINX TLS 1.2/1.3 & mTLS Reverse Proxy ({{.Name}})
# Host: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
# Client Cert (for testing): {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

server {
    listen {{.Port}} ssl http2;
    server_name {{.Host}};

    ssl_certificate     "{{.ServerCertPath}}";
    ssl_certificate_key "{{.ServerKeyPath}}";
    ssl_client_certificate "{{.CACertPath}}";
    ssl_verify_client {{if .MutualTLS}}on{{else}}optional{{end}};
    ssl_verify_depth 2;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass {{index .Extra "upstream_url"}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Fingerprint $ssl_client_fingerprint;
    }
}
`,
		"verify_nginx_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify NGINX TLS/mTLS proxy at https://{{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/"
`,
	},
	"vite": {
		"vite.config.mtls.ts": `// Vite Dev & Preview Server HTTPS / mTLS Configuration ({{.Name}})
// Host: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
// CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

import fs from "node:fs";
import type { ServerOptions } from "node:https";
import { defineConfig } from "vite";

const httpsOptions: ServerOptions = {
  ca: fs.readFileSync("{{.CACertPath}}"),
  cert: fs.readFileSync("{{.ServerCertPath}}"),
  key: fs.readFileSync("{{.ServerKeyPath}}"),
  requestCert: {{if .MutualTLS}}true{{else}}false{{end}},
  rejectUnauthorized: {{if .MutualTLS}}true{{else}}false{{end}},
  minVersion: "TLSv1.2",
};

export default defineConfig({
  server: {
    host: "{{.Host}}",
    port: {{.Port}},
    strictPort: true,
    https: httpsOptions,
  },
  preview: {
    host: "{{.Host}}",
    port: {{.Port}},
    strictPort: true,
    https: httpsOptions,
  },
});
`,
		"client_fetch_mtls.mjs": `// Node.js mTLS Client for Vite / API Endpoints ({{.Name}} - https://{{.Host}}:{{.Port}})
// CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

import fs from "node:fs";
import https from "node:https";

const agent = new https.Agent({
  ca: fs.readFileSync("{{.CACertPath}}"),
  cert: fs.readFileSync("{{.ClientCertPath}}"),
  key: fs.readFileSync("{{.ClientKeyPath}}"),
  rejectUnauthorized: true,
});

https.get("https://{{.Host}}:{{.Port}}/", { agent }, (res) => {
  console.log("Status:", res.statusCode);
  res.on("data", (d) => process.stdout.write(d));
});
`,
	},
	"proxmox": {
		"deploy_proxmox_cert.sh": `#!/usr/bin/env bash
set -euo pipefail
# Deploy Custom CA / TLS Certificate to Proxmox VE Node ({{.Name}} - {{.Host}}:{{.Port}})
# Source CA: {{.CACertPath}} (Bundle: {{.LocalCACertPath}})
# Source Server Cert: {{.ServerCertPath}} (Bundle: {{.LocalServerCertPath}})
# Source Server Key: {{.ServerKeyPath}} (Bundle: {{.LocalServerKeyPath}})

PVE_NODE="${PVE_NODE:-$(hostname -s)}"
PVE_NODE_DIR="/etc/pve/nodes/${PVE_NODE}"

echo "[mgtls] Installing CA certificate from {{.CACertPath}} into system trust store..."
cp "{{.CACertPath}}" "/usr/local/share/ca-certificates/mgtls-{{.Name}}-ca.crt"
update-ca-certificates

echo "[mgtls] Deploying pveproxy TLS certificate & key to ${PVE_NODE_DIR}..."
install -m 0640 "{{.ServerCertPath}}" "${PVE_NODE_DIR}/pveproxy-ssl.pem"
install -m 0600 "{{.ServerKeyPath}}" "${PVE_NODE_DIR}/pveproxy-ssl.key"

echo "[mgtls] Restarting pveproxy on {{.Host}}:{{.Port}}..."
systemctl reload-or-restart pveproxy
echo "[mgtls] Proxmox VE TLS certificate deployment complete."
`,
		"proxmox_pveproxy_verify.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Proxmox VE API TLS & Certificate Chain at https://{{.Host}}:{{.Port}}/api2/json/version
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  "https://{{.Host}}:{{.Port}}/api2/json/version"

openssl s_client \
  -connect "{{.Host}}:{{.Port}}" \
  -servername "{{.Host}}" \
  -CAfile "{{.CACertPath}}" \
  </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
`,
		"README-proxmox.md": `# Proxmox VE TLS / ACME Deployment Guide ({{.Name}})

## Target Configuration
- **Proxmox Host**: ` + "`{{.Host}}`" + `
- **pveproxy Port**: ` + "`{{.Port}}`" + `
- **CA Certificate**: ` + "`{{.CACertPath}}`" + ` (Bundled: ` + "`{{.LocalCACertPath}}`" + `)
- **Node Certificate**: ` + "`{{.ServerCertPath}}`" + ` (Bundled: ` + "`{{.LocalServerCertPath}}`" + `)
- **Node Private Key**: ` + "`{{.ServerKeyPath}}`" + ` (Bundled: ` + "`{{.LocalServerKeyPath}}`" + `)

## 1. Deploy Certificate via Script
Run the generated deployment script on the Proxmox VE node:
` + "```bash\n./deploy_proxmox_cert.sh\n```" + `

## 2. Alternative: pvenode CLI Installation
` + "```bash\npvenode cert set {{.ServerCertPath}} {{.ServerKeyPath}} --force --restart\n```" + `

## 3. Verification
Verify ` + "`https://{{.Host}}:{{.Port}}/api2/json/version`" + ` using the custom CA:
` + "```bash\n./proxmox_pveproxy_verify.sh\n```" + `
`,
	},
	"openssh": {
		"sshd_ca.conf": `# OpenSSH Daemon (sshd_config.d) CA & Host Certificate Configuration ({{.Name}})
# Host: {{.Host}} | Port: {{.Port}}
# Trusted User CA Public Key: {{.CACertPath}} (Bundle: {{.LocalCACertPath}})
# Host Certificate: {{.ServerCertPath}} (Bundle: {{.LocalServerCertPath}})
# Host Private Key: {{.ServerKeyPath}} (Bundle: {{.LocalServerKeyPath}})

Port {{.Port}}
ListenAddress {{.Host}}
TrustedUserCAKeys {{.CACertPath}}
HostKey {{.ServerKeyPath}}
HostCertificate {{.ServerCertPath}}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
`,
		"ssh_client_ca.conf": `# OpenSSH Client Configuration & @cert-authority known_hosts ({{.Name}})
# Target Host: {{.Host}} | Port: {{.Port}}
# CA Public Key: {{.CACertPath}}
# User Certificate: {{.ClientCertPath}} (Bundle: {{.LocalClientCertPath}})
# User Private Key: {{.ClientKeyPath}} (Bundle: {{.LocalClientKeyPath}})
#
# Add to ~/.ssh/known_hosts:
# @cert-authority {{.Host}},*.{{.Host}} <contents-of-{{.CACertPath}}>

Host {{.Host}}
    HostName {{.Host}}
    Port {{.Port}}
    IdentityFile {{.ClientKeyPath}}
    CertificateFile {{.ClientCertPath}}
    IdentitiesOnly yes
`,
		"deploy_ssh_ca.sh": `#!/usr/bin/env bash
set -euo pipefail
# Deploy OpenSSH User CA and Host Certificate on {{.Host}}:{{.Port}} ({{.Name}})
# CA Key: {{.CACertPath}} | Host Cert: {{.ServerCertPath}} | Host Key: {{.ServerKeyPath}}
# Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
mkdir -p "${SSHD_DROPIN_DIR}"
install -m 0644 "{{.CACertPath}}" "/etc/ssh/mgtls_user_ca.pub"
install -m 0644 "{{.ServerCertPath}}" "/etc/ssh/mgtls_host_key-cert.pub"
install -m 0600 "{{.ServerKeyPath}}" "/etc/ssh/mgtls_host_key"
install -m 0644 "sshd_ca.conf" "${SSHD_DROPIN_DIR}/50-mgtls-ca.conf"

sshd -t
systemctl reload sshd || systemctl reload ssh
echo "[mgtls] OpenSSH CA configuration deployed for {{.Host}}:{{.Port}}."
`,
	},
	"caddy": {
		"Caddyfile": `# Caddy 2 TLS 1.3 & Mutual TLS Configuration ({{.Name}})
# Host: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} (Bundle: {{.LocalCACertPath}})
# Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
# Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

https://{{.Host}}:{{.Port}} {
	tls "{{.ServerCertPath}}" "{{.ServerKeyPath}}" {
		protocols tls1.2 tls1.3
		client_auth {
			mode {{if .MutualTLS}}require_and_verify{{else}}verify_if_given{{end}}
			trusted_ca_cert_file "{{.CACertPath}}"
		}
	}

	reverse_proxy {{index .Extra "upstream_url"}} {
		header_up X-SSL-Client-CN {http.request.tls.client.subject}
		header_up X-SSL-Client-Fingerprint {http.request.tls.client.fingerprint}
	}
}
`,
		"verify_caddy_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Caddy mTLS endpoint at https://{{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/"
`,
	},
	"traefik": {
		"traefik-dynamic-tls.yml": `# Traefik v3 Dynamic TLS & mTLS Configuration ({{.Name}})
# Host: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
# Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

http:
  routers:
    {{.Name}}-router:
      rule: "Host(` + "`{{.Host}}`" + `)"
      service: {{.Name}}-service
      tls:
        options: {{.Name}}-mtls-options

  services:
    {{.Name}}-service:
      loadBalancer:
        servers:
          - url: "{{index .Extra "upstream_url"}}"

tls:
  certificates:
    - certFile: "{{.ServerCertPath}}"
      keyFile: "{{.ServerKeyPath}}"
  options:
    {{.Name}}-mtls-options:
      minVersion: VersionTLS12
      clientAuth:
        caFiles:
          - "{{.CACertPath}}"
        clientAuthType: {{if .MutualTLS}}RequireAndVerifyClientCert{{else}}VerifyClientCertIfGiven{{end}}
`,
		"verify_traefik_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Traefik v3 mTLS router at https://{{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/"
`,
	},
	"envoy": {
		"envoy-mtls.yaml": `# Envoy Proxy Downstream mTLS & SPIFFE Configuration ({{.Name}})
# Listener: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
# Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

static_resources:
  listeners:
    - name: {{.Name}}_listener
      address:
        socket_address:
          address: {{.Host}}
          port_value: {{.Port}}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: {{.Name}}_ingress
                forward_client_cert_details: SANITIZE_SET
                set_current_client_cert_details:
                  subject: true
                  dns: true
                  uri: true
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: {{.Name}}_vhost
                      domains: ["{{.Host}}", "*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: {{.Name}}_upstream }
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              require_client_certificate: {{if .MutualTLS}}true{{else}}false{{end}}
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_2
                tls_certificates:
                  - certificate_chain: { filename: "{{.ServerCertPath}}" }
                    private_key: { filename: "{{.ServerKeyPath}}" }
                validation_context:
                  trusted_ca: { filename: "{{.CACertPath}}" }
`,
		"verify_envoy_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Envoy mTLS listener at https://{{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/"
`,
	},
	"postgres": {
		"postgresql-ssl.conf": `# PostgreSQL 16+ Server TLS/mTLS Configuration ({{.Name}})
# Host: {{.Host}} | Port: {{.Port}} | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

listen_addresses = '{{.Host}}'
port = {{.Port}}
ssl = on
ssl_ca_file = '{{.CACertPath}}'
ssl_cert_file = '{{.ServerCertPath}}'
ssl_key_file = '{{.ServerKeyPath}}'
ssl_min_protocol_version = 'TLSv1.2'
`,
		"pg_hba_mtls.conf": `# PostgreSQL pg_hba.conf Client Certificate Enforcement ({{.Name}})
# TYPE  DATABASE        USER            ADDRESS                 METHOD
hostssl all             all             0.0.0.0/0               {{if .MutualTLS}}cert clientcert=verify-full{{else}}scram-sha-256{{end}}
hostssl all             all             ::/0                    {{if .MutualTLS}}cert clientcert=verify-full{{else}}scram-sha-256{{end}}
`,
		"verify_postgres_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify PostgreSQL TLS/mTLS connection at {{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

PGSSLMODE="{{if .MutualTLS}}verify-full{{else}}verify-ca{{end}}" \
PGSSLROOTCERT="{{.CACertPath}}" \
PGSSLCERT="{{.ClientCertPath}}" \
PGSSLKEY="{{.ClientKeyPath}}" \
psql "host={{.Host}} port={{.Port}} dbname=postgres" -c "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
`,
	},
	"redis": {
		"redis-tls.conf": `# Redis 7+ / Valkey TLS & Mutual TLS Configuration ({{.Name}})
# Host: {{.Host}} | TLS Port: {{.Port}} | MutualTLS: {{.MutualTLS}}
# CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}

bind {{.Host}}
port 0
tls-port {{.Port}}
tls-cert-file "{{.ServerCertPath}}"
tls-key-file "{{.ServerKeyPath}}"
tls-ca-cert-file "{{.CACertPath}}"
tls-auth-clients {{if .MutualTLS}}yes{{else}}optional{{end}}
tls-protocols "TLSv1.2 TLSv1.3"
`,
		"verify_redis_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Redis TLS/mTLS connection at {{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

redis-cli --tls \
  -h "{{.Host}}" \
  -p "{{.Port}}" \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  PING
`,
	},
	"grpc-go": {
		"grpc_mtls.go": `// Go gRPC TLS 1.3 & Mutual TLS Credentials Helper ({{.Name}})
// Endpoint: {{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
// CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
// Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}
package grpcmtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func ServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("{{.ServerCertPath}}", "{{.ServerKeyPath}}")
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile("{{.CACertPath}}")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA from {{.CACertPath}}")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   {{if .MutualTLS}}tls.RequireAndVerifyClientCert{{else}}tls.VerifyClientCertIfGiven{{end}},
	}, nil
}

func ClientTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("{{.ClientCertPath}}", "{{.ClientKeyPath}}")
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile("{{.CACertPath}}")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   "{{.Host}}",
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}
`,
		"verify_grpc_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify gRPC TLS/mTLS endpoint at {{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

grpcurl \
  -cacert "{{.CACertPath}}" \
  -cert "{{.ClientCertPath}}" \
  -key "{{.ClientKeyPath}}" \
  "{{.Host}}:{{.Port}}" list
`,
	},
	"nodejs-express": {
		"server_mtls.mjs": `// Node.js HTTPS / Express Mutual TLS Server ({{.Name}})
// Endpoint: https://{{.Host}}:{{.Port}} | MutualTLS: {{.MutualTLS}}
// CA: {{.CACertPath}} | Server Cert: {{.ServerCertPath}} | Server Key: {{.ServerKeyPath}}
// Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

import fs from "node:fs";
import https from "node:https";

const options = {
  ca: fs.readFileSync("{{.CACertPath}}"),
  cert: fs.readFileSync("{{.ServerCertPath}}"),
  key: fs.readFileSync("{{.ServerKeyPath}}"),
  requestCert: true,
  rejectUnauthorized: {{if .MutualTLS}}true{{else}}false{{end}},
  minVersion: "TLSv1.2",
};

const server = https.createServer(options, (req, res) => {
  const cert = req.socket.getPeerCertificate();
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    status: "ok",
    service: "{{.Name}}",
    host: "{{.Host}}",
    port: {{.Port}},
    clientCN: cert?.subject?.CN ?? "anonymous",
  }));
});

server.listen({{.Port}}, "{{.Host}}", () => {
  console.log("Node.js mTLS server listening on https://{{.Host}}:{{.Port}}");
});
`,
		"verify_node_mtls.sh": `#!/usr/bin/env bash
set -euo pipefail
# Verify Node.js HTTPS/mTLS server at https://{{.Host}}:{{.Port}}
# CA: {{.CACertPath}} | Client Cert: {{.ClientCertPath}} | Client Key: {{.ClientKeyPath}}

curl --fail --silent --show-error \
  --cacert "{{.CACertPath}}" \
  --cert "{{.ClientCertPath}}" \
  --key "{{.ClientKeyPath}}" \
  "https://{{.Host}}:{{.Port}}/"
`,
	},
}
