# Requirements Specification — `mgtls`

## Functional Requirements

### FR-1: Workspace & State Store (`pkg/store`)
- **FR-1.1**: Maintain a structured workspace directory (default `.mgtls` or `--store-dir`) with isolated subdirectories (`ca/`, `certs/`, `ssh/`, `acme/`, `targets/`).
- **FR-1.2**: Enforce `0700` on private directories, `0600` on private key files, and `0644` on public certificates and generated configs.
- **FR-1.3**: Persist an atomic JSON inventory manifest (`manifest.json`) tracking all managed CAs, certificates, SSH CAs/certs, ACME accounts/orders, and target bundles.

### FR-2: X.509 PKI, Local CAs, Self-Signed & mTLS (`pkg/pki`)
- **FR-2.1**: Generate Root CAs and Intermediate CAs (chained to Root or parent Intermediate) using `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, or `rsa-4096`.
- **FR-2.2**: Generate standalone self-signed certificates for rapid single-node TLS.
- **FR-2.3**: Issue leaf certificates with role profiles (`server`, `client`, `mtls`/`dual`) and Subject Alternative Names (DNS names, IPv4/IPv6 addresses, URIs, Email addresses).
- **FR-2.4**: Assemble complete certificate chains (`fullchain.pem` = leaf + intermediates, `ca-chain.pem` = intermediates + root) and export DER and PKCS#12/PFX bundles.
- **FR-2.5**: Inspect any PEM certificate and verify certificate chains + mTLS key usages against a CA bundle and optional CRL.
- **FR-2.6**: Generate certificate revocation lists (CRLs) and OS-specific trust store installation scripts (Debian/Ubuntu, RHEL/Fedora, Arch, macOS, Windows).

### FR-3: OpenSSH Certificate Authority (`pkg/sshca`)
- **FR-3.1**: Generate dedicated OpenSSH User CA and Host CA keypairs (`ed25519`, `ecdsa-p256`, `rsa-4096`).
- **FR-3.2**: Generate SSH user/host keypairs if not already present, and sign SSH User certificates (`SSH_CERT_TYPE_USER`) and Host certificates (`SSH_CERT_TYPE_HOST`) with principals, validity windows, key IDs, critical options, and extensions.
- **FR-3.3**: Parse and inspect OpenSSH `-cert.pub` files with full metadata (serial, type, key ID, principals, valid after/before, CA fingerprint, extensions).
- **FR-3.4**: Generate `sshd_config`, `ssh_config`, `authorized_principals`, and `@cert-authority` `known_hosts` configurations.

### FR-4: Public Free Encryption & ACME v2 (`pkg/acme`)
- **FR-4.1**: Built-in provider catalog for Let's Encrypt (Prod & Staging), ZeroSSL, Buypass, Google Trust Services, and custom RFC 8555 directory URLs.
- **FR-4.2**: RFC 8555 ACME v2 client supporting ES256 JWS signing, Replay-Nonce management, account registration, External Account Binding (EAB HMAC-SHA256 for ZeroSSL/Google), and order lifecycle.
- **FR-4.3**: Support HTTP-01 (built-in listener + webroot writer), TLS-ALPN-01 (`acme-tls/1` critical extension `1.3.6.1.5.5.7.1.31`), and DNS-01 (TXT record value computation + hook command execution).
- **FR-4.4**: Include an in-memory RFC 8555 compliant mock ACME server (`pkg/acme/mockserver`) for deterministic end-to-end automated testing.

### FR-5: Target Framework & Server Scaffolding (`pkg/targets`)
- **FR-5.1**: Render complete, ready-to-run TLS and mTLS configurations, code integrations, and verification scripts for:
  1. `fastapi`: FastAPI server + Uvicorn TLS/mTLS launcher + `httpx` mTLS client + client cert DN extractor.
  2. `springboot`: Spring Boot 3 `application.yml` with SSL bundles (`server.ssl.bundle`, `client-auth: need`) + Java `RestClient` mTLS snippet.
  3. `mcp`: Model Context Protocol server + client mTLS setups (Node/TS SSE-HTTPS mTLS server, Python FastMCP mTLS server, and Claude/MCP client config).
  4. `nginx`: Production `nginx.conf` with TLS 1.3, `ssl_verify_client on`, `ssl_client_certificate`, and upstream identity headers.
  5. `vite`: `vite.config.ts` with `server.https` (`key`, `cert`, `ca`, `requestCert`, `rejectUnauthorized`).
  6. `proxmox`: Proxmox VE node certificate deployment script (`pvenode cert set` / `/etc/pve/local/pveproxy-ssl.pem` + `pveproxy` reload).
  7. `openssh`: End-to-end OpenSSH CA server & client setup bundle.

### FR-6: Declarative Fleet Engine (`pkg/profile`)
- **FR-6.1**: Parse YAML/JSON declarative manifests (`mgtls.yaml`) specifying CAs, Intermediates, Leaf Certs, SSH CAs, SSH Certs, ACME Certs, and Targets.
- **FR-6.2**: Execute declarative reconciliation (`mgtls apply -f mgtls.yaml`) and health/expiry auditing (`mgtls status`, `mgtls doctor`).

### FR-7: Built-in MCP Server (`pkg/mcpserver`) & CLI (`cmd/mgtls`)
- **FR-7.1**: Expose a complete CLI (`mgtls`) with human-readable and `--json` outputs across all domains.
- **FR-7.2**: Expose a standards-compliant MCP Server (`mgtls mcp serve`) supporting `stdio` and HTTP/HTTPS (with optional mTLS!) transports, providing MCP Tools (`pki_create_ca`, `pki_issue_cert`, `pki_self_sign`, `pki_inspect`, `pki_verify`, `ssh_create_ca`, `ssh_sign_cert`, `ssh_inspect`, `acme_providers`, `acme_obtain`, `target_generate`, `profile_apply`, `store_status`), MCP Resources (`mgtls://store/manifest`, `mgtls://targets/catalog`, `mgtls://acme/providers`), and MCP Prompts (`setup-mtls-service`, `setup-ssh-ca`, `setup-proxmox-tls`).
