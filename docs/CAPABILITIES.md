# `mgtls` Capabilities Manifest (`v1.3.0`)

Machine-readable manifest: [`docs/capabilities.json`](capabilities.json)

- **Total Capabilities**: `19`
- **Operational**: `16`
- **Beta**: `0`
- **Planned**: `3`

## Operational Capabilities (`v1.3.0+`)

| ID | Capability | Package / Path | Status | Verification Command |
| :--- | :--- | :--- | :--- | :--- |
| `CAP-PKI-001` | **Multi-Tier X.509 PKI & Mutual TLS (mTLS)** (Root/Intermediate CAs, Self-Signed, Server/Client/mTLS leaves, PKCS#12, CRL v2, OS trust scripts) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |
| `CAP-SSH-001` | **OpenSSH User & Host Certificate Authorities** (`SSH_CERT_TYPE_USER`, `SSH_CERT_TYPE_HOST`, principal signing, `sshd_config`, `@cert-authority`) | `src/pkg/sshca` | `operational` | `go test -race ./src/pkg/sshca` |
| `CAP-ACME-001` | **RFC 8555 ACME v2 Client & Mock Server** (`letsencrypt`, `zerossl`, `buypass`, `google`, `custom`; `HTTP-01`, `TLS-ALPN-01`, `DNS-01`, EAB) | `src/pkg/acme` | `operational` | `go test -race ./src/pkg/acme` |
| `CAP-TARGETS-001` | **14 Target Platform Generators** (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`, `caddy`, `traefik`, `envoy`, `postgres`, `redis`, `grpc-go`, `nodejs-express`) | `src/pkg/targets` | `operational` | `go test -race ./src/pkg/targets` |
| `CAP-PROFILE-001` | **Declarative Fleet Engine & Health Auditor** (`mgtls apply -f mgtls.yaml`, `mgtls status`, `mgtls doctor`) | `src/pkg/profile` | `operational` | `go test -race ./src/pkg/profile` |
| `CAP-MCP-001` | **MCP JSON-RPC 2.0 Server** (`mgtls mcp serve` over `stdio` & mTLS HTTPS; 21 tools, 3 resources, 3 prompts) | `src/pkg/mcpserver` | `operational` | `go test -race ./src/pkg/mcpserver` |
| `CAP-COOKBOOKS-001` | **Executable Cookbooks & IaC / CI-CD Flows** (5 runnable `.sh` cookbooks, Terraform, Ansible, Kubernetes Secrets, Docker Compose, GitHub Actions, GitLab CI) | `cookbooks/` | `operational` | `./cookbooks/05-iac-and-cicd-integration.sh` |
| `CAP-TEST-001` | **Full E2E Examples, Cookbooks & Shell Test-Quality Verification Harness** (`83.2%+` coverage, 60+ test cases/subtests, mocked PATH & injection safety gates) | `src/test/e2e` | `operational` | `go test -v -race ./src/test/e2e` |
| `CAP-DIST-001` | **Multi-Target Installer, Scratch Container & Onboarding** (`install.sh`, `Dockerfile`, `mgtls guide`, `mgtls init --starter --yes`) | `install.sh`, `Dockerfile` | `operational` | `go test -race ./src/cmd/mgtls` |
| `CAP-WATCH-001` | **Autonomous Renewal Daemon & `systemd` Generator** (`mgtls watch`, `--on-renew`, `mgtls systemd generate`) | `src/pkg/profile` | `operational` | `go test -race ./src/pkg/profile` |
| `CAP-HSM-001` | **Hardware-Backed Root CA, KMS & `ssh-agent` Signer Seams** (`crypto.Signer` & `ssh.Signer` non-exportable CA signing + `SSH_AUTH_SOCK` agent support) | `src/pkg/pki`, `src/pkg/sshca` | `operational` | `go test -race ./src/pkg/pki ./src/pkg/sshca` |
| `CAP-PROBE-001` | **Live TLS & Mutual TLS Endpoint Prober & Cipher Auditor** (`mgtls probe --addr host:port`, `--strict`, and MCP tool `pki_probe`) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |
| `CAP-OCSP-001` | **RFC 6960 OCSP Responder & Stapling Verification Engine** (`mgtls ocsp serve`, `mgtls ocsp verify`, RFC 6960 §4.2.2.2 Ed25519 delegated OCSP signing, and MCP tool `pki_ocsp_verify` — 20 MCP tools total) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |
| `CAP-CSR-001` | **PKCS#10 CSR Workflow & External CA Signing** (`mgtls csr create`, `mgtls csr sign`, MCP tool `pki_csr_sign` — 21 MCP tools total; leaf key never held by mgtls) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |
| `CAP-VAULT-001` | **Encrypted-at-Rest CA Key Vault** (AES-256-GCM envelope, scrypt/HKDF KEK via `MGTLS_PASSPHRASE`/`MGTLS_KEYFILE`, `mgtls vault status|seal|unseal|rotate`) | `src/pkg/store` | `operational` | `go test -race ./src/pkg/store` |
| `CAP-EST-001` | **RFC 7030 Enrollment over Secure Transport (EST) Server & Client** (`mgtls est serve|cacerts|enroll|reenroll`, PKCS#7 `certs-only` DER, constant-time token & mTLS auth, MCP `pki_est_enroll` — 22 MCP tools total) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |

## Planned Capabilities (`v1.4.0`)

| ID | Capability | Target Version | Status |
| :--- | :--- | :--- | :--- |
| `CAP-SPIFFE-001` | **SPIFFE / SPIRE X.509-SVID & Trust Bundle Support** | `v1.4.0` | `planned` |
| `CAP-AUDIT-001` | **Tamper-Evident Cryptographic Audit Log (Hash-Chained Ledger)** | `v1.4.0` | `planned` |
| `CAP-SCAN-001` | **Trust Bundle Compiler & Multi-Endpoint TLS Scanner** | `v1.4.0` | `planned` |
