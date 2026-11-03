# `mgtls` Capabilities Manifest (`v1.0.0`)

Machine-readable manifest: [`docs/capabilities.json`](capabilities.json)

## Operational Capabilities (`v1.0.0`)

| ID | Capability | Package / Path | Status | Verification Command |
| :--- | :--- | :--- | :--- | :--- |
| `CAP-PKI-001` | **Multi-Tier X.509 PKI & Mutual TLS (mTLS)** (Root/Intermediate CAs, Self-Signed, Server/Client/mTLS leaves, PKCS#12, CRL v2, OS trust scripts) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |
| `CAP-SSH-001` | **OpenSSH User & Host Certificate Authorities** (`SSH_CERT_TYPE_USER`, `SSH_CERT_TYPE_HOST`, principal signing, `sshd_config`, `@cert-authority`) | `src/pkg/sshca` | `operational` | `go test -race ./src/pkg/sshca` |
| `CAP-ACME-001` | **RFC 8555 ACME v2 Client & Mock Server** (`letsencrypt`, `zerossl`, `buypass`, `google`, `custom`; `HTTP-01`, `TLS-ALPN-01`, `DNS-01`, EAB) | `src/pkg/acme` | `operational` | `go test -race ./src/pkg/acme` |
| `CAP-TARGETS-001` | **7 Target Platform Generators** (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`) | `src/pkg/targets` | `operational` | `go test -race ./src/pkg/targets` |
| `CAP-PROFILE-001` | **Declarative Fleet Engine & Health Auditor** (`mgtls apply -f mgtls.yaml`, `mgtls status`, `mgtls doctor`) | `src/pkg/profile` | `operational` | `go test -race ./src/pkg/profile` |
| `CAP-MCP-001` | **MCP JSON-RPC 2.0 Server** (`mgtls mcp serve` over `stdio` & mTLS HTTPS; 18 tools, 3 resources, 3 prompts) | `src/pkg/mcpserver` | `operational` | `go test -race ./src/pkg/mcpserver` |
| `CAP-COOKBOOKS-001` | **Executable Cookbooks & IaC / CI-CD Flows** (5 runnable `.sh` cookbooks, Terraform, Ansible, Kubernetes Secrets, Docker Compose, GitHub Actions, GitLab CI) | `cookbooks/` | `operational` | `./cookbooks/05-iac-and-cicd-integration.sh` |

## Planned Capabilities (`v1.1.0`)

| ID | Capability | Target Release | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| `CAP-HSM-001` | **PKCS#11 & YubiKey PIV Hardware Token Root CA Signing** | `v1.1.0` | `planned` | Non-exportable hardware-backed Root CA and OpenSSH CA signing keys via PKCS#11 and PIV smartcards |
