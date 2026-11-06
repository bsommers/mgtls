# `mgtls` Capabilities Manifest (`v1.1.1`)

Machine-readable manifest: [`docs/capabilities.json`](capabilities.json)

- **Total Capabilities**: `9`
- **Operational**: `8`
- **Beta**: `0`
- **Planned**: `1`

## Operational Capabilities (`v1.1.1`)

| ID | Capability | Package / Path | Status | Verification Command |
| :--- | :--- | :--- | :--- | :--- |
| `CAP-PKI-001` | **Multi-Tier X.509 PKI & Mutual TLS (mTLS)** (Root/Intermediate CAs, Self-Signed, Server/Client/mTLS leaves, PKCS#12, CRL v2, OS trust scripts) | `src/pkg/pki` | `operational` | `go test -race ./src/pkg/pki` |
| `CAP-SSH-001` | **OpenSSH User & Host Certificate Authorities** (`SSH_CERT_TYPE_USER`, `SSH_CERT_TYPE_HOST`, principal signing, `sshd_config`, `@cert-authority`) | `src/pkg/sshca` | `operational` | `go test -race ./src/pkg/sshca` |
| `CAP-ACME-001` | **RFC 8555 ACME v2 Client & Mock Server** (`letsencrypt`, `zerossl`, `buypass`, `google`, `custom`; `HTTP-01`, `TLS-ALPN-01`, `DNS-01`, EAB) | `src/pkg/acme` | `operational` | `go test -race ./src/pkg/acme` |
| `CAP-TARGETS-001` | **14 Target Platform Generators** (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`, `caddy`, `traefik`, `envoy`, `postgres`, `redis`, `grpc-go`, `nodejs-express`) | `src/pkg/targets` | `operational` | `go test -race ./src/pkg/targets` |
| `CAP-PROFILE-001` | **Declarative Fleet Engine, Health Auditor & Renewal Daemon** (`mgtls apply -f mgtls.yaml`, `mgtls status`, `mgtls doctor`, `mgtls watch`, `mgtls systemd generate`) | `src/pkg/profile` | `operational` | `go test -race ./src/pkg/profile` |
| `CAP-MCP-001` | **MCP JSON-RPC 2.0 Server** (`mgtls mcp serve` over `stdio` & mTLS HTTPS; 18 tools, 3 resources, 3 prompts) | `src/pkg/mcpserver` | `operational` | `go test -race ./src/pkg/mcpserver` |
| `CAP-COOKBOOKS-001` | **Executable Cookbooks & IaC / CI-CD Flows** (5 runnable `.sh` cookbooks, Terraform, Ansible, Kubernetes Secrets, Docker Compose, GitHub Actions, GitLab CI) | `cookbooks/` | `operational` | `./cookbooks/05-iac-and-cicd-integration.sh` |
| `CAP-TEST-001` | **Full E2E Examples, Cookbooks & Shell Test-Quality Verification Harness** (`83.2%` coverage, 56 test cases/subtests, mocked PATH & injection safety gates) | `src/test/e2e` | `operational` | `go test -v -race ./src/test/e2e` |

## Planned Capabilities (`v1.2.0`)

| ID | Capability | Target Release | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| `CAP-HSM-001` | **PKCS#11 & YubiKey PIV Hardware Token Root CA Signing** | `v1.2.0` | `planned` | Non-exportable hardware-backed Root CA and OpenSSH CA signing keys via PKCS#11 and PIV smartcards |
