# Project State & Session Checkpoint — `mgtls`

- **Current Phase**: Completed (All 4 Phases Verified Green)
- **Language / Runtime**: Go 1.26 (`github.com/sysadmin/mgtls`), Pure Go (`CGO_ENABLED=0`)
- **Binary**: `bin/mgtls`
- **User Decisions (Verbatim)**:
  - Go (`go1.26`) implementation
  - Full PKI & mTLS (Root/Intermediate CA chains, self-signed certs, Server/Client mTLS certs, CRL, OS trust scripts)
  - OpenSSH CA & Certificates (User CA, Host CA, signed OpenSSH certs, `sshd_config`/`ssh_config`/`known_hosts`/`authorized_principals`)
  - ACME v2 & Free Public CAs (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services via HTTP-01, TLS-ALPN-01, DNS-01)
  - Target Framework & Server Scaffolding (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`)
  - Callable through both CLI (`mgtls ...`) and Model Context Protocol Server (`mgtls mcp serve` over `stdio` and `http`/`https`/`mtls`)
- **Verification Status**:
  - `CGO_ENABLED=0 go build -o bin/mgtls ./cmd/mgtls` → `0`
  - `go test -v -race -count=1 ./...` → `PASS` across all 7 packages (`cmd/mgtls`, `pkg/store`, `pkg/pki`, `pkg/sshca`, `pkg/acme`, `pkg/targets`, `pkg/profile`, `pkg/mcpserver`)
