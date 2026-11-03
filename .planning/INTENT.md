# Intent: mgtls — Unified TLS, mTLS, CA Chain, OpenSSH CA & ACME Manager (CLI + MCP)

**Problem / who it's for:** Systems administrators, backend/platform engineers, and AI agents who need to rapidly stand up secure TLS, mutual TLS (mTLS), local CA hierarchies, OpenSSH certificate authorities, and free public ACME certificates across heterogeneous services (FastAPI, Spring Boot, MCP servers, NGINX, Vite, Proxmox VE, OpenSSH) without error-prone `openssl`/`ssh-keygen` incantations.

**Outcome & success criteria:**
1. Single static Go (`go1.26`) binary `mgtls` builds cleanly with zero CGO dependencies (`CGO_ENABLED=0 go build ./cmd/mgtls`).
2. 100% passing unit and end-to-end integration test suites (`go test -v -race ./...`), including real in-memory mTLS handshakes, SSH certificate verification, and full RFC 8555 ACME issuance against a local ACME test server.
3. Built-in MCP Server (`mgtls mcp serve`) implements JSON-RPC 2.0 MCP protocol (`initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`) exposing all PKI, SSH CA, ACME, Target, and Declarative Fleet operations.
4. Generates complete, verified setups for all 7 target platforms (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`) plus runnable example projects (`examples/`), comprehensive system architecture documentation (`docs/architecture/`, `docs/specs/`), and full user guides (`docs/user-guide/`).

**In scope:**
- Local X.509 Root CA, Intermediate CA chains, self-signed certs, Server/Client/Dual mTLS certs, CRLs, PEM/DER/PKCS#12 bundles, OS trust store install scripts (`pkg/pki`).
- OpenSSH User CA & Host CA creation, key signing (`*-cert.pub`), certificate inspection, and `sshd_config`/`ssh_config`/`known_hosts` generation (`pkg/sshca`).
- RFC 8555 ACME v2 client supporting Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, and custom ACME URLs via HTTP-01, TLS-ALPN-01, and DNS-01 (`pkg/acme`).
- Target scaffolding generators (`pkg/targets`) for FastAPI, Spring Boot, MCP servers, NGINX, Vite, Proxmox VE, and OpenSSH.
- Declarative YAML/JSON manifest engine (`pkg/profile`) and full CLI + MCP Server (`pkg/mcpserver`, `cmd/mgtls`).

**Out of scope:**
- Hardware HSM PKCS#11 C-library bindings requiring CGO (keep binary 100% pure Go and cross-compilable).
- Proprietary commercial CA REST APIs outside standard RFC 8555 ACME v2 (e.g., legacy DigiCert SOAP APIs).

**Constraints:**
- Language: Go 1.26 (`github.com/sysadmin/mgtls`).
- Strict file permissions: `0600` on all private keys, `0644` on public certificates and configurations.
- Zero external runtime binary dependencies required for core X.509, SSH CA, ACME, or MCP operations.
