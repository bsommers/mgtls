# Roadmap — `mgtls`

## Phase 1: Foundation, GSD Onboarding & Store Contract
- Initialize Git repository, Go module (`github.com/sysadmin/mgtls`), and GSD `.planning/` artifacts.
- Implement `pkg/store` (workspace management, key permission enforcement, atomic manifest persistence) and verify unit tests.

## Phase 2: Parallel Core Subsystem Implementation (Wave 1 Subagents)
- **Track 2A (`pkg/pki`)**: Root CA, Intermediate CA chains, self-signed certs, Server/Client/mTLS certs, CRL, PKCS#12/DER/PEM bundles, trust store scripts, and live TLS/mTLS handshake tests.
- **Track 2B (`pkg/sshca`)**: OpenSSH User & Host CA generation, keypair generation, user/host certificate signing, inspection, `sshd_config`/`known_hosts` generation, and `golang.org/x/crypto/ssh` `CertChecker` verification tests.
- **Track 2C (`pkg/acme`)**: ACME v2 RFC 8555 client (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, EAB, HTTP-01, TLS-ALPN-01, DNS-01) + mock RFC 8555 ACME server and end-to-end order/issuance tests.
- **Track 2D (`pkg/targets`)**: Scaffolding generators and templates for `fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, and `openssh` with unit tests.

## Phase 3: Orchestration, MCP Server & CLI Implementation (Wave 2 Subagents)
- **Track 3A (`pkg/profile`)**: Declarative YAML/JSON fleet manifest parser, validator, and idempotent applier + health doctor (`mgtls.yaml`).
- **Track 3B (`pkg/mcpserver`)**: Model Context Protocol (MCP) JSON-RPC 2.0 server (`stdio` and HTTP/mTLS transports) exposing tools, resources, and prompts for AI agents.
- **Track 3C (`cmd/mgtls`)**: Full CLI integration wiring all packages (`init`, `ca`, `cert`, `ssh`, `acme`, `target`, `apply`, `status`, `doctor`, `mcp`).

## Phase 4: End-to-End Examples, System Documentation & User Guides (Wave 3 Subagents)
- **Track 4A (`examples/` & `test/e2e/`)**: Complete runnable example use cases (FastAPI mTLS, Spring Boot mTLS, MCP Server mTLS, NGINX mTLS, Vite HTTPS/mTLS, Proxmox VE TLS, OpenSSH CA fleet, and multi-stack `mgtls.yaml`) + E2E CLI & MCP integration test suite.
- **Track 4B (`docs/` & `README.md`)**: Full System Architecture & Specification Documentation (`docs/architecture/`, `docs/specs/`) and Full User Guide Documentation (`docs/user-guide/`).
