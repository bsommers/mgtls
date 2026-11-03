# Changelog

All notable changes to `mgtls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-02

### Added
- **Source Layout (`src/cmd/mgtls`, `src/pkg/*`)**: Zero-CGO (`CGO_ENABLED=0`) Go 1.26 codebase organized under `src/` with atomic `.mgtls` workspace persistence (`0700` directories, `0600` private keys, `0644` public artifacts).
- **Multi-Tier X.509 PKI & Mutual TLS (`src/pkg/pki`)**: Root CAs, Intermediate CAs (`fullchain.pem`, `ca-chain.pem`), standalone self-signed certificates, Server/Client/Dual-mTLS leaf certificates (`Ed25519`, `ECDSA P-256`, `ECDSA P-384`, `RSA-2048`, `RSA-4096`), DNS/IP/Email/SPIFFE URI SANs, PKCS#12 (`.p12`) & DER bundles, X.509 v2 CRLs, and OS trust store installers (`debian`, `rhel`, `arch`, `macos`, `windows`).
- **OpenSSH Certificate Authority Engine (`src/pkg/sshca`)**: Dedicated OpenSSH User CAs (`SSH_CERT_TYPE_USER`) and Host CAs (`SSH_CERT_TYPE_HOST`), principal/validity/extension key signing (`*-cert.pub`), certificate inspection, and automated `sshd_config`, `ssh_config`, `authorized_principals`, and `@cert-authority` `known_hosts` bundles.
- **RFC 8555 ACME v2 Public Encryption (`src/pkg/acme`)**: Built-in support for **Let's Encrypt** (Production & Staging), **ZeroSSL** (with EAB), **Buypass Go SSL**, **Google Trust Services** (with EAB), and custom ACME v2 directories (`HTTP-01`, `TLS-ALPN-01`, `DNS-01`), plus an in-memory RFC 8555 mock server.
- **7 Platform Target Generators (`src/pkg/targets`)**: Ready-to-run TLS 1.3 and mTLS server/client configurations and verification scripts for **FastAPI**, **Spring Boot 3.2+**, **MCP Server**, **NGINX**, **Vite**, **Proxmox VE (`pveproxy`)**, and **OpenSSH**.
- **Declarative Fleet Reconciliation & Health Auditing (`src/pkg/profile`)**: Idempotent `mgtls apply -f mgtls.yaml` reconciliation, `mgtls status` JSON inventory, and `mgtls doctor` expiration, revocation, and `0600` key-permission auditing.
- **Model Context Protocol (MCP) Server (`src/pkg/mcpserver`)**: JSON-RPC 2.0 MCP `2024-11-05` server (`mgtls mcp serve`) over `stdio` and HTTP/HTTPS/mTLS (`RequireAndVerifyClientCert`) exposing 18 tools, 3 resources, and 3 guided prompts.
- **Executable Cookbooks & IaC / CI-CD Flows (`cookbooks/`, `docs/cookbooks/`)**: 5 runnable cookbook scripts (`01` through `05`) plus Terraform/OpenTofu external data source bridge, Ansible fleet playbook, Kubernetes TLS Secret generator, Docker Compose mTLS stack, and GitHub Actions / GitLab CI templates.
- **Branding & GitHub Pages Portal (`assets/`, `docs/index.html`)**: Vector SVG/PNG/ASCII logos and icons plus interactive dark-mode documentation portal.

### Verification Telemetry
- **Test Suite**: `go test -race -count=1 ./src/...` — 8/8 packages passing (`src/cmd/mgtls`, `src/pkg/acme`, `src/pkg/mcpserver`, `src/pkg/pki`, `src/pkg/profile`, `src/pkg/sshca`, `src/pkg/store`, `src/pkg/targets`), 0 failures.
- **Cookbooks**: 5/5 executable cookbooks (`cookbooks/01-*.sh` through `cookbooks/05-*.sh`) verified end-to-end.
