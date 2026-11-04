# Changelog

All notable changes to `mgtls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-03

### Added
- **End-to-End Examples, Cookbooks & Shell Test-Quality Verification Suite (`src/test/e2e/e2e_test.go`)**: Automated Go test harness executing all 5 `cookbooks/*.sh` scripts, all 8 `examples/*` workflows, the Terraform external data source bridge (`cookbooks/iac-cicd/terraform/mgtls-external.sh`), and the 4 Shell Test-Quality Checklist invariants (`bash -euo pipefail` reachability, mocked `PATH` binaries for `pvenode`/`systemctl`/`update-ca-certificates`/`update-ca-trust`/`security`, command-string injection safety, and dispatch-table completeness).
- **Comprehensive Unit & Negative-Path Test Expansion (`src/pkg/*/*_test.go`, `src/cmd/mgtls/main_test.go`)**: Expanded total test suite from 23 to 56 test functions & subtests, raising cross-package statement coverage to **83.1%** (`98.8%` Go function reachability, `100%` example/cookbook script reachability).
- **Test Coverage & Suite Robustness Report (`docs/TEST_COVERAGE.md`)**: Detailed step-by-step test execution telemetry, per-package coverage deltas, and P0/P1/P2 gap remediation documentation.
- **Open-Source Ecosystem Comparison & ASCII Capability Heatmap (`docs/architecture/ECOSYSTEM_COMPARISON.md`, `README.md`, `docs/index.html`)**: Side-by-side comparison matrix and ASCII capability heatmap against `Smallstep (step-ca/step-cli)`, `HashiCorp Vault / OpenBao`, `Cloudflare cfssl`, `Square certstrap`, `OpenVPN easy-rsa`, `FiloSottile mkcert`, and `lego / certbot / acme.sh`.
- **Expanded Purpose & Problem Statement Documentation**: Detailed problem statement, before/after comparison tables, and target personas across `README.md`, `docs/index.html`, `docs/user-guide/USER_GUIDE.md`, and `docs/architecture/SYSTEM_ARCHITECTURE.md`.

### Verification Telemetry
- **Test Suite**: `go test -v -race -coverpkg=./src/... ./src/...` — 9/9 packages passing (`56/56` test functions & subtests), `83.1%` cross-package statement coverage (`82.9%` package-local), `98.8%` Go function reachability (`85/86`), `100%` shell cookbook/example reachability (`14/14`).

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
