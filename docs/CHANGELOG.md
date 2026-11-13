# Changelog

All notable changes to `mgtls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-11-13

### Added
- **RFC 7030 EST server & client (`CAP-EST-001`)**: `mgtls est serve|cacerts|enroll|reenroll`, PKCS#7 `certs-only`, token + mTLS auth; MCP `pki_est_enroll`.
- **SPIFFE X.509-SVID & trust bundles (`CAP-SPIFFE-001`)**: `mgtls svid issue|verify`, `mgtls bundle export --format spiffe|pem`; MCP `pki_svid_issue`.
- **Tamper-evident audit ledger (`CAP-AUDIT-001`)**: SHA-256 hash-chained `<store>/audit.jsonl` (CA/cert/CSR/EST/revoke/vault events); `mgtls audit list|verify [--expect-head]`; MCP `pki_audit_verify`. Single-writer; pin head hash to detect tail truncation.
- **Trust bundle compiler & TLS scanner (`CAP-SCAN-001`)**: `mgtls bundle compile` (pem/p7b/p12 truststore), `mgtls scan --targets|--targets-file [--strict]`; MCP `pki_scan` (25 MCP tools total).

### Verification Telemetry
- `go vet ./...` clean; `go test -count=1 -race ./src/...` 9/9 packages passing.

## [1.3.0] - 2026-11-08

### Added
- **Live TLS & Mutual TLS Endpoint Prober & Cipher Auditor (`src/pkg/pki/probe.go` — `CAP-PROBE-001`)**: `mgtls probe --addr host:port` (`--sni`, `--ca`, `--cert`, `--strict`, `--timeout`) and MCP tool `pki_probe` to connect to live TLS/mTLS endpoints, inspect negotiated TLS version/cipher suite/ALPN, verify peer chain against `.mgtls` CAs, check SANs/expiry, and emit JSON diagnostics.
- **RFC 6960 OCSP Responder & Stapling Verification Engine (`src/pkg/pki/ocsp.go` — `CAP-OCSP-001`)**: `mgtls ocsp serve` (HTTP POST/GET responder with RFC 6960 §4.2.2.2 delegated OCSP signing for `Ed25519` CAs), `mgtls ocsp verify` (in-store, HTTP responder URL, and live TLS OCSP stapling verification), and MCP tool `pki_ocsp_verify`.
- **PKCS#10 CSR Workflow (`src/pkg/pki/csr.go` — `CAP-CSR-001`)**: `mgtls csr create` (local key + CSR, refuses to overwrite keys, `--key` to reuse) and `mgtls csr sign` (`--csr file|-`, `--role`, `--days`, `--out`); MCP tool `pki_csr_sign` (21 MCP tools total). Verifies the CSR proof-of-possession signature, rejects RSA <2048 / ECDSA <P-256, takes only CN/SANs from the CSR (requested CA/EKU/key-usage extensions are ignored), caps validity at the CA's `NotAfter`. Issued certs are flagged `external` in the manifest and have no key path; `doctor` accepts them and `watch` reports them under `external_expiring` instead of attempting re-issuance.
- **Encrypted-at-Rest Key Vault (`src/pkg/store/vault.go` — `CAP-VAULT-001`)**: set `MGTLS_KEYFILE` (preferred; >=32 bytes, mode 0600, HKDF-SHA256) or `MGTLS_PASSPHRASE` (scrypt N=32768) and CA, SSH CA, and ACME account private keys are stored as AES-256-GCM `MGTLS ENCRYPTED KEY` PEM envelopes. Reads transparently accept sealed or plaintext files. `mgtls vault status|seal|unseal|rotate` migrate in place (all-or-nothing, atomic replace; `rotate` uses `MGTLS_NEW_KEYFILE`/`MGTLS_NEW_PASSPHRASE`). Leaf-certificate keys are deliberately not encrypted (consumed by external software).

### Fixed
- ACME account key loading no longer regenerates (and overwrites) a key it merely failed to read/decrypt.

### Verification Telemetry
- **Static Analysis & Full Test Suite**: `go vet ./...` (`0` warnings) and `go test -race ./src/...` (`9/9` packages passing, 0 data races).

## [1.2.0] - 2026-11-06

### Added
- **Multi-Target Installer, Container Image & Onboarding (`install.sh`, `Dockerfile`, `src/cmd/mgtls/main.go` — `CAP-DIST-001`)**:
  - Added multi-target installer script (`install.sh`, `scripts/install.sh`, `docs/install.sh`) supporting `--local` (`~/.local`), `--global` (`/usr/local`), `--prefix DIR`, `--copy`, `--from-release`, `--dry-run`, `--uninstall`, `--force`, and `-h/--help`.
  - Added multi-stage zero-CGO scratch container `Dockerfile` (`FROM golang:1.26-alpine` -> `FROM scratch` with non-root user `65532:65532`).
  - Added `mgtls guide` (`--json`) interactive workflow cheat sheet, `mgtls init --starter --yes` (`-y`, `--force`, `--quiet`) starter manifest scaffolder, and contextual `Next steps:` breadcrumbs on `stderr`.
- **7 New Target Framework & Infrastructure Generators (`src/pkg/targets` — 14 Total Targets — `CAP-TARGETS-001`)**:
  - Expanded `mgtls target generate --target <name>` from 7 to **14 targets** by adding **Caddy**, **Traefik**, **Envoy Proxy (xDS SDS)**, **PostgreSQL (`pg_hba.conf` `clientcert=verify-full`)**, **Redis (`tls-auth-clients yes`)**, **gRPC-Go**, and **Node.js / Express**.
- **Autonomous Certificate Renewal Daemon & `systemd` Generator (`src/pkg/profile/profile.go`, `src/cmd/mgtls/main.go` — `CAP-WATCH-001`)**:
  - Added `mgtls watch` (`--manifest`, `--renew-before`, `--interval`, `--on-renew`, `--once`, `--json`) to continuously monitor and rotate expiring X.509 leaf certificates and execute reload hooks (`MGTLS_RENEWED_CERTS`, `MGTLS_RENEWED_COUNT`).
  - Added `mgtls systemd generate` (`--mode timer|daemon`, `--output`, `--manifest`, `--store-dir`, `--binary`, `--user`, `--on-renew`) to scaffold hardened `mgtls-renew.service` and `mgtls-renew.timer` units.
- **Hardware-Backed Root CA, KMS & `ssh-agent` Signer Seams (`src/pkg/pki/pki.go`, `src/pkg/sshca/sshca.go` — `CAP-HSM-001`)**:
  - Extended `pki.CARequest` (`Signer`, `ParentSigner`) and `pki.CertRequest` (`CASigner`) to accept external `crypto.Signer` implementations (YubiKey PIV, PKCS#11 HSM, Cloud KMS) without persisting CA private keys to disk.
  - Extended `sshca.SSHCARequest` (`Signer`) and `sshca.SignSSHRequest` (`CASigner`, `AgentSocket`) plus CLI flag `mgtls ssh-ca sign --agent-socket` (`SSH_AUTH_SOCK`) to sign OpenSSH user and host certificates via a live `ssh-agent`.

### Verification Telemetry
- **Static Analysis & Full Test Suite**: `go vet ./src/...` (`0` warnings), `go test -race ./src/...` (`9/9` packages passing, 60+ test functions & subtests), and `bash tests/run_all.sh` (`100%` pass across all unit, integration, and 14 shell E2E suites).

## [1.1.1] - 2026-11-05

### Security
- **Store Boundary Path-Traversal Protection (`src/pkg/store/store.go`)**: Added `(*Store).SafePath` using `filepath.Rel(s.BaseDir, full)` and enforced it across `WriteKey` and `WritePublic` so untrusted `name` inputs via MCP `tools/call` or YAML fleet manifests cannot escape the `.mgtls` store root (`..` traversal rejected with explicit error).
- **OS Trust Anchor Filename Sanitization (`src/pkg/pki/pki.go`)**: Added `sanitizeTrustAnchorName` in `GenerateTrustScript` restricting generated Debian/RHEL trust anchor filenames to `[a-zA-Z0-9._-]` to prevent shell metacharacter or path-separator injection.

### Fixed
- **Per-Certificate CRL Revocation Reason Preservation (`src/pkg/pki/pki.go`, `src/pkg/store/store.go`)**: Added `RevokeReason int` (`json:"revoke_reason,omitempty"`) to `store.CertRecord` and updated `RevokeCert` so rebuilding a CA's CRL across multiple revoked certificates preserves each certificate's original RFC 5280 reason code.

### Changed
- **Leaf Certificate Artifact Persistence Deduplication (`src/pkg/pki/pki.go`)**: Extracted `writeLeafCertArtifacts` shared by `IssueCert` and `IssueSelfSigned`, eliminating duplicated persistence blocks (`cert.pem`, `key.pem`, `fullchain.pem`, `ca-chain.pem`, `cert.der`, `bundle.pem`).
- **5-Axis Code Review & Quality Audit Report (`docs/CODE_REVIEW.md`)**: Documented the full `/agent-skills:code-review-and-quality` audit across Correctness, Readability, Architecture, Security, Performance, Dependency Discipline, and File Size cohesion.

### Verification Telemetry
- **Static Analysis & Test Suite**: `go vet ./src/...` (`0` warnings) and `go test -v -race -coverpkg=./src/... ./src/...` — 9/9 packages passing, **83.2%** cross-package statement coverage (`100%` `cmd/mgtls`, `93.3%` `store`, `84.8%` `pki`, `83.2%` `mcpserver`, 14/14 shell cookbooks & examples).

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
