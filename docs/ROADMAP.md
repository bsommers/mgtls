# `mgtls` Forward Roadmap

**Completed Releases:** `v1.0.0`, `v1.1.0`, `v1.1.1`, `v1.2.0` (`0607655`), `v1.3.0`  
**Next Target Milestone:** `v1.4.0`

---

## Completed `v1.2.0` Roadmap Options

| # | Option | Status | Summary |
| :--- | :--- | :--- | :--- |
| **1** | **Distribution, Container & Homebrew/Install Script (`CAP-DIST-001`)** | `[x] COMPLETED (c0714e4)` | Multi-target `install.sh` (`--local`, `--global`, `--prefix`, `--from-release`, `--dry-run`, `--uninstall`), multi-stage `Dockerfile` (`FROM scratch`), `mgtls guide`, `mgtls init --starter --yes`, and contextual `Next steps:` breadcrumbs on `stderr`. |
| **2** | **Expanded Target Framework Generators (`CAP-TARGETS-001`)** | `[x] COMPLETED (3d4bcb4)` | Expanded `mgtls target generate` from 7 to **14 targets**: added **Caddy**, **Traefik**, **Envoy Proxy (xDS SDS)**, **PostgreSQL (`pg_hba.conf`)**, **Redis (`tls-auth-clients yes`)**, **gRPC-Go**, and **Node.js / Express**. |
| **3** | **Automated Certificate Renewal Daemon & `systemd` Timer (`CAP-WATCH-001`)** | `[x] COMPLETED (ab615da)` | Added `mgtls watch` (`--manifest`, `--renew-before`, `--interval`, `--on-renew`, `--once`) and `mgtls systemd generate` (`--mode timer|daemon`, `--output`, `--user`, `--on-renew`). |
| **4** | **Hardware-Backed Root CA, KMS & `ssh-agent` Signer Seams (`CAP-HSM-001`)** | `[x] COMPLETED (750023c)` | Extended `pki.CARequest`/`CertRequest` with `crypto.Signer` (`Signer`, `ParentSigner`, `CASigner`) and `sshca.SSHCARequest`/`SignSSHRequest` with `ssh.Signer` + live `ssh-agent` socket (`--agent-socket` / `SSH_AUTH_SOCK`). |

---

## Completed `v1.3.0` Roadmap Options

| # | Option | Scope & Value |
| :--- | :--- | :--- |
| **Option A** | **`[x] COMPLETED (07955b4)` — RFC 6960 OCSP Responder & Stapling Verifier (`CAP-OCSP-001`)** | Added `mgtls ocsp serve` (`src/pkg/pki/ocsp.go`, including RFC 6960 §4.2.2.2 delegated OCSP signing for Ed25519 CAs), `mgtls ocsp verify` (in-store, HTTP responder URL, and live TLS OCSP stapling verification), and MCP tool `pki_ocsp_verify` (20th MCP tool). |
| **Option B** | **`[x] COMPLETED (61f20e2)` — Live TLS / mTLS Endpoint Prober & Cipher Auditor (`CAP-PROBE-001`)** | Added `mgtls probe --addr host:port` (`src/pkg/pki/probe.go`) and MCP tool `pki_probe` to connect to live TLS/mTLS endpoints, inspect negotiated TLS version/cipher suite/ALPN, verify peer chain against `.mgtls` CAs, check SANs/expiry, and emit JSON diagnostics. |
| **Option C** | **`[x] COMPLETED (47bf6a5)` — CSR (`PKCS#10`) Workflow & External CA Signing (`CAP-CSR-001`)** | Added `mgtls csr create` and `mgtls csr sign` (`src/pkg/pki/csr.go`) plus MCP tool `pki_csr_sign` (21st tool) so external workloads generate private keys locally, submit only a PKCS#10 `.csr.pem`, and receive a signed X.509 certificate without `mgtls` ever holding the leaf private key. CSR extensions are ignored; only CN/SANs are honored. |
| **Option D** | **`[x] COMPLETED (47bf6a5)` — Encrypted-at-Rest Private Key Store (`CAP-VAULT-001`)** | Added `src/pkg/store/vault.go` + `mgtls vault status|seal|unseal|rotate` with AES-256-GCM envelope encryption (`MGTLS_KEYFILE` HKDF-SHA256 / `MGTLS_PASSPHRASE` scrypt N=32768) for CA, SSH CA, and ACME account private keys while keeping leaf keys plaintext as deployment artifacts. |

---

## Target `v1.4.0` Roadmap Options (In Order)

| # | Option | Status | Scope & Value |
| :--- | :--- | :--- | :--- |
| **Option 1** | **RFC 7030 Enrollment over Secure Transport (EST) Server & Client (`CAP-EST-001`)** | `[x] COMPLETED` | Added `src/pkg/pki/est.go`, `mgtls est serve|enroll|reenroll|cacerts` (`/.well-known/est/cacerts`, `/simpleenroll`, `/simplereenroll` with PKCS#7 `certs-only` DER encoding, constant-time bootstrap token auth, and mTLS client-cert auth), and MCP tool `pki_est_enroll` (22nd tool). |
| **Option 2** | **SPIFFE / SPIRE X.509-SVID & Trust Bundle Support (`CAP-SPIFFE-001`)** | `[ ] NEXT` | Add `src/pkg/pki/spiffe.go`, first-class `spiffe://<trust-domain>/<workload>` URI SAN validation, `mgtls svid issue|verify`, `mgtls bundle export --format spiffe|pem`, and MCP tool `pki_svid_issue`. |
| **Option 3** | **Tamper-Evident Cryptographic Audit Log (`CAP-AUDIT-001`)** | `[ ] PLANNED` | Append-only SHA-256 hash-chained audit ledger (`.mgtls/audit.jsonl`) recording CA creation, cert issuance, CSR sign, EST enrollment, revocation, and vault operations, plus `mgtls audit list|verify` and MCP tool `pki_audit_verify`. |
| **Option 4** | **Trust Bundle Compiler & Multi-Endpoint TLS Scanner (`CAP-SCAN-001`)** | `[ ] PLANNED` | Multi-CA trust bundle compiler (`PEM`, `PKCS#7/.p7b`, `PKCS#12` truststore) and concurrent multi-target TLS inventory scanner (`mgtls scan --targets ...`) built on `ProbeEndpoint`. |
