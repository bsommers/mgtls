# `mgtls` Forward Roadmap

**Completed Releases:** `v1.0.0`, `v1.1.0`, `v1.1.1`, `v1.2.0` (`0607655`)  
**Next Target Milestone:** `v1.3.0`

---

## Completed `v1.2.0` Roadmap Options

| # | Option | Status | Summary |
| :--- | :--- | :--- | :--- |
| **1** | **Distribution, Container & Homebrew/Install Script (`CAP-DIST-001`)** | `[x] COMPLETED (c0714e4)` | Multi-target `install.sh` (`--local`, `--global`, `--prefix`, `--from-release`, `--dry-run`, `--uninstall`), multi-stage `Dockerfile` (`FROM scratch`), `mgtls guide`, `mgtls init --starter --yes`, and contextual `Next steps:` breadcrumbs on `stderr`. |
| **2** | **Expanded Target Framework Generators (`CAP-TARGETS-001`)** | `[x] COMPLETED (3d4bcb4)` | Expanded `mgtls target generate` from 7 to **14 targets**: added **Caddy**, **Traefik**, **Envoy Proxy (xDS SDS)**, **PostgreSQL (`pg_hba.conf`)**, **Redis (`tls-auth-clients yes`)**, **gRPC-Go**, and **Node.js / Express**. |
| **3** | **Automated Certificate Renewal Daemon & `systemd` Timer (`CAP-WATCH-001`)** | `[x] COMPLETED (ab615da)` | Added `mgtls watch` (`--manifest`, `--renew-before`, `--interval`, `--on-renew`, `--once`) and `mgtls systemd generate` (`--mode timer|daemon`, `--output`, `--user`, `--on-renew`). |
| **4** | **Hardware-Backed Root CA, KMS & `ssh-agent` Signer Seams (`CAP-HSM-001`)** | `[x] COMPLETED (750023c)` | Extended `pki.CARequest`/`CertRequest` with `crypto.Signer` (`Signer`, `ParentSigner`, `CASigner`) and `sshca.SSHCARequest`/`SignSSHRequest` with `ssh.Signer` + live `ssh-agent` socket (`--agent-socket` / `SSH_AUTH_SOCK`). |

---

## Proposed `v1.3.0` Roadmap Options

| # | Option | Scope & Value |
| :--- | :--- | :--- |
| **Option A** | **`[x] COMPLETED` — RFC 6960 OCSP Responder & Stapling Verifier (`CAP-OCSP-001`)** | Added `mgtls ocsp serve` (`src/pkg/pki/ocsp.go`, including RFC 6960 §4.2.2.2 delegated OCSP signing for Ed25519 CAs), `mgtls ocsp verify` (in-store, HTTP responder URL, and live TLS OCSP stapling verification), and MCP tool `pki_ocsp_verify` (20th MCP tool). |
| **Option B** | **`[x] COMPLETED` — Live TLS / mTLS Endpoint Prober & Cipher Auditor (`CAP-PROBE-001`)** | Added `mgtls probe --addr host:port` (`src/pkg/pki/probe.go`) and MCP tool `pki_probe` to connect to live TLS/mTLS endpoints, inspect negotiated TLS version/cipher suite/ALPN, verify peer chain against `.mgtls` CAs, check SANs/expiry, and emit JSON diagnostics. |
| **Option C** | **CSR (`PKCS#10`) Workflow & External CA Signing (`CAP-CSR-001`)** | Add `mgtls csr create` and `mgtls csr sign` so external workloads can generate private keys locally, submit only a PKCS#10 `.csr.pem` to `mgtls` (via CLI or MCP `mgtls_csr_sign`), and receive a signed X.509 certificate without `mgtls` ever holding the leaf private key. |
| **Option D** | **Encrypted-at-Rest Private Key Store (`CAP-VAULT-001`)** | Optional passphrase / environment-key (`MGTLS_PASSPHRASE` / `MGTLS_KEYFILE`) AES-256-GCM envelope encryption for `.mgtls/*/keys/*.key.pem` so private keys on disk are encrypted at rest while remaining zero-CGO. |
