# Session Checkpoint (`docs/CHECKPOINT.md`)

**Timestamp:** 2026-11-08T18:17:35-05:00  
**Status:** IN PROGRESS — needs resume (Options A–D implemented & passing tests; Options C & D uncommitted in working tree; ready to commit & cut `v1.3.0`)  
**Repository:** `mgtls` (`https://github.com/bsommers/mgtls`)  
**Branch:** `main` (`HEAD` at `07955b4`, synced with `origin/main` + uncommitted Options C & D changes)

---

## 1. Goal & User Decisions (Verbatim)
- **Overall Goal**: Execute all 4 `v1.3.0` roadmap initiatives (`Option A`, `Option B`, `Option C`, `Option D`) in `docs/ROADMAP.md`, verify `9/9` Go test packages with `-race`, and cut release `v1.3.0`.
- **User Decisions & Sequence**:
  - Completed `v1.2.0` Options 1–4 (`c0714e4`, `3d4bcb4`, `ab615da`, `750023c`) and published GitHub Release `v1.2.0` (`0607655`).
  - `B first` -> Completed & pushed **Option B (`CAP-PROBE-001`)** in commit `61f20e2` (`src/pkg/pki/probe.go`, `mgtls probe`, MCP `pki_probe`).
  - `Option A` -> Completed & pushed **Option A (`CAP-OCSP-001`)** in commit `07955b4` (`src/pkg/pki/ocsp.go`, `mgtls ocsp serve|verify`, MCP `pki_ocsp_verify`).
  - **Option C (`CAP-CSR-001`) & Option D (`CAP-VAULT-001`)** -> Implemented and verified in the working tree (uncommitted):
    - **Option C (`CAP-CSR-001`)**: `src/pkg/pki/csr.go`, `src/pkg/pki/csr_test.go`, `mgtls csr create|sign` in `src/cmd/mgtls/main.go`, and MCP tool `pki_csr_sign` (21st MCP tool) in `src/pkg/mcpserver/mcpserver.go`.
    - **Option D (`CAP-VAULT-001`)**: `src/pkg/store/vault.go`, `src/pkg/store/vault_test.go`, `mgtls vault status|seal|unseal|rotate` in `src/cmd/mgtls/main.go`, covering CA, SSH CA, and ACME account private keys via AES-256-GCM + PBKDF2-HMAC-SHA256 (`MGTLS_PASSPHRASE` / `MGTLS_KEYFILE`).

---

## 2. Dead Ends & Lessons Learned
- **Ed25519 CAs in `golang.org/x/crypto/ocsp`**: `ocsp.CreateResponse` only supports RSA and ECDSA response signatures directly (`x509: only RSA and ECDSA keys supported`). When the issuing CA in `.mgtls` uses `Ed25519`, `GenerateOCSPResponse` (`src/pkg/pki/ocsp.go`) automatically issues an RFC 6960 §4.2.2.2 delegated OCSP responder certificate (`ecdsa-p256` with `ExtKeyUsageOCSPSigning`) signed by the `Ed25519` CA and embeds `template.Certificate = delCert`, which `ocsp.ParseResponseForCert` verifies cleanly via `crypto/x509`.
- **CSR Untrusted Extension Stripping (`CAP-CSR-001`)**: `SignCSR` (`src/pkg/pki/csr.go`) verifies the CSR signature (`csr.CheckSignature()`) and honors only Subject CN and SANs (`DNSNames`, `IPAddresses`, `URIs`, `EmailAddresses`), ignoring raw CSR `Extensions` / `ExtraExtensions` so untrusted CSRs cannot escalate privileges (`IsCA: true`).
- **Baseline Verification Command**: `go vet ./... && go test -race ./src/...` (`9/9` packages passing, `0` warnings).

---

## 3. Working-Tree & Background Process State
- **Branch**: `main` at commit `07955b4` (`origin/main`).
- **Uncommitted Modified Files (16)**:
  - `docs/CAPABILITIES.md`, `docs/CHANGELOG.md`, `docs/CHECKPOINT.md`, `docs/ROADMAP.md`, `docs/capabilities.json`, `docs/user-guide/USER_GUIDE.md`
  - `src/cmd/mgtls/main.go`, `src/cmd/mgtls/main_test.go`
  - `src/pkg/acme/acme.go`, `src/pkg/mcpserver/mcpserver.go`, `src/pkg/mcpserver/mcpserver_test.go`, `src/pkg/pki/pki.go`, `src/pkg/profile/profile.go`, `src/pkg/profile/profile_test.go`, `src/pkg/sshca/sshca.go`, `src/pkg/store/store.go`
- **Untracked New Files (4)**:
  - `src/pkg/pki/csr.go`, `src/pkg/pki/csr_test.go`
  - `src/pkg/store/vault.go`, `src/pkg/store/vault_test.go`
- **Stashes**: `0`
- **Background Processes / Subagents**: `0` running.

---

## 4. Authorizations
- Prior commit/push approvals do **not** carry across a session reset; re-confirm with the user before pushing to `origin/main` or publishing the `v1.3.0` GitHub Release.

---

## 5. Exact Next Command to Resume
In a fresh session, resume with:
```text
Read docs/CHECKPOINT.md and docs/ROADMAP.md, verify git status and `go vet ./... && go test -race ./src/...`, commit Options C (CAP-CSR-001) and D (CAP-VAULT-001), and prepare the v1.3.0 release.
```
