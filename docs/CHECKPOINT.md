# Session Checkpoint (`docs/CHECKPOINT.md`)

**Timestamp:** 2026-11-08T10:41:15-05:00  
**Status:** STABLE — Option B (`CAP-PROBE-001`) and Option A (`CAP-OCSP-001`) completed and verified; ready for Option C (`CAP-CSR-001`) or Option D (`CAP-VAULT-001`) in `docs/ROADMAP.md`  
**Repository:** `mgtls` (`https://github.com/bsommers/mgtls`)  
**Branch:** `main` (clean working tree, synced with `origin/main`)

---

## 1. Goal & User Decisions (Verbatim)
- **User Requests Completed**:
  - Completed `v1.2.0` roadmap Options 1–4 (`c0714e4`, `3d4bcb4`, `ab615da`, `750023c`) and published GitHub Release `v1.2.0` (`0607655`).
  - `B first` -> Completed **Option B (`CAP-PROBE-001`)** in commit `61f20e2` (`src/pkg/pki/probe.go`, `mgtls probe`, MCP `pki_probe`).
  - `Option A` -> Completed **Option A (`CAP-OCSP-001`)**:
    - Created `src/pkg/pki/ocsp.go` (`GenerateOCSPResponse`, `NewOCSPHTTPHandler`, `ServeOCSP`, `VerifyOCSP`) and `src/pkg/pki/ocsp_test.go`.
    - Added `mgtls ocsp serve` and `mgtls ocsp verify` (`--name`, `--cert`, `--ca`, `--ca-cert`, `--url`, `--stapled`, `--timeout`) in `src/cmd/mgtls/main.go`.
    - Added `pki_ocsp_verify` (20th MCP tool) in `src/pkg/mcpserver/mcpserver.go`.
    - Updated `docs/ROADMAP.md`, `docs/CAPABILITIES.md`, and `docs/capabilities.json`.

---

## 2. Dead Ends & Lessons Learned
- **Ed25519 CAs in `golang.org/x/crypto/ocsp`**: `ocsp.CreateResponse` only supports RSA and ECDSA response signatures directly (`x509: only RSA and ECDSA keys supported`). When the issuing CA in `.mgtls` uses `Ed25519`, `GenerateOCSPResponse` (`src/pkg/pki/ocsp.go`) automatically issues an RFC 6960 §4.2.2.2 delegated OCSP responder certificate (`ecdsa-p256` with `ExtKeyUsageOCSPSigning`) signed by the `Ed25519` CA and embeds `template.Certificate = delCert`, which `ocsp.ParseResponseForCert` verifies cleanly via `crypto/x509`.
- **Verification Command**: `go vet ./... && go test -race ./src/...` (`9/9` packages passing, `0` warnings).

---

## 3. Working-Tree & Background Process State
- **Branch**: `main` (committed and pushed to `origin/main`).
- **Background Processes / Subagents**: `0` running.

---

## 4. Remaining `v1.3.0` Roadmap Options (`docs/ROADMAP.md`)
- **Option C**: CSR (`PKCS#10`) Workflow & External CA Signing (`CAP-CSR-001`: `mgtls csr create`, `mgtls csr sign`, MCP `pki_csr_sign`).
- **Option D**: Encrypted-at-Rest Private Key Store (`CAP-VAULT-001`: AES-256-GCM envelope encryption for `.mgtls` private keys).

---

## 5. Exact Next Command to Resume
In a fresh session (`/exit`, `Ctrl+D`, or New Chat), resume with:
```text
Read docs/CHECKPOINT.md and docs/ROADMAP.md, verify git status, and implement Option C (or Option D).
```
