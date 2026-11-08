# Session Checkpoint (`docs/CHECKPOINT.md`)

**Timestamp:** 2026-11-08T09:17:00-05:00  
**Status:** STABLE — Option B (`CAP-PROBE-001`: `mgtls probe` & MCP `pki_probe`) completed and verified; ready for Option A, C, or D in `docs/ROADMAP.md`  
**Repository:** `mgtls` (`https://github.com/bsommers/mgtls`)  
**Branch:** `main` (clean working tree, synced with `origin/main`)

---

## 1. Goal & User Decisions (Verbatim)
- **User Requests Completed**:
  - Completed `v1.2.0` roadmap Options 1–4 (`c0714e4`, `3d4bcb4`, `ab615da`, `750023c`) and published GitHub Release `v1.2.0` (`0607655`).
  - User selected `B first` from the `v1.3.0` roadmap in `docs/ROADMAP.md`.
- **Completed in This Step (`Option B — CAP-PROBE-001`)**:
  - Created `src/pkg/pki/probe.go` (`ProbeRequest`, `ProbeCertSummary`, `ProbeReport`, `ProbeEndpoint`) and `src/pkg/pki/probe_test.go`.
  - Added `mgtls probe` (`--addr`, `--sni`, `--ca`, `--ca-cert`, `--client-cert-name`, `--client-cert`, `--client-key`, `--alpn`, `--timeout`, `--strict`) to `src/cmd/mgtls/main.go` and `src/cmd/mgtls/main_test.go`.
  - Added `pki_probe` tool (19th MCP tool) to `src/pkg/mcpserver/mcpserver.go` and `src/pkg/mcpserver/mcpserver_test.go`.
  - Updated `docs/ROADMAP.md`, `docs/CAPABILITIES.md`, and `docs/capabilities.json`.

---

## 2. Dead Ends & Lessons Learned
- **Go `flag.FlagSet.Parse` Positional Ordering**: In `flag.FlagSet.Parse`, flags must precede positional arguments (e.g. `mgtls probe --sni ... --strict host:port` or `mgtls probe --addr host:port --sni ... --strict`).
- **Verification Command**: `go vet ./... && go test -race ./src/...` (`9/9` packages passing, `0` warnings).

---

## 3. Working-Tree & Background Process State
- **Branch**: `main` (committed and pushed to `origin/main`).
- **Background Processes / Subagents**: `0` running.

---

## 4. Remaining `v1.3.0` Roadmap Options (`docs/ROADMAP.md`)
- **Option A**: RFC 6960 OCSP Responder & Stapling Verifier (`CAP-OCSP-001`: `mgtls ocsp serve`, `mgtls ocsp verify`, MCP `pki_ocsp_verify`).
- **Option C**: CSR (`PKCS#10`) Workflow & External CA Signing (`CAP-CSR-001`: `mgtls csr create`, `mgtls csr sign`, MCP `pki_csr_sign`).
- **Option D**: Encrypted-at-Rest Private Key Store (`CAP-VAULT-001`: AES-256-GCM envelope encryption for `.mgtls` private keys).

---

## 5. Exact Next Command to Resume
In a fresh session (`/exit`, `Ctrl+D`, or New Chat), resume with:
```text
Read docs/CHECKPOINT.md and docs/ROADMAP.md, verify git status, and implement the next v1.3.0 Option (A, C, or D).
```
