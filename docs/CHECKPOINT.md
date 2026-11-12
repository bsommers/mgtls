# Session Checkpoint (`docs/CHECKPOINT.md`)

**Timestamp:** 2026-11-11T23:20:30-05:00  
**Status:** IN PROGRESS — `v1.4.0` Option 1 (`CAP-EST-001`) complete & tested; Option 2 (`CAP-SPIFFE-001`) next  
**Repository:** `mgtls` (`https://github.com/bsommers/mgtls`)  
**Branch:** `main`

---

## 1. Goal & User Decisions (Verbatim)
- **Overall Goal**: Execute the 4 `v1.4.0` roadmap options in order (`Option 1: CAP-EST-001`, `Option 2: CAP-SPIFFE-001`, `Option 3: CAP-AUDIT-001`, `Option 4: CAP-SCAN-001`) as documented in `docs/ROADMAP.md`.
- **User Decisions & Sequence**:
  - Completed `v1.3.0` (`5e2426c`, tagged and published to GitHub Releases).
  - `"what's next?"` -> Presented the 4 `v1.4.0` options (`CAP-EST-001`, `CAP-SPIFFE-001`, `CAP-AUDIT-001`, `CAP-SCAN-001`).
  - `"start with option 1. we'll do them in order."` -> Completed **Option 1 (`CAP-EST-001`)**:
    - `src/pkg/pki/est.go` + `src/pkg/pki/est_test.go`: RFC 7030 EST server (`NewESTHTTPHandler`, `ServeEST` with `/.well-known/est/cacerts`, `/simpleenroll`, `/simplereenroll`, PKCS#7 `certs-only` DER `EncodePKCS7CertsOnly`/`DecodePKCS7CertsOnly`, constant-time bootstrap token & mTLS client-cert auth with revocation check and re-enroll CN/SAN match verification) and EST client (`ESTFetchCACerts`, `ESTEnroll`).
    - `src/cmd/mgtls/main.go` + `src/cmd/mgtls/main_test.go`: `mgtls est serve|cacerts|enroll|reenroll`.
    - `src/pkg/mcpserver/mcpserver.go` + `src/pkg/mcpserver/mcpserver_test.go`: MCP tool `pki_est_enroll` (22nd MCP tool).

---

## 2. Dead Ends & Lessons Learned
- **Vault CLI Test Order in `src/cmd/mgtls/main_test.go`**: Running `vault rotate` last left `root-ca` sealed with `MGTLS_NEW_PASSPHRASE` when `MGTLS_PASSPHRASE` was cleared afterward; ordering the loop `["status", "seal", "rotate", "unseal"]` leaves the store unsealed for subsequent CLI subtests (`est serve`).
- **Baseline Verification Command**: `go vet ./... && go test -count=1 -race ./src/...` (`9/9` packages passing, `0` warnings).

---

## 3. Working-Tree & Background Process State
- **Branch**: `main`
- **Stashes**: `0`
- **Background Processes / Subagents**: `0` running.

---

## 4. Exact Next Step
Implement **Option 2 (`CAP-SPIFFE-001` — SPIFFE / SPIRE X.509-SVID & Trust Bundle Support)**:
1. Create `src/pkg/pki/spiffe.go` and `src/pkg/pki/spiffe_test.go` (`IssueSVID`, `VerifySVID`, `ExportTrustBundle` supporting `spiffe` RFC-compliant JSON trust bundle & `pem`, strict `spiffe://<trust-domain>/<workload>` URI SAN validation, max 1 SPIFFE ID per X.509-SVID per SPIFFE X.509-SVID spec).
2. Wire `mgtls svid issue|verify` and `mgtls bundle export` in `src/cmd/mgtls/main.go`.
3. Add MCP tool `pki_svid_issue` (23rd MCP tool) in `src/pkg/mcpserver/mcpserver.go`.
4. Verify with `go vet ./... && go test -count=1 -race ./src/...`.
