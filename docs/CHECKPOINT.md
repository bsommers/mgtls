# Checkpoint — `mgtls v1.4.0` Roadmap Execution — 2026-11-12

**Timestamp:** 2026-11-12T06:25:00-05:00  
**Status:** IN PROGRESS — needs resume  
**Repository:** `/home/bill/src/sysadmin/mgtls` (`https://github.com/bsommers/mgtls`)  
**Branch:** `main` at `aa1dc5b` (synced with `origin/main`)

---

## 1. Goal & User Decisions (Verbatim)
- **Overall Goal**: Execute the 4 `v1.4.0` roadmap options in order (`Option 1: CAP-EST-001`, `Option 2: CAP-SPIFFE-001`, `Option 3: CAP-AUDIT-001`, `Option 4: CAP-SCAN-001`) as documented in `docs/ROADMAP.md`, then cut the `v1.4.0` release.
- **User Decisions (Verbatim)**:
  1. `"what's next?"` -> Presented the 4 `v1.4.0` options (`CAP-EST-001`, `CAP-SPIFFE-001`, `CAP-AUDIT-001`, `CAP-SCAN-001`).
  2. `"start with option 1. we'll do them in order."` -> Completed & verified Option 1 (`CAP-EST-001`) in commit `aa1dc5b`.
  3. `"push"` -> Pushed `aa1dc5b` to `origin/main`.
  4. `"checkpoint. I need to exit and have Claude take over"` -> Refreshed `docs/CHECKPOINT.md` for seamless handoff to Claude Code.

---

## 2. Done (with evidence)
- **`v1.3.0` Release (`5e2426c`)**: Tagged `v1.3.0`, pushed to `origin`, built 5 cross-platform binaries + `SHA256SUMS`, and published GitHub Release (`https://github.com/bsommers/mgtls/releases/tag/v1.3.0`).
- **`v1.4.0` Option 1 — `CAP-EST-001` (`aa1dc5b`, pushed to `origin/main`)**:
  - `src/pkg/pki/est.go` & `src/pkg/pki/est_test.go`:
    - `EncodePKCS7CertsOnly` / `DecodePKCS7CertsOnly`: RFC 7030 §4.1.3 degenerate PKCS#7 / CMS `SignedData` (`certs-only`) ASN.1 DER encoder and parser.
    - `NewESTHTTPHandler` & `ServeEST`: `GET /.well-known/est[/<label>]/cacerts`, `POST /simpleenroll`, and `POST /simplereenroll` with constant-time bootstrap token authentication (`subtle.ConstantTimeCompare`), mTLS client-certificate verification (including store revocation check), and RFC 7030 §4.2.2 CN/SAN subject-matching on re-enrollment.
    - `ESTFetchCACerts` & `ESTEnroll`: Client enrollment/re-enrollment that generates keys and PKCS#10 CSRs locally (`CreateCSR`) so leaf private keys never leave the client.
  - `src/cmd/mgtls/main.go` & `src/cmd/mgtls/main_test.go`: Added `mgtls est <serve|cacerts|enroll|reenroll>`.
  - `src/pkg/mcpserver/mcpserver.go` & `src/pkg/mcpserver/mcpserver_test.go`: Added 22nd MCP tool `pki_est_enroll` (`enroll`, `reenroll`, `cacerts`).
  - `go vet ./... && go test -count=1 -race ./src/...` -> **9/9 packages passed** (`src/cmd/mgtls`, `src/pkg/acme`, `src/pkg/mcpserver`, `src/pkg/pki`, `src/pkg/profile`, `src/pkg/sshca`, `src/pkg/store`, `src/pkg/targets`, `src/test/e2e`).

---

## 3. Bugs Fixed & Operational Gotchas (Do Not Reintroduce)
- **GitHub Auth Account Selection (`bsommers` vs `nonont1010`)**:
  - `gh auth status` has `nonont1010` as the default active account and `bsommers` as a secondary logged-in keyring account.
  - When pushing to `origin` (`bsommers/mgtls`) or running `gh release`, always prefix with:
    `GH_TOKEN="$(gh auth token --user bsommers)" git -c credential.helper='!gh auth git-credential' push ...`
- **Vault CLI Test Order in `src/cmd/mgtls/main_test.go`**:
  - In `TestCLIEndToEndWorkflow`, the `vault` subcommand loop is ordered `["status", "seal", "rotate", "unseal"]` (updating `MGTLS_PASSPHRASE` to `MGTLS_NEW_PASSPHRASE` before `unseal`) so that `root-ca` is left unsealed for subsequent CLI subtests (`est serve`, etc.).
- **Ed25519 CAs in `golang.org/x/crypto/ocsp`**:
  - `ocsp.CreateResponse` only supports RSA/ECDSA directly; `src/pkg/pki/ocsp.go` automatically issues an RFC 6960 §4.2.2.2 delegated OCSP responder certificate (`ecdsa-p256` with `ExtKeyUsageOCSPSigning`) when the CA is `Ed25519`.
- **Untrusted CSR Extension Stripping (`src/pkg/pki/csr.go`)**:
  - `SignCSR` honors only Subject CN and SANs (`DNSNames`, `IPAddresses`, `URIs`, `EmailAddresses`) and strips all raw CSR extensions so a CSR or EST enrollment request can never escalate to `IsCA: true`.

---

## 4. Working-Tree & Background Process State
- **Branch**: `main` (only `docs/CHECKPOINT.md` refreshed since `aa1dc5b`)
- **Stashes**: `0`
- **Background Processes / Subagents / Listeners**: `0` running

---

## 5. Update 2026-11-12 (Options 2-4 done locally, NOT pushed)
- `1d6bc7f` CAP-SPIFFE-001: `src/pkg/pki/spiffe.go`, `mgtls svid issue|verify`, `mgtls bundle export`, MCP `pki_svid_issue` (23rd).
- `fe142c7` CAP-AUDIT-001: `src/pkg/store/audit.go` (hash-chained `audit.jsonl`, hooks in CA/cert/CSR/EST/revoke/vault), `mgtls audit list|verify [--expect-head]`, MCP `pki_audit_verify` (24th). Single-writer per process; pin head hash to detect tail truncation.
- CAP-SCAN-001 (uncommitted/see git log): `src/pkg/pki/scan.go` (PEM/p7b/p12 compiler, own PKCS#12 encoder, concurrent scanner), `mgtls bundle compile`, `mgtls scan`, MCP `pki_scan` (25th).
- `go vet ./... && go test -count=1 -race ./src/...` green (9/9).

## 6. Remaining
1. Cut v1.4.0: bump `Version` in `src/cmd/mgtls/main.go` (+ mcpserver version), sync README, docs/index.html, CHANGELOG, CAPABILITIES; push with bsommers token (see §3).
