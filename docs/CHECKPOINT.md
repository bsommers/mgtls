# Session Checkpoint — `mgtls` (`v1.1.1`)

- **Status:** COMPLETE (`v1.1.1` released, tagged, and pushed to `origin/main`)
- **Repository:** `/home/bill/src/sysadmin/mgtls` (`https://github.com/bsommers/mgtls`, branch `main`, tag `v1.1.1`)
- **Goal & User Decisions (Verbatim):**
  1. Go (`go1.26`) static zero-CGO binary (`./src/cmd/mgtls`) + packages under `src/pkg/{store,pki,sshca,acme,targets,profile,mcpserver}` + E2E test suite under `src/test/e2e`.
  2. Full X.509 PKI, OpenSSH User/Host CAs, RFC 8555 ACME v2 client, 7 framework targets (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`), and built-in MCP Server (`mgtls mcp serve`).
  3. `/swe-skills:test-coverage`: Full test suite covering unit tests, negative/security paths, all 8 `examples/`, all 5 `cookbooks/`, Terraform external bridge, and the 4 Shell Test-Quality Checklist gates (`83.1%` statement coverage), documented in `docs/TEST_COVERAGE.md`.
  4. `/release`: Cut semantic version `v1.1.0`, synchronized `docs/CHANGELOG.md`, `docs/CAPABILITIES.md`, `docs/capabilities.json`, tagged `v1.1.0`, built cross-platform binaries, and published GitHub Release `v1.1.0`.
  5. `/agent-skills:code-review-and-quality`: Completed 5-Axis Code Review (`docs/CODE_REVIEW.md`), remediated store path-traversal boundary (`Store.SafePath`), multi-cert CRL revocation reason preservation (`CertRecord.RevokeReason`), trust-anchor shell sanitization (`sanitizeTrustAnchorName`), and leaf-cert artifact deduplication (`writeLeafCertArtifacts`), reaching `83.2%` statement coverage.
  6. `/release` (`v1.1.1`): Cut patch release `v1.1.1`, synchronized `docs/CHANGELOG.md`, `docs/CAPABILITIES.md`, `docs/capabilities.json`, `README.md`, `docs/index.html`, tagged `v1.1.1`, built 5 cross-platform binaries + `SHA256SUMS`, and published GitHub Release `v1.1.1`.
  7. **Option 1 (Distribution & Onboarding)**: Built `install.sh` (`scripts/install.sh`, `docs/install.sh`), `Dockerfile` (multi-stage `FROM scratch`), `mgtls guide`, `mgtls init --starter --yes`, and `stderr` `Next steps:` breadcrumbs (`--quiet`). Saved remaining Options 2, 3, and 4 in `docs/ROADMAP.md` to prompt the user later.
- **Dead Ends:** None.
- **Working-Tree & Background-Process State:**
  - Clean working tree on branch `main` synced with `origin/main` and tag `v1.1.1`.
  - No background processes or subagents running.
- **Exact Next Command (if resuming in a fresh session):**
  `go test -v -race -coverpkg=./src/... ./src/...`
