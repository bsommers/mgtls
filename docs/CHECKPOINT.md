# Session Checkpoint (`docs/CHECKPOINT.md`)

**Timestamp:** 2026-11-06  
**Repository:** `mgtls` (`https://github.com/bsommers/mgtls`)  
**Branch / Release:** `main` (`v1.2.0`)

---

## 1. Completed Milestones in This Session
1. **5-Axis Code Review & Quality Remediation (`0007719`)**:
   - Enforced `(*Store).SafePath` boundary validation in `src/pkg/store/store.go`.
   - Preserved per-certificate RFC 5280 `RevokeReason` codes across CRL rebuilds in `src/pkg/pki/pki.go` and `src/pkg/store/store.go`.
   - Sanitized OS trust anchor filenames in `GenerateTrustScript` (`src/pkg/pki/pki.go`).
   - Deduplicated leaf certificate persistence into `writeLeafCertArtifacts` (`src/pkg/pki/pki.go`).
   - Authored full audit report in `docs/CODE_REVIEW.md`.
2. **Release `v1.1.1` (`d28451d`)**:
   - Published `v1.1.1` with 5 cross-platform zero-CGO binaries + `SHA256SUMS`.
3. **Option 1 — Distribution, Container & Onboarding (`c0714e4` — `CAP-DIST-001`)**:
   - Added `install.sh` (`scripts/install.sh`, `docs/install.sh`), multi-stage `FROM scratch` `Dockerfile`, `mgtls guide`, `mgtls init --starter --yes`, and `Next steps:` breadcrumbs on `stderr`.
4. **Option 2 — 14 Target Framework & Infrastructure Generators (`3d4bcb4` — `CAP-TARGETS-001`)**:
   - Added `caddy`, `traefik`, `envoy`, `postgres`, `redis`, `grpc-go`, and `nodejs-express` target templates (`src/pkg/targets/templates.go`).
5. **Option 3 — Autonomous Renewal Daemon & `systemd` Generator (`ab615da` — `CAP-WATCH-001`)**:
   - Added `mgtls watch` (`--manifest`, `--renew-before`, `--interval`, `--on-renew`, `--once`) and `mgtls systemd generate` (`--mode timer|daemon`).
6. **Option 4 — Hardware-Backed Root CA, KMS & `ssh-agent` Signer Seams (`750023c` — `CAP-HSM-001`)**:
   - Added `crypto.Signer` (`Signer`, `ParentSigner`, `CASigner`) seams to `pki.CARequest` and `pki.CertRequest` (`src/pkg/pki/pki.go`) and `ssh.Signer` + `AgentSocket` (`--agent-socket` / `SSH_AUTH_SOCK`) to `sshca.SSHCARequest` and `sshca.SignSSHRequest` (`src/pkg/sshca/sshca.go`).
7. **Release `v1.2.0`**:
   - Synchronized `docs/CHANGELOG.md`, `docs/CAPABILITIES.md`, `docs/capabilities.json`, `README.md`, `docs/index.html`, and `src/cmd/mgtls/main.go` (`Version = "1.2.0"`), tagged `v1.2.0`, and published cross-platform release binaries.
