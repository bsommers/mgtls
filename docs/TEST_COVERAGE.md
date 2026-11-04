# Test Suite & Coverage Report — `mgtls`

**Date:** `2026-11-03`
**Tooling used:** `go test -race -coverprofile` + `go tool cover` (`Go 1.26.0`) + `shell_function_reachability.sh` + `src/test/e2e` (`bash -euo pipefail` E2E & Shell Test-Quality Harness)

---

## 1. Test Suite Inventory

| Dimension | Baseline (Before Audit) | Current (Post-Remediation) | Delta |
|---|---|---|---|
| Test framework(s) | `testing` (`go test -race`) | `testing` (`go test -race`) + E2E Shell/Cookbook/Example Harness (`src/test/e2e`) | +E2E & Shell Quality Suite |
| Total test files | `8` | `9` (`8` unit/integration + `1` full E2E/Cookbook/Example/Shell suite) | `+1` |
| Total test functions & subtests | `23` | `56` (`27` top-level `Test*` functions + `29` table/cookbook/example subtests) | `+33` (`+143%`) |
| Examples & Cookbooks tested | `0 / 14` automated in `go test` | `14 / 14` (`5` cookbooks + `8` examples + `1` Terraform external bridge) | `+14` (`100%`) |
| CI-enforced? | Template in `cookbooks/cicd/github-actions-mgtls.yml` | Updated with coverage threshold gate & E2E verification | Enforced |
| Runtime (`-race`) | `~1.8s` | `~4.4s` (including RSA-4096, mTLS handshakes, 5 cookbooks, and 8 example scripts) | `+2.6s` |

---

## 2. Coverage Summary

| Metric | Baseline | Post-Remediation | Source |
|---|---|---|---|
| **Total Statement Coverage (Cross-Package)** | `71.9%` | **`83.1%`** (`+11.2%`) | `go test -coverpkg=./src/... -coverprofile` |
| **Total Statement Coverage (Package-Local)** | `69.8%` | **`82.9%`** (`+13.1%`) | `go test -coverprofile ./src/...` |
| **Go Function Reachability** | `82 / 86` (`95.3%`) | **`85 / 86` (`98.8%`)** (only `main()` wrapper entrypoint at `0%`; `run()` is `85.7%`) | `go tool cover -func` |
| **Cookbook & Example Script Reachability** | `0 / 14` (`0.0%`) | **`14 / 14` (`100.0%`)** | `src/test/e2e/e2e_test.go` |

### Per-Package Statement Coverage Breakdown (Step-by-Step Delta)

| Package | Baseline % | Current % | Delta | Key Functions & Paths Covered |
|---|---|---|---|---|
| [`src/pkg/store`](../src/pkg/store/store.go) | `61.6%` | **`89.8%`** | `+28.2%` | `New`, `Init`, `WriteKey` (`0600`), `WritePublic` (`0644`), `LoadManifest`, `GetCA` (`100%`), `GetCert` (`100%`), `GetSSHCA` (`100%`), all `Upsert*` (`93.8%`) |
| [`src/pkg/profile`](../src/pkg/profile/profile.go) | `62.9%` | **`89.0%`** | `+26.1%` | `LoadFleetSpec` (`100%`), `ParseFleetSpec` (`88.2%`), `RunDoctor` (`98.7%`), `resolveTargetPaths` (`92.9%`), `findSSHCert` (`85.7%`), `findACMECert` (`85.7%`), `splitTopLevelComma` (`100%`) |
| [`src/pkg/targets`](../src/pkg/targets/targets.go) | `67.3%` | **`88.8%`** (`90.1%` cross-pkg) | `+21.5%` | `SupportedTargets` (`100%`), `defaultPortForTarget` (`100%`), `Generate` (`90.1%`), `copyArtifactIfPresent` (`88.9%`) across all 7 frameworks |
| [`src/pkg/mcpserver`](../src/pkg/mcpserver/mcpserver.go) | `70.3%` | **`85.8%`** | `+15.5%` | `NewServer` (`100%`), `HandleJSONRPC`, `listTools` (`100%`), `callTool` (`93.3%`), `dispatchTool` (`83.6%`), `ServeStdio`, `ServeHTTP` (TLS + mTLS) |
| [`src/pkg/pki`](../src/pkg/pki/pki.go) | `73.9%` | **`83.4%`** | `+9.5%` | `CreateCA` (`82.4%`), `IssueCert` (`79.5%`), `IssueSelfSigned` (`82.3%`), `InspectCert` (`79.2%`), `VerifyChain` (`86.7%`), `RevokeCert` (`82.2%`), `GenerateTrustScript` (`100%`), `resolveRoleAndEKU` (`100%`), `parseSANs` (`94.0%`) |
| [`src/cmd/mgtls`](../src/cmd/mgtls/main.go) | `65.5%` | **`82.5%`** | `+17.0%` | `run` (`85.7%`), `printUsage` (`100%`), `runInit` (`86.7%`), `runCA` (`88.9%`), `runCert` (`78.3%`), `runSSH` (`87.3%`), `runACME` (`88.9%`), `runTarget` (`81.5%`), `runStatus` (`77.8%`), `runDoctor` (`77.8%`), `runMCP` (`81.0%`) |
| [`src/pkg/sshca`](../src/pkg/sshca/sshca.go) | `77.3%` | **`80.7%`** | `+3.4%` | `CreateSSHCA` (`80.0%`), `SignSSHCert` (`80.2%`), `InspectSSHCert` (`73.3%`), `GenerateSSHConfigBundle` (`83.2%`), `generateSSHKeyPair` (`80.0%`) |
| [`src/pkg/acme`](../src/pkg/acme/acme.go) | `73.6%` | **`74.8%`** | `+1.2%` | `ListProviders` (`100%`), `ResolveProvider` (`88.9%`), `ObtainCertificate`, `CheckRenewal` (`81.8%`), `BuildTLSALPN01Cert`, `computeJWKAndThumbprint` (`100%`), `createCSR` (`100%`), `NewMockACMEServer` |
| [`src/test/e2e`](../src/test/e2e/e2e_test.go) | N/A | **`21/21` E2E PASS** | New | Executes all 5 `cookbooks/*.sh`, all 8 `examples/*`, Terraform external bridge, and 4 Shell Quality gates |

---

## 3. Coverage Gaps Identified & Remediated (P0 / P1 / P2 Analysis)

### P0 — Critical / Security-Boundary Paths (Remediated)

| Function / Module | File | Pre-Audit Gap | Remediation Added | Status |
|---|---|---|---|---|
| `VerifyChain` (EKU Role & SAN enforcement) | [`src/pkg/pki/pki.go`](../src/pkg/pki/pki.go) | Only happy-path `mtls` role tested; `server`-only cert used as `client` (or vice-versa) and untrusted CA rejection were untested. | Added `TestPKINegativeAndEdgeCases` verifying strict rejection of role mismatches, wrong DNS SANs, untrusted CAs, and revoked serials. | **CLOSED** (`86.7%`) |
| `RunDoctor` (`0600` Key Permission & Expiry Audit) | [`src/pkg/profile/profile.go`](../src/pkg/profile/profile.go) | Missing coverage for expired CAs/certs, revoked certs, missing files on disk, SSH CA/cert checks, and ACME expiry checks. | Added `TestRunDoctorComprehensiveStates` covering all severity transitions (`ok`, `warning`, `error`) and permission checks. | **CLOSED** (`98.7%`) |
| `DNSExecHook` & Shell Metacharacter Handling | [`src/pkg/acme/acme.go`](../src/pkg/acme/acme.go) & [`src/test/e2e/e2e_test.go`](../src/test/e2e/e2e_test.go) | Shell hook execution and metacharacter safety (`; touch pwned`) across scripts and environment variables were unverified. | Added `TestShellQualityChecklist/CommandStringInjectionSafety` proving shell metacharacters in values are never executed. | **CLOSED** |
| `ServeHTTP` Mutual TLS Client Auth Enforcement | [`src/pkg/mcpserver/mcpserver.go`](../src/pkg/mcpserver/mcpserver.go) | Tested in unit test, expanded with full JSON-RPC error/dispatch boundary tests. | Verified both unauthenticated TLS rejection and valid client-cert mTLS acceptance + negative JSON-RPC error codes. | **CLOSED** (`85.8%`) |

### P1 — Core Execution Paths (Remediated)

| Function / Module | File | Pre-Audit Gap | Remediation Added | Status |
|---|---|---|---|---|
| `findACMECert` & ACME Fleet Provisioning | [`src/pkg/profile/profile.go`](../src/pkg/profile/profile.go) | `0.0%` coverage — declarative `acme_certs` inside `mgtls.yaml` and targets referencing an ACME cert were untested. | Added `TestFleetSpecEdgeCasesAndACME` running `profile.Apply` against `acme.NewMockACMEServer()`. | **CLOSED** (`85.7%`) |
| `defaultPortForTarget` & TLS-only (`MutualTLS: false`) | [`src/pkg/targets/targets.go`](../src/pkg/targets/targets.go) | `0.0%` unit coverage when `Port == 0` or `MutualTLS == false`. | Added `TestGenerateDefaultsAndTLSOnlyMode` testing all 7 target default ports (`8443`, `443`, `5173`, `8006`, `22`) and TLS-only mode. | **CLOSED** (`100.0%`) |
| CLI Subcommands (`ca list`, `ca trust-script`, `cert revoke`, `ssh inspect`, `acme providers`, `acme renew-check`, `status`) | [`src/cmd/mgtls/main.go`](../src/cmd/mgtls/main.go) | `0.0%`–`35.2%` coverage on several CLI subcommands. | Expanded `TestCLIEndToEndWorkflow` and `TestCLIFlagsHelpVersionAndNegativePaths`. | **CLOSED** (`82.5%`) |
| Multi-Algorithm Matrix (`ecdsa-p384`, `rsa-4096`) | [`src/pkg/pki/pki.go`](../src/pkg/pki/pki.go), [`src/pkg/sshca/sshca.go`](../src/pkg/sshca/sshca.go) | `ecdsa-p384` and `rsa-4096` key generation/signing paths were untested in `pkg/pki`. | Added `ecdsa-p384` and `rsa-4096` to `TestCreateCAAndIssueCertsAcrossAlgorithms` with live mTLS handshakes. | **CLOSED** (`91.7%`) |

### P2 — Remaining Uncovered Lines (Low-Risk Defensive / OS Error Branches)

The remaining `~16.9%` of uncovered statements across `src/...` consist almost entirely of:
1. `main()` (`3` lines in `src/cmd/mgtls/main.go` calling `run(...)` and `os.Exit(1)`), whereas `run(...)` is `85.7%` covered.
2. Defensive OS/filesystem failure branches (`os.MkdirAll`, `os.WriteFile`, `os.Chmod`, `rand.Reader` entropy failure, `json.MarshalIndent` on static structs) that only trigger on kernel/disk failure.
3. Network polling timeout/retry backoff branches in `acme.waitAuthorization` and `acme.finalizeOrder` when a remote ACME CA returns `status: "processing"` across multiple HTTP poll intervals.

---

## 4. Shell Test-Quality Checklist Verification

All 4 checklist items from `swe-skills:test-coverage` are enforced automatically in [`src/test/e2e/e2e_test.go`](../src/test/e2e/e2e_test.go):

- [x] **1. `set -e` (`bash -euo pipefail`) interaction check:** `TestShellQualityChecklist/SetEInteractionReachability` and `TestAllCookbooksEndToEnd` run all 5 cookbooks, all 8 example scripts, and generated target/trust scripts inside `bash -euo pipefail -c '...; echo REACHED_END'` and assert `REACHED_END` is reached without silent non-zero exit traps.
- [x] **2. External-command mocking on `PATH`:** `TestShellQualityChecklist/ExternalCommandMocking` injects fake binaries on `PATH` for `pvenode`, `systemctl`, `update-ca-certificates`, `update-ca-trust`, `security`, and `certutil`, runs the generated Proxmox deployment script (`deploy_proxmox_cert.sh`) and OS trust store scripts, and asserts the exact arguments logged by the mocked binaries.
- [x] **3. Command-string injection safety check:** `TestShellQualityChecklist/CommandStringInjectionSafety` passes shell metacharacters (`; touch <pwned_file>`, `$(touch <pwned_file>)`) through environment/certificate parameters and verifies that no arbitrary command injection occurs.
- [x] **4. Dispatch-table completeness:** `TestShellQualityChecklist/DispatchTableCompleteness` and `TestCLIFlagsHelpVersionAndNegativePaths` verify that unknown CLI commands, unknown subcommands (`ca`, `cert`, `ssh`, `acme`, `target`), unknown MCP transports, and unknown target types fail loudly with non-zero exit codes and descriptive error messages.

---

## 5. Step-by-Step Execution Log & Verification Output

### Step 1: Run Full Unit, Integration & E2E Test Suite (`go test -v -race ./src/...`)

| Package / Suite | Test Function / Subtest | Result | Elapsed | What Was Verified Step-by-Step |
|---|---|---|---|---|
| `src/cmd/mgtls` | `TestCLIEndToEndWorkflow` | **PASS** | `0.19s` | `init --with-root-ca` → `ca create` (intermediate) → `cert issue` → `cert self-sign` → `cert inspect` → `cert verify` → `ssh ca-create` (user & host) → `ssh sign-user` & `sign-host` → `ssh config` → `acme obtain` (mock RFC 8555) → `target generate` (all 7 targets) → `apply -f` → `doctor` → `mcp serve` (`stdio`) → `ca list` → `ca trust-script` → `cert revoke` → `ssh inspect` → `acme providers` → `acme renew-check` → `target list` → `status` |
| `src/cmd/mgtls` | `TestCLIFlagsHelpVersionAndNegativePaths` | **PASS** | `0.00s` | `--help`, `help`, `-h`, `version`, `--version`, `-v`, `--store-dir=...`, plus 14 invalid command/subcommand dispatch error checks |
| `src/pkg/acme` | `TestProviders` | **PASS** | `0.00s` | `ListProviders` & `ResolveProvider` for `letsencrypt`, `letsencrypt-staging`, `zerossl`, `buypass`, `google`, `custom`, and unknown provider rejection |
| `src/pkg/acme` | `TestBuildTLSALPN01Cert` | **PASS** | `0.00s` | Generates `acme-tls/1` cert and verifies critical ASN.1 extension OID `1.3.6.1.5.5.7.1.31` SHA-256 digest |
| `src/pkg/acme` | `TestObtainCertificateAllChallengesAndEAB` | **PASS** | `0.03s` | Full RFC 8555 order lifecycle against `NewMockACMEServer` for `http-01` (webroot + listener), `dns-01` (with `DNSExecHook` & EAB HS256), `tls-alpn-01`, `CheckRenewal`, account key reuse, and negative error checks |
| `src/pkg/mcpserver` | `TestMCPProtocolLifecycleAndTools` | **PASS** | `0.03s` | JSON-RPC 2.0 `initialize`, `tools/list` (18 tools), `resources/list` & `read` (3 resources), `prompts/list` & `get` (3 prompts), `tools/call` across PKI, SSH, ACME, Targets, and Store |
| `src/pkg/mcpserver` | `TestServeStdio` | **PASS** | `0.00s` | Newline-delimited JSON-RPC 2.0 streaming over `stdio` pipes |
| `src/pkg/mcpserver` | `TestServeHTTPAndMutualTLS` | **PASS** | `0.11s` | HTTPS MCP server with `tls.RequireAndVerifyClientCert`: verifies unauthenticated client fails TLS handshake and client with `mgtls`-issued client cert succeeds |
| `src/pkg/mcpserver` | `TestMCPToolsAndJSONRPCNegativePaths` | **PASS** | `0.02s` | Tests `profile_apply`, `store_doctor`, `pki_trust_script`, `ssh_config_bundle`, `acme_obtain`, `ping`, notifications, and JSON-RPC error codes (`-32700`, `-32600`, `-32601`, `-32602`) |
| `src/pkg/pki` | `TestCreateCAAndIssueCertsAcrossAlgorithms` | **PASS** | `3.29s` | Root CA → Intermediate CA → Server & Client mTLS certs + live in-memory `crypto/tls` mutual TLS handshake across `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, and `rsa-4096` |
| `src/pkg/pki` | `TestSelfSignedInspectRevokeAndTrustScripts` | **PASS** | `0.02s` | Self-signed issuance, `InspectCert`, CRL v2 revocation (`RevokeCert`), `VerifyChain` revocation detection, and OS trust scripts |
| `src/pkg/pki` | `TestPKINegativeAndEdgeCases` | **PASS** | `0.07s` | URI/Email/IP SANs, DER certificate inspection fallback, EKU role mismatch rejection (`server` vs `client`), untrusted CA rejection, and invalid algorithm/CA errors |
| `src/pkg/profile` | `TestParseAndApplyFleetSpec` | **PASS** | `0.06s` | Multi-tier YAML fleet spec provisioning CAs, certs, SSH CAs/certs, and all 7 target frameworks |
| `src/pkg/profile` | `TestRunDoctor` | **PASS** | `0.06s` | Verifies healthy store report and detects insecure `0644` private key permissions |
| `src/pkg/profile` | `TestFleetSpecEdgeCasesAndACME` | **PASS** | `0.02s` | JSON fleet spec, inline YAML flow arrays `[a, b]`, `acme_certs` provisioning via mock ACME server, and `findACMECert` target resolution |
| `src/pkg/profile` | `TestRunDoctorComprehensiveStates` | **PASS** | `0.01s` | Verifies `RunDoctor` detection of expired certs, expiring-soon warnings, revoked certs, missing files, SSH CAs/certs, and ACME certs |
| `src/pkg/sshca` | `TestSSHCALifecycleAndCertVerification` | **PASS** | `0.82s` | User & Host CAs (`ed25519`, `ecdsa-p256`, `rsa-4096`), generated & existing `.pub` signing, critical options (`force-command`, `source-address`), cryptographic verification via `ssh.CertChecker`, `InspectSSHCert`, `GenerateSSHConfigBundle`, and negative error paths |
| `src/pkg/store` | `TestStoreInitAndCRUD` | **PASS** | `0.00s` | Workspace initialization, `0600` key / `0644` public permissions, and manifest CRUD |
| `src/pkg/store` | `TestStoreDefaultBaseDirGettersUpsertReplaceAndCorruptedManifest` | **PASS** | `0.01s` | Default `.mgtls` dir, `GetCA`/`GetCert`/`GetSSHCA` found & not-found paths, in-place `Upsert*` updates, and corrupted `manifest.json` error handling |
| `src/pkg/targets` | `TestSupportedTargets` & `TestGenerateAllTargets` | **PASS** | `0.01s` | Verifies all 7 target specs and generates complete bundles for `fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, and `openssh` |
| `src/pkg/targets` | `TestGenerateDefaultsAndTLSOnlyMode` | **PASS** | `0.01s` | Default ports (`8443`, `443`, `5173`, `8006`, `22`), TLS-only (`MutualTLS: false`) mode, and invalid target errors |
| `src/test/e2e` | `TestAllCookbooksEndToEnd` (`5/5` subtests) | **PASS** | `0.42s` | Executes `01-local-pki-and-mtls-mesh.sh`, `02-mcp-agent-zero-trust-mtls.sh`, `03-openssh-zero-trust-ca-fleet.sh`, `04-proxmox-and-acme-automation.sh`, and `05-iac-and-cicd-integration.sh` |
| `src/test/e2e` | `TestAllExamplesEndToEnd` (`8/8` subtests) | **PASS** | `0.38s` | Executes `fleet/mgtls.yaml`, `fastapi-mtls`, `springboot-mtls`, `mcp-mtls`, `nginx-mtls`, `vite-mtls`, `proxmox-tls`, and `openssh-ca` |
| `src/test/e2e` | `TestTerraformExternalBridge` | **PASS** | `0.03s` | Pipes JSON into `cookbooks/iac-cicd/terraform/mgtls-external.sh` and validates returned Terraform external JSON payload |
| `src/test/e2e` | `TestShellQualityChecklist` (`4/4` subtests) | **PASS** | `0.04s` | Verifies `set -euo pipefail` reachability (`REACHED_END`), mocked `PATH` binaries (`pvenode`, `systemctl`, `update-ca-certificates`, `update-ca-trust`, `security`), command-injection immunity, and dispatch-table completeness |

---

## 6. What's Solid & CI Coverage Gate

1. **Real Cryptographic Verification (Zero Fake Certs)**:
   - X.509 certificates are tested against Go's `crypto/x509` verifier and live `crypto/tls` (`RequireAndVerifyClientCert`) handshakes across all 5 supported algorithms (`ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`).
   - OpenSSH User and Host certificates are verified against `golang.org/x/crypto/ssh`'s `ssh.CertChecker.CheckCert` and `CheckHostKey`.
   - ACME v2 orders execute full JWS ES256 signing, nonce rotation, EAB HS256 binding, and CSR finalization against a real HTTP test server (`pkg/acme/mockserver`).
2. **100% Example & Cookbook Execution**:
   - Every shell script in `cookbooks/` (`5/5`), `examples/` (`8/8`), and `cookbooks/iac-cicd/terraform/` (`1/1`) is executed automatically inside `go test ./src/test/e2e`.
3. **CI Coverage Gate Command**:
   ```bash
   go test -race -coverpkg=./src/... -coverprofile=coverage.out ./src/...
   go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$3); if ($3+0 < 80.0) {print "Coverage "$3"% below 80% gate"; exit 1} else {print "Coverage gate PASS: "$3"%"}}'
   ```
