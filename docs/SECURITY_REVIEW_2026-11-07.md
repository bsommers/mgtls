# mgtls Security & Code Review and Improvement Plan (2026-11-07)

**Branch:** `review/security-hardening` (base `main` @ `0607655`, v1.2.0)
**Method:** a multi-lens audit (`swe-skills-2` skills used: `running-multi-lens-audits`, `security-best-practices`,
`hardening-trust-boundaries`, `bounding-untrusted-resource-use`, `controlling-processes-safely`,
`hunting-silent-failures`, `dependency-audit`, `making-verifiable-claims`, `keeping-docs-in-sync`).
The audit ran three independent lenses: (1) the network surfaces (MCP server, ACME client, store), (2) PKI and SSH CA
correctness, and (3) the CLI, watch daemon, generators and installer. Tooling ran alongside them: `govulncheck`,
`gosec`, `go vet`, `go test -race`, `shellcheck`, and a `docker build` smoke test.
Every finding fixed in this branch has a regression test in `src/pkg/*/security_test.go`. Findings that are not
fixed are listed in §4 with a proposed fix.

## 1. Baseline (before changes)

| Check | Result |
|---|---|
| `go test -race ./...` | 9/9 packages pass |
| Coverage | cmd 83.1%, acme 74.8%, mcpserver 85.8%, pki 83.0%, profile 82.2%, sshca 81.2%, store 90.3%, targets 89.2% |
| `govulncheck ./...` | **28 reachable stdlib vulnerabilities** (go1.26.0; fixed in go1.26.1–1.26.10), plus 1 unreached `x/crypto` vuln |
| `gosec` | 40 issues (most are expected G304/G306 file reads and modes; the real ones are triaged below) |
| `gofmt -l` | 11 files not formatted |
| CI | **none** (no `.github/workflows`) |

## 2. Executive summary

mgtls's cryptographic core is sound. It uses 128-bit CSPRNG serials, a 5-minute backdate, the correct ES256 JWS and
EAB HMAC, and verifies ssh-agent signers by fingerprint. The weaknesses are at the **trust boundaries**, where
untrusted data turns into paths, shell, config directives or privileges:

1. **MCP HTTP server was unauthenticated by default.** Any local process could call it, and so could a web page,
   through a `text/plain` cross-origin POST or DNS rebinding. That gave CA signing plus host command execution
   (`acme_obtain.dns_exec_hook` runs `sh -c`).
2. **Name → path aliasing.** `SafePath` only kept writes inside the store. An ACME or MCP request named `../ca/root`
   could overwrite a CA's `key.pem`.
3. **OpenSSH certificates with no principals** were signed silently. OpenSSH treats such a certificate as valid for
   every user or host. Config bundles also silently authorized `root` and `admin`.
4. **Injection in generators.** Several generators interpolated values without escaping:
   - Trust scripts used Go `%q`, which still lets `$(…)` expand.
   - Target configs and scripts were rendered from unvalidated host, path and URL values.
   - systemd units were built from raw strings, so a newline injected directives and `%`/`$` were expanded.
5. **Store races.** The store had only an in-process mutex and used a fixed temp file name. The watch daemon, the
   CLI and the MCP server lost each other's manifest updates (reproduced: 21 of 40 writes survived). Key writes
   also followed symlinks.
6. **Watch daemon fragility.** The first failing certificate stopped the cycle and the whole daemon. Certificates
   already renewed in that cycle never triggered the reload hook, so services kept serving the old certificate.
   There was no SIGTERM handling.
7. **Supply chain.** The toolchain had 28 reachable stdlib CVEs. The container ran as root, although the CHANGELOG
   said otherwise. The installer installed an unverified binary when neither `sha256sum` nor `shasum` was present,
   and under `curl | bash` it would build whatever repository was in the current directory.

## 3. Findings fixed in this branch

Severity: C = critical, H = high, M = medium, L = low. "Repro" means a test fails on `main` and passes here.

| # | Sev | Area | Finding | Fix | Test |
|---|---|---|---|---|---|
| F1 | C | `mcpserver.ServeHTTP` | HTTP transport had no auth. Any local or browser-origin caller got CA signing and RCE. | Startup now requires mTLS (`--client-ca`) or a bearer token (`MGTLS_MCP_TOKEN` / `--token-file`, ≥32 chars, `subtle.ConstantTimeCompare`). `--insecure-no-auth` works on loopback only. Plaintext is refused off loopback. | `TestServeHTTPRefusesUnauthenticatedOrExposedPlaintext`, `TestHTTPHandlerAuthOriginAndContentType` |
| F2 | H | `mcpserver` handler | Cross-origin and DNS-rebinding requests were accepted. Bodies were silently truncated at 10 MiB. Only `ReadHeaderTimeout` was set. | Requests with `Origin` get 403. Non-`application/json` gets 415. `MaxBytesReader` returns 413. Read, write and idle timeouts and `MaxHeaderBytes` are set. | same |
| F3 | H | `mcpserver` `acme_obtain`, `profile_apply` | MCP callers could pass `dns_exec_hook` (`sh -c`) and `skip_verify_tls`, directly or inside an inline manifest. | Both are gated behind `--allow-exec-hooks`. | `TestProfileApplyCannotSmuggleExecHook`, the existing MCP test now asserts the refusal |
| F4 | H | `store`, `pki`, `sshca`, `acme`, `targets`, `profile` | Names were joined into paths without validation, so `../ca/root` aliased another artifact's key. | A single `store.ValidName` allowlist (`^[A-Za-z0-9][A-Za-z0-9._-]*$`, ≤64, no `..`) is enforced at every entry point. | `TestValidNameRejects…`, `TestNamesWithTraversalAreRejected`, `TestObtainRejectsNameThatAliasesCAKey`, `TestGenerateRejects…`, `TestSystemdUnits…` |
| F5 | H | `acme` http-01 | The challenge token from the server was used as a webroot file name (`../../etc/cron.d/x`). | Tokens must match `^[A-Za-z0-9_-]{1,256}$`. The authorization identifier must be one of the requested domains. | `TestValidACMEToken` |
| F6 | M | `acme` | Server responses were unbounded. A garbage or substituted certificate was stored with fabricated "now+90d" validity. A corrupt account key was silently replaced. Solver servers had no timeouts. | Responses are capped at 1 MiB and error bodies truncated. `validateIssuedCert` checks the key match and `VerifyHostname` for every domain. A corrupt account key is an error. Solver servers and connections have deadlines. | `TestValidateIssuedCertRejectsGarbageAndWrongKey` |
| F7 | H | `sshca.SignSSHCert` | Empty principals meant "any user or host". Principals were not validated (newline, comma). A host CA could sign user certs. A supplied `CASigner` was not checked. `ValidHours` could overflow. | Empty principals are refused. Principals are allowlisted, with wildcards allowed only for host certs. The CA type must match. The signer fingerprint must match the record. Validity is capped at 10 years. | `TestSignRejects…` |
| F8 | H | `sshca.GenerateSSHConfigBundle` | Bundles defaulted to authorizing `root` and `admin`. A newline in a host pattern or principal injected `ssh_config` / `authorized_principals` lines. | No default principals when trusting a user CA. Patterns and principals are validated, and the output dir is checked for whitespace and control characters. | `TestConfigBundleRejectsDirectiveInjection` |
| F9 | H | `pki.GenerateTrustScript` | Go `%q` is not shell quoting, so `$(…)` and backticks still ran in the sudo command. The PowerShell variant was also broken. | Added `pki.ShellQuote` (POSIX single quotes). PowerShell now uses single quotes with `''`, plus `--` separators. Control characters are rejected. | `TestTrustScriptQuotesShellAndPowerShell`, `TestShellQuote` |
| F10 | H | `targets.Generate` | Host, path and `upstream_url` values were rendered into shell, nginx, Caddy, sshd, YAML, TS and Java unescaped. One example is the root-run `deploy_proxmox_cert.sh`. | Host and port are validated. Every path, name and extra value rejects control characters and `" ' `` ` `` $ \ ; { }`. `upstream_url` must be an absolute http(s) URL. | `TestGenerateRejectsInjectionAndTraversal` |
| F11 | M | `targets.copyArtifactIfPresent` | All read and write errors were swallowed, so bundles referenced keys that were never written. The certs dir was 0755. | Only not-exist falls back (the intended remote-path semantics). Other errors are returned. Writes are atomic and the certs dir is 0700. | `TestGenerateSurfacesUnreadableArtifact` |
| F12 | H | `profile.GenerateSystemdUnits` | A newline in the unit name, calendar, duration or hook injected directives. `%q` is not systemd quoting, so `$VAR` and `%h` were expanded. The unit name was joined into a path. | Inputs are validated (ValidName, calendar charset, `ParseDuration`, no CR/LF/NUL, absolute binary path). Each argv element is quoted with `systemdQuote` (`\\`, `\"`, `%%`, `$$`). Added `NoNewPrivileges=true`. | `TestSystemdUnitsRejectInjectionAndQuoteSpecifiers` |
| F13 | H | `profile.RunRenewalCycle` / `Watch` | The first error aborted the cycle and the daemon. Renewed certs never got target regeneration or the hook. Reload errors were ignored. The hook had no timeout. | Per-item errors are collected (`errors.Join`, `report.errors`) and the cycle continues. Targets and the hook still run. The daemon keeps looping and `--once` returns the error. Reload errors are reported. The hook has a 5-minute timeout. | `TestRenewalCycleContinuesPastFailingItem` |
| F14 | M | `cmd/mgtls` | `context.Background()` meant SIGTERM killed the process mid-write. `writeJSON` errors were discarded. | `signal.NotifyContext(SIGINT, SIGTERM)`. Report write errors go to stderr. | (manual) |
| F15 | H | `store` | The in-process mutex and a fixed `manifest.json.tmp` name lost updates across processes. | `flock` on `<store>/.lock` around every read-modify-write (unix; no-op elsewhere, documented). Unique temp files. | `TestConcurrentUpsertsFromSeparateHandlesLoseNothing` (**repro: 21/40 on main**) |
| F16 | M | `store.WriteKey/WritePublic` | Writes followed an existing symlink, and an existing 0644 file was briefly world-readable before the `Chmod`. | `WriteFileAtomic`: `CreateTemp` (O_EXCL) at the final mode, fsync, rename, then fsync of the directory. | `TestWriteKeyReplacesSymlinkInsteadOfFollowing` (**repro: wrote through symlink on main**) |
| F17 | H | `go.mod` | 28 reachable stdlib CVEs under go1.26.0 (crypto/x509, crypto/tls, net/http…). | `toolchain go1.26.10`. govulncheck now reports **0 reachable**. | `govulncheck ./...` |
| F18 | M | `Dockerfile` | The container ran as root and `/data` (CA keys) was root-owned. The CHANGELOG claimed non-root. | `USER 65532:65532`, `/data` chowned with mode 0700, base pinned to `golang:1.26.10-alpine`. Verified with `docker build` + `ca create`. | docker smoke test |
| F19 | M | `install.sh` (×3 copies) | No sha tool meant an unverified install. Under `curl \| bash`, it built from the CWD. `--version` was unvalidated. Uninstall `rm -rf`'d a share dir it never created. The default version was stale (v1.1.1). | Each of these now fails closed. The default is v1.2.0. | `bash -n`, `shellcheck`, dry runs |
| F20 | L | docs | The CHANGELOG 1.2.0 claimed `systemd generate --mode/--output/--binary/--user`, `watch --json`, `tests/run_all.sh` and a non-root container, none of which existed. | Added an `[Unreleased]` entry with a "Corrections" note. Updated the README, MCP spec and example README for the new auth. | — |

**Breaking changes** (called out in the PR):
- HTTP MCP needs a token or mTLS.
- `skip_verify_tls` / `dns_exec_hook` over MCP need `--allow-exec-hooks`.
- SSH signing needs principals.
- Bundles trusting a user CA need principals.
- Stricter names: existing store entries whose names fail `ValidName` can no longer be re-issued under those names.
- The container user is 65532, so bind-mounted volumes must be writable by that UID.

## 4. Improvement plan (open items, prioritized)

Tiers follow `running-multi-lens-audits`: 0 = correctness/safety, 1 = robustness, 2 = hygiene, 3 = roadmap.

### Tier 0 — next PR

| # | Sev | Item | Proposed fix |
|---|---|---|---|
| P1 | H | The generated `AuthorizedPrincipalsFile` is a **single global file**, so any certificate carrying any listed principal can log in as *every* local account. | Emit `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u` plus one file per account (map `account → principals`). Update `SSH_CA_AND_ACME_GUIDE.md`. |
| P2 | M | Authenticated MCP callers can still read or write **arbitrary host paths**: `target_generate.output_dir`, `ssh_config_bundle.output_dir`, `pki_inspect.cert_path`, `pki_verify.crl_path`, `profile_apply.manifest_path`, `ssh_sign_cert.agent_socket`, `acme_obtain.webroot_dir`. | Add a `--allowed-root` (default: the store) and resolve every path with `os.Root` (Go 1.24+). Reject anything outside it. |
| P3 | M | ACME directory and SSRF: `http://` directories are accepted, and `newNonce/newOrder/authz/cert` URLs are followed without checking. | Require https except on loopback. Require the same host as the directory (or an allowlist). Set `CheckRedirect` limits. Retry once on `badNonce`. Check the HEAD nonce status. |
| P4 | M | CRL correctness: the CRL `Number` is random (RFC 5280 §5.2.3 requires it to be monotonic). `VerifyChain` accepts expired CRLs and CRLs with no issuer signature check, and does not match the CRL issuer to the leaf issuer. | Keep a persistent per-CA counter. Fail on `now > NextUpdate`. Require a signature from the leaf's issuer. Add a `CRLDistributionPoints` option. |
| P5 | M | `RevokeCert` marks a cert revoked before signing the CRL. It cannot revoke with an HSM CA (no signer parameter). Reason codes are unvalidated. Intermediates cannot be revoked. | Sign first, then commit. Accept a `crypto.Signer`. Validate reasons 0–10 excluding 7. |
| P6 | M | `CreateCA`, `IssueCert` and `CreateSSHCA` overwrite an existing name, replacing a root key and orphaning every certificate it issued. | Fail if the record exists unless `--force` / `Overwrite: true`. Renewal paths pass it explicitly. |
| P7 | M | CA hierarchy: `MaxPathLen` is hard-coded to 2/1. Child and leaf `NotAfter` are not clamped to the issuer. There are no NameConstraints. | Derive `MaxPathLen` from the parent's value minus 1. Clamp `NotAfter`. Add an optional `permitted_dns_domains`. |
| P8 | M | SAN validation: `*`, `*.com`, `a*b`, empty labels and malformed emails are accepted. A CN with spaces yields a certificate with no SAN. | Use an IDNA/hostname validator, allow a wildcard only as the leftmost label with ≥2 labels below, use `mail.ParseAddress`, and require ≥1 SAN for the server role. |
| P9 | M | SSH extensions default to agent, port and X11 forwarding plus user-rc. Critical options and extensions are not allowlisted, and `source-address` is not parsed. There is no KRL. | Default to `permit-pty` only. Allowlist known keys and parse CIDRs. Add `mgtls ssh-ca revoke` producing a KRL and `RevokedKeys`. |
| P10 | M | The `--on-renew` and `dns_exec_hook` hooks get the full `os.Environ()` and run through `sh -c`. | Pass an allowlisted environment and support an argv/script-path form. Keep `sh -c` only as an explicit opt-in. |

### Tier 1 — robustness

| # | Item | Proposed fix |
|---|---|---|
| P11 | Store-only `watch` (no `-f`) silently ignores expiring SSH and ACME certificates and never regenerates targets. | Renew them from stored metadata, or report them in `report.errors`. |
| P12 | Revoked certificates are auto-reissued every cycle (`c.Revoked \|\| …`). That is a policy decision: rotation versus honoring revocation. | Add `renew_revoked: false` by default and report revoked items. **Needs owner decision.** |
| P13 | `watch` flags: `--interval/--renew-before ≤ 0` silently fall back to defaults, and `-f` and `--manifest` both accepted with `-f` silently winning. `systemd generate` lacks the `-f` alias. | Validate the values and error on conflicts. |
| P14 | MCP: no per-call timeout or concurrency cap. A stdio line over 10 MiB kills the server. `decodeArgs` is lenient (unknown fields, unbounded `valid_days`/`http_port`/`reason_code`). | Wrap dispatch in `context.WithTimeout`, add a semaphore, use `DisallowUnknownFields` and range checks. |
| P15 | `prompts/get` interpolates caller arguments into prompt text unescaped, which allows prompt injection. | Quote or JSON-encode the arguments. |
| P16 | http-01 and tls-alpn-01 solvers bind `127.0.0.1` only, so a real CA cannot reach them without a forwarder. | Add a `--solver-addr` flag and document it. |
| P17 | `mockserver.go` (`httptest`, panics) ships in the production `acme` package. | Move it to `internal/acmetest` or a `_test.go` file. |
| P18 | With HSM signers, the algorithm label comes from `req.Algorithm`, not the signer. | Derive it from `signer.Public()`. |
| P19 | The systemd unit has `ProtectSystem=full` but no `ReadWritePaths`, so hooks or targets writing to `/etc` fail with EROFS. The unit has no `User=`. | Emit `ReadWritePaths=<store> <target dirs>`, an optional `User=`, `ProtectHome`, `PrivateDevices`. |
| P20 | `SafePath` is lexical only, so an attacker-planted symlink *directory* inside the store still escapes. Needs prior write access to a 0700 directory. | Use `os.Root` for every store access. |

### Tier 2 — hygiene & supply chain

| # | Item | Proposed fix |
|---|---|---|
| P21 | **No CI.** | Add `.github/workflows/ci.yml` running `gofmt -l`, `go vet`, `go test -race`, `govulncheck`, `gosec` (triaged baseline), `shellcheck`, `docker build`. Pin actions by SHA, set `permissions: contents: read` (`hardening-ci-workflows`). |
| P22 | Release artifacts are checksummed but **not signed**, and SHA256SUMS comes from the same origin as the binary. | Sign with cosign keyless or minisign. The installer verifies the signature when the tool is present and documents the fallback. |
| P23 | Base images are pinned by tag, not digest. | Pin `golang@sha256:…`. Add Renovate or Dependabot. |
| P24 | `x/crypto v0.58.0` has 1 vulnerability, unreached by this code. The fix is only in a pseudo-version so far. | Bump to the next tagged release. |
| P25 | `gofmt` drift in 11 pre-existing files. | **Done here as a separate style-only commit** (no behavior change). Enforce `gofmt -l` in CI. |
| P26 | The installer's `--copy` flag is parsed but has no effect (shellcheck SC2034). There are three byte-identical copies of `install.sh`. | Implement or remove `--copy`. Generate `scripts/` and `docs/` copies from one source plus a CI diff check. |
| P27 | `docs/CODE_REVIEW.md` rates every axis "Pass" for Security, and other docs carry stale counts. | Link to this review. Regenerate claims from commands (`making-verifiable-claims`). |

### Tier 3 — roadmap

- ACME account and EAB key storage via the signer seam (HSM).
- OCSP responder or short-lived certificates as an alternative to CRLs.
- A `mgtls doctor` check for store permissions (0700), unvalidated legacy names, and an unauthenticated MCP configuration.

## 5. Verification (after changes)

```
go vet ./src/...                     # clean
go test -race -count=1 ./...         # 9/9 packages ok (+10 new security test files)
GOOS=windows go build ./...          # ok (flock stub)
govulncheck ./...                    # 0 reachable vulnerabilities
docker build . && docker run … ca create --name t   # ok as uid 65532
bash -n install.sh; shellcheck -S warning install.sh # only pre-existing SC2034 (--copy)
```

Two fixes were proven by reproducing the bug: their tests fail on `main` and pass on this branch (F15: 21/40 updates
lost; F16: the key was written through the symlink). The other new tests use APIs introduced in this branch, so they
do not compile against `main`. Each one asserts the specific refusal or quoting behavior.
