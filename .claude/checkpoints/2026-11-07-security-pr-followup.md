# Checkpoint — 2026-11-07 (mgtls security PR follow-up)

## State
- Worktree: /home/bill/src/sysadmin/mgtls-review, branch `review/security-hardening`, clean at bc1f542, pushed.
- PR: https://github.com/bsommers/mgtls/pull/1 (open). `main` untouched at 0607655. No background jobs.
- Baseline: `go test -race ./...` 9/9 pass, gofmt clean, govulncheck 0 reachable.
- Authorized: commit + push to this branch and update the PR (the user's original request). Nothing else outward-facing.

## User decisions (verbatim)
- "SSH principlas file - is it OK to have one file per user? if so, go do it"
- "Revoked certificates - honor revocation leave an option for rotation, too, if possible."

## Task 1 — per-user AuthorizedPrincipalsFile (plan item P1)
Code: src/pkg/sshca/sshca.go, GenerateSSHConfigBundle (~lines 493-665), with SSHConfigRequest/SSHConfigBundle structs at ~70-88.
Currently writes ONE `outDir/authorized_principals` file and `AuthorizedPrincipalsFile <that path>`.
Design:
- Add `AccountPrincipals map[string][]string` (json/yaml `account_principals`) to SSHConfigRequest.
- Write `outDir/auth_principals/<account>` (dir 0755, files 0644, via store.WriteFileAtomic), one per account.
- sshd drop-in: `AuthorizedPrincipalsFile <outDir>/auth_principals/%u`.
- Validate account names with a POSIX username regex (`^[a-z_][a-z0-9_.-]{0,31}$`; also reject `..` and `/`). Validate principals with the existing validatePrincipal(p,false).
- Fallback when only `Principals` is given: write one file per principal p, at `auth_principals/p` containing `p`, so a principal logs in only as the same-named account. Document this.
- Bundle result: add `AuthorizedPrincipalsDir` and keep `AuthorizedPrincipals` pointing to the dir (or deprecate it). Files map: `auth_principals/<acct>`.
- CLI: in src/cmd/mgtls/main.go `ssh config`, add a repeatable `--account alice=alice,sre` flag. MCP: add `account_principals` to the ssh_config_bundle schema (mcpserver.go ~402).
- Tests: update sshca_test.go:274 (directive check) and the bundle test in sshca security_test.go. New test: account isolation, invalid account names, %u in the drop-in.
- Docs: README:282, examples/openssh-ca/README.md:33, docs/user-guide/SSH_CA_AND_ACME_GUIDE.md:107, SYSTEM_ARCHITECTURE.md:210, MCP_SERVER_SPEC.md:246, CHANGELOG Unreleased, SECURITY_REVIEW P1 → done.

## Task 2 — honor revocation, opt-in rotation (plan item P12)
Code: src/pkg/profile/profile.go RunRenewalCycle (~562). Line ~592: `if c.Revoked || c.NotAfter.Before(cutoff)` marks revoked certs for renewal.
Design:
- By default, revoked certs are NOT reissued, in both manifest mode and store-only mode, including the `GetCert`-exists check for spec entries. Add `SkippedRevoked []string` to RenewalCycleReport.
- Opt-in: a `reissueRevoked bool` param (or an options struct) on RunRenewalCycle. Add `ReissueRevoked` to WatchOptions (line 61) and to the systemd request (line ~94, render as `--reissue-revoked`). CLI `watch --reissue-revoked` (main.go ~1031) and systemd generate (~1073).
- Update all RunRenewalCycle callers (Watch lines 745/779, plus a grep for others, including mcpserver).
- Tests: revoked cert skipped by default; reissued with the flag.
- Docs: CHANGELOG (behavior change), SECURITY_REVIEW P12 → done, watch help text.

## Finish
gofmt, go vet, `go test -race ./...`, govulncheck. Two commits (feat(sshca)…, fix(watch)…), each with the Co-Authored-By trailer `Claude Opus 5.5 <noreply@anthropic.com>`. Push, then update the PR body's Breaking changes and Decisions sections via `gh pr edit 1`.
