# `mgtls` Forward Roadmap & Next Options (`v1.2.0+`)

> **Status**: All 4 Roadmap Options (Option 1: Distribution & Onboarding, Option 2: 14 Target Framework Generators, Option 3: Autonomous Renewal Daemon & `systemd` Generator, and Option 4: Hardware-Backed Root CA / KMS / `ssh-agent` Signer Seams) are **100% COMPLETED**.

---

## Completed Milestone

### [x] Option 1: Distribution & Zero-Friction Onboarding (`COMPLETED`)
- **Multi-Target Installer ([`install.sh`](../install.sh), [`scripts/install.sh`](../scripts/install.sh), [`docs/install.sh`](install.sh))**:
  - Supports `--local` (`${XDG_BIN_HOME:-$HOME/.local/bin}`), `--global` (`/usr/local/bin`), `--prefix DIR`, `--copy`, `--from-release` (downloads prebuilt binary + `SHA256SUMS` from GitHub Releases and verifies SHA-256), `--dry-run`, `--uninstall`, `--force`, and `-h/--help`.
  - Protects unmanaged binaries unless `--force` is passed and prints `export PATH="..."` + `Next steps:` breadcrumbs.
- **Minimal Scratch Container ([`Dockerfile`](../Dockerfile))**:
  - Multi-stage `CGO_ENABLED=0` Alpine builder $\rightarrow$ `FROM scratch` runtime image with CA roots and `/usr/local/bin/mgtls`.
- **In-Tool Onboarding & Workflow Breadcrumbs ([`src/cmd/mgtls/main.go`](../src/cmd/mgtls/main.go))**:
  - `mgtls init --with-root-ca --starter --yes` idempotently initializes `.mgtls/`, creates the Root CA, and writes a starter `mgtls.yaml` manifest.
  - `mgtls guide` prints the 5-stage offline onboarding lifecycle guide (`init` $\rightarrow$ `doctor` $\rightarrow$ `apply`/`target` $\rightarrow$ `ssh`/`acme` $\rightarrow$ `mcp`).
  - `mgtls init`, `mgtls apply`, and `mgtls doctor` emit progressive `Next steps:` breadcrumbs to `stderr` (suppressed via `--quiet`) so `stdout` remains pure JSON for piping.

---

## Remaining Options for Upcoming Milestones (Prompt Later)

### [x] Option 2: New Target Framework Generators (`v1.2.0` — `COMPLETED`)
Expanded `mgtls target generate` in `src/pkg/targets/targets.go` and `src/pkg/targets/templates.go` from 7 to **14 targets** (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`, `caddy`, `traefik`, `envoy`, `postgres`, `redis`, `grpc-go`, `nodejs-express`):
1. **Cloud-Native Ingress & Service Mesh**:
   - **`caddy`**: Automatic mTLS (`client_auth { mode require_and_verify }`) Caddyfile bundle.
   - **`traefik`**: Dynamic TLS `ClientAuthType: RequireAndVerifyClientCert` YAML bundle.
   - **`envoy`**: Static/xDS `DownstreamTlsContext` + SPIFFE SAN validation configuration.
2. **Data Stores**:
   - **`postgres`**: `postgresql.conf` SSL settings + `pg_hba.conf` (`hostssl ... clientcert=verify-full`) + client `psql` connection script.
   - **`redis`**: `redis.conf` (`tls-port`, `tls-auth-clients yes`) + `redis-cli --tls` verification script.
3. **Polyglot RPC & Backend**:
   - **`grpc-go`**: Go `credentials.NewTLS` mutual TLS server & client starter stubs.
   - **`nodejs-express`**: Node.js `node:https` (`requestCert: true, rejectUnauthorized: true`) mTLS server & client bundle.

---

### [x] Option 3: Autonomous Renewal Daemon & Webhook Hooks (`mgtls watch` / `systemd` — `COMPLETED`)
Added continuous lifecycle automation in `src/pkg/profile/profile.go` (`RunRenewalCycle`, `Watch`, `GenerateSystemdUnits`) and `src/cmd/mgtls/main.go` (`mgtls watch`, `mgtls systemd generate`):
1. **`mgtls watch` Daemon Subcommand**:
   - `mgtls watch --manifest mgtls.yaml --interval 12h --renew-before 720h --on-renew "systemctl reload nginx"` (plus `--once` for cron/systemd oneshot execution).
   - Periodically runs expiration checks, automatically re-issues expiring X.509 leaf certificates, self-signed certificates, OpenSSH certificates, and ACME certificates, re-renders affected target bundles, and executes `--on-renew` reload hooks with `MGTLS_STORE_DIR`, `MGTLS_RENEWED_COUNT`, and `MGTLS_RENEWED_CERTS`.
2. **`systemd` Service & Timer Generator (`mgtls systemd generate`)**:
   - Generates `mgtls-renew.service` (`PrivateTmp=true`, `ProtectSystem=full`) and `mgtls-renew.timer` (`Persistent=true`, `RandomizedDelaySec=5m`) units for unattended host deployment.

---

### [x] Option 4: Hardware-Backed Root CA & YubiKey / KMS Support (`CAP-HSM-001` — `COMPLETED`)
Implemented the planned capability from [`docs/CAPABILITIES.md`](CAPABILITIES.md):
1. **Pluggable `crypto.Signer` & `ssh.Signer` Seams (`src/pkg/pki`, `src/pkg/sshca`)**:
   - `pki.CARequest.Signer`, `pki.CARequest.ParentSigner`, and `pki.CertRequest.CASigner` accept any `crypto.Signer` (PKCS#11, YubiKey PIV, KMS, or custom hardware token) without writing CA private keys to disk.
   - `sshca.SSHCARequest.Signer`, `sshca.SignSSHRequest.CASigner`, and `sshca.SignSSHRequest.AgentSocket` (`--agent-socket` / `SSH_AUTH_SOCK`) sign OpenSSH User and Host certificates directly via hardware-backed `ssh-agent` keys.
