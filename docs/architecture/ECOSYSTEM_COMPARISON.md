# Open-Source Ecosystem Comparison & Capability Heatmap — `mgtls`

## 1. Capability Heatmap (ASCII)

Legend:
- `████` **100% (Full Native Support)** — Built-in, zero-config, first-class capability
- `▓▓░░` **50% (Partial / Single-Scope)** — Covers only a subset or requires external plugins/servers
- `░░░░` **0% (Not Supported)** — Out of scope for the tool

```text
╔════════════════════════════════╦════════════╦════════════╦════════════╦════════════╦════════════╦════════════╗
║                                ║   X.509    ║  OpenSSH   ║   Public   ║ App/Server ║Declarative ║   Native   ║
║  OPEN-SOURCE TOOL              ║ Multi-Tier ║ User/Host  ║  ACME v2   ║   mTLS     ║YAML Fleet  ║ MCP Server ║
║                                ║ PKI & mTLS ║     CA     ║  Client    ║Scaffolding ║  (GitOps)  ║ (AI Agent) ║
╠════════════════════════════════╬════════════╬════════════╬════════════╬════════════╬════════════╬════════════╣
║  mgtls (Go 1.26, 0-CGO)        ║ ████  100% ║ ████  100% ║ ████  100% ║ ████  100% ║ ████  100% ║ ████  100% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  Smallstep (step-cli / step-ca)║ ████  100% ║ ████  100% ║ ████  100% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  HashiCorp Vault / OpenBao     ║ ████  100% ║ ████  100% ║ ▓▓░░   50% ║ ░░░░    0% ║ ▓▓░░   50% ║ ▓▓░░   50% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  Cloudflare cfssl              ║ ████  100% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ▓▓░░   50% ║ ░░░░    0% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  Square certstrap              ║ ████  100% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  OpenVPN easy-rsa              ║ ████  100% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  FiloSottile mkcert            ║ ▓▓░░   50% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║ ░░░░    0% ║
╟────────────────────────────────╫────────────╫────────────╫────────────╫────────────╫────────────╫────────────╢
║  lego / certbot / acme.sh      ║ ░░░░    0% ║ ░░░░    0% ║ ████  100% ║ ▓▓░░   50% ║ ░░░░    0% ║ ░░░░    0% ║
╚════════════════════════════════╩════════════╩════════════╩════════════╩════════════╩════════════╩════════════╝

  Overall Ecosystem Coverage Score (out of 6 Core Dimensions):
  ──────────────────────────────────────────────────────────────────────────────
  mgtls                     ████████████████████████████████████  6.0 / 6.0 (100%)
  HashiCorp Vault / OpenBao █████████████████████░░░░░░░░░░░░░░░  3.5 / 6.0  (58%)
  Smallstep (step-cli/ca)   ██████████████████░░░░░░░░░░░░░░░░░░  3.0 / 6.0  (50%)
  Cloudflare cfssl          █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.5 / 6.0  (25%)
  lego / certbot / acme.sh  █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.5 / 6.0  (25%)
  Square certstrap          ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.0 / 6.0  (17%)
  OpenVPN easy-rsa          ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.0 / 6.0  (17%)
  FiloSottile mkcert        ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.5 / 6.0   (8%)
```

---

## 2. Feature Matrix

| Tool | Language | Local X.509 CA & mTLS | OpenSSH User/Host CA | Public ACME Client (LE/ZeroSSL/etc.) | App/Server Config Scaffolding (FastAPI, Spring, NGINX, Vite, Proxmox, MCP) | Declarative Fleet (`mgtls.yaml`) | Native MCP Server for AI Agents |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`mgtls`** | **Go** | **Yes** | **Yes** | **Yes** | **Yes (7 targets)** | **Yes** | **Yes (`stdio` + mTLS HTTP)** |
| **Smallstep (`step-cli` + `step-ca`)** | Go | Yes | Yes | ACME Server + Client | No (raw certs only) | No | No |
| **HashiCorp Vault (PKI + SSH + ACME)** | Go | Yes (heavy server) | Yes | Yes | No | Via Terraform | Community plugins only |
| **Cloudflare `cfssl`** | Go | Yes | No | No | No | JSON profiles only | No |
| **Square `certstrap`** | Go | Yes | No | No | No | No | No |
| **OpenVPN `easy-rsa`** | Shell / OpenSSL | Yes | No | No | No | No | No |
| **FiloSottile `mkcert`** | Go | Local dev Root CA only | No | No | No | No | No |
| **`lego` / `certbot` / `acme.sh`** | Go / Py / Sh | No | No | Yes | NGINX/Apache only (`certbot`) | No | No |

---

## 3. Detailed Tool Breakdown

1. **Smallstep (`step` CLI & `step-ca`)** — *Closest cryptographic neighbor*
   - **Strengths**: Written in Go; handles both X.509 CAs/mTLS and OpenSSH User/Host certificates (`step ssh`).
   - **Gaps vs. `mgtls`**: Designed around a long-running online CA daemon (`step-ca`) rather than a zero-setup declarative fleet & target generator. Stops at outputting `.crt`/`.key` files—does not scaffold drop-in `FastAPI`, `Spring Boot`, `Vite`, `NGINX`, `Proxmox VE`, or `MCP` server/client bundles, and has no built-in MCP server for AI agents.

2. **`mkcert` (by Filippo Valsorda)**
   - **Strengths**: Zero-config local trust store installation and local dev HTTPS certs (`mkcert localhost`).
   - **Gaps vs. `mgtls`**: Explicitly avoids intermediate CAs, CRLs, OpenSSH CAs, public ACME certificates, declarative YAML fleets, or target application configuration templates.

3. **Cloudflare `cfssl` & Square `certstrap`**
   - **Strengths**: Battle-tested Go CLIs for generating X.509 Root/Intermediate CAs and leaf certificates.
   - **Gaps vs. `mgtls`**: Pure X.509 primitives only—no OpenSSH CA support, no Let's Encrypt/ZeroSSL/Buypass/Google ACME client, no target scaffolding, and no MCP interface.

4. **`certbot` / `lego` / `acme.sh` / Caddy (`certmagic`)**
   - **Strengths**: Public ACME v2 certificate issuance and renewal against Let's Encrypt, ZeroSSL, etc.
   - **Gaps vs. `mgtls`**: Public ACME only—they do not manage private mTLS client/server hierarchies, OpenSSH User/Host CAs, or generate multi-framework mTLS code bundles.

5. **HashiCorp Vault / OpenBao (PKI + SSH Secrets Engines)**
   - **Strengths**: Enterprise X.509 PKI and OpenSSH CA signing.
   - **Gaps vs. `mgtls`**: Requires deploying, unsealing, and operating a stateful Vault cluster rather than running a single static CLI/MCP binary against a local or GitOps-managed store.
