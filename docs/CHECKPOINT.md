# Session Checkpoint — `mgtls`

- **Status:** COMPLETE (All user requests fulfilled, tested, committed, and pushed to `origin/main`)
- **Repository:** `/home/bill/src/sysadmin/mgtls` (`https://github.com/bsommers/mgtls`, branch `main`, tag `v1.0.0`)
- **Goal & User Decisions (Verbatim):**
  1. Go (`go1.26`) static zero-CGO binary (`./src/cmd/mgtls`) + packages under `src/pkg/{store,pki,sshca,acme,targets,profile,mcpserver}`.
  2. Full X.509 PKI (Root/Intermediate CAs, self-signed certs, Server/Client mTLS certs, CRLs, OS trust scripts), OpenSSH User/Host CAs, RFC 8555 ACME v2 client (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services), and 7 framework targets (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`).
  3. Built-in Model Context Protocol (MCP) JSON-RPC 2.0 server (`mgtls mcp serve` over `stdio` and mTLS HTTP).
  4. Branding (`assets/` & `docs/assets/`), GitHub Pages (`docs/index.html` at `https://bsommers.github.io/mgtls/`), GitHub About metadata, executable `cookbooks/` + IaC/CI-CD templates, expanded Purpose/Problem statements, and Open-Source Ecosystem Comparison + ASCII Heatmap (`docs/architecture/ECOSYSTEM_COMPARISON.md`).
- **Working-Tree State:** Clean (`main` synced with `origin/main`), no background tasks running.
- **Next Command (if resuming in a new session):**
  `go test -race ./src/...`
