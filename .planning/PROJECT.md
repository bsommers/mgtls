# Project: mgtls — Unified TLS, mTLS, Local/Public CA, OpenSSH Certificate & Target Provisioning Engine (CLI + MCP Server)

## Vision
`mgtls` is a single-binary Go (`go1.26`) cryptographic orchestration tool and Model Context Protocol (MCP) server that simplifies the creation, lifecycle management, and framework scaffolding of X.509 TLS/mTLS certificates, multi-tier local Certificate Authorities (Root + Intermediate CA chains), self-signed certificates, OpenSSH User & Host CAs/certificates, and automated public ACME certificates (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services).

It bridges the gap between raw cryptographic primitives (`openssl`, `ssh-keygen`, `certbot`) and production-ready deployments for Python FastAPI, Spring Boot REST APIs, MCP Servers, NGINX, Vite, Proxmox VE, and OpenSSH fleets—accessible both via an ergonomic CLI and natively as an MCP Server (`mgtls mcp serve`) for AI agents and automation tools.

## Core Capabilities
1. **X.509 PKI, Local CAs & Mutual TLS (`pkg/pki`)**:
   - Root CA, Intermediate CA, and multi-tier CA chain generation (`fullchain.pem`, `ca-bundle.pem`).
   - Standalone self-signed certificate generation.
   - Server, Client, and Dual mTLS certificate issuance with SANs (DNS, IP, URI, Email) and key algorithms (`ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`).
   - Certificate inspection, chain verification, CRL generation/revocation, PEM/DER/PKCS#12 bundle export, and OS trust store installation script generation.
2. **OpenSSH CA & Certificate Engine (`pkg/sshca`)**:
   - SSH User CA & SSH Host CA keypair generation.
   - User & Host public key signing (`*-cert.pub`) with principals, validity intervals, critical options (`force-command`, `source-address`), and extensions (`permit-pty`, `permit-port-forwarding`, etc.).
   - Certificate inspection and automated generation of `sshd_config`, `ssh_config`, `authorized_principals`, and `@cert-authority` `known_hosts` bundles.
3. **ACME v2 & Free Public Encryption (`pkg/acme`)**:
   - Built-in RFC 8555 ACME v2 client supporting Let's Encrypt (Prod/Staging), ZeroSSL (with EAB), Buypass, Google Trust Services (with EAB), and custom ACME directories (Step-CA, Pebble).
   - Supports HTTP-01, TLS-ALPN-01 (`acme-tls/1`), and DNS-01 challenges, plus a deterministic local mock ACME RFC 8555 server (`pkg/acme/mockserver`) for offline verification.
4. **Target Framework & Server Scaffolding (`pkg/targets`)**:
   - Drop-in configurations, server/client code snippets, deployment scripts, and verification harnesses for:
     - `fastapi` (Python FastAPI / Uvicorn + `httpx` mTLS client)
     - `springboot` (Spring Boot 3 `application.yml` SSL bundles + `RestClient` mTLS config)
     - `mcp` (Model Context Protocol Server + Client mTLS transport wrappers in TypeScript/Python/Proxy)
     - `nginx` (NGINX TLS 1.3 + strict `ssl_verify_client on` mTLS reverse proxy)
     - `vite` (Vite dev/preview HTTPS + mTLS configuration)
     - `proxmox` (Proxmox VE `pveproxy-ssl.pem` / `pvenode cert set` automation)
     - `openssh` (OpenSSH daemon and client CA trust automation)
5. **Declarative Fleet Manifests (`pkg/profile`)**:
   - Declarative YAML/JSON (`mgtls.yaml`) provisioning entire multi-CA, mTLS, SSH CA, ACME, and target fleets idempotently via `mgtls apply -f mgtls.yaml`.
6. **Built-in MCP Server (`pkg/mcpserver`)**:
   - Full JSON-RPC 2.0 Model Context Protocol server (`mgtls mcp serve`) over `stdio` and `http`/`https` (including self-hosted mTLS!).
   - Exposes structured MCP Tools, Resources, and Prompts so AI agents and tools can provision CAs, issue mTLS/SSH certs, run ACME orders, inspect chains, and generate target setups programmatically.
