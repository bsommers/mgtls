# Implementation Plan & Interface Contracts — `mgtls`

## 1. Goal
Build `mgtls`, a static Go (`go1.26`) CLI binary and Model Context Protocol (MCP) server that provisions and manages local X.509 CAs, multi-tier CA chains, self-signed certificates, Server/Client mTLS certificates, OpenSSH User/Host CAs and certificates, free public ACME v2 certificates (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services), and drop-in framework setups (`fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`).

## 2. Motivation
Setting up mTLS across polyglot services (Python FastAPI, Spring Boot, MCP servers, NGINX, Vite, Proxmox VE) and OpenSSH CA fleets requires stitching together `openssl`, `ssh-keygen`, `certbot`, and framework-specific config syntax. `mgtls` unifies these into a deterministic, contract-tested engine callable by both humans (CLI) and AI agents (MCP JSON-RPC 2.0 server).

## 3. Architecture
```
                   ┌──────────────────────────────────────┐
                   │             cmd/mgtls                │
                   │  CLI Commands   │  `mgtls mcp serve` │
                   └────────┬────────┴─────────┬──────────┘
                            │                  │
                            ▼                  ▼
                   ┌─────────────────┐┌───────────────────┐
                   │   pkg/profile   ││   pkg/mcpserver   │
                   │ (mgtls.yaml)    ││ (JSON-RPC 2.0 MCP)│
                   └────────┬────────┘└────────┬──────────┘
                            │                  │
        ┌───────────────────┼──────────────────┼───────────────────┐
        ▼                   ▼                  ▼                   ▼
┌───────────────┐   ┌───────────────┐  ┌───────────────┐   ┌───────────────┐
│    pkg/pki    │   │   pkg/sshca   │  │   pkg/acme    │   │  pkg/targets  │
│ X.509 / mTLS  │   │  OpenSSH CAs  │  │ RFC 8555 ACME │   │ 7 Frameworks  │
└───────┬───────┘   └───────┬───────┘  └───────┬───────┘   └───────┬───────┘
        └───────────────────┴─────────┬────────┴───────────────────┘
                                      ▼
                              ┌───────────────┐
                              │   pkg/store   │
                              │ (.mgtls state)│
                              └───────────────┘
```

## 4. Package Contracts

### 4.1 `pkg/store` (Foundational State & File Security)
- `New(baseDir string) (*Store, error)`
- `(*Store) Init() error`
- `(*Store) WriteKey(relPath string, data []byte) (string, error)` (`0600`)
- `(*Store) WritePublic(relPath string, data []byte) (string, error)` (`0644`)
- `(*Store) UpsertCA(rec CARecord) error`, `(*Store) UpsertCert(rec CertRecord) error`, `(*Store) UpsertSSHCA(rec SSHCARecord) error`, `(*Store) UpsertSSHCert(rec SSHCertRecord) error`, `(*Store) UpsertACME(rec ACMERecord) error`, `(*Store) UpsertTarget(rec TargetRecord) error`
- `(*Store) LoadManifest() (*Manifest, error)`

### 4.2 `pkg/pki` (X.509 CAs, Chains, Self-Signed, mTLS, CRL, Trust Store)
- `CreateCA(s *store.Store, req CARequest) (*CAResult, error)` — supports Root (`ParentCA == ""`) and Intermediate (`ParentCA != ""`), algorithms `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`.
- `IssueCert(s *store.Store, req CertRequest) (*CertResult, error)` — roles `server`, `client`, `mtls`, writes `cert.pem`, `key.pem`, `fullchain.pem`, `ca-chain.pem`, `cert.der`, and `.pfb`/`.p12` bundle.
- `IssueSelfSigned(s *store.Store, req SelfSignedRequest) (*CertResult, error)` — standalone self-signed certificate.
- `InspectCert(certPath string) (*CertInfo, error)`
- `VerifyChain(certPath, caBundlePath, crlPath, dnsName, role string) (*VerifyResult, error)`
- `RevokeCert(s *store.Store, caName, certName string, reasonCode int) (string, error)` — updates CRL PEM for `caName`.
- `GenerateTrustScript(caCertPath, name string) (map[string]string, error)` — returns OS scripts (`linux-debian.sh`, `linux-rhel.sh`, `macos.sh`, `windows.ps1`).

### 4.3 `pkg/sshca` (OpenSSH User & Host CA & Certificates)
- `CreateSSHCA(s *store.Store, req SSHCARequest) (*SSHCAResult, error)` — `caType` (`user` or `host`), `algo` (`ed25519`, `ecdsa-p256`, `rsa-4096`).
- `SignSSHCert(s *store.Store, req SignSSHRequest) (*SignSSHResult, error)` — generates keypair if `PubKeyPath == ""`, signs with User or Host CA, writes `*-cert.pub`.
- `InspectSSHCert(certPath string) (*SSHCertInfo, error)`
- `GenerateSSHConfigBundle(s *store.Store, req SSHConfigRequest) (*SSHConfigBundle, error)` — generates `sshd_config.d/mgtls-ca.conf`, `ssh_config.d/mgtls.conf`, `authorized_principals`, and `known_hosts`.

### 4.4 `pkg/acme` (Public Free Encryption & RFC 8555 ACME v2)
- `ListProviders() []ProviderInfo` — `letsencrypt`, `letsencrypt-staging`, `zerossl`, `buypass`, `google`, `custom`.
- `ObtainCertificate(ctx context.Context, s *store.Store, req ObtainRequest) (*ObtainResult, error)` — implements RFC 8555 JWS ES256 client, EAB support, HTTP-01, TLS-ALPN-01 (`1.3.6.1.5.5.7.1.31`), DNS-01, CSR signing, and certificate chain download.
- `pkg/acme/mockserver`: `NewMockACMEServer() *MockServer` — full in-memory RFC 8555 ACME directory/nonce/account/order/challenge/finalize/cert server for offline tests.

### 4.5 `pkg/targets` (Framework & Server Scaffolding)
- `SupportedTargets() []TargetSpec` — `fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh`.
- `Generate(s *store.Store, req GenerateRequest) (*GenerateResult, error)` — auto-provisions or links CA + Server/Client mTLS certs and renders complete framework configs, runnable server/client templates, and verification scripts into output directory.

### 4.6 `pkg/profile` (Declarative Fleet Provisioning & Doctor)
- `LoadManifestFile(path string) (*FleetSpec, error)`
- `Apply(ctx context.Context, s *store.Store, spec *FleetSpec) (*ApplyReport, error)`
- `RunDoctor(s *store.Store, warnDays int) (*DoctorReport, error)`

### 4.7 `pkg/mcpserver` (Model Context Protocol Server)
- `NewServer(s *store.Store) *Server`
- `(*Server) HandleJSONRPC(ctx context.Context, reqBytes []byte) ([]byte, error)`
- `(*Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error`
- `(*Server) ServeHTTP(ctx context.Context, addr, tlsCert, tlsKey, clientCA string) error`

## 5. Global Constraints
1. `CGO_ENABLED=0` pure Go compilation.
2. All private keys must be written with mode `0600`.
3. Subagents own disjoint package directories (`pkg/pki`, `pkg/sshca`, `pkg/acme`, `pkg/targets`, `pkg/profile`, `pkg/mcpserver`, `cmd/mgtls`) and never touch git state directly.
4. All packages must pass `go test -v -race ./...`.
