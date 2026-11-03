# User Guide & CLI Reference — `mgtls`

## 1. Installation & Quickstart

### Build from Source (`Go 1.26+`)

`mgtls` compiles as a single static binary with zero CGO dependencies:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mgtls ./src/src/cmd/mgtls
sudo install -m 0755 mgtls /usr/local/bin/mgtls
```

### Global Flags

Every `mgtls` command accepts the following global flags before or after the subcommand:

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--store-dir <path>` | `.mgtls` (or `$MGTLS_STORE_DIR`) | Path to the cryptographic workspace and `manifest.json` inventory |
| `--json` | `false` | Emit machine-readable JSON output instead of human tables |

---

## 2. Step-by-Step PKI & mTLS Tutorials

### 2.1 Initialize the Cryptographic Store (`mgtls init`)

Initialize an isolated store directory with `0700` permissions on private folders and an empty `manifest.json`:

```bash
mgtls init --store-dir ./.mgtls
```

---

### 2.2 Create a Root CA & Intermediate CA Hierarchy (`mgtls ca create`)

In production architectures, your Root CA key remains offline or restricted while an Intermediate CA issues operational Server and Client mTLS certificates.

```bash
# 1. Create a 10-year Ed25519 Root CA
mgtls ca create \
  --name corp-root-ca \
  --cn "Corp Internal Root CA" \
  --org "Example Corp" \
  --algo ed25519 \
  --days 3650

# 2. Create a 3-year ECDSA P-256 Intermediate CA signed by corp-root-ca
mgtls ca create \
  --name corp-int-ca \
  --parent corp-root-ca \
  --cn "Corp Production Intermediate CA" \
  --org "Example Corp" \
  --algo ecdsa-p256 \
  --days 1095
```

List all managed CAs in the store:
```bash
mgtls ca list
```

---

### 2.3 Install Root CA into OS Trust Stores (`mgtls ca trust-script`)

Generate platform-specific scripts to register `corp-root-ca` in Linux (Debian/Ubuntu, RHEL/Fedora), macOS System Keychain, and Windows `Cert:\LocalMachine\Root`:

```bash
mgtls ca trust-script --name corp-root-ca --output-dir ./trust-scripts
```

Generated scripts in `./trust-scripts/`:
- `linux-debian.sh`: Copies `ca.crt` to `/usr/local/share/ca-certificates/` and runs `update-ca-certificates`.
- `linux-rhel.sh`: Copies `ca.crt` to `/etc/pki/ca-trust/source/anchors/` and runs `update-ca-trust extract`.
- `macos.sh`: Runs `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`.
- `windows.ps1`: Runs `Import-Certificate -FilePath ... -CertStoreLocation Cert:\LocalMachine\Root`.

---

### 2.4 Issue Server, Client, Dual mTLS, and Self-Signed Certificates

#### Issue a Server TLS Certificate (`--role server`)
```bash
mgtls cert issue \
  --name orders-api-server \
  --ca corp-int-ca \
  --cn orders.internal \
  --role server \
  --algo ecdsa-p256 \
  --dns "orders.internal,localhost" \
  --ip "127.0.0.1,10.20.0.15" \
  --days 365
```

#### Issue a Client mTLS Certificate (`--role client`)
```bash
mgtls cert issue \
  --name billing-worker-client \
  --ca corp-int-ca \
  --cn "billing-worker@orders.internal" \
  --role client \
  --algo ed25519 \
  --uri "spiffe://corp.internal/ns/prod/sa/billing-worker" \
  --days 90
```

#### Issue a Peer-to-Peer Dual mTLS Certificate (`--role mtls`)
For mesh nodes (such as etcd, Consul, or peer-to-peer gRPC/MCP nodes) that act as both TLS server and mTLS client:
```bash
mgtls cert issue \
  --name mesh-node-01 \
  --ca corp-int-ca \
  --cn mesh-node-01.internal \
  --role mtls \
  --dns "mesh-node-01.internal,localhost" \
  --ip "10.20.0.21,127.0.0.1" \
  --days 180
```

#### Issue a Standalone Self-Signed Certificate (`mgtls cert self-sign`)
For single-node development or embedded appliances where a separate CA is unnecessary:
```bash
mgtls cert self-sign \
  --name quick-local-dev \
  --cn localhost \
  --algo ecdsa-p256 \
  --dns "localhost,dev.local" \
  --ip "127.0.0.1,::1" \
  --days 365
```

---

### 2.5 Inspect, Verify, and Revoke Certificates

#### Inspect Certificate Metadata (`mgtls cert inspect`)
```bash
mgtls cert inspect --cert .mgtls/certs/orders-api-server/cert.pem
```

#### Verify Certificate Chain, SANs, Role EKU, and CRL (`mgtls cert verify`)
```bash
mgtls cert verify \
  --cert .mgtls/certs/orders-api-server/fullchain.pem \
  --ca .mgtls/ca/corp-int-ca/ca-chain.pem \
  --dns orders.internal \
  --role server
```

#### Revoke a Compromised Certificate (`mgtls cert revoke`)
Revoke a certificate and automatically regenerate the issuing CA's X.509 v2 CRL (`.mgtls/ca/corp-int-ca/crl.pem`):
```bash
mgtls cert revoke \
  --ca corp-int-ca \
  --name billing-worker-client \
  --reason 1

# Verify that verification now rejects the revoked certificate when --crl is supplied:
mgtls cert verify \
  --cert .mgtls/certs/billing-worker-client/fullchain.pem \
  --ca .mgtls/ca/corp-int-ca/ca-chain.pem \
  --crl .mgtls/ca/corp-int-ca/crl.pem \
  --role client
```

---

## 3. Declarative Fleet Management (`mgtls apply`, `status`, `doctor`)

Instead of running imperative commands, you can define your entire PKI hierarchy, mTLS certificates, OpenSSH CAs, ACME certificates, and framework targets in a single `mgtls.yaml` manifest.

### Example `mgtls.yaml`

```yaml
version: "1.0"

cas:
  - name: root-ca
    common_name: "Fleet Root CA"
    organization: "Platform Engineering"
    algorithm: ed25519
    valid_days: 3650

  - name: mesh-int-ca
    parent_ca: root-ca
    common_name: "Mesh Intermediate CA"
    organization: "Platform Engineering"
    algorithm: ecdsa-p256
    valid_days: 1095

certs:
  - name: api-gateway-server
    ca_name: mesh-int-ca
    common_name: api.internal
    role: server
    algorithm: ecdsa-p256
    dns_names:
      - api.internal
      - localhost
    ip_addresses:
      - 127.0.0.1
    valid_days: 365

  - name: agent-client
    ca_name: mesh-int-ca
    common_name: mcp-agent
    role: client
    algorithm: ed25519
    uris:
      - spiffe://internal/agent/mcp-01
    valid_days: 90

ssh_cas:
  - name: fleet-user-ca
    ca_type: user
    algorithm: ed25519
  - name: fleet-host-ca
    ca_type: host
    algorithm: ed25519

ssh_certs:
  - name: admin-alice
    ca_name: fleet-user-ca
    cert_type: user
    key_id: "alice@platform"
    principals:
      - ubuntu
      - root
    valid_hours: 720

targets:
  - name: fastapi-orders
    target: fastapi
    domain: api.internal
    port: 8443
    ca_name: mesh-int-ca
    mtls: true
    output_dir: .mgtls/targets/fastapi-orders
```

### Apply the Manifest Idempotently (`mgtls apply`)

```bash
mgtls apply -f mgtls.yaml
```

### Check Inventory Status & Run Health Diagnostics (`mgtls status`, `mgtls doctor`)

```bash
# View full inventory summary
mgtls status

# Audit file permissions (0600 private keys), certificate chains, and 30-day expiry windows
mgtls doctor --warn-days 30
```

---

## 4. Complete CLI Command Summary

| Command | Subcommands | Description |
| :--- | :--- | :--- |
| `mgtls init` | — | Initialize `.mgtls` workspace directory and `manifest.json` |
| `mgtls ca` | `create`, `list`, `trust-script` | Create Root/Intermediate CAs, list CAs, generate OS trust scripts |
| `mgtls cert` | `issue`, `self-sign`, `list`, `inspect`, `verify`, `revoke` | Issue Server/Client/mTLS certs, self-sign, inspect, verify chains, revoke |
| `mgtls ssh` | `ca-create`, `sign-user`, `sign-host`, `inspect`, `config` | Create SSH User/Host CAs, sign keys, inspect `-cert.pub`, generate `sshd_config` |
| `mgtls acme` | `providers`, `obtain` | List free ACME v2 providers and obtain certificates via HTTP-01/TLS-ALPN-01/DNS-01 |
| `mgtls target` | `list`, `generate` | Scaffold configurations for `fastapi`, `springboot`, `mcp`, `nginx`, `vite`, `proxmox`, `openssh` |
| `mgtls apply` | `-f <mgtls.yaml>` | Reconcile declarative fleet YAML/JSON manifest |
| `mgtls status` | — | Display managed CAs, certificates, SSH certs, ACME certs, and targets |
| `mgtls doctor` | `--warn-days <N>` | Audit store security permissions (`0600`), file presence, and expiry windows |
| `mgtls mcp` | `serve [--http <addr>]` | Run the Model Context Protocol JSON-RPC 2.0 server (`stdio` or HTTP/HTTPS/mTLS) |
