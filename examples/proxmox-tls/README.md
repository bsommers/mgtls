# Proxmox VE Node TLS, Internal CA Chain & ACME Automation Example with `mgtls`

This example demonstrates two production workflows for securing **Proxmox Virtual Environment (Proxmox VE)** Web UI and API (`pveproxy` on port `8006`) using `mgtls`:

1. **Workflow A — Internal Multi-Tier PKI Deployment**:
   Issues a full certificate chain (`fullchain.pem` = Proxmox Node Leaf + Intermediate CA) signed by your internal Root CA, generates OS trust store scripts so workstations trust the Root CA, and deploys the certificate to `/etc/pve/local/pveproxy-ssl.pem` and `/etc/pve/local/pveproxy-ssl.key` (or via `pvenode cert set`).
2. **Workflow B — Free Public ACME v2 Certificate Automation (Let's Encrypt / ZeroSSL / Google Trust Services)**:
   Obtains a publicly trusted DV TLS certificate via RFC 8555 ACME (`dns-01`, `http-01`, or `tls-alpn-01`) and reloads `pveproxy.service`.

## Files in This Example

| File | Description |
| :--- | :--- |
| [`setup_proxmox_tls.sh`](file:///home/bill/src/sysadmin/mgtls/examples/proxmox-tls/setup_proxmox_tls.sh) | Runnable provisioning script demonstrating both internal CA chain issuance + `proxmox` target bundle generation and ACME DNS-01/HTTP-01 automation for Proxmox VE nodes. |

## Quickstart

### 1. Generate Proxmox VE Certificates, OS Trust Scripts & Deployment Bundle

```bash
./setup_proxmox_tls.sh
```

### 2. Deploy to a Proxmox VE Node

On the Proxmox VE host (as `root`), run the generated deployment script or use `pvenode`:

```bash
# Option 1: Using pvenode CLI (recommended on Proxmox VE 7.x / 8.x)
pvenode cert set \
  .mgtls-proxmox/certs/pve-node01-srv/fullchain.pem \
  .mgtls-proxmox/certs/pve-node01-srv/key.pem \
  --force --restart

# Option 2: Direct cluster filesystem installation
install -m 0640 -o root -g www-data \
  .mgtls-proxmox/certs/pve-node01-srv/fullchain.pem \
  /etc/pve/local/pveproxy-ssl.pem
install -m 0600 -o root -g www-data \
  .mgtls-proxmox/certs/pve-node01-srv/key.pem \
  /etc/pve/local/pveproxy-ssl.key
systemctl reload-or-restart pveproxy.service
```

### 3. Verify Proxmox API over TLS

```bash
curl --silent --show-error --fail \
  --cacert .mgtls-proxmox/certs/pve-node01-srv/ca-chain.pem \
  https://pve01.corp.internal:8006/api2/json/version | jq .
```
