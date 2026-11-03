#!/usr/bin/env bash
# Cookbook 04: Proxmox VE Node TLS Deployment & Free Public ACME v2 Automation
# Lists supported free public ACME v2 authorities (Let's Encrypt, ZeroSSL, Buypass, Google Trust),
# provisions a Proxmox VE cluster CA + node certificate, and emits pveproxy deployment scripts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${MGTLS_COOKBOOK_DIR:-$(mktemp -d -t mgtls-cb04-XXXXXX)}"
STORE_DIR="${WORK_DIR}/.mgtls"
OUT_DIR="${WORK_DIR}/proxmox-pve01"

if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
  MGTLS=("${REPO_ROOT}/bin/mgtls" "--store-dir" "${STORE_DIR}")
else
  MGTLS=("go" "run" "${REPO_ROOT}/src/cmd/mgtls" "--store-dir" "${STORE_DIR}")
fi

echo "==> [Cookbook 04] Initializing Proxmox & ACME Store at ${STORE_DIR}"
"${MGTLS[@]}" init

echo "==> [1/3] Querying Built-In Free Public ACME v2 Certificate Authorities"
"${MGTLS[@]}" acme providers

echo "==> [2/3] Provisioning Proxmox Cluster CA & Node Certificate (pve01.lab.internal:8006)"
"${MGTLS[@]}" ca create \
  --name pve-cluster-ca \
  --cn "Proxmox VE Cluster Root CA" \
  --algo ecdsa-p384 \
  --days 3650

"${MGTLS[@]}" cert issue \
  --name pve01-node-tls \
  --ca pve-cluster-ca \
  --cn "pve01.lab.internal" \
  --role server \
  --algo ecdsa-p256 \
  --dns "pve01.lab.internal,pve01,localhost" \
  --ip "192.168.10.10,127.0.0.1" \
  --days 397

echo "==> [3/3] Generating Proxmox VE pveproxy Deployment & Verification Scripts + OS Trust Installer"
"${MGTLS[@]}" target generate \
  --type proxmox \
  --name pve01-deploy \
  --ca pve-cluster-ca \
  --server-cert pve01-node-tls \
  --host "pve01.lab.internal" \
  --port 8006 \
  --out "${OUT_DIR}"

"${MGTLS[@]}" ca trust-script --name pve-cluster-ca > "${OUT_DIR}/install_cluster_ca_trust.txt"
ls -la "${OUT_DIR}"
echo "==> [Cookbook 04 Complete] Proxmox VE bundle ready at ${OUT_DIR}"
