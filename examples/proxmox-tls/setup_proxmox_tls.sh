#!/usr/bin/env bash
set -euo pipefail

# Proxmox VE TLS Provisioning & Deployment Automation Script using mgtls
# Demonstrates:
#   1. Internal Root CA + Intermediate CA + Proxmox Node Certificate (pve01.corp.internal)
#   2. Proxmox VE Target Bundle generation (deploy_proxmox_cert.sh, proxmox_pveproxy_verify.sh)
#   3. OS Trust Store script generation for administrator workstations
#   4. Public ACME v2 (Let's Encrypt / ZeroSSL) automation commands for Proxmox VE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STORE_DIR="${SCRIPT_DIR}/.mgtls-proxmox"
TARGET_OUT="${SCRIPT_DIR}/generated-proxmox"
PVE_HOSTNAME="${PVE_HOSTNAME:-pve01.corp.internal}"
PVE_IP="${PVE_IP:-10.10.0.10}"

MGTLS_BIN="${MGTLS_BIN:-}"
if [[ -z "${MGTLS_BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
    MGTLS_BIN="${REPO_ROOT}/bin/mgtls"
  else
    MGTLS_BIN="go run ${REPO_ROOT}/cmd/mgtls"
  fi
fi

echo "==> [1/6] Initializing Proxmox PKI store at ${STORE_DIR}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" init

echo "==> [2/6] Creating Internal Root CA and Infrastructure Intermediate CA"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-root-ca \
  --cn "Acme Corp Root CA" \
  --algo ed25519 \
  --days 3650

${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-infra-ca \
  --parent corp-root-ca \
  --cn "Acme Corp Datacenter Infrastructure CA" \
  --algo ecdsa-p256 \
  --days 1825

echo "==> [3/6] Issuing Proxmox VE Node Server Certificate (pve-node01-srv)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name pve-node01-srv \
  --ca corp-infra-ca \
  --cn "${PVE_HOSTNAME}" \
  --role server \
  --dns "${PVE_HOSTNAME},pve01,localhost" \
  --ip "${PVE_IP},127.0.0.1" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [4/6] Issuing Proxmox Automation Client Certificate (pve-automation-client)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name pve-automation-client \
  --ca corp-infra-ca \
  --cn "terraform-proxmox-provisioner" \
  --role client \
  --dns "terraform.corp.internal" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [5/6] Generating Proxmox VE Target Deployment Bundle in ${TARGET_OUT}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" target generate \
  --type proxmox \
  --name proxmox-node01 \
  --ca corp-infra-ca \
  --server-cert pve-node01-srv \
  --client-cert pve-automation-client \
  --host "${PVE_HOSTNAME}" \
  --port 8006 \
  --out "${TARGET_OUT}"

echo "==> [6/6] Generating OS Trust Store Scripts for Root CA"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ca trust-script \
  --name corp-root-ca \
  --out "${TARGET_OUT}/trust-scripts"

if [[ "${DEPLOY_TO_LOCAL_PVE:-0}" == "1" ]]; then
  echo "==> Deploying certificate to /etc/pve/local/pveproxy-ssl.pem"
  if command -v pvenode >/dev/null 2>&1; then
    pvenode cert set \
      "${STORE_DIR}/certs/pve-node01-srv/fullchain.pem" \
      "${STORE_DIR}/certs/pve-node01-srv/key.pem" \
      --force --restart
  else
    install -d -m 0755 /etc/pve/local
    install -m 0640 "${STORE_DIR}/certs/pve-node01-srv/fullchain.pem" /etc/pve/local/pveproxy-ssl.pem
    install -m 0600 "${STORE_DIR}/certs/pve-node01-srv/key.pem" /etc/pve/local/pveproxy-ssl.key
    systemctl reload-or-restart pveproxy.service
  fi
fi

if [[ "${RUN_ACME_RENEWAL:-0}" == "1" ]]; then
  echo "==> Requesting Let's Encrypt ACME v2 Certificate for ${PVE_HOSTNAME}"
  ${MGTLS_BIN} --store-dir "${STORE_DIR}" acme obtain \
    --name pve-letsencrypt \
    --provider "${ACME_PROVIDER:-letsencrypt}" \
    --email "${ACME_EMAIL:-admin@corp.internal}" \
    --domains "${PVE_HOSTNAME}" \
    --challenge "${ACME_CHALLENGE:-dns-01}" \
    --dns-hook "${ACME_DNS_HOOK:-}"
fi

echo "[PASS] Proxmox VE TLS bundle and trust scripts generated in ${TARGET_OUT}"
