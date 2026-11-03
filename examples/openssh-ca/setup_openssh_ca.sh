#!/usr/bin/env bash
set -euo pipefail

# End-to-End OpenSSH User CA & Host CA Fleet Setup Script using mgtls
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STORE_DIR="${SCRIPT_DIR}/.mgtls-openssh"
CONFIG_OUT="${SCRIPT_DIR}/generated-openssh-config"
TARGET_OUT="${SCRIPT_DIR}/generated-openssh-target"

MGTLS_BIN="${MGTLS_BIN:-}"
if [[ -z "${MGTLS_BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
    MGTLS_BIN="${REPO_ROOT}/bin/mgtls"
  else
    MGTLS_BIN="go run ${REPO_ROOT}/src/cmd/mgtls"
  fi
fi

echo "==> [1/7] Initializing OpenSSH CA store at ${STORE_DIR}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" init

echo "==> [2/7] Creating OpenSSH User CA (corp-ssh-user-ca) & Host CA (corp-ssh-host-ca)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh ca-create \
  --name corp-ssh-user-ca \
  --type user \
  --algo ed25519 \
  --comment "corp-ssh-user-ca@corp.internal"

${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh ca-create \
  --name corp-ssh-host-ca \
  --type host \
  --algo ed25519 \
  --comment "corp-ssh-host-ca@corp.internal"

echo "==> [3/7] Signing OpenSSH User Certificate (alice-ssh)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh sign \
  --name alice-ssh \
  --ca corp-ssh-user-ca \
  --type user \
  --key-id "alice@corp.internal" \
  --principals "alice,admin,sre" \
  --hours 720 \
  --algo ed25519

echo "==> [4/7] Signing OpenSSH Host Certificate (bastion-host-ssh)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh sign \
  --name bastion-host-ssh \
  --ca corp-ssh-host-ca \
  --type host \
  --key-id "bastion.corp.internal" \
  --principals "bastion.corp.internal,*.corp.internal,10.0.0.10,localhost,127.0.0.1" \
  --hours 8760 \
  --algo ed25519

echo "==> [5/7] Inspecting Signed User & Host Certificates"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh inspect \
  --cert "${STORE_DIR}/ssh/certs/alice-ssh/alice-ssh-cert.pub"

${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh inspect \
  --cert "${STORE_DIR}/ssh/certs/bastion-host-ssh/bastion-host-ssh-cert.pub"

echo "==> [6/7] Generating sshd_config, ssh_config, authorized_principals & @cert-authority known_hosts"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ssh config-bundle \
  --name corp-ssh-fleet \
  --user-ca corp-ssh-user-ca \
  --host-ca corp-ssh-host-ca \
  --user-cert alice-ssh \
  --host-cert bastion-host-ssh \
  --hosts "*.corp.internal,bastion.corp.internal,10.0.0.*,localhost" \
  --principals "alice,admin,sre" \
  --out "${CONFIG_OUT}"

echo "==> [7/7] Generating OpenSSH Target Bundle in ${TARGET_OUT}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" target generate \
  --type openssh \
  --name openssh-fleet-target \
  --host bastion.corp.internal \
  --port 22 \
  --out "${TARGET_OUT}"

echo "[PASS] OpenSSH User/Host CAs, signed certificates, and config bundles generated."
