#!/usr/bin/env bash
# Cookbook 03: OpenSSH Zero-Trust User CA & Host CA Fleet Rollout
# Eliminates static ~/.ssh/authorized_keys and TOFU known_hosts warnings by provisioning
# dedicated OpenSSH User & Host CAs, signing short-lived certificates, and generating fleet configs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${MGTLS_COOKBOOK_DIR:-$(mktemp -d -t mgtls-cb03-XXXXXX)}"
STORE_DIR="${WORK_DIR}/.mgtls"
OUT_DIR="${WORK_DIR}/openssh-fleet"

if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
  MGTLS=("${REPO_ROOT}/bin/mgtls" "--store-dir" "${STORE_DIR}")
else
  MGTLS=("go" "run" "${REPO_ROOT}/src/cmd/mgtls" "--store-dir" "${STORE_DIR}")
fi

echo "==> [Cookbook 03] Initializing OpenSSH CA Store at ${STORE_DIR}"
"${MGTLS[@]}" init

echo "==> [1/4] Creating Dedicated OpenSSH User CA and Host CA (Ed25519)"
"${MGTLS[@]}" ssh ca-create --name prod-ssh-user-ca --type user --algo ed25519 --comment "prod-user-ca@corp.internal"
"${MGTLS[@]}" ssh ca-create --name prod-ssh-host-ca --type host --algo ed25519 --comment "prod-host-ca@corp.internal"

echo "==> [2/4] Signing Short-Lived User Certificate (24h validity, principals: sre,admin,deploy)"
"${MGTLS[@]}" ssh sign \
  --name oncall-sre-user \
  --ca prod-ssh-user-ca \
  --type user \
  --key-id "sre-oncall@corp.internal" \
  --principals "sre,admin,deploy" \
  --hours 24

echo "==> [3/4] Signing Bastion Host Certificate (1-year validity, principals: bastion.corp.internal,10.10.0.5)"
"${MGTLS[@]}" ssh sign \
  --name bastion-host \
  --ca prod-ssh-host-ca \
  --type host \
  --key-id "bastion.corp.internal" \
  --principals "bastion.corp.internal,10.10.0.5" \
  --hours 8760

echo "==> [4/4] Inspecting Certificates & Generating sshd_config / @cert-authority Bundle"
"${MGTLS[@]}" ssh inspect --cert "${STORE_DIR}/ssh/certs/oncall-sre-user/id_key-cert.pub"
"${MGTLS[@]}" ssh inspect --cert "${STORE_DIR}/ssh/certs/bastion-host/id_key-cert.pub"

"${MGTLS[@]}" ssh config-bundle \
  --name prod-ssh-fleet \
  --user-ca prod-ssh-user-ca \
  --host-ca prod-ssh-host-ca \
  --user-cert oncall-sre-user \
  --host-cert bastion-host \
  --hosts "*.corp.internal,10.10.*.*" \
  --account sre=sre \
  --account deploy=sre,deploy \
  --out "${OUT_DIR}"

ls -la "${OUT_DIR}"
echo "==> [Cookbook 03 Complete] OpenSSH Zero-Trust Fleet bundle generated in ${OUT_DIR}"
