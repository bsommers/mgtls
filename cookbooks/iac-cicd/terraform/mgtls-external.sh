#!/usr/bin/env bash
# Terraform / OpenTofu External Data Source Bridge for mgtls
# Reads JSON query from stdin (`store_dir`, `service_domain`), provisions X.509 & OpenSSH CA
# artifacts idempotently via `mgtls`, and emits flat string-map JSON to stdout.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

INPUT="$(cat)"
STORE_DIR="$(printf '%s' "${INPUT}" | sed -n 's/.*"store_dir"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
DOMAIN="$(printf '%s' "${INPUT}" | sed -n 's/.*"service_domain"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

STORE_DIR="${STORE_DIR:-.mgtls-terraform}"
DOMAIN="${DOMAIN:-api.prod.internal}"

if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
  MGTLS=("${REPO_ROOT}/bin/mgtls" "--store-dir" "${STORE_DIR}")
else
  MGTLS=("go" "run" "${REPO_ROOT}/src/cmd/mgtls" "--store-dir" "${STORE_DIR}")
fi

"${MGTLS[@]}" init >/dev/null 2>&1
"${MGTLS[@]}" ca create --name tf-root-ca --cn "Terraform Root CA" --algo ed25519 >/dev/null 2>&1
"${MGTLS[@]}" cert issue --name tf-srv --ca tf-root-ca --cn "${DOMAIN}" --role mtls --dns "${DOMAIN},localhost" --ip "127.0.0.1" >/dev/null 2>&1
"${MGTLS[@]}" ssh ca-create --name tf-ssh-user-ca --type user --algo ed25519 >/dev/null 2>&1

cat <<EOF
{
  "store_dir": "${STORE_DIR}",
  "ca_cert_path": "${STORE_DIR}/ca/tf-root-ca/cert.pem",
  "server_fullchain_path": "${STORE_DIR}/certs/tf-srv/fullchain.pem",
  "server_key_path": "${STORE_DIR}/certs/tf-srv/key.pem",
  "ssh_user_ca_pub_path": "${STORE_DIR}/ssh/ca/tf-ssh-user-ca/id_ca.pub"
}
EOF
