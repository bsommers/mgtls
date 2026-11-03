#!/usr/bin/env bash
set -euo pipefail

# Provision Root CA, Intermediate CA, Vite Server/Client Certificates & Vite Target Bundle
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STORE_DIR="${SCRIPT_DIR}/.mgtls-vite"
TARGET_OUT="${SCRIPT_DIR}/generated-vite"

MGTLS_BIN="${MGTLS_BIN:-}"
if [[ -z "${MGTLS_BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
    MGTLS_BIN="${REPO_ROOT}/bin/mgtls"
  else
    MGTLS_BIN="go run ${REPO_ROOT}/src/cmd/mgtls"
  fi
fi

echo "==> [1/5] Initializing store at ${STORE_DIR}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" init

echo "==> [2/5] Creating Root CA and Frontend Intermediate CA"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-root-ca \
  --cn "Acme Corp Root CA" \
  --algo ed25519 \
  --days 3650

${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-intermediate-ca \
  --parent corp-root-ca \
  --cn "Acme Corp Web Frontend Intermediate CA" \
  --algo ecdsa-p256 \
  --days 1825

echo "==> [3/5] Issuing Vite HTTPS Server Certificate (vite-srv)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name vite-srv \
  --ca corp-intermediate-ca \
  --cn "localhost" \
  --role server \
  --dns "localhost,vite.internal" \
  --ip "127.0.0.1,::1" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [4/5] Issuing Developer Client Certificate (vite-client)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name vite-client \
  --ca corp-intermediate-ca \
  --cn "developer-workstation" \
  --role client \
  --dns "developer-workstation.internal" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [5/5] Generating Vite Target Bundle in ${TARGET_OUT}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" target generate \
  --type vite \
  --name vite-mtls-bundle \
  --ca corp-intermediate-ca \
  --server-cert vite-srv \
  --client-cert vite-client \
  --host localhost \
  --port 5173 \
  --mtls \
  --out "${TARGET_OUT}"

echo "[PASS] Vite HTTPS + mTLS configuration and certificates provisioned."
