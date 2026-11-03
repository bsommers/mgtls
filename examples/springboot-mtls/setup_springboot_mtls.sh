#!/usr/bin/env bash
set -euo pipefail

# Provision Root CA, Intermediate CA, Server/Client Certificates & Spring Boot 3 Target Bundle
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STORE_DIR="${SCRIPT_DIR}/.mgtls-springboot"
TARGET_OUT="${SCRIPT_DIR}/generated-springboot"

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

echo "==> [2/5] Creating Root CA and Intermediate CA"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-root-ca \
  --cn "Acme Corp Root CA" \
  --algo ed25519 \
  --days 3650

${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-intermediate-ca \
  --parent corp-root-ca \
  --cn "Acme Corp Java Services Intermediate CA" \
  --algo ecdsa-p256 \
  --days 1825

echo "==> [3/5] Issuing Spring Boot Server Certificate (springboot-srv)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name springboot-srv \
  --ca corp-intermediate-ca \
  --cn "localhost" \
  --role server \
  --dns "localhost,orders-api.internal" \
  --ip "127.0.0.1,::1" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [4/5] Issuing Spring Boot Client Certificate (springboot-client)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name springboot-client \
  --ca corp-intermediate-ca \
  --cn "inventory-microservice" \
  --role client \
  --dns "inventory-microservice.internal" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [5/5] Generating Spring Boot 3 Target Bundle in ${TARGET_OUT}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" target generate \
  --type springboot \
  --name springboot-mtls-bundle \
  --ca corp-intermediate-ca \
  --server-cert springboot-srv \
  --client-cert springboot-client \
  --host localhost \
  --port 8443 \
  --mtls \
  --out "${TARGET_OUT}"

echo "[PASS] Spring Boot 3.2+ PEM SSL bundle and PKCS#12 artifacts ready."
