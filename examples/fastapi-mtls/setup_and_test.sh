#!/usr/bin/env bash
set -euo pipefail

# End-to-End FastAPI mTLS Provisioning & Verification Script using mgtls
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STORE_DIR="${SCRIPT_DIR}/.mgtls-fastapi"
TARGET_OUT="${SCRIPT_DIR}/generated-fastapi"

MGTLS_BIN="${MGTLS_BIN:-}"
if [[ -z "${MGTLS_BIN}" ]]; then
  if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
    MGTLS_BIN="${REPO_ROOT}/bin/mgtls"
  else
    MGTLS_BIN="go run ${REPO_ROOT}/cmd/mgtls"
  fi
fi

echo "==> [1/6] Initializing mgtls store at ${STORE_DIR}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" init

echo "==> [2/6] Creating Root CA (corp-root-ca) and Intermediate CA (corp-intermediate-ca)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-root-ca \
  --cn "Acme Corp Root CA" \
  --algo ed25519 \
  --days 3650

${MGTLS_BIN} --store-dir "${STORE_DIR}" ca create \
  --name corp-intermediate-ca \
  --parent corp-root-ca \
  --cn "Acme Corp Platform Intermediate CA" \
  --algo ecdsa-p256 \
  --days 1825

echo "==> [3/6] Issuing FastAPI Server Certificate (fastapi-srv)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name fastapi-srv \
  --ca corp-intermediate-ca \
  --cn "localhost" \
  --role server \
  --dns "localhost,fastapi.internal" \
  --ip "127.0.0.1,::1" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [4/6] Issuing FastAPI Client Certificate (fastapi-client)"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert issue \
  --name fastapi-client \
  --ca corp-intermediate-ca \
  --cn "workload-billing-service" \
  --role client \
  --dns "workload-billing-service.internal" \
  --uri "spiffe://corp.internal/ns/prod/sa/billing" \
  --algo ecdsa-p256 \
  --days 365

echo "==> [5/6] Verifying Server & Client Certificate Chains against Root + Intermediate Bundle"
${MGTLS_BIN} --store-dir "${STORE_DIR}" cert verify \
  --cert "${STORE_DIR}/certs/fastapi-srv/cert.pem" \
  --ca "${STORE_DIR}/certs/fastapi-srv/ca-chain.pem" \
  --dns "localhost" \
  --role server

${MGTLS_BIN} --store-dir "${STORE_DIR}" cert verify \
  --cert "${STORE_DIR}/certs/fastapi-client/cert.pem" \
  --ca "${STORE_DIR}/certs/fastapi-client/ca-chain.pem" \
  --role client

echo "==> [6/6] Generating FastAPI Target Scaffolding Bundle in ${TARGET_OUT}"
${MGTLS_BIN} --store-dir "${STORE_DIR}" target generate \
  --type fastapi \
  --name fastapi-mtls-bundle \
  --ca corp-intermediate-ca \
  --server-cert fastapi-srv \
  --client-cert fastapi-client \
  --host localhost \
  --port 8443 \
  --mtls \
  --out "${TARGET_OUT}"

echo "[PASS] FastAPI mTLS PKI hierarchy and target bundle provisioned."
