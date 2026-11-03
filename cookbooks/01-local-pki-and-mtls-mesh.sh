#!/usr/bin/env bash
# Cookbook 01: Multi-Tier Local PKI (Root CA -> Intermediate CA) & Service Mesh mTLS
# Generates a Root CA, Intermediate CA, Server/Client mTLS certificates, verifies chains & CRLs,
# and emits drop-in mTLS bundles for FastAPI, Spring Boot 3, NGINX, and Vite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${MGTLS_COOKBOOK_DIR:-$(mktemp -d -t mgtls-cb01-XXXXXX)}"
STORE_DIR="${WORK_DIR}/.mgtls"
OUT_DIR="${WORK_DIR}/bundles"

if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
  MGTLS=("${REPO_ROOT}/bin/mgtls" "--store-dir" "${STORE_DIR}")
else
  MGTLS=("go" "run" "${REPO_ROOT}/src/cmd/mgtls" "--store-dir" "${STORE_DIR}")
fi

echo "==> [Cookbook 01] Initializing cryptographic store at ${STORE_DIR}"
"${MGTLS[@]}" init

echo "==> [1/5] Creating Offline Root CA (Ed25519, 10-year validity)"
"${MGTLS[@]}" ca create \
  --name mesh-root-ca \
  --cn "Acme Mesh Root CA" \
  --org "Acme Platform Security" \
  --country "US" \
  --algo ed25519 \
  --days 3650

echo "==> [2/5] Creating Issuing Intermediate CA (ECDSA P-256, 5-year validity)"
"${MGTLS[@]}" ca create \
  --name mesh-int-ca \
  --parent mesh-root-ca \
  --cn "Acme Mesh Issuing Intermediate CA" \
  --org "Acme Platform Security" \
  --country "US" \
  --algo ecdsa-p256 \
  --days 1825

echo "==> [3/5] Issuing Server, Client & Dual-mTLS Leaf Certificates"
"${MGTLS[@]}" cert issue \
  --name mesh-gateway-srv \
  --ca mesh-int-ca \
  --cn "gateway.mesh.internal" \
  --role server \
  --algo ecdsa-p256 \
  --dns "localhost,gateway.mesh.internal,api.mesh.internal" \
  --ip "127.0.0.1" \
  --uri "spiffe://mesh.internal/ns/ingress/sa/gateway" \
  --days 365

"${MGTLS[@]}" cert issue \
  --name mesh-Service-client \
  --ca mesh-int-ca \
  --cn "orders-worker.mesh.internal" \
  --role client \
  --algo ed25519 \
  --dns "orders-worker.mesh.internal" \
  --uri "spiffe://mesh.internal/ns/prod/sa/orders-worker" \
  --days 90

echo "==> [4/5] Verifying Multi-Tier Certificate Chain, SANs, and EKU Roles"
"${MGTLS[@]}" cert verify \
  --cert "${STORE_DIR}/certs/mesh-gateway-srv/fullchain.pem" \
  --ca "${STORE_DIR}/ca/mesh-root-ca/cert.pem" \
  --dns "gateway.mesh.internal" \
  --role server

echo "==> [5/5] Generating Drop-In mTLS Bundles for FastAPI, Spring Boot 3, NGINX & Vite"
for TARGET in fastapi springboot nginx vite; do
  "${MGTLS[@]}" target generate \
    --type "${TARGET}" \
    --name "mesh-${TARGET}" \
    --ca mesh-int-ca \
    --server-cert mesh-gateway-srv \
    --client-cert mesh-Service-client \
    --host "gateway.mesh.internal" \
    --mtls \
    --out "${OUT_DIR}/${TARGET}"
done

"${MGTLS[@]}" doctor --warn-days 30
echo "==> [Cookbook 01 Complete] Artifacts generated in ${WORK_DIR}"
