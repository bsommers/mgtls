#!/usr/bin/env bash
# Cookbook 05: Infrastructure-as-Code (IaC) & CI/CD Secret Bundle Provisioning
# Reconciles a declarative mgtls.yaml manifest and exports cryptographic artifacts into
# Kubernetes TLS Secrets, Docker Compose mTLS mounts, and Terraform/Ansible JSON state.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${MGTLS_COOKBOOK_DIR:-$(mktemp -d -t mgtls-cb05-XXXXXX)}"
STORE_DIR="${WORK_DIR}/.mgtls"
K8S_DIR="${WORK_DIR}/k8s-secrets"
TF_DIR="${WORK_DIR}/terraform-out"

if [[ -x "${REPO_ROOT}/bin/mgtls" ]]; then
  MGTLS=("${REPO_ROOT}/bin/mgtls" "--store-dir" "${STORE_DIR}")
else
  MGTLS=("go" "run" "${REPO_ROOT}/src/cmd/mgtls" "--store-dir" "${STORE_DIR}")
fi

mkdir -p "${K8S_DIR}" "${TF_DIR}"

echo "==> [Cookbook 05] Writing Declarative IaC Manifest (${WORK_DIR}/iac-mgtls.yaml)"
cat > "${WORK_DIR}/iac-mgtls.yaml" <<EOF
version: "v1"
store_dir: "${STORE_DIR}"
cas:
  - name: "iac-root-ca"
    common_name: "IaC Root Certificate Authority"
    organization: "Platform Automation"
    country: "US"
    algorithm: "ed25519"
    valid_days: 3650
  - name: "iac-int-ca"
    parent_ca: "iac-root-ca"
    common_name: "IaC Workload Intermediate CA"
    organization: "Platform Automation"
    country: "US"
    algorithm: "ecdsa-p256"
    valid_days: 1825
certs:
  - name: "ingress-mtls"
    common_name: "ingress.prod.internal"
    ca_name: "iac-int-ca"
    role: "mtls"
    algorithm: "ecdsa-p256"
    valid_days: 90
    dns_names:
      - "ingress.prod.internal"
      - "localhost"
    ip_addresses:
      - "127.0.0.1"
    uris:
      - "spiffe://prod.internal/ns/ingress/sa/gateway"
ssh_cas:
  - name: "iac-ssh-user-ca"
    ca_type: "user"
    algorithm: "ed25519"
    comment: "iac-user-ca@prod.internal"
  - name: "iac-ssh-host-ca"
    ca_type: "host"
    algorithm: "ed25519"
    comment: "iac-host-ca@prod.internal"
EOF

echo "==> [1/4] Applying Declarative Manifest Idempotently"
"${MGTLS[@]}" apply -f "${WORK_DIR}/iac-mgtls.yaml"

echo "==> [2/4] Exporting Kubernetes TLS & mTLS Secret Manifest (${K8S_DIR}/ingress-mtls-secret.yaml)"
CRT_B64="$(base64 < "${STORE_DIR}/certs/ingress-mtls/fullchain.pem" | tr -d '\n')"
KEY_B64="$(base64 < "${STORE_DIR}/certs/ingress-mtls/key.pem" | tr -d '\n')"
CA_B64="$(base64 < "${STORE_DIR}/certs/ingress-mtls/ca-chain.pem" | tr -d '\n')"

cat > "${K8S_DIR}/ingress-mtls-secret.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ingress-mtls-tls
  namespace: default
  labels:
    app.kubernetes.io/managed-by: mgtls
type: kubernetes.io/tls
data:
  tls.crt: ${CRT_B64}
  tls.key: ${KEY_B64}
  ca.crt: ${CA_B64}
EOF

echo "==> [3/4] Exporting Structured JSON State for Terraform / Ansible (${TF_DIR}/mgtls-state.json)"
"${MGTLS[@]}" status --json > "${TF_DIR}/mgtls-state.json"

echo "==> [4/4] Running Zero-Trust Doctor Gate for CI/CD Pipeline"
"${MGTLS[@]}" doctor --warn-days 30
ls -la "${K8S_DIR}" "${TF_DIR}"
echo "==> [Cookbook 05 Complete] IaC & CI/CD bundles generated in ${WORK_DIR}"
