#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kubesplaining-e2e}"
KUBECONFIG_PATH="${KUBECONFIG:-${ROOT_DIR}/.tmp/kubeconfig}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd kind
require_cmd kubectl
require_cmd rg

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable; start Docker and rerun make e2e" >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/.tmp"

cleanup() {
  if [[ "${KEEP_CLUSTER}" != "1" ]]; then
    kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
kind create cluster --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}" --wait 90s

kubectl --kubeconfig "${KUBECONFIG_PATH}" apply -f "${ROOT_DIR}/testdata/e2e/vulnerable.yaml"
kubectl --kubeconfig "${KUBECONFIG_PATH}" rollout status deploy/risky-app -n vulnerable --timeout=120s

"${ROOT_DIR}/bin/kubesplaining" download \
  --kubeconfig "${KUBECONFIG_PATH}" \
  --output-file "${ROOT_DIR}/.tmp/e2e-snapshot.json"

"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report" \
  --output-format html,json,csv

rg -q "KUBE-PRIVESC-005" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-ESCAPE-001" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-SA-DEFAULT-001" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-NETPOL-COVERAGE-001" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-NETPOL-WEAKNESS-002" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-SECRETS-001" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-CONFIGMAP-001" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-ADMISSION-001" "${ROOT_DIR}/.tmp/e2e-report/findings.json"
rg -q "KUBE-ADMISSION-002" "${ROOT_DIR}/.tmp/e2e-report/findings.json"

echo "kind e2e completed successfully"
