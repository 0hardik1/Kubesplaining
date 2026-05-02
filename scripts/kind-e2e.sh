#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kubesplaining-e2e}"
KUBECONFIG_PATH="${KUBECONFIG:-${ROOT_DIR}/.tmp/kubeconfig}"
KEEP_CLUSTER="${KEEP_CLUSTER:-1}"
USER_KUBECONFIG="${USER_KUBECONFIG:-${HOME}/.kube/config}"

# ANSI colors when stdout is a terminal and NO_COLOR is not set; plain text under CI / pipes.
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'
  C_BOLD=$'\e[1m'
  C_DIM=$'\e[2m'
  C_GREEN=$'\e[32m'
  C_BLUE=$'\e[34m'
  C_CYAN=$'\e[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_GREEN=""; C_BLUE=""; C_CYAN=""
fi

step()      { printf "\n%s▶ %s%s\n" "${C_BOLD}${C_CYAN}" "$*" "${C_RESET}"; }
ok()        { printf "  %s✓%s %s\n" "${C_GREEN}" "${C_RESET}" "$*"; }
prefix_ok() { sed "s/^/  ${C_GREEN}✓${C_RESET} /"; }

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
    if [[ -f "${USER_KUBECONFIG}" ]]; then
      KUBECONFIG="${USER_KUBECONFIG}" kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
  fi
}

trap cleanup EXIT

step "Creating kind cluster: ${KIND_CLUSTER_NAME}"
# Always start fresh: tear down any prior cluster of the same name, including
# the stale entry in the user's default kubeconfig from a previous run.
kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
if [[ -f "${USER_KUBECONFIG}" ]]; then
  KUBECONFIG="${USER_KUBECONFIG}" kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
fi
# Stream kind's progress (it already prints `✓ Ensuring node image`, `✓ Preparing
# nodes`, etc.), indented under our section header. We strip kind's trailing
# marketing block — we set the kubectl context ourselves further down, and the
# "Have a question / Thanks" lines are noise in this script.
kind create cluster --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}" --wait 90s 2>&1 \
  | sed -E -e '/^Set kubectl context/d' \
            -e '/^You can now use/d' \
            -e '/^kubectl cluster-info/d' \
            -e '/^Have a question/d' \
            -e '/^Thanks/d' \
            -e '/^[[:space:]]*$/d' \
            -e 's/^/    /'
ok "cluster ready"

step "Applying vulnerable manifests"
kubectl --kubeconfig "${KUBECONFIG_PATH}" apply -f "${ROOT_DIR}/testdata/e2e/vulnerable.yaml" | prefix_ok

step "Waiting for workloads to roll out"
ROLLOUTS=(
  "deploy/risky-app:vulnerable"
  "deploy/host-ns-app:vulnerable"
  "deploy/socket-mounts-app:vulnerable"
  "deploy/generic-hostpath-app:vulnerable"
  "deploy/root-runner:vulnerable"
  "deploy/wildcard-app:rbac-fixtures"
  "deploy/imp-app:rbac-fixtures"
  "ds/daemon-app:rbac-fixtures"
  "deploy/unmatched:flat-network"
  "deploy/ingress-app:ingress-only"
  "deploy/psa-priv-app:psa-suppressed"
)
for entry in "${ROLLOUTS[@]}"; do
  obj="${entry%%:*}"
  ns="${entry##*:}"
  kubectl --kubeconfig "${KUBECONFIG_PATH}" rollout status "${obj}" -n "${ns}" --timeout=120s >/dev/null
  ok "${obj} (${ns})"
done

step "Tightening psa-suppressed namespace to PSA enforce=restricted"
# Apply the label after the deployment rolled out so the privileged pod is already
# running. PSA checks creates and updates only, so the existing pod stays — this
# mirrors the production case where a namespace was labeled retroactively.
kubectl --kubeconfig "${KUBECONFIG_PATH}" label namespace psa-suppressed \
  pod-security.kubernetes.io/enforce=restricted --overwrite | prefix_ok

step "Capturing snapshot"
"${ROOT_DIR}/bin/kubesplaining" download \
  --kubeconfig "${KUBECONFIG_PATH}" \
  --output-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" | prefix_ok

step "Running kubesplaining scan"
# Use the default "standard" exclusions preset so the e2e mirrors how users run
# the tool: built-in kube-system / system:* / kubeadm:* noise is suppressed.
SCAN_LOG="${ROOT_DIR}/.tmp/e2e-scan.log"
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report" \
  --output-format html,json,csv | tee "${SCAN_LOG}" | prefix_ok
SUMMARY_LINE=$(grep -m1 "^findings:" "${SCAN_LOG}" 2>/dev/null || echo "")

step "Verifying expected rule IDs"
EXPECTED_RULES=(
  KUBE-PRIVESC-001 KUBE-PRIVESC-003 KUBE-PRIVESC-005 KUBE-PRIVESC-008 KUBE-PRIVESC-009
  KUBE-PRIVESC-010 KUBE-PRIVESC-012 KUBE-PRIVESC-014 KUBE-PRIVESC-017
  KUBE-RBAC-OVERBROAD-001
  KUBE-ESCAPE-001 KUBE-ESCAPE-002 KUBE-ESCAPE-003 KUBE-ESCAPE-004 KUBE-ESCAPE-005
  KUBE-ESCAPE-006 KUBE-ESCAPE-008
  KUBE-CONTAINERD-SOCKET-001 KUBE-HOSTPATH-001
  KUBE-PODSEC-APE-001 KUBE-PODSEC-ROOT-001 KUBE-IMAGE-LATEST-001
  KUBE-NETPOL-COVERAGE-001 KUBE-NETPOL-COVERAGE-002 KUBE-NETPOL-COVERAGE-003
  KUBE-NETPOL-WEAKNESS-001 KUBE-NETPOL-WEAKNESS-002
  KUBE-SECRETS-001 KUBE-CONFIGMAP-001
  KUBE-ADMISSION-001 KUBE-ADMISSION-002 KUBE-ADMISSION-003
  KUBE-SA-DEFAULT-001 KUBE-SA-DEFAULT-002 KUBE-SA-PRIVILEGED-001 KUBE-SA-PRIVILEGED-002
  KUBE-SA-DAEMONSET-001
  KUBE-PRIVESC-PATH-CLUSTER-ADMIN KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS
  KUBE-PRIVESC-PATH-NODE-ESCAPE KUBE-PRIVESC-PATH-SYSTEM-MASTERS
  KUBE-PRIVESC-PATH-NAMESPACE-ADMIN KUBE-PRIVESC-PATH-GENERIC
)

missing=()
for rule in "${EXPECTED_RULES[@]}"; do
  if ! rg -q "\"rule_id\":\s*\"${rule}\"" "${ROOT_DIR}/.tmp/e2e-report/findings.json"; then
    missing+=("${rule}")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "missing expected rules in findings.json:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 1
fi
ok "all ${#EXPECTED_RULES[@]} expected rule IDs present"

# Regression guard for issue #48: a namespace-scoped RoleBinding granting
# `create rolebindings` MUST NOT produce a cluster-admin path finding. The
# finding ID concatenates ruleID + subject Key + target, so a single grep
# pinpoints the exact false positive without needing jq.
NS_SUBJECT_KEY="ServiceAccount/rbac-ns-fixtures/sa-ns-rolebinding-mutate"
NS_FP_ID_PREFIX="KUBE-PRIVESC-PATH-CLUSTER-ADMIN:${NS_SUBJECT_KEY}:"
if rg -q "\"id\":\s*\"${NS_FP_ID_PREFIX}" "${ROOT_DIR}/.tmp/e2e-report/findings.json"; then
  echo "regression: namespace-scoped RoleBinding produced KUBE-PRIVESC-PATH-CLUSTER-ADMIN (issue #48)" >&2
  exit 1
fi
ok "no cluster-admin false positive for namespace-scoped RoleBinding"

# Phase 2 posture finding: KUBE-ADMISSION-NO-POLICY-ENGINE-001 must NOT fire in
# this fixture because the psa-suppressed namespace carries
# pod-security.kubernetes.io/enforce=restricted (set above), and PSAState.HasEnforce()
# returns true for any baseline-or-stricter level. Asserting the absence is more
# valuable than asserting presence: it locks in that the posture finding correctly
# suppresses itself when *any* admission control is in place.
if rg -q "\"rule_id\":\s*\"KUBE-ADMISSION-NO-POLICY-ENGINE-001\"" "${ROOT_DIR}/.tmp/e2e-report/findings.json"; then
  echo "regression: KUBE-ADMISSION-NO-POLICY-ENGINE-001 fired despite psa-suppressed namespace having enforce=restricted" >&2
  exit 1
fi
ok "no policy-engine posture finding (correctly suppressed by psa-suppressed enforce label)"

# The same fixture must instead produce KUBE-PRIVESC-PATH-NAMESPACE-ADMIN, naming
# the namespace it can take over. The finding ID encodes the target namespace as
# the last segment after a fourth `:`.
NS_OK_ID="KUBE-PRIVESC-PATH-NAMESPACE-ADMIN:${NS_SUBJECT_KEY}:namespace_admin:rbac-ns-fixtures"
if ! rg -q "\"id\":\s*\"${NS_OK_ID}\"" "${ROOT_DIR}/.tmp/e2e-report/findings.json"; then
  echo "missing: namespace-scoped RoleBinding did not produce expected KUBE-PRIVESC-PATH-NAMESPACE-ADMIN finding for ${NS_SUBJECT_KEY} → rbac-ns-fixtures" >&2
  exit 1
fi
ok "namespace-admin path emitted for namespace-scoped RoleBinding"

# Default --admission-mode=suppress must drop the privileged-pod finding for the
# psa-suppressed namespace because its enforce=restricted label would block the spec.
PSA_FINDING_ID="KUBE-ESCAPE-001:Deployment:psa-suppressed:psa-priv-app"
if rg -q "\"id\":\s*\"${PSA_FINDING_ID}" "${ROOT_DIR}/.tmp/e2e-report/findings.json"; then
  echo "regression: --admission-mode=suppress did not drop ${PSA_FINDING_ID}" >&2
  exit 1
fi
ok "default suppress mode dropped privileged finding in psa-suppressed namespace"

# admission-summary.json must record the suppression count and the per-namespace breakdown.
if ! rg -q "\"suppressed\":\s*[1-9]" "${ROOT_DIR}/.tmp/e2e-report/admission-summary.json"; then
  echo "missing: admission-summary.json should record suppressed >= 1" >&2
  exit 1
fi
if ! rg -q "psa-suppressed" "${ROOT_DIR}/.tmp/e2e-report/admission-summary.json"; then
  echo "missing: admission-summary.json should mention psa-suppressed namespace" >&2
  exit 1
fi
ok "admission-summary.json records the suppressed psa-suppressed finding"

step "Re-running scan with --admission-mode=attenuate"
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-attenuate" \
  --admission-mode attenuate \
  --output-format json >/dev/null

# Attenuate keeps the finding visible but with the admission tag applied.
if ! rg -q "\"id\":\s*\"${PSA_FINDING_ID}" "${ROOT_DIR}/.tmp/e2e-report-attenuate/findings.json"; then
  echo "missing: attenuate mode should keep ${PSA_FINDING_ID} visible" >&2
  exit 1
fi
if ! rg -q "admission:mitigated-psa-restricted" "${ROOT_DIR}/.tmp/e2e-report-attenuate/findings.json"; then
  echo "missing: attenuate mode should tag findings with admission:mitigated-psa-restricted" >&2
  exit 1
fi
ok "attenuate mode tagged the privileged finding with admission:mitigated-psa-restricted"

if [[ "${KEEP_CLUSTER}" == "1" ]]; then
  step "Wiring kubectl context"
  mkdir -p "$(dirname "${USER_KUBECONFIG}")"
  touch "${USER_KUBECONFIG}"
  KUBECONFIG="${USER_KUBECONFIG}" kind export kubeconfig --name "${KIND_CLUSTER_NAME}" >/dev/null
  ok "kubectl context: kind-${KIND_CLUSTER_NAME}"
  ok "kubeconfig: ${USER_KUBECONFIG}"
fi

REPORT_HTML="${ROOT_DIR}/.tmp/e2e-report/report.html"
REPORT_REL="${REPORT_HTML#"${ROOT_DIR}/"}"
REPORT_URL="file://${REPORT_HTML}"
RULE="═══════════════════════════════════════════════════════════════════════"

printf "\n%s%s%s\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
printf "  %s✓ kubesplaining e2e complete%s\n" "${C_BOLD}${C_GREEN}" "${C_RESET}"
if [[ -n "${SUMMARY_LINE}" ]]; then
  printf "  %s%s%s\n" "${C_DIM}" "${SUMMARY_LINE}" "${C_RESET}"
fi
printf "%s%s%s\n\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"

printf "  %sOpen the HTML report%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s%s%s\n" "${C_BLUE}" "${REPORT_URL}" "${C_RESET}"
printf "    %sopen %s%s\n\n" "${C_DIM}" "${REPORT_REL}" "${C_RESET}"

printf "  %sPoke at the cluster%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %skubectl get pods -A%s\n" "${C_DIM}" "${C_RESET}"
printf "    %skubectl --context kind-%s get clusterrolebindings%s\n\n" "${C_DIM}" "${KIND_CLUSTER_NAME}" "${C_RESET}"

printf "  %sTear it down%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %smake delete%s\n" "${C_DIM}" "${C_RESET}"
