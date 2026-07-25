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

step "Stamping EKS node labels so DetectCloudProvider classifies as eks"
# Slot #15 covers Cloud Provider Integration (EKS). The kind nodes do not
# carry the AWS-managed eks.amazonaws.com/nodegroup label on their own, so
# the collector would classify the cluster as "unknown" and skip every
# KUBE-CLOUD-* rule. Stamping the label here is the minimum touch needed
# to drive the cloud analyzers from the e2e fixtures; the labels are
# harmless for every other slot (no analyzer keys off them).
kubectl --kubeconfig "${KUBECONFIG_PATH}" label nodes --all \
  eks.amazonaws.com/nodegroup=kind-test --overwrite >/dev/null
ok "kind nodes labeled eks.amazonaws.com/nodegroup=kind-test"

step "Applying vulnerable manifests"
# `kubectl apply -f <dir>` recurses through the directory and applies every
# YAML/JSON file in lexical order. Each Wave 1 analyzer slot adds its own
# testdata/e2e/vulnerable/NN-<feature>.yaml shard without editing this script
# or 00-baseline.yaml — zero merge conflicts at the fixture layer.
kubectl --kubeconfig "${KUBECONFIG_PATH}" apply -f "${ROOT_DIR}/testdata/e2e/vulnerable/" | prefix_ok

step "Waiting for workloads to roll out"
# Each *.rollout file under testdata/e2e/expectations/ lists one
# "<kind>/<name>:<namespace>" entry per line. The baseline file ships the set
# of workloads applied by 00-baseline.yaml; Wave 1 slots that introduce new
# workloads drop their own <feature>.rollout alongside the matching
# <feature>.yaml. Lines starting with '#' and blank lines are skipped.
ROLLOUTS=()
shopt -s nullglob
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.rollout; do
  while IFS= read -r line; do
    line="${line%%#*}"            # strip trailing comments
    line="${line#"${line%%[![:space:]]*}"}"  # ltrim
    line="${line%"${line##*[![:space:]]}"}"  # rtrim
    [[ -z "${line}" ]] && continue
    ROLLOUTS+=("${line}")
  done < "${f}"
done
shopt -u nullglob
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

step "Synthesizing audit log for least-privilege fixtures"
# kind does not surface kube-apiserver audit logs by default, so we synthesize a
# small one with timestamps anchored to "now" - that keeps every event inside the
# scan's --audit-window-days window regardless of when the e2e is run. The events
# target three SAs the lp-fixtures namespace mounts:
#
#   sa-lp-narrow    - exercises get + list on configmaps (granted 7 verbs) -> UNUSED-VERB
#   sa-lp-wildcard  - exercises get on secrets (granted verbs:["*"])       -> WILDCARD-USED-PARTIAL
#   sa-lp-orphan    - no events at all                                     -> UNUSED-ROLE
AUDIT_LOG="${ROOT_DIR}/.tmp/e2e-audit.log"
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat > "${AUDIT_LOG}" <<EOF
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"lp-narrow-1","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:lp-fixtures:sa-lp-narrow"},"objectRef":{"apiVersion":"v1","resource":"configmaps","namespace":"lp-fixtures"},"responseStatus":{"code":200},"requestReceivedTimestamp":"${TS}","stageTimestamp":"${TS}"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"lp-narrow-2","stage":"ResponseComplete","verb":"list","user":{"username":"system:serviceaccount:lp-fixtures:sa-lp-narrow"},"objectRef":{"apiVersion":"v1","resource":"configmaps","namespace":"lp-fixtures"},"responseStatus":{"code":200},"requestReceivedTimestamp":"${TS}","stageTimestamp":"${TS}"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"lp-wildcard-1","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:lp-fixtures:sa-lp-wildcard"},"objectRef":{"apiVersion":"v1","resource":"secrets","namespace":"lp-fixtures"},"responseStatus":{"code":200},"requestReceivedTimestamp":"${TS}","stageTimestamp":"${TS}"}
EOF
ok "wrote ${AUDIT_LOG} (3 events)"

step "Running kubesplaining scan (default --max-findings=20)"
# Use the default "standard" exclusions preset so the e2e mirrors how users run
# the tool: built-in kube-system / system:* / kubeadm:* noise is suppressed.
# This invocation uses default flags so the e2e demonstrates the user-facing
# default truncation behavior. Rule-ID coverage assertions further down run
# against a separate --all-findings scan into .tmp/e2e-report-full.
SCAN_LOG="${ROOT_DIR}/.tmp/e2e-scan.log"
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --audit-log "${AUDIT_LOG}" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report" \
  --output-format html,json,csv | tee "${SCAN_LOG}" | prefix_ok

step "Verifying default truncation behavior"
# The fixture deliberately produces > 20 findings, so the default cap must fire.
TRUNC_SIDECAR="${ROOT_DIR}/.tmp/e2e-report/truncation-info.json"
if [[ ! -f "${TRUNC_SIDECAR}" ]]; then
  echo "missing: truncation-info.json should exist when default --max-findings=20 cap fires" >&2
  exit 1
fi
if ! rg -q '"truncated":\s*true' "${TRUNC_SIDECAR}"; then
  echo "expected truncation-info.json to record truncated=true" >&2
  exit 1
fi
if ! rg -q '"shown":\s*20' "${TRUNC_SIDECAR}"; then
  echo "expected truncation-info.json to record shown=20" >&2
  exit 1
fi
DEFAULT_FINDING_COUNT=$(rg -c '"rule_id"' "${ROOT_DIR}/.tmp/e2e-report/findings.json" || echo 0)
if [[ "${DEFAULT_FINDING_COUNT}" != "20" ]]; then
  echo "expected exactly 20 findings under default cap, got ${DEFAULT_FINDING_COUNT}" >&2
  exit 1
fi
if ! rg -q 'class="truncation-banner"' "${ROOT_DIR}/.tmp/e2e-report/report.html"; then
  echo "expected HTML report to render the truncation-banner div" >&2
  exit 1
fi
ok "default cap produced 20 findings, sidecar + HTML banner present"

step "Running kubesplaining scan --all-findings (assertion coverage)"
# All rule-ID assertions and regression checks below run against the full,
# uncapped findings list so we can verify every expected rule fired. The
# default-cap scan above already covers the user-visible banner UX.
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --audit-log "${AUDIT_LOG}" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-full" \
  --all-findings \
  --output-format html,json,csv | prefix_ok
SUMMARY_LINE=$(grep -m1 "^findings:" "${SCAN_LOG}" 2>/dev/null || echo "")

step "Running kubesplaining scan --exclusions-preset=minimal (cloud-rule coverage)"
# Slot #15 (Cloud Provider Integration: EKS) lands rules whose canonical
# Resource lives in kube-system (the aws-auth ConfigMap). The default
# "standard" exclusions preset drops every kube-system-anchored finding, so
# we re-scan with the "minimal" preset for the cloud assertions only. The
# preset still excludes system:* / kubeadm:* subjects so the privesc-graph
# regression tests against the standard-preset scan above remain stable.
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-minimal" \
  --exclusions-preset minimal \
  --all-findings \
  --output-format json >/dev/null
ok "minimal-preset scan written for cloud-rule assertions"

step "Verifying expected rule IDs"
# Each *.expect file under testdata/e2e/expectations/ lists rule IDs one per
# line. The baseline file carries the set 00-baseline.yaml produces; Wave 1
# analyzer slots add their own <feature>.expect alongside the workload shard.
# Lines starting with '#' and blank lines are skipped.
#
# Cloud-eks assertions (slot #15) route against the minimal-preset scan so
# the aws-auth ConfigMap finding (anchored in kube-system) is not dropped.
# Every other expectation file routes against the standard-preset scan.
#
# Historically excluded by the baseline fixture (kept for reviewers landing
# new shards): KUBE-PODSEC-PROCMOUNT-001 — K8s 1.32+ requires hostUsers: false
# to apply procMount: Unmasked, and pods with hostUsers: false do not start
# on kind (mount-product-files.sh hits a permission-denied under the remapped
# UID). Detection is covered by analyzer unit tests in
# internal/analyzer/podsec/analyzer_test.go.
collect_rules() {
  # collect_rules <path-to-.expect-file> appends each non-blank, non-comment
  # rule-ID line to the provided array variable name.
  local file="$1" var="$2" line
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" ]] && continue
    eval "${var}+=(\"\${line}\")"
  done < "${file}"
}

STD_RULES=()
CLOUD_RULES=()
shopt -s nullglob
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.expect; do
  base="$(basename "${f}" .expect)"
  if [[ "${base}" == "cloud-eks" ]]; then
    collect_rules "${f}" CLOUD_RULES
  else
    collect_rules "${f}" STD_RULES
  fi
done
shopt -u nullglob

missing=()
for rule in "${STD_RULES[@]}"; do
  if ! rg -q "\"rule_id\":\s*\"${rule}\"" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
    missing+=("${rule}")
  fi
done
for rule in "${CLOUD_RULES[@]}"; do
  if ! rg -q "\"rule_id\":\s*\"${rule}\"" "${ROOT_DIR}/.tmp/e2e-report-minimal/findings.json"; then
    missing+=("${rule} (minimal-preset scan)")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "missing expected rules in findings.json:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 1
fi
ok "all $(( ${#STD_RULES[@]} + ${#CLOUD_RULES[@]} )) expected rule IDs present"

step "Verifying rule-ID set equality (false-positive gate)"
# The expected-rule check above proves recall (each shard's rules fired). This
# proves the inverse: that NOTHING ELSE fired. The committed *.ruleset goldens
# list the exact rule-ID set each scan produces, so a rule appearing that is not
# in the golden (a candidate false positive) or an expected one vanishing (a
# recall regression) both fail here. The two scans differ on purpose: the full
# scan runs the standard preset + audit log (adds the least-privilege
# KUBE-RBAC-UNUSED-* rules); the minimal scan runs the minimal preset without
# audit data (surfaces the kube-system-anchored cloud/secrets rules the standard
# preset mutes). Regenerate after an intended change with:
#   LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-full/findings.json    | LC_ALL=C sort -u > testdata/e2e/expectations/full-scan.ruleset
#   LC_ALL=C jq -r '.[].rule_id' .tmp/e2e-report-minimal/findings.json | LC_ALL=C sort -u > testdata/e2e/expectations/minimal-scan.ruleset
assert_ruleset() {
  # assert_ruleset <label> <findings.json> <golden.ruleset>. Compares the sorted
  # unique rule-ID set of the scan against the committed golden, failing on any
  # rule added (candidate false positive) or removed (recall regression). Both
  # sides are re-sorted under LC_ALL=C so comm sees a stable collation order
  # regardless of the runner's locale.
  local label="$1" findings="$2" golden="$3"
  local actual="${ROOT_DIR}/.tmp/${label}-scan.ruleset.actual"
  local golden_sorted="${ROOT_DIR}/.tmp/${label}-scan.ruleset.golden"
  LC_ALL=C jq -r '.[].rule_id' "${findings}" | LC_ALL=C sort -u > "${actual}"
  LC_ALL=C sort -u "${golden}" > "${golden_sorted}"
  local added removed
  added="$(comm -13 "${golden_sorted}" "${actual}")"
  removed="$(comm -23 "${golden_sorted}" "${actual}")"
  if [[ -n "${added}" || -n "${removed}" ]]; then
    echo "rule-ID set mismatch for ${label} scan (vs $(basename "${golden}")):" >&2
    [[ -n "${added}" ]]   && printf '  + %s  (unexpected — candidate false positive)\n' ${added} >&2
    [[ -n "${removed}" ]] && printf '  - %s  (missing — recall regression)\n' ${removed} >&2
    echo "  If intentional, regenerate the golden (see comment above)." >&2
    exit 1
  fi
  ok "${label} rule-ID set matches golden ($(wc -l < "${golden}" | tr -d ' ') rules)"
}
assert_ruleset "full"    "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"    "${ROOT_DIR}/testdata/e2e/expectations/full-scan.ruleset"
assert_ruleset "minimal" "${ROOT_DIR}/.tmp/e2e-report-minimal/findings.json" "${ROOT_DIR}/testdata/e2e/expectations/minimal-scan.ruleset"

step "Verifying deny guards (findings that must be absent)"
# Each *.deny file under testdata/e2e/expectations/ lists finding-ID prefixes
# (one per line; '#' comments and blanks skipped) that must NOT appear in the
# standard-preset full scan. A line matches a finding when its id equals the line
# or begins with "<line>:", so a bare rule ID bans every instance and a
# rule:subject prefix bans one. This is the instance-level negative guard the
# rule-ID golden cannot express: a rule can fire legitimately for one subject
# while being a false positive for another.
DENY_RULES=()
shopt -s nullglob
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.deny; do
  collect_rules "${f}" DENY_RULES
done
shopt -u nullglob
deny_violations=()
for deny in "${DENY_RULES[@]}"; do
  while IFS= read -r hit; do
    [[ -z "${hit}" ]] && continue
    deny_violations+=("${hit}  (deny: ${deny})")
  done < <(jq -r --arg d "${deny}" '.[] | select(.id == $d or (.id | startswith($d + ":"))) | .id' "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")
done
if (( ${#deny_violations[@]} > 0 )); then
  echo "deny-guard violations in standard-preset findings.json:" >&2
  printf '  - %s\n' "${deny_violations[@]}" >&2
  exit 1
fi
ok "no deny-guard violations (${#DENY_RULES[@]} guards checked)"

step "Verifying escalation-chain shape"
# Each *.chain file asserts that a finding exists AND that its escalation chain is
# still deep and correctly ordered. Format, one assertion per non-comment line:
#   <finding-id-prefix> <min-hop-count> <ordered,comma,separated,actions> [primary|alternate]
# The fourth column selects which chain to check: primary reads escalation_path and is
# the default when the column is omitted, so every pre-existing assertion reads
# unchanged; alternate reads alternate_escalation_path, the route that survives the
# recommended fix's binding cut (present only on findings tagged privesc:survives-first-cut).
# The action list must appear as an ordered SUBSEQUENCE of the finding's hop actions,
# so adding a new intermediate hop does not spuriously fail the gate.
#
# This is the gate the rule-ID goldens cannot express: they prove which rules fired,
# not that the graph still chains. A regression collapsing every path to a single hop,
# or collapsing every alternate route back to nothing, keeps the rule-ID set identical
# and would otherwise pass silently.
chain_violations=()
chain_checks=0
shopt -s nullglob
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.chain; do
  while read -r prefix min_hops actions variant; do
    case "${prefix}" in ''|'#'*) continue ;; esac
    chain_checks=$(( chain_checks + 1 ))

    # Fourth column selects which chain to assert against. Omitted means primary, so
    # every pre-existing assertion reads unchanged.
    case "${variant}" in
      ''|primary) path_field="escalation_path" ;;
      alternate)  path_field="alternate_escalation_path" ;;
      *) chain_violations+=("${prefix} has unknown variant ${variant}, want primary or alternate"); continue ;;
    esac

    match_count="$(jq -r --arg p "${prefix}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))] | length' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"
    if [[ "${match_count}" != "1" ]]; then
      chain_violations+=("${prefix} matched ${match_count} findings, want exactly 1 (make the prefix more specific)")
      continue
    fi

    actual_hops="$(jq -r --arg p "${prefix}" --arg pf "${path_field}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))][0] | (.[$pf] | length) // 0' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"

    # match_count already proved the finding exists, so a zero-length chain here means
    # the finding has no path field, not that the finding is missing. Reporting the two
    # cases identically would be actively misleading for the alternate variant: this is
    # exactly the shape a regression that collapsed alternate detection back to nothing
    # would produce, and it would send whoever reads the failure hunting a missing
    # finding that was never missing.
    if [[ -z "${actual_hops}" || "${actual_hops}" == "null" || "${actual_hops}" == "0" ]]; then
      chain_violations+=("${prefix} exists but has no ${path_field} chain")
      continue
    fi
    if (( actual_hops < min_hops )); then
      chain_violations+=("${prefix} has ${actual_hops} hops, want at least ${min_hops}")
      continue
    fi

    actual_actions="$(jq -r --arg p "${prefix}" --arg pf "${path_field}" \
      '[.[] | select(.id == $p or (.id | startswith($p + ":")))][0] | [.[$pf][].action] | join(",")' \
      "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"

    # Consume the actual action list left to right, requiring each wanted action to
    # appear after the previous one. The needle variable keeps the nested quoting
    # unambiguous; inlining it into the parameter expansion parses badly in bash.
    missing=""
    remaining=",${actual_actions},"
    for want in ${actions//,/ }; do
      needle=",${want},"
      if [[ "${remaining}" == *"${needle}"* ]]; then
        remaining=",${remaining#*"${needle}"}"
      else
        missing="${want}"
        break
      fi
    done
    if [[ -n "${missing}" ]]; then
      chain_violations+=("${prefix} chain [${actual_actions}] missing ordered action ${missing}")
      continue
    fi
    ok "chain ${prefix} (${path_field}): ${actual_hops} hops [${actual_actions}]"
  done < "${f}"
done
shopt -u nullglob
if (( ${#chain_violations[@]} > 0 )); then
  echo "escalation-chain guard violations:" >&2
  printf '  - %s\n' "${chain_violations[@]}" >&2
  exit 1
fi
ok "all ${chain_checks} escalation-chain guards satisfied"

step "Verifying an alternate never starts with the binding its own fix cuts"
# The whole cut-resilient feature rests on one property, checked here over EVERY
# finding in the full scan, not just the ones a *.chain line names: for a finding with
# a non-empty alternate_escalation_path, let P be escalation_path[0] and A be
# alternate_escalation_path[0]. Then NOT (A.source_binding == P.source_binding AND
# A.binding_namespace == P.binding_namespace). If A's first hop were granted by the
# same binding the remediation removes the subject from, the finding would not merely
# be useless, it would be actively misleading: it tells an operator their fix is
# insufficient and shows them, as proof, a route the fix itself closes.
#
# This is deliberately not a *.chain line. The chain gate above names one finding
# prefix and pins its shape; this walks the whole findings.json and would catch a
# regression in a finding nobody thought to write a *.chain assertion for. A gate that
# only ever sees zero alternates would pass vacuously, so ALT_CHECKED must be nonzero.
#
# A.source_binding can legitimately be empty (Task 9's CutBreakers-only correlation
# edges carry no SourceBinding by design), which is not a violation, just the unstamped
# case surviving legitimately. Both source_binding and binding_namespace are
# `omitempty` in the JSON, so an absent field round-trips as jq `null`; the filter
# below requires BOTH sides' source_binding to be non-null before comparing them, so
# two absent bindings are never mistaken for a match.
ALT_CHECKED="$(jq -r '[.[] | select(((.alternate_escalation_path // []) | length) > 0)] | length' "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"
if [[ "${ALT_CHECKED}" == "0" ]]; then
  echo "no findings carried an alternate_escalation_path: this gate would pass vacuously, which is worse than not gating at all" >&2
  exit 1
fi
ALT_VIOLATIONS="$(jq -r '
  .[]
  | select(((.alternate_escalation_path // []) | length) > 0)
  | . as $f
  | ($f.escalation_path[0].source_binding // null) as $p_binding
  | ($f.escalation_path[0].binding_namespace // "") as $p_ns
  | ($f.alternate_escalation_path[0].source_binding // null) as $a_binding
  | ($f.alternate_escalation_path[0].binding_namespace // "") as $a_ns
  | select($p_binding != null and $a_binding != null and $a_binding == $p_binding and $a_ns == $p_ns)
  | "\($f.id): alternate hop 1 (\($f.alternate_escalation_path[0].action)) shares binding \($a_binding)/\($a_ns) with primary hop 1 (\($f.escalation_path[0].action))"
' "${ROOT_DIR}/.tmp/e2e-report-full/findings.json")"
if [[ -n "${ALT_VIOLATIONS}" ]]; then
  echo "alternate-escalation-path invariant violations (the recommended fix would not actually close the alternate):" >&2
  echo "${ALT_VIOLATIONS}" | sed 's/^/  - /' >&2
  exit 1
fi
ok "no alternate reuses its primary's cut binding (${ALT_CHECKED} alternate-bearing findings checked)"

# NOTE: the issue-#48 cluster-admin false-positive guard and the
# KUBE-ADMISSION-NO-POLICY-ENGINE-001 absence guard now live in
# testdata/e2e/expectations/baseline.deny and are enforced by the deny-guard
# step above. The positive counterpart (the namespace-admin path this same
# fixture MUST produce) stays here.

# The rbac-ns-fixtures RoleBinding must produce KUBE-PRIVESC-PATH-NAMESPACE-ADMIN, naming
# the namespace it can take over. The finding ID encodes the target namespace as
# the last segment after a fourth `:`.
NS_SUBJECT_KEY="ServiceAccount/rbac-ns-fixtures/sa-ns-rolebinding-mutate"
NS_OK_ID="KUBE-PRIVESC-PATH-NAMESPACE-ADMIN:${NS_SUBJECT_KEY}:namespace_admin:rbac-ns-fixtures"
if ! rg -q "\"id\":\s*\"${NS_OK_ID}\"" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "missing: namespace-scoped RoleBinding did not produce expected KUBE-PRIVESC-PATH-NAMESPACE-ADMIN finding for ${NS_SUBJECT_KEY} → rbac-ns-fixtures" >&2
  exit 1
fi
ok "namespace-admin path emitted for namespace-scoped RoleBinding"

# The default-suppress drop of KUBE-ESCAPE-001 for the psa-suppressed namespace
# is now enforced by testdata/e2e/expectations/baseline.deny (deny-guard step
# above). PSA_FINDING_ID is still needed by the attenuate-mode assertion below,
# which checks the inverse (the finding reappears, tagged) under a different scan.
PSA_FINDING_ID="KUBE-ESCAPE-001:Deployment:psa-suppressed:psa-priv-app"

# admission-summary.json must record the suppression count and the per-namespace breakdown.
if ! rg -q "\"suppressed\":\s*[1-9]" "${ROOT_DIR}/.tmp/e2e-report-full/admission-summary.json"; then
  echo "missing: admission-summary.json should record suppressed >= 1" >&2
  exit 1
fi
if ! rg -q "psa-suppressed" "${ROOT_DIR}/.tmp/e2e-report-full/admission-summary.json"; then
  echo "missing: admission-summary.json should mention psa-suppressed namespace" >&2
  exit 1
fi
ok "admission-summary.json records the suppressed psa-suppressed finding"

step "Re-running scan with --admission-mode=attenuate"
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-attenuate" \
  --admission-mode attenuate \
  --all-findings \
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

step "Re-running scan with --remediation-patches"
# Asserts the opt-in remediation-hint flag actually wires through the engine
# and at least one analyzer emits a hint into the JSON output. Without the
# flag, hint emission is stripped by the engine post-process pass; with the
# flag, every module's per-finding RemediationHint passes through.
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-remediation" \
  --remediation-patches \
  --all-findings \
  --output-format json >/dev/null
if ! rg -q '"remediation_hint"' "${ROOT_DIR}/.tmp/e2e-report-remediation/findings.json"; then
  echo "missing: --remediation-patches should produce at least one remediation_hint in findings.json" >&2
  exit 1
fi
ok "remediation hints present under --remediation-patches"

# The check above passes if ANY finding anywhere carries a hint, which would not have
# caught the defect Task 10 part (b) fixed: ForPrivescPath used to guard on a
# `KUBE-PRIVESC-PATH-` RuleID prefix and return nil for everything else, so every
# KUBE-CONFUSED-DEPUTY-001 finding got no hint at all. That fix has unit coverage and,
# until now, no e2e gate: this asserts it directly. A non-null remediation_hint is not
# enough on its own, either: ForPrivescPath falls back to a generic advisory diff with
# no `patch` object when it cannot resolve hop 1's SourceBinding back to a live
# (Cluster)RoleBinding in the snapshot, so a hint that resolved to nothing would satisfy
# a bare non-null check. Require the hint to actually NAME a binding: `patch.target.kind`
# is a (Cluster)RoleBinding and `patch.target.name` is non-empty.
#
# Shard 18's cutres-deputy fixture (added by a later task) is load-bearing for this
# assertion: it is the shape whose deputy findings' hints resolve to a real binding
# (cutres-deputy-cert-a), alongside shard 17's deepchain-deployer (deepchain-gitops).
DEPUTY_HINT_COUNT="$(jq -r '
  [.[] | select(
    .rule_id == "KUBE-CONFUSED-DEPUTY-001"
    and .remediation_hint != null
    and (.remediation_hint.patch.target.kind == "RoleBinding" or .remediation_hint.patch.target.kind == "ClusterRoleBinding")
    and ((.remediation_hint.patch.target.name // "") != "")
  )] | length
' "${ROOT_DIR}/.tmp/e2e-report-remediation/findings.json")"
if [[ "${DEPUTY_HINT_COUNT}" == "0" ]]; then
  echo "missing: at least one KUBE-CONFUSED-DEPUTY-001 finding should carry a remediation_hint naming a (Cluster)RoleBinding, not just a non-null hint" >&2
  exit 1
fi
ok "confused-deputy remediation hints name a (Cluster)RoleBinding (${DEPUTY_HINT_COUNT} findings)"

# Confirm the inverse: without the flag, no hints should leak through.
if rg -q '"remediation_hint"' "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "regression: default scan (no --remediation-patches) should not emit remediation_hint" >&2
  exit 1
fi
ok "default scan correctly omits remediation_hint"

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
REPORT_FULL_HTML="${ROOT_DIR}/.tmp/e2e-report-full/report.html"
REPORT_FULL_REL="${REPORT_FULL_HTML#"${ROOT_DIR}/"}"
REPORT_FULL_URL="file://${REPORT_FULL_HTML}"
RULE="═══════════════════════════════════════════════════════════════════════"

printf "\n%s%s%s\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
printf "  %s✓ kubesplaining e2e complete%s\n" "${C_BOLD}${C_GREEN}" "${C_RESET}"
if [[ -n "${SUMMARY_LINE}" ]]; then
  printf "  %s%s%s\n" "${C_DIM}" "${SUMMARY_LINE}" "${C_RESET}"
fi
printf "%s%s%s\n\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"

printf "  %sOpen the HTML report (default top-20 cap)%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s%s%s\n" "${C_BLUE}" "${REPORT_URL}" "${C_RESET}"
printf "    %sopen %s%s\n\n" "${C_DIM}" "${REPORT_REL}" "${C_RESET}"

printf "  %sOpen the full report (uncapped, includes Least Privilege tab)%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s%s%s\n" "${C_BLUE}" "${REPORT_FULL_URL}" "${C_RESET}"
printf "    %sopen %s%s\n\n" "${C_DIM}" "${REPORT_FULL_REL}" "${C_RESET}"

printf "  %sPoke at the cluster%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %skubectl get pods -A%s\n" "${C_DIM}" "${C_RESET}"
printf "    %skubectl --context kind-%s get clusterrolebindings%s\n\n" "${C_DIM}" "${KIND_CLUSTER_NAME}" "${C_RESET}"

printf "  %sTear it down%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %smake delete%s\n" "${C_DIM}" "${C_RESET}"
