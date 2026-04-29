// Content for network-policy findings. Each rule has a builder that takes runtime context
// (namespace, policy name, workload labels, CIDR) and returns an enriched ruleContent with
// scope-aware language, an attacker walkthrough, ordered remediation steps, and structured
// references / MITRE technique citations.
//
// Sources: Kubernetes NetworkPolicy docs, CIS Kubernetes Benchmark 5.3.2, NSA/CISA Kubernetes
// Hardening Guide v1.2, Calico/Cilium docs, MITRE ATT&CK Containers, Christophe Tafani-Dereeper
// EKS-IMDS escalation, ahmetb network-policy-recipes.
package network

import (
	"fmt"

	"github.com/hardik/kubesplaining/internal/models"
)

type ruleContent struct {
	Title            string
	Scope            models.Scope
	Description      string
	Impact           string
	AttackScenario   []string
	Remediation      string
	RemediationSteps []string
	LearnMore        []models.Reference
	MitreTechniques  []models.MitreTechnique
}

var (
	mitreT1552_005 = models.MitreTechnique{ID: "T1552.005", Name: "Cloud Instance Metadata API", URL: "https://attack.mitre.org/techniques/T1552/005/"}
	mitreT1041     = models.MitreTechnique{ID: "T1041", Name: "Exfiltration Over C2 Channel", URL: "https://attack.mitre.org/techniques/T1041/"}
	mitreT1071     = models.MitreTechnique{ID: "T1071", Name: "Application Layer Protocol", URL: "https://attack.mitre.org/techniques/T1071/"}
	mitreT1090     = models.MitreTechnique{ID: "T1090", Name: "Proxy", URL: "https://attack.mitre.org/techniques/T1090/"}
	mitreT1018     = models.MitreTechnique{ID: "T1018", Name: "Remote System Discovery", URL: "https://attack.mitre.org/techniques/T1018/"}
	mitreT1046     = models.MitreTechnique{ID: "T1046", Name: "Network Service Discovery", URL: "https://attack.mitre.org/techniques/T1046/"}
	mitreT1567     = models.MitreTechnique{ID: "T1567", Name: "Exfiltration Over Web Service", URL: "https://attack.mitre.org/techniques/T1567/"}
	mitreT1078_004 = models.MitreTechnique{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"}
)

var (
	refNetworkPolicies = models.Reference{Title: "Kubernetes — Network Policies", URL: "https://kubernetes.io/docs/concepts/services-networking/network-policies/"}
	refCISBenchmark532 = models.Reference{Title: "CIS Kubernetes Benchmark 5.3.2 — All namespaces should have NetworkPolicies", URL: "https://www.cisecurity.org/benchmark/kubernetes"}
	refNSAHardening    = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guidance v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
)

func contentNetpolCoverage001(namespace string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Namespace `%s` has zero NetworkPolicies — all pods accept any inbound and reach any outbound endpoint", namespace),
		Scope: models.Scope{
			Level:  models.ScopeNamespace,
			Detail: fmt.Sprintf("Namespace `%s` — every workload inside inherits allow-all behavior", namespace),
		},
		Description: fmt.Sprintf("Namespace `%s` contains workloads but no NetworkPolicy objects. Without any policy selecting its pods, the Kubernetes networking model is allow-all in both directions: any pod in any namespace can open a TCP/UDP connection to any pod here, and any pod here can open arbitrary outbound connections (cluster pod CIDR, Services, node IPs, the cloud Instance Metadata Service at `169.254.169.254`, the public internet, and the API server).\n\n"+
			"This is the documented Kubernetes default — a pod is non-isolated for ingress/egress until at least one NetworkPolicy with the relevant `policyTypes` selects it. CIS Kubernetes Benchmark 5.3.2 and the NSA/CISA Hardening Guide v1.2 both require a default-deny baseline in every namespace.\n\n"+
			"A single compromised pod (RCE, leaked credential, supply-chain backdoor) immediately gains the full L3/L4 reachability graph of the cluster: kube-DNS for service discovery, the cloud metadata service for IAM credentials, attacker-controlled C2 endpoints, and high-value pods (databases, vault, kube-system DaemonSets) all without crossing any policy boundary.",
			namespace),
		Impact: "Any pod compromise becomes cluster-wide L3/L4 reach: lateral movement, credential theft from IMDS, and arbitrary egress to attacker C2 are all unblocked.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker exploits an unpatched dependency in any pod in `%s` and lands a shell.", namespace),
			"They scan the pod CIDR (`for i in $(seq 1 254); do nc -zv 10.244.0.$i 6379 5432 3306 27017; done`) — every database port across every namespace is reachable.",
			"They hit the cloud metadata endpoint `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` and exfiltrate the node's IAM credentials.",
			"They establish outbound C2 to attacker-controlled IP/domain over 443 and tunnel harvested secrets, pod tokens, and DNS reconnaissance.",
			"They pivot cluster-wide: query kube-DNS for `*.svc.cluster.local`, identify Vault/Postgres/Redis, authenticate with stolen tokens — full lateral movement.",
		},
		Remediation: fmt.Sprintf("Apply a default-deny-all NetworkPolicy in `%s`, then add minimal explicit allow policies for DNS plus each workload's actual ingress/egress dependencies.", namespace),
		RemediationSteps: []string{
			fmt.Sprintf("Apply a default-deny baseline (`podSelector: {}`, `policyTypes: [Ingress, Egress]`) to `%s`.", namespace),
			"Add a tightly-scoped DNS allow policy (UDP/TCP 53 to kube-system) — without DNS every workload's hostname resolution will fail.",
			"For each workload, write an explicit allow policy: ingress from the named upstream and egress to its actual dependencies — never `0.0.0.0/0`.",
			fmt.Sprintf("Validate with a debug pod: `kubectl run -n %s --rm -it tmp --image=nicolaka/netshoot -- bash` confirming allowed paths work and disallowed paths time out.", namespace),
			"Wire CIS 5.3.2 / Kyverno's `require-network-policy` policy into CI so future namespaces ship with a baseline.",
		},
		LearnMore: []models.Reference{
			refNetworkPolicies,
			refCISBenchmark532,
			refNSAHardening,
			{Title: "Calico — get started with Kubernetes NetworkPolicy", URL: "https://docs.tigera.io/calico/latest/network-policy/get-started/kubernetes-policy/kubernetes-network-policy"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_005, mitreT1041, mitreT1071, mitreT1090, mitreT1018, mitreT1046},
	}
}

func contentNetpolWeakness002(namespace, policyName, cidr string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("NetworkPolicy `%s/%s` allows egress to `%s` (entire internet)", namespace, policyName, cidr),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("NetworkPolicy `%s/%s` — the workloads it selects can reach any IPv4/IPv6 destination", namespace, policyName),
		},
		Description: fmt.Sprintf("NetworkPolicy `%s/%s` contains an egress rule whose `ipBlock.cidr` is `%s`. This is the broadest possible CIDR — semantically equivalent to \"allow this workload to make outbound connections to any destination.\" Because NetworkPolicy egress rules are additive, this single rule defeats whatever segmentation other policies tried to build for the selected pods.\n\n"+
			"Two properties make this rule especially dangerous: (1) `0.0.0.0/0` includes the link-local range that holds the cloud Instance Metadata Service (`169.254.169.254/32` on AWS/Azure, `metadata.google.internal` on GCP), so a compromised pod can scrape node IAM credentials and pivot to the underlying cloud account; (2) `0.0.0.0/0` also includes the Pod and Service CIDRs of the cluster itself, so the rule does not just open the internet — it also opens inter-namespace traffic for the selected pods unless an `except:` block carves out the cluster ranges.\n\n"+
			"A correctly-scoped egress policy uses an `ipBlock` with the specific CIDRs the workload needs (a private VPC peer, a known SaaS provider's published range), or a `namespaceSelector + podSelector` pair to a named in-cluster dependency. `0.0.0.0/0` should never appear in a production egress allow rule.",
			namespace, policyName, cidr),
		Impact: "Selected workload can reach any IP, including cloud IMDS (credential theft) and arbitrary attacker C2 (data exfiltration) — turns any pod compromise into cloud-account compromise.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises a pod selected by `%s.spec.podSelector`.", policyName),
			"They hit `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and pull the node's IAM credentials — the egress rule allows this because IMDS is inside `0.0.0.0/0`.",
			"They use stolen IAM credentials with `aws sts get-caller-identity` then enumerate the cloud account.",
			"They open an outbound TLS connection to `c2.attacker.example` on 443 (covered by the same broad rule) and exfiltrate harvested secrets.",
			"They abuse the same broad CIDR to reach other in-cluster Services unless `except:` carves out the cluster ranges.",
		},
		Remediation: "Replace `0.0.0.0/0` with the specific CIDRs the workload needs, or use `namespaceSelector/podSelector` for in-cluster destinations, and explicitly carve out the IMDS range.",
		RemediationSteps: []string{
			fmt.Sprintf("Inventory what `%s`'s selected pods actually need to reach (use `kubectl exec ... -- ss -tnp` or VPC flow logs).", policyName),
			"Replace the `0.0.0.0/0` rule with a specific allowlist — ipBlocks for required SaaS CIDRs, namespaceSelector/podSelector for in-cluster targets.",
			"At a CNI tier (Calico GlobalNetworkPolicy or Cilium ClusterwideNetworkPolicy), add a non-overridable deny for `169.254.169.254/32`.",
			"Validate with a netshoot pod: confirm legitimate destinations resolve and connect; confirm `curl --max-time 3 http://169.254.169.254/` and arbitrary internet hosts time out.",
			"Add a Kyverno or OPA Gatekeeper policy that rejects any new NetworkPolicy whose ipBlock CIDR is `0.0.0.0/0` or `::/0`.",
		},
		LearnMore: []models.Reference{
			refNetworkPolicies,
			{Title: "Calico GlobalNetworkPolicy reference", URL: "https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy"},
			{Title: "Christophe Tafani-Dereeper — EKS privilege escalation via worker node IAM", URL: "https://blog.christophetd.fr/privilege-escalation-in-aws-elastic-kubernetes-service-eks-by-compromising-the-instance-role-of-worker-nodes/"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_005, mitreT1041, mitreT1071, mitreT1090, mitreT1567},
	}
}

func contentNetpolCoverage002(kind, namespace, name string, labels map[string]string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Workload `%s/%s/%s` is in a policied namespace but no policy podSelector matches it", kind, namespace, name),
		Scope: models.Scope{
			Level:  models.ScopeWorkload,
			Detail: fmt.Sprintf("Workload `%s/%s/%s` (labels %v) — covered by no NetworkPolicy in `%s`", kind, namespace, name, labels, namespace),
		},
		Description: fmt.Sprintf("Workload `%s/%s/%s` runs in `%s` which has at least one NetworkPolicy, but none of those policies' `podSelector` clauses match this workload's labels (`%v`). The Kubernetes NetworkPolicy specification is explicit: a pod is \"non-isolated\" for ingress/egress until a NetworkPolicy with the corresponding `policyTypes` entry selects it.\n\n"+
			"This is the most common misconfiguration in clusters that have started rolling out NetworkPolicies: the operator added policies for the visible apps and forgot a sidecar Job, a CronJob spawned by an operator, a debug Deployment, or a workload whose labels were renamed. \"Selected by no policy\" is semantically identical to \"in a namespace with no policies at all\" for this specific pod — full allow-in, full allow-out — even though `kubectl get netpol` makes the namespace look protected.\n\n"+
			"The failure mode is invisible at a glance: dashboards say \"NetworkPolicies present in namespace,\" CIS 5.3.2 may pass, but the uncovered workload is exactly the kind of pod attackers love — operator-managed, often privileged, often forgotten.",
			kind, namespace, name, namespace, labels),
		Impact: "This single workload retains full allow-all ingress and egress while the rest of the namespace is segmented — making it the easiest pivot point for an attacker who lands anywhere else in the cluster.",
		AttackScenario: []string{
			"Attacker compromises a low-value pod elsewhere in the cluster (CVE in a web app).",
			fmt.Sprintf("They scan the namespace's pod CIDR for reachable services. Other pods in `%s` correctly drop unsolicited traffic — except `%s`, which is uncovered.", namespace, name),
			fmt.Sprintf("They hit `%s`'s exposed application port and exploit a known issue, gaining a shell.", name),
			fmt.Sprintf("From `%s`, attacker has unrestricted egress: hits IMDS for cloud IAM credentials, opens C2 to attacker IPs, uses the pod's mounted ServiceAccount token against the API server.", name),
			"The attacker now has the network position the rest of the namespace's policies were designed to prevent.",
		},
		Remediation: fmt.Sprintf("Either deploy a namespace-wide default-deny baseline in `%s` so every new pod is automatically covered, or add an explicit policy whose `podSelector` matches this workload's labels.", namespace),
		RemediationSteps: []string{
			fmt.Sprintf("Add a default-deny baseline (`podSelector: {}`, `policyTypes: [Ingress, Egress]`) in `%s` so future pods fail closed.", namespace),
			fmt.Sprintf("Write an explicit allow policy whose `podSelector` matches `%s`'s labels and lists only the ingress sources and egress destinations it needs.", name),
			"Validate by re-running this scanner; the workload should now match at least one policy.",
			"Add a CI check (Kyverno's `require-matching-network-policy` or an OPA constraint) that fails if a new workload is admitted with labels not covered by any existing NetworkPolicy.",
		},
		LearnMore: []models.Reference{
			refNetworkPolicies,
			refCISBenchmark532,
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1046, mitreT1018, mitreT1041, mitreT1552_005, mitreT1090},
	}
}

func contentNetpolCoverage003(namespace string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("Namespace `%s` controls ingress but has no Egress policy (one-way enforcement)", namespace),
		Scope: models.Scope{
			Level:  models.ScopeNamespace,
			Detail: fmt.Sprintf("Namespace `%s` — pods are firewalled inbound but can reach any outbound destination", namespace),
		},
		Description: fmt.Sprintf("Namespace `%s` has NetworkPolicy objects that select pods for ingress filtering but no NetworkPolicy enforces egress. In Kubernetes' policy model, ingress and egress are independent dimensions: a pod is isolated for ingress only if a policy with `policyTypes: Ingress` selects it, and isolated for egress only if a policy with `policyTypes: Egress` selects it. A pod can be tightly firewalled inbound and still reach the entire internet outbound — exactly the asymmetry seen here.\n\n"+
			"This is a classic misconfiguration after a half-finished zero-trust migration. Teams typically write ingress policies first because they think of \"who can talk to my service,\" and ship without revisiting outbound. The result looks compliant in dashboards but leaves data exfiltration, cloud IMDS access, and outbound C2 wide open.\n\n"+
			"The practical risk is that egress is the dimension attackers actually want. Inbound restrictions help against external scanners, but a compromised pod's value to an attacker is in what it can talk *out* to: the cloud control plane via IMDS, attacker-controlled C2, internal databases in other namespaces, and the cluster's kube-apiserver.",
			namespace),
		Impact: "Compromised pods in this namespace retain full outbound reach — IMDS credential theft, C2 callbacks, and lateral pivots out of the namespace are unimpeded.",
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises any pod in `%s`.", namespace),
			"They hit IMDS — the namespace has no egress policy, so the request succeeds and node IAM credentials are exfiltrated.",
			"They establish C2 to `attacker.example:443` and stream captured tokens, environment variables, and pod-mounted secrets.",
			"They pivot to other namespaces by talking to ClusterIP Services directly — the missing egress policy doesn't restrict cluster-internal destinations either.",
			"They call kube-apiserver with the pod's ServiceAccount token (egress to apiserver also unrestricted), enumerating RBAC for any privesc opportunity.",
		},
		Remediation: fmt.Sprintf("Add a default-deny-egress NetworkPolicy in `%s`, then explicit per-workload egress allowlists for DNS and actual outbound dependencies.", namespace),
		RemediationSteps: []string{
			fmt.Sprintf("Apply a `default-deny-egress` policy in `%s` targeting `podSelector: {}` so every pod becomes egress-isolated.", namespace),
			"Add an explicit DNS-allow policy (UDP/TCP 53 to kube-system).",
			"For each workload that has legitimate egress, add a tight `to:` clause (specific Service, namespaceSelector+podSelector, or specific external CIDR — never `0.0.0.0/0`).",
			"Validate by `kubectl exec` into a representative pod and confirming `curl --max-time 3 https://example.com/` times out.",
			"Wire CI policy (Kyverno `require-policytypes-egress`) to fail any future namespace with ingress-only coverage.",
		},
		LearnMore: []models.Reference{
			refNetworkPolicies,
			{Title: "Red Hat — Guide to Kubernetes egress NetworkPolicies", URL: "https://www.redhat.com/en/blog/guide-to-kubernetes-egress-network-policies"},
			refNSAHardening,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1041, mitreT1071, mitreT1552_005, mitreT1567, mitreT1090},
	}
}

func contentNetpolWeakness001(namespace, policyName string) ruleContent {
	return ruleContent{
		Title: fmt.Sprintf("NetworkPolicy `%s/%s` accepts ingress from any namespace via empty namespaceSelector", namespace, policyName),
		Scope: models.Scope{
			Level:  models.ScopeObject,
			Detail: fmt.Sprintf("NetworkPolicy `%s/%s` — selected pods are reachable from every namespace, present and future", namespace, policyName),
		},
		Description: fmt.Sprintf("NetworkPolicy `%s/%s` contains an ingress `from:` peer with a `namespaceSelector` that has no `matchLabels` and no `matchExpressions`. In NetworkPolicy semantics this is the special form that means \"every namespace in the cluster\" — exactly the opposite of the Kubernetes default for `from:` peers (which is \"only the policy's own namespace\").\n\n"+
			"In multi-tenant or shared clusters the impact is direct: namespace boundaries are the cheapest soft tenancy boundary Kubernetes offers, and `namespaceSelector: {}` invalidates that boundary for the selected pods. A compromised pod in any tenant — even one with no business need to talk to these pods — has unrestricted access on the allowed ports.\n\n"+
			"The correct pattern is to scope the `namespaceSelector` to the specific labels that identify allowed source namespaces (e.g., `tenancy.example.com/team: data-platform`) and combine it with an explicit `podSelector` so only the right pods in the right namespaces can connect. Combined selectors mean \"pods matching label X in namespaces matching label Y\" — the AND form, not the OR form.",
			namespace, policyName),
		Impact: "Selected workloads are reachable from any pod in any namespace on the allowed ports — defeating namespace-based tenant isolation and inviting cross-tenant lateral movement.",
		AttackScenario: []string{
			"Attacker compromises a low-value pod in some other namespace (CI runner, stale demo, shared sidecar).",
			fmt.Sprintf("They enumerate ClusterIP Services and notice the Service backing `%s`'s pods in `%s`.", policyName, namespace),
			"They attempt a TCP connect from the other namespace — under any other policy this would be denied at the CNI, but `namespaceSelector: {}` matches and the connection succeeds.",
			"They exploit an application-layer issue on the now-reachable port (auth bypass, weak credential, RCE) and pivot into the high-value workload.",
			"They continue lateral motion from inside the target namespace using mounted tokens and secrets.",
		},
		Remediation: "Replace the empty `namespaceSelector` with explicit labels identifying the small set of namespaces that legitimately need access, paired with a `podSelector`.",
		RemediationSteps: []string{
			"Identify which namespaces actually need to reach the selected pods (often one or two — never \"all\").",
			"Label those namespaces with a stable, policy-meaningful key (e.g., `tenancy.example.com/team: data-platform`).",
			fmt.Sprintf("Edit `%s` to replace `namespaceSelector: {}` with `matchLabels` for the chosen label, and add a sibling `podSelector`.", policyName),
			"Validate by attempting connections from a netshoot pod in a non-allowed namespace (must time out) and from an allowed namespace (must succeed).",
			"Add a Kyverno or OPA Gatekeeper rule that warns on any new NetworkPolicy with an empty `namespaceSelector` peer.",
		},
		LearnMore: []models.Reference{
			refNetworkPolicies,
			{Title: "ahmetb network-policy-recipes — allow traffic from all namespaces (illustrates the foot-gun)", URL: "https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/05-allow-traffic-from-all-namespaces.md"},
			{Title: "vCluster — NetworkPolicies for multi-tenant isolation", URL: "https://www.vcluster.com/blog/kubernetes-network-policies-for-isolating-namespaces"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1046, mitreT1018, mitreT1090, mitreT1078_004},
	}
}
