// Content for CertificateSigningRequest findings. Each builder takes the CSR the
// rule fired on plus its lifecycle state ("approved" / "pending") and returns the
// enriched ruleContent: scope-aware language, an attacker walkthrough, ordered
// remediation steps, and structured references / MITRE citations.
//
// Sources: Kubernetes CSR reference (signers, approval and signing authorization),
// the CertificateApproval / CertificateSigning / CertificateSubjectRestriction
// admission-controller reference, Kubernetes X509 client-certificate authentication
// docs, and RBAC Good Practices on CertificateSigningRequest escalation.
package certificates

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ruleContent bundles every enriched field a rule emits beyond Title/Description.
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
	mitreT1078_004 = models.MitreTechnique{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"}
	mitreT1098     = models.MitreTechnique{ID: "T1098", Name: "Account Manipulation", URL: "https://attack.mitre.org/techniques/T1098/"}
	mitreT1098_001 = models.MitreTechnique{ID: "T1098.001", Name: "Account Manipulation: Additional Cloud Credentials", URL: "https://attack.mitre.org/techniques/T1098/001/"}
	mitreT1550     = models.MitreTechnique{ID: "T1550", Name: "Use Alternate Authentication Material", URL: "https://attack.mitre.org/techniques/T1550/"}
)

var (
	refCSRReference = models.Reference{
		Title: "Kubernetes — Certificate Signing Requests (signers, approval, signing)",
		URL:   "https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/",
	}
	refX509Auth = models.Reference{
		Title: "Kubernetes — Authenticating: X509 client certificates (CN → user, O → group)",
		URL:   "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certificates",
	}
	refCertAdmission = models.Reference{
		Title: "Kubernetes — Admission Controllers: CertificateApproval, CertificateSigning, CertificateSubjectRestriction",
		URL:   "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#certificatesubjectrestriction",
	}
	refRBACGoodPractices = models.Reference{
		Title: "Kubernetes — RBAC Good Practices: CertificateSigningRequest escalation",
		URL:   "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#certificatesigningrequest",
	}
	refBoundSATokens = models.Reference{
		Title: "Kubernetes — Bound Service Account Tokens (why a token is the safer credential)",
		URL:   "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens",
	}
)

// auditSteps are the two closing remediation steps both rules share: how to look
// for other issued certificates, and the fact that CA rotation is the only
// revocation Kubernetes offers.
var auditSteps = []string{
	"List what else has been requested recently: `kubectl get csr -o custom-columns=NAME:.metadata.name,SIGNER:.spec.signerName,REQUESTOR:.spec.username,APPROVED:.status.conditions[*].type`. The kube-controller-manager's CSR cleaner deletes issued CSRs roughly an hour after issuance, so an empty or short list is inconclusive — check audit logs for `certificatesigningrequests` create/approve events over the retention window instead.",
	"If you conclude a certificate was issued to an identity that should not have one, rotate the cluster CA. Kubernetes publishes no CRL and the apiserver does no OCSP, so an issued client certificate stays valid for its full lifetime and no RBAC change touches it.",
}

// contentCSR001 — a ServiceAccount requested a client certificate (KUBE-CSR-001).
//
// The signal is the requester, not the contents: we never see the Subject DN
// (the collector drops the raw PEM), so the copy is careful to describe what a
// ServiceAccount-authored client-cert request means rather than asserting which
// identity was claimed.
func contentCSR001(csr models.CSR, state string) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide: a client certificate authenticates against every apiserver in the cluster, independent of the namespace the requesting workload runs in",
	}

	stateLine := "The request is still pending: no certificate has been issued yet, which makes this the rare case where you can intervene before a credential exists. Deny it (`kubectl certificate deny " + csr.Name + "`) rather than letting it age out."
	if state == "approved" {
		stateLine = "The request is APPROVED, so a certificate has been (or is about to be) issued and the credential already exists. Treat this as a live credential you cannot revoke, not as a request to review."
	}

	return ruleContent{
		Title: fmt.Sprintf("ServiceAccount `%s` requested a client certificate (CSR `%s`, %s)", csr.Username, csr.Name, state),
		Scope: scope,
		Description: fmt.Sprintf("CertificateSigningRequest `%s` was submitted by `%s` — a ServiceAccount — against the `%s` signer, whose certificates the kube-apiserver accepts as client credentials.\n\n"+
			"%s\n\n"+
			"Why a ServiceAccount asking for a certificate stands out: a ServiceAccount already has a credential, and it is deliberately the weak kind. Modern SA tokens are bound to a pod, expire on a short TTL, are invalidated when the pod or the ServiceAccount is deleted, and can be traced through the audit log to the workload that used them. A client certificate is the opposite on every axis — it is bearer material with a lifetime measured in months, it survives deletion of the ServiceAccount that requested it, no RBAC change invalidates it, and Kubernetes offers no revocation mechanism at all. A workload converting the first kind of credential into the second is either an unusual (but legitimate) integration, or an attacker building persistence that outlives the compromise being cleaned up.\n\n"+
			"What this finding does NOT claim: kubesplaining never reads the CSR's `spec.request` PEM (the collector drops it by design), so the identity the Subject DN claims is unknown here. It matters because nothing stops that DN from naming someone else — the apiserver maps a certificate's Common Name onto the username it authorizes and never checks whether Kubernetes would have issued that identity, so `CN=system:serviceaccount:kube-system:<privileged-sa>` authenticates as that ServiceAccount. Verify the claimed subject from your audit log or from the certificate itself.",
			csr.Name, csr.Username, csr.SignerName, stateLine),
		Impact: "A workload identity holds (or has asked for) a non-expiring, non-revocable client credential. If the Subject DN named an identity other than the requesting ServiceAccount, the certificate is a privilege escalation as well as a persistence mechanism; either way it survives token rotation, RBAC revocation, and deletion of the ServiceAccount.",
		AttackScenario: []string{
			"Attacker lands in a pod and reads its mounted ServiceAccount token — short-lived, bound to that pod, and useless once the pod is deleted.",
			"They check whether the SA can submit a CSR: `kubectl auth can-i create certificatesigningrequests --as=" + csr.Username + "`.",
			"They generate a key pair off-cluster and submit a CSR against the `" + csr.SignerName + "` signer, naming a privileged identity in the Common Name (a kube-system ServiceAccount, or a control-plane user) — the `O=system:masters` shortcut is blocked for the kube-apiserver-client signer by CertificateSubjectRestriction, but the CN is unrestricted.",
			"An approver (a permissive auto-approver, a human, or the attacker themselves if they hold the approval verbs) approves it and the signer issues the certificate.",
			"They keep the key and certificate outside the cluster. Rotating the SA token, deleting the pod, deleting the ServiceAccount, and revoking its RoleBindings all leave the certificate working until the CA is rotated.",
		},
		Remediation: "Establish whether this request is a sanctioned integration. If it is not, deny/delete it, remove the requesting ServiceAccount's ability to create CSRs, and rotate the cluster CA if a certificate was already issued.",
		RemediationSteps: append([]string{
			fmt.Sprintf("Inspect the request and its approval trail: `kubectl get csr %s -o yaml` (the `spec.request` PEM decodes with `openssl req -noout -text -in <(kubectl get csr %s -o jsonpath='{.spec.request}' | base64 -d)`, which is how you recover the claimed Subject DN).", csr.Name, csr.Name),
			fmt.Sprintf("If the claimed identity is not `%s` itself, treat this as an active escalation: identify what the claimed identity can do and rotate the CA (see below) rather than only deleting the CSR.", csr.Username),
			fmt.Sprintf("Remove `create certificatesigningrequests` from %s unless a documented integration needs it. ServiceAccounts should authenticate with projected, bound tokens; a workload that needs a certificate usually needs a *serving* certificate, which belongs to a namespaced issuer (cert-manager) and a signer whose CA is not in the apiserver's `--client-ca-file`.", csr.Username),
			"Constrain approval so a future request cannot be rubber-stamped: keep the CertificateApproval admission plugin enabled, and scope any `approve` grant on `signers` with `resourceNames` to the one signerName that identity legitimately handles.",
		}, auditSteps...),
		LearnMore: []models.Reference{
			refCSRReference,
			refX509Auth,
			refCertAdmission,
			refBoundSATokens,
			refRBACGoodPractices,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1098_001, mitreT1078_004, mitreT1550},
	}
}

// contentCSR002 — a request against the legacy-unknown signer (KUBE-CSR-002).
func contentCSR002(csr models.CSR, state string) ruleContent {
	scope := models.Scope{
		Level:  models.ScopeCluster,
		Detail: "Cluster-wide: certificates from this signer are client credentials the apiserver accepts anywhere in the cluster",
	}

	stateLine := "The request is still pending, so nothing has been issued from it yet."
	if state == "approved" {
		stateLine = "The request is APPROVED. Whether a certificate actually materialized depends on the signer: kube-controller-manager stopped signing `kubernetes.io/legacy-unknown` in 1.22, so on a modern cluster an approved request commonly sits without a certificate — but a third-party signer, or an older control plane, will have issued one. Check `status.certificate` before concluding either way."
	}

	return ruleContent{
		Title: fmt.Sprintf("CSR `%s` targets the deprecated `kubernetes.io/legacy-unknown` signer (%s)", csr.Name, state),
		Scope: scope,
		Description: fmt.Sprintf("CertificateSigningRequest `%s` (requested by `%s`) names `kubernetes.io/legacy-unknown` as its signer.\n\n"+
			"%s\n\n"+
			"This signer is worth flagging on its own because of what it is *not* guarded by. The CertificateSubjectRestriction admission plugin — the control that blocks the classic cluster-takeover certificate — only inspects CSRs whose signerName is `kubernetes.io/kube-apiserver-client`. A request routed to `legacy-unknown` is outside that check, so it may freely name `system:masters` as an Organization, which the apiserver hard-codes as cluster-admin regardless of RBAC. That makes a legacy-unknown request the standard way to attempt the very escalation the default plugin set is there to prevent.\n\n"+
			"There is also no legitimate modern use. `legacy-unknown` exists for pre-1.18 clients that predate `signerName`, its trust distribution is explicitly undefined in the Kubernetes docs, and kube-controller-manager has refused to sign it since 1.22. A request against it on a current cluster is either very old tooling or someone probing for a signer that skips the subject restriction.",
			csr.Name, csr.Username, stateLine),
		Impact: "A certificate issued by this signer bypasses the CertificateSubjectRestriction check that blocks `system:masters` claims, so it can carry an Organization that authorizes as cluster-admin. Like every Kubernetes client certificate, it cannot be revoked short of a CA rotation.",
		AttackScenario: []string{
			"Attacker holds enough of the certificates API to submit a CSR, and finds their `O=system:masters` request rejected: CertificateSubjectRestriction guards the `kubernetes.io/kube-apiserver-client` signer.",
			"They resubmit the identical request with `signerName: kubernetes.io/legacy-unknown`, which that plugin does not inspect.",
			"If any signer in the cluster still handles legacy-unknown — an older control plane, or a custom signer controller written to catch \"unknown\" signers — the certificate is issued with the `system:masters` group intact.",
			"They authenticate with it: `kubectl --client-certificate=masters.crt --client-key=masters.key get secrets -A` succeeds against every namespace, with RBAC short-circuited.",
		},
		Remediation: "Delete or deny the request, confirm no signer in the cluster handles `kubernetes.io/legacy-unknown`, and treat any certificate already issued from it as a credential that requires a CA rotation to invalidate.",
		RemediationSteps: append([]string{
			fmt.Sprintf("Decode the claimed subject before deciding anything: `kubectl get csr %s -o jsonpath='{.spec.request}' | base64 -d | openssl req -noout -text`. An Organization of `system:masters` makes this an active takeover attempt, not a hygiene issue.", csr.Name),
			fmt.Sprintf("Check whether a certificate was issued: `kubectl get csr %s -o jsonpath='{.status.certificate}'`. Empty means the request was approved but never signed.", csr.Name),
			fmt.Sprintf("Deny and remove the request: `kubectl certificate deny %s && kubectl delete csr %s`.", csr.Name, csr.Name),
			"Confirm no controller in the cluster signs this signerName (`kubectl get pods -A -l app.kubernetes.io/component=signer` and any custom CSR controller you run), and that no grant carries `sign` on `signers` with a `*/*` or `kubernetes.io/*` resourceName wildcard — that wildcard covers legacy-unknown too.",
			fmt.Sprintf("Find out who submitted it and why: the requester was `%s`. Remove its `create certificatesigningrequests` grant if the request was not sanctioned.", csr.Username),
		}, auditSteps...),
		LearnMore: []models.Reference{
			refCSRReference,
			refCertAdmission,
			refX509Auth,
			refRBACGoodPractices,
		},
		MitreTechniques: []models.MitreTechnique{mitreT1098, mitreT1098_001, mitreT1550},
	}
}
