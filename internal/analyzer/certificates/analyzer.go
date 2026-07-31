// Package certificates analyzes CertificateSigningRequest objects: the evidence
// side of the certificates API, as opposed to the RBAC grants that make it
// abusable (those are KUBE-PRIVESC-011 / -024 in the rbac module).
//
// The distinction matters because the two answer different questions. The rbac
// rules say "this subject could mint a client certificate"; these rules say "a
// client certificate was actually requested, and here is who asked". An issued
// Kubernetes client cert cannot be revoked — there is no CRL or OCSP — so the
// evidence that one exists is more urgent than the permission that produced it.
//
// Two honest limits are baked into the copy these rules emit:
//
//   - The collector deliberately drops the raw `spec.request` PEM (see
//     sanitizeCSR), so we know who submitted a CSR and to which signer, but not
//     which identity the Subject DN claimed. A finding here says "a client
//     certificate was requested by X", never "X forged identity Y".
//   - The kube-controller-manager's CSR cleaner deletes issued CSRs about an hour
//     after issuance, and denied/failed ones on a similar timer. An empty CSR list
//     is therefore not evidence that nothing was minted, only that nothing was
//     minted recently. Both rules say so in their remediation steps.
package certificates

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// Analyzer produces CertificateSigningRequest-focused findings from a snapshot.
type Analyzer struct{}

// New returns a new certificates analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "certificates"
}

// serviceAccountUserPrefix is how the apiserver names a ServiceAccount as a
// request author: `system:serviceaccount:<namespace>:<name>`. It is also exactly
// the string an attacker puts in a certificate's Common Name to become that SA,
// which is why a ServiceAccount showing up on both sides of the certificates API
// is worth a finding.
const serviceAccountUserPrefix = "system:serviceaccount:"

// Analyze flags CertificateSigningRequests that represent identity issuance a
// cluster operator would not have asked for: a workload ServiceAccount requesting
// a client certificate, and any request against the subject-unrestricted
// `kubernetes.io/legacy-unknown` signer.
//
// Denied requests are skipped everywhere: the apiserver refused to issue, so the
// object is a record of a blocked attempt rather than a live credential. It is
// still visible in the snapshot for anyone auditing by hand.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, csr := range snapshot.Resources.CertificateSigningRequests {
		if denied(csr) {
			continue
		}

		// KUBE-CSR-001 — a ServiceAccount asked for a client certificate.
		//
		// Restricting to ServiceAccount requesters is what keeps this rule quiet on
		// real clusters. Human admins onboarding users via certs, and the node
		// bootstrap flow (requester `system:bootstrap:<id>` / `system:node:<name>`,
		// signer kube-apiserver-client-kubelet), are both routine and both excluded
		// by construction. A workload identity asking for a second, cert-shaped
		// credential is not routine: the token it already holds is bound, expiring
		// and revocable, and a certificate is none of those things.
		if isServiceAccountUser(csr.Username) && clientAuthSigner(csr.SignerName) {
			severity, score := models.SeverityMedium, 5.6
			state := "pending"
			if csr.Approved {
				severity, score = models.SeverityHigh, 8.2
				state = "approved"
			}
			findings = appendUnique(findings, seen, csrFinding(csr,
				"KUBE-CSR-001", severity, score,
				map[string]any{
					"signer_name": csr.SignerName,
					"requester":   csr.Username,
					"usages":      csr.Usages,
					"approved":    csr.Approved,
					"state":       state,
				},
				"serviceAccountClientCert",
				subjectFromUsername(csr.Username),
				contentCSR001(csr, state)))
		}

		// KUBE-CSR-002 — a request against the legacy-unknown signer.
		//
		// Requester-agnostic on purpose: this rule is about the signer, not the
		// author. `kubernetes.io/legacy-unknown` is the one client-auth signer
		// CertificateSubjectRestriction does not guard, so it is where a
		// system:masters Organization can still be requested.
		if csr.SignerName == permissions.SignerLegacyUnknown {
			severity, score := models.SeverityMedium, 5.0
			state := "pending"
			if csr.Approved {
				severity, score = models.SeverityHigh, 7.5
				state = "approved"
			}
			findings = appendUnique(findings, seen, csrFinding(csr,
				"KUBE-CSR-002", severity, score,
				map[string]any{
					"signer_name": csr.SignerName,
					"requester":   csr.Username,
					"usages":      csr.Usages,
					"approved":    csr.Approved,
					"state":       state,
				},
				"legacyUnknownSigner",
				subjectFromUsername(csr.Username),
				contentCSR002(csr, state)))
		}
	}

	return findings, nil
}

// denied reports whether the CSR carries a Denied or Failed condition. Either way
// no certificate was issued from it.
func denied(csr models.CSR) bool {
	for _, condition := range csr.Conditions {
		if condition.Type == "Denied" || condition.Type == "Failed" {
			if condition.Status == "" || condition.Status == "True" {
				return true
			}
		}
	}
	return false
}

// clientAuthSigner reports whether certificates from this signer authenticate to
// the kube-apiserver as a client. Serving signers (kubelet-serving) and
// third-party signers are out of scope: their certs are not client credentials
// against the apiserver, so a request for one is not identity issuance.
func clientAuthSigner(signerName string) bool {
	for _, signer := range permissions.ClientAuthSigners {
		if signerName == signer {
			return true
		}
	}
	return false
}

// isServiceAccountUser reports whether an apiserver username names a ServiceAccount.
func isServiceAccountUser(username string) bool {
	return strings.HasPrefix(username, serviceAccountUserPrefix) &&
		len(strings.Split(strings.TrimPrefix(username, serviceAccountUserPrefix), ":")) == 2
}

// subjectFromUsername converts `system:serviceaccount:<ns>:<name>` into a SubjectRef so
// the finding is attributed to the identity that asked, not just to the CSR object: the
// report groups it with that ServiceAccount's other findings, and subject-shaped filters
// and exclusions can reach it. Returns nil for any other username shape — Users and
// Groups have no inventory in a snapshot to point at.
//
// This does NOT feed chain amplification, deliberately. The engine's correlate pass bumps
// a finding only when its own (Subject, RuleID) matches a chain hop's (from-subject,
// technique), i.e. only the finding that IS the edge. A CSR object is evidence that an
// edge was used, not the edge, so it keeps its own score.
func subjectFromUsername(username string) *models.SubjectRef {
	if !isServiceAccountUser(username) {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(username, serviceAccountUserPrefix), ":")
	return &models.SubjectRef{Kind: "ServiceAccount", Namespace: parts[0], Name: parts[1]}
}

// csrFinding materializes a CSR-scoped finding from a ruleContent. CSRs are
// cluster-scoped, so the ID's namespace field is empty and Namespace stays unset;
// the ID keeps the three-part `RULE:namespace:name` shape the rest of the codebase
// uses so prefix matching in exclusions and corpus deny lists behaves the same.
func csrFinding(csr models.CSR, ruleID string, severity models.Severity, score float64, evidence map[string]any, check string, subject *models.SubjectRef, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:          fmt.Sprintf("%s::%s", ruleID, csr.Name),
		RuleID:      ruleID,
		Severity:    severity,
		Score:       scoring.Clamp(score),
		Category:    models.CategoryPrivilegeEscalation,
		Title:       content.Title,
		Description: content.Description,
		Subject:     subject,
		Resource: &models.ResourceRef{
			Kind:     "CertificateSigningRequest",
			Name:     csr.Name,
			APIGroup: "certificates.k8s.io",
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:certificates", "check:" + check},
	}
}

// appendUnique deduplicates by Finding.ID before appending.
func appendUnique(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}
