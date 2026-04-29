// Package exclusions loads YAML rules that mute specific findings (system namespaces, expected workloads, etc.)
// and applies them to analyzer output. The standard preset is auto-applied by the scan/scan-resource/report
// commands so built-in Kubernetes noise (kube-system, system:*, kubeadm:*) is suppressed by default; the user
// can opt out with --exclusions-preset=none. Apply drops matched findings from the slice (the Excluded field
// on Finding is reserved for future audit-mode rendering, not used today).
package exclusions

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hardik/kubesplaining/internal/collector"
	"gopkg.in/yaml.v3"
)

// Config is the top-level exclusions document, split by module for readability.
type Config struct {
	Global        GlobalConfig        `yaml:"global"`
	RBAC          RBACConfig          `yaml:"rbac"`
	PodSecurity   PodSecurityConfig   `yaml:"pod_security"`
	NetworkPolicy NetworkPolicyConfig `yaml:"network_policy"`
}

// GlobalConfig holds exclusions that apply across all modules (namespaces, specific subjects, specific rule IDs).
type GlobalConfig struct {
	ExcludeNamespaces      []string           `yaml:"exclude_namespaces,omitempty"`
	ExcludeServiceAccounts []string           `yaml:"exclude_service_accounts,omitempty"` // "ns:name" patterns, wildcards allowed
	ExcludeClusterRoles    []string           `yaml:"exclude_cluster_roles,omitempty"`
	ExcludeFindingIDs      []string           `yaml:"exclude_finding_ids,omitempty"`
	ExcludeSubjects        []SubjectExclusion `yaml:"exclude_subjects,omitempty"` // matches Subject Kind/Name/Namespace patterns regardless of module
}

// RBACConfig scopes subject-level RBAC exclusions.
type RBACConfig struct {
	ExcludeSubjects []SubjectExclusion `yaml:"exclude_subjects,omitempty"`
}

// SubjectExclusion silences findings whose Subject matches all set fields; Reason is surfaced in ExclusionReason.
type SubjectExclusion struct {
	Kind      string `yaml:"kind,omitempty"`
	Name      string `yaml:"name,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	Reason    string `yaml:"reason,omitempty"`
}

// PodSecurityConfig scopes workload-identity and per-check exclusions for the podsec module.
type PodSecurityConfig struct {
	ExcludeWorkloads []WorkloadExclusion `yaml:"exclude_workloads,omitempty"`
	ExcludeChecks    []CheckExclusion    `yaml:"exclude_checks,omitempty"`
}

// WorkloadExclusion silences findings about a specific workload; NamePattern supports shell-style globs.
type WorkloadExclusion struct {
	Kind        string `yaml:"kind,omitempty"`
	Name        string `yaml:"name,omitempty"`
	NamePattern string `yaml:"name_pattern,omitempty"`
	Namespace   string `yaml:"namespace,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
}

// CheckExclusion silences a specific podsec check (matched via a "check:<name>" tag), optionally scoped to a namespace.
type CheckExclusion struct {
	Check     string `yaml:"check,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	Reason    string `yaml:"reason,omitempty"`
}

// NetworkPolicyConfig scopes namespace-wide exclusions for the network module.
type NetworkPolicyConfig struct {
	ExcludeNamespaces []string `yaml:"exclude_namespaces,omitempty"`
}

// Load reads and parses an exclusions YAML file from disk.
func Load(path string) (Config, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read exclusions file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(bytes, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse exclusions file: %w", err)
	}

	return cfg, nil
}

// Write serializes cfg to YAML and writes it to path, creating the parent directory if needed.
func Write(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create exclusions directory: %w", err)
	}

	bytes, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal exclusions file: %w", err)
	}

	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		return fmt.Errorf("write exclusions file: %w", err)
	}

	return nil
}

// Preset returns one of the built-in exclusion profiles. "standard" (default) suppresses built-in
// Kubernetes noise — kube-system / system:* / kubeadm:* — and is auto-applied by scan/scan-resource/report
// unless the user passes --exclusions-preset=none (or its alias "strict") to opt out. "minimal" only filters
// the most obvious system noise; "none" / "strict" return an empty config so every finding surfaces.
func Preset(name string) (Config, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "standard":
		return Config{
			Global: GlobalConfig{
				ExcludeNamespaces:      []string{"kube-system", "kube-public", "kube-node-lease", "gatekeeper-system"},
				ExcludeServiceAccounts: []string{"system:*", "kube-system:*"},
				ExcludeClusterRoles:    []string{"system:*", "kubeadm:*"},
				ExcludeSubjects: []SubjectExclusion{
					{Kind: "Group", Name: "system:*", Reason: "Built-in Kubernetes group"},
					{Kind: "User", Name: "system:*", Reason: "Built-in Kubernetes user"},
					{Kind: "Group", Name: "kubeadm:*", Reason: "Built-in kubeadm group"},
					{Kind: "User", Name: "kubeadm:*", Reason: "Built-in kubeadm user"},
				},
			},
			PodSecurity: PodSecurityConfig{
				ExcludeChecks: []CheckExclusion{
					{Check: "hostNetwork", Namespace: "kube-system", Reason: "System networking components commonly require host networking"},
				},
			},
			NetworkPolicy: NetworkPolicyConfig{
				ExcludeNamespaces: []string{"kube-system", "kube-public", "kube-node-lease"},
			},
		}, nil
	case "minimal":
		return Config{
			Global: GlobalConfig{
				ExcludeNamespaces:      []string{"kube-public", "kube-node-lease"},
				ExcludeServiceAccounts: []string{"system:*"},
				ExcludeClusterRoles:    []string{"system:*"},
			},
		}, nil
	case "strict", "none":
		return Config{}, nil
	default:
		return Config{}, fmt.Errorf("unsupported exclusions preset %q", name)
	}
}

// Merge returns the union of base and overlay: each slice field is concatenated with base entries first,
// and string-slice fields are deduplicated by exact match. Struct slices (subject/workload/check exclusions)
// are concatenated as-is — duplicates are harmless because the matcher returns on first match. Used to layer
// a user-supplied --exclusions-file on top of the built-in --exclusions-preset.
func Merge(base, overlay Config) Config {
	return Config{
		Global: GlobalConfig{
			ExcludeNamespaces:      mergeStrings(base.Global.ExcludeNamespaces, overlay.Global.ExcludeNamespaces),
			ExcludeServiceAccounts: mergeStrings(base.Global.ExcludeServiceAccounts, overlay.Global.ExcludeServiceAccounts),
			ExcludeClusterRoles:    mergeStrings(base.Global.ExcludeClusterRoles, overlay.Global.ExcludeClusterRoles),
			ExcludeFindingIDs:      mergeStrings(base.Global.ExcludeFindingIDs, overlay.Global.ExcludeFindingIDs),
			ExcludeSubjects:        append(append([]SubjectExclusion{}, base.Global.ExcludeSubjects...), overlay.Global.ExcludeSubjects...),
		},
		RBAC: RBACConfig{
			ExcludeSubjects: append(append([]SubjectExclusion{}, base.RBAC.ExcludeSubjects...), overlay.RBAC.ExcludeSubjects...),
		},
		PodSecurity: PodSecurityConfig{
			ExcludeWorkloads: append(append([]WorkloadExclusion{}, base.PodSecurity.ExcludeWorkloads...), overlay.PodSecurity.ExcludeWorkloads...),
			ExcludeChecks:    append(append([]CheckExclusion{}, base.PodSecurity.ExcludeChecks...), overlay.PodSecurity.ExcludeChecks...),
		},
		NetworkPolicy: NetworkPolicyConfig{
			ExcludeNamespaces: mergeStrings(base.NetworkPolicy.ExcludeNamespaces, overlay.NetworkPolicy.ExcludeNamespaces),
		},
	}
}

// mergeStrings concatenates base and overlay, preserving order and dropping exact-match duplicates.
func mergeStrings(base, overlay []string) []string {
	out := make([]string, 0, len(base)+len(overlay))
	seen := make(map[string]struct{}, len(base)+len(overlay))
	for _, src := range [][]string{base, overlay} {
		for _, s := range src {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// EnrichFromSnapshot reads a snapshot and auto-adds any kube-*/-system namespaces to ExcludeNamespaces so a preset can adapt to the target cluster.
func EnrichFromSnapshot(cfg Config, snapshotPath string) (Config, error) {
	if snapshotPath == "" {
		return cfg, nil
	}

	snapshot, err := collector.ReadSnapshot(snapshotPath)
	if err != nil {
		return Config{}, err
	}

	for _, ns := range snapshot.Resources.Namespaces {
		if strings.HasPrefix(ns.Name, "kube-") || strings.HasSuffix(ns.Name, "-system") {
			if !slices.Contains(cfg.Global.ExcludeNamespaces, ns.Name) {
				cfg.Global.ExcludeNamespaces = append(cfg.Global.ExcludeNamespaces, ns.Name)
			}
		}
	}

	return cfg, nil
}
