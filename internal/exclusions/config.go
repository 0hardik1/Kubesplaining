// Package exclusions loads user-supplied YAML rules that mute specific findings (system namespaces, expected
// workloads, etc.) and applies them to analyzer output. A Finding is never dropped; it is annotated with
// Excluded=true and an ExclusionReason so the report can still show suppressed items.
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
	ExcludeNamespaces      []string `yaml:"exclude_namespaces,omitempty"`
	ExcludeServiceAccounts []string `yaml:"exclude_service_accounts,omitempty"` // "ns:name" patterns, wildcards allowed
	ExcludeClusterRoles    []string `yaml:"exclude_cluster_roles,omitempty"`
	ExcludeFindingIDs      []string `yaml:"exclude_finding_ids,omitempty"`
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

// Preset returns one of the built-in exclusion profiles: "standard" (default), "minimal", or "strict" (no exclusions).
func Preset(name string) (Config, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "standard":
		return Config{
			Global: GlobalConfig{
				ExcludeNamespaces:      []string{"kube-system", "kube-public", "kube-node-lease", "gatekeeper-system"},
				ExcludeServiceAccounts: []string{"system:*", "kube-system:*"},
				ExcludeClusterRoles:    []string{"system:*"},
			},
			PodSecurity: PodSecurityConfig{
				ExcludeChecks: []CheckExclusion{
					{Check: "hostNetwork", Namespace: "kube-system", Reason: "System networking components commonly require host networking"},
				},
			},
			NetworkPolicy: NetworkPolicyConfig{
				ExcludeNamespaces: []string{"kube-system"},
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
	case "strict":
		return Config{}, nil
	default:
		return Config{}, fmt.Errorf("unsupported exclusions preset %q", name)
	}
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
