package exclusions

import (
	"slices"
	"testing"
)

func TestPresetNoneIsEmpty(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"none", "strict"} {
		cfg, err := Preset(name)
		if err != nil {
			t.Fatalf("Preset(%q) returned error: %v", name, err)
		}
		if len(cfg.Global.ExcludeNamespaces) != 0 ||
			len(cfg.Global.ExcludeServiceAccounts) != 0 ||
			len(cfg.Global.ExcludeClusterRoles) != 0 ||
			len(cfg.Global.ExcludeSubjects) != 0 ||
			len(cfg.PodSecurity.ExcludeChecks) != 0 ||
			len(cfg.NetworkPolicy.ExcludeNamespaces) != 0 {
			t.Fatalf("Preset(%q) expected empty config, got %#v", name, cfg)
		}
	}
}

func TestPresetStandardCoversBuiltInGaps(t *testing.T) {
	t.Parallel()

	cfg, err := Preset("standard")
	if err != nil {
		t.Fatalf("Preset(standard) failed: %v", err)
	}

	if !slices.Contains(cfg.Global.ExcludeClusterRoles, "kubeadm:*") {
		t.Errorf("standard preset missing kubeadm:* in ExcludeClusterRoles: %v", cfg.Global.ExcludeClusterRoles)
	}
	if !slices.Contains(cfg.NetworkPolicy.ExcludeNamespaces, "kube-public") ||
		!slices.Contains(cfg.NetworkPolicy.ExcludeNamespaces, "kube-node-lease") {
		t.Errorf("standard preset NetworkPolicy.ExcludeNamespaces missing kube-public/kube-node-lease: %v", cfg.NetworkPolicy.ExcludeNamespaces)
	}

	wantSubjects := map[string]bool{
		"Group:system:*":  false,
		"User:system:*":   false,
		"Group:kubeadm:*": false,
		"User:kubeadm:*":  false,
	}
	for _, s := range cfg.Global.ExcludeSubjects {
		key := s.Kind + ":" + s.Name
		if _, ok := wantSubjects[key]; ok {
			wantSubjects[key] = true
		}
	}
	for key, found := range wantSubjects {
		if !found {
			t.Errorf("standard preset missing ExcludeSubjects entry %q", key)
		}
	}
}

func TestMergeCombinesPresetAndUserConfig(t *testing.T) {
	t.Parallel()

	base, err := Preset("standard")
	if err != nil {
		t.Fatalf("Preset(standard) failed: %v", err)
	}

	overlay := Config{
		Global: GlobalConfig{
			ExcludeNamespaces: []string{"my-team", "kube-system"}, // "kube-system" duplicates the preset, should dedupe
			ExcludeFindingIDs: []string{"KUBE-CUSTOM-*"},
			ExcludeSubjects: []SubjectExclusion{
				{Kind: "ServiceAccount", Namespace: "platform", Name: "controller", Reason: "platform team owns this"},
			},
		},
		PodSecurity: PodSecurityConfig{
			ExcludeWorkloads: []WorkloadExclusion{
				{Kind: "Deployment", Namespace: "monitoring", Name: "prometheus", Reason: "monitoring exception"},
			},
		},
	}

	merged := Merge(base, overlay)

	if !slices.Contains(merged.Global.ExcludeNamespaces, "my-team") {
		t.Errorf("merged config missing user namespace 'my-team': %v", merged.Global.ExcludeNamespaces)
	}
	// Dedup: kube-system appears once even though both sources contain it.
	count := 0
	for _, ns := range merged.Global.ExcludeNamespaces {
		if ns == "kube-system" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("merged config should dedupe kube-system, got %d occurrences: %v", count, merged.Global.ExcludeNamespaces)
	}

	if !slices.Contains(merged.Global.ExcludeFindingIDs, "KUBE-CUSTOM-*") {
		t.Errorf("merged config missing user finding-ID pattern: %v", merged.Global.ExcludeFindingIDs)
	}

	// Preset subject entries come first; the user's subject entry is appended.
	if len(merged.Global.ExcludeSubjects) != len(base.Global.ExcludeSubjects)+1 {
		t.Fatalf("expected %d ExcludeSubjects entries, got %d", len(base.Global.ExcludeSubjects)+1, len(merged.Global.ExcludeSubjects))
	}
	last := merged.Global.ExcludeSubjects[len(merged.Global.ExcludeSubjects)-1]
	if last.Name != "controller" || last.Namespace != "platform" {
		t.Errorf("user-supplied subject not appended last: %#v", last)
	}

	if len(merged.PodSecurity.ExcludeWorkloads) != 1 || merged.PodSecurity.ExcludeWorkloads[0].Name != "prometheus" {
		t.Errorf("user workload exclusion not preserved: %#v", merged.PodSecurity.ExcludeWorkloads)
	}

	// Preset's check exclusion should still be present.
	foundHostNetwork := false
	for _, c := range merged.PodSecurity.ExcludeChecks {
		if c.Check == "hostNetwork" {
			foundHostNetwork = true
		}
	}
	if !foundHostNetwork {
		t.Errorf("preset hostNetwork check exclusion lost in merge: %#v", merged.PodSecurity.ExcludeChecks)
	}
}
