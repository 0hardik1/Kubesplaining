package cli

import "github.com/0hardik1/kubesplaining/internal/exclusions"

// loadExclusions resolves the active exclusions config for a scan/report command. The chosen preset
// (default "standard") supplies the built-in noise filter — kube-system, system:*, kubeadm:*, etc. —
// and is auto-applied even when the user does not pass --exclusions-file. When a user file is supplied,
// it is merged on top of the preset (preset rules first, user rules appended), so users layer custom
// suppressions without losing the defaults. Use --exclusions-preset=none to opt out entirely.
func loadExclusions(preset, userFile string) (exclusions.Config, error) {
	cfg, err := exclusions.Preset(preset)
	if err != nil {
		return exclusions.Config{}, err
	}
	if userFile == "" {
		return cfg, nil
	}
	user, err := exclusions.Load(userFile)
	if err != nil {
		return exclusions.Config{}, err
	}
	return exclusions.Merge(cfg, user), nil
}
