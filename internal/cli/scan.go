package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/0hardik1/kubesplaining/internal/analyzer"
	"github.com/0hardik1/kubesplaining/internal/collector"
	"github.com/0hardik1/kubesplaining/internal/connection"
	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/report"
	"github.com/spf13/cobra"
)

// NewScanCmd returns the "scan" subcommand, which runs the full analyzer pipeline
// against either a live cluster or a previously collected snapshot and emits reports.
func NewScanCmd(build BuildInfo) *cobra.Command {
	var (
		connFlags            connectionFlags
		inputFile            string
		outputDir            string
		outputFormats        []string
		severityThreshold    string
		exclusionsFile       string
		exclusionsPreset     string
		namespaces           []string
		excludeNamespaces    []string
		includeManagedFields bool
		parallelism          int
		onlyModules          []string
		skipModules          []string
		ciMode               bool
		ciMaxCritical        int
		ciMaxHigh            int
		maxPrivescDepth      int
		admissionMode        string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Analyze a cluster snapshot or a live cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := models.ParseSeverity(severityThreshold)
			if err != nil {
				return err
			}

			mode, ok := analyzer.ParseAdmissionMode(admissionMode)
			if !ok {
				return fmt.Errorf("invalid --admission-mode %q (must be off, attenuate, or suppress)", admissionMode)
			}

			snapshot, err := loadOrCollectSnapshot(cmd, build, connFlags, inputFile, namespaces, excludeNamespaces, includeManagedFields, parallelism)
			if err != nil {
				return err
			}

			engine := analyzer.NewWithConfig(analyzer.Config{MaxPrivescDepth: maxPrivescDepth})
			result, err := engine.Analyze(cmd.Context(), snapshot, analyzer.Options{
				OnlyModules:   onlyModules,
				SkipModules:   skipModules,
				Threshold:     threshold,
				AdmissionMode: mode,
			})
			if err != nil {
				return err
			}
			findings := result.Findings

			cfg, err := loadExclusions(exclusionsPreset, exclusionsFile)
			if err != nil {
				return err
			}
			findings, _ = exclusions.Apply(cfg, findings)

			if outputDir == "" {
				outputDir = filepath.Join(".", "kubesplaining-report")
			}

			written, err := report.WriteWithAdmission(outputDir, outputFormats, snapshot, findings, result.Admission)
			if err != nil {
				return err
			}

			summary := report.BuildSummary(findings)
			if err := printScanResults(cmd.OutOrStdout(), written, summary); err != nil {
				return err
			}

			if ciMode {
				if summary.Critical > ciMaxCritical {
					return fmt.Errorf("ci threshold exceeded: critical findings %d > %d", summary.Critical, ciMaxCritical)
				}
				if summary.High > ciMaxHigh {
					return fmt.Errorf("ci threshold exceeded: high findings %d > %d", summary.High, ciMaxHigh)
				}
			}

			return nil
		},
	}

	bindConnectionFlags(cmd, &connFlags)
	cmd.Flags().StringVar(&inputFile, "input-file", "", "Path to a snapshot JSON file")
	cmd.Flags().StringVar(&outputDir, "output-dir", filepath.Join(".", "kubesplaining-report"), "Directory for report output")
	cmd.Flags().StringSliceVar(&outputFormats, "output-format", []string{"html", "json"}, "Output formats: html,json,csv,sarif")
	cmd.Flags().StringVar(&severityThreshold, "severity-threshold", "low", "Minimum severity to include: critical,high,medium,low,info")
	cmd.Flags().StringVar(&exclusionsFile, "exclusions-file", "", "Path to a user-supplied exclusions YAML file (merged on top of --exclusions-preset)")
	cmd.Flags().StringVar(&exclusionsPreset, "exclusions-preset", "standard", "Built-in exclusions preset: standard|minimal|strict|none")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to include during live collection")
	cmd.Flags().StringSliceVar(&excludeNamespaces, "exclude-namespaces", nil, "Namespaces to exclude during live collection")
	cmd.Flags().BoolVar(&includeManagedFields, "include-managed-fields", false, "Include managedFields in live-collected resources")
	cmd.Flags().IntVar(&parallelism, "parallelism", 10, "Maximum parallel API requests for live scans")
	cmd.Flags().StringSliceVar(&onlyModules, "only-modules", nil, "Run only specific modules")
	cmd.Flags().StringSliceVar(&skipModules, "skip-modules", nil, "Skip specific modules")
	cmd.Flags().BoolVar(&ciMode, "ci-mode", false, "Exit non-zero when thresholds are exceeded")
	cmd.Flags().IntVar(&ciMaxCritical, "ci-max-critical", 0, "Maximum critical findings allowed in CI mode")
	cmd.Flags().IntVar(&ciMaxHigh, "ci-max-high", 0, "Maximum high findings allowed in CI mode")
	cmd.Flags().IntVar(&maxPrivescDepth, "max-privesc-depth", 5, "Maximum depth for privilege escalation path search")
	cmd.Flags().StringVar(&admissionMode, "admission-mode", string(analyzer.AdmissionModeSuppress), "How to react to namespace PSA labels: off|attenuate|suppress")

	return cmd
}

// loadOrCollectSnapshot returns a snapshot loaded from inputFile when set, or freshly collected from the live cluster otherwise.
func loadOrCollectSnapshot(
	cmd *cobra.Command,
	build BuildInfo,
	connFlags connectionFlags,
	inputFile string,
	namespaces []string,
	excludeNamespaces []string,
	includeManagedFields bool,
	parallelism int,
) (models.Snapshot, error) {
	if inputFile != "" {
		return collector.ReadSnapshot(inputFile)
	}

	clientset, config, err := connection.NewClientset(connFlags.toOptions())
	if err != nil {
		return models.Snapshot{}, err
	}

	c := collector.New(clientset, config, collector.Options{
		Namespaces:           namespaces,
		ExcludeNamespaces:    excludeNamespaces,
		IncludeManagedFields: includeManagedFields,
		Parallelism:          parallelism,
		BuildVersion:         build.Version,
	})

	snapshot, err := c.Collect(cmd.Context())
	if err != nil {
		return models.Snapshot{}, err
	}

	if snapshot.Metadata.ClusterName == "" {
		if host, err := os.Hostname(); err == nil {
			snapshot.Metadata.ClusterName = host
		}
	}

	return snapshot, nil
}
