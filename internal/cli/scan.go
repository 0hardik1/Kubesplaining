package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0hardik1/kubesplaining/internal/analyzer"
	"github.com/0hardik1/kubesplaining/internal/analyzer/leastprivilege"
	"github.com/0hardik1/kubesplaining/internal/baseline"
	"github.com/0hardik1/kubesplaining/internal/collector"
	"github.com/0hardik1/kubesplaining/internal/connection"
	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/report"
	"github.com/0hardik1/kubesplaining/internal/usage"
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
		maxFindings          int
		allFindings          bool
		auditLogPaths        []string
		auditSource          string
		auditWindowDays      int
		leastPrivilegeOnly   bool
		complianceFilters    []string
		customRulesDir       string
		baselineFile         string
		baselineFormat       string
		remediationPatches   bool
		cloudProvider        string
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

			source, ok := usage.ParseSource(auditSource)
			if !ok {
				return fmt.Errorf("invalid --audit-source %q (must be native or eks)", auditSource)
			}
			if auditWindowDays < 1 {
				return fmt.Errorf("invalid --audit-window-days %d (must be >= 1)", auditWindowDays)
			}

			// Pre-flight: --least-privilege-only without --audit-log would produce a
			// near-empty tab (only STALE findings, no UNUSED-* signal). Surface the
			// missing input explicitly so the operator knows to point us at an audit log.
			if leastPrivilegeOnly && len(auditLogPaths) == 0 {
				return fmt.Errorf("--least-privilege-only requires --audit-log <path>; see docs/audit-logs.md for how to obtain one")
			}

			// --least-privilege-only is a "focus mode" shortcut. It overrides --only-modules
			// to the modules that produce least-privilege findings (rbac for STALE rules +
			// leastprivilege for the UNUSED/WILDCARD rules), then applies a rule-ID
			// post-filter so other rbac findings (privesc-related, OVERBROAD) don't leak
			// through — the LP tab's dedicated cluster-admin inventory table covers the
			// "who has cluster-admin" picture. The HTML report's default tab is also
			// flipped to "leastprivilege" so the focus mode lands the operator there.
			if leastPrivilegeOnly {
				onlyModules = []string{"rbac", "leastprivilege"}
			}

			snapshot, err := loadOrCollectSnapshot(cmd, build, connFlags, inputFile, namespaces, excludeNamespaces, includeManagedFields, parallelism)
			if err != nil {
				return err
			}

			// --cloud-provider overrides the collector / manifest auto-detection.
			// "auto" keeps whatever was detected; "none" forces detectors off; the
			// concrete provider names pin detection so an operator can opt in even
			// when the snapshot lacks the usual heuristic signals (e.g. an EKS
			// cluster without aws-auth in kube-system).
			switch cloudProvider {
			case "auto":
				// keep whatever the collector / manifest loader populated
			case "none":
				snapshot.Metadata.CloudProvider = "none"
			case "eks", "gke", "aks":
				snapshot.Metadata.CloudProvider = cloudProvider
			default:
				return fmt.Errorf("invalid --cloud-provider %q (must be auto, eks, gke, aks, or none)", cloudProvider)
			}

			usageIdx, usageWarnings, err := usage.LoadAuditLog(
				auditLogPaths,
				source,
				time.Duration(auditWindowDays)*24*time.Hour,
				time.Now().UTC(),
			)
			if err != nil {
				return fmt.Errorf("load audit log: %w", err)
			}
			snapshot.Metadata.CollectionWarnings = append(snapshot.Metadata.CollectionWarnings, usageWarnings...)

			engine := analyzer.NewWithConfig(analyzer.Config{
				MaxPrivescDepth: maxPrivescDepth,
				CustomRulesDir:  customRulesDir,
			})
			result, err := engine.Analyze(cmd.Context(), snapshot, analyzer.Options{
				OnlyModules:        onlyModules,
				SkipModules:        skipModules,
				Threshold:          threshold,
				AdmissionMode:      mode,
				UsageIndex:         usageIdx,
				RemediationPatches: remediationPatches,
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

			// Apply the rule-ID prefix filter for --least-privilege-only. We do this
			// after exclusions so user-supplied exclusions still apply normally; before
			// truncation so the diversity sampler operates over the focused set.
			if leastPrivilegeOnly {
				findings = filterLeastPrivilege(findings)
			}

			complianceSlugs, err := parseComplianceFilter(complianceFilters)
			if err != nil {
				return err
			}
			findings = applyComplianceFilter(findings, complianceSlugs)

			findings, truncation := report.Truncate(findings, maxFindings, allFindings)

			if outputDir == "" {
				outputDir = filepath.Join(".", "kubesplaining-report")
			}

			reportOpts := report.Options{
				DefaultTab:         defaultTabFor(leastPrivilegeOnly),
				LeastPrivilegeOnly: leastPrivilegeOnly,
				UsageInfo:          report.UsageInfoFrom(usageIdx),
				MaxPrivescDepth:    maxPrivescDepth,
			}

			written, err := report.WriteWithOptions(outputDir, outputFormats, snapshot, findings, result.Admission, truncation, reportOpts)
			if err != nil {
				return err
			}

			summary := report.BuildSummary(findings)
			if err := printScanResults(cmd.OutOrStdout(), written, summary); err != nil {
				return err
			}
			printTruncationNotice(cmd.ErrOrStderr(), truncation)

			// Baseline diff: when --baseline is set we always render and write
			// the delta report alongside the main report so a reviewer can read
			// "what changed since the last run" without invoking `kubesplaining diff`
			// separately. In CI mode the diff also retargets the ci-max gates so
			// they count Added findings only, not the absolute new-scan tally.
			var diffResult *baseline.Result
			if baselineFile != "" {
				format, err := parseDiffFormat(baselineFormat)
				if err != nil {
					return err
				}
				oldFindings, err := baseline.LoadFindings(baselineFile)
				if err != nil {
					return fmt.Errorf("load baseline %s: %w", baselineFile, err)
				}
				r := baseline.Diff(oldFindings, findings)
				diffResult = &r

				diffPath, err := writeDiff(outputDir, format, r)
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (diff vs baseline: %s)\n", diffPath, diffHeadline(r)); err != nil {
					return err
				}
			}

			if ciMode {
				// When a baseline is in play, the gate counts Added findings only:
				// resolved findings cannot trip CI, and unchanged findings have
				// already been accepted by a previous build. Without a baseline,
				// the gate keeps its original full-scan semantics.
				gateLabel := "ci threshold exceeded"
				crit, high := summary.Critical, summary.High
				if diffResult != nil {
					addedSummary := baseline.SummarizeSeverities(diffResult.Added)
					crit, high = addedSummary.Critical, addedSummary.High
					gateLabel = "ci threshold exceeded (delta vs baseline)"
				}

				if crit > ciMaxCritical {
					if diffResult != nil {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
							":fire: regression: %d new critical findings vs baseline (max %d). Run `kubesplaining diff` for the per-finding breakdown.\n",
							crit, ciMaxCritical)
					}
					return fmt.Errorf("%s: critical findings %d > %d", gateLabel, crit, ciMaxCritical)
				}
				if high > ciMaxHigh {
					if diffResult != nil {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
							":fire: regression: %d new high findings vs baseline (max %d). Run `kubesplaining diff` for the per-finding breakdown.\n",
							high, ciMaxHigh)
					}
					return fmt.Errorf("%s: high findings %d > %d", gateLabel, high, ciMaxHigh)
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
	cmd.Flags().IntVar(&maxFindings, "max-findings", 20, "Cap the report to the top N findings by severity/score; 0 disables. CI thresholds evaluate against the truncated list — pass --all-findings in CI mode to evaluate all.")
	cmd.Flags().BoolVar(&allFindings, "all-findings", false, "Include every finding in the report; overrides --max-findings")
	cmd.Flags().StringSliceVar(&auditLogPaths, "audit-log", nil, "Path to a kube-apiserver audit log file or directory (repeatable). See docs/audit-logs.md for how to obtain one.")
	cmd.Flags().StringVar(&auditSource, "audit-source", "native", "Audit-log format: native (kube-apiserver JSON-lines) or eks (CloudWatch export from filter-log-events)")
	cmd.Flags().IntVar(&auditWindowDays, "audit-window-days", 30, "How many days of audit history to consider when computing unused-permission findings")
	cmd.Flags().BoolVar(&leastPrivilegeOnly, "least-privilege-only", false, "Focus mode: only emit least-privilege findings (UNUSED-*, WILDCARD-USED-PARTIAL-*, STALE-*) and open the Least Privilege tab by default. Requires --audit-log. Cluster-admin bindings are listed for review in the LP tab's inventory table instead of firing as findings.")
	cmd.Flags().StringSliceVar(&complianceFilters, "compliance", nil, "Filter findings to those mapped to one or more frameworks (repeatable / comma-separated). Supported: cis, nsa. Empty = no filter; the Compliance tab still renders all controls.")
	cmd.Flags().StringVar(&customRulesDir, "custom-rules", "", "Directory of user-supplied *.cel.yaml rules to evaluate alongside the built-in modules. See examples/custom-rules/ for the wire format.")
	cmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to a previous findings JSON file. When set, a diff.{txt,md,sarif} is written alongside the report and (in --ci-mode) ci-max-* gates count Added findings only, not the absolute scan tally.")
	cmd.Flags().StringVar(&baselineFormat, "baseline-format", "text", "Format for the baseline diff sidecar: text|markdown|sarif")
	cmd.Flags().BoolVar(&remediationPatches, "remediation-patches", false, "Attach structured remediation hints (kubectl patch, Kyverno / Gatekeeper policy, RBAC diff) to every finding. Adds to JSON/SARIF output and the 'Structured remediation' section in HTML. Off by default.")
	cmd.Flags().StringVar(&cloudProvider, "cloud-provider", "auto", "Cloud provider hint for cloud-aware detectors: auto|eks|gke|aks|none. 'auto' keeps the collector / manifest-loader auto-detection; the concrete names override it; 'none' forces detectors off.")

	return cmd
}

// filterLeastPrivilege keeps only rule-IDs that surface in the Least Privilege tab.
// Used when --least-privilege-only is set so the operator's report does not include
// privesc/podsec/network findings they are not focused on right now.
func filterLeastPrivilege(findings []models.Finding) []models.Finding {
	out := findings[:0]
	for _, f := range findings {
		if leastprivilege.IsLeastPrivilegeRule(f.RuleID) {
			out = append(out, f)
		}
	}
	return out
}

// defaultTabFor returns the HTML report's initial-active tab name. --least-privilege-only
// lands the operator on the Least Privilege tab directly; otherwise the report keeps its
// existing default (Attack Paths) by returning "".
func defaultTabFor(leastPrivilegeOnly bool) string {
	if leastPrivilegeOnly {
		return "leastprivilege"
	}
	return ""
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

	dyn, err := connection.NewDynamicClient(config)
	if err != nil {
		return models.Snapshot{}, err
	}

	c := collector.New(clientset, dyn, config, collector.Options{
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
