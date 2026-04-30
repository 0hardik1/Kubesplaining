package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/0hardik1/kubesplaining/internal/analyzer"
	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/manifest"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/spf13/cobra"
)

// NewScanResourceCmd returns the "scan-resource" subcommand, which analyzes a
// single Kubernetes manifest file offline without requiring cluster access.
func NewScanResourceCmd() *cobra.Command {
	var (
		inputFile        string
		resourceType     string
		exclusionsFile   string
		exclusionsPreset string
		outputFormats    []string
	)

	cmd := &cobra.Command{
		Use:   "scan-resource",
		Short: "Analyze a Kubernetes manifest file without cluster access",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("--input-file is required")
			}

			snapshot, err := manifest.LoadSnapshot(inputFile, resourceType)
			if err != nil {
				return err
			}

			engine := analyzer.New()
			findings, err := engine.Analyze(cmd.Context(), snapshot, analyzer.Options{
				Threshold: models.SeverityLow,
			})
			if err != nil {
				return err
			}

			cfg, err := loadExclusions(exclusionsPreset, exclusionsFile)
			if err != nil {
				return err
			}
			findings, _ = exclusions.Apply(cfg, findings)

			return writeScanResourceOutput(cmd, findings, outputFormats)
		},
	}

	cmd.Flags().StringVar(&inputFile, "input-file", "", "Path to a YAML or JSON manifest")
	cmd.Flags().StringVar(&resourceType, "resource-type", "", "Optional resource type hint")
	cmd.Flags().StringVar(&exclusionsFile, "exclusions-file", "", "Path to a user-supplied exclusions YAML file (merged on top of --exclusions-preset)")
	cmd.Flags().StringVar(&exclusionsPreset, "exclusions-preset", "standard", "Built-in exclusions preset: standard|minimal|strict|none")
	cmd.Flags().StringSliceVar(&outputFormats, "output-format", []string{"table"}, "Output formats: table,json")

	return cmd
}

// writeScanResourceOutput renders the manifest scan findings in each requested format (table or JSON) to the command's output streams.
func writeScanResourceOutput(cmd *cobra.Command, findings []models.Finding, formats []string) error {
	normalized := make([]string, 0, len(formats))
	seen := map[string]struct{}{}
	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		if format == "" {
			continue
		}
		if _, ok := seen[format]; ok {
			continue
		}
		seen[format] = struct{}{}
		normalized = append(normalized, format)
	}

	for _, format := range normalized {
		switch format {
		case "json":
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(findings); err != nil {
				return err
			}
		case "table":
			writer := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			if _, err := fmt.Fprintln(writer, "SEVERITY\tRULE ID\tRESOURCE\tTITLE"); err != nil {
				return err
			}
			for _, finding := range findings {
				resource := "-"
				if finding.Resource != nil {
					resource = finding.Resource.Kind + "/" + finding.Resource.Name
				}
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", finding.Severity, finding.RuleID, resource, finding.Title); err != nil {
					return err
				}
			}
			if len(findings) == 0 {
				if _, err := fmt.Fprintln(writer, "INFO\t-\t-\tNo findings"); err != nil {
					return err
				}
			}
			if err := writer.Flush(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported scan-resource output format %q", format)
		}
	}

	if len(findings) > 0 {
		_, err := fmt.Fprintf(cmd.ErrOrStderr(), "findings: %d\n", len(findings))
		return err
	}

	_, err := fmt.Fprintln(os.Stderr, "findings: 0")
	return err
}
