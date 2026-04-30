package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/report"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	"github.com/spf13/cobra"
)

// NewReportCmd returns the "report" subcommand, which regenerates HTML/JSON/CSV/SARIF
// artifacts from a previously produced findings JSON file without re-running analysis.
func NewReportCmd() *cobra.Command {
	var (
		inputFile         string
		outputDir         string
		outputFormats     []string
		severityThreshold string
		exclusionsFile    string
		exclusionsPreset  string
		metadataFile      string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Regenerate reports from a findings JSON file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("--input-file is required")
			}

			threshold, err := models.ParseSeverity(severityThreshold)
			if err != nil {
				return err
			}

			findings, err := report.ReadFindings(inputFile)
			if err != nil {
				return err
			}

			filtered := make([]models.Finding, 0, len(findings))
			for _, finding := range findings {
				if scoring.AboveThreshold(finding, threshold) {
					filtered = append(filtered, finding)
				}
			}

			cfg, err := loadExclusions(exclusionsPreset, exclusionsFile)
			if err != nil {
				return err
			}
			filtered, _ = exclusions.Apply(cfg, filtered)

			snapshot := models.NewSnapshot()
			snapshot.Metadata.ClusterName = "report-regeneration"
			metadataPath := metadataFile
			if metadataPath == "" {
				guessed := report.GuessMetadataPath(inputFile)
				if _, err := os.Stat(guessed); err == nil {
					metadataPath = guessed
				}
			}
			if metadataPath != "" {
				metadata, err := report.ReadMetadata(metadataPath)
				if err != nil {
					return err
				}
				snapshot.Metadata = metadata
			}

			if outputDir == "" {
				outputDir = filepath.Join(".", "kubesplaining-report")
			}

			written, err := report.Write(outputDir, outputFormats, snapshot, filtered)
			if err != nil {
				return err
			}

			summary := report.BuildSummary(filtered)
			for _, path := range written {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "findings: total=%d critical=%d high=%d medium=%d low=%d info=%d\n",
				summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&inputFile, "input-file", "", "Path to a findings JSON file")
	cmd.Flags().StringVar(&outputDir, "output-dir", filepath.Join(".", "kubesplaining-report"), "Directory for regenerated report output")
	cmd.Flags().StringSliceVar(&outputFormats, "output-format", []string{"html", "json"}, "Output formats: html,json,csv,sarif")
	cmd.Flags().StringVar(&severityThreshold, "severity-threshold", "low", "Minimum severity to include: critical,high,medium,low,info")
	cmd.Flags().StringVar(&exclusionsFile, "exclusions-file", "", "Path to a user-supplied exclusions YAML file (merged on top of --exclusions-preset)")
	cmd.Flags().StringVar(&exclusionsPreset, "exclusions-preset", "standard", "Built-in exclusions preset: standard|minimal|strict|none")
	cmd.Flags().StringVar(&metadataFile, "metadata-file", "", "Optional path to scan metadata JSON")

	return cmd
}
