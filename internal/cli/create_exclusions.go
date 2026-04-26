package cli

import (
	"fmt"

	"github.com/hardik/kubesplaining/internal/exclusions"
	"github.com/spf13/cobra"
)

// NewCreateExclusionsCmd returns the "create-exclusions-file" subcommand, which
// emits a starter exclusions YAML from a preset and can pre-populate system
// namespaces discovered in an existing snapshot.
func NewCreateExclusionsCmd() *cobra.Command {
	var (
		outputFile   string
		fromSnapshot string
		preset       string
	)

	cmd := &cobra.Command{
		Use:   "create-exclusions-file",
		Short: "Generate a starter exclusions YAML file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := exclusions.Preset(preset)
			if err != nil {
				return err
			}

			cfg, err = exclusions.EnrichFromSnapshot(cfg, fromSnapshot)
			if err != nil {
				return err
			}

			if outputFile == "" {
				outputFile = "exclusions.yml"
			}

			if err := exclusions.Write(outputFile, cfg); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "exclusions file written to %s\n", outputFile)
			return err
		},
	}

	cmd.Flags().StringVar(&outputFile, "output-file", "exclusions.yml", "Path to the exclusions YAML file")
	cmd.Flags().StringVar(&fromSnapshot, "from-snapshot", "", "Pre-populate system namespaces from a snapshot")
	cmd.Flags().StringVar(&preset, "preset", "standard", "Preset to use: minimal, standard, strict")

	return cmd
}
