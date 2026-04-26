package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewVersionCmd returns a command that prints embedded build information and exits.
func NewVersionCmd(build BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"version=%s commit=%s date=%s\n",
				build.Version,
				build.Commit,
				build.Date,
			)
			return err
		},
	}
}
