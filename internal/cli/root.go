// Package cli assembles the kubesplaining cobra commands that drive the
// collect → analyze → report pipeline and its supporting utilities.
package cli

import "github.com/spf13/cobra"

// NewRootCmd builds the top-level kubesplaining command with all subcommands attached.
func NewRootCmd(build BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "kubesplaining",
		Short:         "Kubernetes security assessment CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		NewDownloadCmd(build),
		NewScanCmd(build),
		NewScanResourceCmd(),
		NewCreateExclusionsCmd(),
		NewReportCmd(),
		NewVersionCmd(build),
	)

	return cmd
}
