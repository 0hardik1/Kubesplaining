package cli

import (
	"fmt"
	"time"

	"github.com/hardik/kubesplaining/internal/collector"
	"github.com/hardik/kubesplaining/internal/connection"
	"github.com/spf13/cobra"
)

// connectionFlags are the shared cluster-connection flags exposed by any subcommand that talks to the API server.
type connectionFlags struct {
	Kubeconfig            string
	Context               string
	APIServer             string
	Token                 string
	TokenFile             string
	CAFile                string
	ClientCertificateFile string
	ClientKeyFile         string
	InsecureSkipTLSVerify bool
	InCluster             bool
	Timeout               time.Duration
}

// toOptions converts the raw flag struct into the connection package's options type.
func (f connectionFlags) toOptions() connection.Options {
	return connection.Options{
		Kubeconfig:            f.Kubeconfig,
		Context:               f.Context,
		APIServer:             f.APIServer,
		Token:                 f.Token,
		TokenFile:             f.TokenFile,
		CAFile:                f.CAFile,
		ClientCertificateFile: f.ClientCertificateFile,
		ClientKeyFile:         f.ClientKeyFile,
		InsecureSkipTLSVerify: f.InsecureSkipTLSVerify,
		InCluster:             f.InCluster,
		Timeout:               f.Timeout,
	}
}

// bindConnectionFlags registers the standard set of cluster-connection flags on cmd.
func bindConnectionFlags(cmd *cobra.Command, flags *connectionFlags) {
	cmd.Flags().StringVar(&flags.Kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVar(&flags.Context, "context", "", "Kubernetes context to use")
	cmd.Flags().StringVar(&flags.APIServer, "api-server", "", "Direct API server URL")
	cmd.Flags().StringVar(&flags.Token, "token", "", "Bearer token")
	cmd.Flags().StringVar(&flags.TokenFile, "token-file", "", "Path to a bearer token file")
	cmd.Flags().StringVar(&flags.CAFile, "certificate-authority", "", "Path to the CA certificate")
	cmd.Flags().StringVar(&flags.ClientCertificateFile, "client-certificate", "", "Path to a client certificate")
	cmd.Flags().StringVar(&flags.ClientKeyFile, "client-key", "", "Path to a client key")
	cmd.Flags().BoolVar(&flags.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification")
	cmd.Flags().BoolVar(&flags.InCluster, "in-cluster", false, "Use in-cluster authentication")
	cmd.Flags().DurationVar(&flags.Timeout, "timeout", 30*time.Second, "API request timeout")
}

// NewDownloadCmd returns the "download" subcommand, which collects a live cluster snapshot and writes it to a JSON file for later offline analysis.
func NewDownloadCmd(build BuildInfo) *cobra.Command {
	var (
		connFlags            connectionFlags
		namespaces           []string
		excludeNamespaces    []string
		outputFile           string
		includeManagedFields bool
		parallelism          int
	)

	cmd := &cobra.Command{
		Use:   "download",
		Short: "Snapshot cluster state into a JSON file",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			clientset, config, err := connection.NewClientset(connFlags.toOptions())
			if err != nil {
				return err
			}

			c := collector.New(clientset, config, collector.Options{
				Namespaces:           namespaces,
				ExcludeNamespaces:    excludeNamespaces,
				IncludeManagedFields: includeManagedFields,
				Parallelism:          parallelism,
				BuildVersion:         build.Version,
			})

			snapshot, err := c.Collect(ctx)
			if err != nil {
				return err
			}

			if outputFile == "" {
				outputFile = fmt.Sprintf("cluster-snapshot-%s.json", time.Now().UTC().Format("20060102-150405"))
			}

			if err := collector.WriteSnapshot(outputFile, snapshot); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "snapshot written to %s\n", outputFile)
			return err
		},
	}

	bindConnectionFlags(cmd, &connFlags)
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Namespaces to include")
	cmd.Flags().StringSliceVar(&excludeNamespaces, "exclude-namespaces", nil, "Namespaces to exclude")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "Path to the snapshot JSON output")
	cmd.Flags().BoolVar(&includeManagedFields, "include-managed-fields", false, "Include managedFields in collected resources")
	cmd.Flags().IntVar(&parallelism, "parallelism", 10, "Maximum parallel API requests")

	return cmd
}
