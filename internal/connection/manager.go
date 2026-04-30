// Package connection builds authenticated Kubernetes client configurations
// from CLI flags, supporting kubeconfig, direct API server, and in-cluster modes.
package connection

import (
	"fmt"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Options captures the connection-related CLI flags used to build a rest.Config.
type Options struct {
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

// BuildConfig assembles a rest.Config from opts, choosing in-cluster, direct, or kubeconfig-based auth.
func BuildConfig(opts Options) (*rest.Config, error) {
	switch {
	case opts.InCluster:
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("build in-cluster config: %w", err)
		}
		cfg.Timeout = opts.Timeout
		return cfg, nil
	case opts.APIServer != "":
		return buildDirectConfig(opts)
	default:
		return buildKubeconfig(opts)
	}
}

// NewClientset builds a Kubernetes clientset and the underlying rest.Config from opts.
func NewClientset(opts Options) (*kubernetes.Clientset, *rest.Config, error) {
	cfg, err := BuildConfig(opts)
	if err != nil {
		return nil, nil, err
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return clientset, cfg, nil
}

// buildKubeconfig loads a rest.Config from the user's kubeconfig, honoring an explicit path and context override.
func buildKubeconfig(opts Options) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		loadingRules.ExplicitPath = opts.Kubeconfig
	}

	overrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	cfg.Timeout = opts.Timeout
	return cfg, nil
}

// buildDirectConfig constructs a rest.Config for talking to an explicit API server URL with token or client-cert auth.
func buildDirectConfig(opts Options) (*rest.Config, error) {
	cfg := &rest.Config{
		Host:            opts.APIServer,
		BearerToken:     opts.Token,
		TLSClientConfig: rest.TLSClientConfig{},
		Timeout:         opts.Timeout,
	}

	if opts.TokenFile != "" {
		tokenBytes, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("read token file: %w", err)
		}
		cfg.BearerToken = string(tokenBytes)
	}

	cfg.CAFile = opts.CAFile
	cfg.CertFile = opts.ClientCertificateFile
	cfg.KeyFile = opts.ClientKeyFile
	cfg.Insecure = opts.InsecureSkipTLSVerify

	if cfg.BearerToken == "" && cfg.CertFile == "" {
		return nil, fmt.Errorf("direct API server mode requires a bearer token or client certificate")
	}

	return cfg, nil
}
