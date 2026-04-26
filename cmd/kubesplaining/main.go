// Package main is the kubesplaining CLI entrypoint. It wires build metadata
// into the cobra root command and exits non-zero on any command error.
package main

import (
	"fmt"
	"os"

	"github.com/hardik/kubesplaining/internal/cli"
)

// These vars are populated at link time via -ldflags and surfaced through the version command.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	info := cli.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	if err := cli.NewRootCmd(info).Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
