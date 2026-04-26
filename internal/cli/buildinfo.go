package cli

// BuildInfo carries the binary's version, git commit, and build date for the version and help output.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}
