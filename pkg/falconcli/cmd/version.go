// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import "github.com/spf13/cobra"

// Build-time variables set by -ldflags.
var (
	// Version is the CLI version string.
	Version = "dev"
	// GitCommit is the git commit hash at build time.
	GitCommit = "unknown"
	// BuildDate is the build timestamp.
	BuildDate = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Run: func(_ *cobra.Command, _ []string) {
			printer.PrintMessage("falcon " + Version + " (commit: " + GitCommit + ", built: " + BuildDate + ")")
		},
	}
}
