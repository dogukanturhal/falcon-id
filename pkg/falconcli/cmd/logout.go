// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/config"
	"github.com/spf13/cobra"
)

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out from Falcon ID",
		Long:  "Invalidate the current session and clear stored credentials from ~/.falcon/config.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Best-effort server-side logout; ignore network errors
			if err := falconClient.Logout(cmd.Context()); err != nil {
				printer.PrintError(fmt.Sprintf("Server logout failed (clearing local credentials anyway): %v", err))
			}

			// Always clear local credentials
			if err := config.Clear(cfgHome); err != nil {
				return fmt.Errorf("clearing credentials: %w", err)
			}

			printer.PrintSuccess("Logged out successfully")
			return nil
		},
	}
}
