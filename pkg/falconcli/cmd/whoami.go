// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"strings"

	"github.com/spf13/cobra"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current authenticated user",
		Long:  "Display information about the currently authenticated user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := falconClient.Whoami(cmd.Context())
			if err != nil {
				return err
			}

			headers := []string{"FIELD", "VALUE"}
			rows := [][]string{
				{"ID", resp.ID},
				{"Email", resp.Email},
				{"Username", resp.Username},
				{"Tenant ID", resp.TenantID},
				{"Tenant Slug", resp.TenantSlug},
				{"Roles", strings.Join(resp.Roles, ", ")},
			}
			return printer.Print(headers, rows, resp)
		},
	}
}
