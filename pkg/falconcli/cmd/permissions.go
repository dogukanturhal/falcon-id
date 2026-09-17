// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
)

func newPermissionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "permissions",
		Short: "Manage permissions",
		Long:  "Commands for listing and inspecting permissions in the Falcon ID platform",
	}
	cmd.AddCommand(newPermissionsListCmd())
	return cmd
}

func newPermissionsListCmd() *cobra.Command {
	var page, pageSize int
	var search string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List permissions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := &client.ListOptions{Page: page, PageSize: pageSize, Search: search}
			resp, err := falconClient.ListPermissions(cmd.Context(), opts)
			if err != nil {
				return err
			}

			headers := []string{"ID", "NAME", "RESOURCE", "ACTION", "DESCRIPTION"}
			rows := make([][]string, len(resp.Permissions))
			for i, p := range resp.Permissions {
				rows[i] = []string{
					p.ID,
					p.Name,
					p.Resource,
					p.Action,
					p.Description,
				}
			}
			return printer.Print(headers, rows, resp)
		},
	}
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Items per page")
	cmd.Flags().StringVar(&search, "search", "", "Search filter")
	return cmd
}
