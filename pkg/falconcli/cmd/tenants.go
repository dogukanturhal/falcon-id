// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
)

func newTenantsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenants",
		Short: "Manage tenants",
		Long:  "Commands for listing and inspecting platform tenants in the Falcon ID platform",
	}
	cmd.AddCommand(newTenantsListCmd())
	return cmd
}

func newTenantsListCmd() *cobra.Command {
	var page, pageSize int
	var search string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tenants",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := &client.ListOptions{Page: page, PageSize: pageSize, Search: search}
			resp, err := falconClient.ListTenants(cmd.Context(), opts)
			if err != nil {
				return err
			}

			headers := []string{"ID", "NAME", "SLUG", "STATUS"}
			rows := make([][]string, len(resp.Tenants))
			for i, t := range resp.Tenants {
				rows[i] = []string{
					t.ID,
					t.Name,
					t.Slug,
					printer.Badge(t.Status),
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
