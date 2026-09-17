// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
)

func newRealmsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "realms",
		Short: "Manage realms",
		Long:  "Commands for listing and inspecting authentication realms in the Falcon ID platform",
	}
	cmd.AddCommand(newRealmsListCmd())
	return cmd
}

func newRealmsListCmd() *cobra.Command {
	var page, pageSize int
	var search string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List realms",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := &client.ListOptions{Page: page, PageSize: pageSize, Search: search}
			resp, err := falconClient.ListRealms(cmd.Context(), opts)
			if err != nil {
				return err
			}

			headers := []string{"ID", "NAME", "TENANT ID", "STATUS"}
			rows := make([][]string, len(resp.Realms))
			for i, r := range resp.Realms {
				rows[i] = []string{
					r.ID,
					r.Name,
					r.TenantID,
					printer.Badge(r.Status),
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
