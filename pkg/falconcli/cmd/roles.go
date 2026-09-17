// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
)

func newRolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roles",
		Short: "Manage roles",
		Long:  "Commands for listing and inspecting roles in the Falcon ID platform",
	}
	cmd.AddCommand(newRolesListCmd())
	cmd.AddCommand(newRolesGetCmd())
	return cmd
}

func newRolesListCmd() *cobra.Command {
	var page, pageSize int
	var search string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List roles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := &client.ListOptions{Page: page, PageSize: pageSize, Search: search}
			resp, err := falconClient.ListRoles(cmd.Context(), opts)
			if err != nil {
				return err
			}

			headers := []string{"ID", "NAME", "DESCRIPTION", "SYSTEM", "CREATED"}
			rows := make([][]string, len(resp.Roles))
			for i, r := range resp.Roles {
				isSystem := "no"
				if r.IsSystem {
					isSystem = "yes"
				}
				rows[i] = []string{
					r.ID,
					r.Name,
					r.Description,
					isSystem,
					r.CreatedAt.Format("2006-01-02"),
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

func newRolesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get [id]",
		Short: "Get role details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := falconClient.GetRole(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			isSystem := "no"
			if resp.IsSystem {
				isSystem = "yes"
			}

			headers := []string{"FIELD", "VALUE"}
			rows := [][]string{
				{"ID", resp.ID},
				{"Name", resp.Name},
				{"Description", resp.Description},
				{"System Role", isSystem},
				{"Created", resp.CreatedAt.Format("2006-01-02 15:04:05")},
			}
			return printer.Print(headers, rows, resp)
		},
	}
}
