// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cmd implements the CLI commands.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check Falcon ID service health",
		Long:  "Retrieve and display the health status of the Falcon ID service and its dependencies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := falconClient.Health(cmd.Context())
			if err != nil {
				return err
			}

			headers := []string{"COMPONENT", "STATUS"}
			rows := [][]string{
				{"falcon-id", printer.Badge(resp.Status)},
			}
			for svc, status := range resp.Services {
				rows = append(rows, []string{svc, printer.Badge(status)})
			}

			if resp.Version != "" {
				printer.PrintMessage(fmt.Sprintf("Version: %s", resp.Version))
			}

			return printer.Print(headers, rows, resp)
		},
	}
}
