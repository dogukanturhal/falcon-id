// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"strings"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/spf13/cobra"
)

func newTokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "Manage API tokens",
		Long:  "Commands for generating and managing API tokens in the Falcon ID platform",
	}
	cmd.AddCommand(newTokensGenerateCmd())
	return cmd
}

func newTokensGenerateCmd() *cobra.Command {
	var name, expiresIn string
	var scopes []string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new API token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := falconClient.GenerateToken(cmd.Context(), &client.GenerateTokenRequest{
				Name:      name,
				ExpiresIn: expiresIn,
				Scopes:    scopes,
			})
			if err != nil {
				return err
			}

			printer.PrintSuccess(fmt.Sprintf("Token generated: %s", resp.Name))
			printer.PrintMessage(fmt.Sprintf("ID:         %s", resp.ID))
			printer.PrintMessage(fmt.Sprintf("Key:        %s", resp.Key))
			if resp.ExpiresAt != "" {
				printer.PrintMessage(fmt.Sprintf("Expires At: %s", resp.ExpiresAt))
			}
			if len(scopes) > 0 {
				printer.PrintMessage(fmt.Sprintf("Scopes:     %s", strings.Join(scopes, ", ")))
			}
			printer.PrintMessage("")
			printer.PrintMessage("Store this key securely — it will not be shown again.")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Token name/label")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Expiry duration (e.g. 30d, 1y)")
	cmd.Flags().StringSliceVar(&scopes, "scopes", nil, "Comma-separated list of permission scopes")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}
