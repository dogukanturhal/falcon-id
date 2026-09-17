// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/config"
	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	var username, password, tenantSlug string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Falcon ID",
		Long:  "Log in to Falcon ID and store credentials in ~/.falcon/config.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if username == "" {
				return fmt.Errorf("--username is required")
			}
			if password == "" {
				return fmt.Errorf("--password is required")
			}
			// Fall back to the persistent --tenant flag or loaded config
			if tenantSlug == "" {
				tenantSlug = cfgTenant
			}
			if tenantSlug == "" {
				return fmt.Errorf("--tenant-slug is required")
			}

			resp, err := falconClient.Login(cmd.Context(), &client.LoginRequest{
				Username:   username,
				Password:   password,
				TenantSlug: tenantSlug,
			})
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			// Persist tokens to config
			cfg, _ := config.Load(cfgHome)
			if cfg == nil {
				cfg = &config.Config{}
			}
			cfg.AccessToken = resp.AccessToken
			cfg.RefreshToken = resp.RefreshToken
			cfg.TenantSlug = tenantSlug
			cfg.Username = username
			cfg.BaseURL = cfgAPIURL
			if err := config.Save(cfg, cfgHome); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			printer.PrintSuccess(fmt.Sprintf("Logged in as %s (tenant: %s)", username, tenantSlug))
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username or email")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	cmd.Flags().StringVar(&tenantSlug, "tenant-slug", "", "Tenant slug")

	return cmd
}
