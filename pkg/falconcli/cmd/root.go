// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"os"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/client"
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/config"
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/output"
	"github.com/spf13/cobra"
)

var (
	cfgAPIURL  string
	cfgOutput  string
	cfgToken   string
	cfgTenant  string
	cfgNoColor bool
	cfgHome    string // for testing

	printer      *output.Printer
	falconClient client.FalconClient

	// testOverrides tracks whether test overrides are active.
	// When set, PersistentPreRunE skips reinitializing printer and client.
	testClientOverride  bool
	testPrinterOverride bool
)

// NewRootCmd builds and returns the root cobra command.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "falcon",
		Short: "Falcon ID CLI — manage identity, access, and tenants",
		Long: `Command-line interface for the Falcon ID identity platform.
Manage users, roles, permissions, tenants, realms, and more.`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			// Load config
			cfg, err := config.Load(cfgHome)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// CLI flags override config file values
			if cfgAPIURL == "" {
				cfgAPIURL = cfg.BaseURL
			}
			if cfgToken == "" {
				cfgToken = cfg.AccessToken
			}
			if cfgTenant == "" {
				cfgTenant = cfg.TenantSlug
			}
			if cfgOutput == "" {
				cfgOutput = cfg.OutputFormat
				if cfgOutput == "" {
					cfgOutput = "table"
				}
			}

			// Only initialize printer/client if test overrides are not active
			if !testPrinterOverride {
				printer = output.NewPrinter(output.Format(cfgOutput), cfgNoColor)
			}
			if !testClientOverride {
				falconClient = client.NewHTTPClient(cfgAPIURL, cfgToken, cfgTenant)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&cfgAPIURL, "api-url", "", "Falcon ID API base URL (default from config or http://localhost:8005)")
	rootCmd.PersistentFlags().StringVarP(&cfgOutput, "output", "o", "", "Output format: table or json (default: table)")
	rootCmd.PersistentFlags().StringVar(&cfgToken, "token", "", "Override stored access token")
	rootCmd.PersistentFlags().StringVar(&cfgTenant, "tenant", "", "Override stored tenant slug")
	rootCmd.PersistentFlags().BoolVar(&cfgNoColor, "no-color", false, "Disable colored output")

	// Register subcommands
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newLoginCmd())
	rootCmd.AddCommand(newLogoutCmd())
	rootCmd.AddCommand(newWhoamiCmd())
	rootCmd.AddCommand(newHealthCmd())
	rootCmd.AddCommand(newUsersCmd())
	rootCmd.AddCommand(newRolesCmd())
	rootCmd.AddCommand(newPermissionsCmd())
	rootCmd.AddCommand(newTenantsCmd())
	rootCmd.AddCommand(newRealmsCmd())
	rootCmd.AddCommand(newTokensCmd())

	return rootCmd
}

// SetHomeOverride overrides the config home directory (for testing).
func SetHomeOverride(home string) {
	cfgHome = home
}

// SetClientOverride injects a mock client (for testing).
// Call with nil to clear the override.
func SetClientOverride(c client.FalconClient) {
	if c == nil {
		testClientOverride = false
		falconClient = nil
		return
	}
	testClientOverride = true
	falconClient = c
}

// SetPrinterOverride injects a custom printer (for testing).
// Call with nil to clear the override.
func SetPrinterOverride(p *output.Printer) {
	if p == nil {
		testPrinterOverride = false
		printer = nil
		return
	}
	testPrinterOverride = true
	printer = p
}

// Execute runs the root command.
func Execute() {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
