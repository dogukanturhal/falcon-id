// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"testing"

	"github.com/dogukanturhal/falcon-id/pkg/falconcli/config"
	"github.com/dogukanturhal/falcon-id/pkg/falconcli/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_HelpOutput(t *testing.T) {
	cmd := NewRootCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "falcon")
	assert.Contains(t, out, "identity")
}

func TestRootCmd_PersistentPreRun_LoadsConfigDefaults(t *testing.T) {
	home := t.TempDir()

	// No config file exists — defaults should be used
	cfg, err := config.Load(home)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8005", cfg.BaseURL)
	assert.Equal(t, "table", cfg.OutputFormat)
}

func TestRootCmd_PersistentPreRun_FlagsOverrideConfig(t *testing.T) {
	home := t.TempDir()

	// Save a config with values
	require.NoError(t, config.Save(&config.Config{
		BaseURL:      "http://from-config.com",
		AccessToken:  "config-token",
		TenantSlug:   "config-tenant",
		OutputFormat: "table",
	}, home))

	// Simulate flags overriding config
	SetHomeOverride(home)
	cfgAPIURL = "http://from-flag.com"
	cfgToken = "flag-token"
	cfgTenant = "flag-tenant"
	cfgOutput = "json"

	assert.Equal(t, "http://from-flag.com", cfgAPIURL)
	assert.Equal(t, "flag-token", cfgToken)
	assert.Equal(t, "flag-tenant", cfgTenant)
	assert.Equal(t, "json", cfgOutput)

	// Reset
	cfgAPIURL = ""
	cfgToken = ""
	cfgTenant = ""
	cfgOutput = ""
}

func TestRootCmd_Subcommands_Registered(t *testing.T) {
	cmd := NewRootCmd()
	subcommandNames := make([]string, 0)
	for _, sub := range cmd.Commands() {
		subcommandNames = append(subcommandNames, sub.Name())
	}

	expected := []string{"version", "login", "logout", "whoami", "health", "users", "roles", "permissions", "tenants", "realms", "tokens"}
	for _, name := range expected {
		assert.Contains(t, subcommandNames, name, "expected subcommand %q to be registered", name)
	}
}

func TestRootCmd_PersistentFlags(t *testing.T) {
	cmd := NewRootCmd()

	assert.NotNil(t, cmd.PersistentFlags().Lookup("api-url"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("output"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("token"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("tenant"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("no-color"))
}

func TestSetClientOverride(t *testing.T) {
	mockClient := new(MockFalconClient)
	SetClientOverride(mockClient)
	assert.Equal(t, mockClient, falconClient)
}

func TestSetPrinterOverride(t *testing.T) {
	p := output.NewPrinter(output.FormatJSON, true)
	SetPrinterOverride(p)
	assert.Equal(t, p, printer)
}

func TestSetHomeOverride(t *testing.T) {
	SetHomeOverride("/tmp/test-home")
	assert.Equal(t, "/tmp/test-home", cfgHome)
	// Reset for other tests
	SetHomeOverride("")
}
