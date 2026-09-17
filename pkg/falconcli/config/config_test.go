// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_DefaultsWhenNoFile(t *testing.T) {
	home := t.TempDir()

	cfg, err := Load(home)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, DefaultBaseURL, cfg.BaseURL)
	assert.Equal(t, "table", cfg.OutputFormat)
	assert.Empty(t, cfg.AccessToken)
	assert.Empty(t, cfg.RefreshToken)
	assert.Empty(t, cfg.TenantSlug)
	assert.Empty(t, cfg.Username)
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	home := t.TempDir()

	original := &Config{
		BaseURL:      "http://falcon.example.com:9090",
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
		TenantSlug:   "acme-corp",
		Username:     "johndoe",
		OutputFormat: "json",
	}

	err := Save(original, home)
	require.NoError(t, err)

	loaded, err := Load(home)
	require.NoError(t, err)
	assert.Equal(t, original.BaseURL, loaded.BaseURL)
	assert.Equal(t, original.AccessToken, loaded.AccessToken)
	assert.Equal(t, original.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, original.TenantSlug, loaded.TenantSlug)
	assert.Equal(t, original.Username, loaded.Username)
	assert.Equal(t, original.OutputFormat, loaded.OutputFormat)
}

func TestSave_CreatesDirectoryIfNotExists(t *testing.T) {
	home := t.TempDir()
	// Use a nested path that doesn't exist yet
	nestedHome := filepath.Join(home, "nested", "path")

	cfg := &Config{BaseURL: DefaultBaseURL, OutputFormat: "table"}
	err := Save(cfg, nestedHome)
	require.NoError(t, err)

	configPath := filepath.Join(nestedHome, configDir, configFile+".yaml")
	_, err = os.Stat(configPath)
	require.NoError(t, err, "config file should exist")
}

func TestSave_FilePermissions(t *testing.T) {
	home := t.TempDir()

	cfg := &Config{
		BaseURL:      DefaultBaseURL,
		AccessToken:  "secret-token",
		OutputFormat: "table",
	}

	err := Save(cfg, home)
	require.NoError(t, err)

	configPath := filepath.Join(home, configDir, configFile+".yaml")
	info, err := os.Stat(configPath)
	require.NoError(t, err)
	// On Unix, the file should be 0600 (owner read/write only)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestClear_RemovesCredentials(t *testing.T) {
	home := t.TempDir()

	// Save full config first
	original := &Config{
		BaseURL:      "http://falcon.example.com",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TenantSlug:   "my-tenant",
		Username:     "admin",
		OutputFormat: "json",
	}
	require.NoError(t, Save(original, home))

	// Clear credentials
	err := Clear(home)
	require.NoError(t, err)

	// Verify credentials are cleared but other settings preserved
	loaded, err := Load(home)
	require.NoError(t, err)
	assert.Empty(t, loaded.AccessToken)
	assert.Empty(t, loaded.RefreshToken)
	assert.Empty(t, loaded.Username)
	// Non-credential fields should be preserved
	assert.Equal(t, "http://falcon.example.com", loaded.BaseURL)
	assert.Equal(t, "json", loaded.OutputFormat)
	assert.Equal(t, "my-tenant", loaded.TenantSlug)
}

func TestClear_WorksWhenNoConfigExists(t *testing.T) {
	home := t.TempDir()

	// Clear when no config exists — should not error
	err := Clear(home)
	require.NoError(t, err)

	// Should create a file with empty credentials
	loaded, err := Load(home)
	require.NoError(t, err)
	assert.Empty(t, loaded.AccessToken)
}

func TestConfigDirPath_UsesHomeDir(t *testing.T) {
	home := t.TempDir()
	path := configDirPath(home)
	assert.Equal(t, filepath.Join(home, configDir), path)
}

func TestConfigDirPath_UsesSystemHome(t *testing.T) {
	// When no override, should use the system home directory
	path := configDirPath("")
	systemHome, err := os.UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(systemHome, configDir), path)
}

func TestSave_OverwritesExistingConfig(t *testing.T) {
	home := t.TempDir()

	// Save initial config
	initial := &Config{
		BaseURL:      DefaultBaseURL,
		AccessToken:  "old-token",
		OutputFormat: "table",
	}
	require.NoError(t, Save(initial, home))

	// Overwrite with new config
	updated := &Config{
		BaseURL:      "http://new-url.example.com",
		AccessToken:  "new-token",
		OutputFormat: "json",
	}
	require.NoError(t, Save(updated, home))

	loaded, err := Load(home)
	require.NoError(t, err)
	assert.Equal(t, "http://new-url.example.com", loaded.BaseURL)
	assert.Equal(t, "new-token", loaded.AccessToken)
	assert.Equal(t, "json", loaded.OutputFormat)
}

func TestLoad_PartialConfig(t *testing.T) {
	home := t.TempDir()

	// Write a minimal config file manually
	dir := filepath.Join(home, configDir)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	configContent := "base_url: http://custom.example.com\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, configFile+".yaml"), []byte(configContent), 0o600))

	cfg, err := Load(home)
	require.NoError(t, err)
	assert.Equal(t, "http://custom.example.com", cfg.BaseURL)
	// Other fields should be empty (not defaults since file was found)
	assert.Empty(t, cfg.AccessToken)
}
