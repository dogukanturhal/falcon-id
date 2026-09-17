// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config provides CLI configuration management.
package config

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	// DefaultBaseURL is the default Falcon ID API URL.
	DefaultBaseURL = "http://localhost:8005"
	configDir      = ".falcon"
	configFile     = "config"
	configType     = "yaml"
)

// Config holds the Falcon CLI configuration.
type Config struct {
	BaseURL      string `mapstructure:"base_url" yaml:"base_url"`
	AccessToken  string `mapstructure:"access_token" yaml:"access_token"`
	RefreshToken string `mapstructure:"refresh_token" yaml:"refresh_token"`
	TenantSlug   string `mapstructure:"tenant_slug" yaml:"tenant_slug"`
	Username     string `mapstructure:"username" yaml:"username"`
	OutputFormat string `mapstructure:"output_format" yaml:"output_format"`
}

// configDirPath returns the config directory path. Accepts homeOverride for testing.
func configDirPath(homeOverride string) string {
	home := homeOverride
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, configDir)
}

// Load reads the config file from ~/.falcon/config.yaml.
// If the file doesn't exist, returns a default config.
func Load(homeOverride string) (*Config, error) {
	dir := configDirPath(homeOverride)
	v := viper.New()
	v.SetConfigName(configFile)
	v.SetConfigType(configType)
	v.AddConfigPath(dir)

	v.SetDefault("base_url", DefaultBaseURL)
	v.SetDefault("output_format", "table")

	cfg := &Config{}
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			cfg.BaseURL = DefaultBaseURL
			cfg.OutputFormat = "table"
			return cfg, nil
		}
		return nil, err
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config to ~/.falcon/config.yaml with 0600 permissions.
func Save(cfg *Config, homeOverride string) error {
	dir := configDirPath(homeOverride)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	v := viper.New()
	v.Set("base_url", cfg.BaseURL)
	v.Set("access_token", cfg.AccessToken)
	v.Set("refresh_token", cfg.RefreshToken)
	v.Set("tenant_slug", cfg.TenantSlug)
	v.Set("username", cfg.Username)
	v.Set("output_format", cfg.OutputFormat)

	filePath := filepath.Join(dir, configFile+".yaml")
	if err := v.WriteConfigAs(filePath); err != nil {
		return err
	}
	return os.Chmod(filePath, 0o600)
}

// Clear removes stored credentials from the config, preserving other settings.
func Clear(homeOverride string) error {
	cfg, err := Load(homeOverride)
	if err != nil {
		cfg = &Config{}
	}
	cfg.AccessToken = ""
	cfg.RefreshToken = ""
	cfg.Username = ""
	return Save(cfg, homeOverride)
}
