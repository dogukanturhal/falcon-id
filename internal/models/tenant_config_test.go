// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== TenantConfig struct ====================

func TestTenantConfig_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		tenantID := uuid.New()
		updatedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		rawValue := json.RawMessage(`{"v": "15m"}`)

		cfg := TenantConfig{
			TenantID:    tenantID,
			ConfigKey:   "access_token_expiry",
			ConfigValue: rawValue,
			Description: "Duration for access tokens",
			UpdatedAt:   now,
			UpdatedBy:   &updatedBy,
			CreatedAt:   now,
		}

		assert.Equal(t, tenantID, cfg.TenantID)
		assert.Equal(t, "access_token_expiry", cfg.ConfigKey)
		assert.Equal(t, rawValue, cfg.ConfigValue)
		assert.Equal(t, "Duration for access tokens", cfg.Description)
		assert.Equal(t, now, cfg.UpdatedAt)
		require.NotNil(t, cfg.UpdatedBy)
		assert.Equal(t, updatedBy, *cfg.UpdatedBy)
		assert.Equal(t, now, cfg.CreatedAt)
	})

	t.Run("should allow nil UpdatedBy", func(t *testing.T) {
		cfg := TenantConfig{
			TenantID:    uuid.New(),
			ConfigKey:   "mfa_required",
			ConfigValue: json.RawMessage(`{"v": true}`),
		}

		assert.Nil(t, cfg.UpdatedBy)
	})

	t.Run("should allow empty Description", func(t *testing.T) {
		cfg := TenantConfig{
			TenantID:    uuid.New(),
			ConfigKey:   "session_timeout",
			ConfigValue: json.RawMessage(`{"v": "30m"}`),
		}

		assert.Empty(t, cfg.Description)
	})
}

// ==================== TenantConfig ConfigValue JSON encoding ====================

func TestTenantConfig_ConfigValue_JSON(t *testing.T) {
	tests := []struct {
		name        string
		configKey   string
		rawValue    json.RawMessage
		expectedKey string
	}{
		{
			name:        "duration config value",
			configKey:   "access_token_expiry",
			rawValue:    json.RawMessage(`{"v":"15m"}`),
			expectedKey: "v",
		},
		{
			name:        "int config value",
			configKey:   "max_login_attempts",
			rawValue:    json.RawMessage(`{"v":5}`),
			expectedKey: "v",
		},
		{
			name:        "bool config value",
			configKey:   "mfa_required",
			rawValue:    json.RawMessage(`{"v":true}`),
			expectedKey: "v",
		},
		{
			name:        "string config value",
			configKey:   "smtp_host",
			rawValue:    json.RawMessage(`{"v":"smtp.example.com"}`),
			expectedKey: "v",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TenantConfig{
				TenantID:    uuid.New(),
				ConfigKey:   tt.configKey,
				ConfigValue: tt.rawValue,
			}

			var decoded map[string]interface{}
			err := json.Unmarshal(cfg.ConfigValue, &decoded)
			require.NoError(t, err)
			assert.Contains(t, decoded, tt.expectedKey)
		})
	}
}

// ==================== ConfigKeyDefinition struct ====================

func TestConfigKeyDefinition_StructFields(t *testing.T) {
	t.Run("should carry all definition fields", func(t *testing.T) {
		def := ConfigKeyDefinition{
			Key:          "access_token_expiry",
			Description:  "Duration of access tokens before they expire",
			Type:         "duration",
			DefaultValue: "15m",
			Category:     "token",
			Sensitive:    false,
		}

		assert.Equal(t, "access_token_expiry", def.Key)
		assert.Equal(t, "Duration of access tokens before they expire", def.Description)
		assert.Equal(t, "duration", def.Type)
		assert.Equal(t, "15m", def.DefaultValue)
		assert.Equal(t, "token", def.Category)
		assert.False(t, def.Sensitive)
	})

	t.Run("should support all known type values", func(t *testing.T) {
		types := []string{"duration", "int", "string", "bool"}

		for _, typ := range types {
			typ := typ
			t.Run(typ, func(t *testing.T) {
				def := ConfigKeyDefinition{
					Key:  "some_key",
					Type: typ,
				}
				assert.Equal(t, typ, def.Type)
			})
		}
	})

	t.Run("should support all known category values", func(t *testing.T) {
		categories := []string{"token", "mfa", "session", "smtp", "password", "rate_limit", "frontend"}

		for _, cat := range categories {
			cat := cat
			t.Run(cat, func(t *testing.T) {
				def := ConfigKeyDefinition{
					Key:      "some_key",
					Category: cat,
				}
				assert.Equal(t, cat, def.Category)
			})
		}
	})

	t.Run("should mark sensitive field correctly", func(t *testing.T) {
		sensitive := ConfigKeyDefinition{
			Key:       "smtp_password",
			Type:      "string",
			Sensitive: true,
		}
		assert.True(t, sensitive.Sensitive)

		notSensitive := ConfigKeyDefinition{
			Key:       "max_login_attempts",
			Type:      "int",
			Sensitive: false,
		}
		assert.False(t, notSensitive.Sensitive)
	})

	t.Run("should allow various default value types", func(t *testing.T) {
		tests := []struct {
			name         string
			defaultValue interface{}
		}{
			{name: "string default", defaultValue: "15m"},
			{name: "int default", defaultValue: 5},
			{name: "bool default", defaultValue: true},
			{name: "nil default", defaultValue: nil},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				def := ConfigKeyDefinition{
					Key:          "some_key",
					DefaultValue: tt.defaultValue,
				}
				assert.Equal(t, tt.defaultValue, def.DefaultValue)
			})
		}
	})
}

// ==================== UpsertTenantConfigRequest ====================

func TestUpsertTenantConfigRequest_StructFields(t *testing.T) {
	t.Run("should carry ConfigKey and ConfigValue", func(t *testing.T) {
		req := UpsertTenantConfigRequest{
			ConfigKey:   "access_token_expiry",
			ConfigValue: "30m",
			Description: "Extended token lifetime",
		}

		assert.Equal(t, "access_token_expiry", req.ConfigKey)
		assert.Equal(t, "30m", req.ConfigValue)
		assert.Equal(t, "Extended token lifetime", req.Description)
	})

	t.Run("should allow empty Description", func(t *testing.T) {
		req := UpsertTenantConfigRequest{
			ConfigKey:   "mfa_required",
			ConfigValue: "true",
		}

		assert.Equal(t, "mfa_required", req.ConfigKey)
		assert.Equal(t, "true", req.ConfigValue)
		assert.Empty(t, req.Description)
	})
}

// ==================== BulkUpsertTenantConfigRequest ====================

func TestBulkUpsertTenantConfigRequest_StructFields(t *testing.T) {
	t.Run("should carry multiple configs", func(t *testing.T) {
		req := BulkUpsertTenantConfigRequest{
			Configs: []UpsertTenantConfigRequest{
				{ConfigKey: "access_token_expiry", ConfigValue: "15m"},
				{ConfigKey: "mfa_required", ConfigValue: "true"},
				{ConfigKey: "max_login_attempts", ConfigValue: "5"},
			},
		}

		assert.Len(t, req.Configs, 3)
		assert.Equal(t, "access_token_expiry", req.Configs[0].ConfigKey)
		assert.Equal(t, "mfa_required", req.Configs[1].ConfigKey)
		assert.Equal(t, "max_login_attempts", req.Configs[2].ConfigKey)
	})

	t.Run("should allow single config entry", func(t *testing.T) {
		req := BulkUpsertTenantConfigRequest{
			Configs: []UpsertTenantConfigRequest{
				{ConfigKey: "smtp_host", ConfigValue: "smtp.example.com"},
			},
		}

		assert.Len(t, req.Configs, 1)
	})
}

// ==================== TenantConfigResponse ====================

func TestTenantConfigResponse_StructFields(t *testing.T) {
	t.Run("should carry all response fields with override", func(t *testing.T) {
		updatedBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		resp := TenantConfigResponse{
			ConfigKey:    "access_token_expiry",
			ConfigValue:  "30m",
			IsOverridden: true,
			Type:         "duration",
			Category:     "token",
			Description:  "Custom token lifetime",
			UpdatedAt:    &now,
			UpdatedBy:    &updatedBy,
		}

		assert.Equal(t, "access_token_expiry", resp.ConfigKey)
		assert.Equal(t, "30m", resp.ConfigValue)
		assert.True(t, resp.IsOverridden)
		assert.Equal(t, "duration", resp.Type)
		assert.Equal(t, "token", resp.Category)
		assert.Equal(t, "Custom token lifetime", resp.Description)
		require.NotNil(t, resp.UpdatedAt)
		assert.Equal(t, now, *resp.UpdatedAt)
		require.NotNil(t, resp.UpdatedBy)
		assert.Equal(t, updatedBy, *resp.UpdatedBy)
	})

	t.Run("should carry default response (not overridden)", func(t *testing.T) {
		resp := TenantConfigResponse{
			ConfigKey:    "mfa_required",
			ConfigValue:  false,
			IsOverridden: false,
			Type:         "bool",
			Category:     "mfa",
		}

		assert.Equal(t, "mfa_required", resp.ConfigKey)
		assert.False(t, resp.IsOverridden)
		assert.Equal(t, false, resp.ConfigValue)
		assert.Nil(t, resp.UpdatedAt)
		assert.Nil(t, resp.UpdatedBy)
	})

	t.Run("should support various ConfigValue types", func(t *testing.T) {
		tests := []struct {
			name        string
			configValue interface{}
		}{
			{name: "string value", configValue: "15m"},
			{name: "int value", configValue: 5},
			{name: "bool true value", configValue: true},
			{name: "bool false value", configValue: false},
			{name: "float value", configValue: 1.5},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp := TenantConfigResponse{
					ConfigKey:   "some_key",
					ConfigValue: tt.configValue,
				}
				assert.Equal(t, tt.configValue, resp.ConfigValue)
			})
		}
	})
}
