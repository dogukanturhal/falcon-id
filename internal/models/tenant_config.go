// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TenantConfig represents a per-tenant configuration override stored in the database.
type TenantConfig struct {
	TenantID    uuid.UUID       `json:"tenant_id"`
	ConfigKey   string          `json:"config_key"`
	ConfigValue json.RawMessage `json:"config_value"` // {"v": <typed_value>}
	Description string          `json:"description,omitempty"`
	UpdatedAt   time.Time       `json:"updated_at"`
	UpdatedBy   *uuid.UUID      `json:"updated_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ConfigKeyDefinition describes a supported dynamic configuration key.
type ConfigKeyDefinition struct {
	Key          string      `json:"key"`
	Description  string      `json:"description"`
	Type         string      `json:"type"` // "duration", "int", "string", "bool"
	DefaultValue interface{} `json:"default_value"`
	Category     string      `json:"category"` // "token", "mfa", "session", "smtp", "password", "rate_limit", "frontend"
	Sensitive    bool        `json:"sensitive"`
}

// UpsertTenantConfigRequest is the API request for upserting a single config key.
type UpsertTenantConfigRequest struct {
	ConfigKey   string `json:"config_key" binding:"required"`
	ConfigValue string `json:"config_value" binding:"required"` // raw string value, parsed by type
	Description string `json:"description,omitempty"`
}

// BulkUpsertTenantConfigRequest is the API request for upserting multiple config keys atomically.
type BulkUpsertTenantConfigRequest struct {
	Configs []UpsertTenantConfigRequest `json:"configs" binding:"required,min=1"`
}

// TenantConfigResponse is the API response for a single config entry.
type TenantConfigResponse struct {
	ConfigKey    string      `json:"config_key"`
	ConfigValue  interface{} `json:"config_value"`
	IsOverridden bool        `json:"is_overridden"`
	Type         string      `json:"type"`
	Category     string      `json:"category"`
	Description  string      `json:"description"`
	UpdatedAt    *time.Time  `json:"updated_at,omitempty"`
	UpdatedBy    *uuid.UUID  `json:"updated_by,omitempty"`
}
