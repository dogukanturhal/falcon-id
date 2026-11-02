// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func validManifest() *models.ProductManifest {
	return &models.ProductManifest{
		Database: &models.DatabaseSpec{
			Type:               "postgresql",
			IsolationDefault:   "pool",
			MigrationSource:    "business-modules/example-pms-service/migrations",
			RequiredExtensions: []string{"pgcrypto"},
			SchemaPrefix:       "hotel_",
		},
		Endpoints: []models.EndpointSpec{
			{Path: "/api/v1/hotel/reservations", Method: "GET", AuthType: "bearer"},
			{Path: "/api/v1/hotel/reservations", Method: "POST", AuthType: "bearer"},
		},
		Permissions: []models.PermissionSpec{
			{Resource: "reservation", Actions: []string{"create", "read", "update", "delete"}},
			{Resource: "room", Actions: []string{"create", "read", "update"}},
		},
		Events: []models.EventSpec{
			{Type: "reservation.created", SchemaVersion: "1.0"},
			{Type: "reservation.checked_in", SchemaVersion: "1.0"},
		},
		Quotas: []models.QuotaSpec{
			{Name: "max_rooms", Unit: "count", DefaultMax: 100},
		},
		Dependencies: []string{"falcon-id"},
	}
}

func TestManifestValidator_ValidManifest(t *testing.T) {
	v := NewManifestValidator()
	err := v.ValidateManifest(validManifest())
	assert.NoError(t, err)
}

func TestManifestValidator_NilManifest(t *testing.T) {
	v := NewManifestValidator()
	assert.NoError(t, v.ValidateManifest(nil))
}

func TestManifestValidator_EmptyRawJSON(t *testing.T) {
	v := NewManifestValidator()
	assert.NoError(t, v.Validate(nil))
	assert.NoError(t, v.Validate(json.RawMessage{}))
}

func TestManifestValidator_InvalidJSON(t *testing.T) {
	v := NewManifestValidator()
	err := v.Validate(json.RawMessage(`{invalid`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid manifest JSON")
}

func TestManifestValidator_Database(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(m *models.ProductManifest)
		wantErr string
	}{
		{
			name:   "no database spec is valid",
			modify: func(m *models.ProductManifest) { m.Database = nil },
		},
		{
			name:    "missing database type",
			modify:  func(m *models.ProductManifest) { m.Database.Type = "" },
			wantErr: "database.type is required",
		},
		{
			name:    "unsupported database type",
			modify:  func(m *models.ProductManifest) { m.Database.Type = "mysql" },
			wantErr: "unsupported database type",
		},
		{
			name:    "missing isolation default",
			modify:  func(m *models.ProductManifest) { m.Database.IsolationDefault = "" },
			wantErr: "isolation_default is required",
		},
		{
			name:    "invalid isolation mode",
			modify:  func(m *models.ProductManifest) { m.Database.IsolationDefault = "magic" },
			wantErr: "invalid isolation_default",
		},
		{
			name:    "schema prefix too long",
			modify:  func(m *models.ProductManifest) { m.Database.SchemaPrefix = "this_is_way_too_long_for_a_prefix" },
			wantErr: "schema_prefix must be <= 20",
		},
		{
			name:    "schema prefix invalid chars",
			modify:  func(m *models.ProductManifest) { m.Database.SchemaPrefix = "Hotel-" },
			wantErr: "schema_prefix must contain only lowercase",
		},
	}

	v := NewManifestValidator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.modify(m)
			err := v.ValidateManifest(m)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestManifestValidator_Endpoints(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(m *models.ProductManifest)
		wantErr string
	}{
		{
			name:    "missing path",
			modify:  func(m *models.ProductManifest) { m.Endpoints[0].Path = "" },
			wantErr: "path is required",
		},
		{
			name:    "path without leading slash",
			modify:  func(m *models.ProductManifest) { m.Endpoints[0].Path = "api/v1/test" },
			wantErr: "must start with /",
		},
		{
			name:    "missing method",
			modify:  func(m *models.ProductManifest) { m.Endpoints[0].Method = "" },
			wantErr: "method is required",
		},
		{
			name:    "invalid method",
			modify:  func(m *models.ProductManifest) { m.Endpoints[0].Method = "FOOBAR" },
			wantErr: "invalid method",
		},
		{
			name: "duplicate endpoint",
			modify: func(m *models.ProductManifest) {
				m.Endpoints = append(m.Endpoints, models.EndpointSpec{
					Path: "/api/v1/hotel/reservations", Method: "GET",
				})
			},
			wantErr: "duplicate endpoint",
		},
	}

	v := NewManifestValidator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.modify(m)
			err := v.ValidateManifest(m)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestManifestValidator_Permissions(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(m *models.ProductManifest)
		wantErr string
	}{
		{
			name:    "missing resource",
			modify:  func(m *models.ProductManifest) { m.Permissions[0].Resource = "" },
			wantErr: "resource is required",
		},
		{
			name:    "empty actions",
			modify:  func(m *models.ProductManifest) { m.Permissions[0].Actions = nil },
			wantErr: "actions must not be empty",
		},
		{
			name: "duplicate permission across resources",
			modify: func(m *models.ProductManifest) {
				m.Permissions = append(m.Permissions, models.PermissionSpec{
					Resource: "reservation", Actions: []string{"create"},
				})
			},
			wantErr: "duplicate permission",
		},
		{
			name: "duplicate action within resource",
			modify: func(m *models.ProductManifest) {
				m.Permissions[0].Actions = []string{"read", "read"}
			},
			wantErr: "duplicate",
		},
	}

	v := NewManifestValidator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.modify(m)
			err := v.ValidateManifest(m)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestManifestValidator_Events(t *testing.T) {
	v := NewManifestValidator()

	t.Run("duplicate event type", func(t *testing.T) {
		m := validManifest()
		m.Events = append(m.Events, models.EventSpec{Type: "reservation.created"})
		err := v.ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate event type")
	})

	t.Run("empty event type", func(t *testing.T) {
		m := validManifest()
		m.Events[0].Type = ""
		err := v.ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "type is required")
	})
}

func TestManifestValidator_Quotas(t *testing.T) {
	v := NewManifestValidator()

	t.Run("duplicate quota", func(t *testing.T) {
		m := validManifest()
		m.Quotas = append(m.Quotas, models.QuotaSpec{Name: "max_rooms"})
		err := v.ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate quota name")
	})

	t.Run("negative default max", func(t *testing.T) {
		m := validManifest()
		m.Quotas[0].DefaultMax = -1
		err := v.ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "default_max must be >= 0")
	})
}

func TestManifestValidator_Dependencies(t *testing.T) {
	v := NewManifestValidator()

	t.Run("duplicate dependency", func(t *testing.T) {
		m := validManifest()
		m.Dependencies = []string{"falcon-id", "falcon-id"}
		err := v.ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate dependency")
	})

	t.Run("empty dependency", func(t *testing.T) {
		m := validManifest()
		m.Dependencies = []string{""}
		err := v.ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be empty")
	})
}

func TestManifestValidator_ValidateRawJSON(t *testing.T) {
	v := NewManifestValidator()
	raw := json.RawMessage(`{
		"database": {
			"type": "postgresql",
			"isolation_default": "silo",
			"migration_source": "business-modules/car-rental/migrations"
		},
		"permissions": [
			{"resource": "vehicle", "actions": ["create", "read"]}
		]
	}`)
	err := v.Validate(raw)
	assert.NoError(t, err)
}
