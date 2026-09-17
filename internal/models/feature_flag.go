// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PlatformFeatureFlag is a DB-backed, tenant-scoped feature flag stored in
// iam_feature_flags.  A nil TenantID represents the global default row;
// a non-nil TenantID is a per-tenant override that takes precedence.
type PlatformFeatureFlag struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	TenantID   *uuid.UUID      `json:"tenant_id,omitempty" db:"tenant_id"`
	FeatureKey string          `json:"feature_key" db:"feature_key"`
	Enabled    bool            `json:"enabled" db:"enabled"`
	Metadata   json.RawMessage `json:"metadata" db:"metadata"`
	CreatedAt  time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at" db:"updated_at"`
}

// SetFeatureFlagRequest is the payload for creating or updating a feature flag.
// TenantID nil means the operation targets the global default.
type SetFeatureFlagRequest struct {
	TenantID   *uuid.UUID      `json:"tenant_id"`
	FeatureKey string          `json:"feature_key" binding:"required,min=1,max=255"`
	Enabled    bool            `json:"enabled"`
	Metadata   json.RawMessage `json:"metadata"`
}

// FeatureFlagCheckResponse is the response for a single feature-flag check.
type FeatureFlagCheckResponse struct {
	FeatureKey string `json:"feature_key"`
	Enabled    bool   `json:"enabled"`
	// Source indicates whether the value came from a tenant override or the global default.
	Source string `json:"source"` // "tenant" | "global"
}
