// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// RegistrationPolicy defines the governance rules that govern how OAuth/OIDC
// client applications may be registered within the platform. Only one policy
// can be marked as the default at any time; it is applied when no more-specific
// policy is resolved for a tenant.
type RegistrationPolicy struct {
	ID                      uuid.UUID `json:"id" db:"id"`
	Name                    string    `json:"name" db:"name"`
	Description             *string   `json:"description,omitempty" db:"description"`
	RequireApproval         bool      `json:"require_approval" db:"require_approval"`
	AllowedRedirectPatterns []string  `json:"allowed_redirect_patterns" db:"allowed_redirect_patterns"`
	MaxAppsPerTenant        int       `json:"max_apps_per_tenant" db:"max_apps_per_tenant"`
	AllowedGrantTypes       []string  `json:"allowed_grant_types" db:"allowed_grant_types"`
	IsDefault               bool      `json:"is_default" db:"is_default"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
}

// CreateRegistrationPolicyRequest is the payload for creating a new registration policy.
// Fields with pointer types are optional; sensible defaults are applied when omitted.
type CreateRegistrationPolicyRequest struct {
	Name                    string   `json:"name" binding:"required"`
	Description             *string  `json:"description"`
	RequireApproval         *bool    `json:"require_approval"`
	AllowedRedirectPatterns []string `json:"allowed_redirect_patterns"`
	MaxAppsPerTenant        *int     `json:"max_apps_per_tenant"`
	AllowedGrantTypes       []string `json:"allowed_grant_types"`
	IsDefault               *bool    `json:"is_default"`
}

// UpdateRegistrationPolicyRequest is the payload for updating an existing registration policy.
// All fields are optional; only provided fields are applied.
type UpdateRegistrationPolicyRequest struct {
	Name                    *string  `json:"name"`
	Description             *string  `json:"description"`
	RequireApproval         *bool    `json:"require_approval"`
	AllowedRedirectPatterns []string `json:"allowed_redirect_patterns"`
	MaxAppsPerTenant        *int     `json:"max_apps_per_tenant"`
	AllowedGrantTypes       []string `json:"allowed_grant_types"`
	IsDefault               *bool    `json:"is_default"`
}

// AppRegistrationValidationRequest carries the details of a prospective app
// registration that must be checked against the effective policy.
type AppRegistrationValidationRequest struct {
	// TenantID is used to check the per-tenant app count against MaxAppsPerTenant.
	TenantID     uuid.UUID `json:"tenant_id"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
}
