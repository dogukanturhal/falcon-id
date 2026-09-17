// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// CredentialPolicyScopeType represents the scope at which a policy applies.
type CredentialPolicyScopeType string

const (
	// CredentialPolicyScopePlatform is an exported identifier.
	CredentialPolicyScopePlatform CredentialPolicyScopeType = "platform"
	// CredentialPolicyScopeTenant is an exported identifier.
	CredentialPolicyScopeTenant CredentialPolicyScopeType = "tenant"
)

// CredentialPolicy defines maximum credential lifetimes at a given scope.
type CredentialPolicy struct {
	ID                    uuid.UUID                 `json:"id" db:"id"`
	ScopeType             CredentialPolicyScopeType `json:"scope_type" db:"scope_type"`
	ScopeID               *uuid.UUID                `json:"scope_id,omitempty" db:"scope_id"`
	MaxSecretLifetimeDays int                       `json:"max_secret_lifetime_days" db:"max_secret_lifetime_days"`
	MaxCertLifetimeDays   int                       `json:"max_cert_lifetime_days" db:"max_cert_lifetime_days"`
	RequireExpiry         bool                      `json:"require_expiry" db:"require_expiry"`
	CreatedAt             time.Time                 `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at" db:"updated_at"`
}

// CreateCredentialPolicyRequest is the payload for creating/updating a credential policy.
type CreateCredentialPolicyRequest struct {
	ScopeType             CredentialPolicyScopeType `json:"scope_type" binding:"required,oneof=platform tenant"`
	ScopeID               *uuid.UUID                `json:"scope_id"`
	MaxSecretLifetimeDays *int                      `json:"max_secret_lifetime_days"`
	MaxCertLifetimeDays   *int                      `json:"max_cert_lifetime_days"`
	RequireExpiry         *bool                     `json:"require_expiry"`
}
