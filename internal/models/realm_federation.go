// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// FederationTrustType determines directionality of the trust.
type FederationTrustType string

const (
	// FederationTrustTypeUnidirectional is an exported identifier.
	FederationTrustTypeUnidirectional FederationTrustType = "unidirectional"
	// FederationTrustTypeBidirectional is an exported identifier.
	FederationTrustTypeBidirectional FederationTrustType = "bidirectional"
)

// FederationTrustLevel controls how deeply the trust is extended.
type FederationTrustLevel string

const (
	// FederationTrustLevelFull is an exported identifier.
	FederationTrustLevelFull FederationTrustLevel = "full"
	// FederationTrustLevelLimited is an exported identifier.
	FederationTrustLevelLimited FederationTrustLevel = "limited"
	// FederationTrustLevelRestricted is an exported identifier.
	FederationTrustLevelRestricted FederationTrustLevel = "restricted"
)

// FederationTrustStatus represents the lifecycle state of a trust.
type FederationTrustStatus string

const (
	// FederationTrustStatusPending is an exported identifier.
	FederationTrustStatusPending FederationTrustStatus = "pending"
	// FederationTrustStatusActive is an exported identifier.
	FederationTrustStatusActive FederationTrustStatus = "active"
	// FederationTrustStatusSuspended is an exported identifier.
	FederationTrustStatusSuspended FederationTrustStatus = "suspended"
	// FederationTrustStatusRevoked is an exported identifier.
	FederationTrustStatusRevoked FederationTrustStatus = "revoked"
)

// RealmFederationTrust represents a directional trust relationship between two realms.
type RealmFederationTrust struct {
	ID            uuid.UUID `json:"id" db:"id"`
	SourceRealmID uuid.UUID `json:"source_realm_id" db:"source_realm_id"`
	TargetRealmID uuid.UUID `json:"target_realm_id" db:"target_realm_id"`

	// Trust configuration
	TrustType  FederationTrustType  `json:"trust_type" db:"trust_type"`
	TrustLevel FederationTrustLevel `json:"trust_level" db:"trust_level"`

	// Access control constraints
	AllowedTenantTypes []string `json:"allowed_tenant_types,omitempty" db:"allowed_tenant_types"`
	MaxGuestUsers      *int     `json:"max_guest_users,omitempty" db:"max_guest_users"`
	RequireMFA         bool     `json:"require_mfa" db:"require_mfa"`
	AllowedRoles       []string `json:"allowed_roles,omitempty" db:"allowed_roles"`
	ScopeRestrictions  []string `json:"scope_restrictions,omitempty" db:"scope_restrictions"`

	// Token override
	TokenLifetimeOverride *int `json:"token_lifetime_override,omitempty" db:"token_lifetime_override"`

	// Lifecycle
	Status        FederationTrustStatus `json:"status" db:"status"`
	EstablishedAt *time.Time            `json:"established_at,omitempty" db:"established_at"`
	RequestedBy   uuid.UUID             `json:"requested_by" db:"requested_by"`
	ApprovedBy    *uuid.UUID            `json:"approved_by,omitempty" db:"approved_by"`

	// Metadata
	Description *string `json:"description,omitempty" db:"description"`
	Metadata    *string `json:"metadata,omitempty" db:"metadata"` // raw JSONB

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// RealmFederationAudit records a single change to a federation trust.
type RealmFederationAudit struct {
	ID        uuid.UUID `json:"id" db:"id"`
	TrustID   uuid.UUID `json:"trust_id" db:"trust_id"`
	ActorID   uuid.UUID `json:"actor_id" db:"actor_id"`
	Action    string    `json:"action" db:"action"`
	OldValue  *string   `json:"old_value,omitempty" db:"old_value"`
	NewValue  *string   `json:"new_value,omitempty" db:"new_value"`
	IPAddress *string   `json:"ip_address,omitempty" db:"ip_address"`
	Reason    *string   `json:"reason,omitempty" db:"reason"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ==================== Request / Response DTOs ====================

// CreateFederationTrustRequest creates a new realm federation trust.
type CreateFederationTrustRequest struct {
	SourceRealmID uuid.UUID            `json:"source_realm_id" binding:"required"`
	TargetRealmID uuid.UUID            `json:"target_realm_id" binding:"required"`
	TrustType     FederationTrustType  `json:"trust_type" binding:"omitempty,oneof=unidirectional bidirectional"`
	TrustLevel    FederationTrustLevel `json:"trust_level" binding:"omitempty,oneof=full limited restricted"`
	Description   string               `json:"description,omitempty"`
	RequireMFA    bool                 `json:"require_mfa,omitempty"`
	MaxGuestUsers *int                 `json:"max_guest_users,omitempty"`
	AllowedRoles  []string             `json:"allowed_roles,omitempty"`

	TokenLifetimeOverride *int     `json:"token_lifetime_override,omitempty"`
	ScopeRestrictions     []string `json:"scope_restrictions,omitempty"`
	AllowedTenantTypes    []string `json:"allowed_tenant_types,omitempty"`
}

// UpdateFederationTrustRequest carries mutable fields.
type UpdateFederationTrustRequest struct {
	TrustType             *FederationTrustType  `json:"trust_type,omitempty" binding:"omitempty,oneof=unidirectional bidirectional"`
	TrustLevel            *FederationTrustLevel `json:"trust_level,omitempty" binding:"omitempty,oneof=full limited restricted"`
	Description           *string               `json:"description,omitempty"`
	RequireMFA            *bool                 `json:"require_mfa,omitempty"`
	MaxGuestUsers         *int                  `json:"max_guest_users,omitempty"`
	AllowedRoles          []string              `json:"allowed_roles,omitempty"`
	TokenLifetimeOverride *int                  `json:"token_lifetime_override,omitempty"`
	ScopeRestrictions     []string              `json:"scope_restrictions,omitempty"`
	AllowedTenantTypes    []string              `json:"allowed_tenant_types,omitempty"`
}

// ApproveFederationTrustRequest carries approval metadata.
type ApproveFederationTrustRequest struct {
	Reason string `json:"reason,omitempty"`
}

// SuspendFederationTrustRequest carries suspension metadata.
type SuspendFederationTrustRequest struct {
	Reason string `json:"reason,omitempty"`
}

// FederationTrustListFilter controls which trusts are returned.
type FederationTrustListFilter struct {
	SourceRealmID *uuid.UUID
	TargetRealmID *uuid.UUID
	Status        *FederationTrustStatus
	Page          int
	PageSize      int
}

// FederationTrustResponse is the API-safe representation of a trust.
type FederationTrustResponse struct {
	ID            uuid.UUID             `json:"id"`
	SourceRealmID uuid.UUID             `json:"source_realm_id"`
	TargetRealmID uuid.UUID             `json:"target_realm_id"`
	TrustType     FederationTrustType   `json:"trust_type"`
	TrustLevel    FederationTrustLevel  `json:"trust_level"`
	Status        FederationTrustStatus `json:"status"`
	RequireMFA    bool                  `json:"require_mfa"`
	MaxGuestUsers *int                  `json:"max_guest_users,omitempty"`
	AllowedRoles  []string              `json:"allowed_roles,omitempty"`
	Description   *string               `json:"description,omitempty"`
	RequestedBy   uuid.UUID             `json:"requested_by"`
	ApprovedBy    *uuid.UUID            `json:"approved_by,omitempty"`
	EstablishedAt *time.Time            `json:"established_at,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

// FederationTrustListResponse wraps a page of trust records.
type FederationTrustListResponse struct {
	Trusts     []*FederationTrustResponse `json:"trusts"`
	Total      int64                      `json:"total"`
	Page       int                        `json:"page"`
	PageSize   int                        `json:"page_size"`
	TotalPages int                        `json:"total_pages"`
}

// IsActive reports whether the trust is currently usable.
func (t *RealmFederationTrust) IsActive() bool {
	return t.Status == FederationTrustStatusActive
}

// IsBidirectional reports whether this trust applies in both directions.
func (t *RealmFederationTrust) IsBidirectional() bool {
	return t.TrustType == FederationTrustTypeBidirectional
}

// ToResponse converts to the API-safe DTO.
func (t *RealmFederationTrust) ToResponse() *FederationTrustResponse {
	return &FederationTrustResponse{
		ID:            t.ID,
		SourceRealmID: t.SourceRealmID,
		TargetRealmID: t.TargetRealmID,
		TrustType:     t.TrustType,
		TrustLevel:    t.TrustLevel,
		Status:        t.Status,
		RequireMFA:    t.RequireMFA,
		MaxGuestUsers: t.MaxGuestUsers,
		AllowedRoles:  t.AllowedRoles,
		Description:   t.Description,
		RequestedBy:   t.RequestedBy,
		ApprovedBy:    t.ApprovedBy,
		EstablishedAt: t.EstablishedAt,
		CreatedAt:     t.CreatedAt,
		UpdatedAt:     t.UpdatedAt,
	}
}
