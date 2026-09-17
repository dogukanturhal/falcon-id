// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ConsentCategory represents the category of a consent type
type ConsentCategory string

const (
	// ConsentCategoryRequired is an exported identifier.
	ConsentCategoryRequired ConsentCategory = "required"
	// ConsentCategoryFunctional is an exported identifier.
	ConsentCategoryFunctional ConsentCategory = "functional"
	// ConsentCategoryAnalytics is an exported identifier.
	ConsentCategoryAnalytics ConsentCategory = "analytics"
	// ConsentCategoryMarketing is an exported identifier.
	ConsentCategoryMarketing ConsentCategory = "marketing"
	// ConsentCategoryOptional is an exported identifier.
	ConsentCategoryOptional ConsentCategory = "optional"
)

// LegalBasis represents the GDPR legal basis for processing
type LegalBasis string

const (
	// LegalBasisConsent is an exported identifier.
	LegalBasisConsent LegalBasis = "consent"
	// LegalBasisContract is an exported identifier.
	LegalBasisContract LegalBasis = "contract"
	// LegalBasisLegalObligation is an exported identifier.
	LegalBasisLegalObligation LegalBasis = "legal_obligation"
	// LegalBasisVitalInterests is an exported identifier.
	LegalBasisVitalInterests LegalBasis = "vital_interests"
	// LegalBasisPublicTask is an exported identifier.
	LegalBasisPublicTask LegalBasis = "public_task"
	// LegalBasisLegitimateInterests is an exported identifier.
	LegalBasisLegitimateInterests LegalBasis = "legitimate_interests"
)

// ConsentType represents a type of consent that can be collected
type ConsentType struct {
	ID                uuid.UUID `json:"id" db:"id"`
	TenantID          uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name              string    `json:"name" db:"name"`
	DisplayName       string    `json:"display_name" db:"display_name"`
	Description       *string   `json:"description,omitempty" db:"description"`
	Category          string    `json:"category" db:"category"`
	IsRequired        bool      `json:"is_required" db:"is_required"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	Version           int       `json:"version" db:"version"`
	LegalBasis        *string   `json:"legal_basis,omitempty" db:"legal_basis"`
	DataRetentionDays *int      `json:"data_retention_days,omitempty" db:"data_retention_days"`
	ExternalPolicyURL *string   `json:"external_policy_url,omitempty" db:"external_policy_url"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// UserConsent represents a user's consent decision
type UserConsent struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	ConsentTypeID  uuid.UUID  `json:"consent_type_id" db:"consent_type_id"`
	Granted        bool       `json:"granted" db:"granted"`
	ConsentVersion int        `json:"consent_version" db:"consent_version"`
	GrantedAt      *time.Time `json:"granted_at,omitempty" db:"granted_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	IPAddress      *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string    `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// UserConsentWithType combines consent with its type for display
type UserConsentWithType struct {
	UserConsent
	ConsentType ConsentType `json:"consent_type"`
}

// ConsentTypeResponse is the API response for a consent type
type ConsentTypeResponse struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	DisplayName       string `json:"display_name"`
	Description       string `json:"description"`
	Category          string `json:"category"`
	IsRequired        bool   `json:"is_required"`
	Version           int    `json:"version"`
	LegalBasis        string `json:"legal_basis,omitempty"`
	ExternalPolicyURL string `json:"external_policy_url,omitempty"`
}

// UserConsentResponse is the API response for a user consent
type UserConsentResponse struct {
	ConsentType ConsentTypeResponse `json:"consent_type"`
	Granted     bool                `json:"granted"`
	GrantedAt   *time.Time          `json:"granted_at,omitempty"`
	RevokedAt   *time.Time          `json:"revoked_at,omitempty"`
	Version     int                 `json:"version"`
}

// ConsentListResponse is the response for listing consents
type ConsentListResponse struct {
	Consents           []UserConsentResponse `json:"consents"`
	PendingRequired    []ConsentTypeResponse `json:"pending_required,omitempty"`
	HasPendingRequired bool                  `json:"has_pending_required"`
}

// UpdateConsentRequest is the request to update a consent
type UpdateConsentRequest struct {
	Granted bool `json:"granted"`
}

// BulkConsentRequest is the request to update multiple consents at once
type BulkConsentRequest struct {
	Consents []struct {
		ConsentTypeID string `json:"consent_type_id"`
		Granted       bool   `json:"granted"`
	} `json:"consents"`
}

// ToResponse converts a ConsentType to ConsentTypeResponse
func (c *ConsentType) ToResponse() *ConsentTypeResponse {
	resp := &ConsentTypeResponse{
		ID:          c.ID.String(),
		Name:        c.Name,
		DisplayName: c.DisplayName,
		Category:    c.Category,
		IsRequired:  c.IsRequired,
		Version:     c.Version,
	}

	if c.Description != nil {
		resp.Description = *c.Description
	}
	if c.LegalBasis != nil {
		resp.LegalBasis = *c.LegalBasis
	}
	if c.ExternalPolicyURL != nil {
		resp.ExternalPolicyURL = *c.ExternalPolicyURL
	}

	return resp
}

// ToResponse converts a UserConsentWithType to UserConsentResponse
func (c *UserConsentWithType) ToResponse() *UserConsentResponse {
	return &UserConsentResponse{
		ConsentType: *c.ConsentType.ToResponse(),
		Granted:     c.Granted,
		GrantedAt:   c.GrantedAt,
		RevokedAt:   c.RevokedAt,
		Version:     c.ConsentVersion,
	}
}

// ConsentHistory represents a historical record of consent changes
type ConsentHistory struct {
	ID             uuid.UUID `json:"id" db:"id"`
	UserID         uuid.UUID `json:"user_id" db:"user_id"`
	ConsentTypeID  uuid.UUID `json:"consent_type_id" db:"consent_type_id"`
	Action         string    `json:"action" db:"action"` // granted, revoked
	ConsentVersion int       `json:"consent_version" db:"consent_version"`
	IPAddress      *string   `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string   `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// ConsentHistoryWithType combines consent history with its type for display
type ConsentHistoryWithType struct {
	ConsentHistory
	ConsentType ConsentType `json:"consent_type"`
}

// ConsentHistoryResponse is the API response for consent history
type ConsentHistoryResponse struct {
	ID             string              `json:"id"`
	ConsentType    ConsentTypeResponse `json:"consent_type"`
	Action         string              `json:"action"`
	ConsentVersion int                 `json:"consent_version"`
	IPAddress      string              `json:"ip_address,omitempty"`
	Timestamp      time.Time           `json:"timestamp"`
}

// ToResponse converts a ConsentHistoryWithType to ConsentHistoryResponse
func (c *ConsentHistoryWithType) ToResponse() *ConsentHistoryResponse {
	resp := &ConsentHistoryResponse{
		ID:             c.ID.String(),
		ConsentType:    *c.ConsentType.ToResponse(),
		Action:         c.Action,
		ConsentVersion: c.ConsentVersion,
		Timestamp:      c.CreatedAt,
	}

	if c.IPAddress != nil {
		resp.IPAddress = *c.IPAddress
	}

	return resp
}
