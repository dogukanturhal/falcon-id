// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AppConsentType represents who granted the consent.
type AppConsentType string

const (
	// AppConsentTypeAdmin is an exported identifier.
	AppConsentTypeAdmin AppConsentType = "admin"
	// AppConsentTypeUser is an exported identifier.
	AppConsentTypeUser AppConsentType = "user"
)

// AppConsentStatus represents the consent lifecycle state.
type AppConsentStatus string

const (
	// AppConsentStatusGranted is an exported identifier.
	AppConsentStatusGranted AppConsentStatus = "granted"
	// AppConsentStatusRevoked is an exported identifier.
	AppConsentStatusRevoked AppConsentStatus = "revoked"
)

// AppConsent represents a consent record for an application in a tenant.
type AppConsent struct {
	ID            uuid.UUID        `json:"id" db:"id"`
	ApplicationID uuid.UUID        `json:"application_id" db:"application_id"`
	TenantID      uuid.UUID        `json:"tenant_id" db:"tenant_id"`
	ConsentedBy   uuid.UUID        `json:"consented_by" db:"consented_by"`
	ConsentType   AppConsentType   `json:"consent_type" db:"consent_type"`
	Scopes        []string         `json:"scopes" db:"scopes"`
	Status        AppConsentStatus `json:"status" db:"status"`
	GrantedAt     time.Time        `json:"granted_at" db:"granted_at"`
	RevokedAt     *time.Time       `json:"revoked_at,omitempty" db:"revoked_at"`
}

// AppConsentResponse is the API response for a consent record.
type AppConsentResponse struct {
	ID            uuid.UUID        `json:"id"`
	ApplicationID uuid.UUID        `json:"application_id"`
	TenantID      uuid.UUID        `json:"tenant_id"`
	ConsentedBy   uuid.UUID        `json:"consented_by"`
	ConsentType   AppConsentType   `json:"consent_type"`
	Scopes        []string         `json:"scopes"`
	Status        AppConsentStatus `json:"status"`
	GrantedAt     time.Time        `json:"granted_at"`
	RevokedAt     *time.Time       `json:"revoked_at,omitempty"`
}

// ToResponse converts an AppConsent to its API response form.
func (c *AppConsent) ToResponse() AppConsentResponse {
	return AppConsentResponse{
		ID:            c.ID,
		ApplicationID: c.ApplicationID,
		TenantID:      c.TenantID,
		ConsentedBy:   c.ConsentedBy,
		ConsentType:   c.ConsentType,
		Scopes:        c.Scopes,
		Status:        c.Status,
		GrantedAt:     c.GrantedAt,
		RevokedAt:     c.RevokedAt,
	}
}

// GrantConsentRequest is the payload for granting consent.
// TenantID and ConsentType are optional — the handler falls back to the
// authenticated user's tenant and "admin" consent type when omitted.
type GrantConsentRequest struct {
	TenantID    uuid.UUID      `json:"tenant_id"`
	ConsentType AppConsentType `json:"consent_type" binding:"omitempty,oneof=admin user"`
	Scopes      []string       `json:"scopes"`
}

// AppConsentListResponse is the paginated list of consents.
type AppConsentListResponse struct {
	Consents []AppConsentResponse `json:"consents"`
	Total    int                  `json:"total"`
}
