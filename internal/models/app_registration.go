// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AppRegistrationStatus represents the operational state of an app registration.
type AppRegistrationStatus string

const (
	// AppRegistrationStatusActive indicates the registration is valid and usable.
	AppRegistrationStatusActive AppRegistrationStatus = "active"
	// AppRegistrationStatusSuspended indicates the registration has been temporarily disabled.
	AppRegistrationStatusSuspended AppRegistrationStatus = "suspended"
	// AppRegistrationStatusRevoked indicates the registration has been permanently cancelled.
	AppRegistrationStatusRevoked AppRegistrationStatus = "revoked"
)

// AppRegistration represents an OAuth-style client registration that belongs to
// a tenant and is optionally linked to a product in the product registry.
// It is used by both SaaS frontends and embedded licensed-product clients.
type AppRegistration struct {
	ID               uuid.UUID             `json:"id" db:"id"`
	ProductID        *uuid.UUID            `json:"product_id,omitempty" db:"product_id"`
	TenantID         uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	ClientID         string                `json:"client_id" db:"client_id"`
	ClientSecretHash string                `json:"-" db:"client_secret_hash"` // Hashed, never exposed
	Name             string                `json:"name" db:"name"`
	Description      *string               `json:"description,omitempty" db:"description"`
	RedirectURIs     []string              `json:"redirect_uris" db:"redirect_uris"`
	AllowedOrigins   []string              `json:"allowed_origins" db:"allowed_origins"`
	GrantTypes       []string              `json:"grant_types" db:"grant_types"`
	Scopes           []string              `json:"scopes" db:"scopes"`
	LogoURL          *string               `json:"logo_url,omitempty" db:"logo_url"`
	Status           AppRegistrationStatus `json:"status" db:"status"`
	CreatedBy        *uuid.UUID            `json:"created_by,omitempty" db:"created_by"`
	CreatedAt        time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at" db:"updated_at"`
}

// IsActive returns true when the app registration is in the active state.
func (a *AppRegistration) IsActive() bool {
	return a.Status == AppRegistrationStatusActive
}

// IsSuspended returns true when the app registration has been temporarily disabled.
func (a *AppRegistration) IsSuspended() bool {
	return a.Status == AppRegistrationStatusSuspended
}

// IsRevoked returns true when the app registration has been permanently cancelled.
func (a *AppRegistration) IsRevoked() bool {
	return a.Status == AppRegistrationStatusRevoked
}

// ==================== Request DTOs ====================

// CreateAppRegistrationRequest is the payload for registering a new application.
type CreateAppRegistrationRequest struct {
	ProductID      *uuid.UUID `json:"product_id"`
	Name           string     `json:"name" binding:"required,min=2,max=255"`
	Description    *string    `json:"description"`
	RedirectURIs   []string   `json:"redirect_uris" binding:"required,min=1"`
	AllowedOrigins []string   `json:"allowed_origins"`
	GrantTypes     []string   `json:"grant_types" binding:"required,min=1"`
	Scopes         []string   `json:"scopes"`
	LogoURL        *string    `json:"logo_url" binding:"omitempty,url"`
}

// UpdateAppRegistrationRequest is the payload for updating an existing app registration.
// All fields are optional to allow partial updates.
type UpdateAppRegistrationRequest struct {
	Name           *string                `json:"name" binding:"omitempty,min=2,max=255"`
	Description    *string                `json:"description"`
	RedirectURIs   []string               `json:"redirect_uris" binding:"omitempty,min=1"`
	AllowedOrigins []string               `json:"allowed_origins"`
	GrantTypes     []string               `json:"grant_types" binding:"omitempty,min=1"`
	Scopes         []string               `json:"scopes"`
	LogoURL        *string                `json:"logo_url" binding:"omitempty,url"`
	Status         *AppRegistrationStatus `json:"status" binding:"omitempty,oneof=active suspended revoked"`
}

// ==================== Response DTOs ====================

// AppRegistrationResponse is the API representation of an app registration.
// The client_secret field is omitted on normal reads; use ToResponseWithSecret
// to include it immediately after creation.
type AppRegistrationResponse struct {
	ID             uuid.UUID             `json:"id"`
	ProductID      *uuid.UUID            `json:"product_id,omitempty"`
	TenantID       uuid.UUID             `json:"tenant_id"`
	ClientID       string                `json:"client_id"`
	ClientSecret   *string               `json:"client_secret,omitempty"` // Only populated at creation
	Name           string                `json:"name"`
	Description    *string               `json:"description,omitempty"`
	RedirectURIs   []string              `json:"redirect_uris"`
	AllowedOrigins []string              `json:"allowed_origins"`
	GrantTypes     []string              `json:"grant_types"`
	Scopes         []string              `json:"scopes"`
	LogoURL        *string               `json:"logo_url,omitempty"`
	Status         AppRegistrationStatus `json:"status"`
	CreatedBy      *uuid.UUID            `json:"created_by,omitempty"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

// AppRegistrationListResponse is the paginated list of app registrations.
type AppRegistrationListResponse struct {
	AppRegistrations []AppRegistrationResponse `json:"app_registrations"`
	Total            int64                     `json:"total"`
	Page             int                       `json:"page"`
	PageSize         int                       `json:"page_size"`
	TotalPages       int                       `json:"total_pages"`
}

// ==================== Conversion methods ====================

// ToResponse converts an AppRegistration to its API response representation
// without the client secret. Use this for all reads after initial creation.
func (a *AppRegistration) ToResponse() *AppRegistrationResponse {
	return &AppRegistrationResponse{
		ID:             a.ID,
		ProductID:      a.ProductID,
		TenantID:       a.TenantID,
		ClientID:       a.ClientID,
		Name:           a.Name,
		Description:    a.Description,
		RedirectURIs:   a.RedirectURIs,
		AllowedOrigins: a.AllowedOrigins,
		GrantTypes:     a.GrantTypes,
		Scopes:         a.Scopes,
		LogoURL:        a.LogoURL,
		Status:         a.Status,
		CreatedBy:      a.CreatedBy,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
}

// ToResponseWithSecret converts an AppRegistration to its API response
// representation including the plain-text client secret. This must only be
// called once immediately after creation; the secret cannot be recovered later.
func (a *AppRegistration) ToResponseWithSecret(clientSecret string) *AppRegistrationResponse {
	resp := a.ToResponse()
	resp.ClientSecret = &clientSecret
	return resp
}
