// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// ServiceAccount represents a service account for machine-to-machine authentication
type ServiceAccount struct {
	ID                   uuid.UUID  `json:"id" db:"id"`
	TenantID             uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name                 string     `json:"name" db:"name"`
	Description          *string    `json:"description,omitempty" db:"description"`
	ClientID             string     `json:"client_id" db:"client_id"`
	ClientSecretHash     string     `json:"-" db:"client_secret_hash"`
	RoleIDs              []string   `json:"role_ids" db:"role_ids"`
	AllowedIPs           []string   `json:"allowed_ips,omitempty" db:"allowed_ips"`
	AllowedEndpoints     []string   `json:"allowed_endpoints,omitempty" db:"allowed_endpoints"`
	IsActive             bool       `json:"is_active" db:"is_active"`
	LastUsedAt           *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	LastUsedIP           *string    `json:"last_used_ip,omitempty" db:"last_used_ip"`
	TokenLifetimeMinutes int        `json:"token_lifetime_minutes" db:"token_lifetime_minutes"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy            *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// ServiceAccountToken represents an access token for a service account
type ServiceAccountToken struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	ServiceAccountID uuid.UUID  `json:"service_account_id" db:"service_account_id"`
	TokenHash        string     `json:"-" db:"token_hash"`
	IPAddress        *string    `json:"ip_address,omitempty" db:"ip_address"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// CreateServiceAccountRequest is the request to create a service account
type CreateServiceAccountRequest struct {
	Name                 string   `json:"name" validate:"required,min=1,max=100"`
	Description          *string  `json:"description,omitempty"`
	RoleIDs              []string `json:"role_ids" validate:"required,min=1"`
	AllowedIPs           []string `json:"allowed_ips,omitempty"`
	AllowedEndpoints     []string `json:"allowed_endpoints,omitempty"`
	TokenLifetimeMinutes *int     `json:"token_lifetime_minutes,omitempty" validate:"omitempty,min=1,max=1440"`
}

// UpdateServiceAccountRequest is the request to update a service account
type UpdateServiceAccountRequest struct {
	Name                 *string  `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Description          *string  `json:"description,omitempty"`
	RoleIDs              []string `json:"role_ids,omitempty"`
	AllowedIPs           []string `json:"allowed_ips,omitempty"`
	AllowedEndpoints     []string `json:"allowed_endpoints,omitempty"`
	IsActive             *bool    `json:"is_active,omitempty"`
	TokenLifetimeMinutes *int     `json:"token_lifetime_minutes,omitempty" validate:"omitempty,min=1,max=1440"`
}

// ServiceAccountResponse is the response for a service account (without secret)
type ServiceAccountResponse struct {
	ID                   uuid.UUID  `json:"id"`
	TenantID             uuid.UUID  `json:"tenant_id"`
	Name                 string     `json:"name"`
	Description          *string    `json:"description,omitempty"`
	ClientID             string     `json:"client_id"`
	RoleIDs              []string   `json:"role_ids"`
	AllowedIPs           []string   `json:"allowed_ips,omitempty"`
	AllowedEndpoints     []string   `json:"allowed_endpoints,omitempty"`
	IsActive             bool       `json:"is_active"`
	LastUsedAt           *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP           *string    `json:"last_used_ip,omitempty"`
	TokenLifetimeMinutes int        `json:"token_lifetime_minutes"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// ServiceAccountCreatedResponse includes the client secret (only shown once at creation)
type ServiceAccountCreatedResponse struct {
	ServiceAccountResponse
	ClientSecret string `json:"client_secret"` // Only shown at creation
}

// ToResponse converts a ServiceAccount to ServiceAccountResponse
func (s *ServiceAccount) ToResponse() *ServiceAccountResponse {
	return &ServiceAccountResponse{
		ID:                   s.ID,
		TenantID:             s.TenantID,
		Name:                 s.Name,
		Description:          s.Description,
		ClientID:             s.ClientID,
		RoleIDs:              s.RoleIDs,
		AllowedIPs:           s.AllowedIPs,
		AllowedEndpoints:     s.AllowedEndpoints,
		IsActive:             s.IsActive,
		LastUsedAt:           s.LastUsedAt,
		LastUsedIP:           s.LastUsedIP,
		TokenLifetimeMinutes: s.TokenLifetimeMinutes,
		CreatedAt:            s.CreatedAt,
		UpdatedAt:            s.UpdatedAt,
	}
}

// ServiceAccountTokenRequest is the OAuth2 client_credentials grant request
type ServiceAccountTokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" validate:"required,eq=client_credentials"`
	ClientID     string `json:"client_id" form:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" form:"client_secret" validate:"required"`
	Scope        string `json:"scope,omitempty" form:"scope"`
}

// ServiceAccountTokenResponse is the OAuth2 token response
type ServiceAccountTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds
	Scope       string `json:"scope,omitempty"`
}
