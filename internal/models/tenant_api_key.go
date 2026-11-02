// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantAPIKeyPrefix is the fixed prefix of every tenant API key
// (lgk_live_<key_id>_<secret>); the OAuth client_id is lgk_live_<key_id>.
const TenantAPIKeyPrefix = "lgk_live_"

// CreateTenantAPIKeyRequest is the body of POST /api/v1/developer/api-keys.
type CreateTenantAPIKeyRequest struct {
	Name        string      `json:"name"`
	Description *string     `json:"description,omitempty"`
	Access      string      `json:"access"` // read | write
	RoleIDs     []uuid.UUID `json:"role_ids"`
	CompanyIDs  []uuid.UUID `json:"company_ids"`
	// ExpiresAt defaults to one year out and may be at most two years out.
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	IPAllowlist []string   `json:"ip_allowlist,omitempty"`
}

// RotateTenantAPIKeyRequest is the optional body of the rotate action.
type RotateTenantAPIKeyRequest struct {
	// GraceHours keeps the previous secret valid for this long (0-168,
	// default 24). 0 revokes the old secret immediately.
	GraceHours *int `json:"grace_hours,omitempty"`
}

// TenantAPIKeyResponse is the credential-free view of a tenant API key.
type TenantAPIKeyResponse struct {
	ID               uuid.UUID   `json:"id"`
	ClientID         string      `json:"client_id"`
	Name             string      `json:"name"`
	Description      *string     `json:"description,omitempty"`
	Access           string      `json:"access"`
	RoleIDs          []uuid.UUID `json:"role_ids"`
	CompanyIDs       []uuid.UUID `json:"company_ids"`
	IPAllowlist      []string    `json:"ip_allowlist"`
	Status           string      `json:"status"` // active | revoked | expired
	CreatedAt        time.Time   `json:"created_at"`
	CreatedBy        *uuid.UUID  `json:"created_by,omitempty"`
	ExpiresAt        *time.Time  `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time  `json:"last_used_at,omitempty"`
	LastUsedIP       *string     `json:"last_used_ip,omitempty"`
	RotatedAt        *time.Time  `json:"rotated_at,omitempty"`
	GraceValidUntil  *time.Time  `json:"grace_valid_until,omitempty"`
	RevokedAt        *time.Time  `json:"revoked_at,omitempty"`
	CompanySyncState string      `json:"company_sync_state"`
}

// TenantAPIKeyCreatedResponse carries the full key, returned exactly once at
// creation and rotation.
type TenantAPIKeyCreatedResponse struct {
	TenantAPIKeyResponse
	Key string `json:"key"`
}

// APIKeyTokenRequest is the form/JSON body of POST /oauth/token/api-key.
// client_id is lgk_live_<key_id> and client_secret the secret half; a caller
// may instead send the whole key as client_id and omit client_secret.
type APIKeyTokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
}

// APIKeyTokenResponse is the OAuth2 token response of the API key exchange.
type APIKeyTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}
