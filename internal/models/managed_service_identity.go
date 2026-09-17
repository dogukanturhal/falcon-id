// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// BootstrapToken is a one-time credential that allows a service to self-register
// with Falcon-ID and receive its RSA private key without manual admin intervention.
type BootstrapToken struct {
	ID            uuid.UUID `json:"id"           db:"id"`
	TokenHash     string    `json:"-"            db:"token_hash"` // SHA-256 of raw token; never expose
	ServiceSlug   string    `json:"service_slug" db:"service_slug"`
	AllowedScopes []string  `json:"allowed_scopes" db:"allowed_scopes"`
	IPAllowlist   []string  `json:"ip_allowlist"  db:"ip_allowlist"`
	MaxUses       int       `json:"max_uses"      db:"max_uses"`
	UsedCount     int       `json:"used_count"    db:"used_count"`
	ExpiresAt     time.Time `json:"expires_at"    db:"expires_at"`
	CreatedBy     uuid.UUID `json:"created_by"    db:"created_by"`
	CreatedAt     time.Time `json:"created_at"    db:"created_at"`
}

// IsExhausted returns true when the token has reached its maximum usage count.
func (bt *BootstrapToken) IsExhausted() bool {
	return bt.UsedCount >= bt.MaxUses
}

// IsExpired returns true when the token has passed its expiry timestamp.
func (bt *BootstrapToken) IsExpired() bool {
	return time.Now().After(bt.ExpiresAt)
}

// IsValid returns true when the token is neither expired nor exhausted.
func (bt *BootstrapToken) IsValid() bool {
	return !bt.IsExpired() && !bt.IsExhausted()
}

// BootstrapTokenResponse is the API representation of a bootstrap token.
// The raw token value is included only at creation time.
type BootstrapTokenResponse struct {
	ID            uuid.UUID `json:"id"`
	ServiceSlug   string    `json:"service_slug"`
	AllowedScopes []string  `json:"allowed_scopes"`
	IPAllowlist   []string  `json:"ip_allowlist"`
	MaxUses       int       `json:"max_uses"`
	UsedCount     int       `json:"used_count"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedBy     uuid.UUID `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	// RawToken is populated only in the CreateBootstrapToken response.
	RawToken string `json:"token,omitempty"`
}

// ToResponse converts a BootstrapToken to its API response form.
func (bt *BootstrapToken) ToResponse() BootstrapTokenResponse {
	return BootstrapTokenResponse{
		ID:            bt.ID,
		ServiceSlug:   bt.ServiceSlug,
		AllowedScopes: bt.AllowedScopes,
		IPAllowlist:   bt.IPAllowlist,
		MaxUses:       bt.MaxUses,
		UsedCount:     bt.UsedCount,
		ExpiresAt:     bt.ExpiresAt,
		CreatedBy:     bt.CreatedBy,
		CreatedAt:     bt.CreatedAt,
	}
}

// BootstrapTokenRequest is sent by a service at startup to register itself
// with Falcon-ID using a one-time bootstrap token.
type BootstrapTokenRequest struct {
	BootstrapToken string            `json:"bootstrap_token" binding:"required"`
	ServiceSlug    string            `json:"service_slug"    binding:"required"`
	ServiceVersion string            `json:"service_version"`
	Endpoints      []ServiceEndpoint `json:"endpoints"`
	Events         []ServiceEvent    `json:"events"`
}

// BootstrapRegistrationResponse is an exported identifier.
// BootstrapTokenResponse is an exported identifier.
// BootstrapTokenResponse is an exported identifier.
// BootstrapTokenResponse is the payload returned after a successful bootstrap.
// The private key is returned exactly once; the service must store it securely.
type BootstrapRegistrationResponse struct {
	ServicePrincipalID uuid.UUID `json:"service_principal_id"`
	PrivateKeyPEM      string    `json:"private_key_pem"`
	KeyID              string    `json:"key_id"`
	TokenEndpoint      string    `json:"token_endpoint"`
	ExpiresIn          int       `json:"expires_in"` // seconds until key rotation required
}

// ServiceHeartbeatRequest is sent by a managed service at regular intervals
// to signal that it is still alive and healthy.
type ServiceHeartbeatRequest struct {
	ServiceSlug    string            `json:"service_slug"    binding:"required"`
	ServiceVersion string            `json:"service_version"`
	HealthStatus   string            `json:"health_status"` // healthy / degraded / unhealthy
	Metadata       map[string]string `json:"metadata"`
}

// CreateBootstrapTokenRequest is the payload for creating a new bootstrap token.
type CreateBootstrapTokenRequest struct {
	ServiceSlug    string   `json:"service_slug"      binding:"required"`
	AllowedScopes  []string `json:"allowed_scopes"`
	IPAllowlist    []string `json:"ip_allowlist"`
	ExpiresInHours int      `json:"expires_in_hours"  binding:"required,min=1,max=720"`
	MaxUses        int      `json:"max_uses"          binding:"omitempty,min=1"`
}
