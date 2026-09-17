// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// FederatedAccount links a user to an external identity provider account
type FederatedAccount struct {
	ID         uuid.UUID `json:"id" db:"id"`
	UserID     uuid.UUID `json:"user_id" db:"user_id"`
	ProviderID uuid.UUID `json:"provider_id" db:"provider_id"`

	// Provider account information
	ProviderUserID   string  `json:"provider_user_id" db:"provider_user_id"`             // External user ID (e.g., Google sub, GitHub id)
	ProviderUsername *string `json:"provider_username,omitempty" db:"provider_username"` // Username at provider
	ProviderEmail    *string `json:"provider_email,omitempty" db:"provider_email"`       // Email at provider

	// OAuth2 tokens (encrypted in database)
	AccessToken    *string    `json:"-" db:"access_token"`
	RefreshToken   *string    `json:"-" db:"refresh_token"`
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty" db:"token_expires_at"`

	// Additional profile data from provider
	ProfileData map[string]interface{} `json:"profile_data,omitempty" db:"profile_data"` // JSON

	// Metadata
	FirstLinkedAt time.Time  `json:"first_linked_at" db:"first_linked_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`

	// Related data (not in DB)
	Provider *IdentityProvider `json:"provider,omitempty"`
}

// FederatedAccountResponse for API responses
type FederatedAccountResponse struct {
	ID               uuid.UUID                 `json:"id"`
	UserID           uuid.UUID                 `json:"user_id"`
	ProviderID       uuid.UUID                 `json:"provider_id"`
	ProviderUserID   string                    `json:"provider_user_id"`
	ProviderUsername *string                   `json:"provider_username,omitempty"`
	ProviderEmail    *string                   `json:"provider_email,omitempty"`
	ProfileData      map[string]interface{}    `json:"profile_data,omitempty"`
	FirstLinkedAt    time.Time                 `json:"first_linked_at"`
	LastUsedAt       *time.Time                `json:"last_used_at,omitempty"`
	Provider         *IdentityProviderResponse `json:"provider,omitempty"`
}

// ToResponse converts FederatedAccount to response format
func (fa *FederatedAccount) ToResponse() *FederatedAccountResponse {
	resp := &FederatedAccountResponse{
		ID:               fa.ID,
		UserID:           fa.UserID,
		ProviderID:       fa.ProviderID,
		ProviderUserID:   fa.ProviderUserID,
		ProviderUsername: fa.ProviderUsername,
		ProviderEmail:    fa.ProviderEmail,
		ProfileData:      fa.ProfileData,
		FirstLinkedAt:    fa.FirstLinkedAt,
		LastUsedAt:       fa.LastUsedAt,
	}

	if fa.Provider != nil {
		resp.Provider = fa.Provider.ToResponse()
	}

	return resp
}
