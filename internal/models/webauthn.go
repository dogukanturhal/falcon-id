// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// WebAuthnCredential represents a stored WebAuthn passkey credential for a user.
// The raw credential bytes (CredentialID, PublicKey, AAGUID) are intentionally
// omitted from the JSON serialisation to prevent accidental exposure via the API.
type WebAuthnCredential struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	UserID          uuid.UUID  `json:"user_id" db:"user_id"`
	TenantID        uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	CredentialID    []byte     `json:"-" db:"credential_id"` // raw bytes, not exposed in API
	PublicKey       []byte     `json:"-" db:"public_key"`
	AttestationType string     `json:"attestation_type" db:"attestation_type"`
	Transport       []string   `json:"transport" db:"transport"`
	SignCount       uint32     `json:"sign_count" db:"sign_count"`
	AAGUID          []byte     `json:"-" db:"aaguid"`
	CloneWarning    bool       `json:"clone_warning" db:"clone_warning"`
	FriendlyName    string     `json:"friendly_name" db:"friendly_name"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`

	// Discoverable / passkey fields (added by migration 153).
	// IsDiscoverable reflects whether the authenticator stored the credential as a
	// resident key, making it usable in passwordless / conditional-UI flows.
	IsDiscoverable bool `json:"is_discoverable" db:"is_discoverable"`
	// BackupEligible is true when the authenticator can synchronise the credential
	// to a backup service (e.g. iCloud Keychain, Google Password Manager).
	BackupEligible bool `json:"backup_eligible" db:"backup_eligible"`
	// BackupState is true when the credential is currently backed up.
	BackupState bool `json:"backup_state" db:"backup_state"`

	// Lifecycle fields (added by migration 153).
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedBy *uuid.UUID `json:"revoked_by,omitempty" db:"revoked_by"`
}

// IsActive returns false when the credential has been explicitly revoked or has
// passed its optional expiry time.
func (c *WebAuthnCredential) IsActive() bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && time.Now().UTC().After(*c.ExpiresAt) {
		return false
	}
	return true
}

// WebAuthnCredentialResponse is the safe, outward-facing API representation of a
// WebAuthnCredential. It strips all cryptographic material.
type WebAuthnCredentialResponse struct {
	ID              uuid.UUID  `json:"id"`
	FriendlyName    string     `json:"friendly_name"`
	AttestationType string     `json:"attestation_type"`
	Transport       []string   `json:"transport"`
	SignCount       uint32     `json:"sign_count"`
	CloneWarning    bool       `json:"clone_warning"`
	IsDiscoverable  bool       `json:"is_discoverable"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// ToResponse converts a WebAuthnCredential to its API-safe representation.
func (c *WebAuthnCredential) ToResponse() *WebAuthnCredentialResponse {
	return &WebAuthnCredentialResponse{
		ID:              c.ID,
		FriendlyName:    c.FriendlyName,
		AttestationType: c.AttestationType,
		Transport:       c.Transport,
		SignCount:       c.SignCount,
		CloneWarning:    c.CloneWarning,
		IsDiscoverable:  c.IsDiscoverable,
		BackupEligible:  c.BackupEligible,
		BackupState:     c.BackupState,
		LastUsedAt:      c.LastUsedAt,
		ExpiresAt:       c.ExpiresAt,
		RevokedAt:       c.RevokedAt,
		CreatedAt:       c.CreatedAt,
	}
}

// RegisterWebAuthnRequest is the request body used to initiate passkey registration.
// FriendlyName is the human-readable label the user assigns to the authenticator
// (e.g., "YubiKey 5", "iPhone Face ID").
type RegisterWebAuthnRequest struct {
	FriendlyName string `json:"friendly_name" binding:"required,min=1,max=255"`
}

// AttestationPolicy describes the enterprise security constraints applied to
// WebAuthn credential registration within a tenant. The zero value is permissive
// (all authenticators accepted, no limit enforced).
type AttestationPolicy struct {
	// AllowedAAGUIDs restricts registration to specific authenticator models
	// identified by their AAGUID (UUID string, e.g. "2fc0579f-8113-47ea-b116-bb5a8db9202a").
	// An empty slice means all authenticators are permitted.
	AllowedAAGUIDs []string `json:"allowed_aaguids"`

	// BlockSyncedPasskeys rejects credentials where the authenticator reports
	// backup_eligible=true. This prevents cloud-synced passkeys (iCloud Keychain,
	// Google Password Manager) from being registered — suitable for high-assurance
	// deployments that require hardware-bound credentials.
	BlockSyncedPasskeys bool `json:"block_synced_passkeys"`

	// RequireAttestation rejects credentials whose attestation_type is "none".
	// When true the client must present a verifiable attestation statement.
	RequireAttestation bool `json:"require_attestation"`

	// MaxCredentialsPerUser caps the number of active credentials a single user
	// may register within this tenant. Zero means no cap is enforced.
	// The recommended production default is 10.
	MaxCredentialsPerUser int `json:"max_credentials_per_user"`
}

// DefaultAttestationPolicy returns a sensible default policy for new tenants:
// all authenticators accepted, no synced-passkey block, attestation optional,
// and a cap of 10 credentials per user.
func DefaultAttestationPolicy() AttestationPolicy {
	return AttestationPolicy{
		MaxCredentialsPerUser: 10,
	}
}
