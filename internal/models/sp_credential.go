// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SPCredentialType represents the type of credential.
type SPCredentialType string

const (
	// SPCredentialTypeRSAKey is an exported identifier.
	SPCredentialTypeRSAKey SPCredentialType = "rsa_key"
	// SPCredentialTypeClientSecret is an exported identifier.
	SPCredentialTypeClientSecret SPCredentialType = "client_secret"
	// SPCredentialTypeCertificate is an exported identifier.
	SPCredentialTypeCertificate SPCredentialType = "x509_certificate"
)

// SPCredentialStatus represents the lifecycle state of a credential.
type SPCredentialStatus string

const (
	// SPCredentialStatusActive is an exported identifier.
	SPCredentialStatusActive SPCredentialStatus = "active"
	// SPCredentialStatusExpired is an exported identifier.
	SPCredentialStatusExpired SPCredentialStatus = "expired"
	// SPCredentialStatusRevoked is an exported identifier.
	SPCredentialStatusRevoked SPCredentialStatus = "revoked"
)

// SPCredential represents a credential stored for a service principal.
type SPCredential struct {
	ID               uuid.UUID          `json:"id" db:"id"`
	SPID             uuid.UUID          `json:"sp_id" db:"sp_id"`
	CredentialType   SPCredentialType   `json:"credential_type" db:"credential_type"`
	KeyID            *string            `json:"key_id,omitempty" db:"key_id"`
	PublicKeyPEM     *string            `json:"-" db:"public_key_pem"`
	SecretHash       *string            `json:"-" db:"secret_hash"`
	DisplayHint      *string            `json:"display_hint,omitempty" db:"display_hint"`
	Status           SPCredentialStatus `json:"status" db:"status"`
	ExpiresAt        *time.Time         `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt        time.Time          `json:"created_at" db:"created_at"`
	RevokedAt        *time.Time         `json:"revoked_at,omitempty" db:"revoked_at"`
	LastUsedAt       *time.Time         `json:"last_used_at,omitempty" db:"last_used_at"`
	ThumbprintSHA1   *string            `json:"thumbprint_sha1,omitempty" db:"thumbprint_sha1"`
	ThumbprintSHA256 *string            `json:"thumbprint_sha256,omitempty" db:"thumbprint_sha256"`
	Subject          *string            `json:"subject,omitempty" db:"subject"`
	Issuer           *string            `json:"issuer,omitempty" db:"issuer"`
	SerialNumber     *string            `json:"serial_number,omitempty" db:"serial_number"`
	NotBefore        *time.Time         `json:"not_before,omitempty" db:"not_before"`
}

// SPCredentialResponse is the API response for a credential (secrets never exposed).
type SPCredentialResponse struct {
	ID               uuid.UUID          `json:"id"`
	SPID             uuid.UUID          `json:"sp_id"`
	CredentialType   SPCredentialType   `json:"credential_type"`
	KeyID            *string            `json:"key_id,omitempty"`
	DisplayHint      *string            `json:"display_hint,omitempty"`
	Status           SPCredentialStatus `json:"status"`
	ExpiresAt        *time.Time         `json:"expires_at,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	RevokedAt        *time.Time         `json:"revoked_at,omitempty"`
	LastUsedAt       *time.Time         `json:"last_used_at,omitempty"`
	ThumbprintSHA1   *string            `json:"thumbprint_sha1,omitempty"`
	ThumbprintSHA256 *string            `json:"thumbprint_sha256,omitempty"`
	Subject          *string            `json:"subject,omitempty"`
	Issuer           *string            `json:"issuer,omitempty"`
	SerialNumber     *string            `json:"serial_number,omitempty"`
	NotBefore        *time.Time         `json:"not_before,omitempty"`
}

// ToResponse converts an SPCredential to its API response form.
func (c *SPCredential) ToResponse() SPCredentialResponse {
	return SPCredentialResponse{
		ID:               c.ID,
		SPID:             c.SPID,
		CredentialType:   c.CredentialType,
		KeyID:            c.KeyID,
		DisplayHint:      c.DisplayHint,
		Status:           c.Status,
		ExpiresAt:        c.ExpiresAt,
		CreatedAt:        c.CreatedAt,
		RevokedAt:        c.RevokedAt,
		LastUsedAt:       c.LastUsedAt,
		ThumbprintSHA1:   c.ThumbprintSHA1,
		ThumbprintSHA256: c.ThumbprintSHA256,
		Subject:          c.Subject,
		Issuer:           c.Issuer,
		SerialNumber:     c.SerialNumber,
		NotBefore:        c.NotBefore,
	}
}

// AddSPCredentialRequest is the payload for adding a credential.
type AddSPCredentialRequest struct {
	CredentialType SPCredentialType `json:"credential_type" binding:"required,oneof=rsa_key client_secret x509_certificate"`
	ExpiresAt      *time.Time       `json:"expires_at"`
	CertificatePEM *string          `json:"certificate_pem,omitempty"`
}

// AddSPCredentialResponse includes the one-time secret or private key.
type AddSPCredentialResponse struct {
	Credential      SPCredentialResponse `json:"credential"`
	ClientSecret    *string              `json:"client_secret,omitempty"`
	PrivateKey      *string              `json:"private_key,omitempty"`
	CertificateInfo *CertificateInfo     `json:"certificate_info,omitempty"`
}

// CertificateInfo holds the parsed metadata from an uploaded X.509 certificate.
type CertificateInfo struct {
	Subject          string    `json:"subject"`
	Issuer           string    `json:"issuer"`
	SerialNumber     string    `json:"serial_number"`
	ThumbprintSHA1   string    `json:"thumbprint_sha1"`
	ThumbprintSHA256 string    `json:"thumbprint_sha256"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
}
