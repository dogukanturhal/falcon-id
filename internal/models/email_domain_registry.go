// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// VerificationMethod enumerates the supported domain ownership verification approaches.
type VerificationMethod string

const (
	// VerificationMethodDNSTXT is an exported identifier.
	VerificationMethodDNSTXT VerificationMethod = "dns_txt"
	// VerificationMethodDNSCNAME is an exported identifier.
	VerificationMethodDNSCNAME VerificationMethod = "dns_cname"
	// VerificationMethodHTTPFile is an exported identifier.
	VerificationMethodHTTPFile VerificationMethod = "http_file"
)

// EmailDomainRegistry records a tenant's claimed and verified email domains.
// Domains are used for Home Realm Discovery: when a user logs in with an email
// matching a verified domain, the system can route them to the correct tenant
// and enforce the appropriate authentication policy (e.g. SSO).
type EmailDomainRegistry struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	TenantID           uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Domain             string     `json:"domain" db:"domain"`
	IsVerified         bool       `json:"is_verified" db:"is_verified"`
	VerificationToken  *string    `json:"-" db:"verification_token"` // Never expose token
	VerificationMethod string     `json:"verification_method" db:"verification_method"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	AutoEnroll         bool       `json:"auto_enroll" db:"auto_enroll"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// CreateEmailDomainRequest is the request to register a new email domain for a tenant.
type CreateEmailDomainRequest struct {
	Domain     string `json:"domain" binding:"required"`
	AutoEnroll bool   `json:"auto_enroll"`
}

// UpdateEmailDomainRequest is the request to update a domain registration.
type UpdateEmailDomainRequest struct {
	AutoEnroll *bool `json:"auto_enroll" binding:"required"`
}

// VerifyDomainRequest is the request to initiate domain ownership verification.
// The method chosen determines how the verification token must be presented.
type VerifyDomainRequest struct {
	VerificationMethod string `json:"verification_method" binding:"required,oneof=dns_txt dns_cname http_file"`
}
