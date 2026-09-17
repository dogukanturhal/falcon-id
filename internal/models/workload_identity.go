// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// WorkloadProviderType enumerates the supported workload identity provider kinds.
type WorkloadProviderType string

const (
	// ProviderTypeKubernetes is an exported identifier.
	ProviderTypeKubernetes WorkloadProviderType = "kubernetes"
	// ProviderTypeAWSSTS is an exported identifier.
	ProviderTypeAWSSTS WorkloadProviderType = "aws_sts"
	// ProviderTypeGCP is an exported identifier.
	ProviderTypeGCP WorkloadProviderType = "gcp"
	// ProviderTypeAzureAD is an exported identifier.
	ProviderTypeAzureAD WorkloadProviderType = "azure_ad"
	// ProviderTypeSPIFFE validates SPIFFE JWT-SVIDs issued by a SPIRE server or
	// any SPIFFE-compliant trust domain.  The issuer_url field holds the trust
	// domain URL (e.g. "https://spire.example.com") and jwks_endpoint optionally
	// overrides the default bundle endpoint derived from that trust domain.
	ProviderTypeSPIFFE WorkloadProviderType = "spiffe"
)

// WorkloadIdentityProvider represents a configured workload identity federation
// provider stored in workload_identity_providers.
type WorkloadIdentityProvider struct {
	ID              uuid.UUID            `json:"id"               db:"id"`
	TenantID        uuid.UUID            `json:"tenant_id"        db:"tenant_id"`
	Name            string               `json:"name"             db:"name"`
	ProviderType    WorkloadProviderType `json:"provider_type"    db:"provider_type"`
	IssuerURL       string               `json:"issuer_url"       db:"issuer_url"`
	AudienceMatch   *string              `json:"audience_match"   db:"audience_match"`
	SubjectMapping  *string              `json:"subject_mapping"  db:"subject_mapping"`
	JWKSEndpoint    *string              `json:"jwks_endpoint"    db:"jwks_endpoint"`
	AllowedSubjects []string             `json:"allowed_subjects" db:"allowed_subjects"`
	RoleBindings    []string             `json:"role_bindings"    db:"role_bindings"`
	IsActive        bool                 `json:"is_active"        db:"is_active"`
	ApplicationID   *uuid.UUID           `json:"application_id,omitempty" db:"application_id"`
	CreatedAt       time.Time            `json:"created_at"       db:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"       db:"updated_at"`
	CreatedBy       *uuid.UUID           `json:"created_by"       db:"created_by"`
	UpdatedBy       *uuid.UUID           `json:"updated_by"       db:"updated_by"`
}

// ============================================================
// Token Exchange DTOs (RFC 8693)
// ============================================================

// SubjectTokenType contains the recognised subject_token_type values for the
// OAuth 2.0 Token Exchange grant.
const (
	SubjectTokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          //nolint:gosec // not a credential, this is a workload identity type name constant
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // not a credential, this is a workload identity type name constant
	SubjectTokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"     //nolint:gosec // not a credential, this is a workload identity type name constant
	SubjectTokenTypeSAML2       = "urn:ietf:params:oauth:token-type:saml2"        //nolint:gosec // not a credential, this is a workload identity type name constant
	IssuedTokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // not a credential, this is a workload identity type name constant
)

// TokenExchangeRequest is the body of an OAuth 2.0 Token Exchange request
// (RFC 8693 §2.1).
type TokenExchangeRequest struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:token-exchange".
	GrantType string `json:"grant_type" form:"grant_type" binding:"required"`

	// SubjectToken is the external workload token being exchanged.
	SubjectToken string `json:"subject_token" form:"subject_token" binding:"required"`

	// SubjectTokenType identifies the type of SubjectToken.
	// Typically SubjectTokenTypeJWT for OIDC/JWTs.
	SubjectTokenType string `json:"subject_token_type" form:"subject_token_type" binding:"required"`

	// Scope is the requested scope for the issued token (space-delimited).
	Scope string `json:"scope" form:"scope"`

	// Audience restricts the audience of the issued token.
	Audience string `json:"audience" form:"audience"`

	// Resource is the URI of the target service.
	Resource string `json:"resource" form:"resource"`
}

// TokenExchangeResponse is the response body for a successful token exchange
// (RFC 8693 §2.2).
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type"`
}

// ============================================================
// CRUD DTOs
// ============================================================

// CreateWorkloadProviderRequest is the payload for creating a provider.
type CreateWorkloadProviderRequest struct {
	Name            string               `json:"name"             binding:"required,max=255"`
	ProviderType    WorkloadProviderType `json:"provider_type"    binding:"required"`
	IssuerURL       string               `json:"issuer_url"       binding:"required,url"`
	AudienceMatch   *string              `json:"audience_match"`
	SubjectMapping  *string              `json:"subject_mapping"`
	JWKSEndpoint    *string              `json:"jwks_endpoint"`
	AllowedSubjects []string             `json:"allowed_subjects"`
	RoleBindings    []string             `json:"role_bindings"`
	IsActive        *bool                `json:"is_active"`
}

// UpdateWorkloadProviderRequest is the payload for updating a provider.
// All fields are optional; only non-nil values are applied.
type UpdateWorkloadProviderRequest struct {
	Name            *string               `json:"name"`
	ProviderType    *WorkloadProviderType `json:"provider_type"`
	IssuerURL       *string               `json:"issuer_url"`
	AudienceMatch   *string               `json:"audience_match"`
	SubjectMapping  *string               `json:"subject_mapping"`
	JWKSEndpoint    *string               `json:"jwks_endpoint"`
	AllowedSubjects []string              `json:"allowed_subjects"`
	RoleBindings    []string              `json:"role_bindings"`
	IsActive        *bool                 `json:"is_active"`
}

// WorkloadProviderListResponse is the paginated list response.
type WorkloadProviderListResponse struct {
	Providers []*WorkloadIdentityProvider `json:"providers"`
	Total     int64                       `json:"total"`
	Page      int                         `json:"page"`
	PageSize  int                         `json:"page_size"`
}

// TestProviderRequest is the payload for the test endpoint.
type TestProviderRequest struct {
	// SubjectToken is a real workload token to validate against this provider.
	SubjectToken string `json:"subject_token" binding:"required"`
}

// TestProviderResponse carries the result of a provider connectivity/validation test.
type TestProviderResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Claims  map[string]interface{} `json:"claims,omitempty"`
}
