// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// SAMLServiceProvider represents a SAML Service Provider that trusts this IDP
type SAMLServiceProvider struct {
	ID                uuid.UUID `json:"id" db:"id"`
	TenantID          uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Name              string    `json:"name" db:"name"`
	EntityID          string    `json:"entity_id" db:"entity_id"`
	ACSURL            string    `json:"acs_url" db:"acs_url"`                     // Assertion Consumer Service URL
	SLOURL            *string   `json:"slo_url,omitempty" db:"slo_url"`           // Single Logout URL
	MetadataURL       *string   `json:"metadata_url,omitempty" db:"metadata_url"` // SP metadata URL
	Certificate       *string   `json:"certificate,omitempty" db:"certificate"`   // SP's public certificate for encrypted assertions
	NameIDFormat      string    `json:"name_id_format" db:"name_id_format"`
	SignAssertions    bool      `json:"sign_assertions" db:"sign_assertions"`
	EncryptAssertions bool      `json:"encrypt_assertions" db:"encrypt_assertions"`
	AttributeMapping  JSONMap   `json:"attribute_mapping" db:"attribute_mapping"`
	AllowedAttributes []string  `json:"allowed_attributes" db:"allowed_attributes"`
	IsActive          bool      `json:"is_active" db:"is_active"`

	// Metadata discovery fields
	RawMetadataXML             *string    `json:"raw_metadata_xml,omitempty" db:"raw_metadata_xml"`
	MetadataLastFetched        *time.Time `json:"metadata_last_fetched,omitempty" db:"metadata_last_fetched"`
	MetadataAutoRefresh        bool       `json:"metadata_auto_refresh" db:"metadata_auto_refresh"`
	MetadataRefreshIntervalHrs int        `json:"metadata_refresh_interval_hours" db:"metadata_refresh_interval_hours"`
	DetectedIDPType            *string    `json:"detected_idp_type,omitempty" db:"detected_idp_type"`
	OrganizationName           *string    `json:"organization_name,omitempty" db:"organization_name"`
	CertificateExpiry          *time.Time `json:"certificate_expiry,omitempty" db:"certificate_expiry"`
	MetadataImportSource       string     `json:"metadata_import_source" db:"metadata_import_source"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

// SAMLAssertionLog represents a log entry for SAML assertions (for debugging/audit)
type SAMLAssertionLog struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	SPID         uuid.UUID  `json:"sp_id" db:"sp_id"`
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	AssertionID  string     `json:"assertion_id" db:"assertion_id"`
	NameID       string     `json:"name_id" db:"name_id"`
	IPAddress    string     `json:"ip_address" db:"ip_address"`
	UserAgent    string     `json:"user_agent" db:"user_agent"`
	Status       string     `json:"status" db:"status"` // success, failed
	ErrorMessage *string    `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// JSONMap is a helper type for JSONB columns
type JSONMap map[string]interface{}

// ==================== SAML Name ID Formats ====================

const (
	// NameIDFormatUnspecified is an exported identifier.
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	// NameIDFormatEmailAddress is an exported identifier.
	NameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	// NameIDFormatPersistent is an exported identifier.
	NameIDFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// NameIDFormatTransient is an exported identifier.
	NameIDFormatTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	// NameIDFormatX509Subject is an exported identifier.
	NameIDFormatX509Subject = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
	// NameIDFormatWindowsDomain is an exported identifier.
	NameIDFormatWindowsDomain = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
)

// ==================== Request/Response DTOs ====================

// CreateSAMLServiceProviderRequest for creating a new SAML SP
type CreateSAMLServiceProviderRequest struct {
	Name              string            `json:"name" binding:"required,min=2,max=100"`
	EntityID          string            `json:"entity_id" binding:"required,max=500"`
	ACSURL            string            `json:"acs_url" binding:"required,url"`
	SLOURL            *string           `json:"slo_url" binding:"omitempty,url"`
	MetadataURL       *string           `json:"metadata_url" binding:"omitempty,url"`
	Certificate       *string           `json:"certificate"`
	NameIDFormat      string            `json:"name_id_format"`
	SignAssertions    *bool             `json:"sign_assertions"`
	EncryptAssertions *bool             `json:"encrypt_assertions"`
	AttributeMapping  map[string]string `json:"attribute_mapping"`
	AllowedAttributes []string          `json:"allowed_attributes"`
}

// UpdateSAMLServiceProviderRequest for updating a SAML SP
type UpdateSAMLServiceProviderRequest struct {
	Name              *string           `json:"name" binding:"omitempty,min=2,max=100"`
	EntityID          *string           `json:"entity_id" binding:"omitempty,max=500"`
	ACSURL            *string           `json:"acs_url" binding:"omitempty,url"`
	SLOURL            *string           `json:"slo_url" binding:"omitempty,url"`
	MetadataURL       *string           `json:"metadata_url" binding:"omitempty,url"`
	Certificate       *string           `json:"certificate"`
	NameIDFormat      *string           `json:"name_id_format"`
	SignAssertions    *bool             `json:"sign_assertions"`
	EncryptAssertions *bool             `json:"encrypt_assertions"`
	AttributeMapping  map[string]string `json:"attribute_mapping"`
	AllowedAttributes []string          `json:"allowed_attributes"`
	IsActive          *bool             `json:"is_active"`
}

// SAMLServiceProviderResponse for API responses
type SAMLServiceProviderResponse struct {
	ID                uuid.UUID         `json:"id"`
	TenantID          uuid.UUID         `json:"tenant_id"`
	Name              string            `json:"name"`
	EntityID          string            `json:"entity_id"`
	ACSURL            string            `json:"acs_url"`
	SLOURL            *string           `json:"slo_url,omitempty"`
	MetadataURL       *string           `json:"metadata_url,omitempty"`
	HasCertificate    bool              `json:"has_certificate"`
	NameIDFormat      string            `json:"name_id_format"`
	SignAssertions    bool              `json:"sign_assertions"`
	EncryptAssertions bool              `json:"encrypt_assertions"`
	AttributeMapping  map[string]string `json:"attribute_mapping"`
	AllowedAttributes []string          `json:"allowed_attributes"`
	IsActive          bool              `json:"is_active"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// SAMLServiceProviderListResponse for list endpoints
type SAMLServiceProviderListResponse struct {
	ServiceProviders []SAMLServiceProviderResponse `json:"service_providers"`
	Total            int64                         `json:"total"`
}

// SAMLMetadataResponse for IDP metadata
type SAMLMetadataResponse struct {
	EntityID      string   `json:"entity_id"`
	SSOURL        string   `json:"sso_url"`
	SLOURL        string   `json:"slo_url"`
	Certificate   string   `json:"certificate"`
	NameIDFormats []string `json:"name_id_formats"`
}

// SAMLAuthnRequest represents an incoming SAML authentication request
type SAMLAuthnRequest struct {
	ID                   string `json:"id"`
	IssueInstant         string `json:"issue_instant"`
	Issuer               string `json:"issuer"`
	AssertionConsumerURL string `json:"assertion_consumer_url"`
	Destination          string `json:"destination"`
	NameIDPolicy         string `json:"name_id_policy"`
	ForceAuthn           bool   `json:"force_authn"`
	IsPassive            bool   `json:"is_passive"`
	RelayState           string `json:"relay_state"`
}

// SAMLAssertion represents a SAML assertion to be sent to the SP
type SAMLAssertion struct {
	ID                  string
	IssueInstant        time.Time
	Issuer              string
	Subject             string
	SubjectNameIDFormat string
	Audience            string
	Recipient           string
	SessionIndex        string
	SessionNotOnOrAfter time.Time
	NotBefore           time.Time
	NotOnOrAfter        time.Time
	Attributes          map[string][]string
	InResponseTo        string
}

// ToResponse converts SAMLServiceProvider to SAMLServiceProviderResponse
func (sp *SAMLServiceProvider) ToResponse() *SAMLServiceProviderResponse {
	attrMapping := make(map[string]string)
	if sp.AttributeMapping != nil {
		for k, v := range sp.AttributeMapping {
			if str, ok := v.(string); ok {
				attrMapping[k] = str
			}
		}
	}

	return &SAMLServiceProviderResponse{
		ID:                sp.ID,
		TenantID:          sp.TenantID,
		Name:              sp.Name,
		EntityID:          sp.EntityID,
		ACSURL:            sp.ACSURL,
		SLOURL:            sp.SLOURL,
		MetadataURL:       sp.MetadataURL,
		HasCertificate:    sp.Certificate != nil && *sp.Certificate != "",
		NameIDFormat:      sp.NameIDFormat,
		SignAssertions:    sp.SignAssertions,
		EncryptAssertions: sp.EncryptAssertions,
		AttributeMapping:  attrMapping,
		AllowedAttributes: sp.AllowedAttributes,
		IsActive:          sp.IsActive,
		CreatedAt:         sp.CreatedAt,
		UpdatedAt:         sp.UpdatedAt,
	}
}

// DefaultAttributeMapping returns the default SAML attribute mapping
func DefaultAttributeMapping() map[string]string {
	return map[string]string{
		"email":       "email",
		"firstName":   "first_name",
		"lastName":    "last_name",
		"displayName": "display_name",
	}
}

// DefaultAllowedAttributes returns the default allowed SAML attributes
func DefaultAllowedAttributes() []string {
	return []string{"email", "firstName", "lastName", "displayName", "groups"}
}
