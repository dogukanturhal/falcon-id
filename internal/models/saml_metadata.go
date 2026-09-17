// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/xml"
	"time"

	"github.com/google/uuid"
)

// ==================== XML Parsing Structs ====================

// SAMLEntityDescriptor represents a SAML metadata EntityDescriptor
type SAMLEntityDescriptor struct {
	XMLName          xml.Name              `xml:"EntityDescriptor"`
	EntityID         string                `xml:"entityID,attr"`
	ValidUntil       string                `xml:"validUntil,attr,omitempty"`
	IDPSSODescriptor *SAMLIDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
	SPSSODescriptor  *SAMLSPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	Organization     *SAMLOrganization     `xml:"Organization,omitempty"`
	ContactPerson    []SAMLContactPerson   `xml:"ContactPerson,omitempty"`
}

// SAMLIDPSSODescriptor represents the IDPSSODescriptor element
type SAMLIDPSSODescriptor struct {
	WantAuthnRequestsSigned string                    `xml:"WantAuthnRequestsSigned,attr,omitempty"`
	ProtocolSupportEnum     string                    `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors          []SAMLKeyDescriptor       `xml:"KeyDescriptor"`
	NameIDFormats           []string                  `xml:"NameIDFormat"`
	SingleSignOnServices    []SAMLSingleSignOnService `xml:"SingleSignOnService"`
	SingleLogoutServices    []SAMLSingleLogoutService `xml:"SingleLogoutService"`
}

// SAMLSPSSODescriptor represents the SPSSODescriptor element
type SAMLSPSSODescriptor struct {
	AuthnRequestsSigned       string                         `xml:"AuthnRequestsSigned,attr,omitempty"`
	WantAssertionsSigned      string                         `xml:"WantAssertionsSigned,attr,omitempty"`
	ProtocolSupportEnum       string                         `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors            []SAMLKeyDescriptor            `xml:"KeyDescriptor"`
	NameIDFormats             []string                       `xml:"NameIDFormat"`
	AssertionConsumerServices []SAMLAssertionConsumerService `xml:"AssertionConsumerService"`
	SingleLogoutServices      []SAMLSingleLogoutService      `xml:"SingleLogoutService"`
}

// SAMLKeyDescriptor represents a KeyDescriptor element
type SAMLKeyDescriptor struct {
	Use     string      `xml:"use,attr,omitempty"` // "signing" or "encryption"
	KeyInfo SAMLKeyInfo `xml:"KeyInfo"`
}

// SAMLKeyInfo represents the KeyInfo element
type SAMLKeyInfo struct {
	X509Data *SAMLX509Data `xml:"X509Data,omitempty"`
}

// SAMLX509Data represents the X509Data element
type SAMLX509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

// SAMLSingleSignOnService represents a SingleSignOnService element
type SAMLSingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// SAMLSingleLogoutService represents a SingleLogoutService element
type SAMLSingleLogoutService struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

// SAMLAssertionConsumerService represents an AssertionConsumerService element
type SAMLAssertionConsumerService struct {
	Index     string `xml:"index,attr"`
	IsDefault string `xml:"isDefault,attr,omitempty"`
	Binding   string `xml:"Binding,attr"`
	Location  string `xml:"Location,attr"`
}

// SAMLOrganization represents the Organization element
type SAMLOrganization struct {
	OrganizationName        []SAMLLocalizedName `xml:"OrganizationName"`
	OrganizationDisplayName []SAMLLocalizedName `xml:"OrganizationDisplayName"`
	OrganizationURL         []SAMLLocalizedURI  `xml:"OrganizationURL"`
}

// SAMLLocalizedName is a localized string with xml:lang attribute
type SAMLLocalizedName struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// SAMLLocalizedURI is a localized URI with xml:lang attribute
type SAMLLocalizedURI struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// SAMLContactPerson represents a ContactPerson element
type SAMLContactPerson struct {
	ContactType  string `xml:"contactType,attr"`
	GivenName    string `xml:"GivenName,omitempty"`
	SurName      string `xml:"SurName,omitempty"`
	EmailAddress string `xml:"EmailAddress,omitempty"`
}

// ==================== Parsed Metadata ====================

// ParsedSAMLMetadata is the normalized result of parsing SAML metadata
type ParsedSAMLMetadata struct {
	EntityID          string     `json:"entity_id"`
	SSOURL            string     `json:"sso_url"`
	SSOBinding        string     `json:"sso_binding"`
	SLOURL            string     `json:"slo_url,omitempty"`
	SLOBinding        string     `json:"slo_binding,omitempty"`
	SigningCertPEM    string     `json:"signing_cert_pem"`
	EncryptionCertPEM string     `json:"encryption_cert_pem,omitempty"`
	NameIDFormats     []string   `json:"name_id_formats,omitempty"`
	OrganizationName  string     `json:"organization_name,omitempty"`
	CertificateExpiry *time.Time `json:"certificate_expiry,omitempty"`
	DetectedIDPType   string     `json:"detected_idp_type,omitempty"` // okta, azure_ad, onelogin, ping, google_workspace, unknown
	WantAuthnSigned   bool       `json:"want_authn_signed"`
	ValidUntil        *time.Time `json:"valid_until,omitempty"`
	RawXML            string     `json:"raw_xml,omitempty"`
}

// ==================== API Request/Response DTOs ====================

// MetadataImportURLRequest for importing metadata from URL
type MetadataImportURLRequest struct {
	URL  string `json:"url" binding:"required,url"`
	Name string `json:"name" binding:"omitempty,max=255"`
}

// MetadataImportXMLRequest for importing metadata from uploaded XML
type MetadataImportXMLRequest struct {
	XML  string `json:"xml" binding:"required"`
	Name string `json:"name" binding:"omitempty,max=255"`
}

// MetadataImportConfirmRequest for confirming metadata import after preview
type MetadataImportConfirmRequest struct {
	Name        string `json:"name" binding:"required,min=2,max=100"`
	EntityID    string `json:"entity_id" binding:"required"`
	MetadataURL string `json:"metadata_url,omitempty"`
	RawXML      string `json:"raw_xml" binding:"required"`
}

// MetadataPreviewResponse for previewing parsed metadata before import
type MetadataPreviewResponse struct {
	Parsed   ParsedSAMLMetadata `json:"parsed"`
	Warnings []string           `json:"warnings,omitempty"`
}

// ==================== Metadata Refresh Log ====================

// SAMLMetadataRefreshLog records metadata refresh attempts
type SAMLMetadataRefreshLog struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	SPID          uuid.UUID              `json:"sp_id" db:"sp_id"`
	Status        string                 `json:"status" db:"status"` // success, failed, no_changes
	Changes       map[string]interface{} `json:"changes,omitempty" db:"changes"`
	ErrorMessage  *string                `json:"error_message,omitempty" db:"error_message"`
	CertRotated   bool                   `json:"cert_rotated" db:"cert_rotated"`
	OldCertExpiry *time.Time             `json:"old_cert_expiry,omitempty" db:"old_cert_expiry"`
	NewCertExpiry *time.Time             `json:"new_cert_expiry,omitempty" db:"new_cert_expiry"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
}
