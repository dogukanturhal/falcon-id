// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/xml"
	"time"

	"github.com/google/uuid"
)

// SAMLSPConfig represents SAML Service Provider configuration for inbound federation
// (tenant uses an external IDP like Okta/Azure AD).
type SAMLSPConfig struct {
	// External IDP metadata
	IDPEntityID    string `json:"idp_entity_id"`
	IDPSSOURL      string `json:"idp_sso_url"`      // IdP SSO endpoint (HTTP-Redirect or HTTP-POST)
	IDPSLOURL      string `json:"idp_slo_url"`      // IdP SLO endpoint
	IDPCertificate string `json:"idp_certificate"`  // IdP signing certificate (PEM)
	IDPMetadataURL string `json:"idp_metadata_url"` // Optional: URL to fetch IdP metadata

	// SP configuration
	SPEntityID      string `json:"sp_entity_id"`      // Our SP entity ID
	SPACSURL        string `json:"sp_acs_url"`        // Assertion Consumer Service URL
	SPSLOURL        string `json:"sp_slo_url"`        // Our SLO URL
	SPSignRequests  bool   `json:"sp_sign_requests"`  // Sign AuthnRequests
	SPWantSigned    bool   `json:"sp_want_signed"`    // Require signed assertions
	SPWantEncrypted bool   `json:"sp_want_encrypted"` // Require encrypted assertions

	// SPAllowIdPInitiated permits UNSOLICITED assertions -- ones carrying no
	// InResponseTo, which therefore cannot be bound to an AuthnRequest we issued.
	//
	// Defaults false, so IdP-initiated SSO is opt-in per provider. It is a
	// legitimate SAML flow, but accepting it silently means any assertion the IdP
	// can mint is accepted without us having asked for it, and a tenant that only
	// uses SP-initiated login gains nothing from leaving that door open. Replay of
	// an accepted unsolicited assertion is still bounded by the assertion-ID
	// replay store (security.ValidateAssertionSemantics).
	SPAllowIdPInitiated bool `json:"sp_allow_idp_initiated"`

	// SPTrustIDPEmailVerification records that this tenant's administrator has
	// decided the IdP verifies the email addresses it asserts.
	//
	// Defaults false, and that is deliberate rather than conservative-by-habit:
	// SAML has no standard email_verified claim, so there is nothing in an
	// assertion to consult. A verified signature proves the assertion CAME FROM
	// the configured IdP; it says nothing about whether that IdP checked the
	// address. Those are different facts and the old code conflated them.
	//
	// This is why the LDAP resolution does not transfer (c-073): there the
	// justification was that a directory mail attribute is administratively
	// controlled by the operator, whereas a SAML IdP is a third party we do not
	// administer. The only real justification available here is an explicit
	// decision by the admin who configured and pinned that IdP -- so it is
	// recorded as one instead of assumed in a comment.
	SPTrustIDPEmailVerification bool `json:"sp_trust_idp_email_verification"`

	// Attribute mapping from SAML assertion to user fields
	AttributeMapping map[string]string `json:"attribute_mapping"`

	// Binding preferences
	SSOBinding string `json:"sso_binding"` // "HTTP-Redirect" or "HTTP-POST"
	SLOBinding string `json:"slo_binding"` // "HTTP-Redirect" or "HTTP-POST"

	// Clock skew tolerance
	ClockSkewSeconds int `json:"clock_skew_seconds"`

	// Name ID format
	NameIDFormat string `json:"name_id_format"`
}

// SAMLSPAuthnRequest tracks SP-initiated AuthnRequests for replay prevention
type SAMLSPAuthnRequest struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	TenantID   uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ProviderID uuid.UUID  `json:"provider_id" db:"provider_id"`
	RequestID  string     `json:"request_id" db:"request_id"`
	RelayState *string    `json:"relay_state,omitempty" db:"relay_state"`
	ACSURL     string     `json:"acs_url" db:"acs_url"`
	IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string    `json:"user_agent,omitempty" db:"user_agent"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty" db:"consumed_at"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// SAMLSPAssertionLog is an audit log entry for inbound SAML assertions
type SAMLSPAssertionLog struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ProviderID   uuid.UUID              `json:"provider_id" db:"provider_id"`
	UserID       *uuid.UUID             `json:"user_id,omitempty" db:"user_id"`
	AssertionID  *string                `json:"assertion_id,omitempty" db:"assertion_id"`
	NameID       *string                `json:"name_id,omitempty" db:"name_id"`
	SessionIndex *string                `json:"session_index,omitempty" db:"session_index"`
	Issuer       *string                `json:"issuer,omitempty" db:"issuer"`
	IPAddress    *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    *string                `json:"user_agent,omitempty" db:"user_agent"`
	Status       string                 `json:"status" db:"status"` // success, failed
	ErrorMessage *string                `json:"error_message,omitempty" db:"error_message"`
	Attributes   map[string]interface{} `json:"attributes,omitempty" db:"attributes"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// SAMLSPLoginRequest for initiating SP-initiated SSO
type SAMLSPLoginRequest struct {
	ProviderID string `json:"provider_id" binding:"required"`
	RelayState string `json:"relay_state,omitempty"`
}

// SAMLSPMetadataResponse for SP metadata XML generation
type SAMLSPMetadataResponse struct {
	EntityID      string   `json:"entity_id"`
	ACSURL        string   `json:"acs_url"`
	SLOURL        string   `json:"slo_url"`
	Certificate   string   `json:"certificate,omitempty"`
	NameIDFormats []string `json:"name_id_formats"`
}

// SAML binding constants used across SLO service and handler layers.
const (
	SAMLBindingHTTPRedirect = "HTTP-Redirect"
	SAMLBindingHTTPPOST     = "HTTP-POST"
)

// SAMLLogoutRequest represents a parsed SAML 2.0 LogoutRequest.
type SAMLLogoutRequest struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Destination  string   `xml:"Destination,attr"`
	Issuer       string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndex []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

// SLOResult is the service return value for HandleSLO.
type SLOResult struct {
	ResponseXML string `json:"response_xml,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	RelayState  string `json:"relay_state,omitempty"`
	Binding     string `json:"binding"`
}

// TrustsAssertedEmail reports whether an email asserted by this SAML provider
// may be recorded as verified.
//
// Extracted so the decision has ONE home that production and tests both call --
// a control that re-implements the predicate proves only that the test agrees
// with itself.
func (c *SAMLSPConfig) TrustsAssertedEmail(email string) bool {
	if c == nil || !c.SPTrustIDPEmailVerification {
		return false
	}
	return email != ""
}
