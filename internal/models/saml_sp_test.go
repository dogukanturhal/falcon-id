// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== SAML binding constants ====================

func TestSAMLBindingConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "HTTP-Redirect binding constant should match SAML spec value",
			constant: SAMLBindingHTTPRedirect,
			expected: "HTTP-Redirect",
		},
		{
			name:     "HTTP-POST binding constant should match SAML spec value",
			constant: SAMLBindingHTTPPOST,
			expected: "HTTP-POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestSAMLBindingConstants_Distinct(t *testing.T) {
	assert.NotEqual(t, SAMLBindingHTTPRedirect, SAMLBindingHTTPPOST,
		"HTTP-Redirect and HTTP-POST constants must be distinct")
}

// ==================== SAMLSPConfig struct ====================

func TestSAMLSPConfig_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLSPConfig", func(t *testing.T) {
		cfg := &SAMLSPConfig{
			IDPEntityID:    "https://idp.okta.com",
			IDPSSOURL:      "https://idp.okta.com/sso",
			IDPSLOURL:      "https://idp.okta.com/slo",
			IDPCertificate: "-----BEGIN CERTIFICATE-----\nMIIB...",
			IDPMetadataURL: "https://idp.okta.com/metadata",

			SPEntityID:      "https://sp.example.com",
			SPACSURL:        "https://sp.example.com/acs",
			SPSLOURL:        "https://sp.example.com/slo",
			SPSignRequests:  true,
			SPWantSigned:    true,
			SPWantEncrypted: false,

			AttributeMapping: map[string]string{
				"email":     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
				"firstName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			},

			SSOBinding:       SAMLBindingHTTPRedirect,
			SLOBinding:       SAMLBindingHTTPPOST,
			ClockSkewSeconds: 60,
			NameIDFormat:     NameIDFormatEmailAddress,
		}

		assert.Equal(t, "https://idp.okta.com", cfg.IDPEntityID)
		assert.Equal(t, "https://idp.okta.com/sso", cfg.IDPSSOURL)
		assert.Equal(t, "https://idp.okta.com/slo", cfg.IDPSLOURL)
		assert.NotEmpty(t, cfg.IDPCertificate)
		assert.Equal(t, "https://idp.okta.com/metadata", cfg.IDPMetadataURL)

		assert.Equal(t, "https://sp.example.com", cfg.SPEntityID)
		assert.Equal(t, "https://sp.example.com/acs", cfg.SPACSURL)
		assert.Equal(t, "https://sp.example.com/slo", cfg.SPSLOURL)
		assert.True(t, cfg.SPSignRequests)
		assert.True(t, cfg.SPWantSigned)
		assert.False(t, cfg.SPWantEncrypted)

		assert.Equal(t, SAMLBindingHTTPRedirect, cfg.SSOBinding)
		assert.Equal(t, SAMLBindingHTTPPOST, cfg.SLOBinding)
		assert.Equal(t, 60, cfg.ClockSkewSeconds)
		assert.Equal(t, NameIDFormatEmailAddress, cfg.NameIDFormat)

		assert.Equal(t, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			cfg.AttributeMapping["email"])
	})

	t.Run("should create a zero-value SAMLSPConfig without panicking", func(t *testing.T) {
		cfg := &SAMLSPConfig{}

		assert.Empty(t, cfg.IDPEntityID)
		assert.Empty(t, cfg.IDPSSOURL)
		assert.Empty(t, cfg.SPEntityID)
		assert.Nil(t, cfg.AttributeMapping)
		assert.False(t, cfg.SPSignRequests)
		assert.False(t, cfg.SPWantSigned)
		assert.False(t, cfg.SPWantEncrypted)
		assert.Zero(t, cfg.ClockSkewSeconds)
	})

	t.Run("should accept zero clock skew for strict time validation", func(t *testing.T) {
		cfg := &SAMLSPConfig{
			ClockSkewSeconds: 0,
		}
		assert.Equal(t, 0, cfg.ClockSkewSeconds)
	})

	t.Run("should accept large clock skew values", func(t *testing.T) {
		cfg := &SAMLSPConfig{
			ClockSkewSeconds: 300, // 5 minutes
		}
		assert.Equal(t, 300, cfg.ClockSkewSeconds)
	})
}

// ==================== SAMLSPAuthnRequest struct ====================

func TestSAMLSPAuthnRequest_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLSPAuthnRequest", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		now := time.Now().Truncate(time.Second)
		expiry := now.Add(5 * time.Minute)
		relay := "https://app.example.com/dashboard"
		ip := testIPAddrTen
		ua := testUserAgentMozilla
		consumed := now.Add(30 * time.Second)

		req := &SAMLSPAuthnRequest{
			ID:         id,
			TenantID:   tenantID,
			ProviderID: providerID,
			RequestID:  "_request_abc123",
			RelayState: &relay,
			ACSURL:     "https://sp.example.com/acs",
			IPAddress:  &ip,
			UserAgent:  &ua,
			ConsumedAt: &consumed,
			ExpiresAt:  expiry,
			CreatedAt:  now,
		}

		assert.Equal(t, id, req.ID)
		assert.Equal(t, tenantID, req.TenantID)
		assert.Equal(t, providerID, req.ProviderID)
		assert.Equal(t, "_request_abc123", req.RequestID)
		require.NotNil(t, req.RelayState)
		assert.Equal(t, relay, *req.RelayState)
		assert.Equal(t, "https://sp.example.com/acs", req.ACSURL)
		require.NotNil(t, req.IPAddress)
		assert.Equal(t, testIPAddrTen, *req.IPAddress)
		require.NotNil(t, req.UserAgent)
		assert.Equal(t, testUserAgentMozilla, *req.UserAgent)
		require.NotNil(t, req.ConsumedAt)
		assert.Equal(t, consumed, *req.ConsumedAt)
		assert.Equal(t, expiry, req.ExpiresAt)
		assert.Equal(t, now, req.CreatedAt)
	})

	t.Run("should create a minimal SAMLSPAuthnRequest with nil optionals", func(t *testing.T) {
		req := &SAMLSPAuthnRequest{
			ID:         uuid.New(),
			TenantID:   uuid.New(),
			ProviderID: uuid.New(),
			RequestID:  "_req_001",
			ACSURL:     "https://sp.example.com/acs",
			ExpiresAt:  time.Now().Add(5 * time.Minute),
			CreatedAt:  time.Now(),
		}

		assert.Nil(t, req.RelayState)
		assert.Nil(t, req.IPAddress)
		assert.Nil(t, req.UserAgent)
		assert.Nil(t, req.ConsumedAt)
	})

	t.Run("ConsumedAt should be nil for an unconsumed request", func(t *testing.T) {
		req := &SAMLSPAuthnRequest{
			ID:        uuid.New(),
			RequestID: "_unconsumed",
		}

		assert.Nil(t, req.ConsumedAt, "unconsumed request should have nil ConsumedAt")
	})

	t.Run("ConsumedAt should be set after the request is consumed", func(t *testing.T) {
		consumed := time.Now()
		req := &SAMLSPAuthnRequest{
			ID:         uuid.New(),
			RequestID:  "_consumed",
			ConsumedAt: &consumed,
		}

		require.NotNil(t, req.ConsumedAt)
		assert.Equal(t, consumed, *req.ConsumedAt)
	})
}

// ==================== SAMLSPAssertionLog struct ====================

func TestSAMLSPAssertionLog_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLSPAssertionLog", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		providerID := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)
		assertionID := "_assertion_001"
		nameID := "user@example.com"
		sessionIndex := "_session_001"
		issuer := "https://idp.okta.com"
		ip := "192.168.1.100"
		ua := "TestAgent/1.0"
		errMsg := "signature validation failed"

		log := &SAMLSPAssertionLog{
			ID:           id,
			TenantID:     tenantID,
			ProviderID:   providerID,
			UserID:       &userID,
			AssertionID:  &assertionID,
			NameID:       &nameID,
			SessionIndex: &sessionIndex,
			Issuer:       &issuer,
			IPAddress:    &ip,
			UserAgent:    &ua,
			Status:       "success",
			ErrorMessage: &errMsg,
			Attributes: map[string]interface{}{
				"email":  "user@example.com",
				"groups": []interface{}{"admin"},
			},
			CreatedAt: now,
		}

		assert.Equal(t, id, log.ID)
		assert.Equal(t, tenantID, log.TenantID)
		assert.Equal(t, providerID, log.ProviderID)
		require.NotNil(t, log.UserID)
		assert.Equal(t, userID, *log.UserID)
		require.NotNil(t, log.AssertionID)
		assert.Equal(t, "_assertion_001", *log.AssertionID)
		require.NotNil(t, log.NameID)
		assert.Equal(t, "user@example.com", *log.NameID)
		require.NotNil(t, log.SessionIndex)
		assert.Equal(t, "_session_001", *log.SessionIndex)
		require.NotNil(t, log.Issuer)
		assert.Equal(t, "https://idp.okta.com", *log.Issuer)
		require.NotNil(t, log.IPAddress)
		assert.Equal(t, "192.168.1.100", *log.IPAddress)
		require.NotNil(t, log.UserAgent)
		assert.Equal(t, "TestAgent/1.0", *log.UserAgent)
		assert.Equal(t, "success", log.Status)
		require.NotNil(t, log.ErrorMessage)
		assert.Equal(t, errMsg, *log.ErrorMessage)
		assert.Equal(t, "user@example.com", log.Attributes["email"])
		assert.Equal(t, now, log.CreatedAt)
	})

	t.Run("should create a minimal SAMLSPAssertionLog with nil optional fields", func(t *testing.T) {
		log := &SAMLSPAssertionLog{
			ID:         uuid.New(),
			TenantID:   uuid.New(),
			ProviderID: uuid.New(),
			Status:     "failed",
			CreatedAt:  time.Now(),
		}

		assert.Nil(t, log.UserID)
		assert.Nil(t, log.AssertionID)
		assert.Nil(t, log.NameID)
		assert.Nil(t, log.SessionIndex)
		assert.Nil(t, log.Issuer)
		assert.Nil(t, log.IPAddress)
		assert.Nil(t, log.UserAgent)
		assert.Nil(t, log.ErrorMessage)
		assert.Nil(t, log.Attributes)
	})

	t.Run("success status should not require an error message", func(t *testing.T) {
		log := &SAMLSPAssertionLog{
			ID:     uuid.New(),
			Status: "success",
		}

		assert.Equal(t, "success", log.Status)
		assert.Nil(t, log.ErrorMessage)
	})
}

// ==================== SAMLSPLoginRequest ====================

func TestSAMLSPLoginRequest_Instantiation(t *testing.T) {
	t.Run("should create a login request with relay state", func(t *testing.T) {
		req := &SAMLSPLoginRequest{
			ProviderID: uuid.New().String(),
			RelayState: "/dashboard",
		}

		assert.NotEmpty(t, req.ProviderID)
		assert.Equal(t, "/dashboard", req.RelayState)
	})

	t.Run("should create a login request without relay state", func(t *testing.T) {
		req := &SAMLSPLoginRequest{
			ProviderID: uuid.New().String(),
		}

		assert.NotEmpty(t, req.ProviderID)
		assert.Empty(t, req.RelayState)
	})
}

// ==================== SAMLSPMetadataResponse ====================

func TestSAMLSPMetadataResponse_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SP metadata response", func(t *testing.T) {
		r := &SAMLSPMetadataResponse{
			EntityID:    "https://sp.example.com",
			ACSURL:      "https://sp.example.com/acs",
			SLOURL:      "https://sp.example.com/slo",
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIB...",
			NameIDFormats: []string{
				NameIDFormatEmailAddress,
				NameIDFormatPersistent,
				NameIDFormatTransient,
			},
		}

		assert.Equal(t, "https://sp.example.com", r.EntityID)
		assert.Equal(t, "https://sp.example.com/acs", r.ACSURL)
		assert.Equal(t, "https://sp.example.com/slo", r.SLOURL)
		assert.NotEmpty(t, r.Certificate)
		assert.Len(t, r.NameIDFormats, 3)
		assert.Equal(t, NameIDFormatEmailAddress, r.NameIDFormats[0])
	})

	t.Run("should allow an empty certificate for unsigned SP", func(t *testing.T) {
		r := &SAMLSPMetadataResponse{
			EntityID: "https://sp.example.com",
			ACSURL:   "https://sp.example.com/acs",
		}

		assert.Empty(t, r.Certificate)
	})
}

// ==================== SAMLLogoutRequest XML struct ====================

func TestSAMLLogoutRequest_XMLParsing(t *testing.T) {
	t.Run("should parse a valid SAML LogoutRequest XML", func(t *testing.T) {
		xmlData := `<samlp:LogoutRequest
			xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
			xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
			ID="_logout_001"
			Version="2.0"
			IssueInstant="2026-02-24T10:00:00Z"
			NotOnOrAfter="2026-02-24T10:05:00Z"
			Destination="https://sp.example.com/slo">
			<saml:Issuer>https://idp.example.com</saml:Issuer>
			<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
			<samlp:SessionIndex>_sess_001</samlp:SessionIndex>
			<samlp:SessionIndex>_sess_002</samlp:SessionIndex>
		</samlp:LogoutRequest>`

		var req SAMLLogoutRequest
		err := xml.Unmarshal([]byte(xmlData), &req)
		require.NoError(t, err)

		assert.Equal(t, "_logout_001", req.ID)
		assert.Equal(t, "2.0", req.Version)
		assert.Equal(t, "2026-02-24T10:00:00Z", req.IssueInstant)
		assert.Equal(t, "2026-02-24T10:05:00Z", req.NotOnOrAfter)
		assert.Equal(t, "https://sp.example.com/slo", req.Destination)
		assert.Equal(t, "https://idp.example.com", req.Issuer)
		assert.Equal(t, NameIDFormatEmailAddress, req.NameID.Format)
		assert.Equal(t, "user@example.com", req.NameID.Value)
		assert.Equal(t, []string{"_sess_001", "_sess_002"}, req.SessionIndex)
	})

	t.Run("should parse a LogoutRequest with no session indexes", func(t *testing.T) {
		xmlData := `<samlp:LogoutRequest
			xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
			xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
			ID="_logout_002"
			Version="2.0"
			IssueInstant="2026-02-24T11:00:00Z"
			Destination="https://sp.example.com/slo">
			<saml:Issuer>https://idp.example.com</saml:Issuer>
			<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">abc123</saml:NameID>
		</samlp:LogoutRequest>`

		var req SAMLLogoutRequest
		err := xml.Unmarshal([]byte(xmlData), &req)
		require.NoError(t, err)

		assert.Equal(t, "_logout_002", req.ID)
		assert.Empty(t, req.SessionIndex)
	})

	t.Run("should produce an error on malformed XML", func(t *testing.T) {
		badXML := `<not-valid-xml`

		var req SAMLLogoutRequest
		err := xml.Unmarshal([]byte(badXML), &req)
		assert.Error(t, err)
	})
}

func TestSAMLLogoutRequest_Instantiation(t *testing.T) {
	t.Run("should instantiate with session indexes", func(t *testing.T) {
		req := &SAMLLogoutRequest{
			ID:           "_logout_003",
			Version:      "2.0",
			IssueInstant: "2026-02-24T12:00:00Z",
			Destination:  "https://sp.example.com/slo",
			Issuer:       "https://idp.example.com",
			SessionIndex: []string{"_s1", "_s2", "_s3"},
		}
		req.NameID.Format = NameIDFormatEmailAddress
		req.NameID.Value = "user@example.com"

		assert.Equal(t, "_logout_003", req.ID)
		assert.Len(t, req.SessionIndex, 3)
		assert.Equal(t, "user@example.com", req.NameID.Value)
		assert.Equal(t, NameIDFormatEmailAddress, req.NameID.Format)
	})
}

// ==================== SLOResult ====================

func TestSLOResult_Instantiation(t *testing.T) {
	tests := []struct {
		name   string
		result SLOResult
	}{
		{
			name: "should create a redirect-binding SLO result",
			result: SLOResult{
				RedirectURL: "https://sp.example.com/slo?SAMLResponse=abc",
				RelayState:  "xyz",
				Binding:     SAMLBindingHTTPRedirect,
			},
		},
		{
			name: "should create a POST-binding SLO result with response XML",
			result: SLOResult{
				ResponseXML: "<samlp:LogoutResponse>...</samlp:LogoutResponse>",
				RelayState:  "xyz",
				Binding:     SAMLBindingHTTPPOST,
			},
		},
		{
			name:   "should allow empty SLO result",
			result: SLOResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.result
			// Verify the result can be created and the binding field is accessible.
			assert.Equal(t, tt.result.Binding, r.Binding)
			assert.Equal(t, tt.result.ResponseXML, r.ResponseXML)
			assert.Equal(t, tt.result.RedirectURL, r.RedirectURL)
			assert.Equal(t, tt.result.RelayState, r.RelayState)
		})
	}
}

func TestSLOResult_BindingValues(t *testing.T) {
	t.Run("redirect binding result should use HTTP-Redirect", func(t *testing.T) {
		r := SLOResult{
			RedirectURL: "https://sp.example.com/redirect",
			Binding:     SAMLBindingHTTPRedirect,
		}

		assert.Equal(t, SAMLBindingHTTPRedirect, r.Binding)
		assert.NotEmpty(t, r.RedirectURL)
		assert.Empty(t, r.ResponseXML)
	})

	t.Run("POST binding result should use HTTP-POST", func(t *testing.T) {
		r := SLOResult{
			ResponseXML: "<Response/>",
			Binding:     SAMLBindingHTTPPOST,
		}

		assert.Equal(t, SAMLBindingHTTPPOST, r.Binding)
		assert.NotEmpty(t, r.ResponseXML)
		assert.Empty(t, r.RedirectURL)
	})
}
