// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSPSLOURL = "https://sp.example.com/slo"

// ==================== NameID format constants ====================

func TestNameIDFormatConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "unspecified format should match SAML 1.1 URN",
			constant: NameIDFormatUnspecified,
			expected: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		},
		{
			name:     "email address format should match SAML 1.1 URN",
			constant: NameIDFormatEmailAddress,
			expected: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		},
		{
			name:     "persistent format should match SAML 2.0 URN",
			constant: NameIDFormatPersistent,
			expected: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		},
		{
			name:     "transient format should match SAML 2.0 URN",
			constant: NameIDFormatTransient,
			expected: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		{
			name:     "X509 subject format should match SAML 1.1 URN",
			constant: NameIDFormatX509Subject,
			expected: "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
		},
		{
			name:     "Windows domain format should match SAML 1.1 URN",
			constant: NameIDFormatWindowsDomain,
			expected: "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// TestNameIDFormatConstants_Distinct verifies that all format constants are
// unique so that none accidentally collapse to the same value.
func TestNameIDFormatConstants_Distinct(t *testing.T) {
	formats := []string{
		NameIDFormatUnspecified,
		NameIDFormatEmailAddress,
		NameIDFormatPersistent,
		NameIDFormatTransient,
		NameIDFormatX509Subject,
		NameIDFormatWindowsDomain,
	}

	seen := make(map[string]struct{}, len(formats))
	for _, f := range formats {
		_, dup := seen[f]
		assert.False(t, dup, "duplicate NameID format constant: %s", f)
		seen[f] = struct{}{}
	}
}

// ==================== SAMLServiceProvider struct ====================

func TestSAMLServiceProvider_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLServiceProvider", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		sloURL := testSPSLOURL
		metadataURL := "https://sp.example.com/metadata"
		cert := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
		fetched := now.Add(-1 * time.Hour)
		expiry := now.Add(365 * 24 * time.Hour)
		idpType := "okta"
		orgName := "Acme Corp"
		importSrc := "manual"

		sp := &SAMLServiceProvider{
			ID:                         id,
			TenantID:                   tenantID,
			Name:                       "My SP",
			EntityID:                   "https://sp.example.com",
			ACSURL:                     "https://sp.example.com/acs",
			SLOURL:                     &sloURL,
			MetadataURL:                &metadataURL,
			Certificate:                &cert,
			NameIDFormat:               NameIDFormatEmailAddress,
			SignAssertions:             true,
			EncryptAssertions:          false,
			AttributeMapping:           JSONMap{"email": "mail"},
			AllowedAttributes:          []string{"email", "firstName"},
			IsActive:                   true,
			MetadataLastFetched:        &fetched,
			MetadataAutoRefresh:        true,
			MetadataRefreshIntervalHrs: 24,
			DetectedIDPType:            &idpType,
			OrganizationName:           &orgName,
			CertificateExpiry:          &expiry,
			MetadataImportSource:       importSrc,
			CreatedAt:                  now,
			UpdatedAt:                  now,
			CreatedBy:                  &createdBy,
		}

		assert.Equal(t, id, sp.ID)
		assert.Equal(t, tenantID, sp.TenantID)
		assert.Equal(t, "My SP", sp.Name)
		assert.Equal(t, "https://sp.example.com", sp.EntityID)
		assert.Equal(t, "https://sp.example.com/acs", sp.ACSURL)
		assert.Equal(t, &sloURL, sp.SLOURL)
		assert.Equal(t, &metadataURL, sp.MetadataURL)
		assert.Equal(t, &cert, sp.Certificate)
		assert.Equal(t, NameIDFormatEmailAddress, sp.NameIDFormat)
		assert.True(t, sp.SignAssertions)
		assert.False(t, sp.EncryptAssertions)
		assert.Equal(t, JSONMap{"email": "mail"}, sp.AttributeMapping)
		assert.Equal(t, []string{"email", "firstName"}, sp.AllowedAttributes)
		assert.True(t, sp.IsActive)
		assert.Equal(t, &fetched, sp.MetadataLastFetched)
		assert.True(t, sp.MetadataAutoRefresh)
		assert.Equal(t, 24, sp.MetadataRefreshIntervalHrs)
		assert.Equal(t, &idpType, sp.DetectedIDPType)
		assert.Equal(t, &orgName, sp.OrganizationName)
		assert.Equal(t, &expiry, sp.CertificateExpiry)
		assert.Equal(t, importSrc, sp.MetadataImportSource)
		assert.Equal(t, now, sp.CreatedAt)
		assert.Equal(t, now, sp.UpdatedAt)
		assert.Equal(t, &createdBy, sp.CreatedBy)
	})

	t.Run("should create a minimal SAMLServiceProvider with zero values", func(t *testing.T) {
		sp := &SAMLServiceProvider{}

		assert.Equal(t, uuid.Nil, sp.ID)
		assert.Equal(t, uuid.Nil, sp.TenantID)
		assert.Empty(t, sp.Name)
		assert.Empty(t, sp.EntityID)
		assert.Nil(t, sp.SLOURL)
		assert.Nil(t, sp.MetadataURL)
		assert.Nil(t, sp.Certificate)
		assert.False(t, sp.IsActive)
		assert.Nil(t, sp.CreatedBy)
	})
}

// ==================== SAMLServiceProvider.ToResponse ====================

func TestSAMLServiceProvider_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		sloURL := testSPSLOURL
		metadataURL := "https://sp.example.com/metadata"
		cert := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"

		sp := &SAMLServiceProvider{
			ID:                id,
			TenantID:          tenantID,
			Name:              "My SP",
			EntityID:          "https://sp.example.com",
			ACSURL:            "https://sp.example.com/acs",
			SLOURL:            &sloURL,
			MetadataURL:       &metadataURL,
			Certificate:       &cert,
			NameIDFormat:      NameIDFormatEmailAddress,
			SignAssertions:    true,
			EncryptAssertions: true,
			AttributeMapping:  JSONMap{"email": "mail", "firstName": "givenName"},
			AllowedAttributes: []string{"email", "firstName", "lastName"},
			IsActive:          true,
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, "My SP", resp.Name)
		assert.Equal(t, "https://sp.example.com", resp.EntityID)
		assert.Equal(t, "https://sp.example.com/acs", resp.ACSURL)
		assert.Equal(t, &sloURL, resp.SLOURL)
		assert.Equal(t, &metadataURL, resp.MetadataURL)
		assert.True(t, resp.HasCertificate, "non-empty certificate should set HasCertificate=true")
		assert.Equal(t, NameIDFormatEmailAddress, resp.NameIDFormat)
		assert.True(t, resp.SignAssertions)
		assert.True(t, resp.EncryptAssertions)
		assert.Equal(t, map[string]string{"email": "mail", "firstName": "givenName"}, resp.AttributeMapping)
		assert.Equal(t, []string{"email", "firstName", "lastName"}, resp.AllowedAttributes)
		assert.True(t, resp.IsActive)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should set HasCertificate to false when Certificate is nil", func(t *testing.T) {
		sp := &SAMLServiceProvider{
			ID:          uuid.New(),
			Certificate: nil,
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.HasCertificate)
	})

	t.Run("should set HasCertificate to false when Certificate is empty string", func(t *testing.T) {
		emptyCert := ""
		sp := &SAMLServiceProvider{
			ID:          uuid.New(),
			Certificate: &emptyCert,
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		assert.False(t, resp.HasCertificate)
	})

	t.Run("should set HasCertificate to true when Certificate is non-empty", func(t *testing.T) {
		cert := "BEGIN CERTIFICATE"
		sp := &SAMLServiceProvider{
			ID:          uuid.New(),
			Certificate: &cert,
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		assert.True(t, resp.HasCertificate)
	})

	t.Run("should convert JSONMap attribute mapping to map[string]string", func(t *testing.T) {
		sp := &SAMLServiceProvider{
			ID:               uuid.New(),
			AttributeMapping: JSONMap{"email": "mail", "name": "displayName"},
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, map[string]string{"email": "mail", "name": "displayName"}, resp.AttributeMapping)
	})

	t.Run("should skip non-string values in JSONMap attribute mapping", func(t *testing.T) {
		sp := &SAMLServiceProvider{
			ID:               uuid.New(),
			AttributeMapping: JSONMap{"email": "mail", "count": 42, "flag": true},
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		// Only the string value "mail" is preserved; integer and bool are skipped.
		assert.Equal(t, map[string]string{"email": "mail"}, resp.AttributeMapping)
	})

	t.Run("should return empty AttributeMapping when JSONMap is nil", func(t *testing.T) {
		sp := &SAMLServiceProvider{
			ID:               uuid.New(),
			AttributeMapping: nil,
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		// ToResponse always initialises the map even if the source is nil.
		assert.NotNil(t, resp.AttributeMapping)
		assert.Empty(t, resp.AttributeMapping)
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		sp := &SAMLServiceProvider{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Certificate: nil,
			SLOURL:      nil,
			MetadataURL: nil,
		}

		resp := sp.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.SLOURL)
		assert.Nil(t, resp.MetadataURL)
		assert.False(t, resp.HasCertificate)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		sp := &SAMLServiceProvider{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			IsActive: true,
		}

		resp1 := sp.ToResponse()
		resp2 := sp.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== DefaultAttributeMapping ====================

func TestDefaultAttributeMapping(t *testing.T) {
	m := DefaultAttributeMapping()

	require.NotNil(t, m)
	assert.Equal(t, "email", m["email"])
	assert.Equal(t, "first_name", m["firstName"])
	assert.Equal(t, "last_name", m["lastName"])
	assert.Equal(t, "display_name", m["displayName"])
}

func TestDefaultAttributeMapping_Idempotent(t *testing.T) {
	m1 := DefaultAttributeMapping()
	m2 := DefaultAttributeMapping()

	assert.Equal(t, m1, m2, "DefaultAttributeMapping should return equal maps on successive calls")
	assert.NotSame(t, &m1, &m2, "DefaultAttributeMapping should return distinct map instances")
}

// ==================== DefaultAllowedAttributes ====================

func TestDefaultAllowedAttributes(t *testing.T) {
	attrs := DefaultAllowedAttributes()

	require.NotEmpty(t, attrs)

	expected := map[string]bool{
		"email":       false,
		"firstName":   false,
		"lastName":    false,
		"displayName": false,
		"groups":      false,
	}

	for _, a := range attrs {
		_, ok := expected[a]
		assert.True(t, ok, "unexpected attribute in DefaultAllowedAttributes: %s", a)
		expected[a] = true
	}

	for attr, seen := range expected {
		assert.True(t, seen, "expected attribute %q not found in DefaultAllowedAttributes", attr)
	}
}

func TestDefaultAllowedAttributes_Idempotent(t *testing.T) {
	a1 := DefaultAllowedAttributes()
	a2 := DefaultAllowedAttributes()

	assert.Equal(t, a1, a2)
}

// ==================== SAMLAssertionLog struct ====================

func TestSAMLAssertionLog_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLAssertionLog", func(t *testing.T) {
		id := uuid.New()
		spID := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)
		errMsg := "assertion validation failed"

		log := &SAMLAssertionLog{
			ID:           id,
			SPID:         spID,
			UserID:       &userID,
			AssertionID:  "_abc123",
			NameID:       "user@example.com",
			IPAddress:    "192.168.1.1",
			UserAgent:    "TestBrowser/1.0",
			Status:       "success",
			ErrorMessage: &errMsg,
			CreatedAt:    now,
		}

		assert.Equal(t, id, log.ID)
		assert.Equal(t, spID, log.SPID)
		assert.Equal(t, &userID, log.UserID)
		assert.Equal(t, "_abc123", log.AssertionID)
		assert.Equal(t, "user@example.com", log.NameID)
		assert.Equal(t, "192.168.1.1", log.IPAddress)
		assert.Equal(t, "TestBrowser/1.0", log.UserAgent)
		assert.Equal(t, "success", log.Status)
		assert.Equal(t, &errMsg, log.ErrorMessage)
		assert.Equal(t, now, log.CreatedAt)
	})

	t.Run("should create a minimal SAMLAssertionLog with nil optional fields", func(t *testing.T) {
		log := &SAMLAssertionLog{
			ID:        uuid.New(),
			SPID:      uuid.New(),
			Status:    "failed",
			CreatedAt: time.Now(),
		}

		assert.Nil(t, log.UserID)
		assert.Nil(t, log.ErrorMessage)
	})

	t.Run("failed status log should store error message", func(t *testing.T) {
		errMsg := "invalid signature"
		log := &SAMLAssertionLog{
			ID:           uuid.New(),
			SPID:         uuid.New(),
			Status:       "failed",
			ErrorMessage: &errMsg,
		}

		require.NotNil(t, log.ErrorMessage)
		assert.Equal(t, "invalid signature", *log.ErrorMessage)
	})
}

// ==================== SAMLAuthnRequest struct ====================

func TestSAMLAuthnRequest_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLAuthnRequest", func(t *testing.T) {
		req := &SAMLAuthnRequest{
			ID:                   "_req_001",
			IssueInstant:         "2026-02-24T10:00:00Z",
			Issuer:               "https://sp.example.com",
			AssertionConsumerURL: "https://sp.example.com/acs",
			Destination:          "https://idp.example.com/sso",
			NameIDPolicy:         NameIDFormatEmailAddress,
			ForceAuthn:           true,
			IsPassive:            false,
			RelayState:           "abc123",
		}

		assert.Equal(t, "_req_001", req.ID)
		assert.Equal(t, "2026-02-24T10:00:00Z", req.IssueInstant)
		assert.Equal(t, "https://sp.example.com", req.Issuer)
		assert.Equal(t, "https://sp.example.com/acs", req.AssertionConsumerURL)
		assert.Equal(t, "https://idp.example.com/sso", req.Destination)
		assert.Equal(t, NameIDFormatEmailAddress, req.NameIDPolicy)
		assert.True(t, req.ForceAuthn)
		assert.False(t, req.IsPassive)
		assert.Equal(t, "abc123", req.RelayState)
	})

	t.Run("ForceAuthn and IsPassive should be mutually exclusive by convention", func(t *testing.T) {
		// SAML 2.0 spec: ForceAuthn and IsPassive MUST NOT both be true.
		// We test instantiation only – enforcement is done at service layer.
		req := &SAMLAuthnRequest{
			ForceAuthn: false,
			IsPassive:  true,
		}

		assert.False(t, req.ForceAuthn)
		assert.True(t, req.IsPassive)
	})
}

// ==================== SAMLAssertion struct ====================

func TestSAMLAssertion_Instantiation(t *testing.T) {
	t.Run("should create a fully populated SAMLAssertion", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		notBefore := now.Add(-5 * time.Minute)
		notOnOrAfter := now.Add(1 * time.Hour)
		sessionExpiry := now.Add(8 * time.Hour)

		a := &SAMLAssertion{
			ID:                  "_assertion_001",
			IssueInstant:        now,
			Issuer:              "https://idp.example.com",
			Subject:             "user@example.com",
			SubjectNameIDFormat: NameIDFormatEmailAddress,
			Audience:            "https://sp.example.com",
			Recipient:           "https://sp.example.com/acs",
			SessionIndex:        "_sess_001",
			SessionNotOnOrAfter: sessionExpiry,
			NotBefore:           notBefore,
			NotOnOrAfter:        notOnOrAfter,
			Attributes: map[string][]string{
				"email":       {"user@example.com"},
				"groups":      {"admin", "users"},
				"displayName": {"Test User"},
			},
			InResponseTo: "_req_001",
		}

		assert.Equal(t, "_assertion_001", a.ID)
		assert.Equal(t, now, a.IssueInstant)
		assert.Equal(t, "https://idp.example.com", a.Issuer)
		assert.Equal(t, "user@example.com", a.Subject)
		assert.Equal(t, NameIDFormatEmailAddress, a.SubjectNameIDFormat)
		assert.Equal(t, "https://sp.example.com", a.Audience)
		assert.Equal(t, "https://sp.example.com/acs", a.Recipient)
		assert.Equal(t, "_sess_001", a.SessionIndex)
		assert.Equal(t, sessionExpiry, a.SessionNotOnOrAfter)
		assert.Equal(t, notBefore, a.NotBefore)
		assert.Equal(t, notOnOrAfter, a.NotOnOrAfter)
		assert.Equal(t, []string{"user@example.com"}, a.Attributes["email"])
		assert.Equal(t, []string{"admin", "users"}, a.Attributes["groups"])
		assert.Equal(t, "_req_001", a.InResponseTo)
	})

	t.Run("should store multiple values per attribute", func(t *testing.T) {
		a := &SAMLAssertion{
			Attributes: map[string][]string{
				"roles": {"admin", "editor", "viewer"},
			},
		}

		assert.Len(t, a.Attributes["roles"], 3)
	})
}

// ==================== SAMLServiceProviderListResponse ====================

func TestSAMLServiceProviderListResponse_Instantiation(t *testing.T) {
	t.Run("should create a list response with multiple SPs", func(t *testing.T) {
		resp := &SAMLServiceProviderListResponse{
			ServiceProviders: []SAMLServiceProviderResponse{
				{ID: uuid.New(), Name: "SP One"},
				{ID: uuid.New(), Name: "SP Two"},
			},
			Total: 2,
		}

		assert.Len(t, resp.ServiceProviders, 2)
		assert.Equal(t, int64(2), resp.Total)
	})

	t.Run("should allow an empty list response", func(t *testing.T) {
		resp := &SAMLServiceProviderListResponse{
			ServiceProviders: []SAMLServiceProviderResponse{},
			Total:            0,
		}

		assert.Empty(t, resp.ServiceProviders)
		assert.Equal(t, int64(0), resp.Total)
	})
}

// ==================== SAMLMetadataResponse ====================

func TestSAMLMetadataResponse_Instantiation(t *testing.T) {
	t.Run("should create a fully populated metadata response", func(t *testing.T) {
		r := &SAMLMetadataResponse{
			EntityID:    "https://idp.example.com",
			SSOURL:      "https://idp.example.com/sso",
			SLOURL:      "https://idp.example.com/slo",
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIB...",
			NameIDFormats: []string{
				NameIDFormatEmailAddress,
				NameIDFormatPersistent,
			},
		}

		assert.Equal(t, "https://idp.example.com", r.EntityID)
		assert.Equal(t, "https://idp.example.com/sso", r.SSOURL)
		assert.Equal(t, "https://idp.example.com/slo", r.SLOURL)
		assert.NotEmpty(t, r.Certificate)
		assert.Len(t, r.NameIDFormats, 2)
		assert.Equal(t, NameIDFormatEmailAddress, r.NameIDFormats[0])
		assert.Equal(t, NameIDFormatPersistent, r.NameIDFormats[1])
	})
}

// ==================== JSONMap type ====================

func TestJSONMap_JSONRoundTrip(t *testing.T) {
	t.Run("should marshal and unmarshal JSONMap correctly", func(t *testing.T) {
		original := JSONMap{
			"email":     "user@example.com",
			"count":     float64(42),
			"enabled":   true,
			"nullField": nil,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored JSONMap
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, original["email"], restored["email"])
		assert.Equal(t, original["count"], restored["count"])
		assert.Equal(t, original["enabled"], restored["enabled"])
		assert.Nil(t, restored["nullField"])
	})

	t.Run("should marshal empty JSONMap to empty JSON object", func(t *testing.T) {
		m := JSONMap{}

		data, err := json.Marshal(m)
		require.NoError(t, err)
		assert.Equal(t, "{}", string(data))
	})
}

// ==================== CreateSAMLServiceProviderRequest ====================

func TestCreateSAMLServiceProviderRequest_FieldConstraints(t *testing.T) {
	t.Run("should set all optional fields", func(t *testing.T) {
		sloURL := testSPSLOURL
		metaURL := "https://sp.example.com/meta"
		cert := "certificate-data"
		signAssertions := true
		encryptAssertions := false

		req := &CreateSAMLServiceProviderRequest{
			Name:              "Test SP",
			EntityID:          "https://sp.example.com",
			ACSURL:            "https://sp.example.com/acs",
			SLOURL:            &sloURL,
			MetadataURL:       &metaURL,
			Certificate:       &cert,
			NameIDFormat:      NameIDFormatEmailAddress,
			SignAssertions:    &signAssertions,
			EncryptAssertions: &encryptAssertions,
			AttributeMapping: map[string]string{
				"email": "mail",
			},
			AllowedAttributes: []string{"email", "firstName"},
		}

		assert.Equal(t, "Test SP", req.Name)
		assert.Equal(t, "https://sp.example.com", req.EntityID)
		assert.Equal(t, "https://sp.example.com/acs", req.ACSURL)
		assert.Equal(t, &sloURL, req.SLOURL)
		assert.Equal(t, &metaURL, req.MetadataURL)
		assert.Equal(t, &cert, req.Certificate)
		assert.Equal(t, NameIDFormatEmailAddress, req.NameIDFormat)
		require.NotNil(t, req.SignAssertions)
		assert.True(t, *req.SignAssertions)
		require.NotNil(t, req.EncryptAssertions)
		assert.False(t, *req.EncryptAssertions)
		assert.Equal(t, "mail", req.AttributeMapping["email"])
		assert.Equal(t, []string{"email", "firstName"}, req.AllowedAttributes)
	})

	t.Run("should allow nil optional pointer fields", func(t *testing.T) {
		req := &CreateSAMLServiceProviderRequest{
			Name:     "Minimal SP",
			EntityID: "https://sp.example.com",
			ACSURL:   "https://sp.example.com/acs",
		}

		assert.Nil(t, req.SLOURL)
		assert.Nil(t, req.MetadataURL)
		assert.Nil(t, req.Certificate)
		assert.Nil(t, req.SignAssertions)
		assert.Nil(t, req.EncryptAssertions)
	})
}

// ==================== UpdateSAMLServiceProviderRequest ====================

func TestUpdateSAMLServiceProviderRequest_FieldConstraints(t *testing.T) {
	t.Run("should allow partial update with all fields", func(t *testing.T) {
		name := "Updated SP"
		entityID := "https://sp-updated.example.com"
		acsURL := "https://sp-updated.example.com/acs"
		sloURL := "https://sp-updated.example.com/slo"
		metaURL := "https://sp-updated.example.com/meta"
		cert := "new-cert"
		nameIDFmt := NameIDFormatPersistent
		signAssertions := false
		encryptAssertions := true
		isActive := false

		req := &UpdateSAMLServiceProviderRequest{
			Name:              &name,
			EntityID:          &entityID,
			ACSURL:            &acsURL,
			SLOURL:            &sloURL,
			MetadataURL:       &metaURL,
			Certificate:       &cert,
			NameIDFormat:      &nameIDFmt,
			SignAssertions:    &signAssertions,
			EncryptAssertions: &encryptAssertions,
			AttributeMapping:  map[string]string{"email": "mail"},
			AllowedAttributes: []string{"email"},
			IsActive:          &isActive,
		}

		require.NotNil(t, req.Name)
		assert.Equal(t, "Updated SP", *req.Name)
		require.NotNil(t, req.EntityID)
		assert.Equal(t, "https://sp-updated.example.com", *req.EntityID)
		require.NotNil(t, req.ACSURL)
		assert.Equal(t, "https://sp-updated.example.com/acs", *req.ACSURL)
		require.NotNil(t, req.NameIDFormat)
		assert.Equal(t, NameIDFormatPersistent, *req.NameIDFormat)
		require.NotNil(t, req.SignAssertions)
		assert.False(t, *req.SignAssertions)
		require.NotNil(t, req.EncryptAssertions)
		assert.True(t, *req.EncryptAssertions)
		require.NotNil(t, req.IsActive)
		assert.False(t, *req.IsActive)
	})

	t.Run("should allow a fully nil update (noop patch)", func(t *testing.T) {
		req := &UpdateSAMLServiceProviderRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.EntityID)
		assert.Nil(t, req.ACSURL)
		assert.Nil(t, req.SLOURL)
		assert.Nil(t, req.MetadataURL)
		assert.Nil(t, req.Certificate)
		assert.Nil(t, req.NameIDFormat)
		assert.Nil(t, req.SignAssertions)
		assert.Nil(t, req.EncryptAssertions)
		assert.Nil(t, req.IsActive)
	})
}
