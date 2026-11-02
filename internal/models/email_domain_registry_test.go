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

// ==================== VerificationMethod constants ====================

func TestVerificationMethodConstants(t *testing.T) {
	assert.Equal(t, VerificationMethod("dns_txt"), VerificationMethodDNSTXT)
	assert.Equal(t, VerificationMethod("dns_cname"), VerificationMethodDNSCNAME)
	assert.Equal(t, VerificationMethod("http_file"), VerificationMethodHTTPFile)
}

// ==================== EmailDomainRegistry JSON — VerificationToken hidden ====================

func TestEmailDomainRegistry_VerificationToken_NotInJSON(t *testing.T) {
	t.Run("VerificationToken must be absent from JSON output", func(t *testing.T) {
		token := "super-secret-dns-verification-token"
		now := time.Now().Truncate(time.Second)

		reg := &EmailDomainRegistry{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			Domain:             "example.com",
			IsVerified:         false,
			VerificationToken:  &token,
			VerificationMethod: string(VerificationMethodDNSTXT),
			AutoEnroll:         true,
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		data, err := json.Marshal(reg)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["verification_token"]
		assert.False(t, exists, "verification_token must not appear in JSON output due to json:\"-\" tag")

		_, exists = raw["VerificationToken"]
		assert.False(t, exists, "VerificationToken must not appear under any capitalisation")

		// The raw token value itself must not appear anywhere in the serialised output.
		assert.NotContains(t, string(data), token,
			"raw token value must not leak into JSON output")
	})

	t.Run("nil VerificationToken must also be absent from JSON output", func(t *testing.T) {
		reg := &EmailDomainRegistry{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			Domain:             "example.com",
			VerificationMethod: string(VerificationMethodHTTPFile),
		}

		data, err := json.Marshal(reg)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["verification_token"]
		assert.False(t, exists, "nil verification_token must not appear in JSON output")
	})
}

// ==================== EmailDomainRegistry JSON — public fields present ====================

func TestEmailDomainRegistry_JSONSerialization(t *testing.T) {
	t.Run("all public fields are serialised correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		token := "tok-abc123"
		now := time.Now().Truncate(time.Second)
		verifiedAt := now.Add(-1 * time.Hour)

		reg := &EmailDomainRegistry{
			ID:                 id,
			TenantID:           tenantID,
			Domain:             "example.com",
			IsVerified:         true,
			VerificationToken:  &token,
			VerificationMethod: string(VerificationMethodDNSCNAME),
			VerifiedAt:         &verifiedAt,
			AutoEnroll:         true,
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		data, err := json.Marshal(reg)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Contains(t, raw, "id")
		assert.Contains(t, raw, "tenant_id")
		assert.Contains(t, raw, "domain")
		assert.Equal(t, "example.com", raw["domain"])
		assert.Contains(t, raw, "is_verified")
		assert.Equal(t, true, raw["is_verified"])
		assert.Contains(t, raw, "verification_method")
		assert.Equal(t, string(VerificationMethodDNSCNAME), raw["verification_method"])
		assert.Contains(t, raw, "verified_at", "verified_at must be present when non-nil")
		assert.Contains(t, raw, "auto_enroll")
		assert.Contains(t, raw, "created_at")
		assert.Contains(t, raw, "updated_at")
	})

	t.Run("verified_at is omitted when nil (omitempty)", func(t *testing.T) {
		reg := &EmailDomainRegistry{
			ID:                 uuid.New(),
			TenantID:           uuid.New(),
			Domain:             "unverified.com",
			IsVerified:         false,
			VerificationMethod: string(VerificationMethodDNSTXT),
			VerifiedAt:         nil,
		}

		data, err := json.Marshal(reg)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["verified_at"]
		assert.False(t, exists, "verified_at must be omitted from JSON when nil")
	})
}

// ==================== CreateEmailDomainRequest validation ====================

func TestCreateEmailDomainRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       CreateEmailDomainRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid minimal request",
			req:       CreateEmailDomainRequest{Domain: "example.com"},
			wantValid: true,
		},
		{
			name:      "valid request with auto_enroll true",
			req:       CreateEmailDomainRequest{Domain: "corp.example.com", AutoEnroll: true},
			wantValid: true,
		},
		{
			name:      "missing domain fails required",
			req:       CreateEmailDomainRequest{},
			wantValid: false,
			wantField: "Domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := validateStruct(t, tt.req)
			if tt.wantValid {
				assert.Nil(t, ve, "expected no validation errors")
				return
			}
			require.NotNil(t, ve, "expected validation errors but got none")
			assert.True(t, hasFieldError(ve, tt.wantField),
				"expected error on field %q, got: %v", tt.wantField, ve)
		})
	}
}

// ==================== VerifyDomainRequest validation ====================

func TestVerifyDomainRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       VerifyDomainRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid dns_txt method",
			req:       VerifyDomainRequest{VerificationMethod: "dns_txt"},
			wantValid: true,
		},
		{
			name:      "valid dns_cname method",
			req:       VerifyDomainRequest{VerificationMethod: "dns_cname"},
			wantValid: true,
		},
		{
			name:      "valid http_file method",
			req:       VerifyDomainRequest{VerificationMethod: "http_file"},
			wantValid: true,
		},
		{
			name:      "missing verification_method fails required",
			req:       VerifyDomainRequest{},
			wantValid: false,
			wantField: "VerificationMethod",
		},
		{
			name:      "unknown method email fails oneof",
			req:       VerifyDomainRequest{VerificationMethod: "email"},
			wantValid: false,
			wantField: "VerificationMethod",
		},
		{
			name:      "uppercase DNS_TXT fails oneof (case-sensitive)",
			req:       VerifyDomainRequest{VerificationMethod: "DNS_TXT"},
			wantValid: false,
			wantField: "VerificationMethod",
		},
		{
			name:      "arbitrary string fails oneof",
			req:       VerifyDomainRequest{VerificationMethod: "smtp"},
			wantValid: false,
			wantField: "VerificationMethod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ve := validateStruct(t, tt.req)
			if tt.wantValid {
				assert.Nil(t, ve, "expected no validation errors")
				return
			}
			require.NotNil(t, ve, "expected validation errors but got none")
			assert.True(t, hasFieldError(ve, tt.wantField),
				"expected error on field %q, got: %v", tt.wantField, ve)
		})
	}
}

// ==================== EmailDomainRegistry zero-value safety ====================

func TestEmailDomainRegistry_ZeroValue(t *testing.T) {
	t.Run("zero-value struct marshals without panic", func(t *testing.T) {
		var reg EmailDomainRegistry
		data, err := json.Marshal(&reg)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
}
