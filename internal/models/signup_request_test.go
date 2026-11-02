// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== AccountType constants ====================

func TestAccountTypeConstants(t *testing.T) {
	assert.Equal(t, AccountType("personal"), AccountTypePersonal)
	assert.Equal(t, AccountType("business"), AccountTypeBusiness)
}

// ==================== SignupRequest — VerificationToken hidden from JSON ====================

func TestSignupRequest_VerificationToken_NotInJSON(t *testing.T) {
	t.Run("VerificationToken must be absent from JSON output", func(t *testing.T) {
		token := "very-secret-email-verification-token-abc123"
		now := time.Now().Truncate(time.Second)

		sr := &SignupRequest{
			ID:                uuid.New(),
			Email:             "alice@example.com",
			AccountType:       string(AccountTypePersonal),
			VerificationToken: token,
			Verified:          false,
			ExpiresAt:         now.Add(24 * time.Hour),
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		data, err := json.Marshal(sr)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["verification_token"]
		assert.False(t, exists, "verification_token must not appear in JSON due to json:\"-\" tag")

		_, exists = raw["VerificationToken"]
		assert.False(t, exists, "VerificationToken must not appear under any capitalisation")

		// The literal token value must not leak.
		assert.NotContains(t, string(data), token,
			"raw token value must not be present anywhere in the JSON output")
	})
}

// ==================== SignupRequest — JSON serialisation ====================

func TestSignupRequest_JSONSerialization(t *testing.T) {
	t.Run("all public fields serialised when fully populated", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		userID := uuid.New()
		now := time.Now().Truncate(time.Second)
		verifiedAt := now.Add(-30 * time.Minute)
		completedAt := now.Add(-10 * time.Minute)
		firstName := "Alice"
		lastName := "Smith"
		companyName := "Acme Corp"
		companySlug := "acme-corp"
		ip := "203.0.113.42"
		ua := "Mozilla/5.0"

		sr := &SignupRequest{
			ID:                id,
			Email:             "alice@acme.com",
			FirstName:         &firstName,
			LastName:          &lastName,
			AccountType:       string(AccountTypeBusiness),
			CompanyName:       &companyName,
			CompanySlug:       &companySlug,
			VerificationToken: "must-not-appear",
			Verified:          true,
			VerifiedAt:        &verifiedAt,
			Completed:         true,
			CompletedAt:       &completedAt,
			TenantID:          &tenantID,
			UserID:            &userID,
			IPAddress:         &ip,
			UserAgent:         &ua,
			ExpiresAt:         now.Add(24 * time.Hour),
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		data, err := json.Marshal(sr)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Contains(t, raw, "id")
		assert.Contains(t, raw, "email")
		assert.Equal(t, "alice@acme.com", raw["email"])
		assert.Contains(t, raw, "first_name")
		assert.Equal(t, firstName, raw["first_name"])
		assert.Contains(t, raw, "last_name")
		assert.Contains(t, raw, "account_type")
		assert.Equal(t, string(AccountTypeBusiness), raw["account_type"])
		assert.Contains(t, raw, "company_name")
		assert.Contains(t, raw, "company_slug")
		assert.Contains(t, raw, "verified")
		assert.Equal(t, true, raw["verified"])
		assert.Contains(t, raw, "verified_at")
		assert.Contains(t, raw, "completed")
		assert.Equal(t, true, raw["completed"])
		assert.Contains(t, raw, "completed_at")
		assert.Contains(t, raw, "tenant_id")
		assert.Contains(t, raw, "user_id")
		assert.Contains(t, raw, "ip_address")
		assert.Contains(t, raw, "user_agent")
		assert.Contains(t, raw, "expires_at")
		assert.Contains(t, raw, "created_at")
		assert.Contains(t, raw, "updated_at")

		// Sensitive field must be absent.
		_, exists := raw["verification_token"]
		assert.False(t, exists)
	})

	t.Run("optional nil pointer fields omitted (omitempty)", func(t *testing.T) {
		sr := &SignupRequest{
			ID:                uuid.New(),
			Email:             "bob@example.com",
			AccountType:       string(AccountTypePersonal),
			VerificationToken: "tok",
			ExpiresAt:         time.Now().Add(time.Hour),
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		data, err := json.Marshal(sr)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		for _, key := range []string{
			"first_name", "last_name", "company_name", "company_slug",
			"verified_at", "completed_at", "tenant_id", "user_id",
			"ip_address", "user_agent",
		} {
			_, exists := raw[key]
			assert.False(t, exists, "%s must be omitted when nil", key)
		}
	})
}

// ==================== SignupRequest — account_type values ====================

func TestSignupRequest_AccountTypeValues(t *testing.T) {
	tests := []struct {
		name        string
		accountType string
		wantValid   bool
	}{
		{
			name:        "personal account type",
			accountType: string(AccountTypePersonal),
			wantValid:   true,
		},
		{
			name:        "business account type",
			accountType: string(AccountTypeBusiness),
			wantValid:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := &SignupRequest{
				AccountType: tt.accountType,
			}
			assert.Equal(t, tt.accountType, sr.AccountType)
		})
	}
}

// ==================== SignupRequest.IsExpired ====================

func TestSignupRequest_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "returns true when ExpiresAt is in the past",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "returns true when ExpiresAt is one nanosecond in the past",
			expiresAt: time.Now().Add(-1 * time.Nanosecond),
			expected:  true,
		},
		{
			name:      "returns false when ExpiresAt is in the future",
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "returns false when ExpiresAt is 48 hours in the future",
			expiresAt: time.Now().Add(48 * time.Hour),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := &SignupRequest{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, sr.IsExpired())
		})
	}
}

// ==================== SignupRequest.IsComplete ====================

func TestSignupRequest_IsComplete(t *testing.T) {
	tests := []struct {
		name     string
		verified bool
		complete bool
		expected bool
	}{
		{
			name:     "returns true when both verified and completed",
			verified: true,
			complete: true,
			expected: true,
		},
		{
			name:     "returns false when verified but not completed",
			verified: true,
			complete: false,
			expected: false,
		},
		{
			name:     "returns false when completed but not verified",
			verified: false,
			complete: true,
			expected: false,
		},
		{
			name:     "returns false when neither verified nor completed",
			verified: false,
			complete: false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := &SignupRequest{
				Verified:  tt.verified,
				Completed: tt.complete,
			}
			assert.Equal(t, tt.expected, sr.IsComplete())
		})
	}
}

// ==================== CreateSignupRequestInput validation ====================

func TestCreateSignupRequestInput_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       CreateSignupRequestInput
		wantValid bool
		wantField string
	}{
		{
			name: "valid personal account with only email",
			req: CreateSignupRequestInput{
				Email:       "alice@example.com",
				AccountType: "personal",
			},
			wantValid: true,
		},
		{
			name: "valid business account with company_name",
			req: CreateSignupRequestInput{
				Email:       "ceo@acme.com",
				AccountType: "business",
				CompanyName: "Acme Corp",
			},
			wantValid: true,
		},
		{
			name: "valid personal account with optional name fields",
			req: CreateSignupRequestInput{
				Email:       "alice@example.com",
				FirstName:   "Alice",
				LastName:    "Smith",
				AccountType: "personal",
			},
			wantValid: true,
		},
		{
			// Email is optional at the struct level — personal signup derives
			// it from Username (the "username or email required" rule is enforced
			// in the service layer, not the binding tags).
			name:      "personal signup with username and no email is valid",
			req:       CreateSignupRequestInput{AccountType: "personal", Username: "alice"},
			wantValid: true,
		},
		{
			name:      "invalid email format fails email validation",
			req:       CreateSignupRequestInput{Email: "not-an-email", AccountType: "personal"},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "missing account_type fails required",
			req:       CreateSignupRequestInput{Email: "alice@example.com"},
			wantValid: false,
			wantField: "AccountType",
		},
		{
			name:      "invalid account_type fails oneof",
			req:       CreateSignupRequestInput{Email: "alice@example.com", AccountType: "enterprise"},
			wantValid: false,
			wantField: "AccountType",
		},
		{
			name:      "first_name exceeds max length",
			req:       CreateSignupRequestInput{Email: "alice@example.com", AccountType: "personal", FirstName: string(make([]byte, 101))},
			wantValid: false,
			wantField: "FirstName",
		},
		{
			name:      "first_name at max length is valid",
			req:       CreateSignupRequestInput{Email: "alice@example.com", AccountType: "personal", FirstName: string(make([]byte, 100))},
			wantValid: true,
		},
		{
			name:      "last_name exceeds max length",
			req:       CreateSignupRequestInput{Email: "alice@example.com", AccountType: "personal", LastName: string(make([]byte, 101))},
			wantValid: false,
			wantField: "LastName",
		},
		{
			name:      "company_name exceeds max length for business",
			req:       CreateSignupRequestInput{Email: "ceo@corp.com", AccountType: "business", CompanyName: string(make([]byte, 256))},
			wantValid: false,
			wantField: "CompanyName",
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

// ==================== VerifySignupEmailInput validation ====================

func TestVerifySignupEmailInput_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       VerifySignupEmailInput
		wantValid bool
		wantField string
	}{
		{
			name:      "valid token",
			req:       VerifySignupEmailInput{Token: "abc123def456"},
			wantValid: true,
		},
		{
			name:      "valid code with signup id",
			req:       VerifySignupEmailInput{SignupID: "6f1c2a7e", Code: "123456"},
			wantValid: true,
		},
		{
			// Code-or-token presence is enforced by SignupService.VerifyEmail
			// (verification_code_invalid), not by binding tags.
			name:      "empty input passes binding",
			req:       VerifySignupEmailInput{},
			wantValid: true,
		},
		{
			name:      "oversized code fails max",
			req:       VerifySignupEmailInput{Code: strings.Repeat("1", 33)},
			wantValid: false,
			wantField: "Code",
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

// ==================== CompleteSignupInput binding validation ====================

func TestCompleteSignupInput_Validation(t *testing.T) {
	// Password policy intentionally is not a binding concern: it is evaluated by
	// the handler/service so dynamic rules produce structured 422 responses.
	// See TestSignupPolicy_DirectHTTPBypassAndPublicContract and
	// TestSignupPasswordPolicy_RejectsBeforeAllSideEffects.
	tests := []struct {
		name      string
		req       CompleteSignupInput
		wantValid bool
		wantField string
	}{
		{
			name: "request with password binds",
			req: CompleteSignupInput{
				SignupRequestID: uuid.New(),
				Password:        "x",
			},
			wantValid: true,
		},
		{
			name: "missing signup_request_id fails required",
			req: CompleteSignupInput{
				Password: "securep4ss",
			},
			wantValid: false,
			wantField: "SignupRequestID",
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

// ==================== SignupRequest JSON round-trip ====================

func TestSignupRequest_JSONRoundTrip(t *testing.T) {
	t.Run("public fields survive marshal/unmarshal cycle", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().UTC().Truncate(time.Second)
		firstName := "Bob"

		original := &SignupRequest{
			ID:                id,
			Email:             "bob@example.com",
			FirstName:         &firstName,
			AccountType:       string(AccountTypePersonal),
			VerificationToken: "secret-token-that-must-not-round-trip",
			Verified:          false,
			Completed:         false,
			ExpiresAt:         now.Add(48 * time.Hour),
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded SignupRequest
		require.NoError(t, json.Unmarshal(data, &decoded))

		assert.Equal(t, original.ID, decoded.ID)
		assert.Equal(t, original.Email, decoded.Email)
		require.NotNil(t, decoded.FirstName)
		assert.Equal(t, *original.FirstName, *decoded.FirstName)
		assert.Equal(t, original.AccountType, decoded.AccountType)

		// VerificationToken must not have round-tripped.
		assert.Empty(t, decoded.VerificationToken,
			"VerificationToken must be empty after JSON round-trip")
	})
}
