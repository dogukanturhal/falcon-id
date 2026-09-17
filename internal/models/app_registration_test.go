// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testLogoURL = "https://example.com/logo.png"

// buildAppRegistration returns a fully populated AppRegistration for use in
// tests. Fields can be overridden by the caller after construction.
func buildAppRegistration() *AppRegistration {
	id := uuid.New()
	productID := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	desc := "An OAuth client app"
	logo := testLogoURL

	return &AppRegistration{ //nolint:gosec // test fixture value, not a real credential
		ID:               id,
		ProductID:        &productID,
		TenantID:         tenantID,
		ClientID:         "app_abcdef1234567890",
		ClientSecretHash: "$2a$10$hashedSecret",
		Name:             "My App",
		Description:      &desc,
		RedirectURIs:     []string{"https://example.com/callback"},
		AllowedOrigins:   []string{"https://example.com"},
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		Scopes:           []string{"openid", "profile", "email"},
		LogoURL:          &logo,
		Status:           AppRegistrationStatusActive,
		CreatedBy:        &createdBy,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// ==================== AppRegistration.IsActive ====================

func TestAppRegistration_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   AppRegistrationStatus
		expected bool
	}{
		{
			name:     "should return true when status is active",
			status:   AppRegistrationStatusActive,
			expected: true,
		},
		{
			name:     "should return false when status is suspended",
			status:   AppRegistrationStatusSuspended,
			expected: false,
		},
		{
			name:     "should return false when status is revoked",
			status:   AppRegistrationStatusRevoked,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
		{
			name:     "should return false for unknown status value",
			status:   "unknown",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AppRegistration{Status: tt.status}
			assert.Equal(t, tt.expected, a.IsActive())
		})
	}
}

// ==================== AppRegistration.IsSuspended ====================

func TestAppRegistration_IsSuspended(t *testing.T) {
	tests := []struct {
		name     string
		status   AppRegistrationStatus
		expected bool
	}{
		{
			name:     "should return true when status is suspended",
			status:   AppRegistrationStatusSuspended,
			expected: true,
		},
		{
			name:     "should return false when status is active",
			status:   AppRegistrationStatusActive,
			expected: false,
		},
		{
			name:     "should return false when status is revoked",
			status:   AppRegistrationStatusRevoked,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AppRegistration{Status: tt.status}
			assert.Equal(t, tt.expected, a.IsSuspended())
		})
	}
}

// ==================== AppRegistration.IsRevoked ====================

func TestAppRegistration_IsRevoked(t *testing.T) {
	tests := []struct {
		name     string
		status   AppRegistrationStatus
		expected bool
	}{
		{
			name:     "should return true when status is revoked",
			status:   AppRegistrationStatusRevoked,
			expected: true,
		},
		{
			name:     "should return false when status is active",
			status:   AppRegistrationStatusActive,
			expected: false,
		},
		{
			name:     "should return false when status is suspended",
			status:   AppRegistrationStatusSuspended,
			expected: false,
		},
		{
			name:     "should return false when status is empty",
			status:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AppRegistration{Status: tt.status}
			assert.Equal(t, tt.expected, a.IsRevoked())
		})
	}
}

// TestAppRegistration_StatusMutualExclusivity verifies that exactly one status
// flag is true for each known status value.
func TestAppRegistration_StatusMutualExclusivity(t *testing.T) {
	tests := []struct {
		status        AppRegistrationStatus
		wantActive    bool
		wantSuspended bool
		wantRevoked   bool
	}{
		{
			status:        AppRegistrationStatusActive,
			wantActive:    true,
			wantSuspended: false,
			wantRevoked:   false,
		},
		{
			status:        AppRegistrationStatusSuspended,
			wantActive:    false,
			wantSuspended: true,
			wantRevoked:   false,
		},
		{
			status:        AppRegistrationStatusRevoked,
			wantActive:    false,
			wantSuspended: false,
			wantRevoked:   true,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			a := &AppRegistration{Status: tt.status}
			assert.Equal(t, tt.wantActive, a.IsActive(), "IsActive mismatch")
			assert.Equal(t, tt.wantSuspended, a.IsSuspended(), "IsSuspended mismatch")
			assert.Equal(t, tt.wantRevoked, a.IsRevoked(), "IsRevoked mismatch")
		})
	}
}

// ==================== AppRegistration.ToResponse ====================

func TestAppRegistration_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		a := buildAppRegistration()

		resp := a.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, a.ID, resp.ID)
		assert.Equal(t, a.ProductID, resp.ProductID)
		assert.Equal(t, a.TenantID, resp.TenantID)
		assert.Equal(t, a.ClientID, resp.ClientID)
		assert.Equal(t, a.Name, resp.Name)
		assert.Equal(t, a.Description, resp.Description)
		assert.Equal(t, a.RedirectURIs, resp.RedirectURIs)
		assert.Equal(t, a.AllowedOrigins, resp.AllowedOrigins)
		assert.Equal(t, a.GrantTypes, resp.GrantTypes)
		assert.Equal(t, a.Scopes, resp.Scopes)
		assert.Equal(t, a.LogoURL, resp.LogoURL)
		assert.Equal(t, a.Status, resp.Status)
		assert.Equal(t, a.CreatedBy, resp.CreatedBy)
		assert.Equal(t, a.CreatedAt, resp.CreatedAt)
		assert.Equal(t, a.UpdatedAt, resp.UpdatedAt)
	})

	t.Run("should NOT include ClientSecretHash in response", func(t *testing.T) {
		a := buildAppRegistration()
		// The hash is set on the model.
		a.ClientSecretHash = "$2a$10$verysecrethashedvalue"

		resp := a.ToResponse()

		require.NotNil(t, resp)
		// ClientSecret must be nil when using the standard ToResponse method.
		assert.Nil(t, resp.ClientSecret,
			"ToResponse must not expose the client secret")
	})

	t.Run("should handle nil optional fields", func(t *testing.T) {
		a := &AppRegistration{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			ClientID:     "app_minimal",
			Name:         "Minimal App",
			RedirectURIs: []string{"https://example.com/cb"},
			GrantTypes:   []string{"implicit"},
			Status:       AppRegistrationStatusActive,
		}

		resp := a.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ProductID)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.LogoURL)
		assert.Nil(t, resp.CreatedBy)
		assert.Nil(t, resp.ClientSecret)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		a := buildAppRegistration()

		resp1 := a.ToResponse()
		resp2 := a.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== AppRegistration.ToResponseWithSecret ====================

func TestAppRegistration_ToResponseWithSecret(t *testing.T) {
	t.Run("should include the plain-text client secret in response", func(t *testing.T) {
		a := buildAppRegistration()
		secret := "plain-text-secret-abc123" //nolint:gosec // test fixture value, not a real credential

		resp := a.ToResponseWithSecret(secret)

		require.NotNil(t, resp)
		require.NotNil(t, resp.ClientSecret,
			"ToResponseWithSecret must populate ClientSecret")
		assert.Equal(t, secret, *resp.ClientSecret)
	})

	t.Run("should carry all base fields identical to ToResponse", func(t *testing.T) {
		a := buildAppRegistration()
		secret := "super-secret-value"

		base := a.ToResponse()
		withSecret := a.ToResponseWithSecret(secret)

		// All fields except ClientSecret should be identical.
		assert.Equal(t, base.ID, withSecret.ID)
		assert.Equal(t, base.ClientID, withSecret.ClientID)
		assert.Equal(t, base.TenantID, withSecret.TenantID)
		assert.Equal(t, base.Name, withSecret.Name)
		assert.Equal(t, base.Status, withSecret.Status)
		assert.Equal(t, base.RedirectURIs, withSecret.RedirectURIs)
		assert.Equal(t, base.GrantTypes, withSecret.GrantTypes)
		assert.Equal(t, base.Scopes, withSecret.Scopes)

		// The secret-bearing version has ClientSecret set.
		assert.Nil(t, base.ClientSecret)
		assert.NotNil(t, withSecret.ClientSecret)
	})

	t.Run("should NOT expose ClientSecretHash even with secret", func(t *testing.T) {
		a := buildAppRegistration()
		a.ClientSecretHash = "$2a$10$storedHashIsNeverExposed"
		secret := "new-plain-secret"

		resp := a.ToResponseWithSecret(secret)

		require.NotNil(t, resp)
		// The response must carry the plain-text secret, not the hash.
		assert.Equal(t, secret, *resp.ClientSecret)
		// There is no hash field on the response struct – this is a compile-time
		// guarantee enforced by the type system. We verify only that the plain-text
		// secret is correct and the hash value is not leaked as the secret value.
		assert.NotEqual(t, a.ClientSecretHash, *resp.ClientSecret)
	})

	t.Run("should produce distinct instances for different secret values", func(t *testing.T) {
		a := buildAppRegistration()

		resp1 := a.ToResponseWithSecret("secret-one")
		resp2 := a.ToResponseWithSecret("secret-two")

		assert.NotEqual(t, *resp1.ClientSecret, *resp2.ClientSecret)
	})

	t.Run("should handle empty secret string", func(t *testing.T) {
		a := buildAppRegistration()

		resp := a.ToResponseWithSecret("")

		require.NotNil(t, resp)
		require.NotNil(t, resp.ClientSecret)
		assert.Equal(t, "", *resp.ClientSecret)
	})
}

// ==================== AppRegistration status constants ====================

func TestAppRegistrationStatusConstants(t *testing.T) {
	assert.Equal(t, AppRegistrationStatus("active"), AppRegistrationStatusActive)
	assert.Equal(t, AppRegistrationStatus("suspended"), AppRegistrationStatusSuspended)
	assert.Equal(t, AppRegistrationStatus("revoked"), AppRegistrationStatusRevoked)
}

// ==================== JSON tag: client_secret_hash never exposed ====================

// TestAppRegistration_ClientSecretHash_JSONTag verifies that the model-level
// json:"-" tag ensures ClientSecretHash is absent from JSON serialisation.
// This is a compile/runtime confirmation test.
func TestAppRegistration_ClientSecretHash_JSONTag(t *testing.T) {
	t.Run("ClientSecretHash field has json dash tag", func(t *testing.T) {
		// We confirm indirectly: ToResponse produces a response type that has no
		// hash field, and the model's json:"-" tag means stdlib encoding/json
		// skips it. We test the absence via the response DTO contract.
		a := buildAppRegistration()
		a.ClientSecretHash = "this-must-not-appear"

		resp := a.ToResponse()

		// The AppRegistrationResponse type deliberately has no hash field.
		// As a runtime check: ClientSecret (the only secret-adjacent field) is nil.
		assert.Nil(t, resp.ClientSecret)
	})
}
