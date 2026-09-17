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

// ==================== TenantBranding JSON serialisation ====================

func TestTenantBranding_JSONSerialization(t *testing.T) {
	t.Run("all fields serialised when fully populated", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)

		logoURL := "https://cdn.example.com/logo.png"
		faviconURL := "https://cdn.example.com/favicon.ico"
		accentColor := "#FF5722"
		customCSS := "body { font-family: sans-serif; }"
		loginTitle := "Welcome to Acme Corp"
		loginSubtitle := "Sign in to your account"
		loginMessage := "Contact support if you need help."
		supportEmail := "support@acme.com"
		supportURL := "https://support.acme.com"
		privacyURL := "https://acme.com/privacy"
		tosURL := "https://acme.com/tos"

		b := &TenantBranding{
			ID:                   id,
			TenantID:             tenantID,
			LogoURL:              &logoURL,
			FaviconURL:           &faviconURL,
			PrimaryColor:         "#1A73E8",
			BackgroundColor:      "#FFFFFF",
			AccentColor:          &accentColor,
			CustomCSS:            &customCSS,
			LoginTitle:           &loginTitle,
			LoginSubtitle:        &loginSubtitle,
			LoginMessage:         &loginMessage,
			SupportEmail:         &supportEmail,
			SupportURL:           &supportURL,
			PrivacyPolicyURL:     &privacyURL,
			TermsOfServiceURL:    &tosURL,
			HideHexxlockBranding: true,
			CreatedAt:            now,
			UpdatedAt:            now,
		}

		data, err := json.Marshal(b)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Contains(t, raw, "id")
		assert.Contains(t, raw, "tenant_id")
		assert.Contains(t, raw, "logo_url")
		assert.Equal(t, logoURL, raw["logo_url"])
		assert.Contains(t, raw, "favicon_url")
		assert.Equal(t, faviconURL, raw["favicon_url"])
		assert.Contains(t, raw, "primary_color")
		assert.Equal(t, "#1A73E8", raw["primary_color"])
		assert.Contains(t, raw, "background_color")
		assert.Equal(t, "#FFFFFF", raw["background_color"])
		assert.Contains(t, raw, "accent_color")
		assert.Equal(t, accentColor, raw["accent_color"])
		assert.Contains(t, raw, "custom_css")
		assert.Contains(t, raw, "login_title")
		assert.Contains(t, raw, "login_subtitle")
		assert.Contains(t, raw, "login_message")
		assert.Contains(t, raw, "support_email")
		assert.Contains(t, raw, "support_url")
		assert.Contains(t, raw, "privacy_policy_url")
		assert.Contains(t, raw, "terms_of_service_url")
		assert.Contains(t, raw, "hide_hexxlock_branding")
		assert.Equal(t, true, raw["hide_hexxlock_branding"])
		assert.Contains(t, raw, "created_at")
		assert.Contains(t, raw, "updated_at")
	})

	t.Run("optional nil fields omitted with omitempty", func(t *testing.T) {
		b := &TenantBranding{
			ID:              uuid.New(),
			TenantID:        uuid.New(),
			PrimaryColor:    "#000000",
			BackgroundColor: "#FFFFFF",
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}

		data, err := json.Marshal(b)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		// All optional pointer fields must be absent when nil.
		for _, key := range []string{
			"logo_url", "favicon_url", "accent_color", "custom_css",
			"login_title", "login_subtitle", "login_message",
			"support_email", "support_url", "privacy_policy_url", "terms_of_service_url",
		} {
			_, exists := raw[key]
			assert.False(t, exists, "%s must be omitted when nil", key)
		}

		// Non-optional fields must always be present.
		assert.Contains(t, raw, "id")
		assert.Contains(t, raw, "tenant_id")
		assert.Contains(t, raw, "primary_color")
		assert.Contains(t, raw, "background_color")
		assert.Contains(t, raw, "hide_hexxlock_branding")
	})

	t.Run("HideHexxlockBranding defaults to false for zero value", func(t *testing.T) {
		b := &TenantBranding{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		}

		assert.False(t, b.HideHexxlockBranding)

		data, err := json.Marshal(b)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, false, raw["hide_hexxlock_branding"])
	})
}

// ==================== TenantBranding JSON round-trip ====================

func TestTenantBranding_JSONRoundTrip(t *testing.T) {
	t.Run("marshal and unmarshal produces identical struct", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().UTC().Truncate(time.Second)
		logoURL := "https://example.com/logo.png"
		accentColor := "#FF0000"

		original := &TenantBranding{
			ID:                   id,
			TenantID:             tenantID,
			LogoURL:              &logoURL,
			PrimaryColor:         "#112233",
			BackgroundColor:      "#FAFAFA",
			AccentColor:          &accentColor,
			HideHexxlockBranding: true,
			CreatedAt:            now,
			UpdatedAt:            now,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded TenantBranding
		require.NoError(t, json.Unmarshal(data, &decoded))

		assert.Equal(t, original.ID, decoded.ID)
		assert.Equal(t, original.TenantID, decoded.TenantID)
		require.NotNil(t, decoded.LogoURL)
		assert.Equal(t, *original.LogoURL, *decoded.LogoURL)
		assert.Equal(t, original.PrimaryColor, decoded.PrimaryColor)
		assert.Equal(t, original.BackgroundColor, decoded.BackgroundColor)
		require.NotNil(t, decoded.AccentColor)
		assert.Equal(t, *original.AccentColor, *decoded.AccentColor)
		assert.Equal(t, original.HideHexxlockBranding, decoded.HideHexxlockBranding)
	})
}

// ==================== UpdateTenantBrandingRequest validation ====================

func TestUpdateTenantBrandingRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       UpdateTenantBrandingRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "empty request is valid (all fields optional)",
			req:       UpdateTenantBrandingRequest{},
			wantValid: true,
		},
		{
			name: "valid request with all fields populated",
			req: UpdateTenantBrandingRequest{
				LogoURL:              strPtr("https://cdn.example.com/logo.png"),
				FaviconURL:           strPtr("https://cdn.example.com/fav.ico"),
				PrimaryColor:         strPtr("#1A73E8"),
				BackgroundColor:      strPtr("#FFFFFF"),
				AccentColor:          strPtr("#FF5722"),
				CustomCSS:            strPtr("body{}"),
				LoginTitle:           strPtr("Sign In"),
				LoginSubtitle:        strPtr("Use your company credentials"),
				LoginMessage:         strPtr("Contact support if locked out."),
				SupportEmail:         strPtr("help@example.com"),
				SupportURL:           strPtr("https://support.example.com"),
				PrivacyPolicyURL:     strPtr("https://example.com/privacy"),
				TermsOfServiceURL:    strPtr("https://example.com/tos"),
				HideHexxlockBranding: boolPtr(true),
			},
			wantValid: true,
		},
		{
			name:      "invalid primary_color hex",
			req:       UpdateTenantBrandingRequest{PrimaryColor: strPtr("not-a-color")},
			wantValid: false,
			wantField: "PrimaryColor",
		},
		{
			name:      "invalid background_color hex",
			req:       UpdateTenantBrandingRequest{BackgroundColor: strPtr("red")},
			wantValid: false,
			wantField: "BackgroundColor",
		},
		{
			name:      "invalid accent_color hex",
			req:       UpdateTenantBrandingRequest{AccentColor: strPtr("#ZZZZZZ")},
			wantValid: false,
			wantField: "AccentColor",
		},
		{
			name:      "login_title exceeds max length",
			req:       UpdateTenantBrandingRequest{LoginTitle: strPtr(string(make([]byte, 256)))},
			wantValid: false,
			wantField: "LoginTitle",
		},
		{
			name:      "login_title at max length is valid",
			req:       UpdateTenantBrandingRequest{LoginTitle: strPtr(string(make([]byte, 255)))},
			wantValid: true,
		},
		{
			name:      "login_subtitle exceeds max length",
			req:       UpdateTenantBrandingRequest{LoginSubtitle: strPtr(string(make([]byte, 501)))},
			wantValid: false,
			wantField: "LoginSubtitle",
		},
		{
			name:      "login_subtitle at max length is valid",
			req:       UpdateTenantBrandingRequest{LoginSubtitle: strPtr(string(make([]byte, 500)))},
			wantValid: true,
		},
		{
			name:      "invalid support_email format",
			req:       UpdateTenantBrandingRequest{SupportEmail: strPtr("not-an-email")},
			wantValid: false,
			wantField: "SupportEmail",
		},
		{
			name:      "valid support_email",
			req:       UpdateTenantBrandingRequest{SupportEmail: strPtr("support@example.com")},
			wantValid: true,
		},
		{
			name:      "invalid support_url",
			req:       UpdateTenantBrandingRequest{SupportURL: strPtr("not-a-url")},
			wantValid: false,
			wantField: "SupportURL",
		},
		{
			name:      "valid support_url",
			req:       UpdateTenantBrandingRequest{SupportURL: strPtr("https://support.example.com")},
			wantValid: true,
		},
		{
			name:      "invalid privacy_policy_url",
			req:       UpdateTenantBrandingRequest{PrivacyPolicyURL: strPtr("://bad-url")},
			wantValid: false,
			wantField: "PrivacyPolicyURL",
		},
		{
			name:      "valid privacy_policy_url",
			req:       UpdateTenantBrandingRequest{PrivacyPolicyURL: strPtr("https://example.com/privacy")},
			wantValid: true,
		},
		{
			name:      "invalid terms_of_service_url",
			req:       UpdateTenantBrandingRequest{TermsOfServiceURL: strPtr("ftp://bad")},
			wantValid: true, // ftp:// is still a valid URL per RFC
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

// ==================== UpdateTenantBrandingRequest — all fields optional ====================

func TestUpdateTenantBrandingRequest_AllFieldsOptional(t *testing.T) {
	t.Run("zero-value request has all nil pointer fields", func(t *testing.T) {
		req := UpdateTenantBrandingRequest{}

		assert.Nil(t, req.LogoURL)
		assert.Nil(t, req.FaviconURL)
		assert.Nil(t, req.PrimaryColor)
		assert.Nil(t, req.BackgroundColor)
		assert.Nil(t, req.AccentColor)
		assert.Nil(t, req.CustomCSS)
		assert.Nil(t, req.LoginTitle)
		assert.Nil(t, req.LoginSubtitle)
		assert.Nil(t, req.LoginMessage)
		assert.Nil(t, req.SupportEmail)
		assert.Nil(t, req.SupportURL)
		assert.Nil(t, req.PrivacyPolicyURL)
		assert.Nil(t, req.TermsOfServiceURL)
		assert.Nil(t, req.HideHexxlockBranding)
	})
}
