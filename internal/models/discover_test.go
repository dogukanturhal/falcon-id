// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== DiscoverRequest validation ====================

func TestDiscoverRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       DiscoverRequest
		wantValid bool
		wantField string
	}{
		{
			name:      "valid request with email only",
			req:       DiscoverRequest{Email: "alice@example.com"},
			wantValid: true,
		},
		{
			name:      "valid request with email and client_id",
			req:       DiscoverRequest{Email: "alice@example.com", ClientID: "client-abc-123"},
			wantValid: true,
		},
		{
			name:      "missing email fails required",
			req:       DiscoverRequest{},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "invalid email format fails email validation",
			req:       DiscoverRequest{Email: "not-an-email"},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "email missing domain fails validation",
			req:       DiscoverRequest{Email: "alice@"},
			wantValid: false,
			wantField: "Email",
		},
		{
			name:      "valid subdomain email",
			req:       DiscoverRequest{Email: "alice@mail.example.com"},
			wantValid: true,
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

// ==================== DiscoverResponse JSON serialisation — omitempty ====================

func TestDiscoverResponse_OmitemptyBehavior(t *testing.T) {
	t.Run("only required fields present when all pointers are nil", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:         "alice@example.com",
			EmailKnown:    false,
			AuthMethod:    "signup",
			SignupAllowed: true,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		// Required non-pointer fields must always be present.
		assert.Contains(t, raw, "email")
		assert.Contains(t, raw, "email_known")
		assert.Contains(t, raw, "auth_method")
		assert.Contains(t, raw, "signup_allowed")

		// All optional pointer/slice fields must be absent.
		for _, key := range []string{
			"tenant_id", "tenant_name", "tenant_slug",
			"sso_provider_id", "sso_provider_type", "sso_provider_name",
			"available_providers", "branding", "account_type",
		} {
			_, exists := raw[key]
			assert.False(t, exists, "%s must be omitted when nil/empty", key)
		}
	})

	t.Run("all fields present when fully populated", func(t *testing.T) {
		tenantID := "11111111-1111-1111-1111-111111111111"
		tenantName := testAcmeCorp
		tenantSlug := "acme-corp"
		ssoID := "sso-provider-uuid"
		ssoType := "saml"
		ssoName := "Acme SSO"
		accountType := "business"
		logoURL := "https://cdn.acme.com/logo.png"
		loginTitle := "Welcome to Acme"
		loginSubtitle := "Sign in with your corporate account"
		loginMessage := "Need help? Contact IT."

		resp := &DiscoverResponse{
			Email:           "alice@acme.com",
			EmailKnown:      true,
			TenantID:        &tenantID,
			TenantName:      &tenantName,
			TenantSlug:      &tenantSlug,
			AuthMethod:      "sso",
			SSOProviderID:   &ssoID,
			SSOProviderType: &ssoType,
			SSOProviderName: &ssoName,
			AvailableProviders: []DiscoverProvider{
				{
					ID:          "google-idp",
					Type:        "google",
					Name:        "google",
					DisplayName: "Sign in with Google",
				},
			},
			Branding: &DiscoverBranding{
				LogoURL:         &logoURL,
				PrimaryColor:    "#1A73E8",
				BackgroundColor: "#FFFFFF",
				LoginTitle:      &loginTitle,
				LoginSubtitle:   &loginSubtitle,
				LoginMessage:    &loginMessage,
			},
			AccountType:   &accountType,
			SignupAllowed: false,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, "alice@acme.com", raw["email"])
		assert.Equal(t, true, raw["email_known"])
		assert.Equal(t, tenantID, raw["tenant_id"])
		assert.Equal(t, tenantName, raw["tenant_name"])
		assert.Equal(t, tenantSlug, raw["tenant_slug"])
		assert.Equal(t, "sso", raw["auth_method"])
		assert.Equal(t, ssoID, raw["sso_provider_id"])
		assert.Equal(t, ssoType, raw["sso_provider_type"])
		assert.Equal(t, ssoName, raw["sso_provider_name"])
		assert.Contains(t, raw, "available_providers")
		assert.Contains(t, raw, "branding")
		assert.Equal(t, accountType, raw["account_type"])
		assert.Equal(t, false, raw["signup_allowed"])
	})
}

// ==================== DiscoverResponse JSON values ====================

func TestDiscoverResponse_JSONValues(t *testing.T) {
	t.Run("email_known false serialises as boolean false", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:      "unknown@example.com",
			EmailKnown: false,
			AuthMethod: "signup",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, false, raw["email_known"])
	})

	t.Run("email_known true serialises as boolean true", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:      "alice@example.com",
			EmailKnown: true,
			AuthMethod: "password",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, true, raw["email_known"])
	})

	t.Run("signup_allowed false serialises correctly", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:         "alice@example.com",
			AuthMethod:    "contact_admin",
			SignupAllowed: false,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, false, raw["signup_allowed"])
	})

	t.Run("signup_allowed true serialises correctly", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:         "newuser@example.com",
			AuthMethod:    "signup",
			SignupAllowed: true,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, true, raw["signup_allowed"])
	})
}

// ==================== DiscoverResponse.AvailableProviders ====================

func TestDiscoverResponse_AvailableProviders(t *testing.T) {
	t.Run("empty slice is omitted from JSON", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:              "alice@example.com",
			AuthMethod:         "password",
			AvailableProviders: []DiscoverProvider{},
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["available_providers"]
		assert.False(t, exists, "empty available_providers slice must be omitted")
	})

	t.Run("providers are serialised with correct fields", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:      "alice@example.com",
			AuthMethod: "password",
			AvailableProviders: []DiscoverProvider{
				{
					ID:          "google-idp-001",
					Type:        "google",
					Name:        "google",
					DisplayName: "Continue with Google",
				},
				{
					ID:          "microsoft-idp-001",
					Type:        "microsoft",
					Name:        "microsoft",
					DisplayName: "Continue with Microsoft",
				},
			},
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		providers, ok := raw["available_providers"].([]interface{})
		require.True(t, ok, "available_providers must be a JSON array")
		require.Len(t, providers, 2)

		first, ok := providers[0].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "google-idp-001", first["id"])
		assert.Equal(t, "google", first["type"])
		assert.Equal(t, "google", first["name"])
		assert.Equal(t, "Continue with Google", first["display_name"])
	})

	t.Run("nil slice is omitted from JSON", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:              "alice@example.com",
			AuthMethod:         "password",
			AvailableProviders: nil,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["available_providers"]
		assert.False(t, exists, "nil available_providers must be omitted from JSON")
	})
}

// ==================== DiscoverBranding JSON serialisation ====================

func TestDiscoverBranding_JSONSerialization(t *testing.T) {
	t.Run("optional fields omitted when nil", func(t *testing.T) {
		b := &DiscoverBranding{
			PrimaryColor:    "#1A73E8",
			BackgroundColor: "#FFFFFF",
		}

		data, err := json.Marshal(b)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Contains(t, raw, "primary_color")
		assert.Contains(t, raw, "background_color")

		for _, key := range []string{"logo_url", "login_title", "login_subtitle", "login_message"} {
			_, exists := raw[key]
			assert.False(t, exists, "%s must be omitted when nil", key)
		}
	})

	t.Run("all fields present when populated", func(t *testing.T) {
		logoURL := "https://cdn.example.com/logo.png"
		loginTitle := "Welcome"
		loginSubtitle := "Sign in to continue"
		loginMessage := "Use your company credentials."

		b := &DiscoverBranding{
			LogoURL:         &logoURL,
			PrimaryColor:    "#FF5722",
			BackgroundColor: "#FAFAFA",
			LoginTitle:      &loginTitle,
			LoginSubtitle:   &loginSubtitle,
			LoginMessage:    &loginMessage,
		}

		data, err := json.Marshal(b)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, logoURL, raw["logo_url"])
		assert.Equal(t, "#FF5722", raw["primary_color"])
		assert.Equal(t, "#FAFAFA", raw["background_color"])
		assert.Equal(t, loginTitle, raw["login_title"])
		assert.Equal(t, loginSubtitle, raw["login_subtitle"])
		assert.Equal(t, loginMessage, raw["login_message"])
	})
}

// ==================== DiscoverBranding embedded in DiscoverResponse ====================

func TestDiscoverResponse_BrandingNil(t *testing.T) {
	t.Run("nil branding is omitted from response JSON", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:      "alice@example.com",
			AuthMethod: "password",
			Branding:   nil,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["branding"]
		assert.False(t, exists, "nil branding must be omitted from JSON")
	})

	t.Run("non-nil branding is included in response JSON", func(t *testing.T) {
		resp := &DiscoverResponse{
			Email:      "alice@example.com",
			AuthMethod: "password",
			Branding: &DiscoverBranding{
				PrimaryColor:    "#000000",
				BackgroundColor: "#FFFFFF",
			},
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		_, exists := raw["branding"]
		assert.True(t, exists, "non-nil branding must be present in JSON")
	})
}

// ==================== DiscoverResponse auth_method values ====================

func TestDiscoverResponse_AuthMethodValues(t *testing.T) {
	authMethods := []string{"password", "sso", "signup", "contact_admin"}

	for _, method := range authMethods {
		method := method
		t.Run("auth_method="+method, func(t *testing.T) {
			resp := &DiscoverResponse{
				Email:      "alice@example.com",
				AuthMethod: method,
			}

			data, err := json.Marshal(resp)
			require.NoError(t, err)

			var raw map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &raw))

			assert.Equal(t, method, raw["auth_method"])
		})
	}
}

// ==================== DiscoverProvider field coverage ====================

func TestDiscoverProvider_Fields(t *testing.T) {
	t.Run("should carry all expected fields", func(t *testing.T) {
		p := DiscoverProvider{
			ID:          "saml-idp-001",
			Type:        "saml",
			Name:        "corporate-sso",
			DisplayName: "Corporate SSO",
		}

		assert.Equal(t, "saml-idp-001", p.ID)
		assert.Equal(t, "saml", p.Type)
		assert.Equal(t, "corporate-sso", p.Name)
		assert.Equal(t, "Corporate SSO", p.DisplayName)
	})

	t.Run("all fields serialised in JSON", func(t *testing.T) {
		p := DiscoverProvider{
			ID:          "oidc-idp-002",
			Type:        "oidc",
			Name:        "google-workspace",
			DisplayName: "Google Workspace",
		}

		data, err := json.Marshal(p)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, "oidc-idp-002", raw["id"])
		assert.Equal(t, "oidc", raw["type"])
		assert.Equal(t, "google-workspace", raw["name"])
		assert.Equal(t, "Google Workspace", raw["display_name"])
	})
}

// ==================== DiscoverRequest ClientID optional ====================

func TestDiscoverRequest_ClientID(t *testing.T) {
	t.Run("client_id is optional and included when set", func(t *testing.T) {
		req := DiscoverRequest{
			Email:    "alice@example.com",
			ClientID: "my-spa-client",
		}

		assert.Equal(t, "alice@example.com", req.Email)
		assert.Equal(t, "my-spa-client", req.ClientID)
	})

	t.Run("client_id is empty string when not set", func(t *testing.T) {
		req := DiscoverRequest{
			Email: "alice@example.com",
		}

		assert.Empty(t, req.ClientID)
	})

	t.Run("client_id is omitted from JSON when empty", func(t *testing.T) {
		req := DiscoverRequest{
			Email: "alice@example.com",
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		// client_id has omitempty, so empty string should not appear.
		_, exists := raw["client_id"]
		assert.False(t, exists, "client_id must be omitted from JSON when empty")
	})

	t.Run("client_id appears in JSON when set", func(t *testing.T) {
		req := DiscoverRequest{
			Email:    "alice@example.com",
			ClientID: "portal-client-id",
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &raw))

		assert.Equal(t, "portal-client-id", raw["client_id"])
	})
}
