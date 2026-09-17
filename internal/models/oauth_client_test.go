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

// buildOAuthClient returns a fully populated OAuthClient for use in tests.
func buildOAuthClient() *OAuthClient {
	tenantID := uuid.New()
	createdBy := uuid.New()
	updatedBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	desc := "My test application"
	logo := testLogoURL
	tos := "https://example.com/tos"
	policy := "https://example.com/privacy"
	contact := "admin@example.com"
	backchannelURI := "https://example.com/backchannel-logout"
	frontchannelURI := "https://example.com/frontchannel-logout"

	return &OAuthClient{
		ID:                       uuid.New(),
		TenantID:                 tenantID,
		ClientID:                 "client_abc123def456",
		ClientSecret:             "encrypted-client-secret-value",
		Name:                     "Test Application",
		Description:              &desc,
		GrantTypes:               []string{"authorization_code", "refresh_token"},
		ResponseTypes:            []string{"code"},
		RedirectURIs:             []string{"https://example.com/callback"},
		Scopes:                   []string{"openid", "profile", "email"},
		AccessTokenLifetime:      3600,
		RefreshTokenLifetime:     2592000,
		IDTokenLifetime:          3600,
		IsPublic:                 false,
		IsConfidential:           true,
		IsFirstParty:             true,
		RequirePKCE:              false,
		AppCategory:              "business",
		RequireAssignment:        false,
		IsActive:                 true,
		LogoURL:                  &logo,
		TosURL:                   &tos,
		PolicyURL:                &policy,
		ContactEmail:             &contact,
		Contacts:                 []string{"admin@example.com"},
		TokenEndpointAuthMethod:  "client_secret_basic",
		IDTokenSignedResponseAlg: "RS256",
		PostLogoutRedirectURIs:   []string{"https://example.com/post-logout"},
		AllowedCORSOrigins:       []string{"https://example.com"},
		BackchannelLogoutURI:     &backchannelURI,
		FrontchannelLogoutURI:    &frontchannelURI,
		CreatedAt:                now,
		UpdatedAt:                now,
		CreatedBy:                &createdBy,
		UpdatedBy:                &updatedBy,
	}
}

// ==================== OAuthClient struct ====================

func TestOAuthClient_Instantiation(t *testing.T) {
	t.Run("should create client with all fields set", func(t *testing.T) {
		c := buildOAuthClient()

		assert.NotEqual(t, uuid.Nil, c.ID)
		assert.NotEqual(t, uuid.Nil, c.TenantID)
		assert.Equal(t, "client_abc123def456", c.ClientID)
		assert.Equal(t, "encrypted-client-secret-value", c.ClientSecret)
		assert.Equal(t, "Test Application", c.Name)
		assert.NotNil(t, c.Description)
		assert.Equal(t, []string{"authorization_code", "refresh_token"}, c.GrantTypes)
		assert.Equal(t, []string{"code"}, c.ResponseTypes)
		assert.Equal(t, []string{"https://example.com/callback"}, c.RedirectURIs)
		assert.Equal(t, 3600, c.AccessTokenLifetime)
		assert.Equal(t, 2592000, c.RefreshTokenLifetime)
		assert.Equal(t, 3600, c.IDTokenLifetime)
		assert.False(t, c.IsPublic)
		assert.True(t, c.IsConfidential)
		assert.True(t, c.IsFirstParty)
		assert.True(t, c.IsActive)
		assert.Equal(t, "client_secret_basic", c.TokenEndpointAuthMethod)
		assert.Equal(t, "RS256", c.IDTokenSignedResponseAlg)
	})

	t.Run("ClientSecret should have json dash tag (never marshaled)", func(t *testing.T) {
		c := buildOAuthClient()
		c.ClientSecret = "this-must-not-appear-in-json"

		data, err := json.Marshal(c)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, hasSecret := decoded["client_secret"]
		assert.False(t, hasSecret,
			"client_secret should be excluded from JSON output due to json:\"-\" tag")
	})

	t.Run("should create public (SPA) client without secret dependency", func(t *testing.T) {
		c := &OAuthClient{
			ID:                       uuid.New(),
			TenantID:                 uuid.New(),
			ClientID:                 "spa-client-xyz",
			Name:                     "Single Page App",
			GrantTypes:               []string{"authorization_code"},
			ResponseTypes:            []string{"code"},
			RedirectURIs:             []string{"https://myapp.example.com/callback"},
			IsPublic:                 true,
			IsConfidential:           false,
			RequirePKCE:              true,
			IsActive:                 true,
			TokenEndpointAuthMethod:  "none",
			IDTokenSignedResponseAlg: "RS256",
		}

		assert.True(t, c.IsPublic)
		assert.False(t, c.IsConfidential)
		assert.True(t, c.RequirePKCE)
		assert.Equal(t, "none", c.TokenEndpointAuthMethod)
	})
}

// ==================== OAuthClient.ToResponse ====================

func TestOAuthClient_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		c := buildOAuthClient()

		resp := c.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, c.ID, resp.ID)
		assert.Equal(t, c.TenantID, resp.TenantID)
		assert.Equal(t, c.ClientID, resp.ClientID)
		assert.Equal(t, c.Name, resp.Name)
		assert.Equal(t, c.Description, resp.Description)
		assert.Equal(t, c.GrantTypes, resp.GrantTypes)
		assert.Equal(t, c.ResponseTypes, resp.ResponseTypes)
		assert.Equal(t, c.RedirectURIs, resp.RedirectURIs)
		assert.Equal(t, c.Scopes, resp.Scopes)
		assert.Equal(t, c.AccessTokenLifetime, resp.AccessTokenLifetime)
		assert.Equal(t, c.RefreshTokenLifetime, resp.RefreshTokenLifetime)
		assert.Equal(t, c.IDTokenLifetime, resp.IDTokenLifetime)
		assert.Equal(t, c.IsPublic, resp.IsPublic)
		assert.Equal(t, c.IsConfidential, resp.IsConfidential)
		assert.Equal(t, c.IsFirstParty, resp.IsFirstParty)
		assert.Equal(t, c.RequirePKCE, resp.RequirePKCE)
		assert.Equal(t, c.IsActive, resp.IsActive)
		assert.Equal(t, c.LogoURL, resp.LogoURL)
		assert.Equal(t, c.TosURL, resp.TosURL)
		assert.Equal(t, c.PolicyURL, resp.PolicyURL)
		assert.Equal(t, c.ContactEmail, resp.ContactEmail)
		assert.Equal(t, c.Contacts, resp.Contacts)
		assert.Equal(t, c.TokenEndpointAuthMethod, resp.TokenEndpointAuthMethod)
		assert.Equal(t, c.IDTokenSignedResponseAlg, resp.IDTokenSignedResponseAlg)
		assert.Equal(t, c.PostLogoutRedirectURIs, resp.PostLogoutRedirectURIs)
		assert.Equal(t, c.AllowedCORSOrigins, resp.AllowedCORSOrigins)
		assert.Equal(t, c.BackchannelLogoutURI, resp.BackchannelLogoutURI)
		assert.Equal(t, c.FrontchannelLogoutURI, resp.FrontchannelLogoutURI)
		assert.Equal(t, c.CreatedAt, resp.CreatedAt)
		assert.Equal(t, c.UpdatedAt, resp.UpdatedAt)
	})

	t.Run("should NOT include ClientSecret in response", func(t *testing.T) {
		c := buildOAuthClient()
		c.ClientSecret = "super-secret-encrypted-value"

		resp := c.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ClientSecret,
			"ToResponse must not expose the client secret")
	})

	t.Run("should handle nil optional pointer fields", func(t *testing.T) {
		c := &OAuthClient{
			ID:                       uuid.New(),
			TenantID:                 uuid.New(),
			ClientID:                 "client-minimal",
			Name:                     "Minimal Client",
			GrantTypes:               []string{"client_credentials"},
			ResponseTypes:            []string{"code"},
			RedirectURIs:             []string{"https://example.com/cb"},
			IsActive:                 true,
			TokenEndpointAuthMethod:  "client_secret_basic",
			IDTokenSignedResponseAlg: "RS256",
		}

		resp := c.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.ClientSecret)
		assert.Nil(t, resp.Description)
		assert.Nil(t, resp.LogoURL)
		assert.Nil(t, resp.TosURL)
		assert.Nil(t, resp.PolicyURL)
		assert.Nil(t, resp.ContactEmail)
		assert.Nil(t, resp.BackchannelLogoutURI)
		assert.Nil(t, resp.FrontchannelLogoutURI)
	})

	t.Run("should produce a distinct instance on each call", func(t *testing.T) {
		c := buildOAuthClient()

		resp1 := c.ToResponse()
		resp2 := c.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== OAuthClient.ToResponseWithSecret ====================

func TestOAuthClient_ToResponseWithSecret(t *testing.T) {
	t.Run("should include the plain-text client secret in response", func(t *testing.T) {
		c := buildOAuthClient()
		secret := "plain-text-secret-abc123" //nolint:gosec // test fixture value, not a real credential

		resp := c.ToResponseWithSecret(secret)

		require.NotNil(t, resp)
		require.NotNil(t, resp.ClientSecret,
			"ToResponseWithSecret must populate ClientSecret")
		assert.Equal(t, secret, *resp.ClientSecret)
	})

	t.Run("should carry all base fields identical to ToResponse", func(t *testing.T) {
		c := buildOAuthClient()
		secret := "creation-only-secret"

		base := c.ToResponse()
		withSecret := c.ToResponseWithSecret(secret)

		// All fields except ClientSecret should match.
		assert.Equal(t, base.ID, withSecret.ID)
		assert.Equal(t, base.ClientID, withSecret.ClientID)
		assert.Equal(t, base.TenantID, withSecret.TenantID)
		assert.Equal(t, base.Name, withSecret.Name)
		assert.Equal(t, base.IsActive, withSecret.IsActive)
		assert.Equal(t, base.GrantTypes, withSecret.GrantTypes)
		assert.Equal(t, base.RedirectURIs, withSecret.RedirectURIs)
		assert.Equal(t, base.TokenEndpointAuthMethod, withSecret.TokenEndpointAuthMethod)
		assert.Equal(t, base.IDTokenSignedResponseAlg, withSecret.IDTokenSignedResponseAlg)

		// Secret is nil in base, set in withSecret.
		assert.Nil(t, base.ClientSecret)
		assert.NotNil(t, withSecret.ClientSecret)
		assert.Equal(t, secret, *withSecret.ClientSecret)
	})

	t.Run("should NOT expose the encrypted ClientSecret as the secret", func(t *testing.T) {
		c := buildOAuthClient()
		c.ClientSecret = "$enc$very-long-encrypted-blob"
		plainSecret := "new-plain-secret"

		resp := c.ToResponseWithSecret(plainSecret)

		require.NotNil(t, resp)
		assert.Equal(t, plainSecret, *resp.ClientSecret)
		// The encrypted blob must not leak through.
		assert.NotEqual(t, c.ClientSecret, *resp.ClientSecret)
	})

	t.Run("should produce distinct instances for different secrets", func(t *testing.T) {
		c := buildOAuthClient()

		resp1 := c.ToResponseWithSecret("secret-one")
		resp2 := c.ToResponseWithSecret("secret-two")

		assert.NotEqual(t, *resp1.ClientSecret, *resp2.ClientSecret)
	})

	t.Run("should handle empty secret string", func(t *testing.T) {
		c := buildOAuthClient()

		resp := c.ToResponseWithSecret("")

		require.NotNil(t, resp)
		require.NotNil(t, resp.ClientSecret)
		assert.Equal(t, "", *resp.ClientSecret)
	})
}

// ==================== OAuthAuthorizationCode.IsExpired ====================

func TestOAuthAuthorizationCode_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "should be expired when ExpiresAt is in the past",
			expiresAt: time.Now().Add(-1 * time.Minute),
			expected:  true,
		},
		{
			name:      "should not be expired when ExpiresAt is in the future",
			expiresAt: time.Now().Add(10 * time.Minute),
			expected:  false,
		},
		{
			name:      "should be expired one nanosecond past expiry",
			expiresAt: time.Now().Add(-1 * time.Nanosecond),
			expected:  true,
		},
		{
			name:      "should not be expired far in the future",
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := &OAuthAuthorizationCode{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				ClientID:    uuid.New(),
				UserID:      uuid.New(),
				Code:        "authcode-abc123",
				RedirectURI: "https://example.com/callback",
				ExpiresAt:   tt.expiresAt,
			}

			assert.Equal(t, tt.expected, code.IsExpired())
		})
	}
}

func TestOAuthAuthorizationCode_IsExpired_Boundary(t *testing.T) {
	t.Run("should be expired one second past expiry", func(t *testing.T) {
		code := &OAuthAuthorizationCode{
			ExpiresAt: time.Now().Add(-1 * time.Second),
		}
		assert.True(t, code.IsExpired())
	})

	t.Run("should not be expired one second before expiry", func(t *testing.T) {
		code := &OAuthAuthorizationCode{
			ExpiresAt: time.Now().Add(1 * time.Second),
		}
		assert.False(t, code.IsExpired())
	})
}

// ==================== OAuthToken.IsExpired ====================

func TestOAuthToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "should be expired when ExpiresAt is in the past",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "should not be expired when ExpiresAt is in the future",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "should be expired one nanosecond past expiry",
			expiresAt: time.Now().Add(-1 * time.Nanosecond),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &OAuthToken{ //nolint:gosec // test fixture value, not a real credential
				ID:        uuid.New(),
				TenantID:  uuid.New(),
				ClientID:  uuid.New(),
				TokenType: "access_token",
				Token:     "hashed-token-value",
				ExpiresAt: tt.expiresAt,
			}

			assert.Equal(t, tt.expected, token.IsExpired())
		})
	}
}

// ==================== OAuthState.IsExpired ====================

func TestOAuthState_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "should be expired when ExpiresAt is in the past",
			expiresAt: time.Now().Add(-5 * time.Minute),
			expected:  true,
		},
		{
			name:      "should not be expired when ExpiresAt is in the future",
			expiresAt: time.Now().Add(5 * time.Minute),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &OAuthState{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				ClientID:    uuid.New(),
				State:       "random-state-value",
				RedirectURI: "https://example.com/callback",
				ExpiresAt:   tt.expiresAt,
			}

			assert.Equal(t, tt.expected, state.IsExpired())
		})
	}
}

// ==================== Expiry mutual consistency ====================

func TestOAuthExpiry_MutualConsistency(t *testing.T) {
	t.Run("fresh code is not expired, 10-minute-old code is", func(t *testing.T) {
		fresh := &OAuthAuthorizationCode{ExpiresAt: time.Now().Add(5 * time.Minute)}
		stale := &OAuthAuthorizationCode{ExpiresAt: time.Now().Add(-10 * time.Minute)}

		assert.False(t, fresh.IsExpired())
		assert.True(t, stale.IsExpired())
	})

	t.Run("active token and expired token behave correctly", func(t *testing.T) {
		active := &OAuthToken{ExpiresAt: time.Now().Add(3600 * time.Second)}
		expired := &OAuthToken{ExpiresAt: time.Now().Add(-3600 * time.Second)}

		assert.False(t, active.IsExpired())
		assert.True(t, expired.IsExpired())
	})
}

// ==================== CreateOAuthClientRequest ====================

func TestCreateOAuthClientRequest_Fields(t *testing.T) {
	t.Run("should populate all required fields", func(t *testing.T) {
		req := CreateOAuthClientRequest{
			Name:           "My App",
			GrantTypes:     []string{"authorization_code"},
			ResponseTypes:  []string{"code"},
			RedirectURIs:   []string{"https://myapp.com/callback"},
			Scopes:         []string{"openid", "profile"},
			IsPublic:       false,
			IsConfidential: true,
			RequirePKCE:    false,
		}

		assert.Equal(t, "My App", req.Name)
		assert.Equal(t, []string{"authorization_code"}, req.GrantTypes)
		assert.Equal(t, []string{"code"}, req.ResponseTypes)
		assert.Equal(t, []string{"https://myapp.com/callback"}, req.RedirectURIs)
		assert.Equal(t, []string{"openid", "profile"}, req.Scopes)
		assert.False(t, req.IsPublic)
		assert.True(t, req.IsConfidential)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		req := CreateOAuthClientRequest{
			Name:          "Minimal App",
			GrantTypes:    []string{"client_credentials"},
			ResponseTypes: []string{"code"},
			RedirectURIs:  []string{"https://example.com/cb"},
		}

		assert.Nil(t, req.Description)
		assert.Nil(t, req.AccessTokenLifetime)
		assert.Nil(t, req.RefreshTokenLifetime)
		assert.Nil(t, req.IDTokenLifetime)
		assert.Nil(t, req.LogoURL)
		assert.Nil(t, req.TosURL)
		assert.Nil(t, req.PolicyURL)
		assert.Nil(t, req.ContactEmail)
		assert.Nil(t, req.BackchannelLogoutURI)
		assert.Nil(t, req.FrontchannelLogoutURI)
	})
}

// ==================== UpdateOAuthClientRequest ====================

func TestUpdateOAuthClientRequest_Fields(t *testing.T) {
	t.Run("all nil fields represents a no-op update", func(t *testing.T) {
		req := UpdateOAuthClientRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.GrantTypes)
		assert.Nil(t, req.ResponseTypes)
		assert.Nil(t, req.RedirectURIs)
		assert.Nil(t, req.IsPublic)
		assert.Nil(t, req.IsConfidential)
		assert.Nil(t, req.IsActive)
		assert.Nil(t, req.AccessTokenLifetime)
		assert.Nil(t, req.TokenEndpointAuthMethod)
	})

	t.Run("should allow partial updates", func(t *testing.T) {
		name := "Updated App Name"
		isActive := false

		req := UpdateOAuthClientRequest{
			Name:     &name,
			IsActive: &isActive,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.GrantTypes)
	})
}

// ==================== OAuthClientListResponse ====================

func TestOAuthClientListResponse_Fields(t *testing.T) {
	t.Run("should hold pagination and client list", func(t *testing.T) {
		c := buildOAuthClient()
		resp := c.ToResponse()

		listResp := OAuthClientListResponse{
			Clients:    []OAuthClientResponse{*resp},
			Total:      1,
			Page:       1,
			PageSize:   20,
			TotalPages: 1,
		}

		assert.Len(t, listResp.Clients, 1)
		assert.Equal(t, int64(1), listResp.Total)
		assert.Equal(t, 1, listResp.Page)
		assert.Equal(t, 20, listResp.PageSize)
		assert.Equal(t, 1, listResp.TotalPages)
	})
}

// ==================== OAuthErrorResponse ====================

func TestOAuthErrorResponse_Fields(t *testing.T) {
	tests := []struct {
		name             string
		errorCode        string
		errorDescription string
		state            string
	}{
		{
			name:             "invalid_client error",
			errorCode:        "invalid_client",
			errorDescription: "Client authentication failed",
			state:            "abc123",
		},
		{
			name:             "access_denied error",
			errorCode:        "access_denied",
			errorDescription: "The resource owner denied the request",
			state:            "",
		},
		{
			name:             "invalid_grant error",
			errorCode:        "invalid_grant",
			errorDescription: "The authorization code is invalid or expired",
			state:            "xyz789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errResp := OAuthErrorResponse{
				Error:            tt.errorCode,
				ErrorDescription: tt.errorDescription,
				State:            tt.state,
			}

			assert.Equal(t, tt.errorCode, errResp.Error)
			assert.Equal(t, tt.errorDescription, errResp.ErrorDescription)
			assert.Equal(t, tt.state, errResp.State)
		})
	}
}

// ==================== OAuthIntrospectResponse ====================

func TestOAuthIntrospectResponse_Fields(t *testing.T) {
	t.Run("active token introspection response", func(t *testing.T) {
		now := time.Now().Unix()
		exp := now + 3600

		resp := OAuthIntrospectResponse{
			Active:    true,
			Scope:     "openid profile email",
			ClientID:  "client_abc123",
			Username:  "alice@example.com",
			TokenType: "Bearer",
			ExpiresAt: exp,
			IssuedAt:  now,
			Subject:   uuid.New().String(),
			Audience:  []string{"resource-server-1"},
			Issuer:    "https://auth.example.com",
		}

		assert.True(t, resp.Active)
		assert.Equal(t, "openid profile email", resp.Scope)
		assert.Equal(t, "client_abc123", resp.ClientID)
		assert.Equal(t, "alice@example.com", resp.Username)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, exp, resp.ExpiresAt)
		assert.Len(t, resp.Audience, 1)
	})

	t.Run("inactive token introspection response", func(t *testing.T) {
		resp := OAuthIntrospectResponse{
			Active: false,
		}

		assert.False(t, resp.Active)
		assert.Equal(t, "", resp.Scope)
		assert.Equal(t, "", resp.ClientID)
	})
}

// ==================== OAuthTokenResponse ====================

func TestOAuthTokenResponse_Fields(t *testing.T) {
	t.Run("should hold all token response fields", func(t *testing.T) {
		resp := OAuthTokenResponse{ //nolint:gosec // test fixture value, not a real credential
			AccessToken:  "eyJhbGciOiJSUzI1NiJ9.access",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "eyJhbGciOiJSUzI1NiJ9.refresh",
			Scope:        "openid profile",
			IDToken:      "eyJhbGciOiJSUzI1NiJ9.id",
		}

		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(3600), resp.ExpiresIn)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, "openid profile", resp.Scope)
		assert.NotEmpty(t, resp.IDToken)
	})

	t.Run("client_credentials response has no id_token or refresh_token", func(t *testing.T) {
		resp := OAuthTokenResponse{ //nolint:gosec // test fixture value, not a real credential
			AccessToken: "eyJhbGciOiJSUzI1NiJ9.cc-access",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		assert.NotEmpty(t, resp.AccessToken)
		assert.Empty(t, resp.RefreshToken)
		assert.Empty(t, resp.IDToken)
	})
}

// ==================== OAuthConsent ====================

func TestOAuthConsent_Instantiation(t *testing.T) {
	t.Run("should create consent record with all fields", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		clientID := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(365 * 24 * time.Hour)

		consent := &OAuthConsent{
			ID:        id,
			UserID:    userID,
			ClientID:  clientID,
			Scopes:    []string{"openid", "profile", "email"},
			GrantedAt: now,
			ExpiresAt: &expires,
		}

		assert.Equal(t, id, consent.ID)
		assert.Equal(t, userID, consent.UserID)
		assert.Equal(t, clientID, consent.ClientID)
		assert.Equal(t, []string{"openid", "profile", "email"}, consent.Scopes)
		assert.Equal(t, now, consent.GrantedAt)
		assert.Equal(t, &expires, consent.ExpiresAt)
		assert.Nil(t, consent.RevokedAt)
	})

	t.Run("should create revoked consent", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		revoked := now.Add(1 * time.Hour)

		consent := &OAuthConsent{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			ClientID:  uuid.New(),
			Scopes:    []string{"openid"},
			GrantedAt: now,
			RevokedAt: &revoked,
		}

		assert.NotNil(t, consent.RevokedAt)
		assert.Equal(t, &revoked, consent.RevokedAt)
	})
}

// ==================== JSON marshaling ====================

func TestOAuthClient_JSONMarshal(t *testing.T) {
	t.Run("ClientSecret must not appear in marshaled JSON", func(t *testing.T) {
		c := buildOAuthClient()
		c.ClientSecret = "very-secret-encrypted-blob"

		data, err := json.Marshal(c)
		require.NoError(t, err)

		// Verify it does not appear in raw JSON bytes.
		assert.NotContains(t, string(data), "very-secret-encrypted-blob")

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, hasSecret := decoded["client_secret"]
		assert.False(t, hasSecret, "client_secret should be absent from JSON")
	})

	t.Run("OAuthClientResponse should marshal and unmarshal correctly", func(t *testing.T) {
		c := buildOAuthClient()
		resp := c.ToResponse()

		data, err := json.Marshal(resp) //nolint:gosec // test struct with secret field, not real credentials
		require.NoError(t, err)

		var decoded OAuthClientResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, resp.ID, decoded.ID)
		assert.Equal(t, resp.ClientID, decoded.ClientID)
		assert.Equal(t, resp.Name, decoded.Name)
		assert.Equal(t, resp.GrantTypes, decoded.GrantTypes)
		assert.Equal(t, resp.IsActive, decoded.IsActive)
		// ClientSecret should be nil in regular response.
		assert.Nil(t, decoded.ClientSecret)
	})
}

// ==================== JWKSet and JWK ====================

func TestJWKSet_Instantiation(t *testing.T) {
	t.Run("should create JWK set with RSA key", func(t *testing.T) {
		jwks := JWKSet{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "key-2024-01",
					Alg: "RS256",
					N:   "base64url-encoded-modulus",
					E:   "AQAB",
				},
			},
		}

		assert.Len(t, jwks.Keys, 1)
		assert.Equal(t, "RSA", jwks.Keys[0].Kty)
		assert.Equal(t, "sig", jwks.Keys[0].Use)
		assert.Equal(t, "RS256", jwks.Keys[0].Alg)
	})
}

// ==================== OAuthAuthorizeRequest ====================

func TestOAuthAuthorizeRequest_Fields(t *testing.T) {
	t.Run("should hold authorization request fields", func(t *testing.T) {
		req := OAuthAuthorizeRequest{
			ResponseType:        "code",
			ClientID:            "client_abc123",
			RedirectURI:         "https://example.com/callback",
			Scope:               "openid profile",
			State:               "random-state-xyz",
			Nonce:               "nonce-value",
			CodeChallenge:       "challenge-value",
			CodeChallengeMethod: "S256",
		}

		assert.Equal(t, "code", req.ResponseType)
		assert.Equal(t, "client_abc123", req.ClientID)
		assert.Equal(t, "https://example.com/callback", req.RedirectURI)
		assert.Equal(t, "openid profile", req.Scope)
		assert.Equal(t, "random-state-xyz", req.State)
		assert.Equal(t, "S256", req.CodeChallengeMethod)
	})
}

// TestCreateOAuthClientRequest_Validate locks down the grant-type-aware
// callback enforcement (Bug 4 fix 2026-04-29). Pre-fix the schema's
// `binding:"required,min=1"` on response_types + redirect_uris blocked
// every machine-to-machine client registration since client_credentials
// has no /authorize round-trip and no callback URI.
func TestCreateOAuthClientRequest_Validate(t *testing.T) {
	t.Run("client_credentials only is valid without redirect/response", func(t *testing.T) {
		req := &CreateOAuthClientRequest{
			Name:       "svc-machine",
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"openid"},
			// ResponseTypes + RedirectURIs intentionally empty.
		}
		assert.NoError(t, req.Validate())
	})

	t.Run("password grant only is valid without callback", func(t *testing.T) {
		req := &CreateOAuthClientRequest{
			Name:       "svc-legacy",
			GrantTypes: []string{"password"},
		}
		assert.NoError(t, req.Validate())
	})

	t.Run("authorization_code requires redirect_uris (response_types derived in service)", func(t *testing.T) {
		// Bug-7 carve-out: response_types is no longer demanded by
		// Validate() — RFC 7591 §2 makes it registration metadata
		// with a defaultable shape (authorization_code → "code"),
		// applied by the service layer. Validate() still requires
		// redirect_uris (RFC 6749 §3.1.2).
		cases := []struct {
			name          string
			responseTypes []string
			redirectURIs  []string
			wantErr       bool
		}{
			{"both empty", nil, nil, true},
			{"redirect missing", []string{"code"}, nil, true},
			{"response missing — derived later", nil, []string{"https://app.example/cb"}, false},
			{"both present", []string{"code"}, []string{"https://app.example/cb"}, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req := &CreateOAuthClientRequest{
					Name:          "svc-browser",
					GrantTypes:    []string{"authorization_code"},
					ResponseTypes: tc.responseTypes,
					RedirectURIs:  tc.redirectURIs,
					// IsFirstParty=true: this test isolates the
					// callback-required logic; the new branding-required
					// rule (logo_url for non-first-party interactive
					// flows) lives in its own subtest below.
					IsFirstParty: true,
				}
				err := req.Validate()
				if tc.wantErr {
					assert.Error(t, err, "expected callback validation to reject %s", tc.name)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("non-first-party authorization_code requires logo_url", func(t *testing.T) {
		// Branding requirement (FU bundle 2026-04-29) — interactive
		// third-party clients MUST register a logo_url so the consent
		// screen has something more identifying than a raw client_name
		// to render. First-party clients skip this (no consent screen
		// is ever shown for them, except for sensitive-scope override).
		t.Run("missing logo_url → reject", func(t *testing.T) {
			req := &CreateOAuthClientRequest{
				Name:         "ThirdPartyApp",
				GrantTypes:   []string{"authorization_code"},
				RedirectURIs: []string{"https://thirdparty.example/cb"},
				// IsFirstParty defaults to false; LogoURL nil
			}
			err := req.Validate()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "logo_url")
		})
		t.Run("empty-string logo_url → reject", func(t *testing.T) {
			empty := ""
			req := &CreateOAuthClientRequest{
				Name:         "ThirdPartyApp",
				GrantTypes:   []string{"authorization_code"},
				RedirectURIs: []string{"https://thirdparty.example/cb"},
				LogoURL:      &empty,
			}
			err := req.Validate()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "logo_url")
		})
		t.Run("logo_url present → accept", func(t *testing.T) {
			logo := "https://thirdparty.example/logo.png"
			req := &CreateOAuthClientRequest{
				Name:         "ThirdPartyApp",
				GrantTypes:   []string{"authorization_code"},
				RedirectURIs: []string{"https://thirdparty.example/cb"},
				LogoURL:      &logo,
			}
			assert.NoError(t, req.Validate())
		})
		t.Run("client_credentials only → branding rule does NOT apply", func(t *testing.T) {
			req := &CreateOAuthClientRequest{
				Name:       "headless-svc",
				GrantTypes: []string{"client_credentials"},
				// No callback, no consent screen, no LogoURL needed.
			}
			assert.NoError(t, req.Validate())
		})
	})

	t.Run("implicit grant requires both redirect_uris + response_types", func(t *testing.T) {
		req := &CreateOAuthClientRequest{
			Name:       "svc-implicit",
			GrantTypes: []string{"implicit"},
		}
		assert.Error(t, req.Validate(), "implicit grant should require redirect_uris + response_types")
	})

	t.Run("mixed authorization_code + client_credentials still requires callback", func(t *testing.T) {
		req := &CreateOAuthClientRequest{
			Name:       "svc-hybrid",
			GrantTypes: []string{"authorization_code", "client_credentials"},
		}
		assert.Error(t, req.Validate(),
			"hybrid grant containing authorization_code MUST still validate callback fields")
	})
}
