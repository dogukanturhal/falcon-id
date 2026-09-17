// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Tests for client_credentials grant via OAuthProviderService.
// The noopOAuthClientRepo, noopUserRepo, and newTestOAuthService helpers are
// defined in oauth_par_service_test.go (same package).

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func newServiceClient(clientID string, tenantID uuid.UUID) *models.OAuthClient {
	now := time.Now()
	return &models.OAuthClient{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		ClientID:             clientID,
		Name:                 "Test " + clientID,
		GrantTypes:           []string{"client_credentials"},
		Scopes:               []string{"events:publish", "events:consume"},
		AccessTokenLifetime:  300,
		RefreshTokenLifetime: 0,
		IsConfidential:       true,
		IsFirstParty:         true,
		IsActive:             true,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

func parseUnsignedClaims(t *testing.T, tokenString string) jwt.MapClaims {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

// TestClientCredentialsGrant_BasicToken verifies that ClientCredentialsGrant
// produces a valid access token with standard JWT claims.
func TestClientCredentialsGrant_BasicToken(t *testing.T) {
	tenantID := uuid.New()
	client := newServiceClient("svc-crm", tenantID)

	svc := newTestOAuthService(t)

	scopes := []string{"events:publish", "events:consume"}
	resp, err := svc.ClientCredentialsGrant(context.Background(), client, scopes, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.AccessToken, "access token must not be empty")
	assert.Empty(t, resp.IDToken, "service tokens must not include an ID token")
	assert.Equal(t, int64(300), resp.ExpiresIn, "TTL must match client access_token_lifetime")

	claims := parseUnsignedClaims(t, resp.AccessToken)

	t.Run("standard JWT claims are present", func(t *testing.T) {
		assert.NotEmpty(t, claims["iss"])
		assert.NotEmpty(t, claims["aud"])
		assert.NotEmpty(t, claims["jti"])
		assert.NotZero(t, claims["iat"])
		assert.NotZero(t, claims["exp"])
	})
}

// TestClientCredentialsGrant_AllowedScopesFiltered verifies that only scopes
// registered on the client are included in the token.
func TestClientCredentialsGrant_AllowedScopesFiltered(t *testing.T) {
	client := &models.OAuthClient{
		ID:                  uuid.New(),
		TenantID:            uuid.New(),
		ClientID:            "tenant-app-client",
		Name:                "Tenant App",
		GrantTypes:          []string{"client_credentials"},
		Scopes:              []string{"api:read"},
		AccessTokenLifetime: 3600,
		IsConfidential:      true,
		IsActive:            true,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	svc := newTestOAuthService(t)

	// Request a scope the client is not allowed to use.
	resp, err := svc.ClientCredentialsGrant(context.Background(), client, []string{"api:read", "api:write"}, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.AccessToken)
}

// TestClientCredentialsGrant_DisallowedGrantType verifies that a client without
// client_credentials in its grant types receives an error.
func TestClientCredentialsGrant_DisallowedGrantType(t *testing.T) {
	client := &models.OAuthClient{
		ID:                  uuid.New(),
		TenantID:            uuid.New(),
		ClientID:            "auth-code-only-client",
		Name:                "Auth Code Only",
		GrantTypes:          []string{"authorization_code"}, // no client_credentials
		Scopes:              []string{"openid"},
		AccessTokenLifetime: 3600,
		IsConfidential:      true,
		IsActive:            true,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	svc := newTestOAuthService(t)

	_, err := svc.ClientCredentialsGrant(context.Background(), client, []string{"openid"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_credentials")
}

// TestClientCredentialsGrant_NilTenant verifies that a client with zero TenantID
// produces a valid token without panicking.
func TestClientCredentialsGrant_NilTenant(t *testing.T) {
	client := newServiceClient("svc-platform", uuid.Nil)

	svc := newTestOAuthService(t)

	resp, err := svc.ClientCredentialsGrant(context.Background(), client, []string{"internal:admin"}, "")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
}

// TestClientCredentialsGrant_EmbedsTenantIDAndSub locks down the fix for the
// 2026-04-29 provision-svcclient-* incident: client_credentials JWTs were
// missing both `tenant_id` and `sub`, causing every admin handler that calls
// middleware.GetTenantID(c) to reject with HTTP 400 "tenant ID not found".
//
// `tenant_id` MUST mirror the client's TenantID (matching what the
// iam_oauth_tokens row already records). `sub` MUST be the client's
// client_id — Auth0/Okta/Keycloak default for service-to-service tokens.
func TestClientCredentialsGrant_EmbedsTenantIDAndSub(t *testing.T) {
	tenantID := uuid.New()
	client := newServiceClient("svc-crm", tenantID)

	svc := newTestOAuthService(t)

	resp, err := svc.ClientCredentialsGrant(context.Background(), client, []string{"events:publish"}, "")
	require.NoError(t, err)
	require.NotNil(t, resp)

	claims := parseUnsignedClaims(t, resp.AccessToken)

	assert.Equal(t, tenantID.String(), claims["tenant_id"],
		"client_credentials JWT MUST carry tenant_id from the client record")
	assert.Equal(t, "svc-crm", claims["sub"],
		"client_credentials JWT MUST carry sub == client_id (Auth0/Okta default)")
	assert.Equal(t, "svc-crm", claims["client_id"],
		"client_id claim should match the issuing client")
}

// TestClientCredentialsGrant_DefaultsScopeWhenOmitted locks down RFC 6749 §3.3:
// when the caller omits `scope`, the authorization server MUST either default
// or fail. We default to the client's full registered scope list (matches
// Auth0/Okta default; the client cannot request scopes its registration
// doesn't grant anyway). Pre-fix the issued token had `scope: ""` which
// resource servers couldn't distinguish from "deliberately narrowed to
// nothing" and the admin API would reject.
func TestClientCredentialsGrant_DefaultsScopeWhenOmitted(t *testing.T) {
	client := newServiceClient("svc-default-scope", uuid.New())
	// client.Scopes is set by newServiceClient to ["events:publish", "events:consume"].

	svc := newTestOAuthService(t)

	t.Run("requestedScopes is nil → default to all client scopes", func(t *testing.T) {
		resp, err := svc.ClientCredentialsGrant(context.Background(), client, nil, "")
		require.NoError(t, err)
		claims := parseUnsignedClaims(t, resp.AccessToken)
		scope, _ := claims["scope"].(string)
		assert.Contains(t, scope, "events:publish")
		assert.Contains(t, scope, "events:consume")
	})

	t.Run("requestedScopes is empty slice → default to all client scopes", func(t *testing.T) {
		resp, err := svc.ClientCredentialsGrant(context.Background(), client, []string{}, "")
		require.NoError(t, err)
		claims := parseUnsignedClaims(t, resp.AccessToken)
		scope, _ := claims["scope"].(string)
		assert.Contains(t, scope, "events:publish")
		assert.Contains(t, scope, "events:consume")
	})

	t.Run("requestedScopes is single empty string (strings.Split artifact) → default", func(t *testing.T) {
		// strings.Split("", " ") returns [""] — guard against this common
		// upstream pitfall by treating a single-empty-element slice as omitted.
		resp, err := svc.ClientCredentialsGrant(context.Background(), client, []string{""}, "")
		require.NoError(t, err)
		claims := parseUnsignedClaims(t, resp.AccessToken)
		scope, _ := claims["scope"].(string)
		assert.Contains(t, scope, "events:publish")
		assert.Contains(t, scope, "events:consume")
	})
}

// TestClientCredentialsGrant_NarrowsExplicitlyRequestedScopes verifies the
// inverse: when the caller does pass `scope`, the issued token narrows to
// the intersection (registered ∩ requested).
func TestClientCredentialsGrant_NarrowsExplicitlyRequestedScopes(t *testing.T) {
	client := newServiceClient("svc-narrow", uuid.New())
	// client.Scopes = ["events:publish", "events:consume"].

	svc := newTestOAuthService(t)

	resp, err := svc.ClientCredentialsGrant(context.Background(), client, []string{"events:publish"}, "")
	require.NoError(t, err)
	claims := parseUnsignedClaims(t, resp.AccessToken)
	scope, _ := claims["scope"].(string)
	assert.Equal(t, "events:publish", scope,
		"explicit scope request must narrow, not default to client.Scopes")
}
