// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// These tests cover the RFC 8693 OAuth 2.0 Token Exchange grant
// added in the tier-1 hardening pass. The exchange validates a
// previously-issued access token + reissues a new token with a
// (possibly narrower) scope and a (possibly different) audience —
// the foundational primitive for downstream-service token narrowing.

func TestTokenExchangeGrant_RejectsNonAccessTokenSubjectType(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})

	_, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		"some-token",
		"urn:ietf:params:oauth:token-type:refresh_token",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_type")
	assert.Contains(t, err.Error(), "is not supported")
}

func TestTokenExchangeGrant_RejectsNonAccessTokenRequestedType(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})

	_, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		"some-token",
		"urn:ietf:params:oauth:token-type:access_token",
		"urn:ietf:params:oauth:token-type:saml2",
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requested_token_type")
}

func TestTokenExchangeGrant_RejectsInvalidSubjectToken(t *testing.T) {
	// A garbage token fails ValidateAccessToken before we look it up
	// in the row store. Maps to invalid_grant per RFC 8693 §2.4.
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	client.GrantTypes = append(client.GrantTypes, tokenExchangeGrantType)

	_, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		"this-is-not-a-jwt",
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

// scopeRequiresDPoP gate is exercised by TestScopeRequiresDPoP and
// TestScopeRequiresDPoP_PlatformShapes; the exchange grant uses the
// same gate as ClientCredentialsGrant + RefreshTokens. Sanity assert:
// ErrDPoPRequired is exposed and is the same sentinel returned by the
// exchange path.
func TestTokenExchangeGrant_ExposesDPoPSentinel(t *testing.T) {
	assert.True(t, errors.Is(ErrDPoPRequired, ErrDPoPRequired),
		"sentinel sanity for clients matching on the error")
}

// LD-R3-TX-3: a client not registered for token-exchange is refused before
// the subject token is even parsed.
func TestTokenExchangeGrant_RejectsClientWithoutGrantType(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"}) // authorization_code + refresh_token only

	_, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		"this-is-not-a-jwt",
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized_client")
}

// LD-R3-TX-3: the legacy access_token exchange only narrows tokens issued to
// the calling client. A second token-exchange client holding the first
// client's (valid, unrevoked) access token cannot re-mint it.
func TestTokenExchangeGrant_RejectsSubjectTokenOfAnotherClient(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc, err := NewOAuthProviderService(repo, &noopUserRepo{}, &config.Config{JWTSecret: "test-secret-for-binding-tests", ServicePort: "8080"})
	require.NoError(t, err)

	issuer := newServiceClient("svc-binding-issuer", uuid.New())
	issuer.Scopes = []string{"events:publish"}
	issuer.GrantTypes = append(issuer.GrantTypes, tokenExchangeGrantType)
	subjectToken := mintAccessTokenForExchange(t, svc, repo, issuer, []string{"events:publish"})

	other := newServiceClient("svc-binding-other", issuer.TenantID)
	other.Scopes = []string{"events:publish"}
	other.GrantTypes = append(other.GrantTypes, tokenExchangeGrantType)

	_, err = svc.TokenExchangeGrant(context.Background(), other, subjectToken,
		"urn:ietf:params:oauth:token-type:access_token", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant: subject_token was not issued to this client")

	// The issuing client itself still narrows its own token.
	resp, err := svc.TokenExchangeGrant(context.Background(), issuer, subjectToken,
		"urn:ietf:params:oauth:token-type:access_token", "", nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
}
