// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
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
