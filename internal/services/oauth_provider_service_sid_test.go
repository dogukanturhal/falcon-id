// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the OIDC Session Management 1.0 §5 `sid` claim
// emission added in migration 220. The `sid` value is the
// falcon_idp_session UUID captured at /oauth/authorize time and
// propagated through the authorization code → token exchange →
// refresh-token rotation chain so RPs can scope OIDC Front-Channel
// Logout 1.0 cascades to a single browser session.

func TestGenerateTokens_SID_EmittedOnIDTokenAndAccessToken(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid", "profile"})
	user := subjectUser()
	idpSessionID := uuid.New()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid", "profile"}, nil, nil,
		[]string{"pwd"},
		&idpSessionID,
	)
	require.NoError(t, err)
	require.NotEmpty(t, resp.IDToken)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.Equal(t, idpSessionID.String(), idClaims["sid"],
		"id_token MUST carry the IdP session UUID as the OIDC Session Management §5 sid claim")

	atClaims := decodeJWTUnverified(t, resp.AccessToken)
	assert.Equal(t, idpSessionID.String(), atClaims["sid"],
		"access_token MUST also carry sid so /me-style pollers can scope cascade-revocation by sid without a /userinfo round-trip")
}

func TestGenerateTokens_SID_OmittedWhenNoIdpSession(t *testing.T) {
	// client_credentials grants and pre-migration sessions have no IdP
	// session id. The `sid` claim MUST be omitted entirely (not emitted
	// as null/empty) — `sid` is OPTIONAL per OIDC Session Management 1.0
	// §5 and emitting an empty value would break RPs that key on its
	// presence to trigger sid-scoped logout cascades.
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	_, idHasSid := idClaims["sid"]
	assert.False(t, idHasSid, "id_token MUST omit sid claim when no IdP session is present")

	atClaims := decodeJWTUnverified(t, resp.AccessToken)
	_, atHasSid := atClaims["sid"]
	assert.False(t, atHasSid, "access_token MUST omit sid claim when no IdP session is present")
}

func TestGenerateTokens_SID_NotConfusedWithJTI(t *testing.T) {
	// Defense against future regressions: sid and jti are different
	// values with different lifetimes. sid is the IdP session UUID
	// (lives for the SSO session); jti is the per-token UUID (one
	// per access token, rotated on every refresh). They MUST never
	// conflate.
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()
	idpSessionID := uuid.New()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		&idpSessionID,
	)
	require.NoError(t, err)

	atClaims := decodeJWTUnverified(t, resp.AccessToken)
	require.NotEmpty(t, atClaims["jti"], "access_token must always have jti")
	require.NotEmpty(t, atClaims["sid"], "access_token must have sid in this fixture")
	assert.NotEqual(t, atClaims["jti"], atClaims["sid"],
		"sid and jti MUST be distinct values with distinct lifetimes")
	assert.Equal(t, idpSessionID.String(), atClaims["sid"])
}
