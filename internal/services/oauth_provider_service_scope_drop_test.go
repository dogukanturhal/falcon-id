// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Tests for the scope-drop visibility WARN added alongside the two
// existing silent-filtering paths in oauth_provider_service.go:
//
//   - ClientCredentialsGrant: a requested scope not in the client's
//     registered Scopes list is dropped without changing the response
//     (still 200 OK, still exactly the same granted-scope set as
//     before this change).
//   - TokenExchangeGrant (the non-:jwt, access_token subject_token
//     path): a requested scope not present on the subject_token's own
//     scopes is dropped the same way, unless the narrowing removes
//     every requested scope (that case already returns invalid_scope
//     and is unaffected here).
//
// Both assert: (1) the WARN fires with client_id / requested /
// granted / dropped scopes when a drop occurs, (2) it does NOT fire
// when every requested scope is registered/allowed, and (3) the
// granted scope set is byte-for-byte identical to what the grant
// returned before this change (no behaviour change).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ──────────────────────────────────────────────────────────────────
// ClientCredentialsGrant
// ──────────────────────────────────────────────────────────────────

func TestClientCredentialsGrant_LogsDroppedScopes(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	svc := newTestOAuthService(t)
	svc.SetClaimsLogger(zap.New(core))

	client := newServiceClient("svc-partial-scopes", uuid.New())
	client.Scopes = []string{"events:publish", "events:consume"}

	resp, err := svc.ClientCredentialsGrant(
		context.Background(),
		client,
		[]string{"events:publish", "events:admin", "events:delete"},
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, resp)

	claims := parseUnsignedClaims(t, resp.AccessToken)
	assert.Equal(t, "events:publish", claims["scope"],
		"granted scope set must be exactly the registered subset — unchanged behaviour")

	entries := logs.FilterMessage("oauth.client_credentials.scope_dropped").All()
	require.Len(t, entries, 1, "expected exactly one scope_dropped WARN for this request")
	fields := entries[0].ContextMap()
	assert.Equal(t, zap.WarnLevel, entries[0].Level)
	assert.Equal(t, "svc-partial-scopes", fields["client_id"])
	assert.ElementsMatch(t, []interface{}{"events:publish", "events:admin", "events:delete"}, fields["requested_scopes"])
	assert.ElementsMatch(t, []interface{}{"events:publish"}, fields["granted_scopes"])
	assert.ElementsMatch(t, []interface{}{"events:admin", "events:delete"}, fields["dropped_scopes"])
}

func TestClientCredentialsGrant_NoLogWhenAllScopesRegistered(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	svc := newTestOAuthService(t)
	svc.SetClaimsLogger(zap.New(core))

	client := newServiceClient("svc-full-scopes", uuid.New())
	client.Scopes = []string{"events:publish", "events:consume"}

	resp, err := svc.ClientCredentialsGrant(
		context.Background(),
		client,
		[]string{"events:publish", "events:consume"},
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, resp)

	entries := logs.FilterMessage("oauth.client_credentials.scope_dropped").All()
	assert.Empty(t, entries, "no scope was dropped — WARN must not fire")
}

// TestClientCredentialsGrant_NoLogPanicWhenLoggerUnwired is the
// nil-safety control: claimsLogger is optional everywhere else in
// this file (refresh-token reuse, subject-claims diagnostics), and
// the new scope-drop WARN must follow the same contract rather than
// crashing when nobody has called SetClaimsLogger.
func TestClientCredentialsGrant_NoPanicWhenLoggerUnwired(t *testing.T) {
	svc := newTestOAuthService(t)
	client := newServiceClient("svc-unwired-logger", uuid.New())
	client.Scopes = []string{"events:publish"}

	assert.NotPanics(t, func() {
		_, err := svc.ClientCredentialsGrant(
			context.Background(),
			client,
			[]string{"events:publish", "events:admin"},
			"",
		)
		require.NoError(t, err)
	})
}

// ──────────────────────────────────────────────────────────────────
// TokenExchangeGrant (RFC 8693, access_token subject_token_type)
// ──────────────────────────────────────────────────────────────────

// mintAccessTokenForExchange issues a client_credentials token through
// the real grant path and registers the resulting row in repo so a
// subsequent TokenExchangeGrant on the same svc can look it up by
// hash — exactly the lookup TokenExchangeGrant performs internally.
func mintAccessTokenForExchange(t *testing.T, svc *OAuthProviderService, repo *rotationPolicyTestRepo, client *models.OAuthClient, scopes []string) string {
	t.Helper()
	resp, err := svc.ClientCredentialsGrant(context.Background(), client, scopes, "")
	require.NoError(t, err)
	require.NotEmpty(t, repo.createdTokenRows)
	row := repo.createdTokenRows[len(repo.createdTokenRows)-1]
	repo.addToken(row.Token, row)
	return resp.AccessToken
}

func TestTokenExchangeGrant_LogsDroppedScopes(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	repo := newRotationPolicyTestRepo()
	svc, err := NewOAuthProviderService(repo, &noopUserRepo{}, &config.Config{JWTSecret: "test-secret-for-scope-drop-tests", ServicePort: "8080"})
	require.NoError(t, err)
	svc.SetClaimsLogger(zap.New(core))

	client := newServiceClient("svc-exchange-source", uuid.New())
	client.Scopes = []string{"events:publish", "events:consume"}
	client.GrantTypes = append(client.GrantTypes, tokenExchangeGrantType)
	subjectToken := mintAccessTokenForExchange(t, svc, repo, client, []string{"events:publish", "events:consume"})

	resp, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		subjectToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		[]string{"events:publish", "events:admin"},
	)
	require.NoError(t, err)
	require.NotNil(t, resp)

	claims := parseUnsignedClaims(t, resp.AccessToken)
	assert.Equal(t, "events:publish", claims["scope"],
		"granted scope set must be exactly the subject_token subset — unchanged behaviour")

	entries := logs.FilterMessage("oauth.token_exchange.scope_dropped").All()
	require.Len(t, entries, 1, "expected exactly one scope_dropped WARN for this request")
	fields := entries[0].ContextMap()
	assert.Equal(t, "svc-exchange-source", fields["client_id"])
	assert.ElementsMatch(t, []interface{}{"events:publish", "events:admin"}, fields["requested_scopes"])
	assert.ElementsMatch(t, []interface{}{"events:publish"}, fields["granted_scopes"])
	assert.ElementsMatch(t, []interface{}{"events:admin"}, fields["dropped_scopes"])
}

func TestTokenExchangeGrant_NoLogWhenRequestedScopesAllSubset(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	repo := newRotationPolicyTestRepo()
	svc, err := NewOAuthProviderService(repo, &noopUserRepo{}, &config.Config{JWTSecret: "test-secret-for-scope-drop-tests", ServicePort: "8080"})
	require.NoError(t, err)
	svc.SetClaimsLogger(zap.New(core))

	client := newServiceClient("svc-exchange-clean", uuid.New())
	client.Scopes = []string{"events:publish", "events:consume"}
	client.GrantTypes = append(client.GrantTypes, tokenExchangeGrantType)
	subjectToken := mintAccessTokenForExchange(t, svc, repo, client, []string{"events:publish", "events:consume"})

	resp, err := svc.TokenExchangeGrant(
		context.Background(),
		client,
		subjectToken,
		"urn:ietf:params:oauth:token-type:access_token",
		"",
		[]string{"events:publish"},
	)
	require.NoError(t, err)
	require.NotNil(t, resp)

	entries := logs.FilterMessage("oauth.token_exchange.scope_dropped").All()
	assert.Empty(t, entries, "requested scope is a full subset — WARN must not fire")
}
