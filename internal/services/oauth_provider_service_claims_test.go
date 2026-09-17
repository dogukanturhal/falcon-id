// SPDX-License-Identifier: AGPL-3.0-or-later

package services

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
// Stub subjectClaimsProvider — returns whatever the test fixture sets.
// ──────────────────────────────────────────────────────────────────────────────

type stubSubjectClaims struct {
	groupPaths []string
	groupErr   error
	roles      []*models.EffectiveRole
	rolesErr   error
}

func (s *stubSubjectClaims) GetUserGroupPaths(_ context.Context, _ uuid.UUID) ([]string, error) {
	return s.groupPaths, s.groupErr
}

func (s *stubSubjectClaims) GetUserEffectiveRoles(_ context.Context, _ uuid.UUID) ([]*models.EffectiveRole, error) {
	return s.roles, s.rolesErr
}

// decodeJWTUnverified parses a JWT without verifying the signature (test
// convenience — we trust the service's own signer in-process).
func decodeJWTUnverified(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	tok, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

// authzCodeClient builds a test client with the given Scopes allowlist.
// The /oauth/authorize code-exchange flow is simulated by calling
// generateTokens directly — this mirrors what ExchangeAuthorizationCode
// would do after a code is successfully validated.
func authzCodeClient(allowedScopes []string) *models.OAuthClient {
	return &models.OAuthClient{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		ClientID:             "claims-test-client",
		Name:                 "Claims Test Client",
		GrantTypes:           []string{"authorization_code", "refresh_token"},
		Scopes:               allowedScopes,
		AccessTokenLifetime:  300,
		RefreshTokenLifetime: 3600,
		IDTokenLifetime:      300,
		IsConfidential:       true,
		IsFirstParty:         true,
		IsActive:             true,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
}

func subjectUser() *models.User {
	return &models.User{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "admin@example.com",
		Email:    "admin@example.com",
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Discovery document
// ──────────────────────────────────────────────────────────────────────────────

func TestDiscoveryDocument_AdvertisesClaimsGapFillers(t *testing.T) {
	svc := newTestOAuthService(t)

	doc := svc.GetDiscoveryDocument()

	assert.Contains(t, doc.ClaimsSupported, "groups", "groups claim must be advertised")
	assert.Contains(t, doc.ClaimsSupported, "roles", "roles claim must be advertised")
	assert.Contains(t, doc.ClaimsSupported, "amr", "amr claim must be advertised")
	assert.Contains(t, doc.ClaimsSupported, "acr", "acr claim must be advertised once passkeys land")
	assert.Contains(t, doc.ClaimsSupported, "tenant_id", "tenant_id claim must be advertised")

	assert.Contains(t, doc.ScopesSupported, "groups", "groups scope must be advertised")
	assert.Contains(t, doc.ScopesSupported, "roles", "roles scope must be advertised")

	// AAL ladder advertised — RPs need the list to know which acr_values
	// they can request on /authorize.
	assert.ElementsMatch(t, []string{ACRValueAAL2, ACRValueAAL3}, doc.AcrValuesSupported,
		"acr_values_supported must publish the AAL2 + AAL3 ladder")

	// Backwards compat: nothing was removed.
	for _, c := range []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "given_name", "family_name", "preferred_username", "email", "email_verified"} {
		assert.Contains(t, doc.ClaimsSupported, c, "pre-existing claim %q must stay advertised", c)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// acr — derived from amr per the AAL ladder.
//
// "hwk" present anywhere in amr → acr = urn:hexxlock:aal3 (passkey).
// otherwise, any non-"user" method  → acr = urn:hexxlock:aal2 (password+OTP).
// only "user" or empty             → acr omitted (no authenticator known).
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateTokens_ACR_AAL3_WhenWebAuthn(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{AMRValueHardwareKey, AMRValueUserVerification},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	require.Contains(t, idClaims, "acr", "acr must be emitted when amr contains hwk")
	assert.Equal(t, ACRValueAAL3, idClaims["acr"], "WebAuthn ceremony must yield AAL3")
}

func TestGenerateTokens_ACR_AAL2_WhenPasswordPlusTOTP(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd", "otp"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	require.Contains(t, idClaims, "acr", "acr must be emitted for password+OTP sessions")
	assert.Equal(t, ACRValueAAL2, idClaims["acr"], "password+OTP caps at AAL2")
}

func TestGenerateTokens_ACR_OmittedWhenAuthMethodsEmpty(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		nil,
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "acr",
		"acr must be omitted rather than emitted with an empty / misleading value")
}

// ──────────────────────────────────────────────────────────────────────────────
// amr — always emitted when snapshot non-empty; omitted otherwise.
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateTokens_AMR_EmittedWhenAuthMethodsProvided(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid", "profile"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", "profile"}, nil, nil,
		[]string{"pwd", "otp"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)
	require.NotEmpty(t, resp.IDToken)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	require.Contains(t, idClaims, "amr")
	amr, ok := idClaims["amr"].([]interface{})
	require.True(t, ok)
	// Umbrella `mfa` is auto-appended whenever a concrete RFC 8176
	// multi-factor method (otp here) is present. Tier-1 RPs (Talon,
	// third-party SaaS) gate on the umbrella; the concrete factor names
	// are kept for audit / risk consumers.
	assert.ElementsMatch(t, []interface{}{"pwd", "otp", "mfa"}, amr)

	atClaims := decodeJWTUnverified(t, resp.AccessToken)
	require.Contains(t, atClaims, "amr", "access_token also carries amr for resource-server checks")
	atAMR, ok := atClaims["amr"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"pwd", "otp", "mfa"}, atAMR,
		"access_token amr must match id_token amr (umbrella included)")
}

func TestGenerateTokens_AMR_PasswordOnly_NoUmbrella(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		// pwd alone is single-factor; the umbrella must NOT be added.
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)
	idClaims := decodeJWTUnverified(t, resp.IDToken)
	amr, ok := idClaims["amr"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"pwd"}, amr,
		"pwd-only session must not pick up the mfa umbrella")
}

func TestGenerateTokens_AMR_WebAuthn_PassesUmbrella(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"hwk", "user"},
		nil,
	)
	require.NoError(t, err)
	idClaims := decodeJWTUnverified(t, resp.IDToken)
	amr, ok := idClaims["amr"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"hwk", "user", "mfa"}, amr,
		"hardware-key authenticator must trigger the mfa umbrella")
	// And acr must reflect AAL3 since hwk is verifier-impersonation-resistant.
	assert.Equal(t, ACRValueAAL3, idClaims["acr"])
}

func TestGenerateTokens_AMR_UmbrellaIdempotent(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		// Caller already included `mfa` (e.g. session restored from a
		// blob that the elevateCurrentSessionAMR path tagged).
		[]string{"pwd", "otp", "mfa"},
		nil,
	)
	require.NoError(t, err)
	idClaims := decodeJWTUnverified(t, resp.IDToken)
	amr, ok := idClaims["amr"].([]interface{})
	require.True(t, ok)
	// Expect exactly one `mfa` entry — no duplicate.
	count := 0
	for _, v := range amr {
		if s, _ := v.(string); s == "mfa" {
			count++
		}
	}
	assert.Equal(t, 1, count, "umbrella must be appended idempotently")
}

func TestGenerateTokens_AMR_OmittedWhenAuthMethodsEmpty(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		nil, // no authentication-method snapshot available
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "amr",
		"amr must be omitted rather than emitted as empty — OIDC Core §2 treats amr as OPTIONAL")
}

// ──────────────────────────────────────────────────────────────────────────────
// groups — scope requested AND client allows → emitted; all other combinations
// → omitted.
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateIDToken_Groups_ScopeRequestedAndClientAllowed(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupPaths: []string{"/platform/admins", "/ops"},
	})
	client := authzCodeClient([]string{"openid", OIDCScopeGroups})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeGroups}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	require.Contains(t, idClaims, "groups")
	groups, ok := idClaims["groups"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"/ops", "/platform/admins"}, groups,
		"groups must be sorted for determinism")
}

func TestGenerateIDToken_Groups_ClientDoesNotAllow_Omitted(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupPaths: []string{"/platform/admins"},
	})
	// Scope requested but client.Scopes does NOT include "groups".
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeGroups}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "groups",
		"client without the groups scope allowlist entry must never receive the claim")
}

func TestGenerateIDToken_Groups_ScopeNotRequested_Omitted(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupPaths: []string{"/platform/admins"},
	})
	client := authzCodeClient([]string{"openid", OIDCScopeGroups})
	user := subjectUser()

	// Client allows groups, but the client did not request the groups scope.
	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "groups",
		"client that did not request the scope must not get the claim")
}

func TestGenerateIDToken_Groups_NoProviderWired_OmittedNotFailed(t *testing.T) {
	svc := newTestOAuthService(t)
	// Intentionally do NOT call SetSubjectClaimsProvider.
	client := authzCodeClient([]string{"openid", OIDCScopeGroups})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeGroups}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err, "token issuance must not fail when the provider is unwired")

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "groups",
		"without a wired provider the claim is silently omitted")
}

func TestGenerateIDToken_Groups_ProviderError_OmittedNotFailed(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupErr: assert.AnError,
	})
	client := authzCodeClient([]string{"openid", OIDCScopeGroups})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeGroups}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err, "a transient provider error must not fail token issuance")

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "groups")
}

// ──────────────────────────────────────────────────────────────────────────────
// roles — EffectiveRoles deduped + sorted; same scope gating as groups.
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateIDToken_Roles_EmittedAndDeduplicated(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		roles: []*models.EffectiveRole{
			{RoleID: uuid.New(), RoleName: "platform-admin", Source: "direct"},
			// Same role inherited via a group — must NOT duplicate.
			{RoleID: uuid.New(), RoleName: "platform-admin", Source: "group"},
			{RoleID: uuid.New(), RoleName: "ops-viewer", Source: "group"},
		},
	})
	client := authzCodeClient([]string{"openid", OIDCScopeRoles})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeRoles}, nil, nil,
		[]string{"pwd"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	require.Contains(t, idClaims, "roles")
	roles, ok := idClaims["roles"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"ops-viewer", "platform-admin"}, roles,
		"direct+group-inherited entries for the same role must be deduplicated")
}

func TestGenerateIDToken_Roles_ClientDoesNotAllow_Omitted(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		roles: []*models.EffectiveRole{{RoleID: uuid.New(), RoleName: "platform-admin"}},
	})
	client := authzCodeClient([]string{"openid"}) // no "roles"
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeRoles}, nil, nil,
		nil,
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "roles")
}

// ──────────────────────────────────────────────────────────────────────────────
// Access token mirrors id_token for groups/roles/amr (Auth0/Okta behaviour —
// saves resource servers a /userinfo round-trip).
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateAccessToken_CarriesGroupsRolesAMR(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupPaths: []string{"/platform/admins"},
		roles:      []*models.EffectiveRole{{RoleID: uuid.New(), RoleName: "platform-admin"}},
	})
	client := authzCodeClient([]string{"openid", OIDCScopeGroups, OIDCScopeRoles})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", OIDCScopeGroups, OIDCScopeRoles}, nil, nil,
		[]string{"pwd", "otp"},
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	atClaims := decodeJWTUnverified(t, resp.AccessToken)
	assert.Contains(t, atClaims, "groups")
	assert.Contains(t, atClaims, "roles")
	assert.Contains(t, atClaims, "amr")
}

// ──────────────────────────────────────────────────────────────────────────────
// Backwards compat: a client that requests no new scopes gets today's exact
// claim set — no empty `groups`/`roles`/`amr` surprises.
// ──────────────────────────────────────────────────────────────────────────────

func TestGenerateIDToken_BackwardsCompat_NoNewScopes_NoNewClaims(t *testing.T) {
	svc := newTestOAuthService(t)
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupPaths: []string{"/platform/admins"},
		roles:      []*models.EffectiveRole{{RoleID: uuid.New(), RoleName: "platform-admin"}},
	})
	client := authzCodeClient([]string{"openid", "profile", "email"})
	user := subjectUser()

	resp, err := svc.generateTokens(		context.Background(),
		client, user,
		[]string{"openid", "profile", "email"}, nil, nil,
		nil, // pre-migration session: no amr snapshot
		nil, // no IdP session id (test fixture pre-migration-220)
	)
	require.NoError(t, err)

	idClaims := decodeJWTUnverified(t, resp.IDToken)
	assert.NotContains(t, idClaims, "groups")
	assert.NotContains(t, idClaims, "roles")
	assert.NotContains(t, idClaims, "amr")

	// Positive checks on today's expected claim set — nothing removed.
	for _, c := range []string{"iss", "sub", "aud", "exp", "iat", "tenant_id"} {
		assert.Contains(t, idClaims, c)
	}
}
