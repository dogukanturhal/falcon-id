// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

const testAccessTokenType = "urn:ietf:params:oauth:token-type:access_token"

type fakeTenantExchangeStore struct {
	m     *models.TenantExchangeMembership
	err   error
	calls int
}

func (f *fakeTenantExchangeStore) ResolveTenantExchange(_ context.Context, _, tenantID uuid.UUID) (*models.TenantExchangeMembership, error) {
	f.calls++
	if f.m == nil || f.err != nil {
		return nil, f.err
	}
	if f.m.TenantID != tenantID {
		return nil, nil
	}
	return f.m, nil
}

type fakeTenantExchangeLimiter struct{ allowed bool }

func (f *fakeTenantExchangeLimiter) Check(context.Context, string, int, time.Duration, time.Duration) (*redispkg.RateLimitResult, error) {
	return &redispkg.RateLimitResult{Allowed: f.allowed}, nil
}

type tenantExchangeFixture struct {
	svc     *OAuthProviderService
	repo    *rotationPolicyTestRepo
	store   *fakeTenantExchangeStore
	client  *models.OAuthClient
	user    *models.User
	target  uuid.UUID
	subject string
}

// newTenantExchangeFixture: an accountant (home tenant = their practice)
// with an active external membership in a client tenant, and a genuine
// home-tenant access token issued to the BFF client.
func newTenantExchangeFixture(t *testing.T) *tenantExchangeFixture {
	t.Helper()
	repo := newRotationPolicyTestRepo()
	user := subjectUser()
	user.IsActive = true
	svc := newTestOAuthProviderService(t, repo, &fixedUserRepo{user: user})
	svc.SetSubjectClaimsProvider(&stubSubjectClaims{
		groupPaths: []string{"/partner/admins"},
		roles:      []*models.EffectiveRole{{RoleID: uuid.New(), RoleName: "Tenant Admin"}, {RoleID: uuid.New(), RoleName: "external_readonly"}},
	})
	client := activeConfidentialBFFClient("rotate")
	client.Scopes = []string{"openid", "profile", "roles", "groups"}
	target := uuid.New()
	store := &fakeTenantExchangeStore{m: &models.TenantExchangeMembership{
		TenantID: target, TenantSlug: "client", TenantStatus: "active",
		SeatClass: models.SeatClassExternal, Status: models.UserMembershipStatusActive,
		RoleNames: []string{"external_readonly"},
	}}
	svc.SetTenantExchange(store, nil)

	subject, err := svc.generateTokens(context.Background(), client, user, []string{"openid", "profile", "roles", "groups"}, nil, nil, nil, nil)
	require.NoError(t, err)
	hash := svc.hashSecret(subject.AccessToken)
	repo.addToken(hash, &models.OAuthToken{
		ID: uuid.New(), TenantID: client.TenantID, ClientID: client.ID, UserID: &user.ID,
		TokenType: "access_token", Token: hash, Scopes: []string{"openid", "profile", "roles", "groups"},
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	return &tenantExchangeFixture{svc: svc, repo: repo, store: store, client: client, user: user, target: target, subject: subject.AccessToken}
}

func (f *tenantExchangeFixture) exchange(ctx context.Context) (*models.OAuthTokenResponse, error) {
	return f.svc.TenantTokenExchange(ctx, f.client, f.subject, testAccessTokenType, "", f.target.String(), nil)
}

func TestTenantTokenExchange_IssuesTargetTenantGuestToken(t *testing.T) {
	f := newTenantExchangeFixture(t)

	resp, err := f.exchange(context.Background())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.RefreshToken, "exchange is not a login: no refresh token")
	assert.Empty(t, resp.IDToken, "exchange is not a login: no id_token")
	assert.Equal(t, f.target.String(), resp.TenantID)
	assert.Equal(t, "client", resp.TenantSlug)
	assert.Equal(t, "external", resp.MembershipKind)
	assert.LessOrEqual(t, resp.ExpiresIn, int64(tenantExchangeAccessTokenTTL/time.Second))

	claims := decodeJWTUnverified(t, resp.AccessToken)
	assert.Equal(t, f.target.String(), claims["tenant_id"], "token carries the target tenant")
	assert.Equal(t, f.user.ID.String(), claims["sub"])
	assert.Equal(t, "external", claims["membership_kind"], "guests are marked")
	assert.Equal(t, []interface{}{"external_readonly"}, claims["roles"], "only target-tenant roles; the partner admin role must not leak")
	assert.NotContains(t, claims, "groups", "group paths are not tenant-scoped and are dropped")
	assert.NotContains(t, claims, "platform_admin")
	act, ok := claims["act"].(map[string]interface{})
	require.True(t, ok, "RFC 8693 act claim records the client")
	assert.Equal(t, f.client.ClientID, act["client_id"])
	aud := claims["aud"]
	assert.Contains(t, aud, f.client.ClientID, "same audience as normal tokens")

	exp := int64(claims["exp"].(float64))
	assert.LessOrEqual(t, exp, time.Now().Add(tenantExchangeAccessTokenTTL+5*time.Second).Unix())

	// The stored row expires with the access token (no long-lived refresh hash).
	row := f.repo.createdTokenRows[len(f.repo.createdTokenRows)-1]
	assert.WithinDuration(t, time.Unix(exp, 0), row.ExpiresAt, 2*time.Second)
}

func TestTenantTokenExchange_MemberKindIsMarked(t *testing.T) {
	f := newTenantExchangeFixture(t)
	f.store.m.SeatClass = models.SeatClassMember

	resp, err := f.exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "member", decodeJWTUnverified(t, resp.AccessToken)["membership_kind"])
}

func TestTenantTokenExchange_Rejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(f *tenantExchangeFixture)
		wantErr string
	}{
		{"no membership", func(f *tenantExchangeFixture) { f.store.m = nil }, "invalid_target:"},
		{"membership for another tenant only", func(f *tenantExchangeFixture) { f.target = uuid.New() }, "invalid_target:"},
		{"deactivated (revoked) membership", func(f *tenantExchangeFixture) {
			f.store.m.Status = models.UserMembershipStatusDeactivated
		}, "invalid_target:"},
		{"service seat class", func(f *tenantExchangeFixture) { f.store.m.SeatClass = models.SeatClassService }, "invalid_target:"},
		{"tenant suspended (status)", func(f *tenantExchangeFixture) { f.store.m.TenantStatus = "suspended" }, "invalid_target:"},
		{"protected platform tenant", func(f *tenantExchangeFixture) {
			f.target = uuid.MustParse(models.HexxlockInternalTenantID)
			f.store.m.TenantID = f.target
		}, "invalid_target:"},
		{"subject token issued to another client", func(f *tenantExchangeFixture) {
			other := activeConfidentialBFFClient("rotate")
			other.ClientID = "some-other-bff"
			f.client = other
		}, "invalid_grant:"},
		{"public client", func(f *tenantExchangeFixture) { f.client.IsPublic = true }, "unauthorized_client:"},
		{"revoked subject token", func(f *tenantExchangeFixture) {
			f.repo.tokenByHash[f.svc.hashSecret(f.subject)].IsRevoked = true
		}, "invalid_grant:"},
		{"unknown subject token row", func(f *tenantExchangeFixture) {
			delete(f.repo.tokenByHash, f.svc.hashSecret(f.subject))
		}, "invalid_grant:"},
		{"garbage subject token", func(f *tenantExchangeFixture) { f.subject = "not-a-jwt" }, "invalid_grant:"},
		{"inactive user", func(f *tenantExchangeFixture) { f.user.IsActive = false }, "invalid_grant:"},
		{"locked user", func(f *tenantExchangeFixture) { f.user.IsLocked = true }, "invalid_grant:"},
		{"non-uuid target", func(f *tenantExchangeFixture) { f.target = uuid.Nil }, "invalid_request:"},
		{"exchange disabled", func(f *tenantExchangeFixture) { f.svc.SetTenantExchange(nil, nil) }, "invalid_request:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTenantExchangeFixture(t)
			tc.mutate(f)
			_, err := f.exchange(context.Background())
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tc.wantErr), "got %q", err.Error())
		})
	}
}

func TestTenantTokenExchange_RejectsExpiredSubjectToken(t *testing.T) {
	f := newTenantExchangeFixture(t)
	f.client.AccessTokenLifetime = -60 // mint an already-expired subject token
	expired, err := f.svc.generateTokens(context.Background(), f.client, f.user, []string{"openid"}, nil, nil, nil, nil)
	require.NoError(t, err)
	f.client.AccessTokenLifetime = 300
	hash := f.svc.hashSecret(expired.AccessToken)
	f.repo.addToken(hash, &models.OAuthToken{ID: uuid.New(), ClientID: f.client.ID, UserID: &f.user.ID, Token: hash, Scopes: []string{"openid"}})
	f.subject = expired.AccessToken

	_, err = f.exchange(context.Background())
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "invalid_grant:"), err.Error())
}

func TestTenantTokenExchange_DPoPBoundSubjectNeedsSameKey(t *testing.T) {
	f := newTenantExchangeFixture(t)
	bound, err := f.svc.generateTokens(WithDPoPJKT(context.Background(), "jkt-1"), f.client, f.user, []string{"openid"}, nil, nil, nil, nil)
	require.NoError(t, err)
	hash := f.svc.hashSecret(bound.AccessToken)
	f.repo.addToken(hash, &models.OAuthToken{ID: uuid.New(), ClientID: f.client.ID, UserID: &f.user.ID, Token: hash, Scopes: []string{"openid"}})
	f.subject = bound.AccessToken

	_, err = f.exchange(context.Background())
	require.Error(t, err, "bearer replay of a DPoP-bound token must fail")
	_, err = f.exchange(WithDPoPJKT(context.Background(), "jkt-other"))
	require.Error(t, err)
	_, err = f.exchange(WithDPoPJKT(context.Background(), "jkt-1"))
	require.NoError(t, err)
}

func TestTenantTokenExchange_ScopeNeverWidens(t *testing.T) {
	f := newTenantExchangeFixture(t)
	_, err := f.svc.TenantTokenExchange(context.Background(), f.client, f.subject, testAccessTokenType, "", f.target.String(), []string{"admin:all"})
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "invalid_scope:"))
}

func TestTenantTokenExchange_RateLimited(t *testing.T) {
	f := newTenantExchangeFixture(t)
	f.svc.SetTenantExchange(f.store, &fakeTenantExchangeLimiter{allowed: false})
	_, err := f.exchange(context.Background())
	require.True(t, errors.Is(err, ErrTenantExchangeRateLimited))
	assert.Zero(t, f.store.calls, "a limited request must not reach the membership lookup")
}

func TestTenantTokenExchange_SuspendedTargetTenant(t *testing.T) {
	f := newTenantExchangeFixture(t)
	f.svc.SetTenantSuspensionChecker(fakeSuspension{f.target: true})
	_, err := f.exchange(context.Background())
	require.True(t, errors.Is(err, ErrTenantSuspended))
}

func TestTenantTokenExchange_DoesNotMutateRepositoryUser(t *testing.T) {
	f := newTenantExchangeFixture(t)
	home := f.user.TenantID
	_, err := f.exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, home, f.user.TenantID)
}

// reissueSubject replaces the fixture's subject token with one carrying the
// given authentication methods (the default fixture token has no amr claim).
func (f *tenantExchangeFixture) reissueSubject(t *testing.T, amr []string) {
	t.Helper()
	scopes := []string{"openid", "profile", "roles", "groups"}
	subject, err := f.svc.generateTokens(context.Background(), f.client, f.user, scopes, nil, nil, amr, nil)
	require.NoError(t, err)
	hash := f.svc.hashSecret(subject.AccessToken)
	f.repo.addToken(hash, &models.OAuthToken{
		ID: uuid.New(), TenantID: f.client.TenantID, ClientID: f.client.ID, UserID: &f.user.ID,
		TokenType: "access_token", Token: hash, Scopes: scopes,
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	f.subject = subject.AccessToken
}

func TestTenantTokenExchange_AdminRoleInJoinedTenantRequiresMFA(t *testing.T) {
	for _, role := range []string{"owner", "admin", "Admin"} {
		t.Run(role+" without MFA is stepped up", func(t *testing.T) {
			f := newTenantExchangeFixture(t)
			f.store.m.SeatClass = models.SeatClassMember
			f.store.m.RoleNames = []string{"viewer", role}
			f.reissueSubject(t, []string{"pwd"})
			_, err := f.exchange(context.Background())
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), "insufficient_user_authentication:"), "got %q", err.Error())
		})
	}

	t.Run("admin with MFA amr exchanges and amr is carried forward", func(t *testing.T) {
		f := newTenantExchangeFixture(t)
		f.store.m.SeatClass = models.SeatClassMember
		f.store.m.RoleNames = []string{"admin"}
		f.reissueSubject(t, []string{"pwd", "otp"})
		resp, err := f.exchange(context.Background())
		require.NoError(t, err)
		amr, _ := decodeJWTUnverified(t, resp.AccessToken)["amr"].([]interface{})
		assert.Contains(t, amr, "otp")
		assert.Contains(t, amr, "mfa")
	})

	t.Run("non-admin role needs no MFA", func(t *testing.T) {
		f := newTenantExchangeFixture(t)
		f.store.m.SeatClass = models.SeatClassMember
		f.store.m.RoleNames = []string{"accountant"}
		f.reissueSubject(t, []string{"pwd"})
		_, err := f.exchange(context.Background())
		require.NoError(t, err)
	})

	t.Run("admin in the home tenant is not stepped up", func(t *testing.T) {
		f := newTenantExchangeFixture(t)
		f.store.m.SeatClass = models.SeatClassMember
		f.store.m.RoleNames = []string{"owner"}
		f.user.TenantID = f.target
		f.reissueSubject(t, []string{"pwd"})
		_, err := f.exchange(context.Background())
		require.NoError(t, err)
	})
}

// publicExchangeFixture turns the fixture client into an allowlisted native
// public client (PKCE + first-party).
func publicExchangeFixture(t *testing.T, allowlisted bool) *tenantExchangeFixture {
	t.Helper()
	f := newTenantExchangeFixture(t)
	f.client.IsPublic = true
	f.client.IsConfidential = false
	f.client.RequirePKCE = true
	f.client.IsFirstParty = true
	f.client.GrantTypes = append(f.client.GrantTypes, tokenExchangeGrantType)
	if allowlisted {
		f.svc.cfg.TenantExchangePublicClientIDs = []string{f.client.ClientID}
	}
	return f
}

func TestTenantTokenExchange_PublicClient(t *testing.T) {
	t.Run("allowlisted succeeds", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		resp, err := f.exchange(context.Background())
		require.NoError(t, err)
		assert.Equal(t, f.target.String(), resp.TenantID)
	})
	t.Run("not allowlisted", func(t *testing.T) {
		f := publicExchangeFixture(t, false)
		_, err := f.exchange(context.Background())
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "unauthorized_client:"))
	})
	t.Run("allowlisted but not registered for token-exchange grant", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		f.client.GrantTypes = []string{"authorization_code", "refresh_token"}
		_, err := f.exchange(context.Background())
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "unauthorized_client:"))
	})
	t.Run("allowlisted but not PKCE", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		f.client.RequirePKCE = false
		_, err := f.exchange(context.Background())
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "unauthorized_client:"))
	})
	t.Run("allowlisted but third party", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		f.client.IsFirstParty = false
		_, err := f.exchange(context.Background())
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "unauthorized_client:"))
	})
	t.Run("subject token from another client", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		f.repo.tokenByHash[f.svc.hashSecret(f.subject)].ClientID = uuid.New()
		_, err := f.exchange(context.Background())
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "invalid_grant:"))
	})
	t.Run("no membership", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		f.store.m = nil
		_, err := f.exchange(context.Background())
		require.Error(t, err)
		assert.Equal(t, tenantExchangeDenied, err.Error())
	})
	t.Run("rate limit applies", func(t *testing.T) {
		f := publicExchangeFixture(t, true)
		f.svc.SetTenantExchange(f.store, &fakeTenantExchangeLimiter{allowed: false})
		_, err := f.exchange(context.Background())
		require.True(t, errors.Is(err, ErrTenantExchangeRateLimited))
	})
}

// An exchanged token is itself a valid subject token for the same client.
// Re-exchanging it must never push the expiry past the original subject's.
func TestTenantTokenExchange_ChainNeverExtendsExpiry(t *testing.T) {
	f := newTenantExchangeFixture(t)
	f.client.AccessTokenLifetime = 120
	f.reissueSubject(t, nil)
	subjectExp := int64(decodeJWTUnverified(t, f.subject)["exp"].(float64))
	f.client.AccessTokenLifetime = 3600

	for i := 0; i < 3; i++ {
		resp, err := f.exchange(context.Background())
		require.NoError(t, err, "hop %d", i+1)
		exp := int64(decodeJWTUnverified(t, resp.AccessToken)["exp"].(float64))
		assert.LessOrEqual(t, exp, subjectExp, "hop %d must not extend exp", i+1)
		assert.LessOrEqual(t, resp.ExpiresIn, int64(120), "hop %d expires_in follows the capped expiry", i+1)
		assert.Greater(t, resp.ExpiresIn, int64(0))

		hash := f.svc.hashSecret(resp.AccessToken)
		f.repo.addToken(hash, &models.OAuthToken{
			ID: uuid.New(), TenantID: f.client.TenantID, ClientID: f.client.ID, UserID: &f.user.ID,
			TokenType: "access_token", Token: hash, Scopes: []string{"openid", "profile", "roles", "groups"},
			ExpiresAt: time.Unix(exp, 0), CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		f.subject = resp.AccessToken
	}
}
