// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type termFakeSessions struct {
	active     []models.Session
	endedAll   bool
	endedExcep *uuid.UUID
	endedOne   []uuid.UUID
	failEnd    error
}

func (f *termFakeSessions) GetActiveSessions(context.Context, uuid.UUID) ([]models.Session, error) {
	return f.active, nil
}
func (f *termFakeSessions) EndSession(_ context.Context, id uuid.UUID, _ string) error {
	f.endedOne = append(f.endedOne, id)
	return nil
}
func (f *termFakeSessions) EndAllUserSessions(context.Context, uuid.UUID, string) error {
	f.endedAll = true
	return f.failEnd
}
func (f *termFakeSessions) EndAllUserSessionsExcept(_ context.Context, _ uuid.UUID, except uuid.UUID, _ string) error {
	f.endedExcep = &except
	return f.failEnd
}

type termFakeTokens struct {
	allRevoked bool
	bySession  []uuid.UUID
}

func (f *termFakeTokens) RevokeAllUserOAuthTokens(context.Context, uuid.UUID, string) error {
	f.allRevoked = true
	return nil
}
func (f *termFakeTokens) RevokeOAuthTokensBySession(_ context.Context, sid, _ uuid.UUID) error {
	f.bySession = append(f.bySession, sid)
	return nil
}

type termFakeBlacklist struct {
	cleared   int
	userCalls int
	sessions  []uuid.UUID
}

func (f *termFakeBlacklist) BlacklistUserTokens(context.Context, uuid.UUID, string, time.Duration) error {
	f.userCalls++
	return nil
}
func (f *termFakeBlacklist) ClearUser(context.Context, uuid.UUID) error {
	f.cleared++
	return nil
}
func (f *termFakeBlacklist) BlacklistSession(_ context.Context, id uuid.UUID, _ string, _ time.Duration) error {
	f.sessions = append(f.sessions, id)
	return nil
}

type termFakeBCL struct{ calls []string }

func (f *termFakeBCL) NotifyLogout(_ context.Context, _ uuid.UUID, sid string, _ uuid.UUID) error {
	f.calls = append(f.calls, sid)
	return nil
}

func newTermSSOCache(t *testing.T) *redispkg.SessionCache {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	client, err := redispkg.NewClient(&redispkg.Config{
		URL: "redis://" + mr.Addr(), MaxRetries: 1, MinIdleConns: 1, MaxIdleConns: 2,
		ConnMaxLifetime: time.Minute, DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return redispkg.NewSessionCache(client, "term", 30*time.Minute)
}

type termHarness struct {
	term     *UserAccessTerminator
	sessions *termFakeSessions
	tokens   *termFakeTokens
	bl       *termFakeBlacklist
	bcl      *termFakeBCL
	sso      *redispkg.SessionCache
}

func newTermHarness(t *testing.T) *termHarness {
	h := &termHarness{
		sessions: &termFakeSessions{}, tokens: &termFakeTokens{}, bl: &termFakeBlacklist{},
		bcl: &termFakeBCL{}, sso: newTermSSOCache(t),
	}
	h.term = NewUserAccessTerminator(h.sessions, h.tokens, h.sso, h.bl, h.bcl, nil, 0, zap.NewNop())
	return h
}

func (h *termHarness) addSSO(t *testing.T, userID, rowID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	require.NoError(t, h.sso.SetIdpSession(context.Background(), id, &redispkg.IdpSessionData{
		UserID: userID, TenantID: uuid.New(), SessionID: rowID, AuthTime: time.Now().Unix(),
	}))
	return id
}

func (h *termHarness) ssoAlive(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	d, err := h.sso.GetIdpSession(context.Background(), id)
	require.NoError(t, err)
	return d != nil
}

// ---------------------------------------------------------------------------
// Terminator
// ---------------------------------------------------------------------------

func TestTerminateUserAccess_EndsEverythingAndBlacklistsUser(t *testing.T) {
	h := newTermHarness(t)
	uid, tid, row := uuid.New(), uuid.New(), uuid.New()
	h.sessions.active = []models.Session{{ID: row, UserID: uid}}
	sso := h.addSSO(t, uid, row)

	require.NoError(t, h.term.TerminateUserAccess(context.Background(), uid, tid, "admin_disable", nil))
	assert.Equal(t, []string{"", sso.String()}, h.bcl.calls, "sub-wide BCL plus one per SSO session id")

	assert.True(t, h.sessions.endedAll)
	assert.True(t, h.tokens.allRevoked)
	assert.False(t, h.ssoAlive(t, sso), "SSO cookie state must be gone")
	assert.Equal(t, 1, h.bl.userCalls)
	assert.Equal(t, []uuid.UUID{row}, h.bl.sessions)
}

func TestTerminateUserAccess_ExceptKeepsCurrentSession(t *testing.T) {
	h := newTermHarness(t)
	uid, keepRow, dropRow := uuid.New(), uuid.New(), uuid.New()
	h.sessions.active = []models.Session{{ID: keepRow, UserID: uid}, {ID: dropRow, UserID: uid}}
	keep := h.addSSO(t, uid, keepRow)
	drop := h.addSSO(t, uid, dropRow)

	require.NoError(t, h.term.TerminateUserAccess(context.Background(), uid, uuid.New(), "password_change", &keepRow))

	require.NotNil(t, h.sessions.endedExcep)
	assert.Equal(t, keepRow, *h.sessions.endedExcep)
	assert.False(t, h.sessions.endedAll)
	assert.True(t, h.ssoAlive(t, keep))
	assert.False(t, h.ssoAlive(t, drop))
	assert.Equal(t, 0, h.bl.userCalls, "flat user blacklist would kill the surviving session")
	assert.Equal(t, []uuid.UUID{dropRow}, h.bl.sessions)
	assert.Equal(t, []string{drop.String()}, h.bcl.calls, "BCL only for the ended SSO session")
}

func TestClearUserBlock(t *testing.T) {
	h := newTermHarness(t)
	h.term.ClearUserBlock(context.Background(), uuid.New())
	assert.Equal(t, 1, h.bl.cleared)
}

func TestUserBlacklistTTL_FromConfig(t *testing.T) {
	assert.Equal(t, 16*time.Minute, UserBlacklistTTL(nil))
	assert.Equal(t, 10*time.Minute+30*time.Second+time.Minute,
		UserBlacklistTTL(&config.Config{AccessTokenExpiry: 10 * time.Minute, JWTClockSkewLeeway: 30 * time.Second}))
}

type recordingTerminator struct {
	with  []TerminateOptions
	calls int
}

func (r *recordingTerminator) TerminateUserAccess(context.Context, uuid.UUID, uuid.UUID, string, *uuid.UUID) error {
	r.calls++
	return nil
}
func (r *recordingTerminator) TerminateUserAccessWith(_ context.Context, _, _ uuid.UUID, _ string, o TerminateOptions) error {
	r.calls++
	r.with = append(r.with, o)
	return nil
}
func (r *recordingTerminator) TerminateSession(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) error {
	r.calls++
	return nil
}
func (r *recordingTerminator) ClearUserBlock(context.Context, uuid.UUID) {}

func TestAdminDisableMFA_TerminatesAccessWithoutUserBlacklist(t *testing.T) {
	svc, users, mfaRepo, _, _ := createTestMFAService()
	rec := &recordingTerminator{}
	svc.SetAccessTerminator(rec)
	u := &models.User{ID: uuid.New(), TenantID: uuid.New(), MFAEnabled: true}
	users.On("GetByID", mock.Anything, u.ID).Return(u, nil)
	users.On("HasNonPrimaryMFAFactor", mock.Anything, u.ID).Return(false, nil)
	users.On("Update", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	mfaRepo.On("DeleteAllRecoveryCodes", mock.Anything, u.ID).Return(nil)

	require.NoError(t, svc.AdminDisableMFA(context.Background(), u.ID))
	require.Len(t, rec.with, 1)
	assert.False(t, rec.with[0].BlacklistUser)
}

func TestTerminateUserAccessWith_NoUserBlacklistForCredentialRotation(t *testing.T) {
	h := newTermHarness(t)
	uid := uuid.New()
	require.NoError(t, h.term.TerminateUserAccessWith(context.Background(), uid, uuid.New(), "password_reset", TerminateOptions{}))
	assert.Equal(t, 0, h.bl.userCalls)
	assert.True(t, h.sessions.endedAll)
}

func TestTerminateUserAccess_BestEffortReturnsJoinedError(t *testing.T) {
	h := newTermHarness(t)
	h.sessions.failEnd = errors.New("db down")
	uid := uuid.New()
	err := h.term.TerminateUserAccess(context.Background(), uid, uuid.New(), "x", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "end_sessions")
	assert.True(t, h.tokens.allRevoked, "later steps still run")
	assert.Equal(t, 1, h.bl.userCalls)
}

func TestTerminateSession_OnlyThatSession(t *testing.T) {
	h := newTermHarness(t)
	uid, rowA, rowB := uuid.New(), uuid.New(), uuid.New()
	ssoA := h.addSSO(t, uid, rowA)
	ssoB := h.addSSO(t, uid, rowB)

	require.NoError(t, h.term.TerminateSession(context.Background(), uid, uuid.New(), rowA, "revoked by admin"))

	assert.Equal(t, []uuid.UUID{rowA}, h.sessions.endedOne)
	assert.False(t, h.sessions.endedAll)
	assert.False(t, h.tokens.allRevoked)
	assert.False(t, h.ssoAlive(t, ssoA))
	assert.True(t, h.ssoAlive(t, ssoB))
	assert.Contains(t, h.tokens.bySession, rowA)
	assert.Contains(t, h.tokens.bySession, ssoA, "tokens bound to the IdP SSO id end too")
	assert.Equal(t, []uuid.UUID{rowA}, h.bl.sessions)
	assert.Equal(t, 0, h.bl.userCalls)
}

// ---------------------------------------------------------------------------
// Wiring: password reset -> silent SSO fails
// ---------------------------------------------------------------------------

func TestPasswordReset_TerminatesSSOSession(t *testing.T) {
	ctx := context.Background()
	userRepo := new(MockPwdResetUserRepo)
	tokenRepo := new(MockPwdResetTokenRepo)
	svc, _ := newPasswordResetService(userRepo, tokenRepo)
	h := newTermHarness(t)
	svc.SetAccessTerminator(h.term)

	token, hash := generatePlaintextToken(t)
	userID, tenantID, resetID, row := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sso := h.addSSO(t, userID, row)

	tokenRepo.On("GetPasswordReset", ctx, mock.AnythingOfType("string")).Return(&models.PasswordReset{
		ID: resetID, UserID: userID, TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour),
	}, nil)
	userRepo.On("GetByID", ctx, userID).Return(&models.User{ID: userID, TenantID: tenantID, IsActive: true}, nil)
	userRepo.On("Update", ctx, mock.AnythingOfType("*models.User")).Return(nil)
	tokenRepo.On("MarkPasswordResetUsed", ctx, resetID).Return(nil)
	tokenRepo.On("InvalidateUserPasswordResets", ctx, userID).Return(nil)

	require.NoError(t, svc.ResetPassword(ctx, token, "newsecurepass", "127.0.0.1"))

	assert.False(t, h.ssoAlive(t, sso), "silent SSO must fail after a password reset")
	assert.True(t, h.sessions.endedAll)
	assert.True(t, h.tokens.allRevoked)
	assert.Equal(t, 0, h.bl.userCalls, "reset must not lock the user out of logging in again")
}

// ---------------------------------------------------------------------------
// Wiring: SCIM deactivate terminates; reactivation/no-op does not
// ---------------------------------------------------------------------------

type scimFakeUsers struct {
	scimServiceUserRepo
	u *models.User
}

func (f *scimFakeUsers) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	cp := *f.u
	return &cp, nil
}
func (f *scimFakeUsers) Update(_ context.Context, u *models.User) error {
	f.u = u
	return nil
}

func TestSCIM_DeactivateTerminatesAccess(t *testing.T) {
	h := newTermHarness(t)
	uid, row := uuid.New(), uuid.New()
	sso := h.addSSO(t, uid, row)
	users := &scimFakeUsers{u: &models.User{ID: uid, TenantID: uuid.New(), Username: "u", Email: "u@x.io", IsActive: true}}
	svc := &SCIMService{userRepo: users, cfg: &config.Config{}}
	svc.SetAccessTerminator(h.term)

	_, err := svc.UpdateUser(context.Background(), uid, &models.SCIMUser{UserName: "u", Active: false})
	require.NoError(t, err)

	assert.True(t, h.tokens.allRevoked)
	assert.False(t, h.ssoAlive(t, sso))
	assert.Equal(t, 1, h.bl.userCalls)
}

func TestSCIM_ReactivateClearsUserBlock(t *testing.T) {
	h := newTermHarness(t)
	uid := uuid.New()
	users := &scimFakeUsers{u: &models.User{ID: uid, TenantID: uuid.New(), Username: "u", Email: "u@x.io", IsActive: false}}
	svc := &SCIMService{userRepo: users, cfg: &config.Config{}}
	svc.SetAccessTerminator(h.term)
	_, err := svc.UpdateUser(context.Background(), uid, &models.SCIMUser{UserName: "u", Active: true})
	require.NoError(t, err)
	assert.Equal(t, 1, h.bl.cleared)
	assert.False(t, h.tokens.allRevoked)
}

func TestSCIM_PatchActiveStaysActiveDoesNotTerminate(t *testing.T) {
	h := newTermHarness(t)
	uid := uuid.New()
	users := &scimFakeUsers{u: &models.User{ID: uid, TenantID: uuid.New(), Username: "u", Email: "u@x.io", IsActive: true}}
	svc := &SCIMService{userRepo: users, cfg: &config.Config{}}
	svc.SetAccessTerminator(h.term)

	_, err := svc.UpdateUser(context.Background(), uid, &models.SCIMUser{UserName: "u", Active: true})
	require.NoError(t, err)
	assert.False(t, h.tokens.allRevoked)
}

// ---------------------------------------------------------------------------
// userEligibleForTokens + OAuth grants
// ---------------------------------------------------------------------------

func TestUserEligibleForTokens(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	assert.NoError(t, userEligibleForTokens(nil), "nil user (client_credentials) is eligible")
	assert.NoError(t, userEligibleForTokens(&models.User{IsActive: true, ActivationStatus: "active"}))
	assert.NoError(t, userEligibleForTokens(&models.User{IsActive: true, IsLocked: true, LockedUntil: &past}), "expired lock")
	assert.Error(t, userEligibleForTokens(&models.User{IsActive: false}))
	assert.Error(t, userEligibleForTokens(&models.User{IsActive: true, ActivationStatus: "pending_deletion"}))
	assert.Error(t, userEligibleForTokens(&models.User{IsActive: true, ActivationStatus: "admin_deleted"}))
	assert.NoError(t, userEligibleForTokens(&models.User{IsActive: true, IsLocked: true, LockedUntil: &future}),
		"a timed failed-login lock must not kill standing access")
	assert.Error(t, userEligibleForTokens(&models.User{IsActive: true, IsLocked: true}), "admin lock (no expiry)")
}

func TestExchangeAuthorizationCode_InactiveUserRejected(t *testing.T) {
	user := subjectUser()
	user.IsActive = false
	svc, repo, client, redirectURI, code := newTxExchangeFixture(t)
	repo.code.UserID = user.ID
	svc.userRepo = &fixedUserRepo{user: user}

	resp, err := svc.ExchangeAuthorizationCode(context.Background(), client, code, redirectURI, "", "")
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.False(t, repo.codeUsed(), "ineligible owner must not burn the code")
}

func newRefreshToken(svc *OAuthProviderService, repo *rotationPolicyTestRepo, client *models.OAuthClient, userID *uuid.UUID, plain string, family uuid.UUID) {
	hash := svc.hashSecret(plain)
	repo.addToken(hash, &models.OAuthToken{
		ID: uuid.New(), TenantID: client.TenantID, ClientID: client.ID, UserID: userID,
		TokenType: "access_token", Token: "access-" + plain, Scopes: []string{"openid"},
		RefreshToken: &hash, TokenFamilyID: &family, ExpiresAt: time.Now().Add(time.Hour),
	})
}

func TestRefreshTokens_DeactivatedUserFailsAndRevokesFamily(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	client := activeConfidentialBFFClient("rotate")
	userID := uuid.New()
	svc.userRepo = &bindingUserRepo{user: &models.User{ID: userID, TenantID: client.TenantID, IsActive: false}}
	fam := uuid.New()
	newRefreshToken(svc, repo, client, &userID, "rt-disabled", fam)

	resp, err := svc.RefreshTokens(context.Background(), client, "rt-disabled", "")
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Equal(t, []uuid.UUID{fam}, repo.revokedFamilies)
}

func TestRefreshTokens_NilUserIDStillWorks(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	client := activeConfidentialBFFClient("rotate")
	newRefreshToken(svc, repo, client, nil, "rt-machine", uuid.New())

	resp, err := svc.RefreshTokens(context.Background(), client, "rt-machine", "")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, repo.revokedFamilies)
}
