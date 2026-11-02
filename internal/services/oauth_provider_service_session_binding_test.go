// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// Tests for refresh-token <-> login-session binding (migration 0028):
//   - explicit session end (logout, admin revoke, password change, ...) makes
//     the session's refresh token fail with invalid_grant and revokes its family
//   - idle/absolute expiry of the SSO session does NOT: refresh keeps working
//     and the rotated token is re-bound to a freshly cut session row
//   - RFC 9700 reuse detection is unchanged for session-bound tokens
//   - /oauth/revoke on a refresh token revokes the whole family (RFC 7009)

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// bindingUserRepo returns a live user so the refresh drift path (which only
// runs for user-bound tokens) is exercised.
type bindingUserRepo struct {
	noopUserRepo
	user *models.User
}

func (r *bindingUserRepo) GetByID(context.Context, uuid.UUID) (*models.User, error) {
	return r.user, nil
}

type sessionBindingRepo struct {
	*rotationPolicyTestRepo
	revokedSessions []uuid.UUID
}

func (r *sessionBindingRepo) ListSessionIDsByIdpSession(_ context.Context, idp, userID uuid.UUID) ([]uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []uuid.UUID
	for _, t := range r.tokenByID {
		if t.UserID != nil && *t.UserID == userID && t.IdpSessionID != nil && *t.IdpSessionID == idp && t.SessionID != nil {
			out = append(out, *t.SessionID)
		}
	}
	return out, nil
}

// boundTo mirrors the repository predicate: session_id or idp_session_id match.
func boundTo(t *models.OAuthToken, sid uuid.UUID) bool {
	return (t.SessionID != nil && *t.SessionID == sid) || (t.IdpSessionID != nil && *t.IdpSessionID == sid)
}

// RevokeTokensBySession mirrors the repository: revoke live tokens bound to the
// session, plus their rotation families.
func (r *sessionBindingRepo) RevokeTokensBySession(_ context.Context, sid, userID uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokedSessions = append(r.revokedSessions, sid)
	families := map[uuid.UUID]bool{}
	for _, t := range r.tokenByID {
		if t.UserID != nil && *t.UserID == userID && boundTo(t, sid) && t.TokenFamilyID != nil {
			families[*t.TokenFamilyID] = true
		}
	}
	var n int64
	for _, t := range r.tokenByID {
		bound := boundTo(t, sid)
		inFamily := t.TokenFamilyID != nil && families[*t.TokenFamilyID]
		if !t.IsRevoked && t.UserID != nil && *t.UserID == userID && (bound || inFamily) {
			t.IsRevoked = true
			n++
		}
	}
	return n, nil
}

// RevokeAllUserOAuthTokens mirrors the repository's user-wide sweep.
func (r *sessionBindingRepo) RevokeAllUserOAuthTokens(_ context.Context, userID uuid.UUID, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tokenByID {
		if t.UserID != nil && *t.UserID == userID {
			t.IsRevoked = true
		}
	}
	return nil
}

// fakeSessionContext implements sessionContextService over an in-memory map.
type fakeSessionContext struct {
	sessions map[uuid.UUID]*models.Session
	cut      []*models.Session
	ended    map[uuid.UUID]string // EndSession calls: id -> reason
	// reads, when set for an id, are served in order (the last repeats) so a
	// test can flip a session to ended between the check and the re-check.
	reads   map[uuid.UUID][]*models.Session
	readErr error
	// shareReads counts FOR SHARE re-reads (the post-mint re-check).
	shareReads int
}

func (f *fakeSessionContext) GetSessionByID(_ context.Context, id uuid.UUID) (*models.Session, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if seq := f.reads[id]; len(seq) > 0 {
		cur := seq[0]
		if len(seq) > 1 {
			f.reads[id] = seq[1:]
		}
		return cur, nil
	}
	return f.sessions[id], nil
}

func (f *fakeSessionContext) GetSessionByIDInRealm(ctx context.Context, id, _ uuid.UUID) (*models.Session, error) {
	return f.GetSessionByID(ctx, id)
}

func (f *fakeSessionContext) GetSessionByIDInRealmForShare(ctx context.Context, id, realm uuid.UUID) (*models.Session, error) {
	f.shareReads++
	return f.GetSessionByIDInRealm(ctx, id, realm)
}

func (f *fakeSessionContext) EndSession(_ context.Context, id uuid.UUID, reason string) error {
	if f.ended == nil {
		f.ended = map[uuid.UUID]string{}
	}
	f.ended[id] = reason
	return nil
}

func (f *fakeSessionContext) CreateSessionFromRefresh(_ context.Context, userID uuid.UUID, _ []string) (*models.Session, error) {
	s := &models.Session{ID: uuid.New(), UserID: userID, IsActive: true}
	f.sessions[s.ID] = s
	f.cut = append(f.cut, s)
	return s, nil
}

func endedSession(reason string) *models.Session {
	now := time.Now()
	return &models.Session{ID: uuid.New(), IsActive: false, EndedAt: &now, EndReason: &reason}
}

type sessionBindingFixture struct {
	repo      *sessionBindingRepo
	svc       *OAuthProviderService
	sessions  *fakeSessionContext
	client    *models.OAuthClient
	plaintext string
	token     *models.OAuthToken
}

// newSessionBindingFixture seeds one refresh token bound to `session`.
func newSessionBindingFixture(t *testing.T, session *models.Session) *sessionBindingFixture {
	t.Helper()
	repo := &sessionBindingRepo{rotationPolicyTestRepo: newRotationPolicyTestRepo()}
	svc := newRefreshPolicyTestService(t, repo.rotationPolicyTestRepo)
	svc.clientRepo = repo
	client := activeConfidentialBFFClient("rotate")
	svc.userRepo = &bindingUserRepo{user: &models.User{ID: uuid.New(), TenantID: client.TenantID, IsActive: true}}
	sessions := &fakeSessionContext{sessions: map[uuid.UUID]*models.Session{session.ID: session}, reads: map[uuid.UUID][]*models.Session{}}
	svc.SetSessionContextService(sessions)

	plaintext := "bound-refresh-token-" + uuid.NewString()
	hash := svc.hashSecret(plaintext)
	id := uuid.New()
	sid := session.ID
	userID := uuid.New()
	tok := &models.OAuthToken{
		ID: id, TenantID: client.TenantID, ClientID: client.ID, UserID: &userID,
		TokenType: "access_token", Token: "access-hash-" + uuid.NewString(),
		Scopes: []string{"openid"}, RefreshToken: &hash, TokenFamilyID: &id,
		SessionID: &sid, ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now().Add(-time.Hour), UpdatedAt: time.Now().Add(-time.Hour),
	}
	repo.addToken(hash, tok)
	return &sessionBindingFixture{repo: repo, svc: svc, sessions: sessions, client: client, plaintext: plaintext, token: tok}
}

func (f *sessionBindingFixture) refresh() (*models.OAuthTokenResponse, error) {
	return f.svc.RefreshTokens(context.Background(), f.client, f.plaintext, "")
}

func TestRefreshTokens_SessionBinding_ExplicitEndRejected(t *testing.T) {
	// Every end reason written by a logout/revoke/password/disable path.
	for _, reason := range []string{
		"logout", "revoked", "revoked_by_admin", "password_change", "password_reset",
		"user_deleted", "user_deactivated", "tenant_suspended", "backchannel_logout",
		"employee_access_expired", "account_deletion_scheduled", "some_future_reason",
	} {
		t.Run(reason, func(t *testing.T) {
			f := newSessionBindingFixture(t, endedSession(reason))
			resp, err := f.refresh()
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), "invalid_grant")
			assert.Equal(t, []uuid.UUID{*f.token.TokenFamilyID}, f.repo.revokedFamilies,
				"explicitly ended session must revoke the token family")
			assert.Equal(t, []uuid.UUID{f.token.ID}, f.repo.consumedTokenIDs,
				"the check runs after the CAS consume; the consumed token is dead either way")
			assert.Empty(t, f.repo.createdTokenRows, "no tokens may be minted")
		})
	}
}

func TestRefreshTokens_SessionBinding_IdleOrAbsoluteExpiryKeepsRefreshWorking(t *testing.T) {
	for _, reason := range []string{"inactivity_timeout", "expired", "session_regenerated", "session_regenerated_on_login"} {
		t.Run(reason, func(t *testing.T) {
			f := newSessionBindingFixture(t, endedSession(reason))
			resp, err := f.refresh()
			require.NoError(t, err, "SSO session lapse must not kill the refresh token")
			require.NotNil(t, resp)
			assert.NotEmpty(t, resp.RefreshToken)
			assert.Empty(t, f.repo.revokedFamilies)
			assert.Empty(t, f.repo.revokedSessions)

			// The rotated token is re-bound to the freshly cut session row.
			require.Len(t, f.sessions.cut, 1)
			require.Len(t, f.repo.createdTokenRows, 1)
			row := f.repo.createdTokenRows[0]
			require.NotNil(t, row.SessionID)
			assert.Equal(t, f.sessions.cut[0].ID, *row.SessionID)
			assert.Equal(t, f.token.TokenFamilyID, row.TokenFamilyID, "family is preserved across rotation")
		})
	}
}

func TestRefreshTokens_SessionBinding_ActiveSessionRebindsToSameRow(t *testing.T) {
	active := &models.Session{ID: uuid.New(), IsActive: true}
	f := newSessionBindingFixture(t, active)
	_, err := f.refresh()
	require.NoError(t, err)
	assert.Empty(t, f.sessions.cut, "no drift: no new session row")
	require.Len(t, f.repo.createdTokenRows, 1)
	require.NotNil(t, f.repo.createdTokenRows[0].SessionID)
	assert.Equal(t, active.ID, *f.repo.createdTokenRows[0].SessionID)
}

func TestRefreshTokens_SessionBinding_LegacyUnboundTokenUnaffected(t *testing.T) {
	f := newSessionBindingFixture(t, endedSession("logout"))
	// A legacy token has neither session_id nor idp_session_id.
	f.repo.mu.Lock()
	f.repo.tokenByID[f.token.ID].SessionID = nil
	f.repo.mu.Unlock()

	resp, err := f.refresh()
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, f.repo.revokedFamilies)
}

func TestRefreshTokens_SessionBinding_ReuseDetectionUnchanged(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	// Legit rotation consumes the token...
	_, err := f.refresh()
	require.NoError(t, err)

	// ...a replay of the stale copy outside the grace window trips family revoke.
	f.repo.mu.Lock()
	old := time.Now().Add(-10 * time.Minute)
	f.repo.tokenByID[f.token.ID].RevokedAt = &old
	f.repo.mu.Unlock()

	resp, err := f.refresh()
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Equal(t, []uuid.UUID{*f.token.TokenFamilyID}, f.repo.revokedFamilies)
}

func TestRevokeToken_RefreshTokenRevokesWholeFamily(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	require.NoError(t, f.svc.RevokeToken(context.Background(), f.client, f.plaintext, "refresh_token"))
	assert.Equal(t, []uuid.UUID{*f.token.TokenFamilyID}, f.repo.revokedFamilies)
}

func TestRevokeToken_AccessTokenDoesNotRevokeFamily(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	accessPlain := "access-token-plain"
	accessHash := f.svc.hashSecret(accessPlain)
	cp := *f.token
	cp.Token = accessHash
	f.repo.addToken(accessHash, &cp)

	require.NoError(t, f.svc.RevokeToken(context.Background(), f.client, accessPlain, "access_token"))
	assert.Empty(t, f.repo.revokedFamilies)
}

func TestRevokeSessionTokens_DelegatesAndIgnoresNil(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	sid, uid := uuid.New(), uuid.New()
	require.NoError(t, f.svc.RevokeSessionTokens(context.Background(), sid, uid))
	require.NoError(t, f.svc.RevokeSessionTokens(context.Background(), uuid.Nil, uid))
	require.NoError(t, f.svc.RevokeSessionTokens(context.Background(), sid, uuid.Nil))
	assert.Equal(t, []uuid.UUID{sid}, f.repo.revokedSessions)
}

// stubRowSource lets the issuance path resolve the iam_sessions row behind the
// opaque falcon_idp_session id, as the Redis cache does.
type stubRowSource struct {
	idpID, rowID, owner uuid.UUID
}

func (s *stubRowSource) GetIdpSessionAuthTime(context.Context, uuid.UUID) (int64, bool, error) {
	return time.Now().Unix(), true, nil
}

func (s *stubRowSource) GetIdpSessionRowID(_ context.Context, id uuid.UUID) (uuid.UUID, uuid.UUID, bool, error) {
	if id == s.idpID {
		return s.rowID, s.owner, true, nil
	}
	return uuid.Nil, uuid.Nil, false, nil
}

func TestGenerateTokens_StampsSessionRowFromIdpSession(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	client := activeConfidentialBFFClient("rotate")
	user := &models.User{ID: uuid.New(), TenantID: client.TenantID}
	src := &stubRowSource{idpID: uuid.New(), rowID: uuid.New(), owner: user.ID}
	svc.SetSessionCacheAuthTimeSource(src)
	idp := src.idpID
	_, err := svc.generateTokens(context.Background(), client, user, []string{"openid"}, nil, nil, nil, &idp)
	require.NoError(t, err)
	require.Len(t, repo.createdTokenRows, 1)
	row := repo.createdTokenRows[0]
	require.NotNil(t, row.SessionID)
	assert.Equal(t, src.rowID, *row.SessionID)
	require.NotNil(t, row.IdpSessionID)
	assert.Equal(t, idp, *row.IdpSessionID, "sid claim value is unchanged")

	// Unknown idp session id degrades to an unbound token, never an error.
	other := uuid.New()
	_, err = svc.generateTokens(context.Background(), client, user, []string{"openid"}, nil, nil, nil, &other)
	require.NoError(t, err)
	assert.Nil(t, repo.createdTokenRows[1].SessionID)
}

func TestIsExplicitSessionEnd(t *testing.T) {
	for _, r := range []string{"expired", "inactivity_timeout", "session_regenerated", "session_regenerated_on_login"} {
		assert.False(t, models.IsExplicitSessionEnd(r), r)
	}
	for _, r := range []string{"logout", "revoked", "password_change", "unknown"} {
		assert.True(t, models.IsExplicitSessionEnd(r), r)
	}
}

// addSessionToken seeds another refresh token for the same user bound to session.
func (f *sessionBindingFixture) addSessionToken(session *models.Session) (plaintext string, tok *models.OAuthToken) {
	f.sessions.sessions[session.ID] = session
	plaintext = "other-refresh-" + uuid.NewString()
	hash := f.svc.hashSecret(plaintext)
	id := uuid.New()
	sid := session.ID
	tok = &models.OAuthToken{
		ID: id, TenantID: f.client.TenantID, ClientID: f.client.ID, UserID: f.token.UserID,
		TokenType: "access_token", Token: "access-hash-" + uuid.NewString(),
		Scopes: []string{"openid"}, RefreshToken: &hash, TokenFamilyID: &id,
		SessionID: &sid, ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	f.repo.addToken(hash, tok)
	return plaintext, tok
}

// Password change / reset / logout-all-devices / admin disable use the
// user-wide sweep: every session's refresh token fails, including sessions the
// caller never ended individually.
func TestTokenService_RevokeAllUserOAuthTokens_KillsEverySessionsRefresh(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	otherPlain, _ := f.addSessionToken(&models.Session{ID: uuid.New(), IsActive: true})

	ts := &TokenService{}
	ts.SetOAuthClientRepository(f.repo)
	require.NoError(t, ts.RevokeAllUserOAuthTokens(context.Background(), *f.token.UserID, "password_change"))

	for _, plain := range []string{f.plaintext, otherPlain} {
		resp, err := f.svc.RefreshTokens(context.Background(), f.client, plain, "")
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid_grant")
	}
}

// A session row that belongs to ANOTHER user must never be bound.
func TestGenerateTokens_SessionOwnerMismatchBindsNil(t *testing.T) {
	repo := newRotationPolicyTestRepo()
	svc := newRefreshPolicyTestService(t, repo)
	client := activeConfidentialBFFClient("rotate")
	user := &models.User{ID: uuid.New(), TenantID: client.TenantID}
	src := &stubRowSource{idpID: uuid.New(), rowID: uuid.New(), owner: uuid.New()}
	svc.SetSessionCacheAuthTimeSource(src)

	idp := src.idpID
	_, err := svc.generateTokens(context.Background(), client, user, []string{"openid"}, nil, nil, nil, &idp)
	require.NoError(t, err)
	require.Len(t, repo.createdTokenRows, 1)
	assert.Nil(t, repo.createdTokenRows[0].SessionID, "owner mismatch must bind nil")
}

// The session is explicitly ended AFTER the pre-mint read but before the token
// is handed out (the end's sweep ran before our insert). The post-mint re-read
// must catch it: invalid_grant, family revoked.
func TestRefreshTokens_SessionBinding_EndedBetweenConsumeAndInsert(t *testing.T) {
	t.Run("no drift", func(t *testing.T) {
		active := &models.Session{ID: uuid.New(), IsActive: true}
		f := newSessionBindingFixture(t, active)
		f.sessions.reads[active.ID] = []*models.Session{active, {ID: active.ID, IsActive: false, EndReason: strPtr("logout")}}

		resp, err := f.refresh()
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid_grant")
		assert.Equal(t, []uuid.UUID{*f.token.TokenFamilyID}, f.repo.revokedFamilies)
		assert.Empty(t, f.sessions.ended, "no session row was cut, nothing to end")
	})
	t.Run("with drift", func(t *testing.T) {
		lapsed := endedSession(models.SessionEndReasonInactivityTimeout)
		f := newSessionBindingFixture(t, lapsed)
		f.sessions.reads[lapsed.ID] = []*models.Session{lapsed, {ID: lapsed.ID, IsActive: false, EndReason: strPtr("logout")}}

		resp, err := f.refresh()
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "invalid_grant")
		assert.Equal(t, []uuid.UUID{*f.token.TokenFamilyID}, f.repo.revokedFamilies)
		require.Len(t, f.sessions.cut, 1)
		assert.Equal(t, "revoked", f.sessions.ended[f.sessions.cut[0].ID],
			"the session row cut during the race must be ended")
	})
}

// A failed session lookup must neither reject nor cut a new row.
func TestRefreshTokens_SessionBinding_LookupErrorKeepsBinding(t *testing.T) {
	active := &models.Session{ID: uuid.New(), IsActive: true}
	f := newSessionBindingFixture(t, active)
	f.sessions.readErr = errors.New("db down")

	resp, err := f.refresh()
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, f.sessions.cut, "lookup error must not cut a new row")
	require.Len(t, f.repo.createdTokenRows, 1)
	require.NotNil(t, f.repo.createdTokenRows[0].SessionID)
	assert.Equal(t, active.ID, *f.repo.createdTokenRows[0].SessionID, "binding kept")
}

// A token swept by an explicit session end and then replayed is NOT theft:
// plain invalid_grant, no family-revoke, no CAEP.
func TestRefreshTokens_SessionBinding_RevokedByEndedSessionIsNotReuse(t *testing.T) {
	f := newSessionBindingFixture(t, endedSession("logout"))
	old := time.Now().Add(-time.Hour)
	f.repo.mu.Lock()
	f.repo.tokenByID[f.token.ID].IsRevoked = true
	f.repo.tokenByID[f.token.ID].RevokedAt = &old
	f.repo.mu.Unlock()

	resp, err := f.refresh()
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Empty(t, f.repo.revokedFamilies, "no theft handling for an explicitly ended session")
}

type suspendedTenants struct{ suspended map[uuid.UUID]bool }

func (s suspendedTenants) IsSuspended(_ context.Context, id uuid.UUID) bool { return s.suspended[id] }

// After a suspension revokes every token, replays must say tenant_suspended and
// must NOT trip the theft handling (family revoke / CAEP) per replayed token.
func TestRefreshTokens_RevokedTokenOfSuspendedTenantIsNotReuse(t *testing.T) {
	f := newSessionBindingFixture(t, &models.Session{ID: uuid.New(), IsActive: true})
	user, _ := f.svc.userRepo.GetByID(context.Background(), uuid.New())
	f.svc.tenantSuspension = suspendedTenants{suspended: map[uuid.UUID]bool{user.TenantID: true}}
	old := time.Now().Add(-time.Hour)
	f.repo.mu.Lock()
	f.repo.tokenByID[f.token.ID].IsRevoked = true
	f.repo.tokenByID[f.token.ID].RevokedAt = &old
	f.repo.mu.Unlock()

	resp, err := f.refresh()
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrTenantSuspended)
	assert.Empty(t, f.repo.revokedFamilies)
}

func TestEndHintedSession(t *testing.T) {
	ctx := context.Background()
	t.Run("hint sid is a session row of the subject", func(t *testing.T) {
		row := &models.Session{ID: uuid.New(), IsActive: true}
		f := newSessionBindingFixture(t, row)
		subject := *f.token.UserID
		row.UserID = subject
		require.NoError(t, f.svc.EndHintedSession(ctx, row.ID, subject))
		assert.Equal(t, "logout", f.sessions.ended[row.ID])
	})
	t.Run("hint sid is the idp id: ends each bound row and revokes the tokens", func(t *testing.T) {
		row := &models.Session{ID: uuid.New(), IsActive: true}
		f := newSessionBindingFixture(t, row)
		idp := uuid.New()
		f.repo.mu.Lock()
		f.repo.tokenByID[f.token.ID].IdpSessionID = &idp
		f.repo.mu.Unlock()
		require.NoError(t, f.svc.EndHintedSession(ctx, idp, *f.token.UserID))
		assert.Equal(t, "logout", f.sessions.ended[row.ID])
		assert.True(t, f.repo.tokenByID[f.token.ID].IsRevoked, "token bound by the idp id is revoked")
	})
	t.Run("another user's rows and tokens are untouched", func(t *testing.T) {
		row := &models.Session{ID: uuid.New(), IsActive: true}
		f := newSessionBindingFixture(t, row)
		idp := uuid.New()
		f.repo.mu.Lock()
		f.repo.tokenByID[f.token.ID].IdpSessionID = &idp
		f.repo.mu.Unlock()
		require.NoError(t, f.svc.EndHintedSession(ctx, idp, uuid.New()))
		assert.Empty(t, f.sessions.ended)
		assert.False(t, f.repo.tokenByID[f.token.ID].IsRevoked)
	})
}
