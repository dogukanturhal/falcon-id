// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// lineageTestRepo is an in-memory iam_oauth_tokens with the lineage
// (replaced_by) semantics of OAuthClientRepository. BeginTx holds txMu until
// Commit/Rollback, standing in for the row lock LockRefreshRecovery takes.
type lineageTestRepo struct {
	noopOAuthClientRepo

	mu       sync.Mutex
	txMu     sync.Mutex
	byID     map[uuid.UUID]*models.OAuthToken
	families []uuid.UUID
	// precheckErr, when set, makes the lock-free pre-check fail (transient DB error).
	precheckErr error
	// afterGet, when set, runs once right after a GetOAuthTokenByHash for hash
	// returned (locks released), so a test can interleave a concurrent request
	// between the service's read and its later checks.
	afterGet     func()
	afterGetHash string
	// txOpen is true between BeginTx and Commit/Rollback; t fails the test if a
	// family revoke (other connection) runs while the tx still holds row locks.
	txOpen bool
	t      *testing.T
}

func newLineageTestRepo() *lineageTestRepo {
	return &lineageTestRepo{byID: map[uuid.UUID]*models.OAuthToken{}}
}

func (r *lineageTestRepo) add(tok *models.OAuthToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *tok
	r.byID[tok.ID] = &cp
}

func (r *lineageTestRepo) row(id uuid.UUID) models.OAuthToken {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.byID[id]
}

// Non-transactional reads wait for an open tx so they never observe a half-
// applied recovery (Postgres hides uncommitted writes the same way).
func (r *lineageTestRepo) GetOAuthTokenByHash(_ context.Context, h string) (*models.OAuthToken, error) {
	r.txMu.Lock()
	defer r.txMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.byID {
		if t.Token == h || (t.RefreshToken != nil && *t.RefreshToken == h) {
			cp := *t
			if hook := r.afterGet; hook != nil && r.afterGetHash == h {
				r.afterGet = nil
				r.mu.Unlock()
				r.txMu.Unlock()
				hook()
				r.txMu.Lock()
				r.mu.Lock()
			}
			return &cp, nil
		}
	}
	return nil, assertFail("token not found")
}

func (r *lineageTestRepo) CreateOAuthToken(_ context.Context, tok *models.OAuthToken) error {
	r.add(tok)
	return nil
}

func (r *lineageTestRepo) ConsumeRefreshToken(_ context.Context, id uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.byID[id]
	if t == nil || t.IsRevoked {
		return false, nil
	}
	now := time.Now()
	t.IsRevoked, t.RevokedAt = true, &now
	rsn := repositories.RevokeReasonRotated
	t.RevokeReason = &rsn
	return true, nil
}

func (r *lineageTestRepo) RevokeRefreshTokenFamily(_ context.Context, fam uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.txOpen && r.t != nil {
		r.t.Errorf("RevokeRefreshTokenFamily ran while the recovery tx still held row locks (would deadlock on Postgres)")
	}
	r.families = append(r.families, fam)
	var n int64
	for _, t := range r.byID {
		if t.TokenFamilyID != nil && *t.TokenFamilyID == fam && !t.IsRevoked {
			t.IsRevoked = true
			n++
		}
	}
	return n, nil
}

func (r *lineageTestRepo) SetTokenReplacedBy(_ context.Context, id, succ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID[id].ReplacedBy != nil {
		return nil // mirrors AND replaced_by IS NULL
	}
	r.byID[id].ReplacedBy = &succ
	return nil
}

func (r *lineageTestRepo) RefreshSuccessorUnused(_ context.Context, id uuid.UUID) (bool, error) {
	if r.precheckErr != nil {
		return false, r.precheckErr
	}
	r.txMu.Lock()
	defer r.txMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.byID[id]
	return t != nil && !t.IsRevoked && t.ReplacedBy == nil, nil
}

func (r *lineageTestRepo) BeginTx(_ context.Context) (repositories.OAuthClientTx, error) {
	r.txMu.Lock()
	r.mu.Lock()
	r.txOpen = true
	r.mu.Unlock()
	return &lineageTestTx{r: r}, nil
}

type lineageTestTx struct {
	r    *lineageTestRepo
	done bool
}

func (t *lineageTestTx) MarkAuthorizationCodeUsedCAS(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func (t *lineageTestTx) CreateOAuthToken(ctx context.Context, tok *models.OAuthToken) error {
	return t.r.CreateOAuthToken(ctx, tok)
}

func (t *lineageTestTx) SetTokenReplacedBy(ctx context.Context, id, succ uuid.UUID) error {
	return t.r.SetTokenReplacedBy(ctx, id, succ)
}

func (t *lineageTestTx) RepointTokenReplacedBy(_ context.Context, id, from, to uuid.UUID) error {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if cur := t.r.byID[id].ReplacedBy; cur == nil || *cur != from {
		return assertFail("lineage pointer moved")
	}
	t.r.byID[id].ReplacedBy = &to
	return nil
}

func (t *lineageTestTx) LockRefreshRecovery(_ context.Context, id, observed uuid.UUID) (repositories.RefreshRecoveryOutcome, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if cur := t.r.byID[id].ReplacedBy; cur == nil || *cur != observed {
		return repositories.RefreshRecoveryRaced, nil
	}
	root := t.r.byID[id]
	if root.RecoveryCount >= 1 || root.RevokedAt == nil || time.Since(*root.RevokedAt) > repositories.RefreshRecoveryWindow {
		return repositories.RefreshRecoveryIneligible, nil
	}
	succ := t.r.byID[observed]
	if succ == nil || succ.IsRevoked || succ.ReplacedBy != nil {
		return repositories.RefreshRecoveryLineageAdvanced, nil
	}
	succ.IsRevoked = true
	rsn := repositories.RevokeReasonRecoverySuperseded
	succ.RevokeReason = &rsn
	root.RecoveryCount++
	return repositories.RefreshRecoveryOK, nil
}

func (t *lineageTestTx) end() {
	if !t.done {
		t.done = true
		t.r.mu.Lock()
		t.r.txOpen = false
		t.r.mu.Unlock()
		t.r.txMu.Unlock()
	}
}
func (t *lineageTestTx) Commit(context.Context) error   { t.end(); return nil }
func (t *lineageTestTx) Rollback(context.Context) error { t.end(); return nil }

func newLineageFixture(t *testing.T, client *models.OAuthClient) (*OAuthProviderService, *lineageTestRepo, string, uuid.UUID) {
	t.Helper()
	repo := newLineageTestRepo()
	repo.t = t
	svc, err := NewOAuthProviderService(repo, &noopUserRepo{}, &config.Config{
		JWTSecret: "test-secret-for-refresh-recovery-tests", ServicePort: "8080",
	})
	require.NoError(t, err)
	plain := "original-refresh-token-" + uuid.NewString()
	hash := svc.hashSecret(plain)
	id := uuid.New()
	repo.add(&models.OAuthToken{
		ID: id, TenantID: client.TenantID, ClientID: client.ID, TokenType: "access_token",
		Token: "access-hash-" + id.String(), Scopes: []string{"openid"}, RefreshToken: &hash,
		TokenFamilyID: &id, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	return svc, repo, plain, id
}

// testReplayIP is the client IP every request in these tests comes from; the
// rotated successor is stamped with it, so recovery's IP check passes.
const testReplayIP = "203.0.113.7"

// ageRevocation moves the consumed token's revoked_at out of the grace window
// but well inside the recovery window.
func ageRevocation(repo *lineageTestRepo, id uuid.UUID) { ageRevocationBy(repo, id, 30*time.Second) }

// ageRevocationBy sets the consumed token's revoked_at to d ago.
func ageRevocationBy(repo *lineageTestRepo, id uuid.UUID, d time.Duration) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	old := time.Now().Add(-d)
	repo.byID[id].RevokedAt = &old
}

func liveCount(repo *lineageTestRepo, fam uuid.UUID) int {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	n := 0
	for _, t := range repo.byID {
		if t.TokenFamilyID != nil && *t.TokenFamilyID == fam && !t.IsRevoked {
			n++
		}
	}
	return n
}

func TestRefreshRecovery_LostResponse_RecoversOnce(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	first, err := svc.RefreshTokens(ctx, client, plain, "") // response "lost"
	require.NoError(t, err)
	n1 := repo.row(id).ReplacedBy
	require.NotNil(t, n1, "rotation must record replaced_by")
	ageRevocation(repo, id)

	second, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err, "replay of a consumed token whose successor is unused must recover")
	assert.NotEqual(t, first.RefreshToken, second.RefreshToken)
	assert.Empty(t, repo.families, "recovery must not revoke the family")
	assert.True(t, repo.row(*n1).IsRevoked, "unused successor must be revoked")
	n2 := repo.row(id).ReplacedBy
	require.NotNil(t, n2)
	assert.NotEqual(t, *n1, *n2, "replaced_by must point at the recovered pair")
	assert.Equal(t, 1, liveCount(repo, id))

	// The recovered refresh token works.
	_, err = svc.RefreshTokens(ctx, client, second.RefreshToken, "")
	require.NoError(t, err)
}

func TestRefreshRecovery_InsideGraceWindow_StillAlreadyConsumed(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, _ := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	_, err = svc.RefreshTokens(ctx, client, plain, "") // immediately: inside the 10s grace window
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh_race")
	assert.Empty(t, repo.families, "a grace-window replay is a benign race, not theft")
}

func TestRefreshRecovery_SecondReplayAfterRecoveredSuccessorUsed_RevokesFamily(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	recovered, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	_, err = svc.RefreshTokens(ctx, client, recovered.RefreshToken, "") // successor used
	require.NoError(t, err)

	ageRevocation(repo, id)
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families, "lineage advanced: family must be revoked")
	assert.Equal(t, 0, liveCount(repo, id))
}

func TestRefreshRecovery_SuccessorUsedBeforeReplay_RevokesFamily(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	first, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	_, err = svc.RefreshTokens(ctx, client, first.RefreshToken, "")
	require.NoError(t, err)

	ageRevocation(repo, id)
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
}

func TestRefreshRecovery_PublicClient_NoRecovery(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	client.IsPublic, client.IsConfidential = true, false
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
}

func TestRefreshRecovery_OtherClient_NoRecovery(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	rows := len(repo.byID)

	other := activeConfidentialBFFClient("rotate") // a different (authenticated) client
	_, err = svc.RefreshTokens(ctx, other, plain, "")
	require.Error(t, err)
	assert.Len(t, repo.byID, rows, "no pair may be minted for a client that does not own the token")
}

// Concurrent replays are covered deterministically by
// TestRefreshRecovery_PointerMoved_RacedAndWinnerPairValid: a replay that
// arrives after the winner committed sees recovery_count=1 and is (correctly)
// indistinguishable from a sequential second replay, so a free-running
// goroutine race cannot assert a fixed outcome.

func TestRefreshRecovery_TransientPrecheckError_LeavesFamilyIntact(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	repo.precheckErr = assertFail("connection reset")
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_error")
	assert.Empty(t, repo.families, "a transient store error must not revoke the family")
	assert.Equal(t, 1, liveCount(repo, id), "successor stays live")
}

func TestRefreshRecovery_PointerMoved_RacedAndWinnerPairValid(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)

	// Replay A reads R0 (pointer -> R1); before its pre-check runs, replay B
	// recovers and moves the pointer to R2, revoking R1.
	var winner *models.OAuthTokenResponse
	repo.afterGetHash = svc.hashSecret(plain)
	repo.afterGet = func() {
		var werr error
		winner, werr = svc.RefreshTokens(ctx, client, plain, "")
		require.NoError(t, werr)
	}
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh_race")
	assert.Empty(t, repo.families, "a lost recovery race is not theft")
	require.NotNil(t, winner)
	_, err = svc.RefreshTokens(ctx, client, winner.RefreshToken, "")
	require.NoError(t, err, "the winner's pair must stay valid")
}

func TestRefreshRecovery_SecondReplayAfterRecovery_RevokesFamily(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	_, err = svc.RefreshTokens(ctx, client, plain, "") // the one allowed recovery
	require.NoError(t, err)
	_, err = svc.RefreshTokens(ctx, client, plain, "") // R2 still unused, but recovery is one-shot
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
}

func TestRefreshRecovery_ReplayOlderThanWindow_RevokesFamily(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocationBy(repo, id, repositories.RefreshRecoveryWindow+time.Minute)
	rows := len(repo.byID)
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
	assert.Len(t, repo.byID, rows, "no pair may be minted")
}

// The recovery is not IP-bound (the BFF forwards no browser IP, so the check
// would block nobody); a replay from another IP still recovers.
func TestRefreshRecovery_DifferentIP_StillRecovers(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)

	_, err := svc.RefreshTokens(WithRequestIP(context.Background(), testReplayIP), client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	resp, err := svc.RefreshTokens(WithRequestIP(context.Background(), "198.51.100.9"), client, plain, "")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Empty(t, repo.families)
}

func TestRefreshRecovery_SupersededSuccessorInsideGrace_RevokesFamily(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	r1, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	_, err = svc.RefreshTokens(ctx, client, plain, "") // recovery supersedes R1 just now
	require.NoError(t, err)

	// R1 was revoked milliseconds ago (inside the grace window) but by a
	// recovery: presenting it is theft, never a benign double-submit.
	_, err = svc.RefreshTokens(ctx, client, r1.RefreshToken, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
}

func TestRefreshRecovery_SupersededSuccessorLosesCAS_RevokesFamily(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	r1, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)

	// R1 is read live; a recovery of R0 supersedes it before R1's consume CAS.
	repo.afterGetHash = svc.hashSecret(r1.RefreshToken)
	repo.afterGet = func() {
		_, rerr := svc.RefreshTokens(ctx, client, plain, "")
		require.NoError(t, rerr)
	}
	_, err = svc.RefreshTokens(ctx, client, r1.RefreshToken, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
}

// The pre-check passes on a stale read, then the authoritative lock finds the
// token outside the window: theft handling must run AFTER the recovery tx's
// row locks are released (the fake fails the test otherwise).
func TestRefreshRecovery_IneligibleUnderLock_ReleasesTxBeforeFamilyRevoke(t *testing.T) {
	client := activeConfidentialBFFClient("rotate")
	svc, repo, plain, id := newLineageFixture(t, client)
	ctx := WithRequestIP(context.Background(), testReplayIP)

	_, err := svc.RefreshTokens(ctx, client, plain, "")
	require.NoError(t, err)
	ageRevocation(repo, id)
	repo.afterGetHash = svc.hashSecret(plain)
	repo.afterGet = func() { ageRevocationBy(repo, id, repositories.RefreshRecoveryWindow+time.Minute) }
	_, err = svc.RefreshTokens(ctx, client, plain, "")
	require.Error(t, err)
	assert.Equal(t, []uuid.UUID{id}, repo.families)
}
