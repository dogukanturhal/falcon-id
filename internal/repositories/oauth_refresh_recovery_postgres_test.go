//go:build integration

// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories_test

// Real-Postgres coverage for lost-response refresh recovery
// (migration 0031 replaced_by + OAuthClientRepository.LockRefreshRecovery).
// Self-skips without TEST_DATABASE_URL; run via
// hack/run-oauth-recovery-postgres-tests.sh.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

const recoveryTestIP = "203.0.113.7"

func ptrString(v string) *string { return &v }

func TestRefreshRecoveryPostgres_ConcurrentReplaysOneWinner(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL/DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := newReleasedSchemaPool(ctx, t, dsn)
	defer pool.Close()
	repo := repositories.NewOAuthClientRepository(pool)

	tenantID, clientID, userID := uuid.New(), uuid.New(), uuid.New()
	rootID, succID := uuid.New(), uuid.New()
	root := newToken(rootID, tenantID, clientID, userID, "refresh-root-"+uuid.NewString(), rootID)
	succ := newToken(succID, tenantID, clientID, userID, "refresh-succ-"+uuid.NewString(), rootID)
	succ.IPAddress = ptrString(recoveryTestIP)
	require.NoError(t, repo.CreateOAuthToken(ctx, root))
	won, err := repo.ConsumeRefreshToken(ctx, rootID)
	require.NoError(t, err)
	require.True(t, won)
	require.NoError(t, repo.CreateOAuthToken(ctx, succ))
	require.NoError(t, repo.SetTokenReplacedBy(ctx, rootID, succID))

	got, err := repo.GetOAuthTokenByHash(ctx, *root.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, got.ReplacedBy)
	require.Equal(t, succID, *got.ReplacedBy)
	unused, err := repo.RefreshSuccessorUnused(ctx, succID)
	require.NoError(t, err)
	require.True(t, unused)

	const n = 8
	var ok, raced, other int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := repo.BeginTx(ctx)
			if err != nil {
				atomic.AddInt32(&other, 1)
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			out, err := tx.LockRefreshRecovery(ctx, rootID, succID)
			if err != nil {
				atomic.AddInt32(&other, 1)
				return
			}
			switch out {
			case repositories.RefreshRecoveryOK:
				newID := uuid.New()
				if err := tx.CreateOAuthToken(ctx, newToken(newID, tenantID, clientID, userID, "refresh-new-"+uuid.NewString(), rootID)); err != nil {
					atomic.AddInt32(&other, 1)
					return
				}
				if err := tx.RepointTokenReplacedBy(ctx, rootID, succID, newID); err != nil {
					atomic.AddInt32(&other, 1)
					return
				}
				if err := tx.Commit(ctx); err != nil {
					atomic.AddInt32(&other, 1)
					return
				}
				atomic.AddInt32(&ok, 1)
			case repositories.RefreshRecoveryRaced:
				atomic.AddInt32(&raced, 1)
			default:
				atomic.AddInt32(&other, 1)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), ok, "exactly one concurrent replay may recover")
	require.Equal(t, int32(n-1), raced)
	require.Zero(t, other)

	unused, err = repo.RefreshSuccessorUnused(ctx, succID)
	require.NoError(t, err)
	require.False(t, unused, "the old successor must be revoked by the winner")

	// Lineage advanced: the old successor is gone, so a replay that still
	// observes it as the head is classified as raced, never OK.
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	out, err := tx.LockRefreshRecovery(ctx, rootID, succID)
	require.NoError(t, err)
	require.Equal(t, repositories.RefreshRecoveryRaced, out)
	require.NoError(t, tx.Rollback(ctx))

	// The winner bumped recovery_count and marked the old successor superseded;
	// the consumed root itself was revoked by a normal rotation.
	var count int16
	var reason, rootReason *string
	require.NoError(t, pool.QueryRow(ctx, `SELECT recovery_count FROM iam_oauth_tokens WHERE id = $1`, rootID).Scan(&count))
	require.Equal(t, int16(1), count)
	require.NoError(t, pool.QueryRow(ctx, `SELECT revoke_reason FROM iam_oauth_tokens WHERE id = $1`, succID).Scan(&reason))
	require.NotNil(t, reason)
	require.Equal(t, repositories.RevokeReasonRecoverySuperseded, *reason)
	require.NoError(t, pool.QueryRow(ctx, `SELECT revoke_reason FROM iam_oauth_tokens WHERE id = $1`, rootID).Scan(&rootReason))
	require.NotNil(t, rootReason)
	require.Equal(t, repositories.RevokeReasonRotated, *rootReason)

	// Recovery is one-shot: a second replay (pointer now at the recovered
	// pair, observed correctly) is ineligible.
	var head uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, `SELECT replaced_by FROM iam_oauth_tokens WHERE id = $1`, rootID).Scan(&head))
	tx2, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	out, err = tx2.LockRefreshRecovery(ctx, rootID, head)
	require.NoError(t, err)
	require.Equal(t, repositories.RefreshRecoveryIneligible, out)
	require.NoError(t, tx2.Rollback(ctx))

	// replaced_by is write-once on the normal path.
	require.NoError(t, repo.SetTokenReplacedBy(ctx, rootID, uuid.New()))
	var still uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, `SELECT replaced_by FROM iam_oauth_tokens WHERE id = $1`, rootID).Scan(&still))
	require.Equal(t, head, still)
}

// rotatedPair seeds a consumed root and its unused successor (stamped with
// recoveryTestIP) and returns their ids.
func rotatedPair(ctx context.Context, t *testing.T, repo *repositories.OAuthClientRepository) (rootID, succID uuid.UUID) {
	t.Helper()
	tenantID, clientID, userID := uuid.New(), uuid.New(), uuid.New()
	rootID, succID = uuid.New(), uuid.New()
	require.NoError(t, repo.CreateOAuthToken(ctx, newToken(rootID, tenantID, clientID, userID, "r-"+uuid.NewString(), rootID)))
	succ := newToken(succID, tenantID, clientID, userID, "s-"+uuid.NewString(), rootID)
	succ.IPAddress = ptrString(recoveryTestIP)
	require.NoError(t, repo.CreateOAuthToken(ctx, succ))
	_, err := repo.ConsumeRefreshToken(ctx, rootID)
	require.NoError(t, err)
	require.NoError(t, repo.SetTokenReplacedBy(ctx, rootID, succID))
	return rootID, succID
}

func lockOutcome(ctx context.Context, t *testing.T, repo *repositories.OAuthClientRepository, rootID, succID uuid.UUID) repositories.RefreshRecoveryOutcome {
	t.Helper()
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	out, err := tx.LockRefreshRecovery(ctx, rootID, succID)
	require.NoError(t, err)
	return out
}

func TestRefreshRecoveryPostgres_WindowGate(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL/DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := newReleasedSchemaPool(ctx, t, dsn)
	defer pool.Close()
	repo := repositories.NewOAuthClientRepository(pool)

	rootID, succID := rotatedPair(ctx, t, repo)
	// Replay older than the recovery window -> Ineligible.
	_, err := pool.Exec(ctx, `UPDATE iam_oauth_tokens SET revoked_at = now() - interval '6 minutes' WHERE id = $1`, rootID)
	require.NoError(t, err)
	require.Equal(t, repositories.RefreshRecoveryIneligible, lockOutcome(ctx, t, repo, rootID, succID))

	// Same row inside the window with the matching IP -> OK.
	_, err = pool.Exec(ctx, `UPDATE iam_oauth_tokens SET revoked_at = now() - interval '1 minute' WHERE id = $1`, rootID)
	require.NoError(t, err)
	require.Equal(t, repositories.RefreshRecoveryOK, lockOutcome(ctx, t, repo, rootID, succID))
}

func TestRefreshRecoveryPostgres_UsedSuccessorIsLineageAdvanced(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL/DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := newReleasedSchemaPool(ctx, t, dsn)
	defer pool.Close()
	repo := repositories.NewOAuthClientRepository(pool)

	tenantID, clientID, userID := uuid.New(), uuid.New(), uuid.New()
	rootID, succID := uuid.New(), uuid.New()
	require.NoError(t, repo.CreateOAuthToken(ctx, newToken(rootID, tenantID, clientID, userID, "r-"+uuid.NewString(), rootID)))
	succTok := newToken(succID, tenantID, clientID, userID, "s-"+uuid.NewString(), rootID)
	succTok.IPAddress = ptrString(recoveryTestIP)
	require.NoError(t, repo.CreateOAuthToken(ctx, succTok))
	_, err := repo.ConsumeRefreshToken(ctx, rootID)
	require.NoError(t, err)
	require.NoError(t, repo.SetTokenReplacedBy(ctx, rootID, succID))
	_, err = repo.ConsumeRefreshToken(ctx, succID) // successor used (rotated)
	require.NoError(t, err)

	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	out, err := tx.LockRefreshRecovery(ctx, rootID, succID)
	require.NoError(t, err)
	require.Equal(t, repositories.RefreshRecoveryLineageAdvanced, out)
}
