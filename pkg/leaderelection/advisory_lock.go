// SPDX-License-Identifier: AGPL-3.0-or-later

package leaderelection

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AdvisoryLockElector uses PostgreSQL session-level advisory locks for leader
// election. It matches the existing behaviour in the provisioning orchestrator
// (pg_try_advisory_lock / pg_advisory_unlock) and the schema migrator
// (pg_advisory_lock / pg_advisory_unlock).
//
// The advisory lock is session-scoped in PostgreSQL: it is released
// automatically when the connection is closed, which provides a safety net
// against leader crashes. Each call to TryAcquire acquires and immediately
// releases the connection; the lock is associated with the underlying
// PostgreSQL backend process, not the pgxpool connection object.
//
// Callers that need the lock to persist across multiple operations should
// either manage the connection lifetime themselves or use RunAsLeader, which
// acquires and releases within a single logical unit of work.
type AdvisoryLockElector struct {
	pool     *pgxpool.Pool
	lockID   int64
	isLeader atomic.Bool
}

// Ensure AdvisoryLockElector satisfies the LeaderElector interface at compile time.
var _ LeaderElector = (*AdvisoryLockElector)(nil)

// NewAdvisoryLockElector creates an AdvisoryLockElector using the given pool
// and PostgreSQL advisory lock ID.
//
// The lockID must be stable and unique across all leader election uses within
// the same PostgreSQL database. The existing constants in falcon-id are:
//
//	857491001  provisioning orchestrator reconciler
//	857491002  schema migrator
func NewAdvisoryLockElector(pool *pgxpool.Pool, lockID int64) *AdvisoryLockElector {
	return &AdvisoryLockElector{
		pool:   pool,
		lockID: lockID,
	}
}

// TryAcquire attempts a non-blocking acquisition of the advisory lock using
// pg_try_advisory_lock. The connection is returned to the pool immediately
// after the attempt; the lock itself is held by the PostgreSQL session
// backing that connection until explicitly released or the session ends.
//
// Returns (true, nil)  — leadership acquired.
// Returns (false, nil) — another session holds the lock.
// Returns (false, err) — connection or query failure.
func (a *AdvisoryLockElector) TryAcquire(ctx context.Context) (bool, error) {
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("leaderelection: acquire connection: %w", err)
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", a.lockID).Scan(&acquired); err != nil {
		return false, fmt.Errorf("leaderelection: pg_try_advisory_lock(%d): %w", a.lockID, err)
	}

	a.isLeader.Store(acquired)
	return acquired, nil
}

// Release unlocks the advisory lock via pg_advisory_unlock. It is a no-op
// when this instance does not currently hold leadership.
func (a *AdvisoryLockElector) Release(ctx context.Context) error {
	if !a.isLeader.Load() {
		return nil
	}

	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("leaderelection: acquire connection for release: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", a.lockID); err != nil {
		return fmt.Errorf("leaderelection: pg_advisory_unlock(%d): %w", a.lockID, err)
	}

	a.isLeader.Store(false)
	return nil
}

// IsLeader reports whether this instance currently holds the advisory lock.
// The result reflects the outcome of the most recent TryAcquire or Release
// call; no database round-trip is performed.
func (a *AdvisoryLockElector) IsLeader() bool {
	return a.isLeader.Load()
}

// RunAsLeader attempts to acquire leadership and, if successful, calls fn with
// the provided context. Leadership is released via defer after fn returns.
//
// If leadership cannot be acquired, fn is not invoked and nil is returned.
// This mirrors the guard pattern used in reconcileAll() of the provisioning
// orchestrator.
func (a *AdvisoryLockElector) RunAsLeader(ctx context.Context, fn func(ctx context.Context)) error {
	acquired, err := a.TryAcquire(ctx)
	if err != nil {
		return err
	}
	if !acquired {
		return nil // another instance is the leader; skip silently
	}
	defer a.Release(ctx) //nolint:errcheck // best-effort release on return

	fn(ctx)
	return nil
}
