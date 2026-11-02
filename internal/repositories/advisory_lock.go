// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	advisoryLockMinBackoff = 200 * time.Millisecond
	advisoryLockMaxBackoff = time.Second
)

// AdvisoryLocker serializes work across replicas with a Postgres session
// advisory lock keyed by a string. While waiting, no pooled connection is
// held; the connection is held only for as long as the lock is.
type AdvisoryLocker struct {
	pool *pgxpool.Pool
}

// NewAdvisoryLocker creates an AdvisoryLocker.
func NewAdvisoryLocker(pool *pgxpool.Pool) *AdvisoryLocker {
	return &AdvisoryLocker{pool: pool}
}

// WithLock polls pg_try_advisory_lock until the lock for key is held (or ctx
// is done, returning ctx.Err()), runs fn, then releases the lock. fn must not
// use the locker's connection.
func (l *AdvisoryLocker) WithLock(ctx context.Context, key string, fn func(context.Context) error) error {
	backoff := advisoryLockMinBackoff
	for {
		conn, err := l.pool.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("AdvisoryLocker: acquire connection: %w", err)
		}

		var acquired bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1, 0))", key).Scan(&acquired); err != nil {
			conn.Release()
			return fmt.Errorf("AdvisoryLocker: lock %q: %w", key, err)
		}
		if acquired {
			return l.runLocked(ctx, conn, key, fn)
		}

		conn.Release()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > advisoryLockMaxBackoff {
			backoff = advisoryLockMaxBackoff
		}
	}
}

// runLocked runs fn while holding the lock on conn, then unlocks and releases
// conn. If the unlock fails or reports it did not hold the lock, the session
// is closed so Postgres drops the lock rather than leaking it into the pool.
func (l *AdvisoryLocker) runLocked(ctx context.Context, conn *pgxpool.Conn, key string, fn func(context.Context) error) error {
	defer conn.Release()
	defer func() {
		// Fresh context: ctx may already be cancelled.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		err := conn.QueryRow(unlockCtx, "SELECT pg_advisory_unlock(hashtextextended($1, 0))", key).Scan(&unlocked)
		if err != nil || !unlocked {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	return fn(ctx)
}
