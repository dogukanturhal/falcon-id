// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// SessionActivityRepository is the minimum surface needed to bump
// session.last_activity_at. Kept as an interface so tests can inject a stub
// without importing repositories (and to keep the middleware independent of
// the concrete repo type).
type SessionActivityRepository interface {
	UpdateLastActivity(ctx context.Context, id uuid.UUID) error
}

// SessionActivityTracker throttles + applies LastActivityAt updates so that
// every authenticated API request contributes to idle-timeout calculations
// without hammering the database.
//
// Tier-1 semantics:
//   - At most one DB write per session per `minInterval` (default 60s). The
//     gate uses Redis SET NX EX, so coordination holds across Falcon-ID
//     replicas — not just within one pod.
//   - Updates run in a detached goroutine with context.Background so they
//     outlive the originating request and never add tail latency.
//   - Redis unavailability is non-fatal. Without the gate we still fire
//     updates; the DB absorbs bursts because UPDATE last_activity_at on a
//     primary-keyed row is cheap (~2k/s/replica on typical pgx). OWASP
//     Session Management Cheat Sheet explicitly calls out server-side
//     activity enforcement as a correctness property.
type SessionActivityTracker struct {
	repo        SessionActivityRepository
	redis       *redispkg.Client
	minInterval time.Duration
}

// NewSessionActivityTracker wires the tracker. `minInterval` bounds the
// per-session write rate; pass 0 to use the tier-1 default (60s).
func NewSessionActivityTracker(repo SessionActivityRepository, rdb *redispkg.Client, minInterval time.Duration) *SessionActivityTracker {
	if minInterval <= 0 {
		minInterval = 60 * time.Second
	}
	return &SessionActivityTracker{repo: repo, redis: rdb, minInterval: minInterval}
}

// Touch records activity for the given session. Fire-and-forget: safe to
// call from the request hot path — the caller is not blocked on Redis or
// Postgres. Callers pass the bare session UUID; the sentinel value
// uuid.Nil is a no-op (unauthenticated paths should never reach here).
func (t *SessionActivityTracker) Touch(sessionID uuid.UUID) {
	if t == nil || t.repo == nil || sessionID == uuid.Nil {
		return
	}
	go t.touchAsync(sessionID)
}

func (t *SessionActivityTracker) touchAsync(sessionID uuid.UUID) {
	// context.Background intentionally — the middleware that launched us
	// has already finished responding. Using the request context would
	// cancel the DB write the instant the client disconnected.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if t.redis != nil {
		key := "session_activity_gate:" + sessionID.String()
		// SET key 1 NX EX <minInterval> — atomic claim of the write slot.
		// If the slot is already held, another replica (or the same
		// replica on a prior request within the window) did the write
		// and we skip. NX guarantees at-most-one winner per window.
		claimed, err := t.redis.SetNX(ctx, key, "1", t.minInterval)
		if err == nil && !claimed {
			return
		}
		// If Redis returned an error we fall through to the DB update —
		// better a small burst of writes than silent idle-timeout drift.
	}

	if err := t.repo.UpdateLastActivity(ctx, sessionID); err != nil {
		logger.Log.Warn("session activity update failed",
			zap.String("session_id", sessionID.String()),
			zap.Error(err))
	}
}
