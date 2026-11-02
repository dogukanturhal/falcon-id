// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconsole

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/operatorauth"
)

// liveTTL bounds how long a revocation can lag: the operator assertion is a
// 5-minute bearer, so every operator-chain request re-checks the operator
// against live state (cached this long per user).
const liveTTL = 15 * time.Second

type liveState struct {
	ok      bool
	roles   map[string]bool
	fetched time.Time
}

// liveness caches the live standing of operators.
type liveness struct {
	mu sync.Mutex
	m  map[uuid.UUID]liveState
}

func (l *liveness) get(id uuid.UUID) (liveState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.m[id]
	if !ok || time.Since(s.fetched) > liveTTL {
		return liveState{}, false
	}
	return s, true
}

func (l *liveness) put(id uuid.UUID, s liveState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[uuid.UUID]liveState{}
	}
	s.fetched = time.Now()
	l.m[id] = s
}

// forget drops the cached state of a user (offboarding / role revoke), so the
// next request sees the revocation at once on this replica.
func (l *liveness) forget(id uuid.UUID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, id)
}

// liveCheck rejects an assertion whose operator has been revoked since it was
// minted: the account must still be active and unlocked, and every platform
// role claimed in the assertion must still be in force (an elevation revoked
// or expired, or a standing role removed, fails immediately instead of
// surviving until the 5-minute assertion expires). Fails closed when the
// state cannot be read. Mounted right after operatorauth.RequireOperator.
func (cs *Console) liveCheck(c *gin.Context) {
	a := operatorauth.ActorFrom(c)
	if a == nil {
		fail(c, http.StatusUnauthorized, "actor_assertion_required")
		return
	}
	st, ok := cs.live.get(a.UserID)
	if !ok {
		var err error
		load := cs.LiveState
		if load == nil {
			load = cs.loadLive
		}
		st, err = load(c.Request.Context(), a)
		if err != nil {
			cs.Log.Error("operator liveness check failed", zap.String("actor", a.UserID.String()), zap.Error(err))
			fail(c, http.StatusServiceUnavailable, "operator_state_unavailable")
			return
		}
		cs.live.put(a.UserID, st)
	}
	if !st.ok {
		fail(c, http.StatusUnauthorized, "actor_assertion_revoked")
		return
	}
	for _, r := range a.PlatformRoles {
		if !st.roles[r] {
			fail(c, http.StatusUnauthorized, "actor_assertion_revoked")
			return
		}
	}
	c.Next()
}

func (cs *Console) loadLive(ctx context.Context, a *operatorauth.Actor) (liveState, error) {
	u, err := cs.Users.GetByID(ctx, a.UserID)
	if err != nil {
		return liveState{}, err
	}
	if u == nil || !u.IsActive || u.IsLocked {
		return liveState{ok: false}, nil
	}
	roles, err := cs.Authority.ActiveRolesFor(ctx, a.UserID, u.Email)
	if err != nil {
		return liveState{}, err
	}
	set := make(map[string]bool, len(roles))
	for _, r := range roles {
		set[r] = true
	}
	return liveState{ok: len(set) > 0, roles: set}, nil
}
