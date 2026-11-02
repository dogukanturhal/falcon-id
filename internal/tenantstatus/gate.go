// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantstatus

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DefaultGateTTL bounds how long a pod may serve a stale answer after a
// suspension / resume was applied on ANOTHER pod. The pod that applies an
// event invalidates its own entry immediately.
const DefaultGateTTL = 10 * time.Second

type reader interface {
	IsSuspended(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

type gateEntry struct {
	suspended bool
	expires   time.Time
}

// Gate answers "is this tenant suspended?" from a short-TTL in-process cache
// in front of iam_tenant_status. It fails OPEN: unknown tenants and read
// errors with no cached value are reported as not suspended; on a read error
// the last known value (even if expired) is preferred over "not suspended".
// Protected tenants are always reported as not suspended.
type Gate struct {
	repo reader
	ttl  time.Duration
	log  *zap.Logger
	now  func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]gateEntry
}

// NewGate builds a Gate. ttl <= 0 uses DefaultGateTTL; log may be nil.
func NewGate(repo reader, ttl time.Duration, log *zap.Logger) *Gate {
	if ttl <= 0 {
		ttl = DefaultGateTTL
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Gate{repo: repo, ttl: ttl, log: log, now: time.Now, cache: make(map[uuid.UUID]gateEntry)}
}

// IsSuspended reports whether tenantID is currently suspended.
func (g *Gate) IsSuspended(ctx context.Context, tenantID uuid.UUID) bool {
	if g == nil || tenantID == uuid.Nil || IsProtected(tenantID) {
		return false
	}
	now := g.now()
	g.mu.Lock()
	e, ok := g.cache[tenantID]
	g.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.suspended
	}

	suspended, err := g.repo.IsSuspended(ctx, tenantID)
	if err != nil {
		g.log.Warn("tenantstatus gate: read failed, failing open", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		if ok {
			return e.suspended
		}
		return false
	}
	g.mu.Lock()
	g.cache[tenantID] = gateEntry{suspended: suspended, expires: now.Add(g.ttl)}
	g.mu.Unlock()
	return suspended
}

// Invalidate drops the cached answer for tenantID (called after an event is applied).
func (g *Gate) Invalidate(tenantID uuid.UUID) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.cache, tenantID)
	g.mu.Unlock()
}
