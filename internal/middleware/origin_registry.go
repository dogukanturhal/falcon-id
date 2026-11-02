// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TenantOriginLister returns the set of fully-qualified origins
// (scheme://host, no trailing slash, no port) that CORS/CSRF should trust
// on top of the static allowlist, sourced from tenant-management's tenant
// registry (ADR-0029 source of truth).
//
// Implementations MUST apply their own "active"/trust filtering before
// returning a host — this interface has no way to express "returned but
// unverified", so a host reaching AllowedOrigins/Contains is treated as
// fully trusted. See cmd/tenant_management_origin_lister.go for the
// concrete contract this is built against (tenant-management's IsActive
// flag) and why that is the trust boundary Stage 3 uses, given the
// app-host endpoint (platform-core !80) has no separate
// DNS/ownership-verification signal of its own.
type TenantOriginLister interface {
	ListActiveOrigins(ctx context.Context) ([]string, error)
}

// DynamicOriginRegistry caches a tenant-derived origin set refreshed on a
// bounded TTL in the background, so CORS preflight and CSRF origin checks
// stay a single in-memory map lookup — never a per-request call out to
// tenant-management.
//
// SECURITY / fail-closed contract: this type can only ever narrow toward
// "contributes nothing, static allowlist decides alone":
//   - Before the first successful Refresh, Contains reports false for
//     every origin.
//   - A failed Refresh (timeout, 403 pending scope grant, endpoint not yet
//     deployed, network error) leaves the LAST successfully cached set in
//     place — it never falls back to "allow everything", and it never
//     clears a previously good set just because one refresh failed.
//   - A nil *DynamicOriginRegistry (no lister configured) is safe to call
//     Contains/Refresh/StartBackgroundRefresh on and always behaves as
//     "contributes nothing".
//
// Callers (CORS's isOriginAllowed, CSRF's validateOrigin) MUST combine
// Contains with their own static allowlist; this registry is additive
// only and is never the sole source of truth.
type DynamicOriginRegistry struct {
	lister  TenantOriginLister
	ttl     time.Duration
	timeout time.Duration
	logger  *zap.Logger

	mu      sync.RWMutex
	origins map[string]bool
	lastOK  time.Time
	lastErr error
}

// NewDynamicOriginRegistry builds a registry backed by lister. ttl controls
// the background refresh cadence; timeout bounds each individual refresh
// call so a slow/hung tenant-management never blocks longer than timeout.
// A nil lister is accepted: the returned registry is a permanent no-op
// (Contains always false), matching the "endpoint not deployed yet"
// posture the rest of Stage 2/3 already uses.
func NewDynamicOriginRegistry(lister TenantOriginLister, ttl, timeout time.Duration, logger *zap.Logger) *DynamicOriginRegistry {
	if logger == nil {
		logger = zap.NewNop()
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &DynamicOriginRegistry{
		lister:  lister,
		ttl:     ttl,
		timeout: timeout,
		logger:  logger,
		origins: map[string]bool{},
	}
}

// Refresh performs one synchronous lookup and, only on success, replaces
// the cached set. It never loops or sleeps — StartBackgroundRefresh (or an
// explicit boot-time call) owns cadence.
func (r *DynamicOriginRegistry) Refresh(ctx context.Context) error {
	if r == nil || r.lister == nil {
		return nil // no lister configured: dynamic contribution stays empty, by design
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	origins, err := r.lister.ListActiveOrigins(timeoutCtx)
	if err != nil {
		r.mu.Lock()
		r.lastErr = err
		r.mu.Unlock()
		return err
	}

	next := make(map[string]bool, len(origins))
	for _, o := range origins {
		if o == "" {
			continue
		}
		next[strings.ToLower(o)] = true
	}

	r.mu.Lock()
	r.origins = next
	r.lastOK = time.Now()
	r.lastErr = nil
	r.mu.Unlock()
	return nil
}

// Contains reports whether origin is in the last successfully cached
// dynamic set. It never triggers a lookup itself. A nil receiver reports
// false — safe to call unconditionally from CORS/CSRF even when no
// registry was wired at boot.
func (r *DynamicOriginRegistry) Contains(origin string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.origins[strings.ToLower(origin)]
}

// LastRefreshError returns the error from the most recent failed Refresh,
// or nil if the last attempt succeeded (or none has run yet). Intended for
// health/readiness reporting only — never consulted on the request path.
func (r *DynamicOriginRegistry) LastRefreshError() error {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastErr
}

// LastRefreshSucceededAt returns the time of the last successful Refresh,
// or the zero time if none has ever succeeded.
func (r *DynamicOriginRegistry) LastRefreshSucceededAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastOK
}

// StartBackgroundRefresh performs one immediate best-effort Refresh, then
// refreshes again every ttl until ctx is cancelled. A failed refresh is
// logged and leaves the previously cached set (or the empty set, if none
// has ever succeeded) in place — see the fail-closed contract on
// DynamicOriginRegistry above. Safe to call on a nil registry or one built
// with a nil lister (no-op, no goroutine started).
func (r *DynamicOriginRegistry) StartBackgroundRefresh(ctx context.Context) {
	if r == nil || r.lister == nil {
		return
	}
	if err := r.Refresh(ctx); err != nil {
		r.logger.Warn("dynamic origin registry: initial refresh failed; CORS/CSRF will use the static allowlist only until a refresh succeeds",
			zap.Error(err))
	}
	go func() {
		ticker := time.NewTicker(r.ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.Refresh(ctx); err != nil {
					r.logger.Warn("dynamic origin registry: background refresh failed; keeping last known-good set",
						zap.Error(err))
				}
			}
		}
	}()
}
