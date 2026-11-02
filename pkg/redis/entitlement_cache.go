// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// EntitlementCacheTTL is the "fresh" cache TTL for the tenant entitlements
// envelope (the product roadmap §4.1: "60s last-known-good"). A fresh-cache
// hit is served directly; a miss falls through to Postgres, and a
// Postgres read failure falls through to the separate, much longer-lived
// last-known-good key (see EntitlementLKGTTL) before finally failing
// closed. Both TTLs live here, not in the caller, so the "60s / LKG" policy
// is defined in exactly one place.
const EntitlementCacheTTL = 60 * time.Second

// EntitlementLKGTTL is deliberately much longer than EntitlementCacheTTL:
// it exists purely to survive a sustained Postgres outage without failing
// every tenant closed the moment the 60s fresh cache expires. 24h bounds
// how long a tenant can keep running on a stale snapshot during an
// extended outage -- long enough to ride out routine maintenance windows,
// short enough that a genuinely abandoned/deleted tenant's stale
// entitlements don't linger indefinitely once nothing is refreshing them.
const EntitlementLKGTTL = 24 * time.Hour

// EntitlementCacheService caches the per-tenant entitlements envelope
// (modules + flags + trial_eligibility) that backs GET
// /api/v1/tenant/entitlements. It maintains TWO keys per tenant:
//
//   - a "fresh" key, TTL EntitlementCacheTTL (60s), which is the normal
//     read path;
//   - a "last-known-good" (LKG) key, TTL EntitlementLKGTTL, refreshed
//     every time the fresh key is refreshed, used ONLY when a live
//     Postgres read fails.
//
// Fail-closed contract (the product roadmap §4.1, §4.9): if neither the fresh
// key, nor Postgres, nor the LKG key can produce an envelope, the caller
// (services.TenantEntitlementService) MUST return an empty/no-access
// envelope. This cache never itself decides to fail closed -- it only
// reports "miss" (nil, nil) for both fresh and LKG lookups and lets the
// service layer make that call, keeping the fail-closed decision in one
// place.
type EntitlementCacheService struct {
	client *Client
	logger *zap.Logger
}

// NewEntitlementCacheService creates a new entitlement cache service.
func NewEntitlementCacheService(client *Client, logger *zap.Logger) *EntitlementCacheService {
	return &EntitlementCacheService{client: client, logger: logger}
}

func freshKey(tenantID string) string {
	return fmt.Sprintf("iam:entitlements:fresh:%s", tenantID)
}

func lkgKey(tenantID string) string {
	return fmt.Sprintf("iam:entitlements:lkg:%s", tenantID)
}

// GetFresh returns the cached envelope if present and unexpired. A miss
// (key absent or expired) returns (nil, nil) -- not an error; the caller
// falls through to Postgres.
func (s *EntitlementCacheService) GetFresh(ctx context.Context, tenantID string, out interface{}) (bool, error) {
	return s.get(ctx, freshKey(tenantID), out)
}

// GetLKG returns the last-known-good envelope if present and unexpired.
// A miss returns (false, nil) -- the caller must then fail closed.
func (s *EntitlementCacheService) GetLKG(ctx context.Context, tenantID string, out interface{}) (bool, error) {
	return s.get(ctx, lkgKey(tenantID), out)
}

func (s *EntitlementCacheService) get(ctx context.Context, key string, out interface{}) (bool, error) {
	val, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		s.logger.Warn("entitlement cache get failed", zap.String("key", key), zap.Error(err))
		return false, fmt.Errorf("EntitlementCacheService.get: %w", err)
	}
	if val == "" {
		return false, nil
	}
	if err := json.Unmarshal([]byte(val), out); err != nil {
		// A corrupt/unparseable cache entry must never propagate as a
		// fabricated result -- treat it as a miss so the caller falls
		// through to Postgres/LKG/fail-closed, and drop the record so it
		// stops poisoning subsequent reads.
		s.logger.Warn("entitlement cache entry unparseable, treating as miss", zap.String("key", key), zap.Error(err))
		_ = s.client.Del(ctx, key)
		return false, nil
	}
	return true, nil
}

// Set writes the envelope to BOTH the fresh key (60s TTL) and the LKG key
// (24h TTL) in one call. Every successful read from Postgres refreshes
// both, so LKG always reflects the last value we actually confirmed from
// the source of truth -- never a value that itself came from LKG.
func (s *EntitlementCacheService) Set(ctx context.Context, tenantID string, envelope interface{}) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("EntitlementCacheService.Set marshal: %w", err)
	}

	var errs []error
	if err := s.client.Set(ctx, freshKey(tenantID), string(body), EntitlementCacheTTL); err != nil {
		errs = append(errs, fmt.Errorf("fresh: %w", err))
	}
	if err := s.client.Set(ctx, lkgKey(tenantID), string(body), EntitlementLKGTTL); err != nil {
		errs = append(errs, fmt.Errorf("lkg: %w", err))
	}
	if len(errs) > 0 {
		s.logger.Warn("entitlement cache set partially failed", zap.String("tenant_id", tenantID), zap.Errors("errors", errs))
		return errors.Join(errs...)
	}
	return nil
}

// InvalidateFresh drops only the fresh key, e.g. immediately after a
// consumer/PUT upsert so the very next read is forced to Postgres rather
// than waiting out the remaining TTL. The LKG key is intentionally left
// untouched -- it must keep serving the previous (still-valid) snapshot if
// the immediately-following Postgres read happens to fail.
func (s *EntitlementCacheService) InvalidateFresh(ctx context.Context, tenantID string) error {
	if err := s.client.Del(ctx, freshKey(tenantID)); err != nil {
		return fmt.Errorf("EntitlementCacheService.InvalidateFresh: %w", err)
	}
	return nil
}
