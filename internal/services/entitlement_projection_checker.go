// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// projectionMemoTTL keeps one tenant's entitlement envelope for the duration
// of a role-picker call (getEntitledModules loops over ~30 modules), without
// serving stale answers beyond a few seconds.
const projectionMemoTTL = 5 * time.Second

// projectionMemoMax bounds the memo so it cannot grow without limit.
const projectionMemoMax = 1024

type entitlementEnvelopeSource interface {
	GetEntitlements(ctx context.Context, tenantID uuid.UUID) (EntitlementEnvelope, error)
}

type projectionMemoEntry struct {
	env     EntitlementEnvelope
	expires time.Time
}

// ProjectionOrLegacyChecker answers module entitlement for the role picker:
// a module is entitled when the legacy product-manifest check says so OR the
// iam_tenant_module_entitlements projection grants an entitlement code that
// covers the module. Accepting either only ever adds modules versus today.
type ProjectionOrLegacyChecker struct {
	legacy ModuleEntitlementChecker
	ent    entitlementEnvelopeSource

	mu   sync.Mutex
	memo map[uuid.UUID]projectionMemoEntry
}

// NewProjectionOrLegacyChecker constructs the combined checker. legacy may be
// nil (projection only).
func NewProjectionOrLegacyChecker(legacy ModuleEntitlementChecker, ent entitlementEnvelopeSource) *ProjectionOrLegacyChecker {
	return &ProjectionOrLegacyChecker{legacy: legacy, ent: ent, memo: map[uuid.UUID]projectionMemoEntry{}}
}

// IsTenantEntitled implements ModuleEntitlementChecker.
func (c *ProjectionOrLegacyChecker) IsTenantEntitled(ctx context.Context, tenantID uuid.UUID, module string) (bool, error) {
	var legacyErr error
	if c.legacy != nil {
		ok, err := c.legacy.IsTenantEntitled(ctx, tenantID, module)
		if ok {
			return true, nil
		}
		legacyErr = err
	}

	if c.ent != nil {
		env, err := c.envelope(ctx, tenantID)
		if err == nil {
			codes := map[string]bool{}
			for _, code := range EntitlementCodesForPermissionModule(strings.ToLower(module)) {
				codes[code] = true
			}
			for _, m := range env.Modules {
				if codes[m.Code] && models.ModuleEntitlementStatus(m.Status).IsGranting() {
					return true, nil
				}
			}
		} else if legacyErr == nil {
			legacyErr = err
		}
	}
	return false, legacyErr
}

func (c *ProjectionOrLegacyChecker) envelope(ctx context.Context, tenantID uuid.UUID) (EntitlementEnvelope, error) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.memo[tenantID]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.env, nil
	}
	c.mu.Unlock()

	env, err := c.ent.GetEntitlements(ctx, tenantID)
	if err != nil {
		return EntitlementEnvelope{}, err
	}

	c.mu.Lock()
	if len(c.memo) >= projectionMemoMax {
		c.memo = map[uuid.UUID]projectionMemoEntry{}
	}
	c.memo[tenantID] = projectionMemoEntry{env: env, expires: now.Add(projectionMemoTTL)}
	c.mu.Unlock()
	return env, nil
}
