// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// bootstrapPlatformRealmTenant idempotently ensures the canonical
// exampletenant tenant (`00000000-0000-0000-0000-000000000002`) is
// mapped to the platform realm (`WellKnownRealmPlatform`) in the
// `realm_tenants` table on the control-plane DB.
//
// Why this seed is required:
//
//   - The realms row alone is not sufficient: realm-aware code paths
//     (RealmService.GetTenantRealm, the realm middleware, RLS policies
//     guarded by current_realm_id, the per-realm credential context for
//     OAuth token issuance) all key off `realm_tenants` to resolve
//     `tenant_id → realm_id`. Without this mapping, every request that
//     enters tenant-scoped logic falls back to DefaultRealmID
//     (WellKnownRealmShared) and Sprint-1 #5's wrong-realm class
//     reproduces silently.
//
//   - Keystone manages the `realm_tenants` TABLE structure (via
//     SchemaDefinition `falcon-id-control-public-desired`); Keystone
//     does NOT manage table ROWS. The well-known mapping is operational
//     data, so the application is the right component to ensure it.
//
// Why this lives next to bootstrapPlatformRealm:
//
//   - Same trust boundary — the application owns `realms` row creation
//     and `realm_tenants` row creation as a single seed unit. Splitting
//     them across operator vs. application would re-introduce the
//     "schema is keystone-reconciled but data is not" gap that motivated
//     bootstrapPlatformRealm + bootstrapAdminUser in the first place
//     (operational notes).
//
//   - Idempotent on every restart, survives any future falcon-id-pg
//     fresh-initdb without operator intervention. Same shape as
//     bootstrapPlatformRealm.
//
// Idempotency:
//
//   - GetTenantRealm first; if the tenant already maps to the platform
//     realm, skip. If it maps to a DIFFERENT realm, log a warning and
//     skip — operator-driven realm migration is the canonical path for
//     re-mapping a tenant, and silently overwriting on every boot would
//     defeat that intent (mirrors the OAuth provisioner client mismatch
//     handling in cmd/oauth_provisioner_bootstrap.go).
//   - If no mapping exists, INSERT.
//
// Failure mode:
//
//   - On error, log ERROR and return — do NOT panic. Application must
//     come up to serve health probes; a missing mapping is operator-
//     visible via:
//     1. Stale realm context in /oauth/token responses for
//        exampletenant users
//     2. A TODO follow-up Prometheus alert on
//        `realm_tenants WHERE tenant_id = HexxlockInternalTenantID`
//        being absent for >5m
//
// This function is safe to call on every restart.
func bootstrapPlatformRealmTenant(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tenantID, err := uuid.Parse(models.HexxlockInternalTenantID)
	if err != nil {
		// Should never fire — HexxlockInternalTenantID is a compile-time const.
		logger.Error("bootstrapPlatformRealmTenant: failed to parse HexxlockInternalTenantID",
			zap.Error(err),
		)
		return
	}
	realmID := models.WellKnownRealmPlatform

	existing, err := repos.Realm.GetTenantRealm(ctx, tenantID)
	if err != nil && !isNoRowsError(err) {
		logger.Error("bootstrapPlatformRealmTenant: failed to check for existing mapping",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return
	}
	if existing != nil {
		if existing.ID == realmID {
			logger.Info("bootstrapPlatformRealmTenant: mapping already correct, skipping",
				zap.String("tenant_id", tenantID.String()),
				zap.String("realm_id", realmID.String()),
			)
			return
		}
		// Tenant is mapped to a different realm — operator-driven migration
		// is the canonical path. Loud-but-non-fatal log so the divergence is
		// surfaced without overwriting a deliberate operator action.
		logger.Warn("bootstrapPlatformRealmTenant: tenant mapped to non-platform realm, skipping (operator migration is the canonical re-map path)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("current_realm_id", existing.ID.String()),
			zap.String("expected_realm_id", realmID.String()),
		)
		return
	}

	// Use EnsureRealmTenant (schema-aligned to the live SD) instead of
	// AssignTenant (which references `assigned_by`, missing in the live
	// `realm_tenants` table — verified live 2026-05-07:
	// `column "assigned_by" of relation "realm_tenants" does not exist`).
	// EnsureRealmTenant is idempotent: ON CONFLICT (tenant_id) DO NOTHING
	// swallows races between sibling pods and re-runs.
	if err := repos.Realm.EnsureRealmTenant(ctx, realmID, tenantID); err != nil {
		// Repository-layer wrapping; check for unique-constraint-violation
		// strings as a defense in depth (race with sibling pod).
		if isRealmAlreadyExistsError(err) {
			logger.Info("bootstrapPlatformRealmTenant: mapping created concurrently by another pod, treating as success",
				zap.String("tenant_id", tenantID.String()),
				zap.String("realm_id", realmID.String()),
			)
			return
		}
		logger.Error("bootstrapPlatformRealmTenant: failed to create mapping",
			zap.String("tenant_id", tenantID.String()),
			zap.String("realm_id", realmID.String()),
			zap.Error(err),
		)
		return
	}

	logger.Info("bootstrapPlatformRealmTenant: mapping created",
		zap.String("tenant_id", tenantID.String()),
		zap.String("realm_id", realmID.String()),
	)
}

// bootstrapConsumerRealmTenant idempotently maps the shared CONSUMER tenant
// (WellKnownTenantConsumer — the B2C home for personal accounts) to the SHARED
// realm (WellKnownRealmShared). Personal signups enroll users in the consumer
// tenant and user creation resolves the realm via this mapping, so without it
// personal signup-complete fails the same way the platform mapping prevents
// for exampletenant. Mirrors bootstrapPlatformRealmTenant; must run AFTER
// bootstrapConsumerTenant (the tenant row) and bootstrapSharedRealm (the realm
// row) so the realm_tenants FK holds.
func bootstrapConsumerRealmTenant(repos *Repositories) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tenantID := models.WellKnownTenantConsumer
	realmID := models.WellKnownRealmShared

	existing, err := repos.Realm.GetTenantRealm(ctx, tenantID)
	if err != nil && !isNoRowsError(err) {
		logger.Error("bootstrapConsumerRealmTenant: failed to check for existing mapping",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return
	}
	if existing != nil {
		if existing.ID == realmID {
			logger.Info("bootstrapConsumerRealmTenant: mapping already correct, skipping",
				zap.String("tenant_id", tenantID.String()),
				zap.String("realm_id", realmID.String()),
			)
			return
		}
		logger.Warn("bootstrapConsumerRealmTenant: consumer tenant mapped to non-shared realm, skipping (operator migration is the canonical re-map path)",
			zap.String("tenant_id", tenantID.String()),
			zap.String("current_realm_id", existing.ID.String()),
			zap.String("expected_realm_id", realmID.String()),
		)
		return
	}

	if err := repos.Realm.EnsureRealmTenant(ctx, realmID, tenantID); err != nil {
		if isRealmAlreadyExistsError(err) {
			logger.Info("bootstrapConsumerRealmTenant: mapping created concurrently by another pod, treating as success",
				zap.String("tenant_id", tenantID.String()),
				zap.String("realm_id", realmID.String()),
			)
			return
		}
		logger.Error("bootstrapConsumerRealmTenant: failed to create mapping",
			zap.String("tenant_id", tenantID.String()),
			zap.String("realm_id", realmID.String()),
			zap.Error(err),
		)
		return
	}

	logger.Info("bootstrapConsumerRealmTenant: mapping created",
		zap.String("tenant_id", tenantID.String()),
		zap.String("realm_id", realmID.String()),
	)
}

// isNoRowsError matches the pgx-flavoured "no rows in result set" error
// surfaced by RealmRepository.GetTenantRealm when the tenant has no row in
// realm_tenants. This is the EXPECTED first-boot state and must NOT be
// treated as an operational failure. Substring match because the
// repository today wraps pgx.ErrNoRows in fmt.Errorf; a follow-up MR can
// thread errors.Is once the repository surfaces a typed sentinel.
func isNoRowsError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no rows in result set")
}
