// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// setupModuleEntitlementTestDB provisions migration 0014's two tables in
// an isolated schema against TEST_DATABASE_URL, mirroring the pattern in
// team_roles_postgres_integration_test.go. Skips (does not fail) when
// TEST_DATABASE_URL is unset, matching this repo's existing convention for
// Postgres-backed repository tests.
func setupModuleEntitlementTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required for module entitlement repository integration tests")
	}
	ctx := context.Background()
	schema := "entitlements_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE iam_tenant_module_entitlements (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    module_code         TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'grace', 'expired')),
    seats               INTEGER,
    expires_at          TIMESTAMPTZ,
    source              TEXT,
    tier_code           TEXT,
    read_only           BOOLEAN NOT NULL DEFAULT FALSE,
    ever_trialed        BOOLEAN NOT NULL DEFAULT FALSE,
    ever_subscribed     BOOLEAN NOT NULL DEFAULT FALSE,
    event_version       BIGINT NOT NULL DEFAULT 0,
    source_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT iam_tenant_module_entitlements_tenant_module_uq UNIQUE (tenant_id, module_code)
);

CREATE TABLE iam_tenant_entitlement_flags (
    tenant_id           UUID PRIMARY KEY,
    flags               JSONB NOT NULL DEFAULT '{}'::jsonb,
    limits              JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_version       BIGINT NOT NULL DEFAULT 0,
    source_updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
`)
	require.NoError(t, err)

	return pool
}

func TestModuleEntitlementRepository_UpsertModule_Idempotency(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)
	ctx := context.Background()
	tenantID := uuid.New()

	// First write: version 1, applied.
	applied, err := repo.UpsertModule(ctx, &models.ModuleEntitlement{
		TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive,
		EventVersion: 1, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.True(t, applied)

	// Stale duplicate redelivery at the SAME version: must be rejected
	// (applied=false, no error) and must not overwrite fields.
	applied, err = repo.UpsertModule(ctx, &models.ModuleEntitlement{
		TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusExpired,
		EventVersion: 1, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.False(t, applied, "equal event_version must be rejected as a stale duplicate")

	rows, err := repo.GetByTenant(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, models.ModuleEntitlementStatusActive, rows[0].Status, "stale duplicate must not have overwritten status")

	// Out-of-order (older) version: also rejected.
	applied, err = repo.UpsertModule(ctx, &models.ModuleEntitlement{
		TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusExpired,
		EventVersion: 0, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.False(t, applied, "older event_version must be rejected")

	// Newer version: applied, overwrites fields.
	applied, err = repo.UpsertModule(ctx, &models.ModuleEntitlement{
		TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusExpired,
		EventVersion: 2, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.True(t, applied, "newer event_version must be applied")

	rows, err = repo.GetByTenant(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, models.ModuleEntitlementStatusExpired, rows[0].Status)
	require.Equal(t, int64(2), rows[0].EventVersion)
}

func TestModuleEntitlementRepository_MetadataMigrationIdempotent(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `ALTER TABLE iam_tenant_module_entitlements DROP COLUMN source, DROP COLUMN tier_code`)
	require.NoError(t, err)
	ddl, err := os.ReadFile("../migrations/0024_module_entitlement_source_tier.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, string(ddl))
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}
	var columns int
	err = pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='iam_tenant_module_entitlements' AND column_name IN ('source','tier_code') AND data_type='text' AND is_nullable='YES'`).Scan(&columns)
	require.NoError(t, err)
	require.Equal(t, 2, columns)
}

func TestModuleEntitlementRepository_SourceTierRoundtrip(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)
	ctx := context.Background()
	source, tier := "operator-comp", "professional"
	e := &models.ModuleEntitlement{TenantID: uuid.New(), ModuleCode: "crm", Status: models.ModuleEntitlementStatusActive,
		Source: &source, TierCode: &tier, EventVersion: 10, SourceUpdatedAt: time.Now().UTC()}
	applied, err := repo.UpsertModule(ctx, e)
	require.NoError(t, err)
	require.True(t, applied)
	rows, err := repo.GetByTenant(ctx, e.TenantID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, &source, rows[0].Source)
	require.Equal(t, &tier, rows[0].TierCode)
	// An older snapshot must not erase the metadata; a newer full snapshot
	// deliberately clears omitted/null metadata rather than retaining a stale comp.
	e.Source, e.TierCode, e.EventVersion = nil, nil, 9
	applied, err = repo.UpsertModule(ctx, e)
	require.NoError(t, err)
	require.False(t, applied)
	rows, err = repo.GetByTenant(ctx, e.TenantID)
	require.NoError(t, err)
	require.Equal(t, &source, rows[0].Source)
	require.Equal(t, &tier, rows[0].TierCode)
	e.EventVersion = 11
	applied, err = repo.UpsertModule(ctx, e)
	require.NoError(t, err)
	require.True(t, applied)
	rows, err = repo.GetByTenant(ctx, e.TenantID)
	require.NoError(t, err)
	require.Nil(t, rows[0].Source)
	require.Nil(t, rows[0].TierCode)
}

func TestModuleEntitlementRepository_UpsertModule_MultipleModulesPerTenant(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)
	ctx := context.Background()
	tenantID := uuid.New()

	for _, code := range []string{"crm", "marketing", "hcm"} {
		applied, err := repo.UpsertModule(ctx, &models.ModuleEntitlement{
			TenantID: tenantID, ModuleCode: code, Status: models.ModuleEntitlementStatusActive,
			EventVersion: 1, SourceUpdatedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
		require.True(t, applied)
	}

	rows, err := repo.GetByTenant(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, rows, 3)
}

func TestModuleEntitlementRepository_UpsertFlags_Idempotency(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)
	ctx := context.Background()
	tenantID := uuid.New()

	applied, err := repo.UpsertFlags(ctx, &models.TenantEntitlementFlags{
		TenantID: tenantID, Flags: map[string]bool{"beta": true}, EventVersion: 1, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.True(t, applied)

	// Stale duplicate: rejected.
	applied, err = repo.UpsertFlags(ctx, &models.TenantEntitlementFlags{
		TenantID: tenantID, Flags: map[string]bool{"beta": false}, EventVersion: 1, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.False(t, applied)

	flags, err := repo.GetFlags(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, flags)
	require.True(t, flags.Flags["beta"], "stale duplicate must not have overwritten flags")

	// Newer version: applied.
	applied, err = repo.UpsertFlags(ctx, &models.TenantEntitlementFlags{
		TenantID: tenantID, Flags: map[string]bool{"beta": false}, EventVersion: 2, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.True(t, applied)

	flags, err = repo.GetFlags(ctx, tenantID)
	require.NoError(t, err)
	require.False(t, flags.Flags["beta"])
}

func TestModuleEntitlementRepository_GetFlags_NoRow_ReturnsNilNil(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)

	flags, err := repo.GetFlags(context.Background(), uuid.New())
	require.NoError(t, err)
	require.Nil(t, flags, "no flags row must be (nil, nil), never an error")
}

func TestModuleEntitlementRepository_GetByTenant_NoRows_ReturnsEmptyNilNil(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)

	rows, err := repo.GetByTenant(context.Background(), uuid.New())
	require.NoError(t, err)
	require.Empty(t, rows)
}

// Migration 0020: limits ride the flags row; a snapshot that omits one map
// keeps the stored value of that map (COALESCE), under the same version guard.
func TestModuleEntitlementRepository_UpsertFlags_LimitsPreservedWhenOmitted(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)
	ctx := context.Background()
	tenantID := uuid.New()

	applied, err := repo.UpsertFlags(ctx, &models.TenantEntitlementFlags{
		TenantID: tenantID, Limits: map[string]int64{"production_bom_depth": 10}, EventVersion: 1, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.True(t, applied)
	got, err := repo.GetFlags(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, int64(10), got.Limits["production_bom_depth"])
	require.Empty(t, got.Flags, "first insert without flags stores {}")

	_, err = repo.UpsertFlags(ctx, &models.TenantEntitlementFlags{
		TenantID: tenantID, Flags: map[string]bool{"beta": true}, EventVersion: 2, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	got, err = repo.GetFlags(ctx, tenantID)
	require.NoError(t, err)
	require.True(t, got.Flags["beta"])
	require.Equal(t, int64(10), got.Limits["production_bom_depth"], "flags-only snapshot must not wipe limits")

	_, err = repo.UpsertFlags(ctx, &models.TenantEntitlementFlags{
		TenantID: tenantID, Limits: map[string]int64{"production_bom_depth": -1}, EventVersion: 2, SourceUpdatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	got, err = repo.GetFlags(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, int64(10), got.Limits["production_bom_depth"], "stale version must not overwrite limits")
}

func TestModuleEntitlementRepository_ReadOnlyRoundtripAndMigration(t *testing.T) {
	pool := setupModuleEntitlementTestDB(t)
	repo := NewModuleEntitlementRepository(pool)
	ctx := context.Background()
	tenantID := uuid.New()
	e := &models.ModuleEntitlement{TenantID: tenantID, ModuleCode: "crm", Status: models.ModuleEntitlementStatusGrace,
		ReadOnly: true, EventVersion: 1, SourceUpdatedAt: time.Now().UTC()}
	applied, err := repo.UpsertModule(ctx, e)
	require.NoError(t, err)
	require.True(t, applied)
	rows, err := repo.GetByTenant(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.True(t, rows[0].ReadOnly)

	// A newer snapshot without read_only clears it.
	e.ReadOnly, e.EventVersion = false, 2
	applied, err = repo.UpsertModule(ctx, e)
	require.NoError(t, err)
	require.True(t, applied)
	rows, err = repo.GetByTenant(ctx, tenantID)
	require.NoError(t, err)
	require.False(t, rows[0].ReadOnly)

	// Migration is idempotent and adds a NOT NULL default-false column.
	_, err = pool.Exec(ctx, `ALTER TABLE iam_tenant_module_entitlements DROP COLUMN read_only`)
	require.NoError(t, err)
	ddl, err := os.ReadFile("../migrations/0027_iam_module_entitlement_read_only.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, string(ddl))
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='iam_tenant_module_entitlements' AND column_name='read_only' AND data_type='boolean' AND is_nullable='NO'`).Scan(&n))
	require.Equal(t, 1, n)
}
