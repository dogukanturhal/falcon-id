// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration
// +build integration

// Package database_test contains integration tests for RLS policy enforcement.
// These tests require a live PostgreSQL instance with all migrations applied and
// must be invoked explicitly via:
//
//	go test -tags=integration ./internal/shared/database/... -run TestRLS
//
// The DATABASE_URL environment variable must point to the target database.
package database_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import the database package to confirm the import path is correct and
	// to make the dependency explicit, even though no symbols are used directly
	// from the package in these black-box tests.
	_ "github.com/dogukanturhal/falcon-id/internal/shared/database"
)

// getTestDB connects to the database identified by DATABASE_URL or skips the
// calling test if the variable is absent.  The pool is registered for cleanup
// so callers do not need to close it manually.
func getTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	require.NoError(t, err, "failed to create pgxpool from DATABASE_URL")

	t.Cleanup(func() { pool.Close() })

	return pool
}

// =============================================================================
// TestRLSPoliciesExist
// Verifies that every table expected to carry a Row Level Security policy has
// relrowsecurity = true in pg_class.  This confirms that the migration which
// enables RLS (062 and the forthcoming 072) was applied successfully.
// =============================================================================

// TestRLSPoliciesExist queries pg_class to confirm RLS is enabled on every
// IAM table that should be covered by a tenant or realm isolation policy.
func TestRLSPoliciesExist(t *testing.T) {
	db := getTestDB(t)

	// Tables are grouped by the migration that introduced their RLS policy.
	tablesWithRLS := []string{
		// -----------------------------------------------------------------------
		// Migration 062 – product/license/app-registration hardening
		// -----------------------------------------------------------------------
		"iam_licenses",
		"iam_app_registrations",
		"iam_app_role_assignments",
		"iam_app_auth_policies",

		// -----------------------------------------------------------------------
		// Migration 072 – dual policy (tenant_id + realm_id)
		// -----------------------------------------------------------------------
		"iam_users",
		"iam_sessions",
		"iam_refresh_tokens",
		"iam_roles",
		"iam_api_keys",
		"iam_audit_log",
		"iam_user_groups",
		"iam_identity_providers",
		"iam_ldap_configs",
		"iam_oauth_providers",
		"iam_saml_service_providers",
		"iam_password_policies",
		"iam_rate_limiting_rules",
		"iam_ip_rules",
		"iam_webhooks",
		"iam_service_accounts",

		// -----------------------------------------------------------------------
		// Migration 072 – tenant-only policy
		// -----------------------------------------------------------------------
		"iam_user_roles",
		"iam_role_permissions",
		"iam_groups",
		"iam_user_devices",
		"iam_organizations",
		"iam_magic_links",
		"iam_invitations",
		"iam_consent_records",
		"iam_delegations",
		"iam_impersonation_sessions",
	}

	for _, table := range tablesWithRLS {
		table := table // capture loop variable for subtest closure
		t.Run(table, func(t *testing.T) {
			t.Parallel()

			var rlsEnabled bool
			err := db.QueryRow(
				context.Background(),
				"SELECT relrowsecurity FROM pg_class WHERE relname = $1",
				table,
			).Scan(&rlsEnabled)

			require.NoError(t, err,
				"table %s must exist in pg_class (migration may not have been applied)", table)
			assert.True(t, rlsEnabled,
				"RLS must be enabled on %s (ALTER TABLE ... ENABLE ROW LEVEL SECURITY missing)", table)
		})
	}
}

// =============================================================================
// TestRLSBlocksCrossTenantAccess
// Inserts rows for two distinct tenants, then activates the RLS session
// variable for tenant A and asserts that only tenant A's rows are visible.
// The entire test runs inside a transaction that is rolled back on exit so
// it leaves no residue in the database.
// =============================================================================

// TestRLSBlocksCrossTenantAccess verifies that setting app.current_tenant_id
// restricts SELECT results to only the matching tenant's rows.
func TestRLSBlocksCrossTenantAccess(t *testing.T) {
	db := getTestDB(t)
	ctx := context.Background()

	tenantA := uuid.New()
	tenantB := uuid.New()

	// Use a transaction so the test data is never committed.
	tx, err := db.Begin(ctx)
	require.NoError(t, err, "begin transaction")
	defer tx.Rollback(ctx) //nolint:errcheck

	// ------------------------------------------------------------------
	// Seed prerequisite: the iam_tenants and iam_realms rows must exist
	// before we can insert child rows that reference them via FK.
	// ------------------------------------------------------------------
	realmA := uuid.New()
	realmB := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_tenants (id, name, slug, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, tenantA, fmt.Sprintf("rls-test-tenant-a-%s", tenantA), fmt.Sprintf("rls-test-a-%s", tenantA[:8]))
	require.NoError(t, err, "insert tenant A")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_tenants (id, name, slug, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, tenantB, fmt.Sprintf("rls-test-tenant-b-%s", tenantB), fmt.Sprintf("rls-test-b-%s", tenantB[:8]))
	require.NoError(t, err, "insert tenant B")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_realms (id, tenant_id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, realmA, tenantA,
		fmt.Sprintf("realm-a-%s", realmA),
		fmt.Sprintf("realm-a-%s", realmA[:8]))
	require.NoError(t, err, "insert realm A")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_realms (id, tenant_id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, realmB, tenantB,
		fmt.Sprintf("realm-b-%s", realmB),
		fmt.Sprintf("realm-b-%s", realmB[:8]))
	require.NoError(t, err, "insert realm B")

	// ------------------------------------------------------------------
	// Insert one iam_users row per tenant.
	// ------------------------------------------------------------------
	userA := uuid.New()
	userB := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_users
			(id, tenant_id, realm_id, email, email_hash, username, status, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
	`, userA, tenantA, realmA,
		fmt.Sprintf("rls-user-a-%s@example.com", userA),
		fmt.Sprintf("hash-a-%s", userA),
		fmt.Sprintf("rls-user-a-%s", userA[:8]))
	require.NoError(t, err, "insert user for tenant A")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_users
			(id, tenant_id, realm_id, email, email_hash, username, status, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
	`, userB, tenantB, realmB,
		fmt.Sprintf("rls-user-b-%s@example.com", userB),
		fmt.Sprintf("hash-b-%s", userB),
		fmt.Sprintf("rls-user-b-%s", userB[:8]))
	require.NoError(t, err, "insert user for tenant B")

	// ------------------------------------------------------------------
	// Activate tenant A's RLS context via SET LOCAL (transaction-scoped).
	// ------------------------------------------------------------------
	_, err = tx.Exec(ctx,
		"SET LOCAL app.current_tenant_id = $1",
		tenantA.String())
	require.NoError(t, err, "set app.current_tenant_id to tenant A")

	// ------------------------------------------------------------------
	// Assert: only tenant A's user is visible.
	// ------------------------------------------------------------------
	rows, err := tx.Query(ctx,
		"SELECT id FROM iam_users WHERE id = ANY($1)",
		[]uuid.UUID{userA, userB})
	require.NoError(t, err, "query iam_users with RLS active")
	defer rows.Close()

	var visible []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		visible = append(visible, id)
	}
	require.NoError(t, rows.Err())

	assert.Contains(t, visible, userA,
		"tenant A's user must be visible when app.current_tenant_id = tenant A")
	assert.NotContains(t, visible, userB,
		"tenant B's user must NOT be visible when app.current_tenant_id = tenant A (RLS violation)")
}

// =============================================================================
// TestRLSBlocksCrossRealmAccess
// Like the tenant test above but focuses on realm_id isolation.  Two users
// belong to the same tenant but different realms; only the realm that matches
// app.current_realm_id should be visible when that session variable is set.
// =============================================================================

// TestRLSBlocksCrossRealmAccess verifies that app.current_realm_id restricts
// visibility to rows belonging to the matching realm within a tenant.
func TestRLSBlocksCrossRealmAccess(t *testing.T) {
	db := getTestDB(t)
	ctx := context.Background()

	tenantID := uuid.New()
	realmA := uuid.New()
	realmB := uuid.New()

	tx, err := db.Begin(ctx)
	require.NoError(t, err, "begin transaction")
	defer tx.Rollback(ctx) //nolint:errcheck

	// Seed prerequisite tenant.
	_, err = tx.Exec(ctx, `
		INSERT INTO iam_tenants (id, name, slug, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, tenantID,
		fmt.Sprintf("rls-realm-test-tenant-%s", tenantID),
		fmt.Sprintf("rls-realm-%s", tenantID[:8]))
	require.NoError(t, err, "insert tenant")

	// Seed two realms under the same tenant.
	_, err = tx.Exec(ctx, `
		INSERT INTO iam_realms (id, tenant_id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, realmA, tenantID,
		fmt.Sprintf("realm-a-%s", realmA),
		fmt.Sprintf("ra-%s", realmA[:8]))
	require.NoError(t, err, "insert realm A")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_realms (id, tenant_id, name, slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, realmB, tenantID,
		fmt.Sprintf("realm-b-%s", realmB),
		fmt.Sprintf("rb-%s", realmB[:8]))
	require.NoError(t, err, "insert realm B")

	// Insert one user in each realm (same tenant).
	userInRealmA := uuid.New()
	userInRealmB := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_users
			(id, tenant_id, realm_id, email, email_hash, username, status, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
	`, userInRealmA, tenantID, realmA,
		fmt.Sprintf("realm-user-a-%s@example.com", userInRealmA),
		fmt.Sprintf("hash-ra-%s", userInRealmA),
		fmt.Sprintf("realm-user-a-%s", userInRealmA[:8]))
	require.NoError(t, err, "insert user in realm A")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_users
			(id, tenant_id, realm_id, email, email_hash, username, status, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
	`, userInRealmB, tenantID, realmB,
		fmt.Sprintf("realm-user-b-%s@example.com", userInRealmB),
		fmt.Sprintf("hash-rb-%s", userInRealmB),
		fmt.Sprintf("realm-user-b-%s", userInRealmB[:8]))
	require.NoError(t, err, "insert user in realm B")

	// Activate the tenant context so the tenant-level policy allows access,
	// then additionally restrict to realm A only.
	_, err = tx.Exec(ctx,
		"SET LOCAL app.current_tenant_id = $1",
		tenantID.String())
	require.NoError(t, err, "set app.current_tenant_id")

	_, err = tx.Exec(ctx,
		"SET LOCAL app.current_realm_id = $1",
		realmA.String())
	require.NoError(t, err, "set app.current_realm_id to realm A")

	// Query both users by ID.
	rows, err := tx.Query(ctx,
		"SELECT id FROM iam_users WHERE id = ANY($1)",
		[]uuid.UUID{userInRealmA, userInRealmB})
	require.NoError(t, err, "query iam_users with realm RLS active")
	defer rows.Close()

	var visible []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		visible = append(visible, id)
	}
	require.NoError(t, rows.Err())

	assert.Contains(t, visible, userInRealmA,
		"user in realm A must be visible when app.current_realm_id = realm A")
	assert.NotContains(t, visible, userInRealmB,
		"user in realm B must NOT be visible when app.current_realm_id = realm A (realm RLS violation)")
}

// =============================================================================
// TestRLSSuperuserBypass
// When no session variables are set (the COALESCE fallback path), all rows
// should be visible to the application role — this is the intended behaviour
// for migration runs, background jobs, and superuser contexts.
// =============================================================================

// TestRLSSuperuserBypass confirms that when app.current_tenant_id is absent,
// the COALESCE(NULLIF(...), tenant_id) fallback makes all rows visible so that
// migrations and system-level queries are never blocked by RLS.
func TestRLSSuperuserBypass(t *testing.T) {
	db := getTestDB(t)
	ctx := context.Background()

	tenantA := uuid.New()
	tenantB := uuid.New()

	tx, err := db.Begin(ctx)
	require.NoError(t, err, "begin transaction")
	defer tx.Rollback(ctx) //nolint:errcheck

	// Seed two tenants and their realms.
	realmA := uuid.New()
	realmB := uuid.New()

	for _, row := range []struct {
		id   uuid.UUID
		name string
		slug string
	}{
		{tenantA, fmt.Sprintf("bypass-tenant-a-%s", tenantA), fmt.Sprintf("bypass-a-%s", tenantA[:8])},
		{tenantB, fmt.Sprintf("bypass-tenant-b-%s", tenantB), fmt.Sprintf("bypass-b-%s", tenantB[:8])},
	} {
		_, err = tx.Exec(ctx, `
			INSERT INTO iam_tenants (id, name, slug, status, created_at, updated_at)
			VALUES ($1, $2, $3, 'active', NOW(), NOW())
			ON CONFLICT (id) DO NOTHING
		`, row.id, row.name, row.slug)
		require.NoError(t, err, "insert tenant %s", row.id)
	}

	for _, row := range []struct {
		id       uuid.UUID
		tenantID uuid.UUID
	}{
		{realmA, tenantA},
		{realmB, tenantB},
	} {
		_, err = tx.Exec(ctx, `
			INSERT INTO iam_realms (id, tenant_id, name, slug, created_at, updated_at)
			VALUES ($1, $2, $3, $4, NOW(), NOW())
			ON CONFLICT (id) DO NOTHING
		`, row.id, row.tenantID,
			fmt.Sprintf("bypass-realm-%s", row.id),
			fmt.Sprintf("bypass-r-%s", row.id[:8]))
		require.NoError(t, err, "insert realm %s", row.id)
	}

	// Insert one user per tenant.
	userA := uuid.New()
	userB := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_users
			(id, tenant_id, realm_id, email, email_hash, username, status, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
	`, userA, tenantA, realmA,
		fmt.Sprintf("bypass-a-%s@example.com", userA),
		fmt.Sprintf("bhash-a-%s", userA),
		fmt.Sprintf("bypass-a-%s", userA[:8]))
	require.NoError(t, err, "insert user A")

	_, err = tx.Exec(ctx, `
		INSERT INTO iam_users
			(id, tenant_id, realm_id, email, email_hash, username, status, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW())
	`, userB, tenantB, realmB,
		fmt.Sprintf("bypass-b-%s@example.com", userB),
		fmt.Sprintf("bhash-b-%s", userB),
		fmt.Sprintf("bypass-b-%s", userB[:8]))
	require.NoError(t, err, "insert user B")

	// Explicitly clear any session variables that may linger from a previous
	// subtest or connection pool reuse, simulating a clean superuser context.
	_, err = tx.Exec(ctx, "SET LOCAL app.current_tenant_id = ''")
	require.NoError(t, err, "clear app.current_tenant_id")

	_, err = tx.Exec(ctx, "SET LOCAL app.current_realm_id = ''")
	require.NoError(t, err, "clear app.current_realm_id")

	// Both rows must be visible because the COALESCE fallback returns the
	// row's own tenant_id when the session variable is empty, effectively
	// making the policy condition always true (tenant_id = tenant_id).
	rows, err := tx.Query(ctx,
		"SELECT id FROM iam_users WHERE id = ANY($1)",
		[]uuid.UUID{userA, userB})
	require.NoError(t, err, "query iam_users without RLS context")
	defer rows.Close()

	var visible []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		visible = append(visible, id)
	}
	require.NoError(t, rows.Err())

	assert.Contains(t, visible, userA,
		"user A must be visible when no tenant session variable is set (superuser bypass)")
	assert.Contains(t, visible, userB,
		"user B must be visible when no tenant session variable is set (superuser bypass)")
}
