// SPDX-License-Identifier: AGPL-3.0-or-later

package services

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
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// fakePlatformSpiceDB is an in-memory stand-in for *spicedb.Client's
// WritePlatformElevation/DeletePlatformElevation, satisfying
// platformSpiceDBClient structurally. Real SpiceDB compile/write
// correctness (the hxl_platform definition + active_elevation caveat) was
// already verified separately against a live authzed/spicedb container;
// this test's job is the Postgres state machine (migration 0016's
// triggers/CHECKs + the service's transitions), not the SpiceDB wire
// protocol.
type fakePlatformSpiceDB struct {
	writes  int
	deletes int
}

func (f *fakePlatformSpiceDB) WritePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string, expiresAt time.Time) (string, error) {
	f.writes++
	return "fake-zed-token", nil
}

func (f *fakePlatformSpiceDB) DeletePlatformElevation(ctx context.Context, userID uuid.UUID, roleKey string) (string, error) {
	f.deletes++
	return "fake-zed-token", nil
}

// setupPlatformJITTestDB creates an isolated schema, applies migration
// 0016 against stub iam_tenants/iam_users tables, and returns a
// PlatformJITService wired to it plus the raw pool (for test seeding/
// assertions) and a cleanup func. Requires TEST_DATABASE_URL - run via
// hack/run-jit-postgres-tests.sh.
func setupPlatformJITTestDB(t *testing.T) (svc *PlatformJITService, repo *repositories.PlatformElevationRepository, pool *pgxpool.Pool, spice *fakePlatformSpiceDB, cleanup func()) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-jit-postgres-tests.sh")
	}

	ctx := context.Background()
	schema := "platform_jit_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)

	cleanup = func() {
		p.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}

	_, err = p.Exec(ctx, `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_tenants (id uuid PRIMARY KEY);
CREATE TABLE iam_users (id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES iam_tenants(id));
-- Migration 0016 GRANTs to the prod app role; roles are cluster-wide, so
-- create it idempotently and tolerate a concurrent creator.
DO $$ BEGIN
  CREATE ROLE falcon_id_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
`)
	if err != nil {
		cleanup()
		t.Fatalf("stub schema: %v", err)
	}

	migrationSQL, err := os.ReadFile("../migrations/0016_iam_platform_roles_jit_elevations.sql")
	if err != nil {
		cleanup()
		t.Fatalf("read migration 0016: %v", err)
	}
	if _, err := p.Exec(ctx, string(migrationSQL)); err != nil {
		cleanup()
		t.Fatalf("apply migration 0016: %v", err)
	}

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	outsideTenantID := uuid.New()
	_, err = p.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1), ($2)`, internalTenantID, outsideTenantID)
	if err != nil {
		cleanup()
		t.Fatalf("seed tenants: %v", err)
	}

	r := repositories.NewPlatformElevationRepository(p)
	sp := &fakePlatformSpiceDB{}
	s := NewPlatformJITService(r, r, sp, nil, zap.NewNop())

	return s, r, p, sp, cleanup
}

func seedUser(t *testing.T, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(), `INSERT INTO iam_users (id, tenant_id) VALUES ($1,$2)`, id, tenantID)
	require.NoError(t, err)
	return id
}

// TestPlatformJITPostgres_StandingAssignmentRejected proves the mandated
// "standing-assignment 403" behavior: GrantStandingRole rejects every
// role_key except platform_viewer at the service layer
// (ErrPlatformRoleNotStandingAssignable — mapped to HTTP 403
// platform_role_not_standing_assignable by platformJITErrorStatus), BEFORE
// any DB write is attempted. The identical rule is also enforced by the
// iam_platform_roles_enforce DB trigger (migration 0016) as defense in
// depth; TestPlatformJITPostgres_TriggerRejectsDirectNonStandingInsert
// below exercises that layer directly.
func TestPlatformJITPostgres_StandingAssignmentRejected(t *testing.T) {
	svc, _, pool, _, cleanup := setupPlatformJITTestDB(t)
	defer cleanup()
	ctx := context.Background()

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	targetUser := seedUser(t, pool, internalTenantID)
	granter := seedUser(t, pool, internalTenantID)

	for _, roleKey := range []string{"platform_admin", "platform_support", "platform_billing", "platform_security"} {
		_, err := svc.GrantStandingRole(ctx, granter, targetUser, roleKey)
		require.ErrorIsf(t, err, ErrPlatformRoleNotStandingAssignable, "role_key=%s", roleKey)
	}

	_, err := svc.GrantStandingRole(ctx, granter, targetUser, "not_a_real_role")
	require.ErrorIs(t, err, ErrInvalidRoleKey)

	// The only standing-assignable key succeeds.
	role, err := svc.GrantStandingRole(ctx, granter, targetUser, "platform_viewer")
	require.NoError(t, err)
	require.Equal(t, models.PlatformRoleViewer, role.RoleKey)
}

// TestPlatformJITPostgres_TriggerRejectsDirectNonStandingInsert exercises
// the DB layer directly (bypassing the service's own guard) to prove the
// iam_platform_roles_enforce trigger independently rejects a raw INSERT of
// a non-platform_viewer standing row with no backing active elevation —
// the belt-and-suspenders enforcement the service-layer check mirrors.
func TestPlatformJITPostgres_TriggerRejectsDirectNonStandingInsert(t *testing.T) {
	_, _, pool, _, cleanup := setupPlatformJITTestDB(t)
	defer cleanup()
	ctx := context.Background()

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	targetUser := seedUser(t, pool, internalTenantID)

	_, err := pool.Exec(ctx, `INSERT INTO iam_platform_roles (user_id, role_key) VALUES ($1, 'platform_admin')`, targetUser)
	require.Error(t, err)

	// platform_viewer, the standing-assignable key, is unaffected.
	_, err = pool.Exec(ctx, `INSERT INTO iam_platform_roles (user_id, role_key) VALUES ($1, 'platform_viewer')`, targetUser)
	require.NoError(t, err)
}

// TestPlatformJITPostgres_TriggerRejectsNonInternalTenantMember proves the
// internal-tenant-membership CHECK: a user outside the Platform-internal
// tenant cannot hold ANY iam_platform_roles row, including platform_viewer.
func TestPlatformJITPostgres_TriggerRejectsNonInternalTenantMember(t *testing.T) {
	_, _, pool, _, cleanup := setupPlatformJITTestDB(t)
	defer cleanup()
	ctx := context.Background()

	outsideTenantID := uuid.New()
	_, err := pool.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1)`, outsideTenantID)
	require.NoError(t, err)
	outsideUser := seedUser(t, pool, outsideTenantID)

	_, err = pool.Exec(ctx, `INSERT INTO iam_platform_roles (user_id, role_key) VALUES ($1, 'platform_viewer')`, outsideUser)
	require.Error(t, err)
}

// TestPlatformJITPostgres_FullLifecycle exercises request -> two-person
// approval -> activation -> revoke against a real Postgres instance with
// migration 0016 applied, proving the CHECK constraints, triggers, and
// service-layer state machine agree.
func TestPlatformJITPostgres_FullLifecycle(t *testing.T) {
	svc, repo, pool, spice, cleanup := setupPlatformJITTestDB(t)
	defer cleanup()
	ctx := context.Background()

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := seedUser(t, pool, internalTenantID)
	approver := seedUser(t, pool, internalTenantID)

	// Two-person rule: self-approval is rejected before activation.
	e, err := svc.RequestElevation(ctx, requester, "platform_admin", nil, "incident 1234", time.Hour)
	require.NoError(t, err)
	require.Equal(t, models.PlatformElevationPending, e.Status)

	_, err = svc.ApproveElevation(ctx, e.ID, requester)
	require.ErrorIs(t, err, ErrSelfApprovalNotAllowed)

	approved, err := svc.ApproveElevation(ctx, e.ID, approver)
	require.NoError(t, err)
	require.Equal(t, models.PlatformElevationApproved, approved.Status)

	// Double-approve is rejected (no longer pending).
	_, err = svc.ApproveElevation(ctx, e.ID, approver)
	require.ErrorIs(t, err, ErrElevationNotPending)

	active, err := svc.ActivateElevation(ctx, e.ID)
	require.NoError(t, err)
	require.Equal(t, models.PlatformElevationActive, active.Status)
	require.Equal(t, 1, spice.writes)

	// GrantStandingRole for platform_viewer (the one standing-assignable
	// key) succeeds for an internal-tenant user.
	viewer := seedUser(t, pool, internalTenantID)
	role, err := svc.GrantStandingRole(ctx, approver, viewer, "platform_viewer")
	require.NoError(t, err)
	require.Equal(t, models.PlatformRoleViewer, role.RoleKey)

	// iam_platform_roles is the materialized projection of every currently
	// held platform role, JIT-activated or directly granted — at this
	// point that's the requester's active platform_admin elevation PLUS
	// the viewer's standing platform_viewer grant.
	roles, err := svc.ListStandingRoles(ctx)
	require.NoError(t, err)
	require.Len(t, roles, 2)

	require.NoError(t, svc.RevokeElevation(ctx, e.ID, approver))
	require.Equal(t, 1, spice.deletes)

	got, err := repo.GetElevationByID(ctx, e.ID)
	require.NoError(t, err)
	require.Equal(t, models.PlatformElevationRevoked, got.Status)

	// The transition hash chain has one row per state change; verify it's
	// non-empty and the chain links (each entry's prev_hash equals the
	// previous entry's entry_hash).
	rows, err := pool.Query(ctx, `SELECT prev_hash, entry_hash FROM iam_jit_elevation_transitions WHERE elevation_id = $1 ORDER BY occurred_at ASC, id ASC`, e.ID)
	require.NoError(t, err)
	var prevSeen string
	count := 0
	for rows.Next() {
		var prevHash, entryHash string
		require.NoError(t, rows.Scan(&prevHash, &entryHash))
		require.Equal(t, prevSeen, prevHash, "transition %d: prev_hash must equal previous entry_hash", count)
		prevSeen = entryHash
		count++
	}
	rows.Close()
	require.GreaterOrEqual(t, count, 3) // requested, approved, activated, revoked
}

// TestPlatformJITPostgres_ExpirySweepIdempotent proves RunExpirySweep is
// safe to call repeatedly: the second call over an already-expired,
// already-revoked row is a no-op (revoked==0, no error), matching the
// DB-driven idempotency the brief requires.
func TestPlatformJITPostgres_ExpirySweepIdempotent(t *testing.T) {
	svc, _, pool, spice, cleanup := setupPlatformJITTestDB(t)
	defer cleanup()
	ctx := context.Background()

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := seedUser(t, pool, internalTenantID)
	approver := seedUser(t, pool, internalTenantID)

	e, err := svc.RequestElevation(ctx, requester, "platform_support", nil, "on-call diagnostics", time.Second)
	require.NoError(t, err)
	_, err = svc.ApproveElevation(ctx, e.ID, approver)
	require.NoError(t, err)
	_, err = svc.ActivateElevation(ctx, e.ID)
	require.NoError(t, err)

	// Force expiry immediately rather than sleeping a full second.
	_, err = pool.Exec(ctx, `UPDATE iam_jit_elevations SET expires_at = now() - interval '1 second' WHERE id = $1`, e.ID)
	require.NoError(t, err)

	revoked, sweepErr := svc.RunExpirySweep(ctx, 10)
	require.NoError(t, sweepErr)
	require.Equal(t, 1, revoked)
	require.Equal(t, 1, spice.deletes)

	// Second pass: the row is no longer status='active', so
	// ListExpiredActive returns nothing — idempotent no-op.
	revoked2, sweepErr2 := svc.RunExpirySweep(ctx, 10)
	require.NoError(t, sweepErr2)
	require.Zero(t, revoked2)
	require.Equal(t, 1, spice.deletes) // unchanged
}

// TestPlatformJITPostgres_BreakGlassSLAViolation proves the 24h
// retroactive-approval SLA: a break-glass activation older than the SLA
// window with no retroactive approval is flagged AND auto-revoked by
// RunBreakGlassSLASweep, exactly once, and that a late retroactive
// approval is still recorded afterward (audit completeness).
func TestPlatformJITPostgres_BreakGlassSLAViolation(t *testing.T) {
	svc, repo, pool, spice, cleanup := setupPlatformJITTestDB(t)
	defer cleanup()
	ctx := context.Background()

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	requester := seedUser(t, pool, internalTenantID)

	e, err := svc.RequestBreakGlass(ctx, requester, "platform_security", nil, "prod outage - no time for approval", time.Minute)
	require.NoError(t, err)
	require.True(t, e.IsBreakGlass)
	require.Equal(t, models.PlatformElevationActive, e.Status)
	require.Equal(t, 1, spice.writes)

	// Backdate created_at past the 24h SLA window.
	_, err = pool.Exec(ctx, `UPDATE iam_jit_elevations SET created_at = now() - interval '25 hours' WHERE id = $1`, e.ID)
	require.NoError(t, err)

	violations, sweepErr := svc.RunBreakGlassSLASweep(ctx, 10)
	require.NoError(t, sweepErr)
	require.Equal(t, 1, violations)
	require.Equal(t, 1, spice.deletes)

	got, err := repo.GetElevationByID(ctx, e.ID)
	require.NoError(t, err)
	require.True(t, got.BreakGlassViolation)
	require.Equal(t, models.PlatformElevationRevoked, got.Status)

	// Idempotent: a second sweep pass does not re-flag or re-count.
	violations2, sweepErr2 := svc.RunBreakGlassSLASweep(ctx, 10)
	require.NoError(t, sweepErr2)
	require.Zero(t, violations2)

	// A retroactive approval arriving late is still recorded (idempotent,
	// two-person rule still applies) even though the grant was already
	// auto-revoked for missing the SLA — the audit trail must reflect
	// both facts.
	approver := seedUser(t, pool, internalTenantID)
	_, err = svc.RetroactivelyApprove(ctx, e.ID, approver)
	require.NoError(t, err)
	_, err = svc.RetroactivelyApprove(ctx, e.ID, approver) // idempotent re-call
	require.NoError(t, err)

	_, err = svc.RetroactivelyApprove(ctx, e.ID, requester) // self-approval still rejected
	require.ErrorIs(t, err, ErrSelfApprovalNotAllowed)
}
