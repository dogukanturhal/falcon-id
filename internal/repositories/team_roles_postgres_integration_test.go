// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/testsupport"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestReplaceTeamRolesPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "team_roles_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_users(id uuid primary key, tenant_id uuid not null, is_active bool not null, updated_at timestamptz not null default now());
CREATE TABLE iam_roles(id uuid primary key, tenant_id uuid not null, name text not null, priority int not null, is_system bool not null default false);
CREATE TABLE iam_user_roles(user_id uuid not null references iam_users(id), role_id uuid not null references iam_roles(id), assigned_by uuid, expires_at timestamptz, primary key(user_id,role_id));
CREATE INDEX iam_user_roles_role_id_idx ON iam_user_roles(role_id);
CREATE TABLE iam_oauth_tokens(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid, token_type text NOT NULL DEFAULT 'access_token', refresh_token text, is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), idp_session_id uuid, token_family_id uuid, session_id uuid);
CREATE TABLE iam_sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid not null references iam_users(id), is_active bool not null default true, ended_at timestamptz, end_reason text);
CREATE TABLE iam_audit_log(id uuid primary key default gen_random_uuid(), tenant_id uuid, user_id uuid, target_user_id uuid, action text, resource_type text, resource_id uuid, details jsonb, ip_address text, country_code text, user_agent text, success bool, error_message text, created_at timestamptz default now());`)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewUserRepository(pool)
	require.NoError(t, execTest(pool, testsupport.PermissionOutboxDDL))
	tenant, actor, target := uuid.New(), uuid.New(), uuid.New()
	owner, member, orgAdmin, manager := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, u := range []uuid.UUID{actor, target} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, u, tenant)
		require.NoError(t, err)
	}
	for _, r := range []struct {
		id     uuid.UUID
		name   string
		p      int
		system bool
	}{{owner, "owner", 100, false}, {member, "member", 10, false}, {orgAdmin, "org_admin", 100, true}, {manager, "manager", 200, false}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_roles(id,tenant_id,name,priority,is_system) VALUES($1,$2,$3,$4,$5)`, r.id, tenant, r.name, r.p, r.system)
		require.NoError(t, err)
	}
	for _, g := range [][2]uuid.UUID{{actor, manager}, {target, member}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, g[0], g[1])
		require.NoError(t, err)
	}
	audit := func() *models.AuditLog {
		typ := "user"
		return &models.AuditLog{TenantID: tenant, UserID: &actor, TargetUserID: &target, Action: "team_roles_replace", ResourceType: &typ, ResourceID: &target, Details: map[string]interface{}{"result": "success"}, Success: true}
	}
	// Sole owner removal is rejected and creates neither an audit row nor a mutation.
	_, err = pool.Exec(ctx, `DELETE FROM iam_user_roles WHERE user_id=$1 AND role_id=$2`, target, member)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, target, owner)
	require.NoError(t, err)
	err = repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{owner, member}, []uuid.UUID{member}, audit())
	require.ErrorIs(t, err, ErrTeamLastAdministrator)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_audit_log`).Scan(&n))
	require.Zero(t, n)
	// org_admin is explicitly not an effective administrator; a replacement succeeds.
	_, err = pool.Exec(ctx, `DELETE FROM iam_user_roles WHERE user_id=$1`, target)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, target, orgAdmin)
	require.NoError(t, err)
	err = repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member}, []uuid.UUID{member}, audit())
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_audit_log WHERE action='team_roles_replace'`).Scan(&n))
	require.Equal(t, 1, n)
	// Production currently has system org_admin rows (priority 100), while
	// CreateSystemRoles creates system admin rows at the same priority. Neither
	// may become editable merely because a stale handler candidate included it.
	err = repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member, orgAdmin}, []uuid.UUID{orgAdmin}, audit())
	require.Error(t, err)
	var hasMemberGrant bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles WHERE user_id=$1 AND role_id=$2)`, target, member).Scan(&hasMemberGrant))
	require.True(t, hasMemberGrant)
	// Audit failure rolls back the editable delete/insert.
	_, err = pool.Exec(ctx, `ALTER TABLE iam_audit_log ADD CONSTRAINT fail_audit CHECK(false) NOT VALID`)
	require.NoError(t, err)
	err = repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member}, []uuid.UUID{member}, audit())
	require.Error(t, err)
	var preserved bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles WHERE user_id=$1 AND role_id=$2)`, target, member).Scan(&preserved))
	require.True(t, preserved)
}

func TestTeamInvitationPostgresUniqueContract(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "team_invite_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TABLE iam_team_invitations(id uuid primary key, tenant_id uuid not null, email text not null, email_normalized text generated always as (lower(btrim(email))) stored, role_ids uuid[] not null, invited_by uuid not null, token text not null, status text not null, seat_class text not null default 'member', last_resent_at timestamptz, expires_at timestamptz not null, created_at timestamptz not null default now(), accepted_at timestamptz);
CREATE UNIQUE INDEX idx_iam_team_invitations_pending_tenant_email_normalized_unique ON iam_team_invitations (tenant_id, email_normalized) WHERE status='pending';`)
	require.NoError(t, err)
	repo := NewTeamInvitationRepository(pool)
	tenant, actor, role := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().Add(time.Hour)
	first := &models.TeamInvitation{TenantID: tenant, Email: "member@example.test", RoleIDs: []uuid.UUID{role}, InvitedBy: actor, Token: "one", Status: models.TeamInvitationStatusPending, ExpiresAt: now}
	require.NoError(t, repo.Create(ctx, first))
	second := &models.TeamInvitation{TenantID: tenant, Email: " MEMBER@EXAMPLE.TEST ", RoleIDs: []uuid.UUID{role}, InvitedBy: actor, Token: "two", Status: models.TeamInvitationStatusPending, ExpiresAt: now}
	require.ErrorIs(t, repo.Create(ctx, second), ErrDuplicatePendingInvitation)
	// Expiry is a lifecycle transition, not a permanent uniqueness tombstone:
	// expire and re-invite in one transaction so concurrent creators still rely
	// on the partial unique index for the active invitation.
	require.NoError(t, repo.InTransaction(ctx, func(tx pgx.Tx) error {
		txRepo := repo.WithDB(tx)
		if _, err := tx.Exec(ctx, `UPDATE iam_team_invitations SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, first.ID); err != nil {
			return err
		}
		if _, err := txRepo.ExpirePendingForEmail(ctx, tenant, "MEMBER@example.test"); err != nil {
			return err
		}
		return txRepo.Create(ctx, second)
	}))
	var expiredStatus string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM iam_team_invitations WHERE id = $1`, first.ID).Scan(&expiredStatus))
	require.Equal(t, "expired", expiredStatus)
	var active int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_team_invitations WHERE tenant_id = $1 AND status = 'pending'`, tenant).Scan(&active))
	require.Equal(t, 1, active)
}

func TestRoleCataloguePostgresExcludesMixedModuleRoles(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "role_catalogue_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	require.NoError(t, func() error {
		_, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
		return err
	}())
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TABLE iam_roles(id uuid primary key, tenant_id uuid not null, name text not null, display_name text not null, description text, is_system bool not null default false, is_default bool not null default false, priority int not null default 0, created_at timestamptz not null default now(), updated_at timestamptz not null default now(), created_by uuid, updated_by uuid);
CREATE TABLE iam_permissions(id uuid primary key, module text not null);
CREATE TABLE iam_role_permissions(role_id uuid not null, permission_id uuid not null);`)
	require.NoError(t, err)
	tenant := uuid.New()
	pure, mixed, empty := uuid.New(), uuid.New(), uuid.New()
	core, paid := uuid.New(), uuid.New()
	for _, r := range []struct {
		id   uuid.UUID
		name string
	}{{pure, "pure"}, {mixed, "mixed"}, {empty, "empty"}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_roles(id, tenant_id, name, display_name) VALUES($1,$2,$3,$3)`, r.id, tenant, r.name)
		require.NoError(t, err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO iam_permissions(id,module) VALUES($1,'core'),($2,'billing')`, core, paid)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_role_permissions(role_id,permission_id) VALUES($1,$2),($3,$2),($3,$4)`, pure, core, mixed, paid)
	require.NoError(t, err)
	roles, total, err := NewRoleRepository(pool).ListForModules(ctx, tenant, 1, 20, "", []string{"core", "iam"})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	ids := map[uuid.UUID]bool{}
	for _, role := range roles {
		ids[role.ID] = true
	}
	require.True(t, ids[pure])
	require.True(t, ids[empty])
	require.False(t, ids[mixed])
}

func TestTeamInvitationPostgresTokenDigestAndLegacyLookup(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "team_delivery_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	require.NoError(t, func() error {
		_, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
		return err
	}())
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_team_invitations(id uuid primary key, tenant_id uuid not null, email text not null, role_ids uuid[] not null, invited_by uuid not null, token text not null, status text not null, seat_class text not null default 'member', last_resent_at timestamptz, expires_at timestamptz not null, created_at timestamptz not null default now(), accepted_at timestamptz);`)
	require.NoError(t, err)
	invRepo := NewTeamInvitationRepository(pool)
	tenant, actor, role := uuid.New(), uuid.New(), uuid.New()
	rawToken := "new-secret-token"
	digest := models.TeamInvitationTokenDigest(rawToken)
	inv := &models.TeamInvitation{TenantID: tenant, Email: "new@example.test", RoleIDs: []uuid.UUID{role}, InvitedBy: actor, Token: digest, Status: models.TeamInvitationStatusPending, ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, invRepo.Create(ctx, inv))

	resolved, err := invRepo.GetByToken(ctx, rawToken)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, inv.ID, resolved.ID)
	stolenDigest, err := invRepo.GetByToken(ctx, digest)
	require.NoError(t, err)
	require.Nil(t, stolenDigest, "a digest read from storage must not be accepted as a bearer token")

	legacy := &models.TeamInvitation{TenantID: tenant, Email: "legacy@example.test", RoleIDs: []uuid.UUID{role}, InvitedBy: actor, Token: "legacy-plaintext-token", Status: models.TeamInvitationStatusPending, ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, invRepo.Create(ctx, legacy))
	resolvedLegacy, err := invRepo.GetByToken(ctx, legacy.Token)
	require.NoError(t, err)
	require.NotNil(t, resolvedLegacy)
	require.Equal(t, legacy.ID, resolvedLegacy.ID)
}

func TestReplaceTeamRolesPostgresConcurrentAndBoundaries(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "team_bounds_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_users(id uuid primary key, tenant_id uuid not null, is_active bool not null, updated_at timestamptz not null default now());
CREATE TABLE iam_roles(id uuid primary key, tenant_id uuid not null, name text not null, priority int not null, is_system bool not null default false);
CREATE TABLE iam_user_roles(user_id uuid not null references iam_users(id), role_id uuid not null references iam_roles(id), assigned_by uuid, expires_at timestamptz, primary key(user_id,role_id));
CREATE INDEX iam_user_roles_role_id_idx ON iam_user_roles(role_id);
CREATE TABLE iam_audit_log(id uuid primary key default gen_random_uuid(), tenant_id uuid, user_id uuid, target_user_id uuid, action text, resource_type text, resource_id uuid, details jsonb, ip_address text, country_code text, user_agent text, success bool, error_message text, created_at timestamptz default now());`)
	require.NoError(t, err)
	repo := NewUserRepository(pool)
	require.NoError(t, execTest(pool, testsupport.PermissionOutboxDDL))
	tenant, actor := uuid.New(), uuid.New()
	owner, member, manager, org := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, r := range []struct {
		id       uuid.UUID
		name     string
		priority int
	}{{owner, "owner", 100}, {member, "member", 10}, {manager, "manager", 200}, {org, "org_admin", 90}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_roles(id,tenant_id,name,priority) VALUES($1,$2,$3,$4)`, r.id, tenant, r.name, r.priority)
		require.NoError(t, err)
	}
	users := []uuid.UUID{actor, uuid.New(), uuid.New(), uuid.New()}
	for _, u := range users {
		_, err = pool.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,$3)`, u, tenant, true)
		require.NoError(t, err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, actor, manager)
	require.NoError(t, err)
	for _, u := range users[1:3] {
		_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, u, owner)
		require.NoError(t, err)
	}
	audit := func(target uuid.UUID) *models.AuditLog {
		typ := "user"
		return &models.AuditLog{TenantID: tenant, UserID: &actor, TargetUserID: &target, Action: "team_roles_replace", ResourceType: &typ, ResourceID: &target, Details: map[string]interface{}{"result": "success", "requested_role_count": 1}, Success: true}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, target := range users[1:3] {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			results <- repo.ReplaceTeamRoles(ctx, tenant, actor, id, []uuid.UUID{owner, member}, []uuid.UUID{member}, audit(id))
		}(target)
	}
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrTeamLastAdministrator) {
			rejected++
		} else {
			t.Fatalf("unexpected concurrent error: %v", e)
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, rejected)
	var activeAdmins int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(DISTINCT u.id) FROM iam_users u JOIN iam_user_roles ur ON ur.user_id=u.id JOIN iam_roles r ON r.id=ur.role_id WHERE u.is_active AND r.name IN ('owner','admin') AND (ur.expires_at IS NULL OR ur.expires_at>NOW())`).Scan(&activeAdmins))
	require.Equal(t, 1, activeAdmins)
	// Repository-local actor validation rejects inactive and cross-tenant actors
	// before priority/final-admin authorization can run.
	_, err = pool.Exec(ctx, `UPDATE iam_users SET is_active=false WHERE id=$1`, actor)
	require.NoError(t, err)
	err = repo.SetTeamMemberActive(ctx, tenant, actor, users[1], true)
	require.ErrorIs(t, err, ErrTeamActorNotActive)
	_, err = pool.Exec(ctx, `UPDATE iam_users SET is_active=true WHERE id=$1`, actor)
	require.NoError(t, err)
	err = repo.SetTeamMemberActive(ctx, tenant, uuid.New(), users[1], true)
	require.ErrorIs(t, err, ErrTeamActorNotActive)
	// Inactive and expired owner grants are not classified as active administrators.
	inactive := users[3]
	_, err = pool.Exec(ctx, `UPDATE iam_users SET is_active=false WHERE id=$1`, inactive)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id,expires_at) VALUES($1,$2,NOW()-INTERVAL '1 hour')`, inactive, owner)
	require.NoError(t, err)
	// Preserve a grant outside the editable intersection exactly.
	winner := users[1]
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, winner, org)
	require.NoError(t, err)
	err = repo.ReplaceTeamRoles(ctx, tenant, actor, winner, []uuid.UUID{member}, []uuid.UUID{member}, audit(winner))
	require.NoError(t, err)
	var preserved bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles WHERE user_id=$1 AND role_id=$2)`, winner, org).Scan(&preserved))
	require.True(t, preserved)
	// Equal-priority and unknown/other-tenant requested roles fail before audit.
	err = repo.ReplaceTeamRoles(ctx, tenant, winner, winner, []uuid.UUID{member}, []uuid.UUID{member}, audit(winner))
	require.ErrorIs(t, err, ErrTeamTargetPriority)
	foreign := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO iam_roles(id,tenant_id,name,priority) VALUES($1,$2,'member',1)`, foreign, uuid.New())
	require.NoError(t, err)
	err = repo.ReplaceTeamRoles(ctx, tenant, actor, winner, []uuid.UUID{foreign}, []uuid.UUID{foreign}, audit(winner))
	require.Error(t, err)
}

func TestReplaceTeamRolesPostgresLockedCandidateAndRollback(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "team_lock_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	require.NoError(t, func() error {
		_, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
		return err
	}())
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_users(id uuid primary key, tenant_id uuid not null, is_active bool not null, updated_at timestamptz not null default now());
CREATE TABLE iam_roles(id uuid primary key, tenant_id uuid not null, name text not null, priority int not null, is_system bool not null default false);
CREATE TABLE iam_user_roles(user_id uuid not null references iam_users(id), role_id uuid not null references iam_roles(id), assigned_by uuid, expires_at timestamptz, primary key(user_id,role_id));
CREATE INDEX iam_user_roles_role_id_idx ON iam_user_roles(role_id);
CREATE TABLE iam_audit_log(id uuid primary key default gen_random_uuid(), tenant_id uuid, user_id uuid, target_user_id uuid, action text, resource_type text, resource_id uuid, details jsonb, ip_address text, country_code text, user_agent text, success bool, error_message text, created_at timestamptz default now());`)
	require.NoError(t, err)
	repo := NewUserRepository(pool)
	require.NoError(t, execTest(pool, testsupport.PermissionOutboxDDL))
	tenant, actor, target := uuid.New(), uuid.New(), uuid.New()
	manager, member, systemAdmin := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{actor, target} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, id, tenant)
		require.NoError(t, err)
	}
	for _, role := range []struct {
		id       uuid.UUID
		name     string
		priority int
		system   bool
	}{{manager, "manager", 200, false}, {member, "member", 10, false}, {systemAdmin, "admin", 100, true}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_roles VALUES($1,$2,$3,$4,$5)`, role.id, tenant, role.name, role.priority, role.system)
		require.NoError(t, err)
	}
	for _, grant := range [][2]uuid.UUID{{actor, manager}, {target, member}} {
		_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, grant[0], grant[1])
		require.NoError(t, err)
	}
	typ := "user"
	audit := func() *models.AuditLog {
		return &models.AuditLog{TenantID: tenant, UserID: &actor, TargetUserID: &target, Action: "team_roles_replace", ResourceType: &typ, ResourceID: &target, Details: map[string]interface{}{"result": "success", "requested_role_count": 1}, Success: true}
	}

	// Hold the candidate row exclusively. ReplaceTeamRoles must wait for its
	// FOR SHARE lock and classify the value committed by the concurrent writer.
	locker, err := pool.Acquire(ctx)
	require.NoError(t, err)
	tx, err := locker.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT id FROM iam_roles WHERE id=$1 FOR UPDATE`, member)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		result <- repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member}, []uuid.UUID{member}, audit())
	}()
	_, err = tx.Exec(ctx, `UPDATE iam_roles SET is_system=true, priority=100 WHERE id=$1`, member)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	locker.Release()
	require.Error(t, <-result, "the committed system value, not a stale candidate, is authoritative")

	_, err = pool.Exec(ctx, `UPDATE iam_roles SET is_system=false, priority=10 WHERE id=$1`, member)
	require.NoError(t, err)
	// A failed DELETE rolls back before any requested insertion.
	_, err = pool.Exec(ctx, `CREATE FUNCTION fail_team_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'delete failure'; END $$; CREATE TRIGGER fail_team_delete BEFORE DELETE ON iam_user_roles FOR EACH ROW EXECUTE FUNCTION fail_team_delete();`)
	require.NoError(t, err)
	require.Error(t, repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member}, []uuid.UUID{member}, audit()))
	_, err = pool.Exec(ctx, `DROP TRIGGER fail_team_delete ON iam_user_roles; DROP FUNCTION fail_team_delete()`)
	require.NoError(t, err)
	// A failed INSERT restores the original editable grant too.
	_, err = pool.Exec(ctx, `CREATE FUNCTION fail_team_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'insert failure'; END $$; CREATE TRIGGER fail_team_insert BEFORE INSERT ON iam_user_roles FOR EACH ROW EXECUTE FUNCTION fail_team_insert();`)
	require.NoError(t, err)
	require.Error(t, repo.ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member}, []uuid.UUID{member}, audit()))
	var preserved bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iam_user_roles WHERE user_id=$1 AND role_id=$2)`, target, member).Scan(&preserved))
	require.True(t, preserved)
}

func TestSetTeamMemberActivePostgresCanonicalAdministratorRoles(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "team_life_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}()
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE TABLE iam_users(id uuid primary key, tenant_id uuid not null, username text NOT NULL DEFAULT 'person', is_active bool not null, updated_at timestamptz not null default now());
CREATE TABLE iam_roles(id uuid primary key, tenant_id uuid not null, name text not null, priority int not null, is_system bool not null default false);
CREATE TABLE iam_user_roles(user_id uuid not null references iam_users(id), role_id uuid not null references iam_roles(id), assigned_by uuid, expires_at timestamptz, primary key(user_id,role_id));
CREATE INDEX iam_user_roles_role_id_idx ON iam_user_roles(role_id);
CREATE TABLE iam_oauth_tokens(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid, token_type text NOT NULL DEFAULT 'access_token', refresh_token text, is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), idp_session_id uuid, token_family_id uuid, session_id uuid);
CREATE TABLE iam_sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid not null references iam_users(id), is_active bool not null default true, ended_at timestamptz, end_reason text);
CREATE TABLE iam_user_memberships(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, user_id uuid NOT NULL, seat_class text NOT NULL DEFAULT 'member', status text NOT NULL DEFAULT 'active', invitation_id uuid, created_at timestamptz NOT NULL DEFAULT now(), deactivated_at timestamptz, access_expires_at timestamptz, UNIQUE(tenant_id,user_id));
CREATE TABLE tenant_seat_counters(tenant_id uuid PRIMARY KEY, seats_used int NOT NULL DEFAULT 0, seats_pending int NOT NULL DEFAULT 0, seat_limit int, seat_limit_version bigint, seat_limit_computed_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now());`)
	require.NoError(t, err)
	repo := NewUserRepository(pool)
	tenant, actor := uuid.New(), uuid.New()
	manager := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, actor, tenant)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_roles VALUES($1,$2,'manager',200,false)`, manager, tenant)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, actor, manager)
	require.NoError(t, err)
	for _, name := range []string{"admin", "org_admin", "owner", "platform_admin", "super_admin"} {
		t.Run(name, func(t *testing.T) {
			_, err = pool.Exec(ctx, `DELETE FROM iam_user_roles WHERE user_id <> $1`, actor)
			require.NoError(t, err)
			_, err = pool.Exec(ctx, `DELETE FROM iam_users WHERE id <> $1`, actor)
			require.NoError(t, err)
			_, err = pool.Exec(ctx, `DELETE FROM iam_roles WHERE id <> $1`, manager)
			require.NoError(t, err)
			role, one, two := uuid.New(), uuid.New(), uuid.New()
			_, err := pool.Exec(ctx, `INSERT INTO iam_roles VALUES($1,$2,$3,100,true)`, role, tenant, name)
			require.NoError(t, err)
			for _, user := range []uuid.UUID{one, two} {
				_, err = pool.Exec(ctx, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, user, tenant)
				require.NoError(t, err)
				_, err = pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, user, role)
				require.NoError(t, err)
			}
			// Final two serializes through the tenant advisory lock: exactly one
			// deactivation commits, retaining one active canonical administrator.
			results := make(chan error, 2)
			start := make(chan struct{})
			for _, target := range []uuid.UUID{one, two} {
				go func(id uuid.UUID) { <-start; results <- repo.SetTeamMemberActive(ctx, tenant, actor, id, false) }(target)
			}
			close(start)
			success, rejected := 0, 0
			for range 2 {
				err := <-results
				if err == nil {
					success++
				} else if errors.Is(err, ErrTeamLastAdministrator) {
					rejected++
				} else {
					t.Fatalf("unexpected lifecycle error: %v", err)
				}
			}
			require.Equal(t, 1, success)
			require.Equal(t, 1, rejected)
			// The remaining final holder cannot be deactivated, but may be
			// reactivated idempotently; an expired grant is not an administrator.
			var active uuid.UUID
			require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM iam_users WHERE id=ANY($1) AND is_active`, []uuid.UUID{one, two}).Scan(&active))
			require.ErrorIs(t, repo.SetTeamMemberActive(ctx, tenant, actor, active, false), ErrTeamLastAdministrator)
		})
	}
}

func TestSetTeamMemberActivePostgres_LastOwnerWithOtherAdmin(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; use throwaway postgres")
	}
	pool, cleanup := newTeamPostgresFixture(t, dsn)
	defer cleanup()
	tenant, actor, owner, admin := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct {
		user     uuid.UUID
		role     string
		priority int
	}{
		{actor, "manager", 200}, {owner, "owner", 100}, {admin, "admin", 100},
	} {
		require.NoError(t, execTest(pool, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, row.user, tenant))
		roleID := uuid.New()
		require.NoError(t, execTest(pool, `INSERT INTO iam_roles(id,tenant_id,name,priority) VALUES($1,$2,$3,$4)`, roleID, tenant, row.role, row.priority))
		require.NoError(t, execTest(pool, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, row.user, roleID))
	}
	require.NoError(t, execTest(pool, `INSERT INTO iam_sessions(user_id) VALUES($1)`, owner))
	before := teamMutationSnapshot(t, pool)
	repo := NewUserRepository(pool)
	require.ErrorIs(t, repo.SetTeamMemberActive(context.Background(), tenant, actor, owner, false), ErrTeamLastAdministrator)
	require.Equal(t, before, teamMutationSnapshot(t, pool), "last owner rejection changes no users, grants, sessions or audits")
	require.ErrorIs(t, repo.SetTeamMemberActive(context.Background(), tenant, actor, actor, false), ErrTeamSelfDeactivation)
}

// TestSetTeamMemberActivePostgresRejectionMatrix deliberately exercises only
// reject paths. Each row starts from the same production-shaped fixture and
// proves that a failed authorization has no observable member/session/audit
// side effect.
func TestSetTeamMemberActivePostgresRejectionMatrix(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, p *pgxpool.Pool, tenant, actor, target, manager, member, equal, higher, admin uuid.UUID) (uuid.UUID, uuid.UUID, bool)
		want  error
	}{
		{"actor_missing", func(t *testing.T, _ *pgxpool.Pool, _ uuid.UUID, _ uuid.UUID, target, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			return uuid.New(), target, false
		}, ErrTeamActorNotActive},
		{"actor_wrong_tenant", func(t *testing.T, p *pgxpool.Pool, _, actor, target, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `UPDATE iam_users SET tenant_id=$2 WHERE id=$1`, actor, uuid.New()))
			return actor, target, false
		}, ErrTeamActorNotActive},
		{"actor_inactive", func(t *testing.T, p *pgxpool.Pool, _ uuid.UUID, actor, target, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `UPDATE iam_users SET is_active=false WHERE id=$1`, actor))
			return actor, target, false
		}, ErrTeamActorNotActive},
		{"actor_no_roles", func(t *testing.T, p *pgxpool.Pool, _ uuid.UUID, actor, target, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `DELETE FROM iam_user_roles WHERE user_id=$1`, actor))
			return actor, target, false
		}, ErrTeamTargetPriority},
		{"actor_expired_only_role", func(t *testing.T, p *pgxpool.Pool, _ uuid.UUID, actor, target, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `UPDATE iam_user_roles SET expires_at=NOW()-INTERVAL '1 second' WHERE user_id=$1`, actor))
			return actor, target, false
		}, ErrTeamTargetPriority},
		{"target_missing", func(t *testing.T, _ *pgxpool.Pool, _ uuid.UUID, actor, _, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			return actor, uuid.New(), false
		}, ErrTeamTargetNotFound},
		{"target_wrong_tenant", func(t *testing.T, p *pgxpool.Pool, _ uuid.UUID, actor, target, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `UPDATE iam_users SET tenant_id=$2 WHERE id=$1`, target, uuid.New()))
			return actor, target, false
		}, ErrTeamTargetNotFound},
		{"target_equal_priority", func(t *testing.T, p *pgxpool.Pool, _ uuid.UUID, actor, target, _, _, equal, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `DELETE FROM iam_user_roles WHERE user_id=$1`, target))
			require.NoError(t, execTest(p, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, target, equal))
			return actor, target, false
		}, ErrTeamTargetPriority},
		{"target_higher_priority", func(t *testing.T, p *pgxpool.Pool, _ uuid.UUID, actor, target, _, _, _, higher, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			require.NoError(t, execTest(p, `DELETE FROM iam_user_roles WHERE user_id=$1`, target))
			require.NoError(t, execTest(p, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, target, higher))
			return actor, target, false
		}, ErrTeamTargetPriority},
		{"self_deactivate", func(t *testing.T, _ *pgxpool.Pool, _ uuid.UUID, actor, _, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			return actor, actor, false
		}, ErrTeamSelfDeactivation},
		{"self_reactivate", func(t *testing.T, _ *pgxpool.Pool, _ uuid.UUID, actor, _, _, _, _, _, _ uuid.UUID) (uuid.UUID, uuid.UUID, bool) {
			return actor, actor, true
		}, ErrTeamTargetPriority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, closeFixture := newTeamPostgresFixture(t, dsn)
			defer closeFixture()
			tenant, actor, target := uuid.New(), uuid.New(), uuid.New()
			manager, member, equal, higher, admin := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
			for _, u := range []uuid.UUID{actor, target} {
				require.NoError(t, execTest(p, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, u, tenant))
			}
			for _, r := range []struct {
				id       uuid.UUID
				name     string
				priority int
			}{{manager, "manager", 200}, {member, "member", 10}, {equal, "equal", 200}, {higher, "higher", 300}, {admin, "admin", 100}} {
				require.NoError(t, execTest(p, `INSERT INTO iam_roles(id,tenant_id,name,priority,is_system) VALUES($1,$2,$3,$4,false)`, r.id, tenant, r.name, r.priority))
			}
			require.NoError(t, execTest(p, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2),($3,$4)`, actor, manager, target, member))
			require.NoError(t, execTest(p, `INSERT INTO iam_sessions(user_id,is_active) VALUES($1,true)`, target))
			callActor, callTarget, active := tc.setup(t, p, tenant, actor, target, manager, member, equal, higher, admin)
			before := teamMutationSnapshot(t, p)
			err := NewUserRepository(p).SetTeamMemberActive(context.Background(), tenant, callActor, callTarget, active)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, teamMutationSnapshot(t, p), "rejections must not mutate users, sessions, grants, or audit")
		})
	}
}

func TestReplaceTeamRolesPostgresSetAndAuditContract(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	p, closeFixture := newTeamPostgresFixture(t, dsn)
	defer closeFixture()
	tenant, actor, target := uuid.New(), uuid.New(), uuid.New()
	manager, member, preserved := uuid.New(), uuid.New(), uuid.New()
	for _, u := range []uuid.UUID{actor, target} {
		require.NoError(t, execTest(p, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, u, tenant))
	}
	for _, r := range []struct {
		id       uuid.UUID
		name     string
		priority int
	}{{manager, "manager", 200}, {member, "member", 10}, {preserved, "viewer", 1}} {
		require.NoError(t, execTest(p, `INSERT INTO iam_roles(id,tenant_id,name,priority,is_system) VALUES($1,$2,$3,$4,false)`, r.id, tenant, r.name, r.priority))
	}
	require.NoError(t, execTest(p, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2),($3,$4),($3,$5)`, actor, manager, target, member, preserved))
	typ := "user"
	audit := &models.AuditLog{TenantID: tenant, UserID: &actor, TargetUserID: &target, Action: "team_roles_replace", ResourceType: &typ, ResourceID: &target, Details: map[string]interface{}{"result": "success", "requested_role_count": 1}, Success: true}
	// Duplicate IDs are normalized, rather than becoming duplicate grants or a
	// second audit interpretation. The non-editable viewer remains untouched.
	require.NoError(t, NewUserRepository(p).ReplaceTeamRoles(context.Background(), tenant, actor, target, []uuid.UUID{member, member}, []uuid.UUID{member, member}, audit))
	var grants, audits int
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_user_roles WHERE user_id=$1`, target).Scan(&grants))
	require.Equal(t, 2, grants)
	require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM iam_audit_log`).Scan(&audits))
	require.Equal(t, 1, audits)
	var gotTenant, gotActor, gotTarget, resourceID uuid.UUID
	var action, resourceType, details string
	var success bool
	var errMessage *string
	require.NoError(t, p.QueryRow(context.Background(), `SELECT tenant_id,user_id,target_user_id,action,resource_type,resource_id,details::text,success,error_message FROM iam_audit_log`).Scan(&gotTenant, &gotActor, &gotTarget, &action, &resourceType, &resourceID, &details, &success, &errMessage))
	require.Equal(t, tenant, gotTenant)
	require.Equal(t, actor, gotActor)
	require.Equal(t, target, gotTarget)
	require.Equal(t, "team_roles_replace", action)
	require.Equal(t, "user", resourceType)
	require.Equal(t, target, resourceID)
	require.True(t, success)
	require.Nil(t, errMessage)
	require.JSONEq(t, `{"requested_role_count":1,"result":"success"}`, details)
	for _, forbidden := range []string{"email", "token", "session", "role_id", "roles"} {
		require.NotContains(t, strings.ToLower(details), forbidden)
	}
}

// TestReplaceTeamRolesPostgresAuthorizationLocks is intentionally driven by a
// database advisory barrier, not a timer: the trigger is reached only after
// the repository has locked the authorization catalogue rows. PostgreSQL must
// then reject each conflicting writer within lock_timeout.
func TestReplaceTeamRolesPostgresAuthorizationLocks(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh")
	}
	for round := 0; round < 2; round++ {
		for _, tc := range []struct {
			name  string
			write func(context.Context, *pgx.Conn, uuid.UUID, uuid.UUID) error
		}{
			{"tenant_change", func(ctx context.Context, c *pgx.Conn, role, _ uuid.UUID) error {
				_, err := c.Exec(ctx, `UPDATE iam_roles SET tenant_id=$2 WHERE id=$1`, role, uuid.New())
				return err
			}},
			{"priority_and_system_change", func(ctx context.Context, c *pgx.Conn, role, _ uuid.UUID) error {
				_, err := c.Exec(ctx, `UPDATE iam_roles SET priority=99,is_system=true WHERE id=$1`, role)
				return err
			}},
			{"delete", func(ctx context.Context, c *pgx.Conn, role, _ uuid.UUID) error {
				_, err := c.Exec(ctx, `DELETE FROM iam_roles WHERE id=$1`, role)
				return err
			}},
			{"fk_key_share_insert", func(ctx context.Context, c *pgx.Conn, role, user uuid.UUID) error {
				_, err := c.Exec(ctx, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2)`, user, role)
				return err
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p, closeFixture := newTeamPostgresFixture(t, dsn)
				defer closeFixture()
				ctx := context.Background()
				var schema string
				require.NoError(t, p.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema))
				tenant, actor, target, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
				manager, member := uuid.New(), uuid.New()
				for _, u := range []uuid.UUID{actor, target, other} {
					require.NoError(t, execTest(p, `INSERT INTO iam_users(id,tenant_id,is_active) VALUES($1,$2,true)`, u, tenant))
				}
				for _, r := range []struct {
					id       uuid.UUID
					name     string
					priority int
				}{{manager, "manager", 200}, {member, "member", 10}} {
					require.NoError(t, execTest(p, `INSERT INTO iam_roles(id,tenant_id,name,priority,is_system) VALUES($1,$2,$3,$4,false)`, r.id, tenant, r.name, r.priority))
				}
				require.NoError(t, execTest(p, `INSERT INTO iam_user_roles(user_id,role_id) VALUES($1,$2),($3,$4)`, actor, manager, target, member))
				// The trigger parks the replacement after its authorization locks.
				require.NoError(t, execTest(p, `CREATE FUNCTION team_lock_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(987654); RETURN OLD; END $$; CREATE TRIGGER team_lock_barrier BEFORE DELETE ON iam_user_roles FOR EACH ROW EXECUTE FUNCTION team_lock_barrier()`))
				barrier, err := pgx.Connect(ctx, dsn)
				require.NoError(t, err)
				defer func() { _ = barrier.Close(ctx) }()
				require.NoError(t, execConn(barrier, `SELECT pg_advisory_lock(987654)`))
				result := make(chan error, 1)
				go func() {
					result <- NewUserRepository(p).ReplaceTeamRoles(ctx, tenant, actor, target, []uuid.UUID{member}, []uuid.UUID{}, nil)
				}()
				waitForAdvisoryBarrier(t, p)
				writer, err := pgx.Connect(ctx, dsn)
				require.NoError(t, err)
				defer func() { _ = writer.Close(ctx) }()
				require.NoError(t, execConn(writer, `SET search_path TO `+pgx.Identifier{schema}.Sanitize()))
				require.NoError(t, execConn(writer, `SET lock_timeout='300ms'`))
				err = tc.write(ctx, writer, member, other)
				require.Error(t, err)
				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr)
				require.Equal(t, "55P03", pgErr.Code)
				require.NoError(t, execConn(barrier, `SELECT pg_advisory_unlock(987654)`))
				select {
				case err := <-result:
					require.NoError(t, err)
				case <-time.After(2 * time.Second):
					t.Fatal("replacement did not complete after barrier release")
				}
			})
		}
	}
}

func newTeamPostgresFixture(t *testing.T, dsn string) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()
	schema := "team_release_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	require.NoError(t, execConn(admin, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()))
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	require.NoError(t, execTest(p, `CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, username text NOT NULL DEFAULT 'person', is_active boolean NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL, priority integer NOT NULL CHECK(priority >= 0), is_system boolean NOT NULL DEFAULT false);
CREATE TABLE iam_user_roles(user_id uuid NOT NULL REFERENCES iam_users(id) ON DELETE RESTRICT, role_id uuid NOT NULL REFERENCES iam_roles(id) ON DELETE RESTRICT, assigned_by uuid, expires_at timestamptz, PRIMARY KEY(user_id,role_id)); CREATE INDEX iam_user_roles_role_id_idx ON iam_user_roles(role_id);
CREATE TABLE iam_oauth_tokens(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid, token_type text NOT NULL DEFAULT 'access_token', refresh_token text, is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), idp_session_id uuid, token_family_id uuid, session_id uuid);
CREATE TABLE iam_sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES iam_users(id), is_active boolean NOT NULL DEFAULT true, ended_at timestamptz, end_reason text);
CREATE TABLE iam_user_memberships(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, user_id uuid NOT NULL, seat_class text NOT NULL DEFAULT 'member', status text NOT NULL DEFAULT 'active', invitation_id uuid, created_at timestamptz NOT NULL DEFAULT now(), deactivated_at timestamptz, access_expires_at timestamptz, UNIQUE(tenant_id,user_id));
CREATE TABLE tenant_seat_counters(tenant_id uuid PRIMARY KEY, seats_used int NOT NULL DEFAULT 0, seats_pending int NOT NULL DEFAULT 0, seat_limit int, seat_limit_version bigint, seat_limit_computed_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE iam_audit_log(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid, target_user_id uuid, action text, resource_type text, resource_id uuid, details jsonb, ip_address text, country_code text, user_agent text, success boolean, error_message text, created_at timestamptz DEFAULT now());`))
	require.NoError(t, execTest(p, testsupport.PermissionOutboxDDL))
	return p, func() {
		p.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close(ctx)
	}
}

func execTest(p *pgxpool.Pool, sql string, args ...interface{}) error {
	_, err := p.Exec(context.Background(), sql, args...)
	return err
}

func waitForAdvisoryBarrier(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting int
		require.NoError(t, p.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND wait_event='advisory'`).Scan(&waiting))
		if waiting > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("repository never reached authorization-lock barrier")
		case <-tick.C:
		}
	}
}
func execConn(c *pgx.Conn, sql string, args ...interface{}) error {
	_, err := c.Exec(context.Background(), sql, args...)
	return err
}
func teamMutationSnapshot(t *testing.T, p *pgxpool.Pool) string {
	t.Helper()
	var s string
	require.NoError(t, p.QueryRow(context.Background(), `SELECT (SELECT coalesce(string_agg(id::text || ':' || tenant_id::text || ':' || is_active::text, ',' ORDER BY id), '') FROM iam_users) || '|' || (SELECT coalesce(string_agg(user_id::text || ':' || role_id::text || ':' || coalesce(expires_at::text,''), ',' ORDER BY user_id,role_id), '') FROM iam_user_roles) || '|' || (SELECT coalesce(string_agg(user_id::text || ':' || is_active::text || ':' || coalesce(end_reason,''), ',' ORDER BY user_id), '') FROM iam_sessions) || '|' || (SELECT count(*)::text FROM iam_audit_log)`).Scan(&s))
	return s
}
