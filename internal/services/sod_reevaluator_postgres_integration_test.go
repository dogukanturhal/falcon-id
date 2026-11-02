// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// Real-Postgres tests for SoDReevaluator (run: hack/run-jit-postgres-tests.sh
// or hack/run-sod-postgres-tests.sh; both match -run 'Postgres').

const (
	sodPermCreate  = "accounting:journal_entries:create"
	sodPermApprove = "accounting:journal_entries:approve"
)

type sodAuditRecorder struct {
	mu     sync.Mutex
	events []string
}

func (a *sodAuditRecorder) LogUserAction(_ context.Context, _ uuid.UUID, _, _ *uuid.UUID, action string, _ bool, _ map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, action)
}

func (a *sodAuditRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

type sodPG struct {
	pool   *pgxpool.Pool
	repo   *repositories.SoDRepository
	reeval *SoDReevaluator
	audit  *sodAuditRecorder
	tenant uuid.UUID
}

func newSoDPG(t *testing.T) *sodPG {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-sod-postgres-tests.sh")
	}
	ctx := context.Background()
	schema := "sod_reeval_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
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

	_, err = pool.Exec(ctx, `CREATE TABLE iam_tenants(id uuid PRIMARY KEY);
CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL);
CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL);
CREATE TABLE iam_permissions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL);
CREATE TABLE iam_role_permissions(role_id uuid NOT NULL, permission_id uuid NOT NULL);
CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, expires_at timestamptz, PRIMARY KEY(user_id, role_id));`)
	require.NoError(t, err)
	// Migration 0015 GRANTs to the prod app role; roles are cluster-wide, so
	// create it idempotently and tolerate a concurrent creator.
	_, err = pool.Exec(ctx, `DO $$ BEGIN CREATE ROLE falcon_id_app NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;`)
	require.NoError(t, err)
	mig, err := os.ReadFile("../migrations/0015_iam_sod.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(mig))
	require.NoError(t, err)

	tenant := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO iam_tenants(id) VALUES($1)`, tenant)
	require.NoError(t, err)

	repo := repositories.NewSoDRepository(pool)
	audit := &sodAuditRecorder{}
	return &sodPG{
		pool: pool, repo: repo, audit: audit, tenant: tenant,
		reeval: NewSoDReevaluator(repo, repositories.NewPermissionRepository(pool), audit, pool),
	}
}

// role creates a role holding the given permissions.
func (p *sodPG) role(t *testing.T, perms ...string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	_, err := p.pool.Exec(ctx, `INSERT INTO iam_roles(id, tenant_id, name) VALUES($1,$2,$3)`, id, p.tenant, "r-"+id.String()[:8])
	require.NoError(t, err)
	for _, perm := range perms {
		_, err = p.pool.Exec(ctx, `INSERT INTO iam_permissions(name) VALUES($1) ON CONFLICT DO NOTHING`, perm)
		require.NoError(t, err)
		_, err = p.pool.Exec(ctx, `INSERT INTO iam_role_permissions(role_id, permission_id) SELECT $1, id FROM iam_permissions WHERE name=$2`, id, perm)
		require.NoError(t, err)
	}
	return id
}

func (p *sodPG) user(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := p.pool.Exec(context.Background(), `INSERT INTO iam_users(id, tenant_id) VALUES($1,$2)`, id, p.tenant)
	require.NoError(t, err)
	return id
}

func (p *sodPG) assign(t *testing.T, user, role uuid.UUID, expiresSQL string) {
	t.Helper()
	_, err := p.pool.Exec(context.Background(),
		`INSERT INTO iam_user_roles(user_id, role_id, expires_at) VALUES($1,$2,`+expiresSQL+`)`, user, role)
	require.NoError(t, err)
}

func (p *sodPG) openViolations(t *testing.T, user uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM iam_sod_violations WHERE tenant_id=$1 AND user_id=$2 AND resolved_at IS NULL`, p.tenant, user).Scan(&n))
	return n
}

func TestSoDReevaluatorPostgres_DetectsOnceThenResolvesWithoutRevoking(t *testing.T) {
	p := newSoDPG(t)
	ctx := context.Background()
	maker, checker := p.role(t, sodPermCreate), p.role(t, sodPermApprove)
	u := p.user(t)
	p.assign(t, u, maker, "NULL")
	p.assign(t, u, checker, "NULL")

	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 1, p.openViolations(t, u), "maker+checker is a default-rule conflict")
	assert.Equal(t, 1, p.audit.count(), "one audit event for the newly opened violation")
	var detected1 string
	require.NoError(t, p.pool.QueryRow(ctx, `SELECT detected_at::text FROM iam_sod_violations WHERE user_id=$1`, u).Scan(&detected1))

	// Second pass: nothing new -> no extra audit event, detected_at preserved.
	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 1, p.audit.count())
	var detected2 string
	require.NoError(t, p.pool.QueryRow(ctx, `SELECT detected_at::text FROM iam_sod_violations WHERE user_id=$1`, u).Scan(&detected2))
	assert.Equal(t, detected1, detected2)

	// Warn mode: assignments untouched.
	var roles int
	require.NoError(t, p.pool.QueryRow(ctx, `SELECT count(*) FROM iam_user_roles WHERE user_id=$1`, u).Scan(&roles))
	assert.Equal(t, 2, roles)

	// Conflict removed -> violation resolved by the next pass.
	_, err := p.pool.Exec(ctx, `DELETE FROM iam_user_roles WHERE user_id=$1 AND role_id=$2`, u, checker)
	require.NoError(t, err)
	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 0, p.openViolations(t, u))

	// Re-introduced -> reopens and audits again.
	p.assign(t, u, checker, "NULL")
	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 1, p.openViolations(t, u))
	assert.Equal(t, 2, p.audit.count())
}

func TestSoDReevaluatorPostgres_ExpiredAssignmentsIgnored(t *testing.T) {
	p := newSoDPG(t)
	maker, checker := p.role(t, sodPermCreate), p.role(t, sodPermApprove)
	u := p.user(t)
	p.assign(t, u, maker, "NULL")
	p.assign(t, u, checker, "now() - interval '1 hour'")

	require.NoError(t, p.reeval.RunDaily(context.Background()))
	assert.Equal(t, 0, p.openViolations(t, u))
}

func TestSoDReevaluatorPostgres_DisablingOverrideSuppressesDefaultRule(t *testing.T) {
	p := newSoDPG(t)
	ctx := context.Background()
	maker, checker := p.role(t, sodPermCreate), p.role(t, sodPermApprove)
	u := p.user(t)
	p.assign(t, u, maker, "NULL")
	p.assign(t, u, checker, "NULL")
	require.NoError(t, p.reeval.RunDaily(ctx))
	require.Equal(t, 1, p.openViolations(t, u))

	svc := NewSoDService(p.repo, p.repo, repositories.NewPermissionRepository(p.pool))
	var def models.SoDRule
	rules, err := p.repo.ListDefaultRules(ctx)
	require.NoError(t, err)
	for _, r := range rules {
		if r.PermissionA == sodPermCreate && r.PermissionB == sodPermApprove {
			def = r
		}
	}
	require.NotEqual(t, uuid.Nil, def.ID)
	_, err = svc.CreateDisablingOverride(ctx, p.tenant, &def, nil)
	require.NoError(t, err)

	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 0, p.openViolations(t, u), "disabled-for-tenant default rule must resolve its violation")
}

func TestSoDReevaluatorPostgres_RuleChangeTriggersTenantReevaluation(t *testing.T) {
	p := newSoDPG(t)
	ctx := context.Background()
	a, b := p.role(t, "crm:deals:create"), p.role(t, "crm:deals:approve")
	u := p.user(t)
	p.assign(t, u, a, "NULL")
	p.assign(t, u, b, "NULL")
	require.NoError(t, p.reeval.RunDaily(ctx))
	require.Equal(t, 0, p.openViolations(t, u))

	svc := NewSoDService(p.repo, p.repo, repositories.NewPermissionRepository(p.pool))
	svc.SetRuleChangeHook(func(tenantID uuid.UUID) {
		require.NoError(t, p.reeval.ReevaluateTenant(ctx, tenantID)) // synchronous stand-in for the async hook
	})
	rule, err := svc.CreateRule(ctx, p.tenant, &models.CreateSoDRuleRequest{
		Module: "crm", PermissionA: "crm:deals:create", PermissionB: "crm:deals:approve",
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, p.openViolations(t, u), "new rule applies to existing assignments immediately")

	disabled := true
	_, err = svc.UpdateRule(ctx, p.tenant, rule.ID, &models.UpdateSoDRuleRequest{Disabled: &disabled})
	require.NoError(t, err)
	assert.Equal(t, 0, p.openViolations(t, u), "disabling the rule resolves the violation")
}

func TestSoDReevaluatorPostgres_NonLeaderSkipsPass(t *testing.T) {
	p := newSoDPG(t)
	ctx := context.Background()
	maker, checker := p.role(t, sodPermCreate), p.role(t, sodPermApprove)
	u := p.user(t)
	p.assign(t, u, maker, "NULL")
	p.assign(t, u, checker, "NULL")

	// Another "replica" holds the leader lock on its own session.
	other, err := p.pool.Acquire(ctx)
	require.NoError(t, err)
	var got bool
	require.NoError(t, other.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", advisoryLockSoDReevaluator).Scan(&got))
	require.True(t, got)

	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 0, p.openViolations(t, u), "non-leader must not evaluate")

	_, err = other.Exec(ctx, "SELECT pg_advisory_unlock($1)", advisoryLockSoDReevaluator)
	require.NoError(t, err)
	other.Release()
	require.NoError(t, p.reeval.RunDaily(ctx))
	assert.Equal(t, 1, p.openViolations(t, u), "leader runs once the lock is free")
}

