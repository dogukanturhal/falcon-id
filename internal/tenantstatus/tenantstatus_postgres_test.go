// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantstatus

// Real-Postgres coverage (TEST_DATABASE_URL; skips otherwise): idempotency,
// ordering, revocation-on-suspend, resume, protected tenant, fail-open gate.
// Run with hack/run-tenantstatus-postgres-tests.sh.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set -- skipping real-Postgres tenantstatus tests")
	}
	ctx := context.Background()
	schema := "ts_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
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

	// Minimal stubs of the tables the revocation sweep touches. Column names
	// mirror the production schema; roles are cluster-wide so create the app
	// role idempotently (migration 0018 GRANTs to it).
	_, err = pool.Exec(ctx, `
DO $$ BEGIN CREATE ROLE falcon_id_app NOLOGIN; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
CREATE TABLE iam_users (id uuid PRIMARY KEY, tenant_id uuid NOT NULL);
CREATE TABLE iam_sessions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL,
  is_active boolean NOT NULL DEFAULT true, ended_at timestamptz, end_reason text);
CREATE TABLE iam_oauth_tokens (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  user_id uuid, token_type text NOT NULL DEFAULT 'access_token', refresh_token text,
  is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(),
  idp_session_id uuid, token_family_id uuid, session_id uuid);`)
	require.NoError(t, err)
	mig, err := os.ReadFile("../migrations/0018_iam_tenant_status.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(mig))
	require.NoError(t, err)
	return pool
}

type seeded struct{ tenant, user uuid.UUID }

func seed(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID) seeded {
	t.Helper()
	ctx := context.Background()
	user := uuid.New()
	_, err := pool.Exec(ctx, `INSERT INTO iam_users(id, tenant_id) VALUES($1,$2)`, user, tenant)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = pool.Exec(ctx, `INSERT INTO iam_sessions(user_id) VALUES($1)`, user)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO iam_oauth_tokens(tenant_id, user_id, refresh_token) VALUES($1,$2,'r')`, tenant, user)
		require.NoError(t, err)
	}
	return seeded{tenant, user}
}

func counts(t *testing.T, pool *pgxpool.Pool, s seeded) (activeSessions, liveTokens int) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_sessions WHERE user_id=$1 AND is_active`, s.user).Scan(&activeSessions))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_oauth_tokens WHERE tenant_id=$1 AND NOT is_revoked`, s.tenant).Scan(&liveTokens))
	return
}

func evt(tenant uuid.UUID, status string, version int64) Event {
	return Event{TenantID: tenant, Status: status, EventVersion: version, EventTime: time.Now().UTC()}
}

func TestApply_SuspendRevokesOnlyThatTenantsSessionsAndTokens(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	ctx := context.Background()
	a := seed(t, pool, uuid.New())
	b := seed(t, pool, uuid.New())

	res, err := repo.Apply(ctx, evt(a.tenant, "suspended", 10))
	require.NoError(t, err)
	assert.Equal(t, ResultApplied, res)

	s, tk := counts(t, pool, a)
	assert.Equal(t, 0, s, "all sessions of the suspended tenant revoked")
	assert.Equal(t, 0, tk, "all oauth tokens (access+refresh) of the suspended tenant revoked")
	var reason string
	require.NoError(t, pool.QueryRow(ctx, `SELECT end_reason FROM iam_sessions WHERE user_id=$1 LIMIT 1`, a.user).Scan(&reason))
	assert.Equal(t, EndReasonTenantSuspended, reason)

	s, tk = counts(t, pool, b)
	assert.Equal(t, 2, s, "other tenants untouched")
	assert.Equal(t, 2, tk)

	sus, err := repo.IsSuspended(ctx, a.tenant)
	require.NoError(t, err)
	assert.True(t, sus)
}

// A suspension also revokes tokens of the tenant's USERS whose tenant_id is the
// CLIENT's tenant (cross-tenant client), session-bound or legacy-unbound, and
// the session-bound ones go through the shared end-and-sweep statement.
func TestApply_SuspendRevokesTokensOfTenantUsersIssuedByForeignClients(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	ctx := context.Background()
	a := seed(t, pool, uuid.New())
	b := seed(t, pool, uuid.New())

	var sessA uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM iam_sessions WHERE user_id=$1 LIMIT 1`, a.user).Scan(&sessA))
	foreignClientTenant := b.tenant // token.tenant_id = the client's tenant, not the user's
	_, err := pool.Exec(ctx, `INSERT INTO iam_oauth_tokens(tenant_id, user_id, session_id) VALUES ($1,$2,$3), ($1,$2,NULL)`,
		foreignClientTenant, a.user, sessA)
	require.NoError(t, err)

	_, err = repo.Apply(ctx, evt(a.tenant, "suspended", 10))
	require.NoError(t, err)

	var live int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_oauth_tokens WHERE user_id=$1 AND NOT is_revoked`, a.user).Scan(&live))
	assert.Equal(t, 0, live, "bound and legacy tokens of the suspended tenant's user are revoked")
	_, tk := counts(t, pool, b)
	assert.Equal(t, 2, tk, "the other tenant's own tokens are untouched")
}

func TestApply_IdempotentRedeliveryDoesNotRerunRevocation(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	ctx := context.Background()
	a := seed(t, pool, uuid.New())

	_, err := repo.Apply(ctx, evt(a.tenant, "suspended", 10))
	require.NoError(t, err)

	// A new session appears (e.g. created by a stale pod); a redelivered
	// duplicate of the same event must be a no-op and not touch it.
	_, err = pool.Exec(ctx, `INSERT INTO iam_sessions(user_id) VALUES($1)`, a.user)
	require.NoError(t, err)

	res, err := repo.Apply(ctx, evt(a.tenant, "suspended", 10))
	require.NoError(t, err)
	assert.Equal(t, ResultSkipped, res, "same event_version is a duplicate")
	s, _ := counts(t, pool, a)
	assert.Equal(t, 1, s, "duplicate delivery must not re-run the revocation sweep")
}

func TestApply_OrderingStaleEventsNeverRegressState(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	ctx := context.Background()
	tenant := uuid.New()
	seed(t, pool, tenant)

	// Arrival order: v30 resume, then older v20 suspend (out of order), then v10 resume.
	res, err := repo.Apply(ctx, evt(tenant, "active", 30))
	require.NoError(t, err)
	assert.Equal(t, ResultApplied, res)
	res, err = repo.Apply(ctx, evt(tenant, "suspended", 20))
	require.NoError(t, err)
	assert.Equal(t, ResultSkipped, res, "older suspend arriving after a newer resume is ignored")
	res, err = repo.Apply(ctx, evt(tenant, "active", 10))
	require.NoError(t, err)
	assert.Equal(t, ResultSkipped, res)

	sus, err := repo.IsSuspended(ctx, tenant)
	require.NoError(t, err)
	assert.False(t, sus, "tenant stays resumed")

	// A genuinely newer suspend is applied.
	res, err = repo.Apply(ctx, evt(tenant, "suspended", 40))
	require.NoError(t, err)
	assert.Equal(t, ResultApplied, res)
	sus, _ = repo.IsSuspended(ctx, tenant)
	assert.True(t, sus)
}

func TestApply_ResumeReenablesAndGateFollows(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	gate := NewGate(repo, time.Hour, nil) // long TTL: only Invalidate can flip it
	ctx := context.Background()
	tenant := uuid.New()
	seed(t, pool, tenant)

	assert.False(t, gate.IsSuspended(ctx, tenant), "unknown tenant fails open")

	c := NewConsumer(repo, gate, nil, nil)
	require.NoError(t, c.Handle(ctx, envelope(tenant, "suspended", 5)))
	assert.True(t, gate.IsSuspended(ctx, tenant), "consumer invalidates the gate on apply")

	require.NoError(t, c.Handle(ctx, envelope(tenant, "active", 6)))
	assert.False(t, gate.IsSuspended(ctx, tenant), "resume re-enables")
}

func TestConsumer_ProtectedTenantNeverSuspended(t *testing.T) {
	pool := newPG(t)
	repo := NewRepository(pool)
	gate := NewGate(repo, time.Hour, nil)
	ctx := context.Background()
	hexxlock := uuid.MustParse("00000000-0000-0000-0000-000000000002")

	_, err := repo.Apply(ctx, evt(hexxlock, "suspended", 1))
	require.ErrorIs(t, err, ErrProtectedTenant)

	c := NewConsumer(repo, gate, nil, nil)
	require.NoError(t, c.Handle(ctx, envelope(hexxlock, "suspended", 2)), "rejected, not retried / DLQ'd")
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_tenant_status WHERE tenant_id=$1`, hexxlock).Scan(&n))
	assert.Equal(t, 0, n, "nothing persisted for the protected tenant")
	assert.False(t, gate.IsSuspended(ctx, hexxlock))
}

func TestConsumer_MalformedEventsArePermanentErrors(t *testing.T) {
	pool := newPG(t)
	c := NewConsumer(NewRepository(pool), nil, nil, nil)
	for _, bad := range []string{`not json`, `{"data":"x"}`, `{"data":{"status":"suspended"}}`, `{"data":{"tenant_id":"` + uuid.NewString() + `"}}`} {
		err := c.Handle(context.Background(), []byte(bad))
		var perm permanentError
		assert.True(t, errors.As(err, &perm), "payload %q must be permanent (DLQ)", bad)
	}
}

func envelope(tenant uuid.UUID, status string, version int64) []byte {
	b, _ := json.Marshal(map[string]any{
		"type":      "tenant.status.snapshot",
		"tenant_id": tenant.String(),
		"timestamp": time.Now().UTC(),
		"data":      map[string]any{"tenant_id": tenant.String(), "event_version": version, "status": status},
	})
	return b
}
