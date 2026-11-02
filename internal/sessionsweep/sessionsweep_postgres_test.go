// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionsweep

// Real-Postgres coverage of the end-and-sweep statement (TEST_DATABASE_URL;
// skips otherwise). Run with hack/run-team-postgres-tests.sh. The token table
// is built from its pre-0028 shape plus the REAL migration 0028, so the test
// also proves the column/index DDL the sweep depends on.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSweepPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set -- skipping real-Postgres sessionsweep tests")
	}
	ctx := context.Background()
	schema := "sw_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
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
CREATE TABLE iam_sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL,
  is_active boolean NOT NULL DEFAULT true, ended_at timestamptz, end_reason text);
CREATE TABLE iam_oauth_tokens(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid,
  is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(),
  idp_session_id uuid, token_family_id uuid);
-- the indexes production already has on this table (session_id's comes from 0028)
CREATE INDEX iam_oauth_tokens_idp_session_id_idx ON iam_oauth_tokens (idp_session_id) WHERE idp_session_id IS NOT NULL;
CREATE INDEX idx_iam_oauth_tokens_user ON iam_oauth_tokens (user_id);
CREATE INDEX idx_iam_oauth_tokens_family ON iam_oauth_tokens (token_family_id) WHERE token_family_id IS NOT NULL;`)
	require.NoError(t, err)
	mig, err := os.ReadFile("../migrations/0028_oauth_token_session_binding.sql")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(mig))
	require.NoError(t, err)
	return pool
}

type sweepFixture struct {
	t    *testing.T
	pool *pgxpool.Pool
}

func (f sweepFixture) session(user uuid.UUID, active bool, reason string) uuid.UUID {
	id := uuid.New()
	var r *string
	if reason != "" {
		r = &reason
	}
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO iam_sessions(id, user_id, is_active, end_reason) VALUES ($1,$2,$3,$4)`, id, user, active, r)
	require.NoError(f.t, err)
	return id
}

// token inserts a live token; any of session/idp/family may be nil.
func (f sweepFixture) token(user uuid.UUID, session, idp, family *uuid.UUID) uuid.UUID {
	id := uuid.New()
	_, err := f.pool.Exec(context.Background(),
		`INSERT INTO iam_oauth_tokens(id, user_id, session_id, idp_session_id, token_family_id) VALUES ($1,$2,$3,$4,$5)`,
		id, user, session, idp, family)
	require.NoError(f.t, err)
	return id
}

func (f sweepFixture) revoked(id uuid.UUID) bool {
	var r bool
	require.NoError(f.t, f.pool.QueryRow(context.Background(),
		`SELECT is_revoked FROM iam_oauth_tokens WHERE id = $1`, id).Scan(&r))
	return r
}

func ptr(u uuid.UUID) *uuid.UUID { return &u }

const endOne = `UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $2
	WHERE id = $1 AND (is_active = true OR end_reason IN (` + NonExplicitReasons + `)) RETURNING id, user_id`

func TestSessionSweepPostgres_ExplicitReasonRevokesBoundTokensAndFamilies(t *testing.T) {
	f := sweepFixture{t, newSweepPG(t)}
	user := uuid.New()
	s1, s2 := f.session(user, true, ""), f.session(user, true, "")

	byRow := f.token(user, ptr(s1), nil, nil)                // session_id match
	byIdp := f.token(user, nil, ptr(s1), nil)                // idp_session_id match only
	fam := uuid.New()                                        // family: a rotated parent bound to s1, a child re-bound to s2
	famParent := f.token(user, ptr(s1), nil, ptr(fam))       //
	famChild := f.token(user, ptr(s2), nil, ptr(fam))        // different session, same family -> must die
	otherSession := f.token(user, ptr(s2), nil, nil)         // untouched
	legacy := f.token(user, nil, nil, nil)                   // unbound -> untouched
	otherFam := f.token(user, ptr(s2), nil, ptr(uuid.New())) // untouched

	n, err := End(context.Background(), f.pool, endOne, "logout", "$1", s1, "logout")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "one session row ended")

	for name, id := range map[string]uuid.UUID{"session_id": byRow, "idp_session_id": byIdp, "family parent": famParent, "family child": famChild} {
		assert.True(t, f.revoked(id), name)
	}
	for name, id := range map[string]uuid.UUID{"other session": otherSession, "legacy unbound": legacy, "other family": otherFam} {
		assert.False(t, f.revoked(id), name)
	}
}

func TestSessionSweepPostgres_NonExplicitReasonKeepsTokens(t *testing.T) {
	f := sweepFixture{t, newSweepPG(t)}
	user := uuid.New()
	for _, reason := range []string{"expired", "inactivity_timeout", "session_regenerated", "session_regenerated_on_login"} {
		s := f.session(user, true, "")
		tok := f.token(user, ptr(s), ptr(s), nil)
		n, err := End(context.Background(), f.pool, endOne, reason, "$1", s, reason)
		require.NoError(t, err)
		assert.Equal(t, int64(1), n, reason)
		assert.False(t, f.revoked(tok), "%s must not revoke tokens", reason)
	}
}

// A retried explicit end on an already-ended session still sweeps, and a
// lapsed session is upgraded to the explicit reason.
func TestSessionSweepPostgres_IdempotentAndUpgradesLapsedReason(t *testing.T) {
	f := sweepFixture{t, newSweepPG(t)}
	user := uuid.New()

	done := f.session(user, false, "logout")
	tok := f.token(user, ptr(done), nil, nil)
	n, err := End(context.Background(), f.pool, endOne, "logout", "$1", done, "logout")
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "already ended: no row ended")
	assert.True(t, f.revoked(tok), "but the sweep still ran")

	lapsed := f.session(user, false, "inactivity_timeout")
	tok2 := f.token(user, ptr(lapsed), nil, nil)
	n, err = End(context.Background(), f.pool, endOne, "revoked", "$1", lapsed, "revoked")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	assert.True(t, f.revoked(tok2))
	var reason string
	require.NoError(t, f.pool.QueryRow(context.Background(), `SELECT end_reason FROM iam_sessions WHERE id=$1`, lapsed).Scan(&reason))
	assert.Equal(t, "revoked", reason, "lapsed reason upgraded to the explicit one")
}

func TestSessionSweepPostgres_BulkEndSweepsEveryEndedSession(t *testing.T) {
	f := sweepFixture{t, newSweepPG(t)}
	user, other := uuid.New(), uuid.New()
	a, b := f.session(user, true, ""), f.session(user, true, "")
	o := f.session(other, true, "")
	ta, tb := f.token(user, ptr(a), nil, nil), f.token(user, nil, ptr(b), nil)
	to := f.token(other, ptr(o), nil, nil)

	n, err := End(context.Background(), f.pool,
		`UPDATE iam_sessions SET is_active = false, ended_at = NOW(), end_reason = $2 WHERE user_id = $1 AND is_active = true RETURNING id, user_id`,
		"backchannel_logout", "", user, "backchannel_logout")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	assert.True(t, f.revoked(ta))
	assert.True(t, f.revoked(tb))
	assert.False(t, f.revoked(to), "other user's token untouched")
}

// The sweep runs on every explicit session end against a table that reaches
// 1M rows. Its plan must use the indexes (session_id / idp_session_id / family
// / user_id), never sequentially scan iam_oauth_tokens.
func TestSessionSweepPostgres_PlanUsesIndexesOn1MRows(t *testing.T) {
	if testing.Short() {
		t.Skip("loads 1M rows")
	}
	f := sweepFixture{t, newSweepPG(t)}
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `
INSERT INTO iam_oauth_tokens(id, tenant_id, user_id, session_id, idp_session_id, token_family_id, is_revoked)
SELECT gen_random_uuid(), gen_random_uuid(),
  ('00000000-0000-0000-0000-' || lpad((g % 5000)::text, 12, '0'))::uuid,
  CASE WHEN g % 10 < 3 THEN ('11111111-0000-0000-0000-' || lpad((g % 200000)::text, 12, '0'))::uuid END,
  CASE WHEN g % 10 < 3 THEN ('22222222-0000-0000-0000-' || lpad((g % 200000)::text, 12, '0'))::uuid END,
  CASE WHEN g % 10 < 8 THEN ('33333333-0000-0000-0000-' || lpad((g % 400000)::text, 12, '0'))::uuid END,
  (g % 7 = 0)
FROM generate_series(1, 1000000) g;
ANALYZE iam_oauth_tokens;`)
	require.NoError(t, err)

	user := uuid.New()
	sess := f.session(user, true, "")
	f.token(user, ptr(sess), nil, nil)
	_, err = f.pool.Exec(ctx, `ANALYZE iam_oauth_tokens`)
	require.NoError(t, err)

	conn, err := f.pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, "PREPARE sweep(uuid, text) AS "+Statement(endOne, "logout", "$1"))
	require.NoError(t, err)
	rows, err := conn.Query(ctx, "EXPLAIN EXECUTE sweep('"+sess.String()+"', 'logout')")
	require.NoError(t, err)
	var plan []string
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan = append(plan, line)
	}
	require.NoError(t, rows.Err())
	text := strings.Join(plan, "\n")
	t.Logf("sweep plan on 1M iam_oauth_tokens rows:\n%s", text)
	assert.NotContains(t, text, "Seq Scan on iam_oauth_tokens", "the sweep must not sequentially scan the token table")
	assert.Contains(t, text, "Bitmap", "expected index/bitmap scans over the token table")

	// And it still does the right thing at that size.
	n, err := End(ctx, f.pool, endOne, "logout", "$1", sess, "logout")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}
