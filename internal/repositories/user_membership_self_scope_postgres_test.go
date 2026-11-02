// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Runs the membership lookups as a NOBYPASSRLS role against the real 0013
// tenant policy (FORCE RLS) plus migration 0019, the way falcon_id_app runs
// in production. TEST_DATABASE_URL must be a superuser DSN (it creates a role).
func TestUserMembershipSelfScopePostgres_RLS(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	schema := "mself_" + suffix
	role := "mself_app_" + suffix

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize())
		_ = admin.Close(ctx)
	})

	selfSelect, err := os.ReadFile("../migrations/0019_iam_user_memberships_self_select.sql")
	require.NoError(t, err)

	partner, client, other := uuid.New(), uuid.New(), uuid.New()
	accountant, colleague := uuid.New(), uuid.New()
	partnerAdmin, clientRead := uuid.New(), uuid.New()

	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	for _, stmt := range []string{
		"CREATE SCHEMA " + pgx.Identifier{schema}.Sanitize(),
		"SET LOCAL search_path = " + pgx.Identifier{schema}.Sanitize(),
		`CREATE TABLE iam_tenants(id uuid PRIMARY KEY, slug text NOT NULL, status text NOT NULL DEFAULT 'active')`,
		`CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL)`,
		`CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, expires_at timestamptz)`,
		`CREATE TABLE iam_user_memberships(
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id uuid NOT NULL REFERENCES iam_tenants(id),
			user_id uuid NOT NULL,
			seat_class text NOT NULL DEFAULT 'member',
			status text NOT NULL DEFAULT 'active',
			UNIQUE (tenant_id, user_id))`,
		// 0013, verbatim policy.
		`ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY iam_user_memberships_tenant_isolation ON iam_user_memberships
			USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''))`,
		string(selfSelect),
		"CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + pgx.Identifier{role}.Sanitize(),
		"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + pgx.Identifier{role}.Sanitize(),
	} {
		_, err := tx.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	_, err = tx.Exec(ctx, `INSERT INTO iam_tenants (id, slug) VALUES ($1,'partner'), ($2,'client'), ($3,'other')`, partner, client, other)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class) VALUES
		($1, $4, 'member'), ($2, $4, 'external'), ($3, $5, 'member')`, partner, client, other, accountant, colleague)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id, name) VALUES ($1, $3, 'Tenant Admin'), ($2, $4, 'external_readonly')`,
		partnerAdmin, clientRead, partner, client)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id) VALUES ($1, $2), ($1, $3)`, accountant, partnerAdmin, clientRead)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.MaxConns = 1 // one connection: proves the GUC does not survive the scope
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// The finding: without a GUC the app role sees none of the rows.
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM iam_user_memberships WHERE user_id = $1`, accountant).Scan(&n))
	require.Zero(t, n, "FORCE RLS hides cross-tenant memberships from a NOBYPASSRLS role on the raw pool")

	repo := NewUserMembershipRepository(pool)
	m, err := repo.ResolveTenantExchange(ctx, accountant, client)
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, models.SeatClassExternal, m.SeatClass)
	require.Equal(t, models.UserMembershipStatusActive, m.Status)
	require.Equal(t, "client", m.TenantSlug)
	require.Equal(t, "active", m.TenantStatus)
	require.Equal(t, []string{"external_readonly"}, m.RoleNames, "partner-tenant roles must not appear under the client")

	none, err := repo.ResolveTenantExchange(ctx, accountant, other)
	require.NoError(t, err)
	require.Nil(t, none, "another user's membership is not the accountant's")

	// Inside the scope only the user's own rows are visible, and writes still
	// need the tenant policy.
	require.NoError(t, WithUserMembershipScope(ctx, pool, accountant, func(tx pgx.Tx) error {
		var users int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT user_id) FROM iam_user_memberships`).Scan(&users); err != nil {
			return err
		}
		require.Equal(t, 1, users)
		tag, err := tx.Exec(ctx, `UPDATE iam_user_memberships SET status = 'deactivated' WHERE user_id = $1`, accountant)
		if err != nil {
			return err
		}
		require.Zero(t, tag.RowsAffected(), "the self policy is SELECT-only")
		return nil
	}))

	var guc string
	require.NoError(t, pool.QueryRow(ctx, `SELECT COALESCE(current_setting('app.current_user_id', true), '')`).Scan(&guc))
	require.Empty(t, guc, "app.current_user_id is transaction-local")

	require.Error(t, WithUserMembershipScope(ctx, pool, uuid.Nil, func(pgx.Tx) error { return nil }))
}
