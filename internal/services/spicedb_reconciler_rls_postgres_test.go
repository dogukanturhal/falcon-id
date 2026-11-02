// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// LD-R3-TX-2: the reconciler's per-tenant membership scan runs as the
// NOBYPASSRLS app role against iam_user_memberships' FORCE RLS tenant
// policy. Unscoped, the external member's membership is invisible and the
// member would be converged to "no roles"; scoped, the client-tenant grant
// survives, and the member's partner-tenant role never leaks in.
func TestLoadUserRoleStatesPostgres_RLSAppRole(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	schema := pgx.Identifier{"recon_rls_" + suffix}.Sanitize()
	role := pgx.Identifier{"recon_app_" + suffix}.Sanitize()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+role)
		_ = admin.Close(ctx)
	})

	clientT, partnerT := uuid.New(), uuid.New()
	clerk, accountant, revoked := uuid.New(), uuid.New(), uuid.New()
	clientRead, clientClerk, partnerAdmin := uuid.New(), uuid.New(), uuid.New()
	for _, stmt := range []string{
		"CREATE SCHEMA " + schema,
		"SET search_path = " + schema,
		`CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, is_active boolean NOT NULL DEFAULT true)`,
		`CREATE TABLE iam_user_memberships(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
			user_id uuid NOT NULL, seat_class text NOT NULL, status text NOT NULL DEFAULT 'active')`,
		`CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL)`,
		`CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, expires_at timestamptz)`,
		"CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON ALL TABLES IN SCHEMA " + schema + " TO " + role,
		// 0013 policy shape.
		`ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY iam_user_memberships_tenant_isolation ON iam_user_memberships
			USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''))`,
	} {
		_, err := admin.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	_, err = admin.Exec(ctx, `INSERT INTO iam_users (id, tenant_id) VALUES ($1, $4), ($2, $5), ($3, $5)`,
		clerk, accountant, revoked, clientT, partnerT)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status) VALUES
		($1, $2, 'member', 'active'), ($1, $3, 'external', 'active'), ($1, $4, 'external', 'deactivated')`,
		clientT, clerk, accountant, revoked)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO iam_roles (id, tenant_id) VALUES ($1, $4), ($2, $4), ($3, $5)`,
		clientRead, clientClerk, partnerAdmin, clientT, partnerT)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id) VALUES ($1, $4), ($2, $5), ($2, $6), ($3, $5)`,
		clerk, accountant, revoked, clientClerk, clientRead, partnerAdmin)
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["search_path"] = strings.Trim(schema, `"`)
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+role)
		return err
	}
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(app.Close)

	var n int
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM iam_user_memberships`).Scan(&n))
	require.Zero(t, n, "precondition: FORCE RLS hides memberships from the unscoped app role")

	states, err := loadUserRoleStates(ctx, app, clientT)
	require.NoError(t, err)
	require.Contains(t, states, clerk)
	require.True(t, states[clerk].active)
	require.Equal(t, map[uuid.UUID]struct{}{clientClerk: {}}, states[clerk].desired)

	require.Contains(t, states, accountant, "the external member is visible to the scoped scan")
	require.True(t, states[accountant].active)
	require.Equal(t, map[uuid.UUID]struct{}{clientRead: {}}, states[accountant].desired,
		"client-tenant grant kept, partner-tenant role never leaks in")

	require.Contains(t, states, revoked, "a revoked external member is still listed so stale edges are removed")
	require.False(t, states[revoked].active)
	require.Empty(t, states[revoked].desired)
}
