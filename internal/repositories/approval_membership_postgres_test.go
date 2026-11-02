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
)

func TestApprovalMembershipPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	schema, role := "apvmember_"+suffix, "apvmember_app_"+suffix
	sch, rol := pgx.Identifier{schema}.Sanitize(), pgx.Identifier{role}.Sanitize()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		defer admin.Close(ctx)
		_, err := admin.Exec(ctx, "DROP SCHEMA "+sch+" CASCADE")
		require.NoError(t, err)
		_, err = admin.Exec(ctx, "DROP ROLE "+rol)
		require.NoError(t, err)
	})
	_, err = admin.Exec(ctx, `CREATE SCHEMA `+sch+`; SET search_path = `+sch+`;
	CREATE TABLE iam_users(id uuid PRIMARY KEY,tenant_id uuid,is_active boolean DEFAULT true,deletion_scheduled_at timestamptz,activation_status text);
	CREATE TABLE iam_user_memberships(tenant_id uuid,user_id uuid,seat_class text,status text DEFAULT 'active',access_expires_at timestamptz);
	ALTER TABLE iam_users ENABLE ROW LEVEL SECURITY; ALTER TABLE iam_users FORCE ROW LEVEL SECURITY;
	CREATE POLICY users_tenant ON iam_users USING (tenant_id::text = current_setting('app.current_tenant_id',true));
	ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY; ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY;
	CREATE POLICY members_tenant ON iam_user_memberships USING (tenant_id::text = current_setting('app.current_tenant_id',true));
	CREATE ROLE `+rol+` NOLOGIN NOSUPERUSER NOBYPASSRLS;
	GRANT USAGE ON SCHEMA `+sch+` TO `+rol+`; GRANT SELECT ON ALL TABLES IN SCHEMA `+sch+` TO `+rol)
	require.NoError(t, err)
	tenant, other := uuid.New(), uuid.New()
	var expected []uuid.UUID
	for _, tc := range []struct {
		class, status, activation, expiry string
		active, deleted, eligible         bool
	}{
		{"member", "active", "active", "", true, false, true},
		{"employee", "active", "active", "", true, false, true},
		{"external", "active", "active", "", true, false, false},
		{"service", "active", "active", "", true, false, true},
		{"kiosk", "active", "active", "", true, false, true},
		{"member", "deactivated", "active", "", true, false, false},
		{"member", "active", "pending_deletion", "", true, false, false},
		{"member", "active", "admin_deleted", "", true, false, false},
		{"member", "active", "active", "", false, false, false},
		{"member", "active", "active", "", true, true, false},
		{"employee", "active", "active", "2000-01-01", true, false, false},
		{"employee", "active", "active", "2099-01-01", true, false, true},
	} {
		id := uuid.New()
		_, err = admin.Exec(ctx, `INSERT INTO iam_users VALUES($1,$2,$3,CASE WHEN $4 THEN now() ELSE NULL END,$5)`, id, tenant, tc.active, tc.deleted, tc.activation)
		require.NoError(t, err)
		_, err = admin.Exec(ctx, `INSERT INTO iam_user_memberships VALUES($1,$2,$3,$4,NULLIF($5,'')::timestamptz)`, tenant, id, tc.class, tc.status, tc.expiry)
		require.NoError(t, err)
		if tc.eligible {
			expected = append(expected, id)
		}
	}
	foreign := uuid.New()
	_, err = admin.Exec(ctx, `INSERT INTO iam_users(id,tenant_id) VALUES($1,$2);`, foreign, other)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO iam_user_memberships(tenant_id,user_id,seat_class) VALUES($1,$2,'member')`, other, foreign)
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error { _, err := c.Exec(ctx, "SET ROLE "+rol); return err }
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	members, err := NewUserMembershipRepository(pool).ListApprovalMembers(ctx, tenant)
	require.NoError(t, err)
	require.ElementsMatch(t, expected, members)
	members, err = NewUserMembershipRepository(pool).ListApprovalMembers(ctx, other)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{foreign}, members)
}
