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

// Employee-class (ESS) seats against real PostgreSQL with FORCE RLS and migration 0021 applied verbatim, run as a
// NOBYPASSRLS role like production. TEST_DATABASE_URL is a superuser DSN of a throwaway database.
func TestEmployeeSeatPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run against a throwaway docker postgres")
	}
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	schema, role := "empseat_"+suffix, "empseat_app_"+suffix
	sch, rol := pgx.Identifier{schema}.Sanitize(), pgx.Identifier{role}.Sanitize()

	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+sch+" CASCADE")
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+rol)
	})
	migration, err := os.ReadFile("../migrations/0021_iam_employee_seat_class.sql")
	require.NoError(t, err)

	tenant, other := uuid.New(), uuid.New()
	expired, future, member, unset, otherTenantUser := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()

	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	for _, stmt := range []string{
		"CREATE SCHEMA " + sch,
		"SET LOCAL search_path = " + sch,
		`CREATE TABLE iam_tenants(id uuid PRIMARY KEY, status text NOT NULL DEFAULT 'active')`,
		`CREATE TABLE iam_users(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, username text NOT NULL DEFAULT 'person', is_active boolean NOT NULL DEFAULT true, deletion_scheduled_at timestamptz)`,
		`CREATE TABLE iam_user_memberships(
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES iam_tenants(id), user_id uuid NOT NULL,
			seat_class text NOT NULL DEFAULT 'member' CONSTRAINT iam_user_memberships_seat_class_check CHECK (seat_class IN ('member','external','service')),
			status text NOT NULL DEFAULT 'active', invitation_id uuid, created_at timestamptz NOT NULL DEFAULT now(), deactivated_at timestamptz, UNIQUE (tenant_id, user_id))`,
		`ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY iam_user_memberships_tenant_isolation ON iam_user_memberships USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''))`,
		string(migration),
		"CREATE ROLE " + rol + " NOLOGIN NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + sch + " TO " + rol,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + sch + " TO " + rol,
	} {
		_, err := tx.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	_, err = tx.Exec(ctx, `INSERT INTO iam_tenants(id) VALUES ($1), ($2)`, tenant, other)
	require.NoError(t, err)
	for _, u := range []struct {
		id, tenant uuid.UUID
	}{{expired, tenant}, {future, tenant}, {member, tenant}, {unset, tenant}, {otherTenantUser, other}} {
		_, err = tx.Exec(ctx, `INSERT INTO iam_users(id, tenant_id) VALUES ($1, $2)`, u.id, u.tenant)
		require.NoError(t, err)
	}
	for _, m := range []struct {
		tenant, user uuid.UUID
		class        string
		expires      *time.Time
	}{
		{tenant, expired, "employee", ptrTime(time.Now().Add(-time.Hour))},
		{tenant, future, "employee", ptrTime(time.Now().Add(time.Hour))},
		{tenant, unset, "employee", nil},
		{tenant, member, "member", nil},
		{other, otherTenantUser, "employee", ptrTime(time.Now().Add(-time.Hour))},
	} {
		_, err = tx.Exec(ctx, `INSERT INTO iam_user_memberships(tenant_id, user_id, seat_class, access_expires_at) VALUES ($1,$2,$3,$4)`, m.tenant, m.user, m.class, m.expires)
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(ctx))

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+rol)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()

	memberships := NewUserMembershipRepository(pool)
	users := NewUserRepository(pool)

	t.Run("CountActiveByTenant_ExcludesEmployeeSeats", func(t *testing.T) {
		n, err := users.CountActiveByTenant(ctx, tenant)
		require.NoError(t, err)
		require.Equal(t, 1, n, "only the member seat counts; 3 employee users are seat-free")
		emp, err := memberships.CountActiveEmployeeSeatUsers(ctx, tenant)
		require.NoError(t, err)
		require.Equal(t, 3, emp)
	})

	t.Run("ListExpired_OnlyExpiredAndTenantScoped", func(t *testing.T) {
		ids, err := memberships.ListExpiredEmployee(ctx, tenant, 10)
		require.NoError(t, err)
		require.Equal(t, []uuid.UUID{expired}, ids)
	})

	t.Run("SetAccessExpiry_RefusesNonEmployee", func(t *testing.T) {
		ok, err := memberships.SetAccessExpiry(ctx, tenant, member, ptrTime(time.Now()))
		require.NoError(t, err)
		require.False(t, ok, "a member seat can never be expired through this path")
		ok, err = memberships.SetAccessExpiry(ctx, tenant, unset, ptrTime(time.Now().Add(-time.Minute)))
		require.NoError(t, err)
		require.True(t, ok)
		ids, err := memberships.ListExpiredEmployee(ctx, tenant, 10)
		require.NoError(t, err)
		require.ElementsMatch(t, []uuid.UUID{expired, unset}, ids)
	})

	t.Run("DeactivateEmployee_LeavesOthers", func(t *testing.T) {
		ok, err := memberships.DeactivateEmployee(ctx, tenant, expired)
		require.NoError(t, err)
		require.True(t, ok)
		ids, err := memberships.ListExpiredEmployee(ctx, tenant, 10)
		require.NoError(t, err)
		require.Equal(t, []uuid.UUID{unset}, ids)
		m, err := memberships.GetByTenantAndUser(ctx, tenant, future)
		require.NoError(t, err)
		require.Equal(t, models.UserMembershipStatusActive, m.Status)
		require.Equal(t, models.SeatClassEmployee, m.SeatClass)
		require.NotNil(t, m.AccessExpiresAt)
	})

	t.Run("IsSeatFree", func(t *testing.T) {
		free, err := memberships.IsSeatFree(ctx, tenant, future)
		require.NoError(t, err)
		require.True(t, free)
		free, err = memberships.IsSeatFree(ctx, tenant, member)
		require.NoError(t, err)
		require.False(t, free)
	})
}

func ptrTime(t time.Time) *time.Time { return &t }
