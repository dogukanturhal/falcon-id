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

// NewRLSAppPool turns a setupSeatCounterSchema-style schema into the
// production shape for the two FORCE RLS tables (0013): the 0013 tenant
// policies, owned by a NOSUPERUSER NOBYPASSRLS role (FORCE makes the policy
// bind the owner too, which is falcon_id_app's situation), and returns a
// one-connection pool running as that role. One connection proves the
// tenant GUC never survives a scope.
func newRLSAppPool(t *testing.T, dsn string, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	var schema string
	require.NoError(t, admin.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema))
	role := "rls_app_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	ident := pgx.Identifier{role}.Sanitize()
	for _, stmt := range []string{
		"CREATE ROLE " + ident + " NOLOGIN NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + ident,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + ident,
		`ALTER TABLE iam_user_memberships ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE iam_user_memberships FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY iam_user_memberships_tenant_isolation ON iam_user_memberships
			USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''))`,
		`ALTER TABLE tenant_seat_counters ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE tenant_seat_counters FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_seat_counters_tenant_isolation ON tenant_seat_counters
			USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''))`,
		"ALTER TABLE iam_user_memberships OWNER TO " + ident,
		"ALTER TABLE tenant_seat_counters OWNER TO " + ident,
	} {
		_, err := admin.Exec(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	t.Cleanup(func() {
		// Runs before the schema drop registered by the schema helper:
		// hand ownership back and drop the role's grants first.
		_, _ = admin.Exec(ctx, "REASSIGN OWNED BY "+ident+" TO CURRENT_USER")
		_, _ = admin.Exec(ctx, "DROP OWNED BY "+ident)
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+ident)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+ident)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// LD-R3-TX-2: every SeatCounterRepository / UserMembershipRepository method
// works for a NOBYPASSRLS role on the raw pool (no request GUC) and inside a
// caller transaction, touches only its own tenant, and leaves no GUC behind.
func TestTenantScopePostgres_RLSRepositories(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	ctx := context.Background()
	admin := setupSeatCounterSchema(t, dsn)
	clientT, partnerT := uuid.New(), uuid.New()
	accountant, member := uuid.New(), uuid.New()
	_, err := admin.Exec(ctx, `INSERT INTO iam_tenants (id) VALUES ($1), ($2)`, clientT, partnerT)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `INSERT INTO iam_users (id) VALUES ($1), ($2)`, accountant, member)
	require.NoError(t, err)
	app := newRLSAppPool(t, dsn, admin)

	// The bug being fixed: a NOBYPASSRLS role without the GUC sees nothing.
	_, err = admin.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id, seats_used) VALUES ($1, 3)`, partnerT)
	require.NoError(t, err)
	var n int
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM tenant_seat_counters`).Scan(&n))
	require.Zero(t, n, "FORCE RLS hides every row from an unscoped NOBYPASSRLS role")

	seats := NewSeatCounterRepository(app)
	memberships := NewUserMembershipRepository(app)

	// Seat counters on the raw pool.
	require.NoError(t, seats.EnsureRow(ctx, clientT))
	got, err := seats.Get(ctx, clientT)
	require.NoError(t, err)
	require.NotNil(t, got, "Get must see the row EnsureRow wrote")
	_, applied, err := seats.SetSeatLimit(ctx, clientT, 2, nil, nil)
	require.NoError(t, err)
	require.True(t, applied)
	_, err = seats.ReserveSeat(ctx, clientT)
	require.NoError(t, err)
	_, err = seats.ReserveSeat(ctx, clientT)
	require.NoError(t, err)
	_, err = seats.ReserveSeat(ctx, clientT)
	require.ErrorIs(t, err, ErrSeatLimitReached, "limit enforcement still works under RLS")
	require.NoError(t, seats.ConfirmSeat(ctx, clientT))
	require.NoError(t, seats.ReleaseReservation(ctx, clientT))
	got, err = seats.Get(ctx, clientT)
	require.NoError(t, err)
	require.Equal(t, 1, got.SeatsUsed)
	require.Equal(t, 0, got.SeatsPending)

	// Expiry sweep: several tenants in one call.
	_, err = seats.ReserveSeat(ctx, clientT)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE tenant_seat_counters SET seats_pending = 2 WHERE tenant_id = $1`, partnerT)
	require.NoError(t, err)
	require.NoError(t, seats.ReleaseReservationsBulk(ctx, map[uuid.UUID]int{clientT: 1, partnerT: 2}))
	var clientPending, partnerPending, partnerUsed int
	require.NoError(t, admin.QueryRow(ctx, `SELECT seats_pending FROM tenant_seat_counters WHERE tenant_id = $1`, clientT).Scan(&clientPending))
	require.NoError(t, admin.QueryRow(ctx, `SELECT seats_pending, seats_used FROM tenant_seat_counters WHERE tenant_id = $1`, partnerT).Scan(&partnerPending, &partnerUsed))
	require.Zero(t, clientPending)
	require.Zero(t, partnerPending)
	require.Equal(t, 3, partnerUsed, "the bulk release never touches seats_used")

	// Accept from a partner tenant: membership upsert + seat confirm inside
	// the caller's transaction, all-or-nothing.
	inviteID := uuid.New()
	_, err = admin.Exec(ctx, `INSERT INTO iam_team_invitations (id, tenant_id, email, invited_by, token, seat_class, expires_at)
		VALUES ($1, $2, 'smmm@partner.test', $3, 'digest', 'external', $4)`, inviteID, clientT, member, time.Now().Add(time.Hour))
	require.NoError(t, err)
	tx, err := app.Begin(ctx)
	require.NoError(t, err)
	_, err = memberships.WithDB(tx).Upsert(ctx, &models.UserMembership{TenantID: clientT, UserID: accountant, SeatClass: models.SeatClassExternal, InvitationID: &inviteID})
	require.NoError(t, err)
	require.NoError(t, seats.WithDB(tx).ConfirmSeat(ctx, clientT))
	require.NoError(t, tx.Rollback(ctx))
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM iam_user_memberships`).Scan(&n))
	require.Zero(t, n, "rolled-back accept leaves no membership")

	tx, err = app.Begin(ctx)
	require.NoError(t, err)
	_, err = memberships.WithDB(tx).Upsert(ctx, &models.UserMembership{TenantID: clientT, UserID: accountant, SeatClass: models.SeatClassExternal, InvitationID: &inviteID})
	require.NoError(t, err)
	_, err = memberships.WithDB(tx).Upsert(ctx, &models.UserMembership{TenantID: partnerT, UserID: member, SeatClass: models.SeatClassMember})
	require.NoError(t, err, "a later statement in the same tx re-scopes to its own tenant")
	require.NoError(t, tx.Commit(ctx))

	m, err := memberships.GetByTenantAndUser(ctx, clientT, accountant)
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, models.SeatClassExternal, m.SeatClass)
	m, err = memberships.GetByTenantAndUser(ctx, partnerT, accountant)
	require.NoError(t, err)
	require.Nil(t, m)

	// External-member list and revoke, as the client tenant admin would.
	_, err = admin.Exec(ctx, `ALTER TABLE iam_users ADD COLUMN email text NOT NULL DEFAULT '', ADD COLUMN display_name text`)
	require.NoError(t, err)
	rows, err := memberships.ListActiveExternal(ctx, clientT)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, accountant, rows[0].UserID)
	rows, err = memberships.ListActiveExternal(ctx, partnerT)
	require.NoError(t, err)
	require.Empty(t, rows)
	ok, err := memberships.DeactivateExternal(ctx, partnerT, accountant)
	require.NoError(t, err)
	require.False(t, ok, "no external membership in the partner tenant")
	ok, err = memberships.DeactivateExternal(ctx, clientT, accountant)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = memberships.Deactivate(ctx, partnerT, member)
	require.NoError(t, err)
	_, err = memberships.Reactivate(ctx, partnerT, member)
	require.NoError(t, err)
	var status string
	require.NoError(t, admin.QueryRow(ctx, `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, clientT, accountant).Scan(&status))
	require.Equal(t, "deactivated", status)
	require.NoError(t, admin.QueryRow(ctx, `SELECT status FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`, partnerT, member).Scan(&status))
	require.Equal(t, "active", status)

	// The scope is transaction-local: the single pooled connection is back
	// to seeing nothing.
	var guc string
	require.NoError(t, app.QueryRow(ctx, `SELECT COALESCE(current_setting('app.current_tenant_id', true), '')`).Scan(&guc))
	require.Empty(t, guc)
	require.NoError(t, app.QueryRow(ctx, `SELECT count(*) FROM iam_user_memberships`).Scan(&n))
	require.Zero(t, n)

	_, err = seats.Get(ctx, uuid.Nil)
	require.Error(t, err, "a nil tenant id is refused, never run unscoped")
}
