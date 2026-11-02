// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// setupSeatReleaseSchema extends the seat-counter test schema with the iam_users columns and the role/session tables
// SetTeamMemberActive reads.
func setupSeatReleaseSchema(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	_, err := pool.Exec(context.Background(), `
		ALTER TABLE iam_users ADD COLUMN tenant_id uuid, ADD COLUMN is_active bool NOT NULL DEFAULT true,
			ADD COLUMN deletion_scheduled_at timestamptz, ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
		CREATE TABLE iam_roles(id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL, priority int NOT NULL);
		CREATE TABLE iam_user_roles(user_id uuid NOT NULL, role_id uuid NOT NULL, expires_at timestamptz);
		CREATE TABLE iam_oauth_tokens(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid, user_id uuid, token_type text NOT NULL DEFAULT 'access_token', refresh_token text, is_revoked boolean NOT NULL DEFAULT false, revoked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), idp_session_id uuid, token_family_id uuid, session_id uuid);
CREATE TABLE iam_sessions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL, is_active bool NOT NULL DEFAULT true, ended_at timestamptz, end_reason text);`)
	require.NoError(t, err)
	return pool
}

type seatFixture struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
	members  *UserMembershipRepository
	seats    *SeatCounterRepository
}

// newSeatFixture seeds a tenant with the given limit and `n` active member users, each with a membership, and
// seats_used = n.
func newSeatFixture(t *testing.T, limit, n int) (*seatFixture, []uuid.UUID) {
	t.Helper()
	pool := setupSeatReleaseSchema(t)
	ctx := context.Background()
	f := &seatFixture{pool: pool, tenantID: uuid.New(), members: NewUserMembershipRepository(pool), seats: NewSeatCounterRepository(pool)}
	_, err := pool.Exec(ctx, `INSERT INTO iam_tenants(id) VALUES($1)`, f.tenantID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO tenant_seat_counters(tenant_id, seats_used, seat_limit) VALUES($1,$2,$3)`, f.tenantID, n, limit)
	require.NoError(t, err)
	users := make([]uuid.UUID, 0, n)
	for i := 0; i < n; i++ {
		users = append(users, f.addMember(t, models.SeatClassMember))
	}
	return f, users
}

func (f *seatFixture) addMember(t *testing.T, class models.SeatClass) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	_, err := f.pool.Exec(ctx, `INSERT INTO iam_users(id, tenant_id) VALUES($1,$2)`, id, f.tenantID)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO iam_user_memberships(tenant_id, user_id, seat_class) VALUES($1,$2,$3)`, f.tenantID, id, string(class))
	require.NoError(t, err)
	return id
}

func (f *seatFixture) used(t *testing.T) int {
	t.Helper()
	c, err := f.seats.Get(context.Background(), f.tenantID)
	require.NoError(t, err)
	require.NotNil(t, c)
	return c.SeatsUsed
}

func TestSeatRelease_RemoveFreesSeatForInvite(t *testing.T) {
	f, users := newSeatFixture(t, 2, 2)
	ctx := context.Background()

	_, err := f.seats.ReserveSeat(ctx, f.tenantID)
	require.ErrorIs(t, err, ErrSeatLimitReached, "tenant is full")

	removed, err := f.members.Delete(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.True(t, removed)
	require.Equal(t, 1, f.used(t))

	_, err = f.seats.ReserveSeat(ctx, f.tenantID)
	require.NoError(t, err, "freed seat lets the next invite through")

	removed, err = f.members.Delete(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.False(t, removed, "second remove is a no-op")
	require.Equal(t, 1, f.used(t))
}

func TestSeatRelease_DeactivateTwiceFreesOneSeat(t *testing.T) {
	f, users := newSeatFixture(t, 5, 3)
	ctx := context.Background()

	changed, err := f.members.Deactivate(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.True(t, changed)
	changed, err = f.members.Deactivate(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, 2, f.used(t), "exactly one seat freed")

	// A deactivated membership removed later frees nothing more.
	_, err = f.members.Delete(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.Equal(t, 2, f.used(t))
}

func TestSeatRelease_SeatFreeClassesNeverTouchCounter(t *testing.T) {
	f, _ := newSeatFixture(t, 5, 1)
	ctx := context.Background()
	employee := f.addMember(t, models.SeatClassEmployee)
	external := f.addMember(t, models.SeatClassExternal)

	ok, err := f.members.DeactivateEmployee(ctx, f.tenantID, employee)
	require.NoError(t, err)
	require.True(t, ok)
	changed, err := f.members.Deactivate(ctx, f.tenantID, external)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = f.members.Reactivate(ctx, f.tenantID, external)
	require.NoError(t, err)
	require.Equal(t, 1, f.used(t), "employee and external rows are seat-free")
}

func TestSeatRelease_ReactivateWhenFullIsRefused(t *testing.T) {
	f, users := newSeatFixture(t, 2, 2)
	ctx := context.Background()

	_, err := f.members.Deactivate(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	_, err = f.seats.ReserveSeat(ctx, f.tenantID) // the freed seat is taken by a pending invite
	require.NoError(t, err)

	_, err = f.members.Reactivate(ctx, f.tenantID, users[0])
	require.ErrorIs(t, err, ErrSeatLimitReached)
	m, err := f.members.GetByTenantAndUser(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.Equal(t, models.UserMembershipStatusDeactivated, m.Status, "refused reactivation leaves the row deactivated")
	require.Equal(t, 1, f.used(t))

	require.NoError(t, f.seats.ReleaseReservation(ctx, f.tenantID))
	changed, err := f.members.Reactivate(ctx, f.tenantID, users[0])
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 2, f.used(t))
}

func TestSeatRelease_RecomputeFixesDrift(t *testing.T) {
	f, users := newSeatFixture(t, 10, 3)
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `UPDATE tenant_seat_counters SET seats_used = 7 WHERE tenant_id = $1`, f.tenantID)
	require.NoError(t, err)
	// A disabled user and a user pending deletion do not hold a seat even if their membership row is still active.
	_, err = f.pool.Exec(ctx, `UPDATE iam_users SET is_active = false WHERE id = $1`, users[0])
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE iam_users SET deletion_scheduled_at = now() WHERE id = $1`, users[1])
	require.NoError(t, err)

	prev, actual, err := f.seats.RecomputeUsedSeats(ctx, f.tenantID)
	require.NoError(t, err)
	require.Equal(t, 7, prev)
	require.Equal(t, 1, actual)
	require.Equal(t, 1, f.used(t))

	prev, actual, err = f.seats.RecomputeUsedSeats(ctx, f.tenantID)
	require.NoError(t, err)
	require.Equal(t, prev, actual, "second pass changes nothing")

	// A tenant without a counter row gets one.
	other := uuid.New()
	_, err = f.pool.Exec(ctx, `INSERT INTO iam_tenants(id) VALUES($1)`, other)
	require.NoError(t, err)
	_, actual, err = f.seats.RecomputeUsedSeats(ctx, other)
	require.NoError(t, err)
	require.Zero(t, actual)
}

func TestSeatRelease_ActiveHumanCountExcludesServiceIdentities(t *testing.T) {
	f, _ := newSeatFixture(t, 10, 2)
	ctx := context.Background()
	// Both a correctly classified service identity with an ordinary username
	// and the buggy bootstrap's active "member" service row must be excluded.
	f.addMember(t, models.SeatClassService)
	legacySvc := f.addMember(t, models.SeatClassMember)
	_, err := f.pool.Exec(ctx, `UPDATE iam_users SET username = 'SvC-payment-provider-sync' WHERE id = $1`, legacySvc)
	require.NoError(t, err)
	deactivated := f.addMember(t, models.SeatClassMember)
	_, err = f.pool.Exec(ctx, `UPDATE iam_user_memberships SET status = 'deactivated' WHERE user_id = $1`, deactivated)
	require.NoError(t, err)
	// User can still be is_active=true while tenant membership is deactivated.
	app := newRLSAppPool(t, os.Getenv("TEST_DATABASE_URL"), f.pool)
	n, err := NewUserRepository(app).CountActiveByTenant(ctx, f.tenantID)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	_, actual, err := NewSeatCounterRepository(app).RecomputeUsedSeats(ctx, f.tenantID)
	require.NoError(t, err)
	require.Equal(t, 2, actual)
	// Legacy service membership lifecycle must not release a human's seat
	// or require a seat when reactivated, even if misclassified as member.
	members := NewUserMembershipRepository(app)
	changed, err := members.Deactivate(ctx, f.tenantID, legacySvc)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 2, f.used(t))
	_, _, err = NewSeatCounterRepository(app).SetSeatLimit(ctx, f.tenantID, 2, nil, nil)
	require.NoError(t, err)
	changed, err = members.Reactivate(ctx, f.tenantID, legacySvc)
	require.NoError(t, err, "services never require seats, even at the human limit")
	require.True(t, changed)
	require.Equal(t, 2, f.used(t))
	removed, err := members.Delete(ctx, f.tenantID, legacySvc)
	require.NoError(t, err)
	require.True(t, removed)
	require.Equal(t, 2, f.used(t))
}

func TestSeatRelease_TeamMemberActiveAndDelete(t *testing.T) {
	f, users := newSeatFixture(t, 2, 2)
	ctx := context.Background()
	repo := NewUserRepository(f.pool)

	actor := f.addMember(t, models.SeatClassExternal) // acting admin; external row so it holds no seat
	hi, lo := uuid.New(), uuid.New()
	for _, r := range []struct {
		id   uuid.UUID
		name string
		prio int
	}{{hi, "manager", 200}, {lo, "member", 10}} {
		_, err := f.pool.Exec(ctx, `INSERT INTO iam_roles(id, tenant_id, name, priority) VALUES($1,$2,$3,$4)`, r.id, f.tenantID, r.name, r.prio)
		require.NoError(t, err)
	}
	_, err := f.pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id, role_id) VALUES($1,$2)`, actor, hi)
	require.NoError(t, err)
	for _, u := range users {
		_, err = f.pool.Exec(ctx, `INSERT INTO iam_user_roles(user_id, role_id) VALUES($1,$2)`, u, lo)
		require.NoError(t, err)
	}

	require.NoError(t, repo.SetTeamMemberActive(ctx, f.tenantID, actor, users[0], false))
	require.Equal(t, 1, f.used(t))
	require.NoError(t, repo.SetTeamMemberActive(ctx, f.tenantID, actor, users[0], false), "repeat deactivate")
	require.Equal(t, 1, f.used(t), "repeat deactivate frees nothing more")

	_, err = f.seats.ReserveSeat(ctx, f.tenantID) // someone else takes the freed seat
	require.NoError(t, err)
	err = repo.SetTeamMemberActive(ctx, f.tenantID, actor, users[0], true)
	require.ErrorIs(t, err, ErrSeatLimitReached)
	var active bool
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT is_active FROM iam_users WHERE id = $1`, users[0]).Scan(&active))
	require.False(t, active, "refused reactivation rolls the user back to inactive")

	require.NoError(t, f.seats.ReleaseReservation(ctx, f.tenantID))
	require.NoError(t, repo.SetTeamMemberActive(ctx, f.tenantID, actor, users[0], true))
	require.Equal(t, 2, f.used(t))

	// Removing an active member frees its seat and does not trip the membership FK.
	require.NoError(t, repo.Delete(ctx, users[1]))
	require.Equal(t, 1, f.used(t))
}
