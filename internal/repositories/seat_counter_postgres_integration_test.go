// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// setupSeatCounterSchema creates a throwaway schema with the minimal
// tenant_seat_counters/iam_team_invitations/iam_user_memberships DDL needed
// to exercise SeatCounterRepository/UserMembershipRepository/
// TeamInvitationRepository.ExpirePendingAndReleaseSeats against a real
// Postgres instance (TEST_DATABASE_URL — see hack/run-team-postgres-tests.sh
// for the docker-based local runner this mirrors).
func setupSeatCounterSchema(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	schema := "seat_ctr_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

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

		CREATE TABLE iam_tenants(id uuid PRIMARY KEY);
		CREATE TABLE iam_users(id uuid PRIMARY KEY, username text NOT NULL DEFAULT 'person');

		CREATE TABLE iam_team_invitations (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			email TEXT NOT NULL,
			role_ids UUID[] NOT NULL DEFAULT '{}',
			invited_by UUID NOT NULL,
			token TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			seat_class TEXT NOT NULL DEFAULT 'member' CHECK (seat_class IN ('member','external','service')),
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			accepted_at TIMESTAMPTZ NULL,
			last_resent_at TIMESTAMPTZ NULL
		);
		CREATE UNIQUE INDEX idx_iam_team_invitations_pending_tenant_email_normalized_unique
			ON iam_team_invitations (tenant_id, lower(email)) WHERE status = 'pending';

		CREATE TABLE iam_user_memberships (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			seat_class TEXT NOT NULL DEFAULT 'member' CHECK (seat_class IN ('member','external','service','employee')),
			status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','deactivated')),
			invitation_id UUID NULL REFERENCES iam_team_invitations(id),
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			deactivated_at TIMESTAMPTZ NULL,
			access_expires_at TIMESTAMPTZ NULL,
			CONSTRAINT iam_user_memberships_tenant_user_uq UNIQUE (tenant_id, user_id)
		);

		CREATE TABLE tenant_seat_counters (
			tenant_id UUID PRIMARY KEY,
			seats_used INTEGER NOT NULL DEFAULT 0 CHECK (seats_used >= 0),
			seats_pending INTEGER NOT NULL DEFAULT 0 CHECK (seats_pending >= 0),
			seat_limit INTEGER NULL CHECK (seat_limit IS NULL OR seat_limit >= 0),
			seat_limit_version BIGINT NULL,
			seat_limit_computed_at TIMESTAMPTZ NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	require.NoError(t, err)
	return pool
}

// TestSeatCounterPostgres_ReserveSeat_NeverExceedsLimit is the seat-race
// test: N goroutines concurrently call ReserveSeat against the SAME tenant
// with a seat_limit of limit, each in its own transaction (mirroring
// CreateInvitation's usage). Asserts exactly `limit` reservations succeed
// and the rest are rejected with ErrSeatLimitReached, and that the final
// counters row never has seats_used+seats_pending > seat_limit.
//
// This is the concurrency guarantee described in
// seat_counter_repository.go's doc comment: the atomic
// UPDATE ... WHERE seats_used + seats_pending < seat_limit RETURNING
// statement, not a read-then-write SELECT/UPDATE pair.
func TestSeatCounterPostgres_ReserveSeat_NeverExceedsLimit(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewSeatCounterRepository(pool)

	tenantID := uuid.New()
	const limit = 10
	const attempts = 40

	_, err := pool.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id, seat_limit) VALUES ($1, $2)`, tenantID, limit)
	require.NoError(t, err)

	var succeeded, rejected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Errorf("begin: %v", err)
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()

			_, err = repo.WithDB(tx).ReserveSeat(ctx, tenantID)
			if err == nil {
				if commitErr := tx.Commit(ctx); commitErr != nil {
					t.Errorf("commit: %v", commitErr)
					return
				}
				succeeded.Add(1)
				return
			}
			if err == ErrSeatLimitReached { //nolint:errorlint // sentinel returned directly by ReserveSeat
				rejected.Add(1)
				return
			}
			t.Errorf("unexpected ReserveSeat error: %v", err)
		}()
	}
	wg.Wait()

	require.Equal(t, int64(limit), succeeded.Load(), "exactly seat_limit reservations should succeed")
	require.Equal(t, int64(attempts-limit), rejected.Load(), "the rest should be rejected with ErrSeatLimitReached")

	final, err := repo.Get(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, final)
	require.NotNil(t, final.SeatLimit)
	require.LessOrEqual(t, final.SeatsUsed+final.SeatsPending, *final.SeatLimit,
		"seats_used + seats_pending must never exceed seat_limit")
	require.Equal(t, limit, final.SeatsPending)
	require.Equal(t, 0, final.SeatsUsed)
}

// TestSeatCounterPostgres_ReserveSeat_UnlimitedWhenSeatLimitNil confirms the
// fail-open convention: a tenant with no seat_limit row configured yet
// (seat_limit IS NULL) never has reservations rejected.
func TestSeatCounterPostgres_ReserveSeat_UnlimitedWhenSeatLimitNil(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewSeatCounterRepository(pool)
	tenantID := uuid.New()

	require.NoError(t, repo.EnsureRow(ctx, tenantID))
	for i := 0; i < 25; i++ {
		_, err := repo.ReserveSeat(ctx, tenantID)
		require.NoError(t, err)
	}
	counters, err := repo.Get(ctx, tenantID)
	require.NoError(t, err)
	require.Nil(t, counters.SeatLimit)
	require.Equal(t, 25, counters.SeatsPending)
}

// TestSeatCounterPostgres_ConfirmSeat_ConvertsReservation covers accept:
// a pending reservation becomes used capacity, atomically.
func TestSeatCounterPostgres_ConfirmSeat_ConvertsReservation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewSeatCounterRepository(pool)
	tenantID := uuid.New()

	require.NoError(t, repo.EnsureRow(ctx, tenantID))
	_, err := repo.ReserveSeat(ctx, tenantID)
	require.NoError(t, err)

	require.NoError(t, repo.ConfirmSeat(ctx, tenantID))

	counters, err := repo.Get(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, 0, counters.SeatsPending)
	require.Equal(t, 1, counters.SeatsUsed)
}

// TestSeatCounterPostgres_ReleaseReservation_Revoke covers revoke/decline:
// a released reservation frees the pending slot without touching seats_used.
func TestSeatCounterPostgres_ReleaseReservation_Revoke(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewSeatCounterRepository(pool)
	tenantID := uuid.New()

	require.NoError(t, repo.EnsureRow(ctx, tenantID))
	_, err := repo.ReserveSeat(ctx, tenantID)
	require.NoError(t, err)

	require.NoError(t, repo.ReleaseReservation(ctx, tenantID))

	counters, err := repo.Get(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, 0, counters.SeatsPending)
	require.Equal(t, 0, counters.SeatsUsed)

	// Releasing again must floor at 0, never go negative.
	require.NoError(t, repo.ReleaseReservation(ctx, tenantID))
	counters, err = repo.Get(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, 0, counters.SeatsPending)
}

// TestTeamInvitationPostgres_ExpirePendingAndReleaseSeats covers the expiry
// job: an overdue pending invitation flips to 'expired' and its seat
// reservation is released; a non-expired pending invitation and a
// non-member-class expired invitation are left alone / don't affect counts.
func TestTeamInvitationPostgres_ExpirePendingAndReleaseSeats(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	invRepo := NewTeamInvitationRepository(pool)
	seatRepo := NewSeatCounterRepository(pool)

	tenantA, tenantB := uuid.New(), uuid.New()
	require.NoError(t, seatRepo.EnsureRow(ctx, tenantA))
	require.NoError(t, seatRepo.EnsureRow(ctx, tenantB))
	_, err := seatRepo.ReserveSeat(ctx, tenantA)
	require.NoError(t, err)
	_, err = seatRepo.ReserveSeat(ctx, tenantA)
	require.NoError(t, err)
	_, err = seatRepo.ReserveSeat(ctx, tenantB)
	require.NoError(t, err)

	mkInv := func(tenantID uuid.UUID, seatClass models.SeatClass, expiresAt time.Time) uuid.UUID {
		inv := &models.TeamInvitation{
			TenantID:  tenantID,
			Email:     uuid.NewString() + "@example.com",
			RoleIDs:   []uuid.UUID{},
			InvitedBy: uuid.New(),
			Token:     uuid.NewString(),
			Status:    models.TeamInvitationStatusPending,
			ExpiresAt: expiresAt,
			SeatClass: seatClass,
		}
		require.NoError(t, invRepo.Create(ctx, inv))
		return inv.ID
	}

	expiredMemberA1 := mkInv(tenantA, models.SeatClassMember, time.Now().Add(-time.Hour))
	expiredMemberA2 := mkInv(tenantA, models.SeatClassMember, time.Now().Add(-time.Minute))
	stillPendingA := mkInv(tenantA, models.SeatClassMember, time.Now().Add(time.Hour))
	expiredExternalB := mkInv(tenantB, models.SeatClassExternal, time.Now().Add(-time.Hour))

	counts, err := invRepo.ExpirePendingAndReleaseSeats(ctx)
	require.NoError(t, err)

	require.Equal(t, 2, counts[tenantA], "two expired member-class invitations in tenant A")
	require.Zero(t, counts[tenantB], "external seat_class never counts, even when expired")

	require.NoError(t, seatRepo.ReleaseReservationsBulk(ctx, counts))

	countersA, err := seatRepo.Get(ctx, tenantA)
	require.NoError(t, err)
	require.Equal(t, 0, countersA.SeatsPending, "both reservations released")

	countersB, err := seatRepo.Get(ctx, tenantB)
	require.NoError(t, err)
	require.Equal(t, 1, countersB.SeatsPending, "tenant B's external invite never reserved a seat, so its own member reservation is untouched")

	for _, id := range []uuid.UUID{expiredMemberA1, expiredMemberA2, expiredExternalB} {
		inv, err := invRepo.GetByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, models.TeamInvitationStatusExpired, inv.Status)
	}
	stillPending, err := invRepo.GetByID(ctx, stillPendingA)
	require.NoError(t, err)
	require.Equal(t, models.TeamInvitationStatusPending, stillPending.Status)
}

// TestUserMembershipPostgres_UpsertAndDeactivate covers accept's membership
// creation plus deactivate/reactivate lifecycle.
func TestUserMembershipPostgres_UpsertAndDeactivate(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewUserMembershipRepository(pool)

	tenantID, userID := uuid.New(), uuid.New()
	m, err := repo.Upsert(ctx, &models.UserMembership{TenantID: tenantID, UserID: userID, SeatClass: models.SeatClassMember})
	require.NoError(t, err)
	require.Equal(t, models.UserMembershipStatusActive, m.Status)
	require.True(t, m.IsActiveMember())

	_, err = repo.Deactivate(ctx, tenantID, userID)
	require.NoError(t, err)
	got, err := repo.GetByTenantAndUser(ctx, tenantID, userID)
	require.NoError(t, err)
	require.Equal(t, models.UserMembershipStatusDeactivated, got.Status)
	require.False(t, got.IsActiveMember())
	require.NotNil(t, got.DeactivatedAt)

	_, err = repo.Reactivate(ctx, tenantID, userID)
	require.NoError(t, err)
	got, err = repo.GetByTenantAndUser(ctx, tenantID, userID)
	require.NoError(t, err)
	require.Equal(t, models.UserMembershipStatusActive, got.Status)
	require.Nil(t, got.DeactivatedAt)
}

// TestSeatCounterPostgres_SetSeatLimit_StaleVersionRejected exercises the
// R1 "trial-aware seat caps" (spec 25 §4.5) outbox-retry scenario:
// subscription-management's reconciler sweep can redeliver an older PUT
// after a newer one has already applied. SetSeatLimit must reject the
// stale (lower-version) write rather than overwrite the newer value, and
// must still apply a later write with a higher version than what is
// currently stored.
func TestSeatCounterPostgres_SetSeatLimit_StaleVersionRejected(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewSeatCounterRepository(pool)

	tenantID := uuid.New()
	require.NoError(t, repo.EnsureRow(ctx, tenantID))

	now := time.Now().UTC()
	v1 := now.UnixNano()
	v2 := now.Add(time.Second).UnixNano()

	// First (newer) write applies.
	counters, applied, err := repo.SetSeatLimit(ctx, tenantID, 25, &v2, &now)
	require.NoError(t, err)
	require.True(t, applied)
	require.NotNil(t, counters.SeatLimit)
	require.Equal(t, 25, *counters.SeatLimit)
	require.NotNil(t, counters.SeatLimitVersion)
	require.Equal(t, v2, *counters.SeatLimitVersion)

	// A stale, lower-version retry (the outbox redelivering an older
	// compute) must be rejected as a no-op, and must return the CURRENT
	// (newer) state, not the rejected value.
	older := now.Add(-time.Minute)
	stale, applied, err := repo.SetSeatLimit(ctx, tenantID, 5, &v1, &older)
	require.NoError(t, err)
	require.False(t, applied)
	require.NotNil(t, stale.SeatLimit)
	require.Equal(t, 25, *stale.SeatLimit, "stale write must not have moved seat_limit backwards")
	require.Equal(t, v2, *stale.SeatLimitVersion)

	// A genuinely newer version still applies on top of v2.
	v3 := now.Add(2 * time.Second).UnixNano()
	newer, applied, err := repo.SetSeatLimit(ctx, tenantID, 30, &v3, &now)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 30, *newer.SeatLimit)
	require.Equal(t, v3, *newer.SeatLimitVersion)

	// An unversioned (manual/operator) PUT is always applied, even "after"
	// a versioned one -- backward compatible with pre-0014 behaviour.
	manual, applied, err := repo.SetSeatLimit(ctx, tenantID, 3, nil, nil)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 3, *manual.SeatLimit)
	// The manual write did not carry a version, so the column it leaves
	// behind is whatever the DB stored for a NULL EXCLUDED value: NULL,
	// per the INSERT list explicitly setting seat_limit_version to the
	// (nil) parameter.
	require.Nil(t, manual.SeatLimitVersion)

	// Verify via a fresh Get too (repo methods must agree).
	got, err := repo.Get(ctx, tenantID)
	require.NoError(t, err)
	require.Equal(t, 3, *got.SeatLimit)
}

// reserveSeatIfConsuming mirrors TeamInvitationHandler.CreateInvitation's
// exact gating (team_invitation_handler.go: "consumesSeat :=
// inv.ConsumesSeat() && h.seatCounters != nil") so this test proves the
// same seat-class exemption the handler relies on, without needing the
// handler's full role-catalogue/email wiring.
func reserveSeatIfConsuming(ctx context.Context, repo *SeatCounterRepository, tenantID uuid.UUID, seatClass models.SeatClass) (*models.SeatCounters, error) {
	inv := &models.TeamInvitation{SeatClass: seatClass}
	if !inv.ConsumesSeat() {
		return repo.Get(ctx, tenantID)
	}
	return repo.ReserveSeat(ctx, tenantID)
}

// TestSeatCounterPostgres_ExternalSeatClassNeverConsumesSeat_EvenAtLimit
// covers the lead-review requirement that accountant/guest ("external")
// seats -- the product roadmap's mali müşavir seats, seat_class=external --
// are free and must never count against seat_limit or ReserveSeat's atomic
// capacity check, in BOTH directions:
//   - a member-class reservation is correctly rejected once the tenant is
//     already at its (fully consumed) limit;
//   - an external-class "reservation" for the SAME tenant, at the SAME
//     already-exhausted limit, never touches seats_used/seats_pending and
//     is never blocked -- because it never calls ReserveSeat at all.
//
// This complements TestTeamInvitationPostgres_ExpirePendingAndReleaseSeats
// (which proves external never counts on the release/expiry side) by
// covering the reservation/admission side at the exact capacity boundary.
func TestSeatCounterPostgres_ExternalSeatClassNeverConsumesSeat_EvenAtLimit(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required; run hack/run-team-postgres-tests.sh (or an equivalent docker postgres) first")
	}
	pool := setupSeatCounterSchema(t, dsn)
	ctx := context.Background()
	repo := NewSeatCounterRepository(pool)

	tenantID := uuid.New()
	require.NoError(t, repo.EnsureRow(ctx, tenantID))
	limit := 1
	_, applied, err := repo.SetSeatLimit(ctx, tenantID, limit, nil, nil)
	require.NoError(t, err)
	require.True(t, applied)

	// Exhaust the tenant's single seat with a member-class reservation.
	counters, err := reserveSeatIfConsuming(ctx, repo, tenantID, models.SeatClassMember)
	require.NoError(t, err)
	require.Equal(t, 1, counters.SeatsPending)

	// A second member-class reservation must now be rejected: the tenant
	// is at its limit.
	_, err = reserveSeatIfConsuming(ctx, repo, tenantID, models.SeatClassMember)
	require.ErrorIs(t, err, ErrSeatLimitReached)

	// An external-class "reservation" at the SAME exhausted limit must
	// succeed (no error) precisely because it never reaches ReserveSeat,
	// and must leave seats_used/seats_pending completely unchanged.
	before, err := repo.Get(ctx, tenantID)
	require.NoError(t, err)
	afterExternal, err := reserveSeatIfConsuming(ctx, repo, tenantID, models.SeatClassExternal)
	require.NoError(t, err, "external seat_class must never be blocked by seat_limit")
	require.Equal(t, before.SeatsUsed, afterExternal.SeatsUsed, "external reservation must not touch seats_used")
	require.Equal(t, before.SeatsPending, afterExternal.SeatsPending, "external reservation must not touch seats_pending")

	// A service-class "reservation" gets the same exemption (ConsumesSeat
	// is false for both external and service).
	afterService, err := reserveSeatIfConsuming(ctx, repo, tenantID, models.SeatClassService)
	require.NoError(t, err, "service seat_class must never be blocked by seat_limit")
	require.Equal(t, before.SeatsUsed, afterService.SeatsUsed)
	require.Equal(t, before.SeatsPending, afterService.SeatsPending)
}
