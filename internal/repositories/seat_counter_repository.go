// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// SeatCounterRepository owns tenant_seat_counters: the single-row-per-tenant
// race-free reservation counter behind the product roadmap §2.1/§4.9's
// "seats_used + pending invites must never exceed seat_limit" rule
// (the product specification §13.2/§13.7).
//
// CONCURRENCY MODEL: every mutating method here is a single atomic
// UPDATE ... WHERE <condition> RETURNING ... statement, never a
// SELECT-then-decide-then-UPDATE. Postgres evaluates the WHERE clause and
// performs the row update atomically under the row's own lock, so two
// concurrent ReserveSeat calls against the same tenant_id can never both
// observe "under limit" and both succeed past it — the second transaction's
// UPDATE simply blocks on the first's row lock until it commits (or rolls
// back), then re-evaluates the WHERE clause against the now-current row.
// This is the same guarantee an explicit `SELECT ... FOR UPDATE` gives, with
// one fewer round trip and no separate lock-then-compare step to get wrong.
//
// FOLLOW-UP (documented per task instructions, not implemented on this
// branch): SeatLimit is set either by an operator via
// PUT /internal/v1/tenants/{id}/seat-limit (SeatLimitHandler) or, in the
// future, by a subscription-management/entitlements sync once
// included_seats (MAX across active module plans) + seat-pack quantities
// exist as queryable data in falcon-id (they do not today — grepped
// product_subscription_resolver.go, module_entitlement_checker.go and the
// whole tree for included_seats/seat_limit/iam_tenant_module_entitlements
// and found none). Until that sync lands, SeatLimit stays NULL (= not
// enforced) for a tenant unless someone calls the PUT endpoint.
type SeatCounterRepository struct {
	db DBTX
}

// NewSeatCounterRepository creates a new SeatCounterRepository.
func NewSeatCounterRepository(db *pgxpool.Pool) *SeatCounterRepository {
	return &SeatCounterRepository{db: db}
}

// EnsureRow idempotently creates the tenant's counter row (seat_limit NULL,
// seats_used/seats_pending 0) if one does not already exist. Safe to call
// from any transaction before a reservation attempt on a tenant that may
// predate this feature (e.g. one somehow missed by the 0013 migration
// backfill, or a freshly bootstrapped tenant).
func (r *SeatCounterRepository) EnsureRow(ctx context.Context, tenantID uuid.UUID) error {
	err := r.execScoped(ctx, tenantID, `
		INSERT INTO tenant_seat_counters (tenant_id)
		VALUES ($1)
		ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("EnsureRow: %w", err)
	}
	return nil
}

// ErrSeatLimitReached is returned by ReserveSeat when the atomic UPDATE's
// WHERE clause rejected the reservation (seats_used + seats_pending would
// meet or exceed seat_limit). Callers translate this into
// 409 problem+json code: seat_limit_reached.
var ErrSeatLimitReached = errors.New("seat limit reached")

// ReserveSeat atomically increments seats_pending by 1, but only if the
// tenant's seat_limit is unset (NULL — not yet configured, enforcement OFF)
// or seats_used+seats_pending is still below it. Returns the post-update
// counters on success, or ErrSeatLimitReached (with the pre-update counters,
// for the 409 body's seatLimit/seatsUsed/shortfall fields) when the
// reservation is rejected.
//
// Must be called inside the SAME transaction as the invitation INSERT it
// guards (see TeamInvitationHandler.CreateInvitation): if the insert later
// fails and the transaction rolls back, the reservation rolls back with it,
// so a failed invite never leaks a phantom pending seat.
func (r *SeatCounterRepository) ReserveSeat(ctx context.Context, tenantID uuid.UUID) (*models.SeatCounters, error) {
	var (
		counters  models.SeatCounters
		seatLimit *int
	)
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			UPDATE tenant_seat_counters
			SET seats_pending = seats_pending + 1, updated_at = now()
			WHERE tenant_id = $1
			  AND (seat_limit IS NULL OR seats_used + seats_pending < seat_limit)
			RETURNING tenant_id, seats_used, seats_pending, seat_limit, updated_at`,
			tenantID,
		).Scan(&counters.TenantID, &counters.SeatsUsed, &counters.SeatsPending, &seatLimit, &counters.UpdatedAt)
	})
	counters.SeatLimit = seatLimit
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the row doesn't exist (caller forgot EnsureRow — treat as a
		// programmer error surfaced as the same limit-reached signal so the
		// handler still returns a clean 409/500 rather than a bare SQL "no
		// rows") or the WHERE clause rejected the reservation. Distinguish
		// by re-reading the current counters for the 409 body.
		current, getErr := r.Get(ctx, tenantID)
		if getErr != nil {
			return nil, fmt.Errorf("ReserveSeat: seat limit reached, and re-read failed: %w", getErr)
		}
		return current, ErrSeatLimitReached
	}
	if err != nil {
		return nil, fmt.Errorf("ReserveSeat: %w", err)
	}
	return &counters, nil
}

// ReleaseReservation atomically decrements seats_pending by 1 (floored at 0)
// when an invitation that had reserved a seat is revoked, declined, or
// expires without being accepted.
func (r *SeatCounterRepository) ReleaseReservation(ctx context.Context, tenantID uuid.UUID) error {
	err := r.execScoped(ctx, tenantID, `
		UPDATE tenant_seat_counters
		SET seats_pending = GREATEST(seats_pending - 1, 0), updated_at = now()
		WHERE tenant_id = $1`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("ReleaseReservation: %w", err)
	}
	return nil
}

// ReleaseReservationsBulk decrements seats_pending for every tenant_id key in
// counts by the given count (floored at 0 per tenant), in one transaction.
// Used by the expiry sweep, which can expire several tenants' invitations in
// a single pass. The tenant RLS policy admits one tenant per GUC value, so
// each tenant gets its own scoped statement inside the shared transaction.
func (r *SeatCounterRepository) ReleaseReservationsBulk(ctx context.Context, counts map[uuid.UUID]int) error {
	if len(counts) == 0 {
		return nil
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ReleaseReservationsBulk: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit makes rollback a no-op
	for id, n := range counts {
		if n <= 0 {
			continue
		}
		if err := setTenantScope(ctx, tx, id); err != nil {
			return fmt.Errorf("ReleaseReservationsBulk: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE tenant_seat_counters
			SET seats_pending = GREATEST(seats_pending - $2, 0), updated_at = now()
			WHERE tenant_id = $1`,
			id, n,
		); err != nil {
			return fmt.Errorf("ReleaseReservationsBulk: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("ReleaseReservationsBulk: commit: %w", err)
	}
	return nil
}

// ConfirmSeat atomically converts a pending reservation into used capacity:
// seats_pending -= 1 (floored at 0), seats_used += 1. Called from
// AcceptInvitation in the same transaction as the iam_user_memberships
// upsert, so acceptance either fully lands (invitation accepted + membership
// created + seat converted) or fully rolls back.
func (r *SeatCounterRepository) ConfirmSeat(ctx context.Context, tenantID uuid.UUID) error {
	err := r.execScoped(ctx, tenantID, `
		UPDATE tenant_seat_counters
		SET seats_pending = GREATEST(seats_pending - 1, 0),
		    seats_used = seats_used + 1,
		    updated_at = now()
		WHERE tenant_id = $1`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("ConfirmSeat: %w", err)
	}
	return nil
}

// ReleaseUsedSeat atomically decrements seats_used by 1 (floored at 0).
// UserMembershipRepository.Deactivate/Delete call it in the SAME transaction
// as the membership change, and only for a row that actually moved from
// active to gone, so a repeated deactivate frees exactly one seat.
func (r *SeatCounterRepository) ReleaseUsedSeat(ctx context.Context, tenantID uuid.UUID) error {
	err := r.execScoped(ctx, tenantID, `
		UPDATE tenant_seat_counters
		SET seats_used = GREATEST(seats_used - 1, 0), updated_at = now()
		WHERE tenant_id = $1`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("ReleaseUsedSeat: %w", err)
	}
	return nil
}

// OccupyUsedSeat is the reactivation counterpart of ReleaseUsedSeat: a
// conditional increment of seats_used that applies only while
// seats_used + seats_pending < seat_limit (or no limit is configured), and
// returns ErrSeatLimitReached otherwise. Like ReserveSeat it is one atomic
// UPDATE ... WHERE, so concurrent reactivations and invitations can never
// jointly pass the limit.
func (r *SeatCounterRepository) OccupyUsedSeat(ctx context.Context, tenantID uuid.UUID) error {
	return WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
			return fmt.Errorf("OccupyUsedSeat: ensure row: %w", err)
		}
		tag, err := tx.Exec(ctx, `
			UPDATE tenant_seat_counters
			SET seats_used = seats_used + 1, updated_at = now()
			WHERE tenant_id = $1
			  AND (seat_limit IS NULL OR seats_used + seats_pending < seat_limit)`,
			tenantID)
		if err != nil {
			return fmt.Errorf("OccupyUsedSeat: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrSeatLimitReached
		}
		return nil
	})
}

// RecomputeUsedSeats rewrites seats_used from the membership ledger (active
// seat_class='member' rows of iam_user_memberships whose user is active and
// not pending deletion, the seat-counting source of truth) and reports the value it replaced and the recomputed one.
// SeatQuotaReconciler runs it per tenant so any drift left by a path that
// skipped Release/OccupyUsedSeat converges instead of persisting.
func (r *SeatCounterRepository) RecomputeUsedSeats(ctx context.Context, tenantID uuid.UUID) (previous, actual int, err error) {
	err = WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_seat_counters (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM iam_user_memberships m
			JOIN iam_users u ON u.id = m.user_id AND u.tenant_id = m.tenant_id
			WHERE m.tenant_id = $1 AND m.seat_class = 'member' AND m.status = 'active'
			  AND u.is_active = true AND u.deletion_scheduled_at IS NULL
			  AND u.username NOT ILIKE 'svc-%'`, tenantID).Scan(&actual); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT seats_used FROM tenant_seat_counters WHERE tenant_id = $1 FOR UPDATE`, tenantID).Scan(&previous); err != nil {
			return err
		}
		if previous == actual {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE tenant_seat_counters SET seats_used = $2, updated_at = now() WHERE tenant_id = $1`, tenantID, actual)
		return err
	})
	if err != nil {
		return 0, 0, fmt.Errorf("RecomputeUsedSeats: %w", err)
	}
	return previous, actual, nil
}

// Get returns the current counters for a tenant, or nil if no row exists yet.
func (r *SeatCounterRepository) Get(ctx context.Context, tenantID uuid.UUID) (*models.SeatCounters, error) {
	var (
		counters     models.SeatCounters
		seatLimit    *int
		seatLimitVer *int64
		seatLimitCAt *time.Time
	)
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id, seats_used, seats_pending, seat_limit,
			       seat_limit_version, seat_limit_computed_at, updated_at
			FROM tenant_seat_counters WHERE tenant_id = $1`,
			tenantID,
		).Scan(&counters.TenantID, &counters.SeatsUsed, &counters.SeatsPending, &seatLimit,
			&seatLimitVer, &seatLimitCAt, &counters.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("Get: %w", err)
	}
	counters.SeatLimit = seatLimit
	counters.SeatLimitVersion = seatLimitVer
	counters.SeatLimitComputedAt = seatLimitCAt
	return &counters, nil
}

// SetSeatLimit upserts the tenant's seat_limit. Called by
// PUT /internal/v1/tenants/{id}/seat-limit (SeatLimitHandler, ServiceAuth +
// RequireScope("iam:seats:write")) — either an operator/manual call
// (version == nil, always applied, same behaviour as before 0014) or
// subscription-management's computed-seat-limit feed (R1 "trial-aware
// seat caps", spec 25 §4.5), which always sets version to its
// computed_at as Unix nanoseconds.
//
// STALE-WRITE REJECTION: when version is non-nil, the write is applied
// only if the row has no recorded seat_limit_version yet, or the
// existing seat_limit_version is strictly less than the incoming one.
// subscription-management retries this PUT via an outbox/reconciler
// sweep, so an older call can be redelivered after a newer one already
// landed; without this compare that redelivery would silently move the
// enforced cap backwards. The compare and the write happen in the same
// atomic INSERT ... ON CONFLICT DO UPDATE ... WHERE, so two concurrent
// PUTs for the same tenant can never both "win" — same pattern as
// ReserveSeat's doc comment.
//
// Returns (counters, applied=true) when the write took effect, or
// (currentCounters, applied=false) when it was rejected as stale — the
// caller (SeatLimitHandler) turns applied=false into a 409 with the
// current (newer) state rather than a 200 that implies the caller's
// value won.
//
// NEVER-EVICT: this method only ever writes the seat_limit/version/
// computed_at columns. It never touches seats_used/seats_pending and
// never deletes iam_user_memberships rows, so lowering the limit
// (including below current seats_used, e.g. expired/read_only or a
// canceled seat pack) can never evict an existing member — it only
// changes the threshold ReserveSeat checks for a FUTURE reservation
// (new invite).
func (r *SeatCounterRepository) SetSeatLimit(ctx context.Context, tenantID uuid.UUID, limit int, version *int64, computedAt *time.Time) (*models.SeatCounters, bool, error) {
	var (
		counters     models.SeatCounters
		seatLimit    *int
		seatLimitVer *int64
		seatLimitCAt *time.Time
	)
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO tenant_seat_counters
				(tenant_id, seat_limit, seat_limit_version, seat_limit_computed_at, updated_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (tenant_id) DO UPDATE
				SET seat_limit = EXCLUDED.seat_limit,
				    seat_limit_version = EXCLUDED.seat_limit_version,
				    seat_limit_computed_at = EXCLUDED.seat_limit_computed_at,
				    updated_at = now()
			WHERE $3::bigint IS NULL
			   OR tenant_seat_counters.seat_limit_version IS NULL
			   OR tenant_seat_counters.seat_limit_version < $3::bigint
			RETURNING tenant_id, seats_used, seats_pending, seat_limit, seat_limit_version, seat_limit_computed_at, updated_at`,
			tenantID, limit, version, computedAt,
		).Scan(&counters.TenantID, &counters.SeatsUsed, &counters.SeatsPending, &seatLimit, &seatLimitVer, &seatLimitCAt, &counters.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// WHERE clause rejected the write (or, in principle, a row didn't
		// exist and the INSERT's own conflict target found nothing to
		// return -- can't happen here since ON CONFLICT DO UPDATE only
		// fires when a conflicting row exists; the INSERT branch itself
		// always returns a row when there's no conflict). Re-read current
		// state for the caller's 409 body.
		current, getErr := r.Get(ctx, tenantID)
		if getErr != nil {
			return nil, false, fmt.Errorf("SetSeatLimit: stale write, and re-read failed: %w", getErr)
		}
		return current, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("SetSeatLimit: %w", err)
	}
	counters.SeatLimit = seatLimit
	counters.SeatLimitVersion = seatLimitVer
	counters.SeatLimitComputedAt = seatLimitCAt
	return &counters, true, nil
}

// execScoped runs one tenant-keyed statement under that tenant's RLS scope
// (see WithTenantScope).
func (r *SeatCounterRepository) execScoped(ctx context.Context, tenantID uuid.UUID, sql string, args ...interface{}) error {
	return WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}
