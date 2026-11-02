// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// UserMembershipRepository owns iam_user_memberships: the tenant<->user
// membership + seat_class ledger created when a team invitation is accepted
// (the product specification §13.7). This table, not a live
// COUNT(*) over iam_users, is the seat-counting source of truth that
// tenant_seat_counters.seats_used tracks.
type UserMembershipRepository struct {
	db DBTX
}

// NewUserMembershipRepository creates a new UserMembershipRepository.
// Every tenant-keyed method runs under that tenant's RLS scope
// (WithTenantScope): the table has FORCE RLS and its callers include paths
// with no tenant GUC (accept from a partner tenant, external-member list and
// revoke).
func NewUserMembershipRepository(db *pgxpool.Pool) *UserMembershipRepository {
	return &UserMembershipRepository{db: db}
}

// Upsert creates or reactivates a tenant<->user membership row. Called from
// TeamInvitationHandler.AcceptInvitation inside the same transaction as the
// invitation's TransitionPending(...Accepted) and the seat counter's
// ConfirmSeat, so acceptance is all-or-nothing.
//
// On conflict (tenant_id, user_id) — e.g. a previously deactivated member
// re-accepting a fresh invitation, or a duplicate accept race caught by the
// invitation's own row lock but landing here regardless — this updates
// seat_class/status/invitation_id/deactivated_at rather than erroring, since
// the membership identity (tenant, user) is unique and the latest accepted
// invitation should win.
func (r *UserMembershipRepository) Upsert(ctx context.Context, m *models.UserMembership) (*models.UserMembership, error) {
	var out models.UserMembership
	var invitationID *uuid.UUID
	err := WithTenantScope(ctx, r.db, m.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status, invitation_id)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET
				seat_class = EXCLUDED.seat_class,
				status = EXCLUDED.status,
				invitation_id = EXCLUDED.invitation_id,
				deactivated_at = NULL
			RETURNING id, tenant_id, user_id, seat_class, status, invitation_id, created_at, deactivated_at`,
			m.TenantID, m.UserID, m.SeatClass, models.UserMembershipStatusActive, m.InvitationID,
		).Scan(&out.ID, &out.TenantID, &out.UserID, &out.SeatClass, &out.Status, &invitationID, &out.CreatedAt, &out.DeactivatedAt)
	})
	out.InvitationID = invitationID
	if err != nil {
		return nil, fmt.Errorf("Upsert: %w", err)
	}
	return &out, nil
}

// GetByTenantAndUser returns the membership row for a tenant/user pair, or
// nil if none exists.
func (r *UserMembershipRepository) GetByTenantAndUser(ctx context.Context, tenantID, userID uuid.UUID) (*models.UserMembership, error) {
	var out models.UserMembership
	var invitationID *uuid.UUID
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id, tenant_id, user_id, seat_class, status, invitation_id, created_at, deactivated_at, access_expires_at
			FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2`,
			tenantID, userID,
		).Scan(&out.ID, &out.TenantID, &out.UserID, &out.SeatClass, &out.Status, &invitationID, &out.CreatedAt, &out.DeactivatedAt, &out.AccessExpiresAt)
	})
	out.InvitationID = invitationID
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTenantAndUser: %w", err)
	}
	return &out, nil
}

// Deactivate marks the tenant's active membership deactivated and, for a
// seat-consuming (member-class) row, frees its seat in the SAME transaction
// (tenant_seat_counters.seats_used - 1). It reports whether a row actually
// changed: only that row releases a seat, so deactivating twice frees one.
// Employee/external/service rows are seat-free and never touch the counter.
func (r *UserMembershipRepository) Deactivate(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	changed := false
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var billable bool
		err := tx.QueryRow(ctx, `
			UPDATE iam_user_memberships
			SET status = $3, deactivated_at = now()
			WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'
			RETURNING seat_class = 'member' AND NOT EXISTS
				(SELECT 1 FROM iam_users u WHERE u.id = iam_user_memberships.user_id AND u.username ILIKE 'svc-%')`,
			tenantID, userID, models.UserMembershipStatusDeactivated,
		).Scan(&billable)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		changed = true
		if billable {
			return (&SeatCounterRepository{db: tx}).ReleaseUsedSeat(ctx, tenantID)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("Deactivate: %w", err)
	}
	return changed, nil
}

// Reactivate marks a previously deactivated membership active again. For a
// member-class row it re-occupies a seat with a conditional increment
// (seats_used + seats_pending < seat_limit) in the same transaction and
// returns ErrSeatLimitReached, leaving the row deactivated, when the tenant
// is full. It reports whether a row actually changed.
func (r *UserMembershipRepository) Reactivate(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	changed := false
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var billable bool
		err := tx.QueryRow(ctx, `
			UPDATE iam_user_memberships
			SET status = $3, deactivated_at = NULL
			WHERE tenant_id = $1 AND user_id = $2 AND status = 'deactivated'
			RETURNING seat_class = 'member' AND NOT EXISTS
				(SELECT 1 FROM iam_users u WHERE u.id = iam_user_memberships.user_id AND u.username ILIKE 'svc-%')`,
			tenantID, userID, models.UserMembershipStatusActive,
		).Scan(&billable)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		changed = true
		if billable {
			return (&SeatCounterRepository{db: tx}).OccupyUsedSeat(ctx, tenantID)
		}
		return nil
	})
	if errors.Is(err, ErrSeatLimitReached) {
		return false, ErrSeatLimitReached
	}
	if err != nil {
		return false, fmt.Errorf("Reactivate: %w", err)
	}
	return changed, nil
}

// Delete removes the membership row (user removal) and, when it was an
// ACTIVE member-class row, frees its seat in the same transaction. A row
// that was already deactivated released its seat then, so it frees nothing.
func (r *UserMembershipRepository) Delete(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	removed := false
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var billable bool
		var status models.UserMembershipStatus
		err := tx.QueryRow(ctx, `
			DELETE FROM iam_user_memberships
			WHERE tenant_id = $1 AND user_id = $2
			RETURNING seat_class = 'member' AND NOT EXISTS
				(SELECT 1 FROM iam_users u WHERE u.id = iam_user_memberships.user_id AND u.username ILIKE 'svc-%'), status`,
			tenantID, userID,
		).Scan(&billable, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		removed = true
		if billable && status == models.UserMembershipStatusActive {
			return (&SeatCounterRepository{db: tx}).ReleaseUsedSeat(ctx, tenantID)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("Delete: %w", err)
	}
	return removed, nil
}

// ExternalMemberRow is one active seat_class='external' membership joined to
// the member's identity. The member's home tenant (iam_users.tenant_id) is a
// different tenant: external members are accountants who live in their own
// partner tenant and were invited into this one.
type ExternalMemberRow struct {
	UserID       uuid.UUID
	Email        string
	DisplayName  *string
	InvitationID *uuid.UUID
	CreatedAt    time.Time
}

// ListActiveExternal returns the tenant's active external members.
func (r *UserMembershipRepository) ListActiveExternal(ctx context.Context, tenantID uuid.UUID) ([]ExternalMemberRow, error) {
	out := make([]ExternalMemberRow, 0)
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.user_id, u.email, u.display_name, m.invitation_id, m.created_at
			FROM iam_user_memberships m
			JOIN iam_users u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND m.seat_class = 'external' AND m.status = 'active'
			ORDER BY m.created_at DESC`, tenantID)
		if err != nil {
			return fmt.Errorf("ListActiveExternal: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var row ExternalMemberRow
			if err := rows.Scan(&row.UserID, &row.Email, &row.DisplayName, &row.InvitationID, &row.CreatedAt); err != nil {
				return fmt.Errorf("ListActiveExternal: scan: %w", err)
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("ListActiveExternal: rows: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeactivateExternal ends an active external membership. It reports false
// when the user holds no active external membership in the tenant, so a
// caller can never use it to deactivate a seat-holding member.
func (r *UserMembershipRepository) DeactivateExternal(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	tag, err := r.execScoped(ctx, tenantID, `
		UPDATE iam_user_memberships
		SET status = $3, deactivated_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND seat_class = 'external' AND status = 'active'`,
		tenantID, userID, models.UserMembershipStatusDeactivated,
	)
	if err != nil {
		return false, fmt.Errorf("DeactivateExternal: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// execScoped runs one tenant-keyed statement under that tenant's RLS scope.
func (r *UserMembershipRepository) execScoped(ctx context.Context, tenantID uuid.UUID, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	var tag pgconn.CommandTag
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		var err error
		tag, err = tx.Exec(ctx, sql, args...)
		return err
	})
	return tag, err
}

// TouchLastUsed stamps last_used_at on an active membership. Called after a
// successful tenant token exchange; the stamp picks the default company when a
// person holds more than one active membership.
func (r *UserMembershipRepository) TouchLastUsed(ctx context.Context, tenantID, userID uuid.UUID) error {
	_, err := r.execScoped(ctx, tenantID,
		`UPDATE iam_user_memberships SET last_used_at = now() WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'`,
		tenantID, userID)
	if err != nil {
		return fmt.Errorf("TouchLastUsed: %w", err)
	}
	return nil
}

// UpsertEmployee creates or reactivates the employee-class membership of userID in tenantID (R-HR WP-21). It never
// touches a seat counter: employee seats are seat-free. Called only by the S2S employee-accounts endpoint, inside the
// same flow that creates the iam_users row. An existing membership of another class is left alone (ok=false).
func (r *UserMembershipRepository) UpsertEmployee(ctx context.Context, tenantID, userID uuid.UUID) (created bool, err error) {
	err = WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		tag, execErr := tx.Exec(ctx, `
			INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status)
			VALUES ($1, $2, 'employee', 'active')
			ON CONFLICT (tenant_id, user_id) DO UPDATE
			SET status = 'active', deactivated_at = NULL, access_expires_at = NULL
			WHERE iam_user_memberships.seat_class = 'employee'`,
			tenantID, userID)
		if execErr != nil {
			return execErr
		}
		created = tag.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("UpsertEmployee: %w", err)
	}
	return created, nil
}

// SetAccessExpiry sets (or clears with nil) the access expiry of an ACTIVE employee-class membership. It reports false
// when the user holds no such membership, so a member or external seat can never be expired through this path.
func (r *UserMembershipRepository) SetAccessExpiry(ctx context.Context, tenantID, userID uuid.UUID, expiresAt *time.Time) (bool, error) {
	tag, err := r.execScoped(ctx, tenantID, `
		UPDATE iam_user_memberships SET access_expires_at = $3
		WHERE tenant_id = $1 AND user_id = $2 AND seat_class = 'employee'`,
		tenantID, userID, expiresAt)
	if err != nil {
		return false, fmt.Errorf("SetAccessExpiry: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeactivateEmployee ends an employee-class membership (status deactivated), reporting false when the user holds none.
func (r *UserMembershipRepository) DeactivateEmployee(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	tag, err := r.execScoped(ctx, tenantID, `
		UPDATE iam_user_memberships SET status = 'deactivated', deactivated_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND seat_class = 'employee' AND status = 'active'`,
		tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("DeactivateEmployee: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ListExpiredEmployee returns up to limit users of tenantID whose active employee membership has passed access_expires_at.
func (r *UserMembershipRepository) ListExpiredEmployee(ctx context.Context, tenantID uuid.UUID, limit int) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT user_id FROM iam_user_memberships
			WHERE tenant_id = $1 AND seat_class = 'employee' AND status = 'active'
			  AND access_expires_at IS NOT NULL AND access_expires_at <= now()
			ORDER BY access_expires_at LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("ListExpiredEmployee: %w", err)
	}
	return out, nil
}

// CountActiveEmployeeSeatUsers counts the tenant's active, non-pending-deletion users that hold an employee-class membership
// (the users CountActiveByTenant and the seat-quota reconciler must not bill).
func (r *UserMembershipRepository) CountActiveEmployeeSeatUsers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM iam_users u
			JOIN iam_user_memberships m ON m.user_id = u.id AND m.tenant_id = $1 AND m.seat_class IN ('employee', 'kiosk', 'service', 'external')
			WHERE u.tenant_id = $1 AND u.is_active = true AND u.deletion_scheduled_at IS NULL`, tenantID).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("CountActiveEmployeeSeatUsers: %w", err)
	}
	return n, nil
}

// IsSeatFree reports whether userID holds a non-member membership in tenantID (any status): such a user never
// counted against the tenant's seat quota, so the lifecycle paths must not decrement/increment it.
func (r *UserMembershipRepository) IsSeatFree(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	var free bool
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM iam_user_memberships WHERE tenant_id = $1 AND user_id = $2 AND seat_class IN ('employee', 'kiosk', 'service', 'external'))
			OR EXISTS (SELECT 1 FROM iam_users WHERE tenant_id = $1 AND id = $2 AND username ILIKE 'svc-%')`,
			tenantID, userID).Scan(&free)
	})
	if err != nil {
		return false, fmt.Errorf("IsSeatFree: %w", err)
	}
	return free, nil
}

// ProvisionEmployeeTx records a freshly created employee-class user in ONE tenant-scoped transaction: the seat-free
// membership, the template role grant and the audit row. Either all of it lands or none (the caller then removes the
// user it just created).
func (r *UserMembershipRepository) ProvisionEmployeeTx(ctx context.Context, tenantID, userID, roleID uuid.UUID, audit *models.AuditLog) error {
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status)
			VALUES ($1, $2, 'employee', 'active')
			ON CONFLICT (tenant_id, user_id) DO UPDATE
			SET status = 'active', deactivated_at = NULL, access_expires_at = NULL
			WHERE iam_user_memberships.seat_class = 'employee'`, tenantID, userID); err != nil {
			return fmt.Errorf("membership: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, NULL)
			ON CONFLICT (user_id, role_id) DO NOTHING`, userID, roleID); err != nil {
			return fmt.Errorf("role grant: %w", err)
		}
		if audit != nil {
			if err := CreateAuditLogTx(ctx, tx, audit); err != nil {
				return fmt.Errorf("audit: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ProvisionEmployeeTx: %w", err)
	}
	return nil
}

// ProvisionKioskTx records a freshly created kiosk-class user (R6 WP-23) in ONE tenant-scoped transaction: the seat-free
// membership, the Operatör template role grant and the audit row. Either all of it lands or none (the caller then removes
// the user it just created). Never touches the seat counter.
func (r *UserMembershipRepository) ProvisionKioskTx(ctx context.Context, tenantID, userID, roleID uuid.UUID, audit *models.AuditLog) error {
	err := WithTenantScope(ctx, r.db, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO iam_user_memberships (tenant_id, user_id, seat_class, status)
			VALUES ($1, $2, 'kiosk', 'active')
			ON CONFLICT (tenant_id, user_id) DO UPDATE
			SET status = 'active', deactivated_at = NULL
			WHERE iam_user_memberships.seat_class = 'kiosk'`, tenantID, userID); err != nil {
			return fmt.Errorf("membership: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO iam_user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, NULL)
			ON CONFLICT (user_id, role_id) DO NOTHING`, userID, roleID); err != nil {
			return fmt.Errorf("role grant: %w", err)
		}
		if audit != nil {
			if err := CreateAuditLogTx(ctx, tx, audit); err != nil {
				return fmt.Errorf("audit: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ProvisionKioskTx: %w", err)
	}
	return nil
}

// DeactivateKiosk ends an ACTIVE kiosk-class membership. It reports false when the user holds no such membership, so the
// path can never switch off a seat-holding member.
func (r *UserMembershipRepository) DeactivateKiosk(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	tag, err := r.execScoped(ctx, tenantID, `
		UPDATE iam_user_memberships SET status = $3, deactivated_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND seat_class = 'kiosk' AND status = 'active'`,
		tenantID, userID, models.UserMembershipStatusDeactivated)
	if err != nil {
		return false, fmt.Errorf("DeactivateKiosk: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
