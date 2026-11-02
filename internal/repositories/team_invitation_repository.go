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
	pgxpool "github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TeamInvitationRepository handles database operations for iam_team_invitations.
type TeamInvitationRepository struct {
	db DBTX
}

// ErrDuplicatePendingInvitation is returned when the database's authoritative
// partial unique index rejects a second pending invitation for an email.
var ErrDuplicatePendingInvitation = errors.New("duplicate pending invitation")

// NewTeamInvitationRepository creates a new TeamInvitationRepository.
func NewTeamInvitationRepository(db *pgxpool.Pool) *TeamInvitationRepository {
	return &TeamInvitationRepository{db: db}
}

// WithDB returns a shallow transaction-scoped clone. DBTX is deliberately
// shared with UserRepository so one security operation can compose both.
func (r *TeamInvitationRepository) WithDB(db DBTX) *TeamInvitationRepository {
	clone := *r
	clone.db = db
	return &clone
}

// InTransaction establishes the transaction boundary used by invitation
// mutations. Pool-backed callers retain the same repository API.
func (r *TeamInvitationRepository) InTransaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("team invitation transaction: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit makes rollback a no-op
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("team invitation transaction: commit: %w", err)
	}
	return nil
}

// Create inserts a new team invitation row.
func (r *TeamInvitationRepository) Create(ctx context.Context, inv *models.TeamInvitation) error {
	if inv.ID == uuid.Nil {
		inv.ID = uuid.New()
	}

	if inv.SeatClass == "" {
		inv.SeatClass = models.SeatClassMember
	}

	query := `
		INSERT INTO iam_team_invitations
		    (id, tenant_id, email, role_ids, invited_by, token, status, expires_at, seat_class)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`

	err := r.db.QueryRow(ctx, query,
		inv.ID,
		inv.TenantID,
		inv.Email,
		inv.RoleIDs,
		inv.InvitedBy,
		inv.Token,
		inv.Status,
		inv.ExpiresAt,
		inv.SeatClass,
	).Scan(&inv.CreatedAt)
	if IsPendingInvitationUniqueViolation(err) {
		return fmt.Errorf("Create: %w", ErrDuplicatePendingInvitation)
	}
	return err
}

// ExpirePendingForEmail expires an expired pending row before a re-invite and
// returns how many of the rows it expired held a seat reservation
// (seat_class='member'), which the caller must release in the same
// transaction. It runs in the same transaction as Create, leaving the partial
// unique index as the authoritative concurrency control for an active
// invitation.
//
// The background sweeper (ExpirePendingAndReleaseSeats) releases reservations
// only for rows it flips itself; a row flipped here is no longer 'pending', so
// the sweeper never sees it and its reservation would leak without this count.
func (r *TeamInvitationRepository) ExpirePendingForEmail(ctx context.Context, tenantID uuid.UUID, email string) (int, error) {
	rows, err := r.db.Query(ctx, `UPDATE iam_team_invitations
		SET status = 'expired'
		WHERE tenant_id = $1 AND lower(btrim(email)) = lower(btrim($2))
		  AND status = 'pending' AND expires_at <= NOW()
		RETURNING seat_class`, tenantID, email)
	if err != nil {
		return 0, fmt.Errorf("ExpirePendingForEmail: %w", err)
	}
	defer rows.Close()
	reserved := 0
	for rows.Next() {
		var seatClass models.SeatClass
		if err := rows.Scan(&seatClass); err != nil {
			return 0, fmt.Errorf("ExpirePendingForEmail: scan: %w", err)
		}
		if seatClass == models.SeatClassMember {
			reserved++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("ExpirePendingForEmail: %w", err)
	}
	return reserved, nil
}

// ListPendingByEmail returns the unexpired pending invitations addressed to the
// canonical (trimmed, lower-cased) email in every tenant, newest first. It backs
// the signed-in "my invitations" view; the caller must already have proved the
// mailbox (verified email).
func (r *TeamInvitationRepository) ListPendingByEmail(ctx context.Context, canonicalEmail string) ([]*models.TeamInvitation, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, email, role_ids, invited_by, token,
		       status, expires_at, created_at, accepted_at, seat_class, last_resent_at
		FROM iam_team_invitations
		WHERE lower(btrim(email)) = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC, id DESC`, canonicalEmail)
	if err != nil {
		return nil, fmt.Errorf("ListPendingByEmail: %w", err)
	}
	defer rows.Close()
	var invs []*models.TeamInvitation
	for rows.Next() {
		inv := &models.TeamInvitation{}
		if err := rows.Scan(&inv.ID, &inv.TenantID, &inv.Email, &inv.RoleIDs, &inv.InvitedBy, &inv.Token,
			&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt, &inv.SeatClass, &inv.LastResentAt); err != nil {
			return nil, fmt.Errorf("ListPendingByEmail: scan: %w", err)
		}
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}

// GetByID retrieves a team invitation by primary key.
// Returns (nil, nil) when not found (matching repository convention in this codebase).
func (r *TeamInvitationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.TeamInvitation, error) {
	return r.getByID(ctx, id, "")
}

// GetByIDForUpdate locks an invitation before a revocation transition.
func (r *TeamInvitationRepository) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.TeamInvitation, error) {
	return r.getByID(ctx, id, " FOR UPDATE")
}

func (r *TeamInvitationRepository) getByID(ctx context.Context, id uuid.UUID, lock string) (*models.TeamInvitation, error) {
	inv := &models.TeamInvitation{}
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, email, role_ids, invited_by, token,
		       status, expires_at, created_at, accepted_at, seat_class, last_resent_at
		FROM iam_team_invitations WHERE id = $1`+lock, id,
	).Scan(
		&inv.ID, &inv.TenantID, &inv.Email, &inv.RoleIDs, &inv.InvitedBy, &inv.Token,
		&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt, &inv.SeatClass, &inv.LastResentAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return inv, nil
}

// GetByToken retrieves a team invitation by its unique token value.
// Returns (nil, nil) when not found.
func (r *TeamInvitationRepository) GetByToken(ctx context.Context, token string) (*models.TeamInvitation, error) {
	return r.getByToken(ctx, token, "")
}

// GetByTokenForUpdate locks the token row for the lifetime of the enclosing
// transaction. Accept and revoke both use the same row lock, so a revoked
// invitation can never subsequently be accepted by a stale reader.
func (r *TeamInvitationRepository) GetByTokenForUpdate(ctx context.Context, token string) (*models.TeamInvitation, error) {
	return r.getByToken(ctx, token, " FOR UPDATE")
}

func (r *TeamInvitationRepository) getByToken(ctx context.Context, token, lock string) (*models.TeamInvitation, error) {
	inv := &models.TeamInvitation{}
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, email, role_ids, invited_by, token,
		       status, expires_at, created_at, accepted_at, seat_class, last_resent_at
		FROM iam_team_invitations
		WHERE token = $1
		   OR (token NOT LIKE 'sha256:%' AND token = $2)`+lock,
		models.TeamInvitationTokenDigest(token), token,
	).Scan(
		&inv.ID, &inv.TenantID, &inv.Email, &inv.RoleIDs, &inv.InvitedBy, &inv.Token,
		&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt, &inv.SeatClass, &inv.LastResentAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByToken: %w", err)
	}
	return inv, nil
}

// ListByTenant returns invitations for a tenant, optionally filtered by status.
// Pass status="" to return all statuses.
func (r *TeamInvitationRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, status string) ([]*models.TeamInvitation, error) {
	invitations, _, err := r.ListByTenantPage(ctx, tenantID, status, 1, 100)
	return invitations, err
}

// ListByTenantPage provides bounded, stable invitation inventory pagination.
func (r *TeamInvitationRepository) ListByTenantPage(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]*models.TeamInvitation, int64, error) {
	if page < 1 || pageSize < 1 {
		return nil, 0, fmt.Errorf("ListByTenantPage: invalid pagination")
	}
	var total int64
	countQuery := `SELECT COUNT(*) FROM iam_team_invitations WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if status != "" {
		countQuery += ` AND status = $2`
		args = append(args, status)
	}
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListByTenantPage: count: %w", err)
	}
	var (
		rows pgx.Rows
		err  error
	)
	if status != "" {
		rows, err = r.db.Query(ctx, `
			SELECT id, tenant_id, email, role_ids, invited_by, token,
			       status, expires_at, created_at, accepted_at, seat_class, last_resent_at
			FROM iam_team_invitations
			WHERE tenant_id = $1 AND status = $2
			ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, tenantID, status, pageSize, (page-1)*pageSize)
	} else {
		rows, err = r.db.Query(ctx, `
			SELECT id, tenant_id, email, role_ids, invited_by, token,
			       status, expires_at, created_at, accepted_at, seat_class, last_resent_at
			FROM iam_team_invitations
			WHERE tenant_id = $1
			ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, tenantID, pageSize, (page-1)*pageSize)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("ListByTenantPage: %w", err)
	}
	defer rows.Close()

	var invs []*models.TeamInvitation
	for rows.Next() {
		inv := &models.TeamInvitation{}
		if err := rows.Scan(
			&inv.ID, &inv.TenantID, &inv.Email, &inv.RoleIDs, &inv.InvitedBy, &inv.Token,
			&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt, &inv.SeatClass, &inv.LastResentAt,
		); err != nil {
			return nil, 0, fmt.Errorf("ListByTenantPage: scan: %w", err)
		}
		invs = append(invs, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListByTenantPage: rows: %w", err)
	}
	return invs, total, nil
}

// UpdateStatus sets the status (and optionally accepted_at) on an invitation.
func (r *TeamInvitationRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.TeamInvitationStatus) error {
	var query string
	if status == models.TeamInvitationStatusAccepted {
		query = `UPDATE iam_team_invitations
		         SET status = $1, accepted_at = NOW()
		         WHERE id = $2`
	} else {
		query = `UPDATE iam_team_invitations
		         SET status = $1
		         WHERE id = $2`
	}
	_, err := r.db.Exec(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("UpdateStatus: %w", err)
	}
	return nil
}

// TransitionPending performs the state change as a compare-and-set. Callers
// must hold the invitation row lock; the CAS remains a defence against future
// call sites that do not.
func (r *TeamInvitationRepository) TransitionPending(ctx context.Context, id uuid.UUID, status models.TeamInvitationStatus) (bool, error) {
	query := `UPDATE iam_team_invitations SET status = $1 WHERE id = $2 AND status = 'pending'`
	if status == models.TeamInvitationStatusAccepted {
		query = `UPDATE iam_team_invitations SET status = $1, accepted_at = NOW() WHERE id = $2 AND status = 'pending'`
	}
	result, err := r.db.Exec(ctx, query, status, id)
	if err != nil {
		return false, fmt.Errorf("TransitionPending: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// IsPendingInvitationUniqueViolation identifies the partial unique index
// owned by the the GitOps repository worktree. Creation intentionally relies on
// that authority instead of a racy preflight query.
func IsPendingInvitationUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_iam_team_invitations_pending_tenant_email_normalized_unique"
}

// HasPendingInvitation returns true if there is already a pending invitation
// for the given email within the tenant. Used to prevent duplicate invitations.
func (r *TeamInvitationRepository) HasPendingInvitation(ctx context.Context, tenantID uuid.UUID, email string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM iam_team_invitations
		WHERE tenant_id = $1 AND email = $2 AND status = 'pending' AND expires_at > NOW()`,
		tenantID, email,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("HasPendingInvitation: %w", err)
	}
	return count > 0, nil
}

// TeamInvitationResendRateLimit is the minimum interval between two resends
// of the same invitation (the product specification §13.17:
// "max 1 resend per invitation per 5 minutes").
const TeamInvitationResendRateLimit = 5 * time.Minute

// ErrResendRateLimited is returned by Resend when called again inside the
// rate-limit window. Callers translate this into 429.
var ErrResendRateLimited = errors.New("resend rate limited")

// Resend is an atomic compare-and-set: only a still-pending invitation whose
// last_resent_at (or never resent) is older than the rate limit window gets
// its expires_at pushed to newExpiry and last_resent_at set to now(). Returns
// false (no error) if the row is missing, not pending, or was resent too
// recently — callers distinguish "not found"/"not pending" from "rate
// limited" via a follow-up GetByID if they need a more specific response.
func (r *TeamInvitationRepository) Resend(ctx context.Context, id uuid.UUID, newExpiry time.Time, newTokenDigest string) (bool, error) {
	result, err := r.db.Exec(ctx, `
		UPDATE iam_team_invitations
		SET expires_at = $2, last_resent_at = NOW(), token = $3
		WHERE id = $1 AND status = 'pending'
		  AND (last_resent_at IS NULL OR last_resent_at <= NOW() - INTERVAL '5 minutes')`,
		id, newExpiry, newTokenDigest,
	)
	if err != nil {
		return false, fmt.Errorf("Resend: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// ExpirePendingAndReleaseSeats sweeps all pending invitations past
// expires_at to 'expired' and returns, per tenant, how many of them were
// seat_class='member' (i.e. how many pending seat reservations the caller
// must release via SeatCounterRepository.ReleaseReservationsBulk).
//
// This intentionally selects the affected rows in the SAME statement as the
// status flip (a single UPDATE ... RETURNING), so there is no window where a
// row could be re-read as still-pending by a concurrent accept between an
// expire-scan and an update — the row's own lock during the UPDATE is what
// accept's GetByTokenForUpdate contends with.
func (r *TeamInvitationRepository) ExpirePendingAndReleaseSeats(ctx context.Context) (map[uuid.UUID]int, error) {
	rows, err := r.db.Query(ctx, `
		UPDATE iam_team_invitations
		SET status = 'expired'
		WHERE status = 'pending' AND expires_at <= NOW()
		RETURNING tenant_id, seat_class`)
	if err != nil {
		return nil, fmt.Errorf("ExpirePendingAndReleaseSeats: %w", err)
	}
	defer rows.Close()

	counts := make(map[uuid.UUID]int)
	for rows.Next() {
		var tenantID uuid.UUID
		var seatClass models.SeatClass
		if err := rows.Scan(&tenantID, &seatClass); err != nil {
			return nil, fmt.Errorf("ExpirePendingAndReleaseSeats: scan: %w", err)
		}
		if seatClass == models.SeatClassMember {
			counts[tenantID]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ExpirePendingAndReleaseSeats: rows: %w", err)
	}
	return counts, nil
}
