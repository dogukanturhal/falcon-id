// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

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

	query := `
		INSERT INTO iam_team_invitations
		    (id, tenant_id, email, role_ids, invited_by, token, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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
	).Scan(&inv.CreatedAt)
	if IsPendingInvitationUniqueViolation(err) {
		return fmt.Errorf("Create: %w", ErrDuplicatePendingInvitation)
	}
	return err
}

// ExpirePendingForEmail releases an expired pending row before a re-invite.
// It runs in the same transaction as Create, leaving the partial unique index
// as the authoritative concurrency control for an active invitation.
func (r *TeamInvitationRepository) ExpirePendingForEmail(ctx context.Context, tenantID uuid.UUID, email string) error {
	_, err := r.db.Exec(ctx, `UPDATE iam_team_invitations
		SET status = 'expired'
		WHERE tenant_id = $1 AND lower(btrim(email)) = lower(btrim($2))
		  AND status = 'pending' AND expires_at <= NOW()`, tenantID, email)
	if err != nil {
		return fmt.Errorf("ExpirePendingForEmail: %w", err)
	}
	return nil
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
		       status, expires_at, created_at, accepted_at
		FROM iam_team_invitations WHERE id = $1`+lock, id,
	).Scan(
		&inv.ID, &inv.TenantID, &inv.Email, &inv.RoleIDs, &inv.InvitedBy, &inv.Token,
		&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt,
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
		       status, expires_at, created_at, accepted_at
		FROM iam_team_invitations
		WHERE token = $1
		   OR (token NOT LIKE 'sha256:%' AND token = $2)`+lock,
		models.TeamInvitationTokenDigest(token), token,
	).Scan(
		&inv.ID, &inv.TenantID, &inv.Email, &inv.RoleIDs, &inv.InvitedBy, &inv.Token,
		&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt,
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
			       status, expires_at, created_at, accepted_at
			FROM iam_team_invitations
			WHERE tenant_id = $1 AND status = $2
			ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4`, tenantID, status, pageSize, (page-1)*pageSize)
	} else {
		rows, err = r.db.Query(ctx, `
			SELECT id, tenant_id, email, role_ids, invited_by, token,
			       status, expires_at, created_at, accepted_at
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
			&inv.Status, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt,
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
