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

// InvitationRepository is an exported type.
type InvitationRepository struct {
	db      DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of InvitationRepository scoped to the given realm.
func (r *InvitationRepository) WithRealmID(realmID uuid.UUID) *InvitationRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewInvitationRepository is an exported function.
func NewInvitationRepository(db *pgxpool.Pool) *InvitationRepository {
	return &InvitationRepository{db: db}
}

// Create creates a new invitation
func (r *InvitationRepository) Create(ctx context.Context, inv *models.UserInvitation) error {
	query := `
		INSERT INTO iam_user_invitations (
			id, user_id, tenant_id, realm_id, token_hash, invitation_type,
			invited_by_admin_id, invited_by_user_id, email, expires_at, custom_message
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING created_at, updated_at`

	if inv.ID == uuid.Nil {
		inv.ID = uuid.New()
	}

	return r.db.QueryRow(ctx, query,
		inv.ID, inv.UserID, inv.TenantID, inv.RealmID, inv.TokenHash, inv.InvitationType,
		inv.InvitedByAdminID, inv.InvitedByUserID, inv.Email, inv.ExpiresAt, inv.CustomMessage,
	).Scan(&inv.CreatedAt, &inv.UpdatedAt)
}

// GetByID retrieves an invitation by ID
func (r *InvitationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.UserInvitation, error) {
	inv := &models.UserInvitation{}
	query := `
		SELECT id, user_id, tenant_id, realm_id, token_hash, invitation_type,
			invited_by_admin_id, invited_by_user_id, email, email_sent_at, email_send_count,
			last_email_sent_at, status, accepted_at, accepted_ip, expires_at, custom_message,
			created_at, updated_at
		FROM iam_user_invitations
		WHERE id = $1`

	err := r.db.QueryRow(ctx, query, id).Scan(
		&inv.ID, &inv.UserID, &inv.TenantID, &inv.RealmID, &inv.TokenHash, &inv.InvitationType,
		&inv.InvitedByAdminID, &inv.InvitedByUserID, &inv.Email, &inv.EmailSentAt, &inv.EmailSendCount,
		&inv.LastEmailSentAt, &inv.Status, &inv.AcceptedAt, &inv.AcceptedIP, &inv.ExpiresAt, &inv.CustomMessage,
		&inv.CreatedAt, &inv.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return inv, nil
}

// GetByTokenHash retrieves an invitation by token hash
func (r *InvitationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.UserInvitation, error) {
	inv := &models.UserInvitation{}
	query := `
		SELECT id, user_id, tenant_id, realm_id, token_hash, invitation_type,
			invited_by_admin_id, invited_by_user_id, email, email_sent_at, email_send_count,
			last_email_sent_at, status, accepted_at, accepted_ip, expires_at, custom_message,
			created_at, updated_at
		FROM iam_user_invitations
		WHERE token_hash = $1`

	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&inv.ID, &inv.UserID, &inv.TenantID, &inv.RealmID, &inv.TokenHash, &inv.InvitationType,
		&inv.InvitedByAdminID, &inv.InvitedByUserID, &inv.Email, &inv.EmailSentAt, &inv.EmailSendCount,
		&inv.LastEmailSentAt, &inv.Status, &inv.AcceptedAt, &inv.AcceptedIP, &inv.ExpiresAt, &inv.CustomMessage,
		&inv.CreatedAt, &inv.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByTokenHash: %w", err)
	}
	return inv, nil
}

// GetByUserID retrieves the pending invitation for a user
func (r *InvitationRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.UserInvitation, error) {
	inv := &models.UserInvitation{}
	query := `
		SELECT id, user_id, tenant_id, realm_id, token_hash, invitation_type,
			invited_by_admin_id, invited_by_user_id, email, email_sent_at, email_send_count,
			last_email_sent_at, status, accepted_at, accepted_ip, expires_at, custom_message,
			created_at, updated_at
		FROM iam_user_invitations
		WHERE user_id = $1 AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&inv.ID, &inv.UserID, &inv.TenantID, &inv.RealmID, &inv.TokenHash, &inv.InvitationType,
		&inv.InvitedByAdminID, &inv.InvitedByUserID, &inv.Email, &inv.EmailSentAt, &inv.EmailSendCount,
		&inv.LastEmailSentAt, &inv.Status, &inv.AcceptedAt, &inv.AcceptedIP, &inv.ExpiresAt, &inv.CustomMessage,
		&inv.CreatedAt, &inv.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByUserID: %w", err)
	}
	return inv, nil
}

// GetPendingByEmail retrieves the pending invitation for an email
func (r *InvitationRepository) GetPendingByEmail(ctx context.Context, email string, tenantID uuid.UUID) (*models.UserInvitation, error) {
	inv := &models.UserInvitation{}
	query := `
		SELECT id, user_id, tenant_id, realm_id, token_hash, invitation_type,
			invited_by_admin_id, invited_by_user_id, email, email_sent_at, email_send_count,
			last_email_sent_at, status, accepted_at, accepted_ip, expires_at, custom_message,
			created_at, updated_at
		FROM iam_user_invitations
		WHERE email = $1 AND tenant_id = $2 AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1`

	err := r.db.QueryRow(ctx, query, email, tenantID).Scan(
		&inv.ID, &inv.UserID, &inv.TenantID, &inv.RealmID, &inv.TokenHash, &inv.InvitationType,
		&inv.InvitedByAdminID, &inv.InvitedByUserID, &inv.Email, &inv.EmailSentAt, &inv.EmailSendCount,
		&inv.LastEmailSentAt, &inv.Status, &inv.AcceptedAt, &inv.AcceptedIP, &inv.ExpiresAt, &inv.CustomMessage,
		&inv.CreatedAt, &inv.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetPendingByEmail: %w", err)
	}
	return inv, nil
}

// UpdateStatus updates the status of an invitation
func (r *InvitationRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.InvitationStatus) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("UpdateStatus: %w", err)
	}
	return nil
}

// MarkAsAccepted marks an invitation as accepted
func (r *InvitationRepository) MarkAsAccepted(ctx context.Context, id uuid.UUID, ipAddress string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations SET status = 'accepted', accepted_at = NOW(), accepted_ip = $1, updated_at = NOW() WHERE id = $2`,
		ipAddress, id,
	)
	if err != nil {
		return fmt.Errorf("MarkAsAccepted: %w", err)
	}
	return nil
}

// MarkAsRevoked marks an invitation as revoked
func (r *InvitationRepository) MarkAsRevoked(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations SET status = 'revoked', updated_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("MarkAsRevoked: %w", err)
	}
	return nil
}

// UpdateEmailSent updates the email sent tracking fields
func (r *InvitationRepository) UpdateEmailSent(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations
		SET email_sent_at = COALESCE(email_sent_at, NOW()),
			email_send_count = email_send_count + 1,
			last_email_sent_at = NOW(),
			updated_at = NOW()
		WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("UpdateEmailSent: %w", err)
	}
	return nil
}

// UpdateTokenHash updates the token hash for an invitation (used when resending)
func (r *InvitationRepository) UpdateTokenHash(ctx context.Context, id uuid.UUID, tokenHash string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations SET token_hash = $1, expires_at = $2, updated_at = NOW() WHERE id = $3`,
		tokenHash, expiresAt, id,
	)
	if err != nil {
		return fmt.Errorf("UpdateTokenHash: %w", err)
	}
	return nil
}

// ExpireOldInvitations marks expired invitations
func (r *InvitationRepository) ExpireOldInvitations(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations SET status = 'expired', updated_at = NOW() WHERE status = 'pending' AND expires_at < NOW()`,
	)
	if err != nil {
		return 0, fmt.Errorf("ExpireOldInvitations: %w", err)
	}
	return result.RowsAffected(), nil
}

// RevokePendingByUserID revokes all pending invitations for a user
func (r *InvitationRepository) RevokePendingByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_user_invitations SET status = 'revoked', updated_at = NOW() WHERE user_id = $1 AND status = 'pending'`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("RevokePendingByUserID: %w", err)
	}
	return nil
}

// ListByTenantID lists all invitations for a tenant
func (r *InvitationRepository) ListByTenantID(ctx context.Context, tenantID uuid.UUID, status *models.InvitationStatus) ([]*models.UserInvitation, error) {
	query := `
		SELECT id, user_id, tenant_id, realm_id, token_hash, invitation_type,
			invited_by_admin_id, invited_by_user_id, email, email_sent_at, email_send_count,
			last_email_sent_at, status, accepted_at, accepted_ip, expires_at, custom_message,
			created_at, updated_at
		FROM iam_user_invitations
		WHERE tenant_id = $1`

	args := []interface{}{tenantID}

	if status != nil {
		query += ` AND status = $2`
		args = append(args, *status)
	}

	query += ` ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ListByTenantID: %w", err)
	}
	defer rows.Close()

	var invitations []*models.UserInvitation
	for rows.Next() {
		inv := &models.UserInvitation{}
		err := rows.Scan(
			&inv.ID, &inv.UserID, &inv.TenantID, &inv.RealmID, &inv.TokenHash, &inv.InvitationType,
			&inv.InvitedByAdminID, &inv.InvitedByUserID, &inv.Email, &inv.EmailSentAt, &inv.EmailSendCount,
			&inv.LastEmailSentAt, &inv.Status, &inv.AcceptedAt, &inv.AcceptedIP, &inv.ExpiresAt, &inv.CustomMessage,
			&inv.CreatedAt, &inv.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("ListByTenantID: %w", err)
		}
		invitations = append(invitations, inv)
	}

	return invitations, rows.Err()
}

// CountRecentByEmail counts recent invitations for rate limiting
func (r *InvitationRepository) CountRecentByEmail(ctx context.Context, email string, since time.Time) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_user_invitations WHERE email = $1 AND created_at > $2`,
		email, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountRecentByEmail: %w", err)
	}
	return count, nil
}

// DeleteByID deletes an invitation by ID
func (r *InvitationRepository) DeleteByID(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM iam_user_invitations WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DeleteByID: %w", err)
	}
	return nil
}
