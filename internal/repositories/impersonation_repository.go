// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

const msgImpersonationList = "List: %w"

// ImpersonationRepository handles impersonation session database operations
type ImpersonationRepository struct {
	db                DBPool
	realmID           *uuid.UUID
	encryptionService *crypto.EncryptionService
}

// WithRealmID returns a shallow clone of ImpersonationRepository scoped to the given realm.
func (r *ImpersonationRepository) WithRealmID(realmID uuid.UUID) *ImpersonationRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewImpersonationRepository creates a new ImpersonationRepository
func NewImpersonationRepository(db *pgxpool.Pool) *ImpersonationRepository {
	return &ImpersonationRepository{db: db}
}

// SetEncryptionService wires the encryption service so JOINed iam_users PII
// (email/first_name/last_name) is decrypted post-scan. Without this, admin
// UIs surface `enc:v1:base64...` ciphertext.
func (r *ImpersonationRepository) SetEncryptionService(es *crypto.EncryptionService) {
	r.encryptionService = es
}

// Create creates a new impersonation session
func (r *ImpersonationRepository) Create(ctx context.Context, session *models.ImpersonationSession) error {
	query := `
		INSERT INTO iam_impersonation_sessions (
			id, tenant_id, admin_user_id, target_user_id, reason,
			ip_address, user_agent, started_at, original_session_id,
			impersonation_session_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.Exec(ctx, query,
		session.ID,
		session.TenantID,
		session.AdminUserID,
		session.TargetUserID,
		session.Reason,
		session.IPAddress,
		session.UserAgent,
		session.StartedAt,
		session.OriginalSessionID,
		session.ImpersonationSessionID,
		session.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	return nil
}

// GetByID retrieves an impersonation session by ID
func (r *ImpersonationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
	query := `
		SELECT id, tenant_id, admin_user_id, target_user_id, reason,
			ip_address, user_agent, started_at, ended_at,
			original_session_id, impersonation_session_id, created_at
		FROM iam_impersonation_sessions
		WHERE id = $1
	`

	session := &models.ImpersonationSession{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.TenantID,
		&session.AdminUserID,
		&session.TargetUserID,
		&session.Reason,
		&session.IPAddress,
		&session.UserAgent,
		&session.StartedAt,
		&session.EndedAt,
		&session.OriginalSessionID,
		&session.ImpersonationSessionID,
		&session.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}

	return session, nil
}

// GetActiveByAdminID gets the active impersonation session for an admin
func (r *ImpersonationRepository) GetActiveByAdminID(ctx context.Context, adminUserID uuid.UUID) (*models.ImpersonationSession, error) {
	query := `
		SELECT id, tenant_id, admin_user_id, target_user_id, reason,
			ip_address, user_agent, started_at, ended_at,
			original_session_id, impersonation_session_id, created_at
		FROM iam_impersonation_sessions
		WHERE admin_user_id = $1 AND ended_at IS NULL
		ORDER BY started_at DESC
		LIMIT 1
	`

	session := &models.ImpersonationSession{}
	err := r.db.QueryRow(ctx, query, adminUserID).Scan(
		&session.ID,
		&session.TenantID,
		&session.AdminUserID,
		&session.TargetUserID,
		&session.Reason,
		&session.IPAddress,
		&session.UserAgent,
		&session.StartedAt,
		&session.EndedAt,
		&session.OriginalSessionID,
		&session.ImpersonationSessionID,
		&session.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("GetActiveByAdminID: %w", err)
	}

	return session, nil
}

// EndSession ends an impersonation session
func (r *ImpersonationRepository) EndSession(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_impersonation_sessions
		SET ended_at = $1
		WHERE id = $2 AND ended_at IS NULL
	`

	result, err := r.db.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("EndSession: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("impersonation session not found or already ended")
	}

	return nil
}

// UpdateImpersonationSessionID updates the session ID of the impersonation
func (r *ImpersonationRepository) UpdateImpersonationSessionID(ctx context.Context, id uuid.UUID, sessionID uuid.UUID) error {
	query := `
		UPDATE iam_impersonation_sessions
		SET impersonation_session_id = $1
		WHERE id = $2
	`

	_, err := r.db.Exec(ctx, query, sessionID, id)
	if err != nil {
		return fmt.Errorf("UpdateImpersonationSessionID: %w", err)
	}
	return nil
}

// List lists impersonation sessions with pagination
func (r *ImpersonationRepository) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, adminUserID, targetUserID *uuid.UUID, activeOnly bool) ([]*models.ImpersonationSession, int, error) {
	offset := (page - 1) * pageSize

	// Build dynamic query
	baseQuery := `
		FROM iam_impersonation_sessions s
		WHERE s.tenant_id = $1
	`
	args := []interface{}{tenantID}
	argIndex := 2

	if adminUserID != nil {
		baseQuery += fmt.Sprintf(" AND s.admin_user_id = $%d", argIndex)
		args = append(args, *adminUserID)
		argIndex++
	}

	if targetUserID != nil {
		baseQuery += fmt.Sprintf(" AND s.target_user_id = $%d", argIndex)
		args = append(args, *targetUserID)
		argIndex++
	}

	if activeOnly {
		baseQuery += " AND s.ended_at IS NULL"
	}

	// Count query
	countQuery := "SELECT COUNT(*) " + baseQuery
	var total int
	err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf(msgImpersonationList, err)
	}

	// Main query
	query := `
		SELECT s.id, s.tenant_id, s.admin_user_id, s.target_user_id, s.reason,
			s.ip_address, s.user_agent, s.started_at, s.ended_at,
			s.original_session_id, s.impersonation_session_id, s.created_at
	` + baseQuery + fmt.Sprintf(" ORDER BY s.started_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf(msgImpersonationList, err)
	}
	defer rows.Close()

	var sessions []*models.ImpersonationSession
	for rows.Next() {
		session := &models.ImpersonationSession{}
		err := rows.Scan(
			&session.ID,
			&session.TenantID,
			&session.AdminUserID,
			&session.TargetUserID,
			&session.Reason,
			&session.IPAddress,
			&session.UserAgent,
			&session.StartedAt,
			&session.EndedAt,
			&session.OriginalSessionID,
			&session.ImpersonationSessionID,
			&session.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf(msgImpersonationList, err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List: rows iteration: %w", err)
	}

	return sessions, total, nil
}

// GetWithUsers retrieves an impersonation session with user details
func (r *ImpersonationRepository) GetWithUsers(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
	query := `
		SELECT
			s.id, s.tenant_id, s.admin_user_id, s.target_user_id, s.reason,
			s.ip_address, s.user_agent, s.started_at, s.ended_at,
			s.original_session_id, s.impersonation_session_id, s.created_at,
			a.id, a.username, a.email, a.first_name, a.last_name,
			t.id, t.username, t.email, t.first_name, t.last_name
		FROM iam_impersonation_sessions s
		JOIN iam_users a ON s.admin_user_id = a.id
		JOIN iam_users t ON s.target_user_id = t.id
		WHERE s.id = $1
	`

	session := &models.ImpersonationSession{}
	adminUser := &models.User{}
	targetUser := &models.User{}

	err := r.db.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.TenantID,
		&session.AdminUserID,
		&session.TargetUserID,
		&session.Reason,
		&session.IPAddress,
		&session.UserAgent,
		&session.StartedAt,
		&session.EndedAt,
		&session.OriginalSessionID,
		&session.ImpersonationSessionID,
		&session.CreatedAt,
		&adminUser.ID,
		&adminUser.Username,
		&adminUser.Email,
		&adminUser.FirstName,
		&adminUser.LastName,
		&targetUser.ID,
		&targetUser.Username,
		&targetUser.Email,
		&targetUser.FirstName,
		&targetUser.LastName,
	)
	if err != nil {
		return nil, fmt.Errorf("GetWithUsers: %w", err)
	}

	// Decrypt JOINed iam_users PII so the admin view shows plaintext, not
	// `enc:v1:base64...` ciphertext. No-op when encryptionService is nil
	// (test wiring) or when the value is empty.
	for _, u := range []*models.User{adminUser, targetUser} {
		if err := r.encryptionService.DecryptStringInPlace(&u.Email); err != nil {
			return nil, fmt.Errorf("GetWithUsers: decrypt email: %w", err)
		}
		if err := r.encryptionService.DecryptStringPtr(&u.FirstName); err != nil {
			return nil, fmt.Errorf("GetWithUsers: decrypt first_name: %w", err)
		}
		if err := r.encryptionService.DecryptStringPtr(&u.LastName); err != nil {
			return nil, fmt.Errorf("GetWithUsers: decrypt last_name: %w", err)
		}
	}

	session.AdminUser = adminUser
	session.TargetUser = targetUser

	return session, nil
}

// MarkSessionAsImpersonation marks a session as being an impersonation
func (r *ImpersonationRepository) MarkSessionAsImpersonation(ctx context.Context, sessionID, impersonatorID, impersonationSessionID uuid.UUID) error {
	query := `
		UPDATE iam_sessions
		SET impersonator_id = $1, impersonation_session_id = $2
		WHERE id = $3
	`

	_, err := r.db.Exec(ctx, query, impersonatorID, impersonationSessionID, sessionID)
	if err != nil {
		return fmt.Errorf("MarkSessionAsImpersonation: %w", err)
	}
	return nil
}

// ClearSessionImpersonation removes impersonation markers from a session
func (r *ImpersonationRepository) ClearSessionImpersonation(ctx context.Context, sessionID uuid.UUID) error {
	query := `
		UPDATE iam_sessions
		SET impersonator_id = NULL, impersonation_session_id = NULL
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("ClearSessionImpersonation: %w", err)
	}
	return nil
}

// GetSessionImpersonationStatus checks if a session is an impersonation
func (r *ImpersonationRepository) GetSessionImpersonationStatus(ctx context.Context, sessionID uuid.UUID) (*uuid.UUID, *uuid.UUID, error) {
	query := `
		SELECT impersonator_id, impersonation_session_id
		FROM iam_sessions
		WHERE id = $1
	`

	var impersonatorID, impersonationSessionID *uuid.UUID
	err := r.db.QueryRow(ctx, query, sessionID).Scan(&impersonatorID, &impersonationSessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("GetSessionImpersonationStatus: %w", err)
	}

	return impersonatorID, impersonationSessionID, nil
}
