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

// AppAccessRepository handles database operations for app role assignments and auth policies.
type AppAccessRepository struct {
	db *pgxpool.Pool
}

// NewAppAccessRepository creates a new AppAccessRepository.
func NewAppAccessRepository(db *pgxpool.Pool) *AppAccessRepository {
	return &AppAccessRepository{db: db}
}

// GetRoleAssignmentsByUserAndClient returns all role assignments for a user+client pair.
func (r *AppAccessRepository) GetRoleAssignmentsByUserAndClient(ctx context.Context, userID, clientID uuid.UUID) ([]models.AppAccessRoleAssignment, error) {
	query := `
		SELECT ara.id, ara.tenant_id, ara.user_id, ara.client_id, ara.role_id,
		       ara.assigned_by, ara.created_at,
		       ro.name AS role_name
		FROM iam_app_role_assignments ara
		JOIN iam_roles ro ON ro.id = ara.role_id
		WHERE ara.user_id = $1 AND ara.client_id = $2
		ORDER BY ro.name`

	rows, err := r.db.Query(ctx, query, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("GetRoleAssignmentsByUserAndClient: %w", err)
	}
	defer rows.Close()

	var assignments []models.AppAccessRoleAssignment
	for rows.Next() {
		var a models.AppAccessRoleAssignment
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.ClientID, &a.RoleID,
			&a.AssignedBy, &a.CreatedAt,
			&a.RoleName,
		); err != nil {
			return nil, fmt.Errorf("GetRoleAssignmentsByUserAndClient scan: %w", err)
		}
		assignments = append(assignments, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRoleAssignmentsByUserAndClient rows: %w", err)
	}

	return assignments, nil
}

// CreateRoleAssignment creates a new app role assignment.
func (r *AppAccessRepository) CreateRoleAssignment(ctx context.Context, assignment *models.AppAccessRoleAssignment) error {
	query := `
		INSERT INTO iam_app_role_assignments (tenant_id, user_id, client_id, role_id, assigned_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`

	err := r.db.QueryRow(ctx, query,
		assignment.TenantID, assignment.UserID, assignment.ClientID, assignment.RoleID, assignment.AssignedBy,
	).Scan(&assignment.ID, &assignment.CreatedAt)
	if err != nil {
		return fmt.Errorf("CreateRoleAssignment: %w", err)
	}

	return nil
}

// DeleteRoleAssignment deletes an app role assignment by ID.
func (r *AppAccessRepository) DeleteRoleAssignment(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_app_role_assignments WHERE id = $1`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DeleteRoleAssignment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("role assignment not found")
	}
	return nil
}

// ListRoleAssignmentsByClient returns paginated role assignments for an application.
func (r *AppAccessRepository) ListRoleAssignmentsByClient(ctx context.Context, clientID uuid.UUID, page, pageSize int) ([]models.AppAccessRoleAssignment, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int64
	countQuery := `SELECT COUNT(*) FROM iam_app_role_assignments WHERE client_id = $1`
	if err := r.db.QueryRow(ctx, countQuery, clientID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListRoleAssignmentsByClient count: %w", err)
	}

	query := `
		SELECT ara.id, ara.tenant_id, ara.user_id, ara.client_id, ara.role_id,
		       ara.assigned_by, ara.created_at,
		       ro.name AS role_name,
		       u.username
		FROM iam_app_role_assignments ara
		JOIN iam_roles ro ON ro.id = ara.role_id
		JOIN iam_users u ON u.id = ara.user_id
		WHERE ara.client_id = $1
		ORDER BY ara.created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, clientID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ListRoleAssignmentsByClient: %w", err)
	}
	defer rows.Close()

	var assignments []models.AppAccessRoleAssignment
	for rows.Next() {
		var a models.AppAccessRoleAssignment
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.ClientID, &a.RoleID,
			&a.AssignedBy, &a.CreatedAt,
			&a.RoleName, &a.Username,
		); err != nil {
			return nil, 0, fmt.Errorf("ListRoleAssignmentsByClient scan: %w", err)
		}
		assignments = append(assignments, a)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListRoleAssignmentsByClient rows: %w", err)
	}

	return assignments, total, nil
}

// ListRoleAssignmentsByUser returns paginated role assignments for a user across all applications.
func (r *AppAccessRepository) ListRoleAssignmentsByUser(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]models.AppAccessRoleAssignment, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int64
	countQuery := `SELECT COUNT(*) FROM iam_app_role_assignments WHERE user_id = $1`
	if err := r.db.QueryRow(ctx, countQuery, userID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListRoleAssignmentsByUser count: %w", err)
	}

	query := `
		SELECT ara.id, ara.tenant_id, ara.user_id, ara.client_id, ara.role_id,
		       ara.assigned_by, ara.created_at,
		       ro.name AS role_name,
		       oc.client_id AS oauth_client_id, oc.client_name AS app_name
		FROM iam_app_role_assignments ara
		JOIN iam_roles ro ON ro.id = ara.role_id
		JOIN iam_oauth_clients oc ON oc.id = ara.client_id
		WHERE ara.user_id = $1
		ORDER BY ara.created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, userID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ListRoleAssignmentsByUser: %w", err)
	}
	defer rows.Close()

	var assignments []models.AppAccessRoleAssignment
	for rows.Next() {
		var a models.AppAccessRoleAssignment
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.UserID, &a.ClientID, &a.RoleID,
			&a.AssignedBy, &a.CreatedAt,
			&a.RoleName, &a.OAuthClientID, &a.AppName,
		); err != nil {
			return nil, 0, fmt.Errorf("ListRoleAssignmentsByUser scan: %w", err)
		}
		assignments = append(assignments, a)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ListRoleAssignmentsByUser rows: %w", err)
	}

	return assignments, total, nil
}

// GetAuthPolicyByClientID returns the auth policy for an application.
func (r *AppAccessRepository) GetAuthPolicyByClientID(ctx context.Context, clientID uuid.UUID) (*models.AppAuthPolicy, error) {
	query := `
		SELECT id, client_id, tenant_id, require_mfa, require_assignment,
		       allowed_ip_ranges, max_session_duration_seconds, created_at, updated_at
		FROM iam_app_auth_policies
		WHERE client_id = $1`

	policy := &models.AppAuthPolicy{}

	err := r.db.QueryRow(ctx, query, clientID).Scan(
		&policy.ID, &policy.ClientID, &policy.TenantID,
		&policy.RequireMFA, &policy.RequireAssignment,
		&policy.AllowedIPRanges, &policy.MaxSessionDurationSeconds,
		&policy.CreatedAt, &policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No policy = no restrictions
		}
		return nil, fmt.Errorf("GetAuthPolicyByClientID: %w", err)
	}

	return policy, nil
}

// CreateAuthPolicy creates a new app auth policy.
func (r *AppAccessRepository) CreateAuthPolicy(ctx context.Context, policy *models.AppAuthPolicy) error {
	query := `
		INSERT INTO iam_app_auth_policies (client_id, tenant_id, require_mfa, require_assignment, allowed_ip_ranges, max_session_duration_seconds)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRow(ctx, query,
		policy.ClientID, policy.TenantID, policy.RequireMFA, policy.RequireAssignment,
		policy.AllowedIPRanges, policy.MaxSessionDurationSeconds,
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("CreateAuthPolicy: %w", err)
	}

	return nil
}

// UpdateAuthPolicy updates an existing app auth policy.
func (r *AppAccessRepository) UpdateAuthPolicy(ctx context.Context, clientID uuid.UUID, req *models.UpdateAppAuthPolicyRequest) error {
	query := `
		UPDATE iam_app_auth_policies
		SET require_mfa = COALESCE($2, require_mfa),
		    require_assignment = COALESCE($3, require_assignment),
		    allowed_ip_ranges = COALESCE($4, allowed_ip_ranges),
		    max_session_duration_seconds = COALESCE($5, max_session_duration_seconds),
		    updated_at = $6
		WHERE client_id = $1`

	tag, err := r.db.Exec(ctx, query,
		clientID, req.RequireMFA, req.RequireAssignment,
		req.AllowedIPRanges, req.MaxSessionDurationSeconds,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("UpdateAuthPolicy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("auth policy not found for client")
	}
	return nil
}
