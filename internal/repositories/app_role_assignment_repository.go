// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ApplicationRoleAssignmentRepository handles database operations for app role assignments.
type ApplicationRoleAssignmentRepository struct {
	pool *pgxpool.Pool
}

// NewApplicationRoleAssignmentRepository creates a new ApplicationRoleAssignmentRepository.
func NewApplicationRoleAssignmentRepository(pool *pgxpool.Pool) *ApplicationRoleAssignmentRepository {
	return &ApplicationRoleAssignmentRepository{pool: pool}
}

const appRoleAssignmentColumns = `id, application_id, app_role_id, principal_type, principal_id, tenant_id, assigned_by, created_at`

func scanAssignment(s interface {
	Scan(dest ...interface{}) error
},
) (*models.ApplicationRoleAssignment, error) {
	var a models.ApplicationRoleAssignment
	err := s.Scan(
		&a.ID, &a.ApplicationID, &a.AppRoleID, &a.PrincipalType,
		&a.PrincipalID, &a.TenantID, &a.AssignedBy, &a.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Create inserts a new app role assignment.
func (r *ApplicationRoleAssignmentRepository) Create(ctx context.Context, a *models.ApplicationRoleAssignment) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_application_role_assignments
			(id, application_id, app_role_id, principal_type, principal_id, tenant_id, assigned_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at`

	err := r.pool.QueryRow(ctx, query,
		a.ID,
		a.ApplicationID,
		a.AppRoleID,
		a.PrincipalType,
		a.PrincipalID,
		a.TenantID,
		a.AssignedBy,
	).Scan(&a.CreatedAt)
	if err != nil {
		return fmt.Errorf("ApplicationRoleAssignmentRepository.Create: %w", err)
	}
	return nil
}

// Delete removes an app role assignment by its primary key.
func (r *ApplicationRoleAssignmentRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		"DELETE FROM iam_application_role_assignments WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("ApplicationRoleAssignmentRepository.Delete: %w", err)
	}
	return nil
}

// ListByApplication returns all role assignments for a given application.
func (r *ApplicationRoleAssignmentRepository) ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.ApplicationRoleAssignment, error) {
	query := fmt.Sprintf(`
		SELECT %s
		FROM iam_application_role_assignments
		WHERE application_id = $1
		ORDER BY created_at DESC`, appRoleAssignmentColumns)

	rows, err := r.pool.Query(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("ApplicationRoleAssignmentRepository.ListByApplication query: %w", err)
	}
	defer rows.Close()

	return scanAssignments(rows)
}

// ListByPrincipal returns all role assignments held by a given principal.
func (r *ApplicationRoleAssignmentRepository) ListByPrincipal(ctx context.Context, principalType string, principalID uuid.UUID) ([]models.ApplicationRoleAssignment, error) {
	query := fmt.Sprintf(`
		SELECT %s
		FROM iam_application_role_assignments
		WHERE principal_type = $1 AND principal_id = $2
		ORDER BY created_at DESC`, appRoleAssignmentColumns)

	rows, err := r.pool.Query(ctx, query, principalType, principalID)
	if err != nil {
		return nil, fmt.Errorf("ApplicationRoleAssignmentRepository.ListByPrincipal query: %w", err)
	}
	defer rows.Close()

	return scanAssignments(rows)
}

// GetByID retrieves a single assignment by its UUID.
func (r *ApplicationRoleAssignmentRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ApplicationRoleAssignment, error) {
	query := fmt.Sprintf(`
		SELECT %s
		FROM iam_application_role_assignments
		WHERE id = $1`, appRoleAssignmentColumns)

	a, err := scanAssignment(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("ApplicationRoleAssignmentRepository.GetByID: %w", err)
	}
	return a, nil
}

// scanAssignments scans a pgx Rows cursor into a slice of ApplicationRoleAssignment.
func scanAssignments(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
},
) ([]models.ApplicationRoleAssignment, error) {
	var assignments []models.ApplicationRoleAssignment
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("ApplicationRoleAssignmentRepository scan: %w", err)
		}
		assignments = append(assignments, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ApplicationRoleAssignmentRepository rows: %w", err)
	}
	return assignments, nil
}
