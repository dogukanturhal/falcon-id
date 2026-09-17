// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppInstallationRepository handles database operations for tenant app installations.
type AppInstallationRepository struct {
	db *pgxpool.Pool
}

// NewAppInstallationRepository creates a new AppInstallationRepository.
func NewAppInstallationRepository(db *pgxpool.Pool) *AppInstallationRepository {
	return &AppInstallationRepository{db: db}
}

// Create inserts a new app installation record and populates the server-generated
// fields: ID, InstalledAt, CreatedAt, and UpdatedAt.
func (r *AppInstallationRepository) Create(ctx context.Context, inst *models.AppInstallation) error {
	if inst.ID == uuid.Nil {
		inst.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_app_installations (
			id, tenant_id, product_id, installed_by, consent_scopes, status
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING installed_at, created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		inst.ID,
		inst.TenantID,
		inst.ProductID,
		inst.InstalledBy,
		inst.ConsentScopes,
		inst.Status,
	).Scan(&inst.InstalledAt, &inst.CreatedAt, &inst.UpdatedAt)
	if err != nil {
		return fmt.Errorf("AppInstallationRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves an app installation by its UUID.
func (r *AppInstallationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AppInstallation, error) {
	query := `
		SELECT id, tenant_id, product_id, installed_by, consent_scopes, status,
		       installed_at, uninstalled_at, created_at, updated_at
		FROM iam_app_installations
		WHERE id = $1
	`
	return r.scanOne(ctx, query, id)
}

// GetByTenantAndProduct retrieves the installation for the given (tenant, product) pair.
// Returns an error wrapping pgx.ErrNoRows if no matching row exists.
func (r *AppInstallationRepository) GetByTenantAndProduct(
	ctx context.Context,
	tenantID, productID uuid.UUID,
) (*models.AppInstallation, error) {
	query := `
		SELECT id, tenant_id, product_id, installed_by, consent_scopes, status,
		       installed_at, uninstalled_at, created_at, updated_at
		FROM iam_app_installations
		WHERE tenant_id = $1
		  AND product_id = $2
	`
	return r.scanOne(ctx, query, tenantID, productID)
}

// scanOne is a shared helper that scans a single row from iam_app_installations.
func (r *AppInstallationRepository) scanOne(ctx context.Context, query string, args ...interface{}) (*models.AppInstallation, error) {
	var inst models.AppInstallation

	err := r.db.QueryRow(ctx, query, args...).Scan(
		&inst.ID,
		&inst.TenantID,
		&inst.ProductID,
		&inst.InstalledBy,
		&inst.ConsentScopes,
		&inst.Status,
		&inst.InstalledAt,
		&inst.UninstalledAt,
		&inst.CreatedAt,
		&inst.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("AppInstallationRepository.scanOne: %w", err)
	}

	return &inst, nil
}

// List returns a paginated slice of installations for a tenant, optionally filtered
// by status. When status is an empty string all statuses are returned.
// It also returns the total count of matching rows for pagination metadata.
func (r *AppInstallationRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	status string,
	page, pageSize int,
) ([]models.AppInstallation, int64, error) {
	offset := (page - 1) * pageSize

	baseQuery := "FROM iam_app_installations WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	argIndex := 2

	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	// Count total matching rows.
	var total int64
	if err := r.db.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("AppInstallationRepository.List count: %w", err)
	}

	// Fetch the requested page.
	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, product_id, installed_by, consent_scopes, status,
		       installed_at, uninstalled_at, created_at, updated_at
		%s
		ORDER BY installed_at DESC
		LIMIT $%d OFFSET $%d`,
		baseQuery, argIndex, argIndex+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("AppInstallationRepository.List query: %w", err)
	}
	defer rows.Close()

	var installations []models.AppInstallation
	for rows.Next() {
		var inst models.AppInstallation
		if err := rows.Scan(
			&inst.ID,
			&inst.TenantID,
			&inst.ProductID,
			&inst.InstalledBy,
			&inst.ConsentScopes,
			&inst.Status,
			&inst.InstalledAt,
			&inst.UninstalledAt,
			&inst.CreatedAt,
			&inst.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("AppInstallationRepository.List scan: %w", err)
		}
		installations = append(installations, inst)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("AppInstallationRepository.List rows: %w", err)
	}

	return installations, total, nil
}

// UpdateStatus sets the lifecycle status of an installation and bumps updated_at.
func (r *AppInstallationRepository) UpdateStatus(
	ctx context.Context,
	id uuid.UUID,
	status models.AppInstallationStatus,
) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_app_installations
		 SET status = $1, updated_at = NOW()
		 WHERE id = $2`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("AppInstallationRepository.UpdateStatus: %w", err)
	}
	return nil
}

// SetUninstalledAt stamps the uninstalled_at column for the given installation.
func (r *AppInstallationRepository) SetUninstalledAt(
	ctx context.Context,
	id uuid.UUID,
	t time.Time,
) error {
	_, err := r.db.Exec(ctx,
		`UPDATE iam_app_installations
		 SET uninstalled_at = $1, updated_at = NOW()
		 WHERE id = $2`,
		t, id,
	)
	if err != nil {
		return fmt.Errorf("AppInstallationRepository.SetUninstalledAt: %w", err)
	}
	return nil
}
