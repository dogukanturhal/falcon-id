// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RegistrationPolicyRepository handles persistence for iam_registration_policies.
type RegistrationPolicyRepository struct {
	pool *pgxpool.Pool
}

// NewRegistrationPolicyRepository creates a new RegistrationPolicyRepository.
func NewRegistrationPolicyRepository(pool *pgxpool.Pool) *RegistrationPolicyRepository {
	return &RegistrationPolicyRepository{pool: pool}
}

const regPolicyColumns = ` id, name, description, require_approval,
	allowed_redirect_patterns, max_apps_per_tenant,
	allowed_grant_types, is_default, created_at, updated_at `

// scanRegistrationPolicy scans a single row into a RegistrationPolicy.
func scanRegistrationPolicy(row interface{ Scan(dest ...any) error }) (*models.RegistrationPolicy, error) {
	var p models.RegistrationPolicy
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.RequireApproval,
		&p.AllowedRedirectPatterns, &p.MaxAppsPerTenant,
		&p.AllowedGrantTypes, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Create inserts a new registration policy and populates CreatedAt/UpdatedAt.
func (r *RegistrationPolicyRepository) Create(ctx context.Context, p *models.RegistrationPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_registration_policies (
			id, name, description, require_approval,
			allowed_redirect_patterns, max_apps_per_tenant,
			allowed_grant_types, is_default
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		p.ID, p.Name, p.Description, p.RequireApproval,
		p.AllowedRedirectPatterns, p.MaxAppsPerTenant,
		p.AllowedGrantTypes, p.IsDefault,
	).Scan(&p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("RegistrationPolicyRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a registration policy by primary key.
func (r *RegistrationPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RegistrationPolicy, error) {
	query := `SELECT` + regPolicyColumns + `FROM iam_registration_policies WHERE id = $1`
	p, err := scanRegistrationPolicy(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyRepository.GetByID: %w", err)
	}
	return p, nil
}

// GetDefault retrieves the policy marked is_default = true.
// Returns an error wrapping pgx.ErrNoRows when no default policy exists.
func (r *RegistrationPolicyRepository) GetDefault(ctx context.Context) (*models.RegistrationPolicy, error) {
	query := `SELECT` + regPolicyColumns + `FROM iam_registration_policies WHERE is_default = true LIMIT 1`
	p, err := scanRegistrationPolicy(r.pool.QueryRow(ctx, query))
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyRepository.GetDefault: %w", err)
	}
	return p, nil
}

// Update persists changes to an existing registration policy and returns the updated record.
func (r *RegistrationPolicyRepository) Update(ctx context.Context, p *models.RegistrationPolicy) error {
	query := `
		UPDATE iam_registration_policies
		SET name = $1,
		    description = $2,
		    require_approval = $3,
		    allowed_redirect_patterns = $4,
		    max_apps_per_tenant = $5,
		    allowed_grant_types = $6,
		    is_default = $7,
		    updated_at = NOW()
		WHERE id = $8
		RETURNING updated_at`

	err := r.pool.QueryRow(ctx, query,
		p.Name, p.Description, p.RequireApproval,
		p.AllowedRedirectPatterns, p.MaxAppsPerTenant,
		p.AllowedGrantTypes, p.IsDefault, p.ID,
	).Scan(&p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("RegistrationPolicyRepository.Update: %w", err)
	}
	return nil
}

// Delete removes a registration policy by ID.
func (r *RegistrationPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_registration_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("RegistrationPolicyRepository.Delete: %w", err)
	}
	return nil
}

// List returns all registration policies ordered by creation time.
func (r *RegistrationPolicyRepository) List(ctx context.Context) ([]models.RegistrationPolicy, error) {
	query := `SELECT` + regPolicyColumns + `FROM iam_registration_policies ORDER BY created_at ASC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("RegistrationPolicyRepository.List: %w", err)
	}
	defer rows.Close()

	var policies []models.RegistrationPolicy
	for rows.Next() {
		p, err := scanRegistrationPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("RegistrationPolicyRepository.List scan: %w", err)
		}
		policies = append(policies, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("RegistrationPolicyRepository.List rows: %w", err)
	}

	return policies, nil
}

// CountByTenantID returns the number of app registrations that belong to tenantID.
// This is used by the service layer to enforce MaxAppsPerTenant.
func (r *RegistrationPolicyRepository) CountByTenantID(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM iam_app_registrations WHERE tenant_id = $1`,
		tenantID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("RegistrationPolicyRepository.CountByTenantID: %w", err)
	}
	return count, nil
}
