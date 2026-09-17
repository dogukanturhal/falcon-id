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

const msgDefaultAccessPolicyNotFound = "default access policy not found"

// DefaultAccessPolicyRepository handles DB operations for default access policies.
type DefaultAccessPolicyRepository struct {
	db *pgxpool.Pool
}

// NewDefaultAccessPolicyRepository creates a new repository.
func NewDefaultAccessPolicyRepository(db *pgxpool.Pool) *DefaultAccessPolicyRepository {
	return &DefaultAccessPolicyRepository{db: db}
}

// Create inserts a new default access policy.
func (r *DefaultAccessPolicyRepository) Create(ctx context.Context, policy *models.DefaultAccessPolicy) error {
	query := `
		INSERT INTO iam_default_access_policies (tenant_id, product_id, policy_type, target_id, scope, is_active, priority, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, product_id, policy_type, target_id) DO NOTHING
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRow(ctx, query,
		policy.TenantID, policy.ProductID, policy.PolicyType, policy.TargetID,
		policy.Scope, policy.IsActive, policy.Priority, policy.CreatedBy,
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("DefaultAccessPolicyRepository.Create: %w", err)
	}

	return nil
}

// GetByID returns a policy by ID.
func (r *DefaultAccessPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DefaultAccessPolicy, error) {
	query := `
		SELECT id, tenant_id, product_id, policy_type, target_id, scope, is_active, priority, created_by, created_at, updated_at
		FROM iam_default_access_policies
		WHERE id = $1`

	p := &models.DefaultAccessPolicy{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.TenantID, &p.ProductID, &p.PolicyType, &p.TargetID,
		&p.Scope, &p.IsActive, &p.Priority, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgDefaultAccessPolicyNotFound)
		}
		return nil, fmt.Errorf("DefaultAccessPolicyRepository.GetByID: %w", err)
	}

	return p, nil
}

// ListByTenant returns active policies for a tenant, ordered by priority.
func (r *DefaultAccessPolicyRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.DefaultAccessPolicy, error) {
	query := `
		SELECT dap.id, dap.tenant_id, dap.product_id, dap.policy_type, dap.target_id,
		       dap.scope, dap.is_active, dap.priority, dap.created_by, dap.created_at, dap.updated_at
		FROM iam_default_access_policies dap
		WHERE dap.tenant_id = $1 AND dap.is_active = true
		ORDER BY dap.priority ASC, dap.created_at ASC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("DefaultAccessPolicyRepository.ListByTenant: %w", err)
	}
	defer rows.Close()

	var policies []models.DefaultAccessPolicy
	for rows.Next() {
		var p models.DefaultAccessPolicy
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.ProductID, &p.PolicyType, &p.TargetID,
			&p.Scope, &p.IsActive, &p.Priority, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("DefaultAccessPolicyRepository.ListByTenant scan: %w", err)
		}
		policies = append(policies, p)
	}

	return policies, rows.Err()
}

// ListAllByTenant returns all policies (active and inactive) for admin listing.
func (r *DefaultAccessPolicyRepository) ListAllByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.DefaultAccessPolicy, error) {
	query := `
		SELECT dap.id, dap.tenant_id, dap.product_id, dap.policy_type, dap.target_id,
		       dap.scope, dap.is_active, dap.priority, dap.created_by, dap.created_at, dap.updated_at
		FROM iam_default_access_policies dap
		WHERE dap.tenant_id = $1
		ORDER BY dap.priority ASC, dap.created_at ASC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("DefaultAccessPolicyRepository.ListAllByTenant: %w", err)
	}
	defer rows.Close()

	var policies []models.DefaultAccessPolicy
	for rows.Next() {
		var p models.DefaultAccessPolicy
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.ProductID, &p.PolicyType, &p.TargetID,
			&p.Scope, &p.IsActive, &p.Priority, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("DefaultAccessPolicyRepository.ListAllByTenant scan: %w", err)
		}
		policies = append(policies, p)
	}

	return policies, rows.Err()
}

// CountByTenant returns the total number of policies for a tenant (for limit enforcement).
func (r *DefaultAccessPolicyRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_default_access_policies WHERE tenant_id = $1`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("DefaultAccessPolicyRepository.CountByTenant: %w", err)
	}
	return count, nil
}

// Update modifies an existing policy.
func (r *DefaultAccessPolicyRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateDefaultAccessPolicyRequest) error {
	query := `
		UPDATE iam_default_access_policies
		SET is_active = COALESCE($2, is_active),
		    priority = COALESCE($3, priority),
		    updated_at = $4
		WHERE id = $1`

	tag, err := r.db.Exec(ctx, query, id, req.IsActive, req.Priority, time.Now())
	if err != nil {
		return fmt.Errorf("DefaultAccessPolicyRepository.Update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgDefaultAccessPolicyNotFound)
	}
	return nil
}

// Delete removes a policy by ID.
func (r *DefaultAccessPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM iam_default_access_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DefaultAccessPolicyRepository.Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgDefaultAccessPolicyNotFound)
	}
	return nil
}
