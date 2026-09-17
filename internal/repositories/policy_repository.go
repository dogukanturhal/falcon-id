// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// PolicyRepository handles database operations for policies
type PolicyRepository struct {
	pool *pgxpool.Pool
}

// NewPolicyRepository creates a new policy repository
func NewPolicyRepository(pool *pgxpool.Pool) *PolicyRepository {
	return &PolicyRepository{pool: pool}
}

// Create creates a new policy
func (r *PolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	query := `
		INSERT INTO iam_policies (
			tenant_id, name, description, effect, priority, conditions,
			rego_code, is_global, is_active, is_system, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		policy.TenantID,
		policy.Name,
		policy.Description,
		policy.Effect,
		policy.Priority,
		policy.Conditions,
		policy.RegoCode,
		policy.IsGlobal,
		policy.IsActive,
		policy.IsSystem,
		policy.CreatedBy,
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// GetByID retrieves a policy by ID
func (r *PolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	query := `
		SELECT id, tenant_id, name, description, effect, priority, conditions,
			   rego_code, is_global, is_active, is_system, created_at, updated_at,
			   created_by, updated_by
		FROM iam_policies
		WHERE id = $1`

	policy := &models.Policy{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
		&policy.Effect, &policy.Priority, &policy.Conditions,
		&policy.RegoCode, &policy.IsGlobal, &policy.IsActive, &policy.IsSystem,
		&policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy, &policy.UpdatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	return policy, nil
}

// GetByTenant retrieves all policies for a tenant (including global policies)
func (r *PolicyRepository) GetByTenant(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]models.Policy, int64, error) {
	offset := (page - 1) * pageSize

	// Count query
	countQuery := `
		SELECT COUNT(*) FROM iam_policies
		WHERE tenant_id = $1 OR is_global = true`

	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count policies: %w", err)
	}

	// Data query
	query := `
		SELECT id, tenant_id, name, description, effect, priority, conditions,
			   rego_code, is_global, is_active, is_system, created_at, updated_at,
			   created_by, updated_by
		FROM iam_policies
		WHERE tenant_id = $1 OR is_global = true
		ORDER BY priority DESC, created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, query, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query policies: %w", err)
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var policy models.Policy
		err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&policy.Effect, &policy.Priority, &policy.Conditions,
			&policy.RegoCode, &policy.IsGlobal, &policy.IsActive, &policy.IsSystem,
			&policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy, &policy.UpdatedBy,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("GetByTenant: rows iteration: %w", err)
	}

	return policies, total, nil
}

// GetActive retrieves all active policies for a tenant (for OPA evaluation)
func (r *PolicyRepository) GetActive(ctx context.Context, tenantID uuid.UUID) ([]models.Policy, error) {
	query := `
		SELECT id, tenant_id, name, description, effect, priority, conditions,
			   rego_code, is_global, is_active, is_system, created_at, updated_at,
			   created_by, updated_by
		FROM iam_policies
		WHERE is_active = true AND (tenant_id = $1 OR is_global = true)
		ORDER BY
			CASE WHEN is_global = true AND is_system = true THEN 1
				 WHEN is_global = true THEN 2
				 WHEN is_system = true THEN 3
				 ELSE 4 END,
			priority DESC`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active policies: %w", err)
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var policy models.Policy
		err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&policy.Effect, &policy.Priority, &policy.Conditions,
			&policy.RegoCode, &policy.IsGlobal, &policy.IsActive, &policy.IsSystem,
			&policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy, &policy.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetActive: rows iteration: %w", err)
	}

	return policies, nil
}

// Update updates a policy
func (r *PolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	query := `
		UPDATE iam_policies SET
			name = $1,
			description = $2,
			effect = $3,
			priority = $4,
			conditions = $5,
			rego_code = $6,
			is_active = $7,
			updated_by = $8,
			updated_at = NOW()
		WHERE id = $9
		RETURNING updated_at`

	err := r.pool.QueryRow(ctx, query,
		policy.Name,
		policy.Description,
		policy.Effect,
		policy.Priority,
		policy.Conditions,
		policy.RegoCode,
		policy.IsActive,
		policy.UpdatedBy,
		policy.ID,
	).Scan(&policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	return nil
}

// Delete deletes a policy
func (r *PolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_policies WHERE id = $1 AND is_system = false`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("policy not found or is a system policy")
	}

	return nil
}

// Activate activates a policy
func (r *PolicyRepository) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE iam_policies SET is_active = true, updated_by = $1, updated_at = NOW()
		WHERE id = $2`

	_, err := r.pool.Exec(ctx, query, updatedBy, id)
	if err != nil {
		return fmt.Errorf("failed to activate policy: %w", err)
	}

	return nil
}

// Deactivate deactivates a policy
func (r *PolicyRepository) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE iam_policies SET is_active = false, updated_by = $1, updated_at = NOW()
		WHERE id = $2`

	_, err := r.pool.Exec(ctx, query, updatedBy, id)
	if err != nil {
		return fmt.Errorf("failed to deactivate policy: %w", err)
	}

	return nil
}

// LogAudit logs a policy change to the audit table
func (r *PolicyRepository) LogAudit(ctx context.Context, audit *models.PolicyAudit) error {
	query := `
		INSERT INTO iam_policy_audit (policy_id, action, old_value, new_value, performed_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, performed_at`

	err := r.pool.QueryRow(ctx, query,
		audit.PolicyID,
		audit.Action,
		audit.OldValue,
		audit.NewValue,
		audit.PerformedBy,
	).Scan(&audit.ID, &audit.PerformedAt)
	if err != nil {
		return fmt.Errorf("failed to log policy audit: %w", err)
	}

	return nil
}

// GetAuditHistory gets audit history for a policy
func (r *PolicyRepository) GetAuditHistory(ctx context.Context, policyID uuid.UUID, limit int) ([]models.PolicyAudit, error) {
	query := `
		SELECT id, policy_id, action, old_value, new_value, performed_by, performed_at
		FROM iam_policy_audit
		WHERE policy_id = $1
		ORDER BY performed_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, query, policyID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit history: %w", err)
	}
	defer rows.Close()

	var audits []models.PolicyAudit
	for rows.Next() {
		var audit models.PolicyAudit
		err := rows.Scan(
			&audit.ID, &audit.PolicyID, &audit.Action,
			&audit.OldValue, &audit.NewValue, &audit.PerformedBy, &audit.PerformedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit: %w", err)
		}
		audits = append(audits, audit)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAuditHistory: rows iteration: %w", err)
	}

	return audits, nil
}

// CountActive returns the count of active policies for a tenant (including global policies)
func (r *PolicyRepository) CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	query := `
		SELECT COUNT(*) FROM iam_policies
		WHERE is_active = true
		AND (tenant_id = $1 OR is_global = true)`

	var count int64
	err := r.pool.QueryRow(ctx, query, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active policies: %w", err)
	}

	return count, nil
}

// PolicyToJSON converts a policy to JSON for audit logging
func PolicyToJSON(policy *models.Policy) json.RawMessage {
	data, _ := json.Marshal(policy)
	return data
}
