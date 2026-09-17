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

const msgDynamicGroupRuleNotFound = "dynamic group rule not found"

// DynamicGroupRuleRepository handles DB operations for dynamic group rules.
type DynamicGroupRuleRepository struct {
	db *pgxpool.Pool
}

// NewDynamicGroupRuleRepository creates a new repository.
func NewDynamicGroupRuleRepository(db *pgxpool.Pool) *DynamicGroupRuleRepository {
	return &DynamicGroupRuleRepository{db: db}
}

// Create inserts a new dynamic group rule.
func (r *DynamicGroupRuleRepository) Create(ctx context.Context, rule *models.DynamicGroupRule) error {
	query := `
		INSERT INTO iam_dynamic_group_rules (tenant_id, group_id, name, description, conditions, is_active, priority, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, group_id, name) DO NOTHING
		RETURNING id, created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		rule.TenantID, rule.GroupID, rule.Name, rule.Description,
		rule.Conditions, rule.IsActive, rule.Priority, rule.CreatedBy,
	).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
}

// GetByID returns a rule by ID.
func (r *DynamicGroupRuleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DynamicGroupRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, conditions, is_active, priority, created_by, created_at, updated_at
		FROM iam_dynamic_group_rules
		WHERE id = $1`

	rule := &models.DynamicGroupRule{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&rule.ID, &rule.TenantID, &rule.GroupID, &rule.Name, &rule.Description,
		&rule.Conditions, &rule.IsActive, &rule.Priority, &rule.CreatedBy,
		&rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New(msgDynamicGroupRuleNotFound)
		}
		return nil, fmt.Errorf("DynamicGroupRuleRepository.GetByID: %w", err)
	}
	return rule, nil
}

// ListActiveByTenant returns all active rules for a tenant.
func (r *DynamicGroupRuleRepository) ListActiveByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.DynamicGroupRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, conditions, is_active, priority, created_by, created_at, updated_at
		FROM iam_dynamic_group_rules
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY priority ASC, created_at ASC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("DynamicGroupRuleRepository.ListActiveByTenant: %w", err)
	}
	defer rows.Close()

	var rules []models.DynamicGroupRule
	for rows.Next() {
		var rule models.DynamicGroupRule
		if err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.GroupID, &rule.Name, &rule.Description,
			&rule.Conditions, &rule.IsActive, &rule.Priority, &rule.CreatedBy,
			&rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("DynamicGroupRuleRepository.ListActiveByTenant scan: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListAllByTenant returns all rules (active and inactive) for admin listing.
func (r *DynamicGroupRuleRepository) ListAllByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.DynamicGroupRule, error) {
	query := `
		SELECT id, tenant_id, group_id, name, description, conditions, is_active, priority, created_by, created_at, updated_at
		FROM iam_dynamic_group_rules
		WHERE tenant_id = $1
		ORDER BY priority ASC, created_at ASC`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("DynamicGroupRuleRepository.ListAllByTenant: %w", err)
	}
	defer rows.Close()

	var rules []models.DynamicGroupRule
	for rows.Next() {
		var rule models.DynamicGroupRule
		if err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.GroupID, &rule.Name, &rule.Description,
			&rule.Conditions, &rule.IsActive, &rule.Priority, &rule.CreatedBy,
			&rule.CreatedAt, &rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("DynamicGroupRuleRepository.ListAllByTenant scan: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// CountByTenant returns the total number of rules for a tenant.
func (r *DynamicGroupRuleRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM iam_dynamic_group_rules WHERE tenant_id = $1`, tenantID).Scan(&count)
	return count, err
}

// Update modifies an existing rule.
func (r *DynamicGroupRuleRepository) Update(ctx context.Context, id uuid.UUID, req *models.UpdateDynamicGroupRuleRequest) error {
	query := `
		UPDATE iam_dynamic_group_rules
		SET is_active = COALESCE($2, is_active),
		    priority = COALESCE($3, priority),
		    updated_at = $4
		WHERE id = $1`

	tag, err := r.db.Exec(ctx, query, id, req.IsActive, req.Priority, time.Now())
	if err != nil {
		return fmt.Errorf("DynamicGroupRuleRepository.Update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgDynamicGroupRuleNotFound)
	}
	return nil
}

// Delete removes a rule by ID.
func (r *DynamicGroupRuleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM iam_dynamic_group_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DynamicGroupRuleRepository.Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New(msgDynamicGroupRuleNotFound)
	}
	return nil
}
