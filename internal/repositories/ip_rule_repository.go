// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// IPRuleRepository is an exported type.
type IPRuleRepository struct {
	pool    DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of IPRuleRepository scoped to the given realm.
func (r *IPRuleRepository) WithRealmID(realmID uuid.UUID) *IPRuleRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewIPRuleRepository is an exported function.
func NewIPRuleRepository(pool *pgxpool.Pool) *IPRuleRepository {
	return &IPRuleRepository{pool: pool}
}

// GetByID retrieves an IP rule by ID
func (r *IPRuleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.IPRule, error) {
	query := `
		SELECT id, tenant_id, name, description, ip_pattern, rule_type, priority,
			   is_active, applies_to, expires_at, hit_count, last_hit_at,
			   created_at, updated_at, created_by, updated_by
		FROM iam_ip_rules
		WHERE id = $1
	`

	var rule models.IPRule
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.IPPattern,
		&rule.RuleType, &rule.Priority, &rule.IsActive, &rule.AppliesTo, &rule.ExpiresAt,
		&rule.HitCount, &rule.LastHitAt, &rule.CreatedAt, &rule.UpdatedAt,
		&rule.CreatedBy, &rule.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get IP rule: %w", err)
	}

	return &rule, nil
}

// GetByTenantID retrieves all IP rules for a tenant
func (r *IPRuleRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	query := `
		SELECT id, tenant_id, name, description, ip_pattern, rule_type, priority,
			   is_active, applies_to, expires_at, hit_count, last_hit_at,
			   created_at, updated_at, created_by, updated_by
		FROM iam_ip_rules
		WHERE tenant_id = $1
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query IP rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.IPRule
	for rows.Next() {
		var rule models.IPRule
		err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.IPPattern,
			&rule.RuleType, &rule.Priority, &rule.IsActive, &rule.AppliesTo, &rule.ExpiresAt,
			&rule.HitCount, &rule.LastHitAt, &rule.CreatedAt, &rule.UpdatedAt,
			&rule.CreatedBy, &rule.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IP rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByTenantID: rows iteration: %w", err)
	}

	return rules, nil
}

// GetActiveRules retrieves all active IP rules for a tenant, ordered by priority
func (r *IPRuleRepository) GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.IPRule, error) {
	query := `
		SELECT id, tenant_id, name, description, ip_pattern, rule_type, priority,
			   is_active, applies_to, expires_at, hit_count, last_hit_at,
			   created_at, updated_at, created_by, updated_by
		FROM iam_ip_rules
		WHERE tenant_id = $1
		  AND is_active = true
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active IP rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.IPRule
	for rows.Next() {
		var rule models.IPRule
		err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.IPPattern,
			&rule.RuleType, &rule.Priority, &rule.IsActive, &rule.AppliesTo, &rule.ExpiresAt,
			&rule.HitCount, &rule.LastHitAt, &rule.CreatedAt, &rule.UpdatedAt,
			&rule.CreatedBy, &rule.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IP rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetActiveRules: rows iteration: %w", err)
	}

	return rules, nil
}

// Create creates a new IP rule
func (r *IPRuleRepository) Create(ctx context.Context, rule *models.IPRule) error {
	query := `
		INSERT INTO iam_ip_rules (
			tenant_id, name, description, ip_pattern, rule_type, priority,
			is_active, applies_to, expires_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at
	`

	err := r.pool.QueryRow(ctx, query,
		rule.TenantID, rule.Name, rule.Description, rule.IPPattern, rule.RuleType,
		rule.Priority, rule.IsActive, rule.AppliesTo, rule.ExpiresAt,
		rule.CreatedBy, rule.UpdatedBy,
	).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create IP rule: %w", err)
	}

	return nil
}

// Update updates an existing IP rule
func (r *IPRuleRepository) Update(ctx context.Context, rule *models.IPRule) error {
	query := `
		UPDATE iam_ip_rules
		SET name = $1, description = $2, ip_pattern = $3, rule_type = $4,
			priority = $5, is_active = $6, applies_to = $7, expires_at = $8,
			updated_by = $9
		WHERE id = $10
		RETURNING updated_at
	`

	err := r.pool.QueryRow(ctx, query,
		rule.Name, rule.Description, rule.IPPattern, rule.RuleType,
		rule.Priority, rule.IsActive, rule.AppliesTo, rule.ExpiresAt,
		rule.UpdatedBy, rule.ID,
	).Scan(&rule.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("IP rule not found")
	}
	if err != nil {
		return fmt.Errorf("failed to update IP rule: %w", err)
	}

	return nil
}

// Delete deletes an IP rule
func (r *IPRuleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_ip_rules WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete IP rule: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("IP rule not found")
	}

	return nil
}

// IncrementHitCount increments the hit count for a rule
func (r *IPRuleRepository) IncrementHitCount(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_ip_rules
		SET hit_count = hit_count + 1, last_hit_at = NOW()
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment hit count: %w", err)
	}

	return nil
}

// LogAction logs an IP rule action
func (r *IPRuleRepository) LogAction(ctx context.Context, log *models.IPRuleLog) error {
	query := `
		INSERT INTO iam_ip_rule_logs (rule_id, tenant_id, ip_address, action, endpoint, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(ctx, query,
		log.RuleID, log.TenantID, log.IPAddress, log.Action, log.Endpoint, log.UserAgent,
	).Scan(&log.ID, &log.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to log IP rule action: %w", err)
	}

	return nil
}

// GetRecentLogs retrieves recent IP rule logs for a tenant
func (r *IPRuleRepository) GetRecentLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error) {
	query := `
		SELECT id, rule_id, tenant_id, ip_address, action, endpoint, user_agent, created_at
		FROM iam_ip_rule_logs
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query IP rule logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.IPRuleLog
	for rows.Next() {
		var log models.IPRuleLog
		err := rows.Scan(
			&log.ID, &log.RuleID, &log.TenantID, &log.IPAddress,
			&log.Action, &log.Endpoint, &log.UserAgent, &log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IP rule log: %w", err)
		}
		logs = append(logs, &log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRecentLogs: rows iteration: %w", err)
	}

	return logs, nil
}

// GetDeniedLogs retrieves denied IP rule logs for a tenant
func (r *IPRuleRepository) GetDeniedLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.IPRuleLog, error) {
	query := `
		SELECT id, rule_id, tenant_id, ip_address, action, endpoint, user_agent, created_at
		FROM iam_ip_rule_logs
		WHERE tenant_id = $1 AND action = 'denied'
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query denied IP rule logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.IPRuleLog
	for rows.Next() {
		var log models.IPRuleLog
		err := rows.Scan(
			&log.ID, &log.RuleID, &log.TenantID, &log.IPAddress,
			&log.Action, &log.Endpoint, &log.UserAgent, &log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan IP rule log: %w", err)
		}
		logs = append(logs, &log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDeniedLogs: rows iteration: %w", err)
	}

	return logs, nil
}

// CleanupOldLogs removes logs older than the specified number of days
func (r *IPRuleRepository) CleanupOldLogs(ctx context.Context, daysToKeep int) (int64, error) {
	query := `
		DELETE FROM iam_ip_rule_logs
		WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
	`

	result, err := r.pool.Exec(ctx, query, daysToKeep)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old IP rule logs: %w", err)
	}

	return result.RowsAffected(), nil
}
