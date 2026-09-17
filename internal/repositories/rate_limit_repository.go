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

// RateLimitRepository is an exported type.
type RateLimitRepository struct {
	pool *pgxpool.Pool
}

// NewRateLimitRepository is an exported function.
func NewRateLimitRepository(pool *pgxpool.Pool) *RateLimitRepository {
	return &RateLimitRepository{pool: pool}
}

// GetRuleByID retrieves a rate limit rule by ID
func (r *RateLimitRepository) GetRuleByID(ctx context.Context, id uuid.UUID) (*models.RateLimitRule, error) {
	query := `
		SELECT id, tenant_id, name, description, endpoint_pattern, method,
			   max_requests, window_seconds, block_duration_seconds, scope,
			   is_active, priority, created_at, updated_at, created_by, updated_by
		FROM iam_rate_limit_rules
		WHERE id = $1
	`

	var rule models.RateLimitRule
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.EndpointPattern, &rule.Method,
		&rule.MaxRequests, &rule.WindowSeconds, &rule.BlockDurationSeconds, &rule.Scope,
		&rule.IsActive, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt, &rule.CreatedBy, &rule.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit rule: %w", err)
	}

	return &rule, nil
}

// GetRulesByTenantID retrieves all rate limit rules for a tenant
func (r *RateLimitRepository) GetRulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error) {
	query := `
		SELECT id, tenant_id, name, description, endpoint_pattern, method,
			   max_requests, window_seconds, block_duration_seconds, scope,
			   is_active, priority, created_at, updated_at, created_by, updated_by
		FROM iam_rate_limit_rules
		WHERE tenant_id = $1
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query rate limit rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.RateLimitRule
	for rows.Next() {
		var rule models.RateLimitRule
		err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.EndpointPattern, &rule.Method,
			&rule.MaxRequests, &rule.WindowSeconds, &rule.BlockDurationSeconds, &rule.Scope,
			&rule.IsActive, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt, &rule.CreatedBy, &rule.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rate limit rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRulesByTenantID: rows iteration: %w", err)
	}

	return rules, nil
}

// GetActiveRules retrieves all active rate limit rules for a tenant, ordered by priority
func (r *RateLimitRepository) GetActiveRules(ctx context.Context, tenantID uuid.UUID) ([]*models.RateLimitRule, error) {
	query := `
		SELECT id, tenant_id, name, description, endpoint_pattern, method,
			   max_requests, window_seconds, block_duration_seconds, scope,
			   is_active, priority, created_at, updated_at, created_by, updated_by
		FROM iam_rate_limit_rules
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active rate limit rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.RateLimitRule
	for rows.Next() {
		var rule models.RateLimitRule
		err := rows.Scan(
			&rule.ID, &rule.TenantID, &rule.Name, &rule.Description, &rule.EndpointPattern, &rule.Method,
			&rule.MaxRequests, &rule.WindowSeconds, &rule.BlockDurationSeconds, &rule.Scope,
			&rule.IsActive, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt, &rule.CreatedBy, &rule.UpdatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rate limit rule: %w", err)
		}
		rules = append(rules, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetActiveRules: rows iteration: %w", err)
	}

	return rules, nil
}

// Create creates a new rate limit rule
func (r *RateLimitRepository) Create(ctx context.Context, rule *models.RateLimitRule) error {
	query := `
		INSERT INTO iam_rate_limit_rules (
			tenant_id, name, description, endpoint_pattern, method,
			max_requests, window_seconds, block_duration_seconds, scope,
			is_active, priority, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, created_at, updated_at
	`

	err := r.pool.QueryRow(ctx, query,
		rule.TenantID, rule.Name, rule.Description, rule.EndpointPattern, rule.Method,
		rule.MaxRequests, rule.WindowSeconds, rule.BlockDurationSeconds, rule.Scope,
		rule.IsActive, rule.Priority, rule.CreatedBy, rule.UpdatedBy,
	).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create rate limit rule: %w", err)
	}

	return nil
}

// Update updates an existing rate limit rule
func (r *RateLimitRepository) Update(ctx context.Context, rule *models.RateLimitRule) error {
	query := `
		UPDATE iam_rate_limit_rules
		SET name = $1, description = $2, endpoint_pattern = $3, method = $4,
			max_requests = $5, window_seconds = $6, block_duration_seconds = $7,
			scope = $8, is_active = $9, priority = $10, updated_by = $11
		WHERE id = $12
		RETURNING updated_at
	`

	err := r.pool.QueryRow(ctx, query,
		rule.Name, rule.Description, rule.EndpointPattern, rule.Method,
		rule.MaxRequests, rule.WindowSeconds, rule.BlockDurationSeconds,
		rule.Scope, rule.IsActive, rule.Priority, rule.UpdatedBy, rule.ID,
	).Scan(&rule.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("rate limit rule not found")
	}
	if err != nil {
		return fmt.Errorf("failed to update rate limit rule: %w", err)
	}

	return nil
}

// Delete deletes a rate limit rule
func (r *RateLimitRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_rate_limit_rules WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete rate limit rule: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("rate limit rule not found")
	}

	return nil
}

// LogEvent logs a rate limit event
func (r *RateLimitRepository) LogEvent(ctx context.Context, event *models.RateLimitEvent) error {
	query := `
		INSERT INTO iam_rate_limit_events (
			rule_id, tenant_id, identifier, endpoint, request_count, blocked, blocked_until
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(ctx, query,
		event.RuleID, event.TenantID, event.Identifier, event.Endpoint,
		event.RequestCount, event.Blocked, event.BlockedUntil,
	).Scan(&event.ID, &event.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to log rate limit event: %w", err)
	}

	return nil
}

// GetRecentEvents retrieves recent rate limit events for a tenant
func (r *RateLimitRepository) GetRecentEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.RateLimitEvent, error) {
	query := `
		SELECT id, rule_id, tenant_id, identifier, endpoint, request_count, blocked, blocked_until, created_at
		FROM iam_rate_limit_events
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query rate limit events: %w", err)
	}
	defer rows.Close()

	var events []*models.RateLimitEvent
	for rows.Next() {
		var event models.RateLimitEvent
		err := rows.Scan(
			&event.ID, &event.RuleID, &event.TenantID, &event.Identifier, &event.Endpoint,
			&event.RequestCount, &event.Blocked, &event.BlockedUntil, &event.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rate limit event: %w", err)
		}
		events = append(events, &event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetRecentEvents: rows iteration: %w", err)
	}

	return events, nil
}

// GetBlockedEvents retrieves blocked rate limit events for a tenant
func (r *RateLimitRepository) GetBlockedEvents(ctx context.Context, tenantID uuid.UUID, limit int) ([]*models.RateLimitEvent, error) {
	query := `
		SELECT id, rule_id, tenant_id, identifier, endpoint, request_count, blocked, blocked_until, created_at
		FROM iam_rate_limit_events
		WHERE tenant_id = $1 AND blocked = true
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocked rate limit events: %w", err)
	}
	defer rows.Close()

	var events []*models.RateLimitEvent
	for rows.Next() {
		var event models.RateLimitEvent
		err := rows.Scan(
			&event.ID, &event.RuleID, &event.TenantID, &event.Identifier, &event.Endpoint,
			&event.RequestCount, &event.Blocked, &event.BlockedUntil, &event.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rate limit event: %w", err)
		}
		events = append(events, &event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetBlockedEvents: rows iteration: %w", err)
	}

	return events, nil
}

// CleanupOldEvents removes events older than the specified number of days
func (r *RateLimitRepository) CleanupOldEvents(ctx context.Context, daysToKeep int) (int64, error) {
	query := `
		DELETE FROM iam_rate_limit_events
		WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
	`

	result, err := r.pool.Exec(ctx, query, daysToKeep)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old rate limit events: %w", err)
	}

	return result.RowsAffected(), nil
}
