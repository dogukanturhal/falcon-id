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

const msgAPIKeyNotFound = "API key not found" //nolint:gosec // not a credential, this is a column name constant

// APIKeyRepository is an exported type.
type APIKeyRepository struct {
	pool    DBPool
	realmID *uuid.UUID
}

// WithRealmID returns a shallow clone of APIKeyRepository scoped to the given realm.
func (r *APIKeyRepository) WithRealmID(realmID uuid.UUID) *APIKeyRepository {
	clone := *r
	clone.realmID = &realmID
	return &clone
}

// NewAPIKeyRepository is an exported function.
func NewAPIKeyRepository(pool *pgxpool.Pool) *APIKeyRepository {
	return &APIKeyRepository{pool: pool}
}

// GetByID retrieves an API key by ID
func (r *APIKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash,
			   scopes, ip_whitelist, allowed_endpoints, rate_limit_override,
			   COALESCE(environment, 'production') as environment, is_active, COALESCE(usage_count, 0) as usage_count,
			   last_used_at, last_used_ip, created_at, expires_at, revoked_at, created_by
		FROM iam_api_keys
		WHERE id = $1
	`

	var key models.APIKey
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description,
		&key.KeyPrefix, &key.KeyHash, &key.Scopes, &key.IPWhitelist,
		&key.AllowedEndpoints, &key.RateLimitOverride, &key.Environment,
		&key.IsActive, &key.UsageCount, &key.LastUsedAt, &key.LastUsedIP,
		&key.CreatedAt, &key.ExpiresAt, &key.RevokedAt, &key.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	return &key, nil
}

// GetByPrefix retrieves an API key by its prefix, regardless of
// whether the key is currently active / unrevoked / unexpired.
//
// The query intentionally does NOT filter on `is_active`,
// `revoked_at`, or `expires_at`. The caller
// (APIKeyService.ValidateAPIKey) inspects those columns and decides
// whether to allow the request — pre-2026-05-21 the repo applied all
// three filters here, collapsing "revoked-key replay attempt",
// "deactivated key", "expired key", and "unknown key prefix" into a
// single nil return, losing the SOC's pivot signal for what's
// commonly an early credential-theft indicator. See
// docs/audits/2026-05-21-repo-state-filter-audit.md.
func (r *APIKeyRepository) GetByPrefix(ctx context.Context, prefix string) (*models.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash,
			   scopes, ip_whitelist, allowed_endpoints, rate_limit_override,
			   COALESCE(environment, 'production') as environment, is_active, COALESCE(usage_count, 0) as usage_count,
			   last_used_at, last_used_ip, created_at, expires_at, revoked_at, created_by
		FROM iam_api_keys
		WHERE key_prefix = $1
	`

	var key models.APIKey
	err := r.pool.QueryRow(ctx, query, prefix).Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description,
		&key.KeyPrefix, &key.KeyHash, &key.Scopes, &key.IPWhitelist,
		&key.AllowedEndpoints, &key.RateLimitOverride, &key.Environment,
		&key.IsActive, &key.UsageCount, &key.LastUsedAt, &key.LastUsedIP,
		&key.CreatedAt, &key.ExpiresAt, &key.RevokedAt, &key.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key by prefix: %w", err)
	}

	return &key, nil
}

// GetByTenantID retrieves all API keys for a tenant
// SECURITY: Limited to 100 keys to prevent memory exhaustion
func (r *APIKeyRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash,
			   scopes, ip_whitelist, allowed_endpoints, rate_limit_override,
			   COALESCE(environment, 'production') as environment, is_active, COALESCE(usage_count, 0) as usage_count,
			   last_used_at, last_used_ip, created_at, expires_at, revoked_at, created_by
		FROM iam_api_keys
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query API keys: %w", err)
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		var key models.APIKey
		err := rows.Scan(
			&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description,
			&key.KeyPrefix, &key.KeyHash, &key.Scopes, &key.IPWhitelist,
			&key.AllowedEndpoints, &key.RateLimitOverride, &key.Environment,
			&key.IsActive, &key.UsageCount, &key.LastUsedAt, &key.LastUsedIP,
			&key.CreatedAt, &key.ExpiresAt, &key.RevokedAt, &key.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan API key: %w", err)
		}
		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByTenantID: rows iteration: %w", err)
	}

	return keys, nil
}

// GetByUserID retrieves all API keys for a user
// SECURITY: Limited to 100 keys to prevent memory exhaustion
func (r *APIKeyRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash,
			   scopes, ip_whitelist, allowed_endpoints, rate_limit_override,
			   COALESCE(environment, 'production') as environment, is_active, COALESCE(usage_count, 0) as usage_count,
			   last_used_at, last_used_ip, created_at, expires_at, revoked_at, created_by
		FROM iam_api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query API keys by user: %w", err)
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		var key models.APIKey
		err := rows.Scan(
			&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description,
			&key.KeyPrefix, &key.KeyHash, &key.Scopes, &key.IPWhitelist,
			&key.AllowedEndpoints, &key.RateLimitOverride, &key.Environment,
			&key.IsActive, &key.UsageCount, &key.LastUsedAt, &key.LastUsedIP,
			&key.CreatedAt, &key.ExpiresAt, &key.RevokedAt, &key.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan API key: %w", err)
		}
		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetByUserID: rows iteration: %w", err)
	}

	return keys, nil
}

// Create creates a new API key
func (r *APIKeyRepository) Create(ctx context.Context, key *models.APIKey) error {
	query := `
		INSERT INTO iam_api_keys (
			tenant_id, user_id, name, description, key_prefix, key_hash,
			scopes, ip_whitelist, allowed_endpoints, rate_limit_override,
			environment, is_active, expires_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(ctx, query,
		key.TenantID, key.UserID, key.Name, key.Description, key.KeyPrefix, key.KeyHash,
		key.Scopes, key.IPWhitelist, key.AllowedEndpoints, key.RateLimitOverride,
		key.Environment, key.IsActive, key.ExpiresAt, key.CreatedBy,
	).Scan(&key.ID, &key.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}

	return nil
}

// Update updates an existing API key
func (r *APIKeyRepository) Update(ctx context.Context, key *models.APIKey) error {
	query := `
		UPDATE iam_api_keys
		SET name = $1, description = $2, scopes = $3, ip_whitelist = $4,
			allowed_endpoints = $5, rate_limit_override = $6, environment = $7,
			is_active = $8, expires_at = $9
		WHERE id = $10
	`

	result, err := r.pool.Exec(ctx, query,
		key.Name, key.Description, key.Scopes, key.IPWhitelist,
		key.AllowedEndpoints, key.RateLimitOverride, key.Environment,
		key.IsActive, key.ExpiresAt, key.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update API key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}

	return nil
}

// Revoke revokes an API key
func (r *APIKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE iam_api_keys SET revoked_at = NOW(), is_active = false WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}

	return nil
}

// Delete permanently deletes an API key
func (r *APIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM iam_api_keys WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	if result.RowsAffected() == 0 {
		return errors.New(msgAPIKeyNotFound)
	}

	return nil
}

// UpdateLastUsed updates the last used timestamp and increments usage count
func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	query := `
		UPDATE iam_api_keys
		SET last_used_at = NOW(), last_used_ip = $1, usage_count = COALESCE(usage_count, 0) + 1
		WHERE id = $2
	`

	_, err := r.pool.Exec(ctx, query, ip, id)
	if err != nil {
		return fmt.Errorf("failed to update API key last used: %w", err)
	}

	return nil
}

// LogUsage logs API key usage
func (r *APIKeyRepository) LogUsage(ctx context.Context, usage *models.APIKeyUsage) error {
	query := `
		INSERT INTO iam_api_key_usage (
			api_key_id, tenant_id, endpoint, method, status_code,
			response_time_ms, ip_address, user_agent
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(ctx, query,
		usage.APIKeyID, usage.TenantID, usage.Endpoint, usage.Method,
		usage.StatusCode, usage.ResponseTimeMs, usage.IPAddress, usage.UserAgent,
	).Scan(&usage.ID, &usage.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to log API key usage: %w", err)
	}

	return nil
}

// GetUsageStats retrieves usage statistics for an API key
func (r *APIKeyRepository) GetUsageStats(ctx context.Context, keyID uuid.UUID) (*models.APIKeyUsageStats, error) {
	stats := &models.APIKeyUsageStats{}

	// Get total requests
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iam_api_key_usage WHERE api_key_id = $1
	`, keyID).Scan(&stats.TotalRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to get total requests: %w", err)
	}

	// Get last 24 hours
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iam_api_key_usage
		WHERE api_key_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
	`, keyID).Scan(&stats.Last24Hours)
	if err != nil {
		return nil, fmt.Errorf("failed to get last 24 hours: %w", err)
	}

	// Get last 7 days
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iam_api_key_usage
		WHERE api_key_id = $1 AND created_at > NOW() - INTERVAL '7 days'
	`, keyID).Scan(&stats.Last7Days)
	if err != nil {
		return nil, fmt.Errorf("failed to get last 7 days: %w", err)
	}

	// Get average response time
	err = r.pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(response_time_ms), 0) FROM iam_api_key_usage
		WHERE api_key_id = $1 AND response_time_ms IS NOT NULL
	`, keyID).Scan(&stats.AvgResponseTimeMs)
	if err != nil {
		return nil, fmt.Errorf("failed to get avg response time: %w", err)
	}

	// Get error rate
	var totalWithStatus, errorCount int64
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0)
		FROM iam_api_key_usage
		WHERE api_key_id = $1 AND status_code IS NOT NULL
	`, keyID).Scan(&totalWithStatus, &errorCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get error rate: %w", err)
	}
	if totalWithStatus > 0 {
		stats.ErrorRate = float64(errorCount) / float64(totalWithStatus) * 100
	}

	// Get top endpoints
	rows, err := r.pool.Query(ctx, `
		SELECT endpoint, COUNT(*) as request_count
		FROM iam_api_key_usage
		WHERE api_key_id = $1
		GROUP BY endpoint
		ORDER BY request_count DESC
		LIMIT 10
	`, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get top endpoints: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var eu models.EndpointUsage
		if err := rows.Scan(&eu.Endpoint, &eu.RequestCount); err != nil {
			return nil, fmt.Errorf("failed to scan endpoint usage: %w", err)
		}
		stats.TopEndpoints = append(stats.TopEndpoints, eu)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetUsageStats: rows iteration: %w", err)
	}

	return stats, nil
}

// CleanupOldUsageLogs removes usage logs older than the specified number of days
func (r *APIKeyRepository) CleanupOldUsageLogs(ctx context.Context, daysToKeep int) (int64, error) {
	query := `
		DELETE FROM iam_api_key_usage
		WHERE created_at < NOW() - ($1 || ' days')::INTERVAL
	`

	result, err := r.pool.Exec(ctx, query, daysToKeep)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old API key usage logs: %w", err)
	}

	return result.RowsAffected(), nil
}
