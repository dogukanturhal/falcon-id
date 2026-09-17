// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantQuotaRepository handles persistence for per-tenant quota records stored
// in the tenant_quotas table.
type TenantQuotaRepository struct {
	pool DBPool
}

// NewTenantQuotaRepository creates a TenantQuotaRepository backed by the given pool.
func NewTenantQuotaRepository(pool DBPool) *TenantQuotaRepository {
	return &TenantQuotaRepository{pool: pool}
}

// GetByTenantID returns the quota record for the specified tenant.
// It returns (nil, nil) when no row exists so callers can distinguish a
// missing row from a database error.
func (r *TenantQuotaRepository) GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantQuota, error) {
	const query = `
		SELECT
			tenant_id,
			subscription_tier,
			api_requests_per_minute,
			api_requests_per_hour,
			api_requests_per_day,
			auth_attempts_per_minute,
			token_refresh_per_minute,
			burst_multiplier,
			custom_limits,
			updated_at,
			updated_by
		FROM tenant_quotas
		WHERE tenant_id = $1`

	row := r.pool.QueryRow(ctx, query, tenantID)
	q, err := scanTenantQuota(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant_quota_repository.GetByTenantID: %w", err)
	}
	return q, nil
}

// GetOrDefault returns the quota for a tenant.  When no explicit record exists
// the function synthesises one from the tier defaults and returns it with a
// zeroed UpdatedAt (so callers can detect a synthetic row).
func (r *TenantQuotaRepository) GetOrDefault(ctx context.Context, tenantID uuid.UUID, tier models.SubscriptionTier) (*models.TenantQuota, error) {
	q, err := r.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if q != nil {
		return q, nil
	}
	// Synthesise from tier defaults.
	d := models.FromDefaults(tenantID, tier)
	return &d, nil
}

// Upsert inserts or updates the quota record for the given tenant.
func (r *TenantQuotaRepository) Upsert(ctx context.Context, q *models.TenantQuota) error {
	if q.UpdatedAt.IsZero() {
		q.UpdatedAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO tenant_quotas (
			tenant_id,
			subscription_tier,
			api_requests_per_minute,
			api_requests_per_hour,
			api_requests_per_day,
			auth_attempts_per_minute,
			token_refresh_per_minute,
			burst_multiplier,
			custom_limits,
			updated_at,
			updated_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (tenant_id) DO UPDATE SET
			subscription_tier        = EXCLUDED.subscription_tier,
			api_requests_per_minute  = EXCLUDED.api_requests_per_minute,
			api_requests_per_hour    = EXCLUDED.api_requests_per_hour,
			api_requests_per_day     = EXCLUDED.api_requests_per_day,
			auth_attempts_per_minute = EXCLUDED.auth_attempts_per_minute,
			token_refresh_per_minute = EXCLUDED.token_refresh_per_minute,
			burst_multiplier         = EXCLUDED.burst_multiplier,
			custom_limits            = EXCLUDED.custom_limits,
			updated_at               = EXCLUDED.updated_at,
			updated_by               = EXCLUDED.updated_by`

	_, err := r.pool.Exec(ctx, query,
		q.TenantID,
		string(q.SubscriptionTier),
		q.APIRequestsPerMinute,
		q.APIRequestsPerHour,
		q.APIRequestsPerDay,
		q.AuthAttemptsPerMinute,
		q.TokenRefreshPerMinute,
		q.BurstMultiplier,
		nullableJSON(q.CustomLimits),
		q.UpdatedAt,
		q.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("tenant_quota_repository.Upsert: %w", err)
	}
	return nil
}

// Delete removes the quota record for the given tenant.  It is not an error if
// no row exists.
func (r *TenantQuotaRepository) Delete(ctx context.Context, tenantID uuid.UUID) error {
	const query = `DELETE FROM tenant_quotas WHERE tenant_id = $1`
	_, err := r.pool.Exec(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("tenant_quota_repository.Delete: %w", err)
	}
	return nil
}

// ============================================================
// Helpers
// ============================================================

// scanTenantQuota scans a single row into a TenantQuota.
func scanTenantQuota(row pgx.Row) (*models.TenantQuota, error) {
	var q models.TenantQuota
	var tierStr string
	err := row.Scan(
		&q.TenantID,
		&tierStr,
		&q.APIRequestsPerMinute,
		&q.APIRequestsPerHour,
		&q.APIRequestsPerDay,
		&q.AuthAttemptsPerMinute,
		&q.TokenRefreshPerMinute,
		&q.BurstMultiplier,
		&q.CustomLimits,
		&q.UpdatedAt,
		&q.UpdatedBy,
	)
	if err != nil {
		return nil, err
	}
	q.SubscriptionTier = models.SubscriptionTier(tierStr)
	return &q, nil
}

// nullableJSON returns nil when the slice is empty so the database stores NULL
// instead of an empty JSON array literal.
func nullableJSON(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
