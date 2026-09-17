// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// FeatureFlagRepository provides DB-backed access to iam_feature_flags.
type FeatureFlagRepository struct {
	pool *pgxpool.Pool
}

// NewFeatureFlagRepository creates a new FeatureFlagRepository.
func NewFeatureFlagRepository(pool *pgxpool.Pool) *FeatureFlagRepository {
	return &FeatureFlagRepository{pool: pool}
}

// scanFeatureFlag scans a single row into a PlatformFeatureFlag.
func scanFeatureFlag(row pgx.Row) (*models.PlatformFeatureFlag, error) {
	ff := &models.PlatformFeatureFlag{}
	var rawMetadata []byte
	err := row.Scan(
		&ff.ID,
		&ff.TenantID,
		&ff.FeatureKey,
		&ff.Enabled,
		&rawMetadata,
		&ff.CreatedAt,
		&ff.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rawMetadata) > 0 {
		ff.Metadata = json.RawMessage(rawMetadata)
	} else {
		ff.Metadata = json.RawMessage("{}")
	}
	return ff, nil
}

const featureFlagSelectCols = `id, tenant_id, feature_key, enabled, metadata, created_at, updated_at`

// ListGlobal returns all feature flags where tenant_id IS NULL (global defaults).
func (r *FeatureFlagRepository) ListGlobal(ctx context.Context) ([]models.PlatformFeatureFlag, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_feature_flags WHERE tenant_id IS NULL ORDER BY feature_key`,
		featureFlagSelectCols,
	)

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("FeatureFlagRepository.ListGlobal: %w", err)
	}
	defer rows.Close()

	var flags []models.PlatformFeatureFlag
	for rows.Next() {
		var rawMetadata []byte
		ff := models.PlatformFeatureFlag{}
		if err := rows.Scan(&ff.ID, &ff.TenantID, &ff.FeatureKey, &ff.Enabled, &rawMetadata, &ff.CreatedAt, &ff.UpdatedAt); err != nil {
			return nil, fmt.Errorf("FeatureFlagRepository.ListGlobal scan: %w", err)
		}
		if len(rawMetadata) > 0 {
			ff.Metadata = json.RawMessage(rawMetadata)
		} else {
			ff.Metadata = json.RawMessage("{}")
		}
		flags = append(flags, ff)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("FeatureFlagRepository.ListGlobal rows: %w", err)
	}
	return flags, nil
}

// ListForTenant returns the resolved flag set for a tenant: both tenant-specific
// rows and global defaults, ordered so that tenant rows appear before global rows
// for the same key (callers can deduplicate by taking the first occurrence per key).
func (r *FeatureFlagRepository) ListForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.PlatformFeatureFlag, error) {
	// NULLS LAST puts global defaults (tenant_id IS NULL) after tenant overrides.
	query := fmt.Sprintf(
		`SELECT %s FROM iam_feature_flags
		 WHERE tenant_id = $1 OR tenant_id IS NULL
		 ORDER BY feature_key, tenant_id NULLS LAST`,
		featureFlagSelectCols,
	)

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("FeatureFlagRepository.ListForTenant: %w", err)
	}
	defer rows.Close()

	var flags []models.PlatformFeatureFlag
	for rows.Next() {
		var rawMetadata []byte
		ff := models.PlatformFeatureFlag{}
		if err := rows.Scan(&ff.ID, &ff.TenantID, &ff.FeatureKey, &ff.Enabled, &rawMetadata, &ff.CreatedAt, &ff.UpdatedAt); err != nil {
			return nil, fmt.Errorf("FeatureFlagRepository.ListForTenant scan: %w", err)
		}
		if len(rawMetadata) > 0 {
			ff.Metadata = json.RawMessage(rawMetadata)
		} else {
			ff.Metadata = json.RawMessage("{}")
		}
		flags = append(flags, ff)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("FeatureFlagRepository.ListForTenant rows: %w", err)
	}
	return flags, nil
}

// IsEnabled checks whether a feature is enabled for a tenant.
// It checks for a tenant-specific override first; if none exists it falls back
// to the global default.  Returns false when neither row is found (fail-open
// for new flags, callers may choose a different default).
func (r *FeatureFlagRepository) IsEnabled(ctx context.Context, tenantID uuid.UUID, featureKey string) (bool, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM iam_feature_flags
		 WHERE feature_key = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
		 ORDER BY tenant_id NULLS LAST
		 LIMIT 1`,
		featureFlagSelectCols,
	)

	ff, err := scanFeatureFlag(r.pool.QueryRow(ctx, query, featureKey, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("FeatureFlagRepository.IsEnabled: %w", err)
	}
	return ff.Enabled, nil
}

// Set upserts a feature flag row.  Pass a nil tenantID to set a global default.
func (r *FeatureFlagRepository) Set(ctx context.Context, tenantID *uuid.UUID, featureKey string, enabled bool, metadata json.RawMessage) error {
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}

	query := `
		INSERT INTO iam_feature_flags (tenant_id, feature_key, enabled, metadata, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (tenant_id, feature_key) DO UPDATE
		SET enabled    = EXCLUDED.enabled,
		    metadata   = EXCLUDED.metadata,
		    updated_at = NOW()`

	_, err := r.pool.Exec(ctx, query, tenantID, featureKey, enabled, []byte(metadata))
	if err != nil {
		return fmt.Errorf("FeatureFlagRepository.Set: %w", err)
	}
	return nil
}

// Delete removes a feature flag row.  Pass nil tenantID to delete a global default.
func (r *FeatureFlagRepository) Delete(ctx context.Context, tenantID *uuid.UUID, featureKey string) error {
	query := `DELETE FROM iam_feature_flags WHERE tenant_id IS NOT DISTINCT FROM $1 AND feature_key = $2`
	_, err := r.pool.Exec(ctx, query, tenantID, featureKey)
	if err != nil {
		return fmt.Errorf("FeatureFlagRepository.Delete: %w", err)
	}
	return nil
}
