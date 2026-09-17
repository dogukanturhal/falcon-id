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

// TenantConfigRepository handles per-tenant configuration storage.
type TenantConfigRepository struct {
	pool *pgxpool.Pool
}

// NewTenantConfigRepository creates a new TenantConfigRepository.
func NewTenantConfigRepository(pool *pgxpool.Pool) *TenantConfigRepository {
	return &TenantConfigRepository{pool: pool}
}

// Get retrieves a single config entry for a tenant and key (tenant-level scope only).
func (r *TenantConfigRepository) Get(ctx context.Context, tenantID uuid.UUID, configKey string) (*models.TenantConfig, error) {
	query := `
		SELECT tenant_id, config_key, config_value, COALESCE(description, ''), updated_at, updated_by, created_at
		FROM iam_tenant_configs
		WHERE tenant_id = $1 AND config_key = $2
		      AND realm_id IS NULL AND application_id IS NULL
	`

	var tc models.TenantConfig
	err := r.pool.QueryRow(ctx, query, tenantID, configKey).Scan(
		&tc.TenantID,
		&tc.ConfigKey,
		&tc.ConfigValue,
		&tc.Description,
		&tc.UpdatedAt,
		&tc.UpdatedBy,
		&tc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tenant config: %w", err)
	}

	return &tc, nil
}

// GetByScope retrieves a config entry for a specific scope (tenant + optional realm + optional app).
func (r *TenantConfigRepository) GetByScope(ctx context.Context, tenantID uuid.UUID, realmID, appID *uuid.UUID, configKey string) (*models.TenantConfig, error) {
	var query string
	var args []interface{}

	switch {
	case appID != nil:
		query = `
			SELECT tenant_id, config_key, config_value, COALESCE(description, ''), updated_at, updated_by, created_at
			FROM iam_tenant_configs
			WHERE tenant_id = $1 AND config_key = $2 AND application_id = $3
		`
		args = []interface{}{tenantID, configKey, *appID}
	case realmID != nil:
		query = `
			SELECT tenant_id, config_key, config_value, COALESCE(description, ''), updated_at, updated_by, created_at
			FROM iam_tenant_configs
			WHERE tenant_id = $1 AND config_key = $2 AND realm_id = $3 AND application_id IS NULL
		`
		args = []interface{}{tenantID, configKey, *realmID}
	default:
		return r.Get(ctx, tenantID, configKey)
	}

	var tc models.TenantConfig
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&tc.TenantID,
		&tc.ConfigKey,
		&tc.ConfigValue,
		&tc.Description,
		&tc.UpdatedAt,
		&tc.UpdatedBy,
		&tc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get scoped config: %w", err)
	}

	return &tc, nil
}

// UpsertByScopeParams groups the parameters for UpsertByScope.
type UpsertByScopeParams struct {
	TenantID    uuid.UUID
	RealmID     *uuid.UUID
	AppID       *uuid.UUID
	ConfigKey   string
	ConfigValue []byte
	Description string
	UpdatedBy   *uuid.UUID
}

// UpsertByScope creates or updates a config entry at a specific scope.
func (r *TenantConfigRepository) UpsertByScope(ctx context.Context, p UpsertByScopeParams) error {
	tenantID := p.TenantID
	realmID := p.RealmID
	appID := p.AppID
	configKey := p.ConfigKey
	configValue := p.ConfigValue
	description := p.Description
	updatedBy := p.UpdatedBy
	// Use the unique index with COALESCE for conflict resolution.
	// uuid.Nil (all-zeros) is the sentinel value matched by the COALESCE expression in the DB index.
	coalescedRealmID := uuid.Nil
	coalescedAppID := uuid.Nil
	if realmID != nil {
		coalescedRealmID = *realmID
	}
	if appID != nil {
		coalescedAppID = *appID
	}

	query := `
		INSERT INTO iam_tenant_configs (tenant_id, config_key, config_value, description, updated_by, realm_id, application_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, config_key, COALESCE(realm_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::uuid))
		DO UPDATE SET
			config_value = EXCLUDED.config_value,
			description = EXCLUDED.description,
			updated_at = now(),
			updated_by = EXCLUDED.updated_by
	`

	// Convert nil UUID sentinels back to NULL for storage
	var storeRealmID, storeAppID *uuid.UUID
	if coalescedRealmID != uuid.Nil {
		storeRealmID = &coalescedRealmID
	}
	if coalescedAppID != uuid.Nil {
		storeAppID = &coalescedAppID
	}

	_, err := r.pool.Exec(ctx, query,
		tenantID,
		configKey,
		configValue,
		description,
		updatedBy,
		storeRealmID,
		storeAppID,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert scoped config: %w", err)
	}

	return nil
}

// GetAllForTenant retrieves all config entries for a tenant.
func (r *TenantConfigRepository) GetAllForTenant(ctx context.Context, tenantID uuid.UUID) ([]models.TenantConfig, error) {
	query := `
		SELECT tenant_id, config_key, config_value, COALESCE(description, ''), updated_at, updated_by, created_at
		FROM iam_tenant_configs
		WHERE tenant_id = $1
		ORDER BY config_key
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant configs: %w", err)
	}
	defer rows.Close()

	var configs []models.TenantConfig
	for rows.Next() {
		var tc models.TenantConfig
		if err := rows.Scan(
			&tc.TenantID,
			&tc.ConfigKey,
			&tc.ConfigValue,
			&tc.Description,
			&tc.UpdatedAt,
			&tc.UpdatedBy,
			&tc.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan tenant config: %w", err)
		}
		configs = append(configs, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetAllForTenant: rows iteration: %w", err)
	}

	return configs, nil
}

// Upsert creates or updates a single config entry.
func (r *TenantConfigRepository) Upsert(ctx context.Context, tc *models.TenantConfig) error {
	query := `
		INSERT INTO iam_tenant_configs (tenant_id, config_key, config_value, description, updated_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, config_key) DO UPDATE SET
			config_value = EXCLUDED.config_value,
			description = EXCLUDED.description,
			updated_at = now(),
			updated_by = EXCLUDED.updated_by
	`

	_, err := r.pool.Exec(ctx, query,
		tc.TenantID,
		tc.ConfigKey,
		tc.ConfigValue,
		tc.Description,
		tc.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert tenant config: %w", err)
	}

	return nil
}

// Delete removes a single config entry, reverting to the static default.
func (r *TenantConfigRepository) Delete(ctx context.Context, tenantID uuid.UUID, configKey string) error {
	query := `DELETE FROM iam_tenant_configs WHERE tenant_id = $1 AND config_key = $2`

	tag, err := r.pool.Exec(ctx, query, tenantID, configKey)
	if err != nil {
		return fmt.Errorf("failed to delete tenant config: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant config not found: %s", configKey)
	}

	return nil
}

// BulkUpsert creates or updates multiple config entries atomically in a single transaction.
func (r *TenantConfigRepository) BulkUpsert(ctx context.Context, configs []models.TenantConfig) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	query := `
		INSERT INTO iam_tenant_configs (tenant_id, config_key, config_value, description, updated_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, config_key) DO UPDATE SET
			config_value = EXCLUDED.config_value,
			description = EXCLUDED.description,
			updated_at = now(),
			updated_by = EXCLUDED.updated_by
	`

	for _, tc := range configs {
		_, err := tx.Exec(ctx, query,
			tc.TenantID,
			tc.ConfigKey,
			tc.ConfigValue,
			tc.Description,
			tc.UpdatedBy,
		)
		if err != nil {
			return fmt.Errorf("failed to upsert tenant config %s: %w", tc.ConfigKey, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit bulk upsert: %w", err)
	}

	return nil
}
