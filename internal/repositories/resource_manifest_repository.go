// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ResourceManifestRepository handles CRUD for iam_product_resource_manifests.
type ResourceManifestRepository struct {
	pool *pgxpool.Pool
}

// NewResourceManifestRepository creates a new repository.
func NewResourceManifestRepository(pool *pgxpool.Pool) *ResourceManifestRepository {
	return &ResourceManifestRepository{pool: pool}
}

// ListByProduct returns all manifest entries for a product, ordered by priority.
func (r *ResourceManifestRepository) ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductResourceManifest, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, product_id, resource_type, resource_name, display_name,
		       config, priority, is_required, created_at, updated_at
		FROM iam_product_resource_manifests
		WHERE product_id = $1
		ORDER BY priority ASC, resource_name ASC
	`, productID)
	if err != nil {
		return nil, fmt.Errorf("list resource manifests: %w", err)
	}
	defer rows.Close()

	var manifests []models.ProductResourceManifest
	for rows.Next() {
		var m models.ProductResourceManifest
		if err := rows.Scan(
			&m.ID, &m.ProductID, &m.ResourceType, &m.ResourceName, &m.DisplayName,
			&m.Config, &m.Priority, &m.IsRequired, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan resource manifest: %w", err)
		}
		manifests = append(manifests, m)
	}
	return manifests, rows.Err()
}

// GetByID returns a single manifest entry.
func (r *ResourceManifestRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProductResourceManifest, error) {
	var m models.ProductResourceManifest
	err := r.pool.QueryRow(ctx, `
		SELECT id, product_id, resource_type, resource_name, display_name,
		       config, priority, is_required, created_at, updated_at
		FROM iam_product_resource_manifests
		WHERE id = $1
	`, id).Scan(
		&m.ID, &m.ProductID, &m.ResourceType, &m.ResourceName, &m.DisplayName,
		&m.Config, &m.Priority, &m.IsRequired, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get resource manifest: %w", err)
	}
	return &m, nil
}

// Create inserts a new manifest entry and returns the full record.
func (r *ResourceManifestRepository) Create(ctx context.Context, m *models.ProductResourceManifest) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if len(m.Config) == 0 {
		m.Config = json.RawMessage(`{}`)
	}
	// Default to required when not explicitly set.
	if !m.IsRequired {
		m.IsRequired = true
	}

	err := r.pool.QueryRow(ctx, `
		INSERT INTO iam_product_resource_manifests
			(id, product_id, resource_type, resource_name, display_name, config, priority, is_required)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at
	`, m.ID, m.ProductID, m.ResourceType, m.ResourceName, m.DisplayName,
		m.Config, m.Priority, m.IsRequired,
	).Scan(&m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create resource manifest: %w", err)
	}
	return nil
}

// UpsertBatch inserts or updates a batch of manifest entries for a product.
// It uses the (product_id, resource_type, resource_name) unique index to detect
// conflicts. The xmax system column distinguishes inserts (xmax = 0) from
// updates (xmax != 0), which lets us return accurate registered/updated counts.
// All rows in the batch are processed; the first DB error aborts and returns it.
func (r *ResourceManifestRepository) UpsertBatch(
	ctx context.Context,
	productID uuid.UUID,
	resources []models.ProductResourceManifest,
) (registered, updated int, err error) {
	for i := range resources {
		m := &resources[i]
		if m.ID == uuid.Nil {
			m.ID = uuid.New()
		}
		if len(m.Config) == 0 {
			m.Config = json.RawMessage(`{}`)
		}

		var wasInsert bool
		upsertErr := r.pool.QueryRow(ctx, `
			INSERT INTO iam_product_resource_manifests
				(id, product_id, resource_type, resource_name, display_name, config, priority, is_required)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (product_id, resource_type, resource_name) DO UPDATE
				SET display_name = EXCLUDED.display_name,
				    config       = EXCLUDED.config,
				    priority     = EXCLUDED.priority,
				    is_required  = EXCLUDED.is_required,
				    updated_at   = NOW()
			RETURNING (xmax = 0)
		`, m.ID, productID, m.ResourceType, m.ResourceName, m.DisplayName,
			m.Config, m.Priority, m.IsRequired,
		).Scan(&wasInsert)
		if upsertErr != nil {
			return registered, updated, fmt.Errorf("upsert resource manifest %q/%q: %w",
				m.ResourceType, m.ResourceName, upsertErr)
		}

		if wasInsert {
			registered++
		} else {
			updated++
		}
	}
	return registered, updated, nil
}

// Delete removes a manifest entry by ID.
func (r *ResourceManifestRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM iam_product_resource_manifests WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete resource manifest: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("resource manifest not found")
	}
	return nil
}

// TenantResourceInstanceRepository handles CRUD for iam_tenant_resource_instances.
type TenantResourceInstanceRepository struct {
	pool *pgxpool.Pool
}

// NewTenantResourceInstanceRepository creates a new repository.
func NewTenantResourceInstanceRepository(pool *pgxpool.Pool) *TenantResourceInstanceRepository {
	return &TenantResourceInstanceRepository{pool: pool}
}

const tenantResourceInstanceColumns = `
	id, tenant_id, product_id, instance_id, manifest_id,
	resource_type, resource_name, status, provisioned_config,
	error_message, retry_count, provisioned_at, created_at, updated_at
`

// Create inserts a new tenant resource instance record.
func (r *TenantResourceInstanceRepository) Create(ctx context.Context, t *models.TenantResourceInstance) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if len(t.ProvisionedConfig) == 0 {
		t.ProvisionedConfig = json.RawMessage(`{}`)
	}

	err := r.pool.QueryRow(ctx, `
		INSERT INTO iam_tenant_resource_instances
			(id, tenant_id, product_id, instance_id, manifest_id,
			 resource_type, resource_name, status, provisioned_config)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+tenantResourceInstanceColumns,
		t.ID, t.TenantID, t.ProductID, t.InstanceID, t.ManifestID,
		t.ResourceType, t.ResourceName, t.Status, t.ProvisionedConfig,
	).Scan(
		&t.ID, &t.TenantID, &t.ProductID, &t.InstanceID, &t.ManifestID,
		&t.ResourceType, &t.ResourceName, &t.Status, &t.ProvisionedConfig,
		&t.ErrorMessage, &t.RetryCount, &t.ProvisionedAt, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create tenant resource instance: %w", err)
	}
	return nil
}

// UpdateStatus updates the status, provisioned_config, and error_message of an instance.
// Pass nil for config to leave it unchanged. Pass an empty string for errMsg to clear it.
func (r *TenantResourceInstanceRepository) UpdateStatus(
	ctx context.Context,
	id uuid.UUID,
	status string,
	config map[string]interface{},
	errMsg string,
) error {
	var configJSON json.RawMessage
	if config != nil {
		b, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("marshal provisioned config: %w", err)
		}
		configJSON = b
	}

	var errMsgPtr *string
	if errMsg != "" {
		errMsgPtr = &errMsg
	}

	var provisionedAt *time.Time
	if status == models.ResourceStatusActive {
		now := time.Now()
		provisionedAt = &now
	}

	_, err := r.pool.Exec(ctx, `
		UPDATE iam_tenant_resource_instances
		SET status = $2,
		    provisioned_config = CASE WHEN $3::jsonb IS NOT NULL THEN $3::jsonb ELSE provisioned_config END,
		    error_message = $4,
		    provisioned_at = CASE WHEN $5::timestamptz IS NOT NULL THEN $5::timestamptz ELSE provisioned_at END,
		    updated_at = NOW()
		WHERE id = $1
	`, id, status, configJSON, errMsgPtr, provisionedAt)
	if err != nil {
		return fmt.Errorf("update tenant resource instance status: %w", err)
	}
	return nil
}

// ListByInstance returns all resource instances associated with a product instance ID.
func (r *TenantResourceInstanceRepository) ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.TenantResourceInstance, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+tenantResourceInstanceColumns+`
		FROM iam_tenant_resource_instances
		WHERE instance_id = $1
		ORDER BY created_at ASC
	`, instanceID)
	if err != nil {
		return nil, fmt.Errorf("list tenant resource instances by instance: %w", err)
	}
	defer rows.Close()

	var instances []models.TenantResourceInstance
	for rows.Next() {
		var t models.TenantResourceInstance
		if err := rows.Scan(
			&t.ID, &t.TenantID, &t.ProductID, &t.InstanceID, &t.ManifestID,
			&t.ResourceType, &t.ResourceName, &t.Status, &t.ProvisionedConfig,
			&t.ErrorMessage, &t.RetryCount, &t.ProvisionedAt, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant resource instance: %w", err)
		}
		instances = append(instances, t)
	}
	return instances, rows.Err()
}

// ListByTenant returns all resource instances for a tenant across all products.
func (r *TenantResourceInstanceRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.TenantResourceInstance, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+tenantResourceInstanceColumns+`
		FROM iam_tenant_resource_instances
		WHERE tenant_id = $1
		ORDER BY product_id, created_at ASC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list tenant resource instances by tenant: %w", err)
	}
	defer rows.Close()

	var instances []models.TenantResourceInstance
	for rows.Next() {
		var t models.TenantResourceInstance
		if err := rows.Scan(
			&t.ID, &t.TenantID, &t.ProductID, &t.InstanceID, &t.ManifestID,
			&t.ResourceType, &t.ResourceName, &t.Status, &t.ProvisionedConfig,
			&t.ErrorMessage, &t.RetryCount, &t.ProvisionedAt, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant resource instance: %w", err)
		}
		instances = append(instances, t)
	}
	return instances, rows.Err()
}

// DeleteByInstance removes all resource instances for a product instance (used during deprovisioning).
func (r *TenantResourceInstanceRepository) DeleteByInstance(ctx context.Context, instanceID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM iam_tenant_resource_instances WHERE instance_id = $1`, instanceID)
	if err != nil {
		return fmt.Errorf("delete tenant resource instances: %w", err)
	}
	return nil
}
