// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ErrStateConflict is returned when a state transition fails because the
// instance was concurrently modified by another replica or process.
var ErrStateConflict = errors.New("state conflict: instance was concurrently modified")

// ProductInstanceRepository handles product instance database operations.
type ProductInstanceRepository struct {
	db *pgxpool.Pool
}

// NewProductInstanceRepository creates a new product instance repository.
func NewProductInstanceRepository(db *pgxpool.Pool) *ProductInstanceRepository {
	return &ProductInstanceRepository{db: db}
}

// Create inserts a new product instance record.
func (r *ProductInstanceRepository) Create(ctx context.Context, pi *models.ProductInstance) error {
	if pi.ID == uuid.Nil {
		pi.ID = uuid.New()
	}

	query := `
		INSERT INTO iam_product_instances (
			id, tenant_id, product_id, plan_id, provisioning_state,
			database_host, database_name, database_schema, database_username,
			connection_string_enc, last_migration_version, current_step,
			completed_steps, failure_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING created_at, updated_at
	`

	err := r.db.QueryRow(ctx, query,
		pi.ID,
		pi.TenantID,
		pi.ProductID,
		pi.PlanID,
		pi.ProvisioningState,
		pi.DatabaseHost,
		pi.DatabaseName,
		pi.DatabaseSchema,
		pi.DatabaseUsername,
		pi.ConnectionStringEnc,
		pi.LastMigrationVersion,
		pi.CurrentStep,
		pi.CompletedSteps,
		pi.FailureReason,
	).Scan(&pi.CreatedAt, &pi.UpdatedAt)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a product instance by its UUID.
func (r *ProductInstanceRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE id = $1
	`
	return r.scanInstance(ctx, query, id)
}

// GetByTenantAndProduct retrieves an instance by tenant and product.
func (r *ProductInstanceRepository) GetByTenantAndProduct(ctx context.Context, tenantID, productID uuid.UUID) (*models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE tenant_id = $1 AND product_id = $2
	`
	return r.scanInstance(ctx, query, tenantID, productID)
}

// ListByTenant returns all product instances for a tenant.
func (r *ProductInstanceRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]models.ProductInstance, int64, error) {
	offset := (page - 1) * pageSize

	var total int64
	countQuery := `SELECT COUNT(*) FROM iam_product_instances WHERE tenant_id = $1 AND provisioning_state != 'deleted'`
	if err := r.db.QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ProductInstanceRepository.ListByTenant count: %w", err)
	}

	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE tenant_id = $1 AND provisioning_state != 'deleted'
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Query(ctx, query, tenantID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ProductInstanceRepository.ListByTenant query: %w", err)
	}
	defer rows.Close()

	var instances []models.ProductInstance
	for rows.Next() {
		pi, err := r.scanInstanceRow(rows)
		if err != nil {
			return nil, 0, err
		}
		instances = append(instances, *pi)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ProductInstanceRepository.ListByTenant rows: %w", err)
	}

	return instances, total, nil
}

// ListByTenantAll returns all non-deleted product instances for a tenant without pagination.
func (r *ProductInstanceRepository) ListByTenantAll(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE tenant_id = $1 AND provisioning_state != 'deleted'
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListByTenantAll: %w", err)
	}
	defer rows.Close()

	var instances []models.ProductInstance
	for rows.Next() {
		pi, err := r.scanInstanceRow(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, *pi)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListByTenantAll rows: %w", err)
	}

	return instances, nil
}

// ListActiveByTenant returns all active product instances for a tenant.
// Used by ProductSubscriptionResolver to populate JWT product claims.
func (r *ProductInstanceRepository) ListActiveByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE tenant_id = $1 AND provisioning_state = 'active'
		ORDER BY created_at
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListActiveByTenant: %w", err)
	}
	defer rows.Close()

	var instances []models.ProductInstance
	for rows.Next() {
		pi, err := r.scanInstanceRow(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, *pi)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListActiveByTenant rows: %w", err)
	}

	return instances, nil
}

// ListVisibleByTenant returns every product instance the JWT products[]
// claim should reflect for a tenant: active AND still-provisioning rows.
// Excludes 'deleting'/'deleted' (cancelled) so a cancelled subscription is
// indistinguishable from no subscription at all — see
// ProductSubscriptionResolver.Resolve / claimStateForProvisioningState for
// how each remaining state maps onto the claim's "state" field.
// Used by ProductSubscriptionResolver to populate JWT product claims.
func (r *ProductInstanceRepository) ListVisibleByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE tenant_id = $1 AND provisioning_state NOT IN ('deleting', 'deleted')
		ORDER BY created_at
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListVisibleByTenant: %w", err)
	}
	defer rows.Close()

	var instances []models.ProductInstance
	for rows.Next() {
		pi, err := r.scanInstanceRow(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, *pi)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListVisibleByTenant rows: %w", err)
	}

	return instances, nil
}

// ListByProduct returns all instances for a given product.
func (r *ProductInstanceRepository) ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE product_id = $1 AND provisioning_state != 'deleted'
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, productID)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListByProduct: %w", err)
	}
	defer rows.Close()

	var instances []models.ProductInstance
	for rows.Next() {
		pi, err := r.scanInstanceRow(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, *pi)
	}
	return instances, rows.Err()
}

// ListPending returns instances that need reconciliation. This includes:
// 1. Non-terminal instances (pending, creating, migrating, etc.)
// 2. Failed instances that are eligible for automatic retry (retry backoff elapsed)
// Results are bounded to 50 rows per batch. Oldest instances are processed first (FIFO).
func (r *ProductInstanceRepository) ListPending(ctx context.Context) ([]models.ProductInstance, error) {
	query := `
		SELECT id, tenant_id, product_id, plan_id, provisioning_state,
		       database_host, database_name, database_schema, database_username,
		       connection_string_enc, last_migration_version, current_step,
		       completed_steps, failure_reason, retry_count, max_retries_exhausted,
		       next_retry_at, provisioned_at,
		       created_at, updated_at
		FROM iam_product_instances
		WHERE (
			provisioning_state NOT IN ('active', 'failed', 'deleted')
		) OR (
			provisioning_state = 'failed'
			AND max_retries_exhausted = false
			AND next_retry_at IS NOT NULL
			AND next_retry_at <= NOW()
		)
		ORDER BY created_at ASC
		LIMIT 50
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.ListPending: %w", err)
	}
	defer rows.Close()

	var instances []models.ProductInstance
	for rows.Next() {
		pi, err := r.scanInstanceRow(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, *pi)
	}
	return instances, rows.Err()
}

// UpdateState transitions the provisioning state and records the current step.
// Guarded to prevent overwriting failed/deleted instances. The 'active' state
// is allowed as a source because Deprovision transitions active → deleting.
func (r *ProductInstanceRepository) UpdateState(ctx context.Context, id uuid.UUID, state models.ProvisioningState, currentStep *string) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = $2,
		    current_step = $3,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state NOT IN ('failed', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id, state, currentStep)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.UpdateState: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.UpdateState %s: %w", id, ErrStateConflict)
	}
	return nil
}

// CompleteStep marks a step as completed and advances the state.
// Guarded against terminal states to prevent concurrent overwrites.
func (r *ProductInstanceRepository) CompleteStep(ctx context.Context, id uuid.UUID, step string, newState models.ProvisioningState) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = $2,
		    completed_steps = array_append(completed_steps, $3),
		    current_step = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state NOT IN ('active', 'failed', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id, newState, step)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.CompleteStep: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.CompleteStep %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetFailed marks the instance as failed with a reason.
// Only transitions from non-terminal states (prevents re-failing deleted instances).
func (r *ProductInstanceRepository) SetFailed(ctx context.Context, id uuid.UUID, reason string) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'failed',
		    failure_reason = $2,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state NOT IN ('active', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id, reason)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.SetFailed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.SetFailed %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetFailedWithRetry marks the instance as failed but schedules an automatic retry.
// The retry_count is incremented and next_retry_at is set based on exponential backoff.
func (r *ProductInstanceRepository) SetFailedWithRetry(ctx context.Context, id uuid.UUID, reason string, retryCount int, nextRetryAt time.Time) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'failed',
		    failure_reason = $2,
		    retry_count = $3,
		    next_retry_at = $4,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state NOT IN ('active', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id, reason, retryCount, nextRetryAt)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.SetFailedWithRetry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.SetFailedWithRetry %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetPermanentlyFailed marks the instance as failed with retries exhausted.
func (r *ProductInstanceRepository) SetPermanentlyFailed(ctx context.Context, id uuid.UUID, reason string) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'failed',
		    failure_reason = $2,
		    max_retries_exhausted = true,
		    next_retry_at = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state NOT IN ('active', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id, reason)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.SetPermanentlyFailed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.SetPermanentlyFailed %s: %w", id, ErrStateConflict)
	}
	return nil
}

// ResetForRetry transitions a failed instance back to pending for automatic retry.
// Preserves retry_count so backoff increases. Clears next_retry_at and failure_reason.
// For manual retry (operator-initiated), use ResetForManualRetry which also resets the counter.
func (r *ProductInstanceRepository) ResetForRetry(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'pending',
		    failure_reason = NULL,
		    next_retry_at = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state = 'failed'
	`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.ResetForRetry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.ResetForRetry %s: instance not in failed state", id)
	}
	return nil
}

// ResetForManualRetry resets a failed instance for operator-initiated retry.
// Clears retry_count, failure_reason, and max_retries_exhausted so it starts fresh.
func (r *ProductInstanceRepository) ResetForManualRetry(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'pending',
		    failure_reason = NULL,
		    retry_count = 0,
		    max_retries_exhausted = false,
		    next_retry_at = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state = 'failed'
	`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.ResetForManualRetry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.ResetForManualRetry %s: instance not in failed state", id)
	}
	return nil
}

// ResetForReprovisioning transitions a failed or deleted instance back to
// pending so it can be re-provisioned. Clears retry state, failure info,
// and stale database connection info (the old DB may have been torn down
// during deletion, so the orchestrator must re-provision from scratch).
func (r *ProductInstanceRepository) ResetForReprovisioning(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'pending',
		    current_step = 'pending',
		    failure_reason = NULL,
		    retry_count = 0,
		    max_retries_exhausted = false,
		    next_retry_at = NULL,
		    completed_steps = '{}',
		    database_host = NULL,
		    database_name = NULL,
		    database_schema = NULL,
		    database_username = NULL,
		    connection_string_enc = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state IN ('failed', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.ResetForReprovisioning: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.ResetForReprovisioning %s: instance not in failed or deleted state", id)
	}
	return nil
}

// SetActive marks the instance as fully provisioned.
// Only transitions from the final provisioning step (registering_service).
func (r *ProductInstanceRepository) SetActive(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'active',
		    provisioned_at = NOW(),
		    current_step = NULL,
		    failure_reason = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state NOT IN ('active', 'failed', 'deleted')
	`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.SetActive: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.SetActive %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetDeleted marks the instance as deleted.
// Only transitions from the 'deleting' state.
func (r *ProductInstanceRepository) SetDeleted(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE iam_product_instances
		SET provisioning_state = 'deleted',
		    updated_at = NOW()
		WHERE id = $1
		  AND provisioning_state = 'deleting'
	`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.SetDeleted: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ProductInstanceRepository.SetDeleted %s: %w", id, ErrStateConflict)
	}
	return nil
}

// UpdateDatabaseInfo stores the database connection details after creation.
func (r *ProductInstanceRepository) UpdateDatabaseInfo(ctx context.Context, id uuid.UUID, host, dbName, schema, username string, connEnc []byte) error {
	query := `
		UPDATE iam_product_instances
		SET database_host = $2,
		    database_name = $3,
		    database_schema = $4,
		    database_username = $5,
		    connection_string_enc = $6,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(ctx, query, id, host, dbName, schema, username, connEnc)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.UpdateDatabaseInfo: %w", err)
	}
	return nil
}

// UpdateMigrationVersion records the last applied migration version.
func (r *ProductInstanceRepository) UpdateMigrationVersion(ctx context.Context, id uuid.UUID, version int) error {
	query := `
		UPDATE iam_product_instances
		SET last_migration_version = $2, updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.Exec(ctx, query, id, version)
	if err != nil {
		return fmt.Errorf("ProductInstanceRepository.UpdateMigrationVersion: %w", err)
	}
	return nil
}

// scanInstance scans a single product instance from a query.
func (r *ProductInstanceRepository) scanInstance(ctx context.Context, query string, args ...interface{}) (*models.ProductInstance, error) {
	var pi models.ProductInstance
	err := r.db.QueryRow(ctx, query, args...).Scan(
		&pi.ID, &pi.TenantID, &pi.ProductID, &pi.PlanID,
		&pi.ProvisioningState,
		&pi.DatabaseHost, &pi.DatabaseName, &pi.DatabaseSchema, &pi.DatabaseUsername,
		&pi.ConnectionStringEnc, &pi.LastMigrationVersion, &pi.CurrentStep,
		&pi.CompletedSteps, &pi.FailureReason,
		&pi.RetryCount, &pi.MaxRetriesExhausted, &pi.NextRetryAt,
		&pi.ProvisionedAt,
		&pi.CreatedAt, &pi.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.scanInstance: %w", err)
	}
	return &pi, nil
}

// scanInstanceRow scans a product instance from a rows iterator.
type scannable interface {
	Scan(dest ...interface{}) error
}

func (r *ProductInstanceRepository) scanInstanceRow(row scannable) (*models.ProductInstance, error) {
	var pi models.ProductInstance
	err := row.Scan(
		&pi.ID, &pi.TenantID, &pi.ProductID, &pi.PlanID,
		&pi.ProvisioningState,
		&pi.DatabaseHost, &pi.DatabaseName, &pi.DatabaseSchema, &pi.DatabaseUsername,
		&pi.ConnectionStringEnc, &pi.LastMigrationVersion, &pi.CurrentStep,
		&pi.CompletedSteps, &pi.FailureReason,
		&pi.RetryCount, &pi.MaxRetriesExhausted, &pi.NextRetryAt,
		&pi.ProvisionedAt,
		&pi.CreatedAt, &pi.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ProductInstanceRepository.scanInstanceRow: %w", err)
	}
	return &pi, nil
}
