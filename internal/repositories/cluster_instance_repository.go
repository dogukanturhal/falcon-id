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

// ClusterStats contains aggregated counts for cluster instances,
// broken down by tier and data center.
type ClusterStats struct {
	TotalClusters   int            `json:"total_clusters"`
	ActiveClusters  int            `json:"active_clusters"`
	PendingClusters int            `json:"pending_clusters"`
	FailedClusters  int            `json:"failed_clusters"`
	ByTier          map[string]int `json:"by_tier"`
	ByDataCenter    map[string]int `json:"by_data_center"`
}

// ClusterInstanceRepository defines all persistence operations for cluster instances.
// The interface is intentionally narrow: each method has a single, well-defined
// responsibility so callers can mock only what they need.
type ClusterInstanceRepository interface {
	// Write operations.
	Create(ctx context.Context, ci *models.ClusterInstance) error
	UpdateState(ctx context.Context, id uuid.UUID, state, step string) error
	SetActive(ctx context.Context, id uuid.UUID, endpoint, kubeconfigRef string) error
	SetFailed(ctx context.Context, id uuid.UUID, reason string) error
	SetFailedWithRetry(ctx context.Context, id uuid.UUID, reason string, nextRetry time.Time) error
	SetPermanentlyFailed(ctx context.Context, id uuid.UUID, reason string) error
	ResetForManualRetry(ctx context.Context, id uuid.UUID) error
	SetDeleting(ctx context.Context, id uuid.UUID) error
	SetDeleted(ctx context.Context, id uuid.UUID) error
	UpdateClusterInfo(ctx context.Context, id uuid.UUID, endpoint, kubeconfigRef, argocdName string) error

	// Read operations.
	GetByID(ctx context.Context, id uuid.UUID) (*models.ClusterInstance, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ClusterInstance, error)
	ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ClusterInstance, error)
	ListPending(ctx context.Context) ([]models.ClusterInstance, error)
	ListAll(ctx context.Context, limit, offset int) ([]models.ClusterInstance, int, error)
	GetStats(ctx context.Context) (*ClusterStats, error)
}

// pgxClusterInstanceRepository is the pgx/pgxpool-backed implementation of
// ClusterInstanceRepository.  It uses explicit column lists on every query to
// remain safe against future schema additions.
type pgxClusterInstanceRepository struct {
	db *pgxpool.Pool
}

// NewClusterInstanceRepository returns a ClusterInstanceRepository backed by
// the provided control-plane pool.  The pool is never closed by the repository.
func NewClusterInstanceRepository(db *pgxpool.Pool) ClusterInstanceRepository {
	return &pgxClusterInstanceRepository{db: db}
}

// clusterColumns is the canonical SELECT column list for cluster instances.
// The order must match exactly the Scan call in scanClusterRow.
const clusterColumns = `
	id, tenant_id, product_id, product_slug,
	cluster_name, isolation_tier, data_center,
	kubernetes_version, node_count, node_size,
	cluster_endpoint, kubeconfig_secret_ref, ca_certificate,
	provisioning_state, current_step, completed_steps,
	failure_reason, retry_count, max_retries_exhausted, next_retry_at,
	provider, crossplane_claim_ref, argocd_cluster_name,
	vcluster_name, vcluster_namespace,
	provisioned_at, created_at, updated_at`

// Create inserts a new cluster instance record.  If ci.ID is the zero UUID a
// new random ID is assigned before insertion.  CreatedAt and UpdatedAt are set
// from the RETURNING clause so the in-memory struct reflects the DB defaults.
func (r *pgxClusterInstanceRepository) Create(ctx context.Context, ci *models.ClusterInstance) error {
	if ci.ID == uuid.Nil {
		ci.ID = uuid.New()
	}
	if ci.ProvisioningState == "" {
		ci.ProvisioningState = models.ClusterProvisioningStatePending
	}
	if ci.Provider == "" {
		ci.Provider = models.ClusterProviderCrossplane
	}
	if ci.KubernetesVersion == "" {
		ci.KubernetesVersion = "1.29"
	}
	if ci.NodeCount == 0 {
		ci.NodeCount = 3
	}
	if ci.NodeSize == "" {
		ci.NodeSize = models.ClusterNodeSizeMedium
	}
	if ci.CompletedSteps == nil {
		ci.CompletedSteps = []string{}
	}

	const query = `
		INSERT INTO iam_cluster_instances (
			id, tenant_id, product_id, product_slug,
			cluster_name, isolation_tier, data_center,
			kubernetes_version, node_count, node_size,
			cluster_endpoint, kubeconfig_secret_ref, ca_certificate,
			provisioning_state, current_step, completed_steps,
			failure_reason, retry_count, max_retries_exhausted, next_retry_at,
			provider, crossplane_claim_ref, argocd_cluster_name,
			vcluster_name, vcluster_namespace
		) VALUES (
			$1,  $2,  $3,  $4,
			$5,  $6,  $7,
			$8,  $9,  $10,
			$11, $12, $13,
			$14, $15, $16,
			$17, $18, $19, $20,
			$21, $22, $23,
			$24, $25
		)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		ci.ID, ci.TenantID, ci.ProductID, ci.ProductSlug,
		ci.ClusterName, ci.IsolationTier, ci.DataCenter,
		ci.KubernetesVersion, ci.NodeCount, ci.NodeSize,
		ci.ClusterEndpoint, ci.KubeConfigSecretRef, ci.CACertificate,
		ci.ProvisioningState, ci.CurrentStep, ci.CompletedSteps,
		ci.FailureReason, ci.RetryCount, ci.MaxRetriesExhausted, ci.NextRetryAt,
		ci.Provider, ci.CrossplaneClaimRef, ci.ArgocdClusterName,
		ci.VclusterName, ci.VclusterNamespace,
	).Scan(&ci.CreatedAt, &ci.UpdatedAt)
}

// GetByID retrieves a single cluster instance by its primary key.
// Returns (nil, nil) when no record exists with that ID.
func (r *pgxClusterInstanceRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ClusterInstance, error) {
	query := `SELECT ` + clusterColumns + `
		FROM iam_cluster_instances
		WHERE id = $1`

	ci := &models.ClusterInstance{}
	err := r.db.QueryRow(ctx, query, id).Scan(clusterDest(ci)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.GetByID: %w", err)
	}
	return ci, nil
}

// ListByTenant returns all non-deleted cluster instances for a tenant, ordered
// by creation time descending (newest first).
func (r *pgxClusterInstanceRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ClusterInstance, error) {
	query := `SELECT ` + clusterColumns + `
		FROM iam_cluster_instances
		WHERE tenant_id = $1
		  AND provisioning_state != 'deleted'
		ORDER BY created_at DESC`

	return r.queryList(ctx, query, "ListByTenant", tenantID)
}

// ListByProduct returns all non-deleted cluster instances for a product, ordered
// by creation time descending.
func (r *pgxClusterInstanceRepository) ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ClusterInstance, error) {
	query := `SELECT ` + clusterColumns + `
		FROM iam_cluster_instances
		WHERE product_id = $1
		  AND provisioning_state != 'deleted'
		ORDER BY created_at DESC`

	return r.queryList(ctx, query, "ListByProduct", productID)
}

// ListPending returns all instances that require reconciliation:
//   - Non-terminal instances still in progress (pending, creating, configuring, registering_routes).
//   - Failed instances eligible for automatic retry (backoff window elapsed, retries not exhausted).
//
// Results are capped at 50 rows and ordered oldest-first (FIFO) so that stalled
// instances do not starve newer ones.
func (r *pgxClusterInstanceRepository) ListPending(ctx context.Context) ([]models.ClusterInstance, error) {
	const query = `SELECT ` + clusterColumns + `
		FROM iam_cluster_instances
		WHERE (
			provisioning_state NOT IN ('active', 'failed', 'deleted')
		) OR (
			provisioning_state   = 'failed'
			AND max_retries_exhausted = false
			AND next_retry_at IS NOT NULL
			AND next_retry_at <= NOW()
		)
		ORDER BY created_at ASC
		LIMIT 50`

	return r.queryList(ctx, query, "ListPending")
}

// ListAll returns a paginated list of all cluster instances across all tenants
// together with the total count.  The total is computed via a window function
// in a single round-trip so the caller does not need a separate COUNT query.
func (r *pgxClusterInstanceRepository) ListAll(ctx context.Context, limit, offset int) ([]models.ClusterInstance, int, error) {
	// The window function COUNT(*) OVER() returns the same total count on every
	// row, so we read it once from the first row.
	query := `
		SELECT COUNT(*) OVER() AS total_count, ` + clusterColumns + `
		FROM iam_cluster_instances ci
		ORDER BY ci.created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("ClusterInstanceRepository.ListAll: %w", err)
	}
	defer rows.Close()

	var (
		instances  []models.ClusterInstance
		totalCount int
	)
	for rows.Next() {
		var ci models.ClusterInstance
		dest := append([]interface{}{&totalCount}, clusterDest(&ci)...)
		if err := rows.Scan(dest...); err != nil {
			return nil, 0, fmt.Errorf("ClusterInstanceRepository.ListAll scan: %w", err)
		}
		instances = append(instances, ci)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("ClusterInstanceRepository.ListAll rows: %w", err)
	}
	return instances, totalCount, nil
}

// UpdateState transitions the provisioning_state and records the current step.
// Guarded against terminal states to prevent concurrent overwrites.
func (r *pgxClusterInstanceRepository) UpdateState(ctx context.Context, id uuid.UUID, state, step string) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state = $2,
		       current_step       = $3,
		       updated_at         = NOW()
		WHERE  id = $1
		  AND  provisioning_state NOT IN ('failed', 'deleted')`

	tag, err := r.db.Exec(ctx, query, id, state, step)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.UpdateState: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.UpdateState %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetActive marks the cluster as fully operational.  The cluster endpoint and
// kubeconfig reference are written atomically with the state transition.
// Only transitions from non-terminal, non-failed states.
func (r *pgxClusterInstanceRepository) SetActive(ctx context.Context, id uuid.UUID, endpoint, kubeconfigRef string) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state  = 'active',
		       cluster_endpoint    = $2,
		       kubeconfig_secret_ref = $3,
		       provisioned_at      = NOW(),
		       current_step        = '',
		       failure_reason      = NULL,
		       updated_at          = NOW()
		WHERE  id = $1
		  AND  provisioning_state NOT IN ('active', 'failed', 'deleted')`

	tag, err := r.db.Exec(ctx, query, id, endpoint, kubeconfigRef)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.SetActive: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.SetActive %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetFailed marks the cluster as failed with a permanent reason (no retry scheduled).
// Only transitions from non-active, non-deleted states.
func (r *pgxClusterInstanceRepository) SetFailed(ctx context.Context, id uuid.UUID, reason string) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state = 'failed',
		       failure_reason     = $2,
		       updated_at         = NOW()
		WHERE  id = $1
		  AND  provisioning_state NOT IN ('active', 'deleted')`

	tag, err := r.db.Exec(ctx, query, id, reason)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.SetFailed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.SetFailed %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetFailedWithRetry marks the cluster as failed and schedules an automatic retry.
// retry_count is incremented by the caller before this method is invoked so the
// new value is persisted alongside the scheduled next_retry_at timestamp.
func (r *pgxClusterInstanceRepository) SetFailedWithRetry(ctx context.Context, id uuid.UUID, reason string, nextRetry time.Time) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state = 'failed',
		       failure_reason     = $2,
		       retry_count        = retry_count + 1,
		       next_retry_at      = $3,
		       updated_at         = NOW()
		WHERE  id = $1
		  AND  provisioning_state NOT IN ('active', 'deleted')`

	tag, err := r.db.Exec(ctx, query, id, reason, nextRetry)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.SetFailedWithRetry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.SetFailedWithRetry %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetPermanentlyFailed marks the cluster as failed with retries exhausted.
// The next_retry_at is cleared and max_retries_exhausted is set so the
// reconcile loop will never pick this instance up again automatically.
func (r *pgxClusterInstanceRepository) SetPermanentlyFailed(ctx context.Context, id uuid.UUID, reason string) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state  = 'failed',
		       failure_reason      = $2,
		       max_retries_exhausted = true,
		       next_retry_at       = NULL,
		       updated_at          = NOW()
		WHERE  id = $1
		  AND  provisioning_state NOT IN ('active', 'deleted')`

	tag, err := r.db.Exec(ctx, query, id, reason)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.SetPermanentlyFailed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.SetPermanentlyFailed %s: %w", id, ErrStateConflict)
	}
	return nil
}

// ResetForManualRetry resets a permanently-failed or failed cluster for an
// operator-initiated retry.  All retry counters are cleared so the backoff
// sequence restarts from zero.  Only transitions from the 'failed' state.
func (r *pgxClusterInstanceRepository) ResetForManualRetry(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state  = 'pending',
		       failure_reason      = NULL,
		       retry_count         = 0,
		       max_retries_exhausted = false,
		       next_retry_at       = NULL,
		       completed_steps     = '{}',
		       current_step        = '',
		       updated_at          = NOW()
		WHERE  id = $1
		  AND  provisioning_state = 'failed'`

	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.ResetForManualRetry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.ResetForManualRetry %s: instance not in failed state", id)
	}
	return nil
}

// SetDeleting transitions the cluster to the deleting state.
// Allowed from any non-terminal state (not already deleting or deleted).
func (r *pgxClusterInstanceRepository) SetDeleting(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state = 'deleting',
		       updated_at         = NOW()
		WHERE  id = $1
		  AND  provisioning_state NOT IN ('deleting', 'deleted')`

	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.SetDeleting: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.SetDeleting %s: %w", id, ErrStateConflict)
	}
	return nil
}

// SetDeleted transitions the cluster to the terminal deleted state.
// Only transitions from the 'deleting' state.
func (r *pgxClusterInstanceRepository) SetDeleted(ctx context.Context, id uuid.UUID) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    provisioning_state = 'deleted',
		       updated_at         = NOW()
		WHERE  id = $1
		  AND  provisioning_state = 'deleting'`

	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.SetDeleted: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.SetDeleted %s: %w", id, ErrStateConflict)
	}
	return nil
}

// UpdateClusterInfo stores runtime details discovered after the cluster becomes
// reachable: the API server endpoint, the Vault/K8s kubeconfig reference, and
// the ArgoCD cluster registration name.
func (r *pgxClusterInstanceRepository) UpdateClusterInfo(ctx context.Context, id uuid.UUID, endpoint, kubeconfigRef, argocdName string) error {
	const query = `
		UPDATE iam_cluster_instances
		SET    cluster_endpoint      = $2,
		       kubeconfig_secret_ref = $3,
		       argocd_cluster_name   = $4,
		       updated_at            = NOW()
		WHERE  id = $1`

	tag, err := r.db.Exec(ctx, query, id, endpoint, kubeconfigRef, argocdName)
	if err != nil {
		return fmt.Errorf("ClusterInstanceRepository.UpdateClusterInfo: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("ClusterInstanceRepository.UpdateClusterInfo %s: cluster not found", id)
	}
	return nil
}

// GetStats returns aggregate counts for the cluster fleet.  All counts are
// computed in a single query using conditional aggregates to avoid N+1 round trips.
func (r *pgxClusterInstanceRepository) GetStats(ctx context.Context) (*ClusterStats, error) {
	const query = `
		SELECT
			COUNT(*)                                                      AS total_clusters,
			COUNT(*) FILTER (WHERE provisioning_state = 'active')        AS active_clusters,
			COUNT(*) FILTER (WHERE provisioning_state IN (
				'pending', 'creating', 'configuring', 'registering_routes'
			))                                                            AS pending_clusters,
			COUNT(*) FILTER (WHERE provisioning_state = 'failed')        AS failed_clusters
		FROM iam_cluster_instances
		WHERE provisioning_state != 'deleted'`

	stats := &ClusterStats{
		ByTier:       make(map[string]int),
		ByDataCenter: make(map[string]int),
	}

	if err := r.db.QueryRow(ctx, query).Scan(
		&stats.TotalClusters,
		&stats.ActiveClusters,
		&stats.PendingClusters,
		&stats.FailedClusters,
	); err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.GetStats: %w", err)
	}

	// Breakdown by isolation tier.
	tierRows, err := r.db.Query(ctx, `
		SELECT isolation_tier, COUNT(*)
		FROM iam_cluster_instances
		WHERE provisioning_state != 'deleted'
		GROUP BY isolation_tier`)
	if err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.GetStats tier: %w", err)
	}
	defer tierRows.Close()
	for tierRows.Next() {
		var tier string
		var count int
		if err := tierRows.Scan(&tier, &count); err != nil {
			return nil, fmt.Errorf("ClusterInstanceRepository.GetStats tier scan: %w", err)
		}
		stats.ByTier[tier] = count
	}
	if err := tierRows.Err(); err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.GetStats tier rows: %w", err)
	}

	// Breakdown by data center.
	dcRows, err := r.db.Query(ctx, `
		SELECT data_center, COUNT(*)
		FROM iam_cluster_instances
		WHERE provisioning_state != 'deleted'
		GROUP BY data_center`)
	if err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.GetStats data_center: %w", err)
	}
	defer dcRows.Close()
	for dcRows.Next() {
		var dc string
		var count int
		if err := dcRows.Scan(&dc, &count); err != nil {
			return nil, fmt.Errorf("ClusterInstanceRepository.GetStats data_center scan: %w", err)
		}
		stats.ByDataCenter[dc] = count
	}
	if err := dcRows.Err(); err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.GetStats data_center rows: %w", err)
	}

	return stats, nil
}

// queryList is the shared list helper used by ListByTenant, ListByProduct, and
// ListPending.  It executes the provided query with optional args, scans every
// row via clusterDest, and collects results into a slice.
func (r *pgxClusterInstanceRepository) queryList(ctx context.Context, query, caller string, args ...interface{}) ([]models.ClusterInstance, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.%s: %w", caller, err)
	}
	defer rows.Close()

	var instances []models.ClusterInstance
	for rows.Next() {
		var ci models.ClusterInstance
		if err := rows.Scan(clusterDest(&ci)...); err != nil {
			return nil, fmt.Errorf("ClusterInstanceRepository.%s scan: %w", caller, err)
		}
		instances = append(instances, ci)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ClusterInstanceRepository.%s rows: %w", caller, err)
	}
	return instances, nil
}

// clusterDest returns the ordered list of scan destinations for a ClusterInstance.
// The column order must match clusterColumns exactly.
func clusterDest(ci *models.ClusterInstance) []interface{} {
	return []interface{}{
		&ci.ID, &ci.TenantID, &ci.ProductID, &ci.ProductSlug,
		&ci.ClusterName, &ci.IsolationTier, &ci.DataCenter,
		&ci.KubernetesVersion, &ci.NodeCount, &ci.NodeSize,
		&ci.ClusterEndpoint, &ci.KubeConfigSecretRef, &ci.CACertificate,
		&ci.ProvisioningState, &ci.CurrentStep, &ci.CompletedSteps,
		&ci.FailureReason, &ci.RetryCount, &ci.MaxRetriesExhausted, &ci.NextRetryAt,
		&ci.Provider, &ci.CrossplaneClaimRef, &ci.ArgocdClusterName,
		&ci.VclusterName, &ci.VclusterNamespace,
		&ci.ProvisionedAt, &ci.CreatedAt, &ci.UpdatedAt,
	}
}
