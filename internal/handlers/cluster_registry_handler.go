// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgClusterRegistryUnavailable = "Cluster registry unavailable — database pool not initialised"
)

// ClusterRegistryEntry is the unified type returned by the registry endpoint.
// It merges platform clusters (platform_cluster_registry) and tenant-provisioned
// clusters (iam_cluster_instances) into a single, consistent shape.
//
// The Class field distinguishes the two origins:
//   - "platform", "dev", "imported" — rows from platform_cluster_registry
//   - "tenant-namespace", "tenant-vcluster", "tenant-dedicated", "tenant-bare-metal" — rows from iam_cluster_instances
type ClusterRegistryEntry struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	DisplayName       string   `json:"display_name"`
	Class             string   `json:"class"`   // platform, dev, imported, tenant-shared, tenant-vcluster, tenant-dedicated, tenant-bare-metal
	Runtime           string   `json:"runtime"` // k3s, k3d, kubeadm, vcluster, capi, imported
	DataCenter        string   `json:"data_center"`
	KubernetesVersion string   `json:"kubernetes_version"`
	NodeCount         int      `json:"node_count"`
	Health            string   `json:"health"` // healthy, degraded, unreachable, unknown
	APIEndpoint       *string  `json:"api_endpoint,omitempty"`
	ArgocdName        *string  `json:"argocd_name,omitempty"`
	Capabilities      []string `json:"capabilities"`
	Description       *string  `json:"description,omitempty"`
	// Tenant context — null for platform/dev clusters.
	TenantID          *string `json:"tenant_id,omitempty"`
	ProductID         *string `json:"product_id,omitempty"`
	ProductSlug       *string `json:"product_slug,omitempty"`
	ProvisioningState *string `json:"provisioning_state,omitempty"`
	FailureReason     *string `json:"failure_reason,omitempty"`
	RetryCount        *int    `json:"retry_count,omitempty"`
	// Timestamps
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ClusterRegistryStats holds aggregated counts for the full cluster fleet
// (both platform and tenant-provisioned clusters).
type ClusterRegistryStats struct {
	Total     int            `json:"total"`
	ByClass   map[string]int `json:"by_class"`
	ByRuntime map[string]int `json:"by_runtime"`
	ByHealth  map[string]int `json:"by_health"`
}

// RegisterClusterRequest is the payload for importing or registering a new
// platform-managed cluster into platform_cluster_registry.
type RegisterClusterRequest struct {
	Name              string            `json:"name"               binding:"required,min=2,max=100"`
	DisplayName       string            `json:"display_name"       binding:"required,min=2,max=200"`
	Class             string            `json:"class"              binding:"required,oneof=platform dev imported"`
	Runtime           string            `json:"runtime"            binding:"required,oneof=k3s k3d kubeadm rke2 imported"`
	DataCenter        string            `json:"data_center"        binding:"omitempty,max=100"`
	APIEndpoint       string            `json:"api_endpoint"       binding:"omitempty,max=500"`
	KubeconfigRef     string            `json:"kubeconfig_ref"     binding:"omitempty,max=500"`
	ArgocdName        string            `json:"argocd_name"        binding:"omitempty,max=200"`
	KubernetesVersion string            `json:"kubernetes_version" binding:"omitempty,max=20"`
	NodeCount         int               `json:"node_count"         binding:"omitempty,min=0"`
	Description       string            `json:"description"        binding:"omitempty,max=1000"`
	Capabilities      []string          `json:"capabilities"`
	Labels            map[string]string `json:"labels"`
}

// UpdateHealthRequest is the payload for PATCH /cluster-registry/:id/health.
type UpdateHealthRequest struct {
	Health string `json:"health" binding:"required,oneof=healthy degraded unreachable unknown"`
}

// ClusterRegistryHandler handles HTTP endpoints that expose a unified view of
// all Kubernetes clusters managed by the HexxLock platform — both the
// infrastructure-level platform clusters and tenant-provisioned clusters.
//
// It queries platform_cluster_registry and iam_cluster_instances directly
// via a pgxpool.Pool because the unified UNION view does not map cleanly
// to a single repository interface.
type ClusterRegistryHandler struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
}

// NewClusterRegistryHandler creates a handler backed by the supplied pool.
// The pool must not be nil; a nil pool causes all handlers to return 503.
func NewClusterRegistryHandler(pool *pgxpool.Pool) *ClusterRegistryHandler {
	return &ClusterRegistryHandler{
		pool:   pool,
		logger: logger.Log,
	}
}

// ─── Endpoints ────────────────────────────────────────────────────────────────

// List handles GET /api/v1/platform/cluster-registry
//
// Returns the unified list of all platform and tenant clusters.
//
// Optional query filters:
//
//	class   – one of: platform, dev, imported, or a "tenant-*" prefix
//	runtime – one of: k3s, k3d, kubeadm, rke2, vcluster, capi, imported
//	health  – one of: healthy, degraded, unreachable, unknown
//
// Response: {"data": [...], "total": N}
func (h *ClusterRegistryHandler) List(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgClusterRegistryUnavailable})
		return
	}

	classFilter := c.Query("class")
	runtimeFilter := c.Query("runtime")
	healthFilter := c.Query("health")

	// Build the UNION query. Filters are applied as a WHERE clause wrapping
	// the entire subquery so the same filter logic covers both sources.
	const baseQuery = `
SELECT
    id::text, name, display_name, class, runtime,
    COALESCE(data_center, ''),
    COALESCE(kubernetes_version, ''),
    COALESCE(node_count, 0),
    health,
    api_endpoint,
    argocd_name,
    capabilities::text,
    description,
    NULL::text AS tenant_id,
    NULL::text AS product_id,
    NULL::text AS product_slug,
    NULL::text AS provisioning_state,
    NULL::text AS failure_reason,
    NULL::int  AS retry_count,
    registered_at AS created_at,
    updated_at
FROM platform_cluster_registry

UNION ALL

SELECT
    id::text,
    cluster_name,
    cluster_name,
    'tenant-' || isolation_tier,
    CASE isolation_tier
        WHEN 'vcluster'   THEN 'vcluster'
        WHEN 'dedicated'  THEN 'capi'
        WHEN 'bare-metal' THEN 'capi'
        ELSE 'k8s'
    END,
    COALESCE(data_center, ''),
    COALESCE(kubernetes_version, ''),
    COALESCE(node_count, 0),
    CASE provisioning_state
        WHEN 'active'  THEN 'healthy'
        WHEN 'failed'  THEN 'unreachable'
        ELSE 'unknown'
    END,
    cluster_endpoint,
    argocd_cluster_name,
    CASE isolation_tier
        WHEN 'vcluster'   THEN '["gitops", "delete", "retry"]'
        WHEN 'dedicated'  THEN '["node-ops", "gitops", "drain", "delete", "retry"]'
        WHEN 'bare-metal' THEN '["node-ops", "gitops", "drain", "cordon", "delete", "retry"]'
        ELSE '["gitops", "delete", "retry"]'
    END,
    NULL::text,
    tenant_id::text,
    product_id::text,
    product_slug,
    provisioning_state,
    failure_reason,
    retry_count,
    created_at,
    updated_at
FROM iam_cluster_instances
WHERE provisioning_state != 'deleted'`

	// Wrap the UNION in a subquery so ORDER BY applies to the combined result
	// and so that per-column WHERE filters are straightforward to append.
	type whereArg struct {
		col string
		val string
	}
	var filters []whereArg
	if classFilter != "" {
		filters = append(filters, whereArg{"class", classFilter})
	}
	if runtimeFilter != "" {
		filters = append(filters, whereArg{"runtime", runtimeFilter})
	}
	if healthFilter != "" {
		filters = append(filters, whereArg{"health", healthFilter})
	}

	var sb strings.Builder
	sb.WriteString("SELECT * FROM (")
	sb.WriteString(baseQuery)
	sb.WriteString(") AS registry")

	var args []interface{}
	if len(filters) > 0 {
		sb.WriteString(" WHERE ")
		for i, f := range filters {
			if i > 0 {
				sb.WriteString(" AND ")
			}
			fmt.Fprintf(&sb, "%s = $%d", f.col, i+1)
			args = append(args, f.val)
		}
	}
	sb.WriteString(" ORDER BY created_at DESC")

	rows, err := h.pool.Query(c.Request.Context(), sb.String(), args...)
	if err != nil {
		h.logger.Error("ClusterRegistryHandler.List: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list cluster registry"})
		return
	}
	defer rows.Close()

	entries := make([]ClusterRegistryEntry, 0)
	for rows.Next() {
		e, err := scanRegistryRow(rows)
		if err != nil {
			h.logger.Error("ClusterRegistryHandler.List: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan cluster registry row"})
			return
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ClusterRegistryHandler.List: rows error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to iterate cluster registry"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  entries,
		"total": len(entries),
	})
}

// GetStats handles GET /api/v1/platform/cluster-registry/stats
//
// Returns aggregated counts across both platform and tenant clusters,
// broken down by class, runtime, and health status.
//
// Response: {"data": {...}}
func (h *ClusterRegistryHandler) GetStats(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgClusterRegistryUnavailable})
		return
	}

	// A single query against the UNION subquery computes all three breakdowns
	// with GROUP BY, avoiding multiple round-trips.
	const query = `
WITH registry AS (
    SELECT class, runtime,
           health
    FROM platform_cluster_registry

    UNION ALL

    SELECT
        'tenant-' || isolation_tier AS class,
        CASE isolation_tier
            WHEN 'vcluster'   THEN 'vcluster'
            WHEN 'dedicated'  THEN 'capi'
            WHEN 'bare-metal' THEN 'capi'
            ELSE 'k8s'
        END AS runtime,
        CASE provisioning_state
            WHEN 'active'  THEN 'healthy'
            WHEN 'failed'  THEN 'unreachable'
            ELSE 'unknown'
        END AS health
    FROM iam_cluster_instances
    WHERE provisioning_state != 'deleted'
)
SELECT
    COUNT(*) AS total,
    class,
    runtime,
    health
FROM registry
GROUP BY GROUPING SETS ((), (class), (runtime), (health))`

	rows, err := h.pool.Query(c.Request.Context(), query)
	if err != nil {
		h.logger.Error("ClusterRegistryHandler.GetStats: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve cluster registry stats"})
		return
	}
	defer rows.Close()

	stats := &ClusterRegistryStats{
		ByClass:   make(map[string]int),
		ByRuntime: make(map[string]int),
		ByHealth:  make(map[string]int),
	}

	for rows.Next() {
		var count int
		var class, runtime, health *string
		if err := rows.Scan(&count, &class, &runtime, &health); err != nil {
			h.logger.Error("ClusterRegistryHandler.GetStats: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan cluster registry stats"})
			return
		}
		switch {
		case class == nil && runtime == nil && health == nil:
			// Grand total row from GROUPING SETS ()
			stats.Total = count
		case class != nil && runtime == nil && health == nil:
			stats.ByClass[*class] = count
		case runtime != nil && class == nil && health == nil:
			stats.ByRuntime[*runtime] = count
		case health != nil && class == nil && runtime == nil:
			stats.ByHealth[*health] = count
		}
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ClusterRegistryHandler.GetStats: rows error", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to iterate cluster registry stats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}

// RegisterCluster handles POST /api/v1/platform/cluster-registry
//
// Imports or registers a new platform-managed cluster. Only inserts into
// platform_cluster_registry — tenant clusters are provisioned through the
// cluster instance provisioner, not this endpoint.
//
// Response: 201 Created {"data": {...}}
func (h *ClusterRegistryHandler) RegisterCluster(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgClusterRegistryUnavailable})
		return
	}

	var req RegisterClusterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default capabilities to empty array when not provided.
	if req.Capabilities == nil {
		req.Capabilities = []string{}
	}

	capsJSON, err := json.Marshal(req.Capabilities)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid capabilities format"})
		return
	}

	labelsJSON := []byte("{}")
	if len(req.Labels) > 0 {
		labelsJSON, err = json.Marshal(req.Labels)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid labels format"})
			return
		}
	}

	nullableStr := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}

	const insertQuery = `
		INSERT INTO platform_cluster_registry (
			name, display_name, class, runtime,
			data_center, api_endpoint, kubeconfig_ref, argocd_name,
			capabilities, labels,
			kubernetes_version, node_count, description
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10,
			$11, $12, $13
		)
		RETURNING
			id::text, name, display_name, class, runtime,
			COALESCE(data_center, ''), COALESCE(kubernetes_version, ''),
			COALESCE(node_count, 0), health,
			api_endpoint, argocd_name, capabilities::text, description,
			registered_at, updated_at`

	row := h.pool.QueryRow(c.Request.Context(), insertQuery,
		req.Name, req.DisplayName, req.Class, req.Runtime,
		nullableStr(req.DataCenter), nullableStr(req.APIEndpoint),
		nullableStr(req.KubeconfigRef), nullableStr(req.ArgocdName),
		capsJSON, labelsJSON,
		nullableStr(req.KubernetesVersion), req.NodeCount, nullableStr(req.Description),
	)

	entry, err := scanRegistryInsertRow(row)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "A cluster with this name already exists"})
			return
		}
		h.logger.Error("ClusterRegistryHandler.RegisterCluster: insert failed",
			zap.String("name", req.Name),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register cluster"})
		return
	}

	h.logger.Info("Platform cluster registered",
		zap.String("id", entry.ID),
		zap.String("name", entry.Name),
		zap.String("class", entry.Class),
		zap.String("runtime", entry.Runtime),
	)

	c.JSON(http.StatusCreated, gin.H{"data": entry})
}

// UpdateHealth handles PATCH /api/v1/platform/cluster-registry/:id/health
//
// Updates the health status of a platform cluster. This endpoint targets
// platform_cluster_registry only — tenant cluster health is derived from
// their provisioning_state and is not directly settable.
//
// Response: 200 OK {"data": {"id": "...", "health": "...", "updated_at": "..."}}
func (h *ClusterRegistryHandler) UpdateHealth(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgClusterRegistryUnavailable})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cluster ID is required"})
		return
	}

	var req UpdateHealthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const query = `
		UPDATE platform_cluster_registry
		SET    health       = $2,
		       last_seen_at = NOW(),
		       updated_at   = NOW()
		WHERE  id = $1
		RETURNING id, health, updated_at`

	var (
		returnedID        string
		returnedHealth    string
		returnedUpdatedAt time.Time
	)
	err := h.pool.QueryRow(c.Request.Context(), query, id, req.Health).
		Scan(&returnedID, &returnedHealth, &returnedUpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found in platform registry"})
			return
		}
		h.logger.Error("ClusterRegistryHandler.UpdateHealth: update failed",
			zap.String("id", id),
			zap.String("health", req.Health),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update cluster health"})
		return
	}

	h.logger.Info("Platform cluster health updated",
		zap.String("id", returnedID),
		zap.String("health", returnedHealth),
	)

	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"id":         returnedID,
		"health":     returnedHealth,
		"updated_at": returnedUpdatedAt.UTC().Format(time.RFC3339),
	}})
}

// Deregister handles DELETE /api/v1/platform/cluster-registry/:id
//
// Removes a cluster from platform_cluster_registry. Only clusters with
// class "imported" or "dev" may be deregistered — "platform" clusters are
// permanent infrastructure and cannot be removed via the API.
//
// Tenant-provisioned clusters (iam_cluster_instances) are not affected by
// this endpoint; use the cluster instance delete endpoint instead.
//
// Response: 204 No Content
func (h *ClusterRegistryHandler) Deregister(c *gin.Context) {
	if h.pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": msgClusterRegistryUnavailable})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cluster ID is required"})
		return
	}

	// Fetch the cluster first to enforce the class guard before deletion.
	var class string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT class FROM platform_cluster_registry WHERE id = $1`, id,
	).Scan(&class)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Cluster not found in platform registry"})
			return
		}
		h.logger.Error("ClusterRegistryHandler.Deregister: lookup failed",
			zap.String("id", id),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up cluster"})
		return
	}

	if class == "platform" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Platform clusters cannot be deregistered — they represent permanent infrastructure",
			"class": class,
		})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM platform_cluster_registry WHERE id = $1 AND class IN ('imported', 'dev')`, id,
	)
	if err != nil {
		h.logger.Error("ClusterRegistryHandler.Deregister: delete failed",
			zap.String("id", id),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deregister cluster"})
		return
	}
	if tag.RowsAffected() == 0 {
		// Race condition: class changed between SELECT and DELETE, or ID gone.
		c.JSON(http.StatusConflict, gin.H{"error": "Cluster could not be deregistered — it may have been modified concurrently"})
		return
	}

	h.logger.Info("Platform cluster deregistered",
		zap.String("id", id),
		zap.String("class", class),
	)

	c.Status(http.StatusNoContent)
}

// ─── Scanning helpers ─────────────────────────────────────────────────────────

// registryScanner is satisfied by both pgx.Row and pgx.Rows, allowing the
// scan helpers below to work with both QueryRow and Query results.
type registryScanner interface {
	Scan(dest ...interface{}) error
}

// scanRegistryRow scans a single row from the UNION query into a ClusterRegistryEntry.
// The column order must match the SELECT list in List exactly.
func scanRegistryRow(row registryScanner) (ClusterRegistryEntry, error) {
	var (
		e               ClusterRegistryEntry
		capabilitiesRaw []byte
		createdAt       time.Time
		updatedAt       time.Time
	)

	if err := row.Scan(
		&e.ID,
		&e.Name,
		&e.DisplayName,
		&e.Class,
		&e.Runtime,
		&e.DataCenter,
		&e.KubernetesVersion,
		&e.NodeCount,
		&e.Health,
		&e.APIEndpoint,
		&e.ArgocdName,
		&capabilitiesRaw,
		&e.Description,
		&e.TenantID,
		&e.ProductID,
		&e.ProductSlug,
		&e.ProvisioningState,
		&e.FailureReason,
		&e.RetryCount,
		&createdAt,
		&updatedAt,
	); err != nil {
		return ClusterRegistryEntry{}, fmt.Errorf("scanRegistryRow: %w", err)
	}

	if len(capabilitiesRaw) > 0 {
		if err := json.Unmarshal(capabilitiesRaw, &e.Capabilities); err != nil {
			return ClusterRegistryEntry{}, fmt.Errorf("scanRegistryRow: unmarshal capabilities: %w", err)
		}
	}
	if e.Capabilities == nil {
		e.Capabilities = []string{}
	}

	e.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	e.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)

	return e, nil
}

// scanRegistryInsertRow scans the RETURNING columns from an INSERT into
// platform_cluster_registry.  The column order matches the RETURNING clause
// in RegisterCluster exactly.
func scanRegistryInsertRow(row registryScanner) (ClusterRegistryEntry, error) {
	var (
		e               ClusterRegistryEntry
		capabilitiesRaw []byte
		createdAt       time.Time
		updatedAt       time.Time
	)

	if err := row.Scan(
		&e.ID,
		&e.Name,
		&e.DisplayName,
		&e.Class,
		&e.Runtime,
		&e.DataCenter,
		&e.KubernetesVersion,
		&e.NodeCount,
		&e.Health,
		&e.APIEndpoint,
		&e.ArgocdName,
		&capabilitiesRaw,
		&e.Description,
		&createdAt,
		&updatedAt,
	); err != nil {
		return ClusterRegistryEntry{}, fmt.Errorf("scanRegistryInsertRow: %w", err)
	}

	if len(capabilitiesRaw) > 0 {
		if err := json.Unmarshal(capabilitiesRaw, &e.Capabilities); err != nil {
			return ClusterRegistryEntry{}, fmt.Errorf("scanRegistryInsertRow: unmarshal capabilities: %w", err)
		}
	}
	if e.Capabilities == nil {
		e.Capabilities = []string{}
	}

	e.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	e.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)

	return e, nil
}
