// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgFailedToListClusterInstances    = "Failed to list cluster instances"
	msgInvalidClusterInstanceID        = "Invalid cluster instance ID"
	msgFailedToRetrieveClusterInstance = "Failed to retrieve cluster instance"
	msgClusterInstanceNotFound         = "Cluster instance not found"
)

// CreateClusterInstanceRequest is the payload for provisioning a new
// Kubernetes cluster for a tenant.
type CreateClusterInstanceRequest struct {
	TenantID          uuid.UUID `json:"tenant_id" binding:"required"`
	ProductID         uuid.UUID `json:"product_id" binding:"required"`
	ProductSlug       string    `json:"product_slug" binding:"required,min=2,max=100"`
	IsolationTier     string    `json:"isolation_tier" binding:"required,oneof=namespace vcluster dedicated bare-metal"`
	DataCenter        string    `json:"data_center" binding:"required,oneof=istanbul ankara"`
	KubernetesVersion string    `json:"kubernetes_version" binding:"omitempty,min=1,max=20"`
	NodeCount         int       `json:"node_count" binding:"omitempty,min=1,max=100"`
	NodeSize          string    `json:"node_size" binding:"omitempty,oneof=small medium large xlarge"`
}

// ClusterInstanceStats mirrors the aggregated stats returned by the repository
// but uses a JSON-friendly shape for the HTTP API.
type ClusterInstanceStats struct {
	Total        int            `json:"total"`
	Active       int            `json:"active"`
	Pending      int            `json:"pending"`
	Failed       int            `json:"failed"`
	ByTier       map[string]int `json:"by_tier"`
	ByDataCenter map[string]int `json:"by_data_center"`
}

// ClusterInstanceRepo is the narrow repository interface required by
// ClusterInstanceHandler. Each method maps directly to a handler use-case,
// keeping the boundary minimal and the handler easily testable with mocks.
type ClusterInstanceRepo interface {
	Create(ctx context.Context, ci *models.ClusterInstance) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.ClusterInstance, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.ClusterInstance, error)
	ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ClusterInstance, error)
	ListAll(ctx context.Context, limit, offset int) ([]models.ClusterInstance, int, error)
	ResetForManualRetry(ctx context.Context, id uuid.UUID) error
	SetDeleting(ctx context.Context, id uuid.UUID) error
	GetStats(ctx context.Context) (*ClusterInstanceStats, error)
}

// ClusterInstanceHandler handles HTTP endpoints for the Kubernetes cluster
// provisioning system. It manages the full lifecycle: create → active → delete,
// along with manual retry for failed clusters and cross-dimensional listing.
type ClusterInstanceHandler struct {
	repo   ClusterInstanceRepo
	logger *zap.Logger
}

// NewClusterInstanceHandler creates a handler backed by the supplied repository.
func NewClusterInstanceHandler(repo ClusterInstanceRepo) *ClusterInstanceHandler {
	return &ClusterInstanceHandler{
		repo:   repo,
		logger: logger.Log,
	}
}

// SetLogger replaces the default logger. Useful for injecting test loggers.
func (h *ClusterInstanceHandler) SetLogger(l *zap.Logger) {
	h.logger = l
}

// ─── Endpoints ────────────────────────────────────────────────────────────────

// List handles GET /api/v1/platform/clusters
//
// Returns a paginated list of all cluster instances across all tenants.
//
// Query params:
//
//	page      – 1-based page number            (default 1)
//	page_size – results per page               (default 20, max 100)
//
// Response: {"data": [...], "total": N, "page": P, "page_size": S}
func (h *ClusterInstanceHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	clusters, total, err := h.repo.ListAll(c.Request.Context(), pageSize, offset)
	if err != nil {
		h.logger.Error("Failed to list cluster instances", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToListClusterInstances})
		return
	}

	if clusters == nil {
		clusters = []models.ClusterInstance{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      clusters,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// Get handles GET /api/v1/platform/clusters/:id
//
// Returns the full detail of a single cluster instance.
//
// Response: {"data": {...}}
func (h *ClusterInstanceHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidClusterInstanceID})
		return
	}

	ci, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to retrieve cluster instance",
			zap.String("id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveClusterInstance})
		return
	}
	if ci == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgClusterInstanceNotFound})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": ci})
}

// Create handles POST /api/v1/platform/clusters
//
// Provisions a new Kubernetes cluster for a tenant. The cluster is created in
// the "pending" state; async provisioning is triggered out-of-band by the
// cluster provisioner background worker.
//
// Response: 202 Accepted  {"data": {...}, "message": "Cluster provisioning initiated"}
func (h *ClusterInstanceHandler) Create(c *gin.Context) {
	var req CreateClusterInstanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build cluster name from tenant slug + product
	clusterName := fmt.Sprintf("%s-%s-%s", req.ProductSlug, req.DataCenter, req.TenantID.String()[:8])

	ci := &models.ClusterInstance{
		ID:                uuid.New(),
		TenantID:          req.TenantID,
		ProductID:         req.ProductID,
		ProductSlug:       req.ProductSlug,
		ClusterName:       clusterName,
		IsolationTier:     req.IsolationTier,
		DataCenter:        req.DataCenter,
		KubernetesVersion: req.KubernetesVersion,
		NodeCount:         req.NodeCount,
		NodeSize:          req.NodeSize,
		ProvisioningState: models.ClusterProvisioningStatePending,
		Provider:          models.ClusterProviderCrossplane,
		CompletedSteps:    []string{},
	}

	if err := h.repo.Create(c.Request.Context(), ci); err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "A cluster with this name already exists"})
			return
		}
		h.logger.Error("Failed to create cluster instance",
			zap.String("tenant_id", req.TenantID.String()),
			zap.String("product_id", req.ProductID.String()),
			zap.String("isolation_tier", req.IsolationTier),
			zap.String("data_center", req.DataCenter),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create cluster instance"})
		return
	}

	h.logger.Info("Cluster instance created",
		zap.String("id", ci.ID.String()),
		zap.String("tenant_id", ci.TenantID.String()),
		zap.String("isolation_tier", ci.IsolationTier),
		zap.String("data_center", ci.DataCenter),
	)

	c.JSON(http.StatusAccepted, gin.H{
		"data":    ci,
		"message": "Cluster provisioning initiated",
	})
}

// Retry handles POST /api/v1/platform/clusters/:id/retry
//
// Resets a failed cluster instance for a manual operator-initiated retry.
//
// Response: 200 OK  {"data": {...}}
func (h *ClusterInstanceHandler) Retry(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidClusterInstanceID})
		return
	}

	ci, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveClusterInstance})
		return
	}
	if ci == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgClusterInstanceNotFound})
		return
	}

	if ci.ProvisioningState != models.ClusterProvisioningStateFailed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Only failed cluster instances are eligible for retry",
			"state": ci.ProvisioningState,
		})
		return
	}

	if err := h.repo.ResetForManualRetry(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to reset cluster instance for retry",
			zap.String("id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset cluster instance for retry"})
		return
	}

	// Re-fetch so the response reflects the updated state.
	updated, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil || updated == nil {
		// Non-fatal — return manually patched version.
		ci.ProvisioningState = models.ClusterProvisioningStatePending
		ci.FailureReason = nil
		ci.RetryCount = 0
		ci.MaxRetriesExhausted = false
		ci.NextRetryAt = nil
		c.JSON(http.StatusOK, gin.H{"data": ci})
		return
	}

	h.logger.Info("Cluster instance reset for manual retry",
		zap.String("id", id.String()),
		zap.String("tenant_id", updated.TenantID.String()),
	)

	c.JSON(http.StatusOK, gin.H{"data": updated})
}

// Delete handles DELETE /api/v1/platform/clusters/:id
//
// Transitions the cluster to "deleting" state. Actual teardown is handled
// asynchronously by the cluster deprovisioner background worker.
//
// Response: 202 Accepted  {"message": "Cluster deletion initiated"}
func (h *ClusterInstanceHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidClusterInstanceID})
		return
	}

	ci, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToRetrieveClusterInstance})
		return
	}
	if ci == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgClusterInstanceNotFound})
		return
	}

	if ci.ProvisioningState == models.ClusterProvisioningStateDeleted ||
		ci.ProvisioningState == models.ClusterProvisioningStateDeleting {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Cluster instance is already being deleted or has been deleted",
			"state": ci.ProvisioningState,
		})
		return
	}

	if err := h.repo.SetDeleting(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to set cluster instance to deleting",
			zap.String("id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate cluster deletion"})
		return
	}

	h.logger.Info("Cluster instance deletion initiated",
		zap.String("id", id.String()),
		zap.String("tenant_id", ci.TenantID.String()),
	)

	c.JSON(http.StatusAccepted, gin.H{"message": "Cluster deletion initiated"})
}

// GetStats handles GET /api/v1/platform/clusters/stats
//
// Returns aggregated platform-wide statistics across all cluster instances.
//
// Response: {"data": {...}}
func (h *ClusterInstanceHandler) GetStats(c *gin.Context) {
	stats, err := h.repo.GetStats(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to retrieve cluster statistics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve cluster statistics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}

// ListByTenant handles GET /api/v1/platform/tenants/:tenant_id/clusters
//
// Returns all non-deleted cluster instances provisioned for a specific tenant.
//
// Response: {"data": [...], "total": N}
func (h *ClusterInstanceHandler) ListByTenant(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	clusters, err := h.repo.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list cluster instances for tenant",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToListClusterInstances})
		return
	}

	if clusters == nil {
		clusters = []models.ClusterInstance{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  clusters,
		"total": len(clusters),
	})
}

// ListByProduct handles GET /api/v1/platform/products/:id/clusters
//
// Returns all non-deleted cluster instances associated with a specific product.
//
// Response: {"data": [...], "total": N}
func (h *ClusterInstanceHandler) ListByProduct(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	clusters, err := h.repo.ListByProduct(c.Request.Context(), productID)
	if err != nil {
		h.logger.Error("Failed to list cluster instances for product",
			zap.String("product_id", productID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgFailedToListClusterInstances})
		return
	}

	if clusters == nil {
		clusters = []models.ClusterInstance{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  clusters,
		"total": len(clusters),
	})
}
