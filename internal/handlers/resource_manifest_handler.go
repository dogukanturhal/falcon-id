// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgResourceManifestInvalidInstanceID = "Invalid instance ID"
)

// resourceManifestRepo is the repository interface the handler needs.
type resourceManifestRepo interface {
	ListByProduct(ctx context.Context, productID uuid.UUID) ([]models.ProductResourceManifest, error)
	Create(ctx context.Context, m *models.ProductResourceManifest) error
	UpsertBatch(ctx context.Context, productID uuid.UUID, resources []models.ProductResourceManifest) (registered, updated int, err error)
}

// resourceInstanceRepo is the repository interface for per-tenant resource instances.
type resourceInstanceRepo interface {
	ListByInstance(ctx context.Context, instanceID uuid.UUID) ([]models.TenantResourceInstance, error)
}

// ResourceManifestHandler handles resource manifest and resource instance API endpoints.
type ResourceManifestHandler struct {
	manifestRepo    resourceManifestRepo
	instanceRepo    resourceInstanceRepo
	orchestrator    *services.ResourceOrchestrator
	productInstRepo productInstanceRepoForResource
}

// productInstanceRepoForResource is the narrow interface needed to look up a
// product instance by ID so we know which tenantID/productID to provision for.
type productInstanceRepoForResource interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.ProductInstance, error)
}

// NewResourceManifestHandler creates the handler.
func NewResourceManifestHandler(
	manifestRepo resourceManifestRepo,
	instanceRepo resourceInstanceRepo,
	orchestrator *services.ResourceOrchestrator,
	productInstRepo productInstanceRepoForResource,
) *ResourceManifestHandler {
	return &ResourceManifestHandler{
		manifestRepo:    manifestRepo,
		instanceRepo:    instanceRepo,
		orchestrator:    orchestrator,
		productInstRepo: productInstRepo,
	}
}

// ListManifest returns all resource manifest entries for a product.
// GET /api/v1/platform/products/:id/resource-manifest
func (h *ResourceManifestHandler) ListManifest(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	manifests, err := h.manifestRepo.ListByProduct(c.Request.Context(), productID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list resource manifest"})
		return
	}

	if manifests == nil {
		manifests = []models.ProductResourceManifest{}
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_manifest": manifests,
		"total":             len(manifests),
	})
}

// AddManifestEntry adds a resource entry to a product's manifest.
// POST /api/v1/platform/products/:id/resource-manifest
func (h *ResourceManifestHandler) AddManifestEntry(c *gin.Context) {
	productID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product ID"})
		return
	}

	var req models.CreateResourceManifestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Marshal config map to JSON.
	configJSON := json.RawMessage(`{}`)
	if len(req.Config) > 0 {
		b, err := json.Marshal(req.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid config JSON"})
			return
		}
		configJSON = b
	}

	isRequired := true
	if req.IsRequired != nil {
		isRequired = *req.IsRequired
	}

	m := &models.ProductResourceManifest{
		ProductID:    productID,
		ResourceType: req.ResourceType,
		ResourceName: req.ResourceName,
		DisplayName:  req.DisplayName,
		Config:       configJSON,
		Priority:     req.Priority,
		IsRequired:   isRequired,
	}

	if err := h.manifestRepo.Create(c.Request.Context(), m); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add manifest entry"})
		return
	}

	c.JSON(http.StatusCreated, m)
}

// ListInstanceResources returns all provisioned resources for a product instance.
// GET /api/v1/platform/instances/:id/resources
func (h *ResourceManifestHandler) ListInstanceResources(c *gin.Context) {
	instanceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgResourceManifestInvalidInstanceID})
		return
	}

	resources, err := h.instanceRepo.ListByInstance(c.Request.Context(), instanceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list instance resources"})
		return
	}

	if resources == nil {
		resources = []models.TenantResourceInstance{}
	}

	c.JSON(http.StatusOK, gin.H{
		"resources": resources,
		"total":     len(resources),
	})
}

// ProvisionAll triggers provisioning of all resources declared in a product's
// manifest for the tenant associated with the given instance.
// POST /api/v1/platform/instances/:id/resources/provision-all
func (h *ResourceManifestHandler) ProvisionAll(c *gin.Context) {
	instanceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgResourceManifestInvalidInstanceID})
		return
	}

	if h.orchestrator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Resource orchestrator not configured"})
		return
	}

	if h.productInstRepo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Product instance repository not configured"})
		return
	}

	// Resolve the product instance to get tenantID and productID.
	pi, err := h.productInstRepo.GetByID(c.Request.Context(), instanceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	// Parse optional tier override from request body.
	var body struct {
		Tier   string `json:"tier"`
		Region string `json:"region"`
	}
	_ = c.ShouldBindJSON(&body)
	tier := body.Tier
	if tier == "" {
		tier = "pool" // safe default
	}

	results, err := h.orchestrator.ProvisionAll(
		c.Request.Context(),
		pi.TenantID,
		pi.ProductID,
		instanceID,
		body.Region,
		tier,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":     "One or more required resources failed to provision",
			"detail":    err.Error(),
			"resources": results,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "All resources provisioned successfully",
		"resources": results,
		"total":     len(results),
	})
}

// RegisterManifest is called by services on startup to declare all of their
// resources. It upserts the full set of resource declarations for the given
// service/product pair so Falcon-ID always has an up-to-date manifest.
//
// POST /api/v1/internal/resource-manifest/register
func (h *ResourceManifestHandler) RegisterManifest(c *gin.Context) {
	var req models.RegisterManifestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	productID, err := uuid.Parse(req.ProductID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid product_id: must be a UUID"})
		return
	}

	// Validate resource types against the known set.
	knownTypes := map[string]struct{}{
		models.ResourceTypeDatabase:         {},
		models.ResourceTypeStorageBucket:    {},
		models.ResourceTypeKafkaTopic:       {},
		models.ResourceTypeApisixRoute:      {},
		models.ResourceTypeSpiceDBNamespace: {},
		models.ResourceTypeDNSEntry:         {},
		models.ResourceTypeTLSCertificate:   {},
		models.ResourceTypeOAuthClient:      {},
	}
	for _, r := range req.Resources {
		if _, ok := knownTypes[r.ResourceType]; !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "unknown resource_type: " + r.ResourceType,
			})
			return
		}
	}

	// Convert DTOs to domain models.
	manifests := make([]models.ProductResourceManifest, len(req.Resources))
	for i, r := range req.Resources {
		configJSON := json.RawMessage(`{}`)
		if len(r.Config) > 0 {
			b, marshalErr := json.Marshal(r.Config)
			if marshalErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config JSON for resource " + r.ResourceName})
				return
			}
			configJSON = b
		}
		manifests[i] = models.ProductResourceManifest{
			ProductID:    productID,
			ResourceType: r.ResourceType,
			ResourceName: r.ResourceName,
			DisplayName:  r.DisplayName,
			Config:       configJSON,
			Priority:     r.Priority,
			IsRequired:   r.IsRequired,
		}
	}

	registered, updated, err := h.manifestRepo.UpsertBatch(c.Request.Context(), productID, manifests)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register manifest: " + err.Error()})
		return
	}

	// Fetch the current total for this product so the response is informative.
	all, listErr := h.manifestRepo.ListByProduct(c.Request.Context(), productID)
	total := 0
	if listErr == nil {
		total = len(all)
	}

	c.JSON(http.StatusOK, models.RegisterManifestResponse{
		ServiceSlug:    req.ServiceSlug,
		ProductID:      req.ProductID,
		Registered:     registered,
		Updated:        updated,
		TotalManifests: total,
	})
}

// HealthCheckAll checks the health of all provisioned resources for an instance.
// POST /api/v1/platform/instances/:id/resources/health-check
func (h *ResourceManifestHandler) HealthCheckAll(c *gin.Context) {
	instanceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgResourceManifestInvalidInstanceID})
		return
	}

	if h.orchestrator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Resource orchestrator not configured"})
		return
	}

	results, err := h.orchestrator.HealthCheckAll(c.Request.Context(), instanceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to perform health checks"})
		return
	}

	healthy := true
	for _, r := range results {
		if !r.Healthy {
			healthy = false
			break
		}
	}

	status := http.StatusOK
	if !healthy {
		status = http.StatusMultiStatus
	}

	c.JSON(status, gin.H{
		"healthy": healthy,
		"results": results,
		"total":   len(results),
	})
}
