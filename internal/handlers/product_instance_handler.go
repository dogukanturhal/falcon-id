// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// instanceDBLookup defines the interface for looking up instance databases.
type instanceDBLookup interface {
	LookupForTenant(ctx context.Context, tenantID uuid.UUID, databaseName string) (*models.InstanceDatabase, error)
	ListByInstanceWithGroups(ctx context.Context, instanceID uuid.UUID) ([]models.InstanceDatabaseResponse, error)
}

// instanceListByTenant defines the interface for listing instances by tenant.
type instanceListByTenant interface {
	ListByTenantAll(ctx context.Context, tenantID uuid.UUID) ([]models.ProductInstance, error)
}

// ProductInstanceHandler handles product instance HTTP endpoints.
type ProductInstanceHandler struct {
	instanceService       *services.ProductInstanceService
	orchestrator          *services.ProvisioningOrchestrator
	instanceDBRepo        instanceDBLookup
	instanceRepo          instanceListByTenant
	provisioningStatusSvc *services.ProvisioningStatusService
	encryption            *crypto.EncryptionService
}

// NewProductInstanceHandler creates a new product instance handler.
func NewProductInstanceHandler(
	instanceService *services.ProductInstanceService,
	orchestrator *services.ProvisioningOrchestrator,
) *ProductInstanceHandler {
	return &ProductInstanceHandler{
		instanceService: instanceService,
		orchestrator:    orchestrator,
	}
}

// SetInstanceDBRepo wires the instance database repository for tenant DB lookup.
func (h *ProductInstanceHandler) SetInstanceDBRepo(repo instanceDBLookup) {
	h.instanceDBRepo = repo
}

// SetInstanceRepo wires the product instance repository for tenant-scoped listing.
func (h *ProductInstanceHandler) SetInstanceRepo(repo instanceListByTenant) {
	h.instanceRepo = repo
}

// SetProvisioningStatusService wires the provisioning status service.
func (h *ProductInstanceHandler) SetProvisioningStatusService(svc *services.ProvisioningStatusService) {
	h.provisioningStatusSvc = svc
}

// SetEncryptionService wires the encryption service for decrypting silo connection strings.
func (h *ProductInstanceHandler) SetEncryptionService(enc *crypto.EncryptionService) {
	h.encryption = enc
}

// The 9 routes previously exposed here (Provision / Get / ListByTenant /
// ListByProduct / Deprovision / Retry / LookupTenantDatabase /
// ListInstanceDatabases / ListByTenantForPlatform) were moved to the
// db-provisioner service as part of Phase 1c decomposition (see
// cmd/routes_products.go comment near line 86). The method bodies were
// removed 2026-05-21 because every @Router annotation flagged them as
// unregistered in the docs/audits/2026-05-21-unregistered-handlers.md
// audit — kept previously as stale code, removed now to keep the audit
// signal clean. GetProvisioningStatus below is the only remaining
// surface and is still wired in cmd/routes.go.


// GetProvisioningStatus returns the provisioning status for the authenticated tenant.
//
// @Summary Get provisioning status
// @Description Returns the current provisioning status for all product instances of the authenticated tenant
// @Tags Product Instances
// @Produce json
// @Success 200 {object} map[string]interface{} "Provisioning status summary"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Failure 503 {object} map[string]string "Provisioning status not available"
// @Router /api/v1/tenant/provisioning/status [get]
func (h *ProductInstanceHandler) GetProvisioningStatus(c *gin.Context) {
	if h.provisioningStatusSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Provisioning status not available"})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	status, err := h.provisioningStatusSvc.GetStatus(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get provisioning status"})
		return
	}

	c.JSON(http.StatusOK, status)
}
