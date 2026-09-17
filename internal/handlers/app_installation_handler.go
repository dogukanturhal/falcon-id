// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// appInstallService defines the service interface used by AppInstallationHandler.
type appInstallService interface {
	Install(ctx context.Context, tenantID, productID, installedBy uuid.UUID, scopes []string) (*models.AppInstallation, error)
	Uninstall(ctx context.Context, tenantID, productID uuid.UUID) error
	GetInstallation(ctx context.Context, tenantID, productID uuid.UUID) (*models.AppInstallation, error)
	ListInstallations(ctx context.Context, tenantID uuid.UUID, status string, page, pageSize int) ([]models.AppInstallation, int64, error)
}

// AppInstallationHandler handles marketplace app install/uninstall HTTP endpoints.
type AppInstallationHandler struct {
	svc appInstallService
}

// NewAppInstallationHandler creates a new AppInstallationHandler.
func NewAppInstallationHandler(svc appInstallService) *AppInstallationHandler {
	return &AppInstallationHandler{svc: svc}
}

// installRequest is the payload for POST /api/v1/platform/apps/install.
type installRequest struct {
	ProductID   uuid.UUID `json:"product_id" binding:"required"`
	InstalledBy uuid.UUID `json:"installed_by"`
	Scopes      []string  `json:"scopes"`
}

// uninstallRequest is the payload for POST /api/v1/platform/apps/uninstall.
type uninstallRequest struct {
	ProductID uuid.UUID `json:"product_id" binding:"required"`
}

// Install handles POST /api/v1/platform/apps/install.
// It requires a valid tenant context and an authenticated user.
func (h *AppInstallationHandler) Install(c *gin.Context) {
	currentUser, ok := RequireCurrentUser(c)
	if !ok {
		return
	}

	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	var req installRequest
	if !BindJSON(c, &req) {
		return
	}

	// Allow override of installed_by; fall back to the authenticated user.
	installedBy := req.InstalledBy
	if installedBy == uuid.Nil {
		installedBy = currentUser.ID
	}

	inst, err := h.svc.Install(c.Request.Context(), tenantID, req.ProductID, installedBy, req.Scopes)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"installation": inst.ToResponse()})
}

// Uninstall handles POST /api/v1/platform/apps/uninstall.
func (h *AppInstallationHandler) Uninstall(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	var req uninstallRequest
	if !BindJSON(c, &req) {
		return
	}

	if err := h.svc.Uninstall(c.Request.Context(), tenantID, req.ProductID); err != nil {
		HandleError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// ListInstallations handles GET /api/v1/platform/apps/installations.
func (h *AppInstallationHandler) ListInstallations(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")

	installations, total, err := h.svc.ListInstallations(c.Request.Context(), tenantID, status, page, pageSize)
	if err != nil {
		HandleError(c, err)
		return
	}

	if pageSize < 1 {
		pageSize = 20
	}

	responses := make([]*models.AppInstallationResponse, 0, len(installations))
	for i := range installations {
		responses = append(responses, installations[i].ToResponse())
	}

	totalPages := CalculateTotalPages(total, pageSize)

	c.JSON(http.StatusOK, gin.H{
		"installations": responses,
		"total":         total,
		"page":          page,
		"page_size":     pageSize,
		"total_pages":   totalPages,
	})
}

// GetInstallation handles GET /api/v1/platform/apps/installations/:id.
// The :id path parameter is the product_id (to look up by tenant+product pair).
func (h *AppInstallationHandler) GetInstallation(c *gin.Context) {
	tenantID, ok := RequireTenantID(c)
	if !ok {
		return
	}

	productID, ok := ParseUUIDParam(c, "id")
	if !ok {
		return
	}

	inst, err := h.svc.GetInstallation(c.Request.Context(), tenantID, productID)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"installation": inst.ToResponse()})
}
