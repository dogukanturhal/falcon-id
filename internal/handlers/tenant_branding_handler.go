// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantBrandingServiceInterface is the service contract consumed by TenantBrandingHandler.
type TenantBrandingServiceInterface interface {
	GetBranding(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error)
	UpdateBranding(ctx context.Context, tenantID uuid.UUID, req *models.UpdateTenantBrandingRequest) (*models.TenantBranding, error)
	DeleteBranding(ctx context.Context, tenantID uuid.UUID) error
}

// TenantBrandingHandler exposes admin endpoints for managing tenant branding.
// Routes are mounted under /api/v1/admin/tenants/:tenant_id/branding.
type TenantBrandingHandler struct {
	service TenantBrandingServiceInterface
}

// NewTenantBrandingHandler constructs a TenantBrandingHandler with the supplied service.
func NewTenantBrandingHandler(service TenantBrandingServiceInterface) *TenantBrandingHandler {
	return &TenantBrandingHandler{service: service}
}

// GetBranding handles GET /api/v1/admin/tenants/:tenant_id/branding.
// Returns the current branding configuration, falling back to platform defaults
// when the tenant has not configured custom branding.
func (h *TenantBrandingHandler) GetBranding(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	branding, err := h.service.GetBranding(c.Request.Context(), tenantID)
	if err != nil {
		HandleError(c, err)
		return
	}

	Success(c, branding)
}

// UpdateBranding handles PUT /api/v1/admin/tenants/:tenant_id/branding.
// Performs a partial update: only non-nil fields in the request body are applied.
// The endpoint is idempotent — calling it on a tenant with no existing branding
// will create a new record seeded with platform defaults then overlaid with the
// provided values.
func (h *TenantBrandingHandler) UpdateBranding(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	var req models.UpdateTenantBrandingRequest
	if !BindJSON(c, &req) {
		return
	}

	branding, err := h.service.UpdateBranding(c.Request.Context(), tenantID, &req)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    branding,
	})
}

// DeleteBranding handles DELETE /api/v1/admin/tenants/:tenant_id/branding.
// Removes the tenant's stored branding. Subsequent GET calls will return
// platform defaults until branding is configured again.
func (h *TenantBrandingHandler) DeleteBranding(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	if err := h.service.DeleteBranding(c.Request.Context(), tenantID); err != nil {
		HandleError(c, err)
		return
	}

	NoContent(c)
}
