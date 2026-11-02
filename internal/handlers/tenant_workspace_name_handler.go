// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// TenantWorkspaceNameHandler serves the two ways a placeholder workspace name
// ("My Company") gets replaced server-side: the S2S rename business calls when
// a tenant's first legal entity is created, and the platform-admin backfill for
// tenants that already exist.
type TenantWorkspaceNameHandler struct {
	svc    *services.TenantWorkspaceNameService
	logger *zap.Logger
}

// NewTenantWorkspaceNameHandler creates the handler.
func NewTenantWorkspaceNameHandler(svc *services.TenantWorkspaceNameService, logger *zap.Logger) *TenantWorkspaceNameHandler {
	return &TenantWorkspaceNameHandler{svc: svc, logger: logger}
}

type workspaceNameRequest struct {
	Name string `json:"name"`
}

// RenameIfPlaceholder handles PUT /internal/v1/tenants/{id}/workspace-name.
// Scope iam:tenants:workspace-name:write is enforced by the route. Renames only
// while the tenant is still on the placeholder; otherwise a 200 "already_named"
// no-op, so callers can fire it on every first-company create without checking.
//
// @Summary Replace the placeholder workspace name (S2S)
// @Tags Internal
// @Router /internal/v1/tenants/{id}/workspace-name [put]
func (h *TenantWorkspaceNameHandler) RenameIfPlaceholder(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}
	var req workspaceNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	outcome, err := h.svc.RenameIfPlaceholder(c.Request.Context(), tenantID, req.Name)
	switch {
	case errors.Is(err, services.ErrInvalidWorkspaceName):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case err != nil:
		h.logger.Error("workspace-name rename failed", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "rename failed"})
	case outcome == services.WorkspaceNotFound:
		c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
	default:
		c.JSON(http.StatusOK, gin.H{"tenantId": tenantID, "result": outcome})
	}
}

// Backfill handles POST /api/platform/management/tenants/placeholder-names/backfill
// (platform admin). Body {"dryRun": false} applies; anything else, including an
// empty body, is a dry run that reports what would change.
//
// @Summary Backfill placeholder workspace names (platform admin)
// @Tags Platform Admin - Tenants
// @Router /api/platform/management/tenants/placeholder-names/backfill [post]
func (h *TenantWorkspaceNameHandler) Backfill(c *gin.Context) {
	var req struct {
		DryRun *bool `json:"dryRun"`
	}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
	}
	dryRun := req.DryRun == nil || *req.DryRun

	report, err := h.svc.Backfill(c.Request.Context(), dryRun)
	if err != nil {
		h.logger.Error("workspace-name backfill failed", zap.Bool("dry_run", dryRun), zap.Error(err))
		status := http.StatusInternalServerError
		if report == nil {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"error": "backfill failed", "report": report})
		return
	}
	h.logger.Info("workspace-name backfill finished", zap.Bool("dry_run", dryRun),
		zap.Int("scanned", report.Scanned), zap.Any("counts", report.Counts))
	c.JSON(http.StatusOK, report)
}
