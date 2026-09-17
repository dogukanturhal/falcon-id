// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// tenant_data_export_handler.go provides TenantDataExportHandler, which exposes
// HTTP endpoints for triggering and listing cross-module tenant data exports.
//
// Routes (registered in cmd/routes_admin.go under the /platform/tenants group):
//
//	POST /platform/tenants/:tenant_id/export    — trigger a full export
//	GET  /platform/tenants/:tenant_id/exports   — list completed exports

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// TenantDataExportService is the interface the handler depends on.
// Satisfied by *services.TenantDataExportService.
type TenantDataExportService interface {
	ExportAll(ctx context.Context, req services.ExportRequest) (*services.ExportResult, error)
	ListExports(ctx context.Context, tenantID uuid.UUID) ([]services.ExportResult, error)
}

// TenantDataExportHandler handles tenant data export HTTP requests.
type TenantDataExportHandler struct {
	svc TenantDataExportService
}

// NewTenantDataExportHandler constructs a TenantDataExportHandler.
func NewTenantDataExportHandler(svc TenantDataExportService) *TenantDataExportHandler {
	return &TenantDataExportHandler{svc: svc}
}

// TriggerExport starts a full cross-module data export for the tenant.
//
// POST /platform/tenants/:tenant_id/export
//
// Request body (all fields optional):
//
//	{
//	  "format":  "json",             // default: "json"
//	  "modules": ["crm", "hr"]       // empty = all modules
//	}
//
// Responses:
//
//	202 – export completed; body contains ExportResult
//	400 – invalid tenant_id or malformed body
//	500 – export failed
func (h *TenantDataExportHandler) TriggerExport(c *gin.Context) {
	tenantID, ok := parseTenantIDParam(c)
	if !ok {
		return
	}

	var body struct {
		Format  string   `json:"format"`
		Modules []string `json:"modules"`
	}
	// Non-binding: all fields are optional.
	_ = c.ShouldBindJSON(&body)

	format := strings.TrimSpace(body.Format)
	if format == "" {
		format = "json"
	}

	req := services.ExportRequest{
		TenantID: tenantID,
		Format:   format,
		Modules:  body.Modules,
	}

	result, err := h.svc.ExportAll(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, result)
}

// ListExports returns all completed exports for the tenant.
//
// GET /platform/tenants/:tenant_id/exports
//
// Responses:
//
//	200 – list of ExportResult (may be empty)
//	400 – invalid tenant_id
//	500 – listing failed
func (h *TenantDataExportHandler) ListExports(c *gin.Context) {
	tenantID, ok := parseTenantIDParam(c)
	if !ok {
		return
	}

	results, err := h.svc.ListExports(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if results == nil {
		results = []services.ExportResult{}
	}

	c.JSON(http.StatusOK, gin.H{"exports": results, "count": len(results)})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// parseTenantIDParam extracts and validates the :tenant_id path parameter.
// It writes a 400 response and returns (uuid.Nil, false) on failure.
func parseTenantIDParam(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("tenant_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id: " + err.Error()})
		return uuid.Nil, false
	}
	return id, true
}
