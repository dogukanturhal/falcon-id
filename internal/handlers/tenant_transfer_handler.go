// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TenantTransferHandler is the API surface for consumer→business
// tenant-transfer requests. STUB ONLY — every endpoint returns 501
// Not Implemented + a descriptive body pointing at the ENT-6 spec.
//
// Why register the routes now: frontend (accounts.example.com) needs
// a stable URL surface to mock against for the UX iteration that
// shows consumer-tenant users a "Move to a business account" banner.
// Without registered routes, the BFF proxy would 404 every probe
// and the frontend would have to fake the integration.
//
// Real implementation surface lands in ENT-6 Phase 2; see the model
// docstring in internal/models/tenant_transfer.go.
type TenantTransferHandler struct {
	logger *zap.Logger
}

// NewTenantTransferHandler constructs the stub handler.
func NewTenantTransferHandler(logger *zap.Logger) *TenantTransferHandler {
	return &TenantTransferHandler{logger: logger}
}

// Create handles POST /api/v1/admin/tenant-transfers.
//
// @Summary Create a tenant-transfer request (consumer→business)
// @Description STUB — returns 501. Real implementation in ENT-6 Phase 2.
// @Tags Tenant Transfer
// @Accept json
// @Produce json
// @Param body body models.CreateTenantTransferRequest true "Transfer request"
// @Success 201 {object} models.TenantTransferRequest
// @Failure 400 {object} map[string]string
// @Failure 501 {object} map[string]string "Not yet implemented (ENT-6 Phase 2)"
// @Router /api/v1/admin/tenant-transfers [post]
func (h *TenantTransferHandler) Create(c *gin.Context) {
	var req models.CreateTenantTransferRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Body parsed cleanly — surface the input in the 501 so
	// callers can verify their request shape was correct.
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "tenant-transfer not yet implemented (ENT-6 Phase 2)",
		"echo":    req,
		"tracker": "docs/operator-runbooks/ent6-tenant-transfer-procedure.md (pending)",
	})
}

// List handles GET /api/v1/admin/tenant-transfers.
//
// @Summary List tenant-transfer requests
// @Description STUB — returns empty list with 200. Real implementation in ENT-6 Phase 2.
// @Tags Tenant Transfer
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/admin/tenant-transfers [get]
func (h *TenantTransferHandler) List(c *gin.Context) {
	// Return empty list with 200 (NOT 501) so the frontend can
	// safely call this on page-load without surfacing an error.
	// When real implementation lands the structure will populate.
	c.JSON(http.StatusOK, gin.H{
		"transfers": []models.TenantTransferRequest{},
		"total":     0,
		"note":      "ENT-6 Phase 2 not yet implemented — list always empty",
	})
}

// Approve handles POST /api/v1/admin/tenant-transfers/:id/approve.
//
// @Summary Approve a tenant-transfer request
// @Description STUB — returns 501. Real implementation in ENT-6 Phase 2.
// @Tags Tenant Transfer
// @Param id path string true "Transfer request UUID"
// @Success 200 {object} models.TenantTransferRequest
// @Failure 501 {object} map[string]string
// @Router /api/v1/admin/tenant-transfers/{id}/approve [post]
func (h *TenantTransferHandler) Approve(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "tenant-transfer approve not yet implemented (ENT-6 Phase 2)",
		"id":      c.Param("id"),
		"tracker": "docs/operator-runbooks/ent6-tenant-transfer-procedure.md (pending)",
	})
}

// Reject handles POST /api/v1/admin/tenant-transfers/:id/reject.
//
// @Summary Reject a tenant-transfer request
// @Description STUB — returns 501. Real implementation in ENT-6 Phase 2.
// @Tags Tenant Transfer
// @Param id path string true "Transfer request UUID"
// @Success 200 {object} models.TenantTransferRequest
// @Failure 501 {object} map[string]string
// @Router /api/v1/admin/tenant-transfers/{id}/reject [post]
func (h *TenantTransferHandler) Reject(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "tenant-transfer reject not yet implemented (ENT-6 Phase 2)",
		"id":      c.Param("id"),
		"tracker": "docs/operator-runbooks/ent6-tenant-transfer-procedure.md (pending)",
	})
}
