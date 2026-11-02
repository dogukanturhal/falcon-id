// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgSoDInvalidRuleID = "Invalid rule ID"
	msgSoDRuleNotFound  = "SoD rule not found"
)

// SoDHandler serves both the internal (ServiceAuth-gated) SoD evaluation
// endpoint and the BFF-facing (tenant-admin gated) SoD rule/violation
// surface. See 23-authorization-rbac-abac-rebac.md §5.2/§8.3 and
// 17-module-account.md §12/§5.1-§5.2.
type SoDHandler struct {
	sodService *services.SoDService
}

// NewSoDHandler is an exported function.
func NewSoDHandler(sodService *services.SoDService) *SoDHandler {
	return &SoDHandler{sodService: sodService}
}

// Evaluate handles POST /internal/v1/sod/evaluate. ServiceAuth-gated
// (see cmd/routes_admin.go); the tenant/user being evaluated is named
// explicitly in the request body, not derived from X-Tenant-ID — see the
// /internal/v1/sod/ exemption comment in internal/middleware/tenant.go.
func (h *SoDHandler) Evaluate(c *gin.Context) {
	var req models.EvaluateSoDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	violations, err := h.sodService.EvaluateUser(c.Request.Context(), req.TenantID, req.UserID, req.RoleIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}
	if violations == nil {
		violations = []models.SoDViolation{}
	}

	c.JSON(http.StatusOK, models.EvaluateSoDResponse{
		TenantID:   req.TenantID,
		UserID:     req.UserID,
		Violations: violations,
	})
}

// ListRules handles GET /api/v1/account/sod-rules. Tenant-admin gated
// (account:sod:manage, checked by the route's RequirePermission
// middleware); tenant is sourced from the session JWT.
func (h *SoDHandler) ListRules(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
		return
	}

	rules, err := h.sodService.ListRulesForTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}
	if rules == nil {
		rules = []models.SoDRule{}
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// CreateRule handles POST /api/v1/account/sod-rules.
func (h *SoDHandler) CreateRule(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
		return
	}

	var req models.CreateSoDRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	createdBy := middleware.GetCurrentUserID(c)

	rule, err := h.sodService.CreateRule(c.Request.Context(), tenantID, &req, createdBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// UpdateRule handles PATCH /api/v1/account/sod-rules/:id.
func (h *SoDHandler) UpdateRule(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
		return
	}

	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSoDInvalidRuleID})
		return
	}

	var req models.UpdateSoDRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.sodService.UpdateRule(c.Request.Context(), tenantID, ruleID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}
	if rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgSoDRuleNotFound})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// ListViolations handles GET /api/v1/account/sod-violations.
func (h *SoDHandler) ListViolations(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant context required"})
		return
	}

	openOnly := c.DefaultQuery("open", "true") != "false"

	violations, err := h.sodService.ListViolationsForTenant(c.Request.Context(), tenantID, openOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRoleInternalError})
		return
	}
	if violations == nil {
		violations = []models.SoDViolation{}
	}

	c.JSON(http.StatusOK, gin.H{"violations": violations})
}
