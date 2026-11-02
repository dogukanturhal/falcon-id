// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// RoleTemplateHandler serves GET /api/v1/role-templates and
// POST /api/v1/role-templates/{key}/instantiate (the product roadmap §4.1).
type RoleTemplateHandler struct {
	roleTemplateService *services.RoleTemplateService
}

// NewRoleTemplateHandler creates a new RoleTemplateHandler.
func NewRoleTemplateHandler(roleTemplateService *services.RoleTemplateService) *RoleTemplateHandler {
	return &RoleTemplateHandler{roleTemplateService: roleTemplateService}
}

// List returns the latest active version of every role template belonging
// to a module the caller's tenant is entitled to.
// @Summary List Role Templates
// @Description List role templates available to the caller's tenant
// @Tags RoleTemplates
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.RoleTemplateListResponse
// @Failure 401 {object} map[string]string
// @Router /api/v1/role-templates [get]
func (h *RoleTemplateHandler) List(c *gin.Context) {
	// SECURITY: tenant comes only from the validated JWT, never a client-
	// supplied header/param.
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context is required"})
		return
	}

	result, err := h.roleTemplateService.ListForTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}
	c.JSON(http.StatusOK, result)
}

// Instantiate creates a tenant role from a role template.
// @Summary Instantiate Role Template
// @Description Create a tenant role from a role template (tenant admin only)
// @Tags RoleTemplates
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param key path string true "Role template key"
// @Param body body models.InstantiateRoleTemplateRequest false "Optional overrides"
// @Success 201 {object} models.InstantiateRoleTemplateResponse
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/v1/role-templates/{key}/instantiate [post]
func (h *RoleTemplateHandler) Instantiate(c *gin.Context) {
	if rejectIfImpersonated(c) {
		return
	}

	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role template key is required"})
		return
	}

	var req models.InstantiateRoleTemplateRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// SECURITY: tenant comes only from the validated JWT (RequireAuth +
	// RequirePermission upstream already established this is a
	// tenant-scoped admin caller); never accept a tenant_id from the
	// request body/headers here.
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context is required"})
		return
	}
	currentUserID := middleware.GetCurrentUserID(c)

	result, err := h.roleTemplateService.Instantiate(c.Request.Context(), tenantID, key, &req, currentUserID)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": errMsg})
			return
		}
		if strings.Contains(errMsg, "not entitled") {
			c.JSON(http.StatusForbidden, gin.H{"error": errMsg})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}

	c.JSON(http.StatusCreated, result)
}

// internalRevokeModuleRequest is the body for
// POST /internal/v1/role-templates/revoke.
type internalRevokeModuleRequest struct {
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
	Module   string    `json:"module" binding:"required"`
}

// RevokeModule disables every template-derived role for a tenant under a
// module. Internal, service-to-service only (behind serviceAuthMiddleware.
// ServiceAuth(), same as every other /internal/v1 route — see
// cmd/routes_admin.go) — trusted callers supply tenant_id/module directly in
// the body, unlike the tenant-facing routes above which never accept a
// caller-supplied tenant.
//
// Documented trigger: falcon-id has no existing Kafka event for "module
// revoked/deactivated/subscription cancelled" (only
// example.tenant.subscription.activated exists, consumed by
// ProvisioningConsumer for the grant side). This endpoint is the fallback
// the task spec calls for pending such an event; whatever billing/
// entitlement change eventually needs to disable a tenant's template-derived
// roles calls this route.
// @Summary Revoke Role-Template-Derived Roles For A Module
// @Description Disable every template-derived role a tenant holds for a module (internal, service-to-service)
// @Tags RoleTemplates
// @Accept json
// @Produce json
// @Success 200 {object} map[string]int
// @Failure 400 {object} map[string]string
// @Router /internal/v1/role-templates/revoke [post]
func (h *RoleTemplateHandler) RevokeModule(c *gin.Context) {
	var req internalRevokeModuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	disabled, err := h.roleTemplateService.RevokeModule(c.Request.Context(), req.TenantID, req.Module)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPermInternalError})
		return
	}
	c.JSON(http.StatusOK, gin.H{"disabled": disabled})
}
