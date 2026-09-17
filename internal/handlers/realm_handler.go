// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgRealmInvalidRequestBody = "Invalid request body"
	msgRealmInvalidRealmID     = "Invalid realm ID"
	msgRealmInvalidIDPID       = "Invalid identity provider ID"
)

// RealmHandler handles HTTP requests for realm management
// These endpoints are only accessible to platform admins
type RealmHandler struct {
	realmService *services.RealmService
	logger       *zap.Logger
}

// NewRealmHandler creates a new realm handler
func NewRealmHandler(realmService *services.RealmService, log *zap.Logger) *RealmHandler {
	return &RealmHandler{
		realmService: realmService,
		logger:       log,
	}
}

// ==================== Realm CRUD ====================

// CreateRealm creates a new realm
// POST /api/platform/realms
func (h *RealmHandler) CreateRealm(c *gin.Context) {
	var req models.CreateRealmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	// Get the current user who is creating this realm
	currentUser := middleware.GetCurrentUser(c)
	var createdBy *uuid.UUID
	if currentUser != nil {
		createdBy = &currentUser.ID
	}

	realm, err := h.realmService.Create(c.Request.Context(), &req, createdBy)
	if err != nil {
		h.logger.Error("Failed to create realm", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Log audit
	h.logAudit(c, realm.ID, "realm.created", "realm", &realm.ID, nil)

	c.JSON(http.StatusCreated, realm.ToResponse())
}

// GetRealm retrieves a realm by ID
// GET /api/platform/realms/:id
func (h *RealmHandler) GetRealm(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	realm, err := h.realmService.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, realm.ToResponse())
}

// ListRealms lists all realms with optional filters
// GET /api/platform/realms
func (h *RealmHandler) ListRealms(c *gin.Context) {
	filters := repositories.RealmFilters{
		Page:     1,
		PageSize: 20,
	}

	// Parse query parameters
	if page := c.Query("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filters.Page = p
		}
	}
	if pageSize := c.Query("page_size"); pageSize != "" {
		if ps, err := strconv.Atoi(pageSize); err == nil && ps > 0 && ps <= 100 {
			filters.PageSize = ps
		}
	}
	if search := c.Query("search"); search != "" {
		filters.Search = search
	}
	if realmType := c.Query("type"); realmType != "" {
		t := models.RealmType(realmType)
		filters.Type = &t
	}
	if status := c.Query("status"); status != "" {
		s := models.RealmStatus(status)
		filters.Status = &s
	}

	response, err := h.realmService.List(c.Request.Context(), filters)
	if err != nil {
		h.logger.Error("Failed to list realms", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list realms"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// UpdateRealm updates a realm
// PUT /api/platform/realms/:id
func (h *RealmHandler) UpdateRealm(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	var req models.UpdateRealmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	realm, err := h.realmService.Update(c.Request.Context(), id, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, id, "realm.updated", "realm", &id, nil)

	c.JSON(http.StatusOK, realm.ToResponse())
}

// ActivateRealm activates a suspended realm
// POST /api/platform/realms/:id/activate
func (h *RealmHandler) ActivateRealm(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	if err := h.realmService.Activate(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, id, "realm.activated", "realm", &id, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Realm activated"})
}

// SuspendRealm suspends an active realm
// POST /api/platform/realms/:id/suspend
func (h *RealmHandler) SuspendRealm(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	if err := h.realmService.Suspend(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, id, "realm.suspended", "realm", &id, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Realm suspended"})
}

// ArchiveRealm archives (soft deletes) a realm
// DELETE /api/platform/realms/:id
func (h *RealmHandler) ArchiveRealm(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	if err := h.realmService.Archive(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, id, "realm.archived", "realm", &id, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Realm archived"})
}

// ==================== Security Policy ====================

// GetSecurityPolicy retrieves the security policy for a realm
// GET /api/platform/realms/:id/security
func (h *RealmHandler) GetSecurityPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	policy, err := h.realmService.GetSecurityPolicy(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy.ToResponse())
}

// UpdateSecurityPolicy updates the security policy for a realm
// PUT /api/platform/realms/:id/security
func (h *RealmHandler) UpdateSecurityPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	var req models.UpdateRealmSecurityPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	policy, err := h.realmService.UpdateSecurityPolicy(c.Request.Context(), id, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, id, "realm.security_policy.updated", "security_policy", nil, nil)

	c.JSON(http.StatusOK, policy.ToResponse())
}

// ==================== Identity Providers ====================

// ListIdentityProviders lists identity providers for a realm
// GET /api/platform/realms/:id/identity-providers
func (h *RealmHandler) ListIdentityProviders(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	providers, err := h.realmService.ListIdentityProviders(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list identity providers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"identity_providers": providers})
}

// ListTenantIdentityProviders lists tenant-scoped IDPs for all tenants in a realm
// GET /api/v1/platform/realms/:id/tenant-identity-providers
func (h *RealmHandler) ListTenantIdentityProviders(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	providers, err := h.realmService.ListTenantIdentityProviders(c.Request.Context(), realmID)
	if err != nil {
		h.logger.Error("Failed to list tenant identity providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenant identity providers"})
		return
	}

	if providers == nil {
		providers = []models.TenantIdentityProviderSummary{}
	}

	c.JSON(http.StatusOK, gin.H{"identity_providers": providers})
}

// AddIdentityProvider adds an identity provider to a realm
// POST /api/platform/realms/:id/identity-providers
func (h *RealmHandler) AddIdentityProvider(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	var req models.CreateRealmIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	idp, err := h.realmService.AddIdentityProvider(c.Request.Context(), realmID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.identity_provider.created", "identity_provider", &idp.ID, nil)

	c.JSON(http.StatusCreated, idp)
}

// RemoveIdentityProvider removes an identity provider from a realm
// DELETE /api/platform/realms/:id/identity-providers/:idp_id
func (h *RealmHandler) RemoveIdentityProvider(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	idpIDStr := c.Param("provider_id")
	idpID, err := uuid.Parse(idpIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidIDPID})
		return
	}

	if err := h.realmService.RemoveIdentityProvider(c.Request.Context(), idpID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.identity_provider.deleted", "identity_provider", &idpID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Identity provider removed"})
}

// GetIdentityProvider gets a single identity provider by ID
// GET /api/platform/realms/:id/identity-providers/:provider_id
func (h *RealmHandler) GetIdentityProvider(c *gin.Context) {
	idpIDStr := c.Param("provider_id")
	idpID, err := uuid.Parse(idpIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidIDPID})
		return
	}

	idp, err := h.realmService.GetIdentityProvider(c.Request.Context(), idpID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, idp)
}

// UpdateIdentityProvider updates an identity provider
// PUT /api/platform/realms/:id/identity-providers/:provider_id
func (h *RealmHandler) UpdateIdentityProvider(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	idpIDStr := c.Param("provider_id")
	idpID, err := uuid.Parse(idpIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidIDPID})
		return
	}

	var req models.UpdateRealmIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	idp, err := h.realmService.UpdateIdentityProvider(c.Request.Context(), idpID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.identity_provider.updated", "identity_provider", &idpID, nil)

	c.JSON(http.StatusOK, idp)
}

// ==================== Tenant Management ====================

// ListRealmTenants lists all tenants in a realm
// GET /api/platform/realms/:id/tenants
func (h *RealmHandler) ListRealmTenants(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	tenants, err := h.realmService.ListRealmTenants(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenants": tenants, "total": len(tenants)})
}

// AssignTenantToRealm assigns a tenant to a realm
// POST /api/platform/realms/:id/tenants
func (h *RealmHandler) AssignTenantToRealm(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	var req models.AssignTenantToRealmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	var assignedBy *uuid.UUID
	if currentUser != nil {
		assignedBy = &currentUser.ID
	}

	if err := h.realmService.AssignTenant(c.Request.Context(), realmID, req.TenantID, assignedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.tenant.assigned", "tenant", &req.TenantID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Tenant assigned to realm"})
}

// RemoveTenantFromRealm removes a tenant from a realm (moves to default)
// DELETE /api/platform/realms/:id/tenants/:tenant_id
func (h *RealmHandler) RemoveTenantFromRealm(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Move tenant to default realm
	currentUser := middleware.GetCurrentUser(c)
	var assignedBy *uuid.UUID
	if currentUser != nil {
		assignedBy = &currentUser.ID
	}

	if err := h.realmService.MigrateTenant(c.Request.Context(), tenantID, models.DefaultRealmID, assignedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.tenant.removed", "tenant", &tenantID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Tenant removed from realm (moved to default)"})
}

// MigrateTenant migrates a tenant between realms
// POST /api/platform/realms/:id/tenants/:tenant_id/migrate
func (h *RealmHandler) MigrateTenant(c *gin.Context) {
	sourceRealmIDStr := c.Param("id")
	sourceRealmID, err := uuid.Parse(sourceRealmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid source realm ID"})
		return
	}

	tenantIDStr := c.Param("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var req struct {
		TargetRealmID uuid.UUID `json:"target_realm_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	var assignedBy *uuid.UUID
	if currentUser != nil {
		assignedBy = &currentUser.ID
	}

	if err := h.realmService.MigrateTenant(c.Request.Context(), tenantID, req.TargetRealmID, assignedBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, sourceRealmID, "realm.tenant.migrated", "tenant", &tenantID, &req.TargetRealmID)

	c.JSON(http.StatusOK, gin.H{
		"message":         "Tenant migrated",
		"source_realm_id": sourceRealmID,
		"target_realm_id": req.TargetRealmID,
	})
}

// Admin assignments, audit logs, domain management, user-facing endpoints,
// and helper functions are in realm_handler_admin.go
