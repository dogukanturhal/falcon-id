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
)

// Note: msgRealmInvalidRealmID and msgRealmInvalidRequestBody are defined in realm_handler.go.

const (
	msgRealmAdminInvalidDomainID = "Invalid domain ID"
)

// ==================== Admin Assignments ====================

// ListRealmAdmins lists all admin assignments for a realm
// GET /api/platform/realms/:id/admins
func (h *RealmHandler) ListRealmAdmins(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	admins, err := h.realmService.ListRealmAdmins(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list admins"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"admins": admins, "total": len(admins)})
}

// AssignRealmAdmin assigns a platform admin to a realm
// POST /api/platform/realms/:id/admins
func (h *RealmHandler) AssignRealmAdmin(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	var req models.AssignRealmAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	var createdBy *uuid.UUID
	if currentUser != nil {
		createdBy = &currentUser.ID
	}

	if err := h.realmService.AssignAdmin(c.Request.Context(), realmID, &req, createdBy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.admin.assigned", "admin", &req.AdminID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Admin assigned to realm"})
}

// RemoveRealmAdmin removes an admin from a realm
// DELETE /api/platform/realms/:id/admins/:admin_id
func (h *RealmHandler) RemoveRealmAdmin(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	adminIDStr := c.Param("admin_id")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid admin ID"})
		return
	}

	if err := h.realmService.RemoveAdmin(c.Request.Context(), realmID, adminID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.admin.removed", "admin", &adminID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Admin removed from realm"})
}

// ==================== Audit Logs ====================

// ListRealmAuditLogs lists audit logs for a realm
// GET /api/platform/realms/:id/audit-logs
func (h *RealmHandler) ListRealmAuditLogs(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	filters := parseRealmAuditLogFilters(c)

	logs, total, err := h.realmService.ListAuditLogs(c.Request.Context(), realmID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list audit logs"})
		return
	}

	totalPages := int(total) / filters.PageSize
	if int(total)%filters.PageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":        logs,
		"total":       total,
		"page":        filters.Page,
		"page_size":   filters.PageSize,
		"total_pages": totalPages,
	})
}

// parseRealmAuditLogFilters builds AuditLogFilters from query parameters.
func parseRealmAuditLogFilters(c *gin.Context) repositories.AuditLogFilters {
	filters := repositories.AuditLogFilters{Page: 1, PageSize: 50}
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			filters.Page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			filters.PageSize = v
		}
	}
	if action := c.Query("action"); action != "" {
		filters.Action = action
	}
	if category := c.Query("category"); category != "" {
		filters.ActionCategory = category
	}
	if adminIDStr := c.Query("admin_id"); adminIDStr != "" {
		if id, err := uuid.Parse(adminIDStr); err == nil {
			filters.AdminID = &id
		}
	}
	return filters
}

// ==================== Domain Management ====================

// ListRealmDomains lists all domains for a realm
// GET /api/platform/realms/:id/domains
func (h *RealmHandler) ListRealmDomains(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	domains, err := h.realmService.ListDomains(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list domains"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"domains": domains, "total": len(domains)})
}

// AddRealmDomain adds a domain to a realm
// POST /api/platform/realms/:id/domains
func (h *RealmHandler) AddRealmDomain(c *gin.Context) {
	idStr := c.Param("id")
	realmID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	var req models.AddRealmDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   msgRealmInvalidRequestBody,
			"details": err.Error(),
		})
		return
	}

	domain, err := h.realmService.AddDomain(c.Request.Context(), realmID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.domain.added", "domain", &domain.ID, nil)

	c.JSON(http.StatusCreated, domain)
}

// RemoveRealmDomain removes a domain from a realm
// DELETE /api/platform/realms/:id/domains/:domain_id
func (h *RealmHandler) RemoveRealmDomain(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	domainIDStr := c.Param("domain_id")
	domainID, err := uuid.Parse(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmAdminInvalidDomainID})
		return
	}

	if err := h.realmService.RemoveDomain(c.Request.Context(), domainID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.domain.removed", "domain", &domainID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Domain removed"})
}

// VerifyRealmDomain verifies a domain
// POST /api/platform/realms/:id/domains/:domain_id/verify
func (h *RealmHandler) VerifyRealmDomain(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	domainIDStr := c.Param("domain_id")
	domainID, err := uuid.Parse(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmAdminInvalidDomainID})
		return
	}

	domain, err := h.realmService.VerifyDomain(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.domain.verified", "domain", &domainID, nil)

	c.JSON(http.StatusOK, domain)
}

// SetPrimaryDomain sets a domain as the primary domain for a realm
// POST /api/platform/realms/:id/domains/:domain_id/primary
func (h *RealmHandler) SetPrimaryDomain(c *gin.Context) {
	realmIDStr := c.Param("id")
	realmID, err := uuid.Parse(realmIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	domainIDStr := c.Param("domain_id")
	domainID, err := uuid.Parse(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmAdminInvalidDomainID})
		return
	}

	if err := h.realmService.SetPrimaryDomain(c.Request.Context(), realmID, domainID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logAudit(c, realmID, "realm.domain.set_primary", "domain", &domainID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Domain set as primary"})
}

// ==================== User-facing Endpoints ====================

// GetAvailableRealms returns realms the current authenticated user has access to
// GET /api/realms/available
func (h *RealmHandler) GetAvailableRealms(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
		return
	}

	// Get user's primary realm from auth context (set by auth middleware / JWT)
	var primaryRealmID uuid.UUID
	if v, ok := c.Get("realm_id"); ok {
		if rid, ok := v.(uuid.UUID); ok {
			primaryRealmID = rid
		}
	}

	realms, err := h.realmService.GetUserAvailableRealms(c.Request.Context(), userID, primaryRealmID)
	if err != nil {
		h.logger.Error("Failed to get user available realms", zap.Error(err), zap.String("user_id", userID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get available realms"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"realms": realms})
}

// SwitchRealm switches the user's current realm context
// POST /api/realms/switch
func (h *RealmHandler) SwitchRealm(c *gin.Context) {
	// Get user ID from context
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
		return
	}

	var req struct {
		RealmID string `json:"realm_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRequestBody, "details": err.Error()})
		return
	}

	realmID, err := uuid.Parse(req.RealmID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRealmInvalidRealmID})
		return
	}

	// Get user's primary realm from auth context
	var primaryRealmID uuid.UUID
	if v, ok := c.Get("realm_id"); ok {
		if rid, ok := v.(uuid.UUID); ok {
			primaryRealmID = rid
		}
	}

	// Verify user has access to this realm
	hasAccess, err := h.realmService.UserHasRealmAccess(c.Request.Context(), userID, realmID, primaryRealmID)
	if err != nil {
		h.logger.Error("Failed to check realm access", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify realm access"})
		return
	}

	if !hasAccess {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this realm"})
		return
	}

	// Get realm details
	realm, err := h.realmService.GetByID(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Realm not found"})
		return
	}

	// TODO: Optionally issue a new token with updated realm context
	// For now, just return the realm info for the frontend to store

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"realm":   realm.ToResponse(),
	})
}

// GetCurrentRealm returns the current realm for the authenticated user
// GET /api/realms/current
func (h *RealmHandler) GetCurrentRealm(c *gin.Context) {
	// Get realm ID from context (set by realm middleware)
	realmIDVal, exists := c.Get("realm_id")
	if !exists {
		c.JSON(http.StatusOK, gin.H{"realm": nil, "message": "No realm context"})
		return
	}

	realmID, ok := realmIDVal.(uuid.UUID)
	if !ok || realmID == uuid.Nil {
		c.JSON(http.StatusOK, gin.H{"realm": nil, "message": "No realm context"})
		return
	}

	realm, err := h.realmService.GetByID(c.Request.Context(), realmID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Realm not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"realm": realm.ToResponse()})
}

// ==================== Helpers ====================

func (h *RealmHandler) logAudit(c *gin.Context, realmID uuid.UUID, action, targetType string, targetID, _ *uuid.UUID) {
	currentUser := middleware.GetCurrentUser(c)

	log := &models.RealmAuditLog{
		RealmID:        realmID,
		Action:         action,
		ActionCategory: stringPtr("config"),
		TargetType:     &targetType,
		TargetID:       targetID,
		RequestIP:      stringPtr(GetClientIP(c)),
		UserAgent:      stringPtr(c.Request.UserAgent()),
		RequestMethod:  stringPtr(c.Request.Method),
		RequestPath:    stringPtr(c.Request.URL.Path),
	}

	if currentUser != nil {
		log.AdminID = &currentUser.ID
		log.AdminEmail = stringPtr(currentUser.Email)
	}

	if err := h.realmService.LogAudit(c.Request.Context(), log); err != nil {
		h.logger.Error("Failed to log realm audit", zap.Error(err))
	}
}

func stringPtr(s string) *string {
	return &s
}
