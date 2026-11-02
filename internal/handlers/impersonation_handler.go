// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgImpersonationInternalError    = "An internal error occurred"
	msgImpersonationSessionNotFound  = "Impersonation session not found"
	msgImpersonationTenantIDNotFound = "Tenant ID not found in context"
)

// ImpersonationHandler handles impersonation-related HTTP requests
type ImpersonationHandler struct {
	impersonationService *services.ImpersonationService
}

// NewImpersonationHandler creates a new ImpersonationHandler
func NewImpersonationHandler(impersonationService *services.ImpersonationService) *ImpersonationHandler {
	return &ImpersonationHandler{
		impersonationService: impersonationService,
	}
}

// StartImpersonation handles POST /api/admin/users/:id/impersonate
func (h *ImpersonationHandler) StartImpersonation(c *gin.Context) {
	// Get admin user ID from context (the one initiating impersonation)
	adminUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get target user ID from URL
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Parse request body
	var req models.StartImpersonationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get original session ID if available
	var originalSessionID *uuid.UUID
	if sessionID, exists := c.Get("session_id"); exists {
		if sid, ok := sessionID.(uuid.UUID); ok {
			originalSessionID = &sid
		}
	}

	// Get client info
	ipAddress := GetClientIP(c)
	userAgent := c.Request.UserAgent()

	adminUID, ok := adminUserID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgImpersonationInternalError})
		return
	}

	// Start impersonation
	response, err := h.impersonationService.StartImpersonation(
		c.Request.Context(),
		adminUID,
		targetUserID,
		req.Reason,
		ipAddress,
		userAgent,
		originalSessionID,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// EndImpersonation handles POST /api/auth/impersonation/end
func (h *ImpersonationHandler) EndImpersonation(c *gin.Context) {
	// Get impersonator ID from token claims
	impersonatorID, exists := c.Get("impersonator_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not currently impersonating"})
		return
	}

	// Get impersonation session ID from token claims
	impersonationSessionID, exists := c.Get("impersonation_session_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgImpersonationSessionNotFound})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.Request.UserAgent()

	impSessionID, ok := impersonationSessionID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgImpersonationInternalError})
		return
	}
	impersonatorUID, ok := impersonatorID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgImpersonationInternalError})
		return
	}

	// End impersonation
	if err := h.impersonationService.EndImpersonation(
		c.Request.Context(),
		impSessionID,
		impersonatorUID,
		ipAddress,
		userAgent,
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Impersonation ended successfully",
	})
}

// GetImpersonationStatus handles GET /api/auth/impersonation/status
func (h *ImpersonationHandler) GetImpersonationStatus(c *gin.Context) {
	// Get impersonation info from context (set by auth middleware)
	var impersonatorID, impersonationSessionID *uuid.UUID

	if id, exists := c.Get("impersonator_id"); exists {
		if uid, ok := id.(uuid.UUID); ok {
			impersonatorID = &uid
		}
	}

	if id, exists := c.Get("impersonation_session_id"); exists {
		if uid, ok := id.(uuid.UUID); ok {
			impersonationSessionID = &uid
		}
	}

	status, err := h.impersonationService.GetImpersonationStatus(
		c.Request.Context(),
		impersonatorID,
		impersonationSessionID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgImpersonationInternalError})
		return
	}

	c.JSON(http.StatusOK, status)
}

// ListImpersonationSessions handles GET /api/admin/impersonation-sessions
func (h *ImpersonationHandler) ListImpersonationSessions(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgImpersonationTenantIDNotFound})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	activeOnly := c.Query("active_only") == queryBoolTrue

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Optional filters
	var adminUserID, targetUserID *uuid.UUID
	if adminID := c.Query("admin_user_id"); adminID != "" {
		if parsed, err := uuid.Parse(adminID); err == nil {
			adminUserID = &parsed
		}
	}
	if targetID := c.Query("target_user_id"); targetID != "" {
		if parsed, err := uuid.Parse(targetID); err == nil {
			targetUserID = &parsed
		}
	}

	tenantUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgImpersonationInternalError})
		return
	}
	response, err := h.impersonationService.ListImpersonationSessions(
		c.Request.Context(),
		tenantUID,
		page,
		pageSize,
		adminUserID,
		targetUserID,
		activeOnly,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgImpersonationInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetImpersonationSession handles GET /api/admin/impersonation-sessions/:id
func (h *ImpersonationHandler) GetImpersonationSession(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgImpersonationTenantIDNotFound})
		return
	}

	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	session, err := h.impersonationService.GetImpersonationSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgImpersonationSessionNotFound})
		return
	}

	// Verify the impersonation session belongs to the current tenant
	tenantUID, ok := tenantID.(uuid.UUID)
	if !ok || session.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgImpersonationSessionNotFound})
		return
	}

	c.JSON(http.StatusOK, session)
}

// EndImpersonationByAdmin handles POST /api/admin/impersonation-sessions/:id/end
// Allows admin to forcefully end any impersonation session
func (h *ImpersonationHandler) EndImpersonationByAdmin(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgImpersonationTenantIDNotFound})
		return
	}

	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	// Get the session to find admin user ID
	session, err := h.impersonationService.GetImpersonationSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgImpersonationSessionNotFound})
		return
	}

	// Verify the impersonation session belongs to the current tenant
	tenantUID, ok := tenantID.(uuid.UUID)
	if !ok || session.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgImpersonationSessionNotFound})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.Request.UserAgent()

	// End impersonation using the session's admin user ID
	if err := h.impersonationService.EndImpersonation(
		c.Request.Context(),
		sessionID,
		session.AdminUserID,
		ipAddress,
		userAgent,
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Impersonation session ended successfully",
	})
}

// GetActiveImpersonation handles GET /api/admin/users/:id/impersonation
// Gets the active impersonation for an admin user
func (h *ImpersonationHandler) GetActiveImpersonation(c *gin.Context) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgImpersonationTenantIDNotFound})
		return
	}

	adminUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	session, err := h.impersonationService.GetActiveImpersonation(c.Request.Context(), adminUserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active impersonation found"})
		return
	}

	// Verify the impersonation session belongs to the current tenant
	tenantUID, ok := tenantID.(uuid.UUID)
	if !ok || session.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active impersonation found"})
		return
	}

	c.JSON(http.StatusOK, session)
}

// SessionTenantID returns the tenant of an impersonation session. The
// operator-chain wrappers use it to scope the tenant-bound handlers above to
// the session's own tenant.
func (h *ImpersonationHandler) SessionTenantID(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error) {
	session, err := h.impersonationService.GetImpersonationSession(ctx, sessionID)
	if err != nil {
		return uuid.Nil, err
	}
	return session.TenantID, nil
}
