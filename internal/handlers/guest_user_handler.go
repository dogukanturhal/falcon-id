// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgInvalidGuestID = "invalid guest ID"
)

// GuestUserHandler handles B2B guest user management endpoints.
type GuestUserHandler struct {
	service *services.GuestUserService
}

// NewGuestUserHandler constructs a GuestUserHandler.
func NewGuestUserHandler(service *services.GuestUserService) *GuestUserHandler {
	return &GuestUserHandler{service: service}
}

// InviteGuest creates a new cross-tenant guest invitation.
//
// @Summary Invite guest user
// @Description Creates a new B2B cross-tenant guest invitation and sends an invite email
// @Tags Guest Users
// @Accept json
// @Produce json
// @Param request body models.InviteGuestRequest true "Guest invitation details"
// @Success 201 {object} map[string]interface{} "Guest invitation created"
// @Failure 400 {object} map[string]string "Validation error or invitation failed"
// @Failure 401 {object} map[string]string "Not authenticated or missing tenant context"
// @Router /api/v1/admin/guests/invite [post]
func (h *GuestUserHandler) InviteGuest(c *gin.Context) {
	var req models.InviteGuestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	hostTenantID, invitedBy, ok := h.tenantAndActor(c)
	if !ok {
		return
	}

	resp, err := h.service.InviteGuest(c.Request.Context(), hostTenantID, &req, invitedBy)
	if err != nil {
		logger.Error("GuestUserHandler.InviteGuest: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": resp})
}

// ListGuests returns a paginated list of guests for the current tenant.
//
// @Summary List guest users
// @Description Returns a paginated list of B2B guest users for the current tenant
// @Tags Guest Users
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param email query string false "Filter by email address"
// @Param status query string false "Filter by status (pending, active, revoked)"
// @Success 200 {object} map[string]interface{} "Paginated list of guest users"
// @Failure 401 {object} map[string]string "Not authenticated or missing tenant context"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/guests [get]
func (h *GuestUserHandler) ListGuests(c *gin.Context) {
	hostTenantID, _, ok := h.tenantAndActor(c)
	if !ok {
		return
	}

	filter := models.GuestUserListFilter{
		Page:     queryInt(c, "page", 1),
		PageSize: queryInt(c, "page_size", 20),
		Email:    c.Query("email"),
	}
	if s := c.Query("status"); s != "" {
		st := models.GuestUserStatus(s)
		filter.Status = &st
	}

	resp, err := h.service.ListGuests(c.Request.Context(), hostTenantID, filter)
	if err != nil {
		logger.Error("GuestUserHandler.ListGuests: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list guests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// GetGuest retrieves a single guest user.
//
// @Summary Get guest user
// @Description Retrieves a single B2B guest user record by ID
// @Tags Guest Users
// @Produce json
// @Param id path string true "Guest user UUID"
// @Success 200 {object} map[string]interface{} "Guest user details"
// @Failure 400 {object} map[string]string "Invalid guest ID"
// @Failure 404 {object} map[string]string "Guest not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/guests/{id} [get]
func (h *GuestUserHandler) GetGuest(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgInvalidGuestID})
		return
	}

	resp, err := h.service.GetGuest(c.Request.Context(), id)
	if err != nil {
		logger.Error("GuestUserHandler.GetGuest: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to get guest"})
		return
	}
	if resp == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "guest not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// UpdateGuest modifies a guest user record.
//
// @Summary Update guest user
// @Description Modifies an existing guest user record
// @Tags Guest Users
// @Accept json
// @Produce json
// @Param id path string true "Guest user UUID"
// @Param request body models.UpdateGuestRequest true "Fields to update"
// @Success 200 {object} map[string]interface{} "Updated guest user"
// @Failure 400 {object} map[string]string "Invalid guest ID, validation error, or update failed"
// @Router /api/v1/admin/guests/{id} [put]
func (h *GuestUserHandler) UpdateGuest(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgInvalidGuestID})
		return
	}

	var req models.UpdateGuestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	resp, err := h.service.UpdateGuest(c.Request.Context(), id, &req)
	if err != nil {
		logger.Error("GuestUserHandler.UpdateGuest: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// DeleteGuest revokes and removes a guest user.
//
// @Summary Delete guest user
// @Description Revokes and removes a B2B guest user, terminating all their access to the tenant
// @Tags Guest Users
// @Produce json
// @Param id path string true "Guest user UUID"
// @Success 200 {object} map[string]string "Guest revoked"
// @Failure 400 {object} map[string]string "Invalid guest ID or revocation failed"
// @Router /api/v1/admin/guests/{id} [delete]
func (h *GuestUserHandler) DeleteGuest(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgInvalidGuestID})
		return
	}

	if err := h.service.RevokeGuest(c.Request.Context(), id); err != nil {
		logger.Error("GuestUserHandler.DeleteGuest: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "guest revoked"})
}

// ResendInvitation re-sends a pending guest invitation.
//
// @Summary Resend guest invitation
// @Description Re-sends the invitation email for a pending guest user
// @Tags Guest Users
// @Produce json
// @Param id path string true "Guest user UUID"
// @Success 200 {object} map[string]interface{} "Invitation resent"
// @Failure 400 {object} map[string]string "Invalid guest ID or resend failed"
// @Router /api/v1/admin/guests/{id}/resend [post]
func (h *GuestUserHandler) ResendInvitation(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgInvalidGuestID})
		return
	}

	resp, err := h.service.ResendInvitation(c.Request.Context(), id)
	if err != nil {
		logger.Error("GuestUserHandler.ResendInvitation: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// SetRoles replaces the role set for a guest user.
//
// @Summary Set guest user roles
// @Description Replaces the entire role set for a B2B guest user
// @Tags Guest Users
// @Accept json
// @Produce json
// @Param id path string true "Guest user UUID"
// @Param request body models.SetGuestRolesRequest true "Role IDs to assign"
// @Success 200 {object} map[string]string "Roles updated"
// @Failure 400 {object} map[string]string "Invalid guest ID, validation error, or role assignment failed"
// @Failure 401 {object} map[string]string "Not authenticated or missing tenant context"
// @Router /api/v1/admin/guests/{id}/roles [put]
func (h *GuestUserHandler) SetRoles(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgInvalidGuestID})
		return
	}

	var req models.SetGuestRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	hostTenantID, assignedBy, ok := h.tenantAndActor(c)
	if !ok {
		return
	}

	if err := h.service.SetRoles(c.Request.Context(), hostTenantID, id, &req, assignedBy); err != nil {
		logger.Error("GuestUserHandler.SetRoles: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "roles updated"})
}

// ==================== helpers ====================

// tenantAndActor extracts the host tenant ID and actor user ID from Gin context.
// Returns false and writes an error response when extraction fails.
func (h *GuestUserHandler) tenantAndActor(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID := GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "missing tenant context"})
		return uuid.Nil, uuid.Nil, false
	}
	actorID := extractActorID(c)
	return tenantID, actorID, true
}
