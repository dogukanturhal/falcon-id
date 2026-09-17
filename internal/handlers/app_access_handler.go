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
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// AppAccessHandler handles app access control admin endpoints.
type AppAccessHandler struct {
	service *services.AppAccessService
	logger  *zap.Logger
}

// NewAppAccessHandler creates a new AppAccessHandler.
func NewAppAccessHandler(service *services.AppAccessService, logger *zap.Logger) *AppAccessHandler {
	return &AppAccessHandler{
		service: service,
		logger:  logger,
	}
}

// AssignRole assigns a role to a user for an application.
//
// @Summary Assign app role
// @Description Assigns a role to a user for the specified application
// @Tags App Access Control
// @Accept json
// @Produce json
// @Param client_id path string true "OAuth client ID or UUID"
// @Param request body models.CreateAppRoleAssignmentRequest true "Role assignment details"
// @Success 201 {object} map[string]string "Role assigned successfully"
// @Failure 400 {object} map[string]string "Validation error or assignment failed"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Router /api/v1/admin/apps/{client_id}/role-assignments [post]
func (h *AppAccessHandler) AssignRole(c *gin.Context) {
	clientID, err := h.service.ResolveClientID(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req models.CreateAppRoleAssignmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	var assignedBy *uuid.UUID
	if currentUser != nil {
		assignedBy = &currentUser.ID
	}

	if err := h.service.AssignRole(c.Request.Context(), clientID, &req, assignedBy); err != nil {
		h.logger.Error("Failed to assign app role", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Role assigned successfully"})
}

// RevokeRole revokes a role assignment.
//
// @Summary Revoke app role assignment
// @Description Revokes an existing role assignment by its ID
// @Tags App Access Control
// @Produce json
// @Param assignment_id path string true "Role assignment UUID"
// @Success 200 {object} map[string]string "Role revoked successfully"
// @Failure 400 {object} map[string]string "Invalid assignment ID or revocation failed"
// @Router /api/v1/admin/apps/role-assignments/{assignment_id} [delete]
func (h *AppAccessHandler) RevokeRole(c *gin.Context) {
	assignmentID, err := uuid.Parse(c.Param("assignment_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid assignment ID"})
		return
	}

	if err := h.service.RevokeRole(c.Request.Context(), assignmentID); err != nil {
		h.logger.Error("Failed to revoke app role", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role revoked successfully"})
}

// ListRoleAssignments lists role assignments for an application.
//
// @Summary List app role assignments
// @Description Returns paginated role assignments for an application
// @Tags App Access Control
// @Produce json
// @Param client_id path string true "OAuth client ID or UUID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} map[string]interface{} "Paginated list of assignments"
// @Failure 400 {object} map[string]string "Invalid client ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/apps/{client_id}/role-assignments [get]
func (h *AppAccessHandler) ListRoleAssignments(c *gin.Context) {
	clientID, err := h.service.ResolveClientID(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	assignments, total, err := h.service.ListRoleAssignments(c.Request.Context(), clientID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list role assignments"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"assignments": assignments,
		"pagination": gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// ListUserAssignments returns app role assignments for a specific user across all apps.
//
// @Summary List user app role assignments
// @Description Returns all app role assignments for a specific user across all applications
// @Tags App Access Control
// @Produce json
// @Param id path string true "User UUID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} map[string]interface{} "Paginated list of assignments"
// @Failure 400 {object} map[string]string "Invalid user ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/users/{id}/role-assignments [get]
func (h *AppAccessHandler) ListUserAssignments(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	assignments, total, err := h.service.ListUserAssignments(c.Request.Context(), userID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list user assignments", zap.Error(err), zap.String("user_id", userID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list user assignments"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"assignments": assignments,
		"pagination": gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// GetAuthPolicy returns the auth policy for an application.
//
// @Summary Get app auth policy
// @Description Returns the authentication policy for the specified application
// @Tags App Access Control
// @Produce json
// @Param client_id path string true "OAuth client ID or UUID"
// @Success 200 {object} map[string]interface{} "Auth policy"
// @Failure 400 {object} map[string]string "Invalid client ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/apps/{client_id}/auth-policy [get]
func (h *AppAccessHandler) GetAuthPolicy(c *gin.Context) {
	clientID, err := h.service.ResolveClientID(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.service.GetAuthPolicy(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get auth policy"})
		return
	}

	if policy == nil {
		c.JSON(http.StatusOK, gin.H{"policy": nil})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policy": policy})
}

// UpsertAuthPolicy creates or updates the auth policy for an application.
//
// @Summary Upsert app auth policy
// @Description Creates or updates the authentication policy for the specified application
// @Tags App Access Control
// @Accept json
// @Produce json
// @Param client_id path string true "OAuth client ID or UUID"
// @Param request body models.UpdateAppAuthPolicyRequest true "Auth policy configuration"
// @Success 200 {object} map[string]string "Auth policy updated successfully"
// @Failure 400 {object} map[string]string "Validation error or update failed"
// @Router /api/v1/admin/apps/{client_id}/auth-policy [put]
func (h *AppAccessHandler) UpsertAuthPolicy(c *gin.Context) {
	clientID, err := h.service.ResolveClientID(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req models.UpdateAppAuthPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.UpsertAuthPolicy(c.Request.Context(), clientID, &req); err != nil {
		h.logger.Error("Failed to upsert auth policy", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Auth policy updated successfully"})
}
