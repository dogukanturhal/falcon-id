// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// appRoleService is the subset of AppRoleService used by AppRoleHandler.
type appRoleService interface {
	AssignRole(ctx context.Context, appID uuid.UUID, req *models.AssignAppRoleRequest, assignedBy uuid.UUID) (*models.ApplicationRoleAssignment, error)
	UnassignRole(ctx context.Context, assignmentID uuid.UUID) error
	ListAssignments(ctx context.Context, appID uuid.UUID) ([]models.ApplicationRoleAssignment, error)
	ListByPrincipal(ctx context.Context, principalType string, principalID uuid.UUID) ([]models.ApplicationRoleAssignment, error)
}

// AppRoleHandler handles HTTP endpoints for app role assignment management.
type AppRoleHandler struct {
	service appRoleService
}

// NewAppRoleHandler creates a new AppRoleHandler.
func NewAppRoleHandler(service appRoleService) *AppRoleHandler {
	return &AppRoleHandler{service: service}
}

// ListAssignments returns all role assignments for an application.
//
// @Summary List app role assignments
// @Description Returns all role assignments for an application
// @Tags App Roles
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} map[string]interface{} "List of role assignments"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/roles/assignments [get]
func (h *AppRoleHandler) ListAssignments(c *gin.Context) {
	appID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid application ID"})
		return
	}

	assignments, err := h.service.ListAssignments(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list role assignments"})
		return
	}

	if assignments == nil {
		assignments = []models.ApplicationRoleAssignment{}
	}

	c.JSON(http.StatusOK, gin.H{
		"assignments": assignments,
		"total":       len(assignments),
	})
}

// AssignRole grants an app role to a principal.
//
// @Summary Assign app role to principal
// @Description Grants an application role to a user or group (principal)
// @Tags App Roles
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.AssignAppRoleRequest true "Role assignment details"
// @Success 201 {object} models.ApplicationRoleAssignment "Created role assignment"
// @Failure 400 {object} map[string]string "Validation error, role not found, or role disabled"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 409 {object} map[string]string "Role assignment already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/roles/assignments [post]
func (h *AppRoleHandler) AssignRole(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	appID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid application ID"})
		return
	}

	var req models.AssignAppRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	assignment, err := h.service.AssignRole(c.Request.Context(), appID, &req, currentUser.ID)
	if err != nil {
		if strings.Contains(err.Error(), "not found in application") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "App role not found in application"})
			return
		}
		if strings.Contains(err.Error(), "is disabled") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "App role is disabled"})
			return
		}
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "Role assignment already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign role"})
		return
	}

	c.JSON(http.StatusCreated, assignment)
}

// UnassignRole removes an app role assignment.
//
// @Summary Unassign app role
// @Description Removes an application role assignment from a principal
// @Tags App Roles
// @Produce json
// @Param id path string true "Application UUID"
// @Param assignment_id path string true "Assignment UUID"
// @Success 204 "Role assignment removed"
// @Failure 400 {object} map[string]string "Invalid assignment ID"
// @Failure 404 {object} map[string]string "Assignment not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/roles/assignments/{assignment_id} [delete]
func (h *AppRoleHandler) UnassignRole(c *gin.Context) {
	assignmentID, err := uuid.Parse(c.Param("assignment_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid assignment ID"})
		return
	}

	if err := h.service.UnassignRole(c.Request.Context(), assignmentID); err != nil {
		if strings.Contains(err.Error(), "no rows") || strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Assignment not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unassign role"})
		return
	}

	c.Status(http.StatusNoContent)
}
