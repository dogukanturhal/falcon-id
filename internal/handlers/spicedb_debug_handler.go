// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

const (
	msgSpiceDBInvalidUserID = "invalid user_id"
)

// SpiceDBDebugHandler provides debug and diagnostic endpoints for SpiceDB
// authorization. All endpoints require platform_admin role.
type SpiceDBDebugHandler struct {
	authzEngine     services.AuthorizationEngine
	reconciler      *services.SpiceDBReconciler
	permResolver    *spicedb.PermissionResolver
	tenantBootstrap *services.TenantBootstrapService
}

// NewSpiceDBDebugHandler creates a new SpiceDB debug handler.
func NewSpiceDBDebugHandler(
	authzEngine services.AuthorizationEngine,
	reconciler *services.SpiceDBReconciler,
	permResolver *spicedb.PermissionResolver,
	tenantBootstrap *services.TenantBootstrapService,
) *SpiceDBDebugHandler {
	return &SpiceDBDebugHandler{
		authzEngine:     authzEngine,
		reconciler:      reconciler,
		permResolver:    permResolver,
		tenantBootstrap: tenantBootstrap,
	}
}

// --- Request / Response types ---

// DebugPermissionRequest is the request body for the permission debug endpoint.
type DebugPermissionRequest struct {
	UserID     string `json:"user_id" binding:"required"`
	TenantID   string `json:"tenant_id" binding:"required"`
	Permission string `json:"permission" binding:"required"`
	ZedToken   string `json:"zed_token,omitempty"`
}

// DebugPermissionResponse is the response from the permission debug endpoint.
type DebugPermissionResponse struct {
	UserID     string `json:"user_id"`
	TenantID   string `json:"tenant_id"`
	Permission string `json:"permission"`
	Allowed    bool   `json:"allowed"`
	Source     string `json:"source"`
	Error      string `json:"error,omitempty"`
}

// BulkAssignRequest is the request body for the bulk assignment endpoint.
type BulkAssignRequest struct {
	TenantID    string           `json:"tenant_id" binding:"required"`
	Assignments []AssignmentItem `json:"assignments" binding:"required,min=1,max=100"`
}

// AssignmentItem represents a single role-user or role-permission assignment.
type AssignmentItem struct {
	Type       string `json:"type" binding:"required,oneof=user_role role_permission user_tenant"`
	UserID     string `json:"user_id,omitempty"`
	RoleID     string `json:"role_id,omitempty"`
	Permission string `json:"permission,omitempty"`
	Relation   string `json:"relation,omitempty"`
}

// BulkAssignResponse is the response from the bulk assignment endpoint.
type BulkAssignResponse struct {
	TenantID  string             `json:"tenant_id"`
	Total     int                `json:"total"`
	Succeeded int                `json:"succeeded"`
	Failed    int                `json:"failed"`
	Results   []AssignmentResult `json:"results"`
}

// AssignmentResult is the result of a single assignment operation.
type AssignmentResult struct {
	Index    int    `json:"index"`
	Type     string `json:"type"`
	Success  bool   `json:"success"`
	ZedToken string `json:"zed_token,omitempty"`
	Error    string `json:"error,omitempty"`
}

// EffectivePermissionsRequest is the request for the effective permissions endpoint.
type EffectivePermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required,min=1,max=1000"`
}

// EffectivePermissionsResponse is the response from the effective permissions endpoint.
type EffectivePermissionsResponse struct {
	UserID      string          `json:"user_id"`
	TenantID    string          `json:"tenant_id"`
	Permissions map[string]bool `json:"permissions"`
}

// --- Handler methods ---

// DebugPermission checks a single permission against SpiceDB and returns
// detailed diagnostic information. This endpoint is intended for admin
// troubleshooting, not for application authorization checks.
func (h *SpiceDBDebugHandler) DebugPermission(c *gin.Context) {
	var req DebugPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSpiceDBInvalidUserID})
		return
	}

	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	resp := DebugPermissionResponse{
		UserID:     req.UserID,
		TenantID:   req.TenantID,
		Permission: req.Permission,
		Source:     "spicedb",
	}

	if h.authzEngine == nil {
		resp.Error = "authorization engine not initialized"
		c.JSON(http.StatusServiceUnavailable, resp)
		return
	}

	// Use the authorization engine to check the permission
	permReq := services.PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: req.Permission,
	}

	if req.ZedToken != "" {
		permReq.ZedToken = req.ZedToken
	}

	result, err := h.authzEngine.CheckPermission(c.Request.Context(), permReq)
	if err != nil {
		resp.Error = err.Error()
		c.JSON(http.StatusOK, resp)
		return
	}

	resp.Allowed = result.Allowed
	resp.Source = result.Source
	c.JSON(http.StatusOK, resp)
}

// GetReconcilerStatus returns the current status and last run stats of the
// SpiceDB reconciler.
func (h *SpiceDBDebugHandler) GetReconcilerStatus(c *gin.Context) {
	if h.reconciler == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciler not initialized"})
		return
	}

	stats := h.reconciler.Stats()
	c.JSON(http.StatusOK, gin.H{
		"tenants_processed":       stats.TenantsProcessed,
		"user_tenant_repairs":     stats.UserTenantRepairs,
		"user_role_repairs":       stats.UserRoleRepairs,
		"role_permission_repairs": stats.RolePermissionRepairs,
		"errors":                  stats.Errors,
		"started_at":              stats.StartedAt,
		"completed_at":            stats.CompletedAt,
	})
}

// TriggerReconciliation triggers an ad-hoc SpiceDB reconciliation pass.
func (h *SpiceDBDebugHandler) TriggerReconciliation(c *gin.Context) {
	if h.reconciler == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "reconciler not initialized"})
		return
	}

	stats, err := h.reconciler.Reconcile(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":                 "reconciliation completed",
		"tenants_processed":       stats.TenantsProcessed,
		"user_tenant_repairs":     stats.UserTenantRepairs,
		"user_role_repairs":       stats.UserRoleRepairs,
		"role_permission_repairs": stats.RolePermissionRepairs,
		"errors":                  stats.Errors,
		"started_at":              stats.StartedAt,
		"completed_at":            stats.CompletedAt,
	})
}

// GetEffectivePermissions resolves the effective permissions for a user from
// SpiceDB by batch-checking a supplied list of permissions. This is used by the
// frontend to render permission-aware UI.
func (h *SpiceDBDebugHandler) GetEffectivePermissions(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req EffectivePermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.authzEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authorization engine not initialized"})
		return
	}

	results, err := h.authzEngine.BatchCheckPermissions(c.Request.Context(), userID, currentUser.TenantID, req.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "permission check failed"})
		return
	}

	c.JSON(http.StatusOK, EffectivePermissionsResponse{
		UserID:      userID.String(),
		TenantID:    currentUser.TenantID.String(),
		Permissions: results,
	})
}

// BulkAssign writes multiple SpiceDB relationships in a single request. Each
// assignment is processed independently — individual failures do not abort the
// remaining writes.
func (h *SpiceDBDebugHandler) BulkAssign(c *gin.Context) {
	var req BulkAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}

	if h.tenantBootstrap == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tenant bootstrap service not initialized"})
		return
	}

	resp := BulkAssignResponse{
		TenantID: req.TenantID,
		Total:    len(req.Assignments),
		Results:  make([]AssignmentResult, len(req.Assignments)),
	}

	ctx := c.Request.Context()

	for i, item := range req.Assignments {
		result := AssignmentResult{
			Index: i,
			Type:  item.Type,
		}

		switch item.Type {
		case "user_role":
			result = h.processUserRoleAssignment(ctx, tenantID, item, i)
		case "role_permission":
			result = h.processRolePermissionAssignment(ctx, tenantID, item, i)
		case "user_tenant":
			result = h.processUserTenantAssignment(ctx, tenantID, item, i)
		default:
			result.Error = "unknown assignment type"
		}

		resp.Results[i] = result
		if result.Success {
			resp.Succeeded++
		} else {
			resp.Failed++
		}
	}

	c.JSON(http.StatusOK, resp)
}

func (h *SpiceDBDebugHandler) processUserRoleAssignment(ctx context.Context, tenantID uuid.UUID, item AssignmentItem, index int) AssignmentResult {
	result := AssignmentResult{Index: index, Type: item.Type}

	userID, err := uuid.Parse(item.UserID)
	if err != nil {
		result.Error = msgSpiceDBInvalidUserID
		return result
	}

	roleID, err := uuid.Parse(item.RoleID)
	if err != nil {
		result.Error = "invalid role_id"
		return result
	}

	token, err := h.tenantBootstrap.BootstrapUserRole(ctx, tenantID, userID, roleID)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.ZedToken = token
	return result
}

func (h *SpiceDBDebugHandler) processRolePermissionAssignment(ctx context.Context, tenantID uuid.UUID, item AssignmentItem, index int) AssignmentResult {
	result := AssignmentResult{Index: index, Type: item.Type}

	roleID, err := uuid.Parse(item.RoleID)
	if err != nil {
		result.Error = "invalid role_id"
		return result
	}

	if item.Permission == "" {
		result.Error = "permission is required for role_permission assignments"
		return result
	}

	bootstrapResult, err := h.tenantBootstrap.BootstrapRolePermissions(ctx, tenantID, roleID, []string{item.Permission})
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if len(bootstrapResult.Errors) > 0 {
		result.Error = bootstrapResult.Errors[0].Error()
		return result
	}

	result.Success = true
	result.ZedToken = bootstrapResult.LastZedToken
	return result
}

func (h *SpiceDBDebugHandler) processUserTenantAssignment(ctx context.Context, tenantID uuid.UUID, item AssignmentItem, index int) AssignmentResult {
	result := AssignmentResult{Index: index, Type: item.Type}

	userID, err := uuid.Parse(item.UserID)
	if err != nil {
		result.Error = msgSpiceDBInvalidUserID
		return result
	}

	isAdmin := item.Relation == "admin"
	token, err := h.tenantBootstrap.BootstrapUserMembership(ctx, tenantID, userID, isAdmin)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.ZedToken = token
	return result
}
