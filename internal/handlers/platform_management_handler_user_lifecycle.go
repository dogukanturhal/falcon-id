// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// Admin user lifecycle: soft-delete, restore, hard-delete.
//
// Authorization is entirely via authMiddleware.RequirePermission(...) at
// the route registration in cmd/routes_admin.go — deliberately no second
// in-handler currentUser.HasPermission(...) check here. That pattern was
// tried before on the Team page and broke it: CurrentUser.Permissions is
// nil for v2 SpiceDB tokens (the resolver that used to populate it is
// dead code), so an in-handler permission check silently fails closed for
// every v2-token caller regardless of their real grants. RequirePermission
// goes through the live SpiceDB check, not the possibly-nil
// CurrentUser.Permissions slice.

type softDeleteUserRequest struct {
	Reason string `json:"reason"`
}

type hardDeleteUserRequest struct {
	// ConfirmUsername must exactly equal the target user's username.
	// Irreversible action — the caller must state, in the request body,
	// exactly which account is being destroyed.
	ConfirmUsername string `json:"confirm_username" binding:"required"`
	// Force skips the "must already be soft-deleted" gate. It does NOT
	// skip the protected-tenant guard or the last-owner guard — those
	// are never skippable.
	Force  bool   `json:"force"`
	Reason string `json:"reason"`
}

// SoftDeleteTenantUser reversibly soft-deletes a user: blocks login,
// hides them from list/read, releases their tenant seat. Restorable via
// RestoreTenantUser.
// @Summary Soft-delete a tenant user (admin)
// @Tags Platform Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param body body softDeleteUserRequest false "Reason"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id}/soft-delete [post]
func (h *PlatformManagementHandler) SoftDeleteTenantUser(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidUserID})
		return
	}
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	var req softDeleteUserRequest
	_ = c.ShouldBindJSON(&req) // body is optional; reason is best-effort documentation

	_, err = h.userService.AdminSoftDeleteUser(c.Request.Context(), currentUser.ID, userID, req.Reason)
	if err != nil {
		writeUserLifecycleError(c, err)
		return
	}

	h.logPlatformAction(c, currentUser, "user_admin_soft_deleted", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
		"reason":    req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{"message": "User soft-deleted successfully"})
}

// RestoreTenantUser reverses SoftDeleteTenantUser.
// @Summary Restore a soft-deleted tenant user (admin)
// @Tags Platform Admin - Users
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id}/restore [post]
func (h *PlatformManagementHandler) RestoreTenantUser(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidUserID})
		return
	}
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	_, err = h.userService.AdminRestoreUser(c.Request.Context(), currentUser.ID, userID)
	if err != nil {
		writeUserLifecycleError(c, err)
		return
	}

	h.logPlatformAction(c, currentUser, "user_admin_restored", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
	})

	c.JSON(http.StatusOK, gin.H{"message": "User restored successfully"})
}

// HardDeleteTenantUser irreversibly erases a user row and its directly
// owned child rows. Requires ConfirmUsername to exactly echo the
// target's username, and — unless Force is set — requires the user to
// already be soft-deleted.
// @Summary Hard-delete a tenant user (admin, irreversible)
// @Tags Platform Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param body body hardDeleteUserRequest true "Confirmation"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id}/hard-delete [post]
func (h *PlatformManagementHandler) HardDeleteTenantUser(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidUserID})
		return
	}
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	var req hardDeleteUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm_username is required"})
		return
	}

	residual, err := h.userService.AdminHardDeleteUser(c.Request.Context(), currentUser.ID, userID, req.ConfirmUsername, req.Force, req.Reason)
	if err != nil {
		writeUserLifecycleError(c, err)
		return
	}

	h.logPlatformAction(c, currentUser, "user_admin_hard_deleted", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
		"force":     req.Force,
		"reason":    req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{
		"message":       "User hard-deleted successfully",
		"residual_rows": residual,
	})
}

// writeUserLifecycleError maps the admin lifecycle sentinel errors to
// specific HTTP statuses instead of collapsing everything to 400/500, so
// the caller (and the behavioural tests) can distinguish "guard refused
// this" from "target not found" from "malformed confirmation."
func writeUserLifecycleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrProtectedTenant):
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot modify a user in the protected platform tenant", "code": "protected_tenant"})
	case errors.Is(err, services.ErrLastOwner):
		c.JSON(http.StatusConflict, gin.H{"error": "cannot delete the last owner of the tenant", "code": "last_owner"})
	case errors.Is(err, services.ErrUserAlreadyDeleted):
		c.JSON(http.StatusConflict, gin.H{"error": "user is already soft-deleted", "code": "already_deleted"})
	case errors.Is(err, repositories.ErrSeatLimitReached):
		c.JSON(http.StatusConflict, gin.H{"error": "seat limit reached", "code": errCodeSeatLimitReached})
	case errors.Is(err, services.ErrUserNotSoftDeleted):
		c.JSON(http.StatusConflict, gin.H{"error": "user must be soft-deleted first (or pass force=true)", "code": "not_soft_deleted"})
	case errors.Is(err, services.ErrConfirmationMismatch):
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm_username does not match the target user's username", "code": "confirmation_mismatch"})
	case err.Error() == "user not found":
		c.JSON(http.StatusNotFound, gin.H{"error": msgPlatMgmtUserNotFound})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
	}
}
