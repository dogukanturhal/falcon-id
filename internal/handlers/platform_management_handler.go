// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
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
	msgPlatMgmtNotAuthenticated = "Not authenticated"
	msgPlatMgmtInternalError    = "An internal error occurred"
	msgPlatMgmtInvalidTenantID  = "Invalid tenant ID"
	msgPlatMgmtInvalidUserID    = "Invalid user ID"
	msgPlatMgmtUserNotFound     = "User not found"
)

// PlatformManagementHandler handles platform admin management operations
// for cross-tenant user, role, and permission management
type PlatformManagementHandler struct {
	userService       *services.UserService
	roleService       *services.RoleService
	permissionService *services.PermissionService
	tenantService     *services.TenantService
	auditService      *services.AuditService
	logger            *zap.Logger
	// acmeappRoleProvisioner is optional (nil in older tests / any wiring
	// path that doesn't construct it): the role-backfill endpoint 503s rather
	// than nil-panicking when unset.
	acmeappRoleProvisioner *services.AcmeAppRoleProvisioner
	// moduleAccess is optional: the module-access reconcile endpoints 503
	// when unset. See platform_management_handler_module_access.go.
	moduleAccess moduleAccessReconciler
}

// SetModuleAccessReconciler wires the module-access provisioner used by the
// module-access reconcile endpoints.
func (h *PlatformManagementHandler) SetModuleAccessReconciler(r moduleAccessReconciler) {
	h.moduleAccess = r
}

// NewPlatformManagementHandler creates a new platform management handler
func NewPlatformManagementHandler(
	userService *services.UserService,
	roleService *services.RoleService,
	permissionService *services.PermissionService,
	tenantService *services.TenantService,
	auditService *services.AuditService,
	logger *zap.Logger,
	acmeappRoleProvisioner *services.AcmeAppRoleProvisioner,
) *PlatformManagementHandler {
	return &PlatformManagementHandler{
		userService:            userService,
		roleService:            roleService,
		permissionService:      permissionService,
		tenantService:          tenantService,
		auditService:           auditService,
		logger:                 logger,
		acmeappRoleProvisioner: acmeappRoleProvisioner,
	}
}

// ============================================================
// TENANT MANAGEMENT
// ============================================================

// ListTenants lists all tenants with pagination
// @Summary List All Tenants
// @Description List all tenants with pagination (platform admin only)
// @Tags Platform Admin - Tenants
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param status query string false "Filter by status"
// @Param type query string false "Filter by type"
// @Param search query string false "Search by name or slug"
// @Success 200 {object} models.TenantListResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/platform/tenants [get]
func (h *PlatformManagementHandler) ListTenants(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")
	tenantType := c.Query("type")
	search := c.Query("search")
	plan := c.Query("plan")

	filters := models.TenantFilters{
		Status: status,
		Type:   tenantType,
		Search: search,
		Plan:   plan,
	}

	tenants, total, err := h.tenantService.ListAll(c.Request.Context(), page, pageSize, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenants": tenants,
		"pagination": gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
		},
	})
}

// GetTenant gets a tenant by ID
// @Summary Get Tenant
// @Description Get tenant details by ID (platform admin only)
// @Tags Platform Admin - Tenants
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} models.TenantResponse
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id} [get]
func (h *PlatformManagementHandler) GetTenant(c *gin.Context) {
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

	tenant, err := h.tenantService.GetByID(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// UpdateTenant updates a tenant's details
// @Summary Update Tenant
// @Description Update tenant details (platform admin only)
// @Tags Platform Admin - Tenants
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param body body models.UpdateTenantRequest true "Tenant data"
// @Success 200 {object} models.TenantResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id} [put]
func (h *PlatformManagementHandler) UpdateTenant(c *gin.Context) {
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

	var req models.UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenant, err := h.tenantService.Update(c.Request.Context(), tenantID, &req)
	if err != nil {
		h.logger.Error("Failed to update tenant", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to update tenant"})
		return
	}

	h.logPlatformAction(c, currentUser, "tenant_updated", "tenant", &tenantID, map[string]interface{}{
		"name":   req.Name,
		"tier":   req.Tier,
		"domain": req.Domain,
	})

	c.JSON(http.StatusOK, tenant)
}

// SuspendTenant suspends a tenant
// @Summary Suspend Tenant
// @Description Suspend a tenant (platform admin only)
// @Tags Platform Admin - Tenants
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param body body models.SuspendTenantRequest true "Suspension reason"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/suspend [post]
func (h *PlatformManagementHandler) SuspendTenant(c *gin.Context) {
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

	var req models.SuspendTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.tenantService.Suspend(c.Request.Context(), tenantID, req.Reason); err != nil {
		h.logger.Error("Failed to suspend tenant", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to suspend tenant"})
		return
	}

	h.logPlatformAction(c, currentUser, "tenant_suspended", "tenant", &tenantID, map[string]interface{}{
		"reason": req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Tenant suspended successfully"})
}

// ReactivateTenant reactivates a suspended tenant
// @Summary Reactivate Tenant
// @Description Reactivate a suspended tenant (platform admin only)
// @Tags Platform Admin - Tenants
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/reactivate [post]
func (h *PlatformManagementHandler) ReactivateTenant(c *gin.Context) {
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

	if err := h.tenantService.Reactivate(c.Request.Context(), tenantID); err != nil {
		h.logger.Error("Failed to reactivate tenant", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to reactivate tenant"})
		return
	}

	h.logPlatformAction(c, currentUser, "tenant_reactivated", "tenant", &tenantID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "Tenant reactivated successfully"})
}

// ============================================================
// CROSS-TENANT USER MANAGEMENT
// ============================================================

// ListTenantUsers lists users in a specific tenant
// @Summary List Tenant Users
// @Description List users in a specific tenant (platform admin only)
// @Tags Platform Admin - Users
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param search query string false "Search query"
// @Param status query string false "Filter by status (active, locked, inactive)"
// @Success 200 {object} models.UserListResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users [get]
func (h *PlatformManagementHandler) ListTenantUsers(c *gin.Context) {
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

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")

	response, err := h.userService.List(c.Request.Context(), tenantID, page, pageSize, search)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetTenantUser gets a user in a specific tenant
// @Summary Get Tenant User
// @Description Get user details in a specific tenant (platform admin only)
// @Tags Platform Admin - Users
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} models.UserResponse
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id} [get]
func (h *PlatformManagementHandler) GetTenantUser(c *gin.Context) {
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

	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPlatMgmtUserNotFound})
		return
	}

	// SECURITY: Verify user belongs to the specified tenant
	if user.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPlatMgmtUserNotFound})
		return
	}

	// Soft-deleted users (self-service pending_deletion or
	// admin-triggered admin_deleted) must not resolve through the
	// ordinary "get user" read path — only the dedicated admin lifecycle
	// endpoints (GET .../users/:user_id/lifecycle, restore, hard-delete)
	// can see them. userService.List already excludes these; this is the
	// matching guard for the single-user read.
	if user.ActivationStatus == "pending_deletion" || user.ActivationStatus == "admin_deleted" {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPlatMgmtUserNotFound})
		return
	}

	c.JSON(http.StatusOK, user)
}

// CreateTenantUser creates a user in a specific tenant
// @Summary Create Tenant User
// @Description Create a new user in a specific tenant (platform admin only)
// @Tags Platform Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param body body models.CreateUserRequest true "User data"
// @Success 201 {object} models.UserResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users [post]
func (h *PlatformManagementHandler) CreateTenantUser(c *gin.Context) {
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

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.TenantID = tenantID

	user, err := h.userService.Create(c.Request.Context(), &req, &currentUser.ID)
	if err != nil {
		var seatErr *services.SeatLimitExceededError
		if errors.As(err, &seatErr) {
			c.JSON(http.StatusConflict, gin.H{
				"error":         "SEAT_LIMIT_EXCEEDED",
				"message":       seatErr.Message,
				"current_usage": seatErr.CurrentUsage,
				"limit":         seatErr.Limit,
			})
			return
		}
		h.logger.Error("Failed to create tenant user", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	h.logPlatformAction(c, currentUser, "user_created", "user", &user.ID, map[string]interface{}{
		"email":     req.Email,
		"tenant_id": tenantID.String(),
	})

	c.JSON(http.StatusCreated, user)
}

// UpdateTenantUser updates a user in a specific tenant
// @Summary Update Tenant User
// @Description Update a user in a specific tenant (platform admin only)
// @Tags Platform Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param body body models.UpdateUserRequest true "User data"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id} [put]
func (h *PlatformManagementHandler) UpdateTenantUser(c *gin.Context) {
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

	// SECURITY: Verify user belongs to the specified tenant before updating
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.Update(c.Request.Context(), userID, &req, &currentUser.ID)
	if err != nil {
		if errors.Is(err, repositories.ErrSeatLimitReached) {
			c.JSON(http.StatusConflict, gin.H{"error": "seat limit reached", "code": errCodeSeatLimitReached})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	h.logPlatformAction(c, currentUser, "user_updated", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
	})

	c.JSON(http.StatusOK, user)
}

// DeleteTenantUser deletes a user in a specific tenant
// @Summary Delete Tenant User
// @Description Delete a user in a specific tenant (platform admin only)
// @Tags Platform Admin - Users
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id} [delete]
func (h *PlatformManagementHandler) DeleteTenantUser(c *gin.Context) {
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

	// SECURITY: Verify user belongs to the specified tenant before deleting
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	if err := h.userService.Delete(c.Request.Context(), userID, &currentUser.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	h.logPlatformAction(c, currentUser, "user_deleted", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
	})

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// ResetUserPassword resets a user's password
// @Summary Reset User Password
// @Description Reset password for a user in any tenant (platform admin only)
// @Tags Platform Admin - Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Param body body models.ResetPasswordRequest true "New password"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id}/reset-password [post]
func (h *PlatformManagementHandler) ResetUserPassword(c *gin.Context) {
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

	var req models.PlatformResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// SECURITY: Verify user belongs to the specified tenant before resetting password
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	mustChange := true
	if req.MustChangePassword != nil {
		mustChange = *req.MustChangePassword
	}

	if err := h.userService.SetPassword(c.Request.Context(), userID, req.Password, mustChange, &currentUser.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	h.logPlatformAction(c, currentUser, "password_reset", "user", &userID, map[string]interface{}{
		"tenant_id":   tenantID.String(),
		"must_change": mustChange,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// UnlockUser unlocks a locked user account
// @Summary Unlock User
// @Description Unlock a locked user account (platform admin only)
// @Tags Platform Admin - Users
// @Produce json
// @Security BearerAuth
// @Param tenant_id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/platform/tenants/{tenant_id}/users/{user_id}/unlock [post]
func (h *PlatformManagementHandler) UnlockUser(c *gin.Context) {
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

	// SECURITY: Verify user belongs to the specified tenant before unlocking
	if !h.verifyUserInTenant(c, userID, tenantID) {
		return
	}

	if err := h.userService.Unlock(c.Request.Context(), userID, &currentUser.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInternalError})
		return
	}

	h.logPlatformAction(c, currentUser, "user_unlocked", "user", &userID, map[string]interface{}{
		"tenant_id": tenantID.String(),
	})

	c.JSON(http.StatusOK, gin.H{"message": "User unlocked successfully"})
}

// verifyUserInTenant checks that a user belongs to the specified tenant.
// Returns false and writes an error response if the user doesn't belong to the tenant.
func (h *PlatformManagementHandler) verifyUserInTenant(c *gin.Context, userID, tenantID uuid.UUID) bool {
	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPlatMgmtUserNotFound})
		return false
	}
	if user.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPlatMgmtUserNotFound})
		return false
	}
	return true
}

// Role management, permissions, audit log, statistics, and helper methods
// are in platform_management_handler_roles.go
