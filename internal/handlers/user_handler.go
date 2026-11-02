// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgUserInvalidUserID    = "Invalid user ID"
	msgUserNotAuthenticated = "Not authenticated"
	msgUserInternalError    = "An internal error occurred"
)

// UserHandler is an exported type.
type UserHandler struct {
	userService *services.UserService
	// redis is used to publish real-time permission-change notifications after
	// a direct DB role mutation, ensuring the SSE stream receives the event
	// even when the change does not flow through SpiceDB.
	redis *goredis.Client
}

// NewUserHandler is an exported function.
func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// SetRedisClient wires a go-redis client for real-time permission notifications.
// Call this during handler initialisation when Redis is available.
func (h *UserHandler) SetRedisClient(client *goredis.Client) {
	h.redis = client
}

// validateUserTenantAccess validates that a user belongs to the requester's tenant.
// SECURITY (CVE-HEXX-IAM-002): This function prevents Insecure Direct Object Reference (IDOR) attacks
// by ensuring users can only access/modify users within their own tenant.
// Platform admins (exampletenant tenant) are allowed to access users across all tenants.
//
// Returns:
// - nil if access is allowed (user is in same tenant OR requester is platform admin)
// - error with 404 message if access denied (returns 404 instead of 403 to prevent tenant enumeration)
func (h *UserHandler) validateUserTenantAccess(c *gin.Context, targetUserID uuid.UUID, currentUser *models.CurrentUser) error {
	// Platform admins can access users from any tenant
	if currentUser.IsPlatformAdmin && currentUser.TenantID.String() == models.HexxlockInternalTenantID {
		logger.Log.Debug("Platform admin accessing cross-tenant user",
			zap.String("admin_id", currentUser.ID.String()),
			zap.String("target_user_id", targetUserID.String()),
		)
		return nil
	}

	// Get target user to check tenant membership
	targetUser, err := h.userService.GetByID(c.Request.Context(), targetUserID)
	if err != nil {
		// User not found - return 404
		logger.Log.Warn("User not found during tenant validation",
			zap.String("target_user_id", targetUserID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("user not found")
	}

	// Validate tenant match
	if targetUser.TenantID != currentUser.TenantID {
		// SECURITY: Return 404 instead of 403 to prevent tenant enumeration
		// This prevents attackers from discovering which user IDs exist in other tenants
		logger.Log.Warn("Cross-tenant user access attempt blocked",
			zap.String("requester_id", currentUser.ID.String()),
			zap.String("requester_tenant", currentUser.TenantID.String()),
			zap.String("target_user_id", targetUserID.String()),
			zap.String("target_user_tenant", targetUser.TenantID.String()),
			zap.String("endpoint", c.Request.URL.Path),
		)
		return fmt.Errorf("user not found")
	}

	return nil
}

// Create creates a new user
// @Summary Create User
// @Description Create a new user
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateUserRequest true "User data"
// @Success 201 {object} models.UserResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/users [post]
func (h *UserHandler) Create(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Use tenant from context if not provided
	if req.TenantID == uuid.Nil {
		req.TenantID = middleware.GetTenantID(c)
	}

	currentUserID := middleware.GetCurrentUserID(c)

	user, err := h.userService.Create(c.Request.Context(), &req, currentUserID)
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// GetByID gets a user by ID
// @Summary Get User
// @Description Get user by ID
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/users/{id} [get]
func (h *UserHandler) GetByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// Update updates a user
// @Summary Update User
// @Description Update user by ID
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param body body models.UpdateUserRequest true "User data"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/users/{id} [put]
func (h *UserHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	user, err := h.userService.Update(c.Request.Context(), id, &req, currentUserID)
	if err != nil {
		if errors.Is(err, repositories.ErrSeatLimitReached) {
			c.JSON(http.StatusConflict, gin.H{"error": "seat limit reached", "code": errCodeSeatLimitReached})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// Delete deletes a user
// @Summary Delete User
// @Description Delete user by ID
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/users/{id} [delete]
func (h *UserHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	err = h.userService.Delete(c.Request.Context(), id, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// List lists users
// @Summary List Users
// @Description List users with pagination
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param search query string false "Search query"
// @Success 200 {object} models.UserListResponse
// @Failure 401 {object} map[string]string
// @Router /api/users [get]
func (h *UserHandler) List(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	// SECURITY: Use GetPagination to enforce max page size of 100
	page, pageSize, _ := GetPagination(c)
	search := c.Query("search")

	response, err := h.userService.List(c.Request.Context(), tenantID, page, pageSize, search)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgUserInternalError})
		return
	}

	c.JSON(http.StatusOK, response)
}

// SetPassword sets a user's password (admin action)
// @Summary Set User Password
// @Description Set password for a user
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param body body models.SetPasswordRequest true "Password data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id}/password [post]
func (h *UserHandler) SetPassword(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		Password   string `json:"password" binding:"required,min=8"`
		MustChange bool   `json:"must_change"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	err = h.userService.SetPassword(c.Request.Context(), id, req.Password, req.MustChange, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password set successfully"})
}

// Lock locks a user account
// @Summary Lock User
// @Description Lock a user account
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param body body models.LockUserRequest true "Lock reason"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id}/lock [post]
func (h *UserHandler) Lock(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	err = h.userService.Lock(c.Request.Context(), id, req.Reason, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User locked"})
}

// Unlock unlocks a user account
// @Summary Unlock User
// @Description Unlock a user account
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id}/unlock [post]
func (h *UserHandler) Unlock(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	err = h.userService.Unlock(c.Request.Context(), id, currentUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User unlocked"})
}

// GetRoles gets roles for a user
// @Summary Get User Roles
// @Description Get roles assigned to a user
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} []models.RoleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id}/roles [get]
func (h *UserHandler) GetRoles(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	roles, err := h.userService.GetUserRoles(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgUserInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

// GetPermissions gets permissions for a user
// @Summary Get User Permissions
// @Description Get permissions for a user
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} []models.PermissionResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id}/permissions [get]
func (h *UserHandler) GetPermissions(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	permissions, err := h.userService.GetUserPermissions(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgUserInternalError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// SetRoles sets roles for a user
// @Summary Set User Roles
// @Description Set roles for a user (replaces existing roles)
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Param body body models.SetUserRolesRequest true "Role IDs"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{id}/roles [put]
func (h *UserHandler) SetRoles(c *gin.Context) {
	idStr := c.Param("id")
	id, err := parseUUID(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgUserInvalidUserID})
		return
	}

	// Get current user for tenant validation
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgUserNotAuthenticated})
		return
	}

	// SECURITY (CVE-HEXX-IAM-002): Validate tenant access to prevent IDOR
	if err := h.validateUserTenantAccess(c, id, currentUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req models.SetUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := middleware.GetCurrentUserID(c)

	if err := h.userService.SetUserRoles(c.Request.Context(), id, req.RoleIDs, currentUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Security audit: permission/role change
	roleIDStrs := make([]string, len(req.RoleIDs))
	for i, rid := range req.RoleIDs {
		roleIDStrs[i] = rid.String()
	}
	actorID := ""
	if currentUserID != nil {
		actorID = currentUserID.String()
	}
	logger.SecurityAudit.Info("Security audit: user roles changed",
		zap.String("event", "auth.permission.roles_changed"),
		zap.String("actor_id", actorID),
		zap.String("actor_username", currentUser.Username),
		zap.String("target_user_id", id.String()),
		zap.Strings("new_role_ids", roleIDStrs),
		zap.String("ip", GetClientIP(c)),
		zap.Time("timestamp", time.Now().UTC()),
	)

	// Publish a real-time notification to the affected user's SSE channel.
	// This covers role mutations that bypass SpiceDB (direct DB writes), so
	// the browser receives the event regardless of whether SpiceDB is enabled.
	h.publishRoleChangedNotification(c.Request.Context(), id.String())

	c.JSON(http.StatusOK, gin.H{"message": "Roles updated successfully"})
}

// publishRoleChangedNotification publishes a permission_changed event to the
// user's Redis Pub/Sub channel so any active SSE connection can relay it to
// the browser immediately.  The call is best-effort — a Redis failure is
// logged as a warning and does not affect the HTTP response.
func (h *UserHandler) publishRoleChangedNotification(ctx context.Context, userID string) {
	if h.redis == nil {
		return
	}

	channel := fmt.Sprintf("hexxlock:permissions:%s", userID)
	msg := fmt.Sprintf(
		`{"type":"permission_changed","user_id":"%s","source":"role_mutation","timestamp":"%s"}`,
		userID,
		time.Now().UTC().Format(time.RFC3339),
	)

	if err := h.redis.Publish(ctx, channel, msg).Err(); err != nil {
		logger.Log.Warn("Failed to publish role-change notification",
			zap.String("user_id", userID),
			zap.String("channel", channel),
			zap.Error(err),
		)
	}
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
