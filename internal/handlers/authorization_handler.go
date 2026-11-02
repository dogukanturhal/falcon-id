// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// pinSubjectToSession forces an authorization query to be about the CALLER and
// nobody else.
//
// models.AuthorizeRequest and models.BatchAuthorizeRequest both carry a
// client-supplied `userId` (binding:"required") and `tenantId`, and both the
// handler and AuthorizationService passed them straight through to the
// permission engine. The routes carry RequireAuth() but no RequirePermission,
// so ANY authenticated caller could ask "what can user X in tenant Y do?" and
// receive a map of permission -> bool. That is textbook Broken Object Level
// Authorization (OWASP API1:2023): the subject of an authorization decision was
// taken from the request body instead of the verified token.
//
// OWASP's guidance is to resolve the principal exclusively from verified token
// claims and ignore — or reject — any user/tenant identifier supplied by the
// client. We reject rather than silently override: a caller asking about a
// different subject is either a bug or an attack, and answering its question
// about ITSELF would hide both.
//
// This endpoint is deliberately self-scoped only. Administrative introspection
// of another user's permissions already has its own gated route
// (/platform/spicedb/users/:id/effective-permissions, behind RequirePermission).
//
// Returns false once it has written the response.
func pinSubjectToSession(c *gin.Context, userID, tenantID *uuid.UUID) bool {
	current := middleware.GetCurrentUser(c)
	if current == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return false
	}

	if *userID != uuid.Nil && *userID != current.ID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "authorization checks are self-scoped: userId must be the authenticated user",
		})
		return false
	}
	if *tenantID != uuid.Nil && *tenantID != current.TenantID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "authorization checks are self-scoped: tenantId must be the authenticated tenant",
		})
		return false
	}

	*userID = current.ID
	*tenantID = current.TenantID
	return true
}

// authorizationServiceAPI is the narrow slice of *services.AuthorizationService
// that AuthorizationHandler depends on. It exists so tests can exercise the
// REAL handler methods (Authorize, AuthorizeBatch, GetEffectivePermissions —
// including pinSubjectToSession, which both Authorize and AuthorizeBatch call
// first) against a test double, instead of maintaining a hand-written mirror
// of the handler that silently drifts from production behaviour.
//
// *services.AuthorizationService satisfies this interface unchanged, so
// production wiring in cmd/ is unaffected.
type authorizationServiceAPI interface {
	Authorize(ctx context.Context, req *models.AuthorizeRequest) (*models.AuthorizeResponse, error)
	AuthorizeBatch(ctx context.Context, req *models.BatchAuthorizeRequest) (*models.BatchAuthorizeResponse, error)
	GetEffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) (*models.EffectivePermissionsResponse, error)
	Simulate(ctx context.Context, actorID, userID, tenantID uuid.UUID, permission string) (*models.SimulateResponse, error)
}

// userLookupAPI is the narrow slice of *services.UserService that
// AuthorizationHandler depends on: resolving a target user's tenant for the
// cross-tenant guard in GetEffectivePermissions. It exists so that guard can
// be exercised by a test double instead of being permanently skipped by
// passing a nil *services.UserService (which stands up UserService's own
// repo/cache dependency graph).
//
// *services.UserService satisfies this interface unchanged, so production
// wiring in cmd/ is unaffected.
type userLookupAPI interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.UserResponse, error)
}

// AuthorizationHandler handles authorization-related HTTP requests
type AuthorizationHandler struct {
	authorizationService authorizationServiceAPI
	userService          userLookupAPI
}

// NewAuthorizationHandler creates a new authorization handler
func NewAuthorizationHandler(authorizationService authorizationServiceAPI, userService userLookupAPI) *AuthorizationHandler {
	return &AuthorizationHandler{
		authorizationService: authorizationService,
		userService:          userService,
	}
}

// Authorize checks if a user has a specific permission
// @Summary Check Permission
// @Description Check if a user has a specific permission
// @Tags Authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.AuthorizeRequest true "Authorization request"
// @Success 200 {object} models.AuthorizeResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/authorize [post]
func (h *AuthorizationHandler) Authorize(c *gin.Context) {
	var req models.AuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !pinSubjectToSession(c, &req.UserID, &req.TenantID) {
		return
	}

	result, err := h.authorizationService.Authorize(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// AuthorizeBatch checks multiple permissions for a user
// @Summary Batch Check Permissions
// @Description Check multiple permissions for a user in one request
// @Tags Authorization
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.BatchAuthorizeRequest true "Batch authorization request"
// @Success 200 {object} models.BatchAuthorizeResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/authorize/batch [post]
func (h *AuthorizationHandler) AuthorizeBatch(c *gin.Context) {
	var req models.BatchAuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !pinSubjectToSession(c, &req.UserID, &req.TenantID) {
		return
	}

	result, err := h.authorizationService.AuthorizeBatch(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetEffectivePermissions returns all effective permissions for a user
// @Summary Get Effective Permissions
// @Description Get all effective permissions for a user (via roles)
// @Tags Authorization
// @Produce json
// @Security BearerAuth
// @Param userId path string true "User ID"
// @Success 200 {object} models.EffectivePermissionsResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/users/{userId}/effective-permissions [get]
func (h *AuthorizationHandler) GetEffectivePermissions(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	// Verify the target user belongs to the caller's tenant
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
		if err != nil || targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if targetUser.TenantID != currentUser.TenantID {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
	}

	result, err := h.authorizationService.GetEffectivePermissions(c.Request.Context(), userID, currentUser.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// sameTenantTarget resolves userID and proves it belongs to the caller's own
// tenant. Fail closed: no user service, lookup error, or a user in another
// tenant all answer 404 "User not found" (never confirming the id exists
// elsewhere). Returns false once a response has been written.
func (h *AuthorizationHandler) sameTenantTarget(c *gin.Context, caller *models.CurrentUser, userID uuid.UUID) bool {
	if h.userService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user lookup unavailable"})
		return false
	}
	target, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil || target == nil || target.TenantID != caller.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return false
	}
	return true
}

// Simulate evaluates "can user X do Y, and why" as another user of the
// caller's OWN tenant (policy simulator, spec 23 §7/§8 #18). Route-gated to
// tenant admins; the tenant comes from the verified session, never the body,
// and the target user must belong to it. Every simulation is audited.
// @Router /api/v1/authorize/simulate [post]
func (h *AuthorizationHandler) Simulate(c *gin.Context) {
	var req models.SimulateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	caller := middleware.GetCurrentUser(c)
	if caller == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if !h.sameTenantTarget(c, caller, req.UserID) {
		return
	}
	result, err := h.authorizationService.Simulate(c.Request.Context(), caller.ID, req.UserID, caller.TenantID, req.Permission)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetEffectivePermissionsByQuery is GET /api/v1/authorize/effective-permissions
// ?userId=: the flattened effective-permission set of one user of the caller's
// own tenant (user access detail screen + CSV export). Route-gated to tenant
// admins; cross-tenant targets answer 404.
// @Router /api/v1/authorize/effective-permissions [get]
func (h *AuthorizationHandler) GetEffectivePermissionsByQuery(c *gin.Context) {
	userID, err := uuid.Parse(c.Query("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid userId"})
		return
	}
	caller := middleware.GetCurrentUser(c)
	if caller == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if !h.sameTenantTarget(c, caller, userID) {
		return
	}
	result, err := h.authorizationService.GetEffectivePermissions(c.Request.Context(), userID, caller.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get effective permissions"})
		return
	}
	c.JSON(http.StatusOK, result)
}
