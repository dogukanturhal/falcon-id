// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// ContextHandler handles tenant/realm context switching
type ContextHandler struct {
	tokenService *services.TokenService
	auditService *services.AuditService
	userRepo     *repositories.UserRepository
	tenantRepo   *repositories.TenantRepository
	realmRepo    *repositories.RealmRepository
	roleRepo     *repositories.RoleRepository
	sessionCache *redis.SessionCache
	redisClient  *redis.Client
	rateLimiter  *redis.RateLimiter
	db           *pgxpool.Pool
}

// ContextHandlerConfig groups all dependencies for NewContextHandler,
// reducing its parameter count below the linting threshold.
type ContextHandlerConfig struct {
	TokenService *services.TokenService
	AuditService *services.AuditService
	UserRepo     *repositories.UserRepository
	TenantRepo   *repositories.TenantRepository
	RealmRepo    *repositories.RealmRepository
	RoleRepo     *repositories.RoleRepository
	SessionCache *redis.SessionCache
	RedisClient  *redis.Client
	RateLimiter  *redis.RateLimiter
	DB           *pgxpool.Pool
}

// NewContextHandler creates a new context handler
func NewContextHandler(cfg ContextHandlerConfig) *ContextHandler {
	return &ContextHandler{
		tokenService: cfg.TokenService,
		auditService: cfg.AuditService,
		userRepo:     cfg.UserRepo,
		tenantRepo:   cfg.TenantRepo,
		realmRepo:    cfg.RealmRepo,
		roleRepo:     cfg.RoleRepo,
		sessionCache: cfg.SessionCache,
		redisClient:  cfg.RedisClient,
		rateLimiter:  cfg.RateLimiter,
		db:           cfg.DB,
	}
}

// AvailableContext represents a tenant/realm the user can access
type AvailableContext struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantSlug string    `json:"tenant_slug"`
	TenantName string    `json:"tenant_name"`
	RealmID    uuid.UUID `json:"realm_id"`
	RealmSlug  string    `json:"realm_slug"`
	RealmName  string    `json:"realm_name"`
	RealmType  string    `json:"realm_type"` // enterprise, shared, sandbox
	Roles      []string  `json:"roles"`      // User's roles in this context
	IsCurrent  bool      `json:"is_current"` // True if this is active context
	// MembershipKind is "home" for the user's own tenant, "member" for another
	// company the person joined by invitation and "external" for
	// a client tenant reached through a seat-free external membership. A
	// client calls the tenant token exchange (POST /oauth/token,
	// target_tenant_id) to obtain a token for an external context.
	MembershipKind string `json:"membership_kind"`
	// LastUsedAt is when the person last worked in this company (membership
	// last_used_at); the client uses it to preselect the default company.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// AvailableContextsResponse contains all contexts accessible to the user
type AvailableContextsResponse struct {
	Contexts []AvailableContext `json:"contexts"`
	Current  *AvailableContext  `json:"current"`
}

// SwitchContextRequest for switching tenant/realm
type SwitchContextRequest struct {
	TenantID uuid.UUID `json:"tenant_id" binding:"required"`
	RealmID  uuid.UUID `json:"realm_id" binding:"required"`
}

// SwitchContextResponse returned after successful context switch
type SwitchContextResponse struct {
	AccessToken string           `json:"access_token"`
	ExpiresIn   int64            `json:"expires_in"`
	Context     AvailableContext `json:"context"`
}

// UserContext represents a user's access to a tenant/realm
type UserContext struct {
	TenantID   uuid.UUID
	TenantSlug string
	TenantName string
	RealmID    uuid.UUID
	RealmSlug  string
	RealmName  string
	RealmType  string
	Roles      []string
	// MembershipKind: "home", "member" or "external" (see AvailableContext).
	MembershipKind string
	LastUsedAt     *time.Time
	// TenantStatus / TenantSuspended are filled by verifyUserContextAccess
	// only (never cached): iam_tenants.status and the iam_tenant_status
	// suspension mirror (0018) of the target tenant.
	TenantStatus    string `json:"-"`
	TenantSuspended bool   `json:"-"`
}

// SessionContextUpdate for updating session context in Redis
type SessionContextUpdate struct {
	TenantID    uuid.UUID
	RealmID     uuid.UUID
	Roles       []string
	Permissions []string
}

// GetAvailableContexts returns all tenants/realms the user can access
// @Summary Get Available Contexts
// @Description List all tenant/realm combinations the user can access
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} AvailableContextsResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/auth/available-contexts [get]
func (h *ContextHandler) GetAvailableContexts(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Try to get cached contexts first
	cachedContexts, err := h.getCachedUserContexts(c.Request.Context(), currentUser.ID)
	if err == nil && len(cachedContexts) > 0 {
		logger.Log.Debug("Retrieved user contexts from cache",
			zap.String("user_id", currentUser.ID.String()),
			zap.Int("count", len(cachedContexts)))
	} else {
		// Cache miss or error - fetch from database
		cachedContexts, err = h.getUserContextsFromDB(c.Request.Context(), currentUser.ID)
		if err != nil {
			logger.Log.Error("Failed to get user contexts",
				zap.Error(err),
				zap.String("user_id", currentUser.ID.String()))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve accessible contexts"})
			return
		}

		// Cache for future requests
		if err := h.cacheUserContexts(c.Request.Context(), currentUser.ID, cachedContexts); err != nil {
			logger.Log.Warn("Failed to cache user contexts", zap.Error(err))
		}
	}

	// Build response
	response := AvailableContextsResponse{
		Contexts: make([]AvailableContext, 0, len(cachedContexts)),
	}

	for _, ctx := range cachedContexts {
		ac := AvailableContext{
			TenantID:   ctx.TenantID,
			TenantSlug: ctx.TenantSlug,
			TenantName: ctx.TenantName,
			RealmID:    ctx.RealmID,
			RealmSlug:  ctx.RealmSlug,
			RealmName:  ctx.RealmName,
			RealmType:  ctx.RealmType,
			Roles:      ctx.Roles,
			IsCurrent:  ctx.TenantID == currentUser.TenantID && ctx.RealmID == currentUser.RealmID,

			MembershipKind: ctx.MembershipKind,
			LastUsedAt:     ctx.LastUsedAt,
		}
		response.Contexts = append(response.Contexts, ac)
		if ac.IsCurrent {
			current := ac
			response.Current = &current
		}
	}

	c.JSON(http.StatusOK, response)
}

// SwitchContext switches user to a different tenant/realm
// @Summary Switch Context
// @Description Switch to a different tenant/realm without full re-authentication
// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body SwitchContextRequest true "Target tenant and realm"
// @Success 200 {object} SwitchContextResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 429 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/auth/switch-context [post]
func (h *ContextHandler) SwitchContext(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req SwitchContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Rate limiting: 10 context switches per minute per user (with 5 minute block on exceed)
	if h.rateLimiter != nil {
		rateLimitKey := fmt.Sprintf("context_switch:%s", currentUser.ID.String())
		result, err := h.rateLimiter.Check(c.Request.Context(), rateLimitKey, 10, time.Minute, 5*time.Minute)
		if err != nil {
			logger.Log.Warn("Rate limit check failed", zap.Error(err))
		} else if !result.Allowed {
			logger.Log.Warn("Context switch rate limit exceeded",
				zap.String("user_id", currentUser.ID.String()),
				zap.String("ip", GetClientIP(c)),
				zap.Duration("retry_after", result.RetryAfter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many context switches. Please try again later.",
				"retry_after": int(result.RetryAfter.Seconds()),
			})
			return
		}
	}

	// Verify user has access to requested context
	hasAccess, contextInfo, err := h.verifyUserContextAccess(
		c.Request.Context(),
		currentUser.ID,
		req.TenantID,
		req.RealmID,
	)
	if err != nil {
		logger.Log.Error("Failed to verify context access",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()),
			zap.String("tenant_id", req.TenantID.String()),
			zap.String("realm_id", req.RealmID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify access"})
		return
	}

	if !hasAccess {
		logger.Log.Warn("Context access denied",
			zap.String("user_id", currentUser.ID.String()),
			zap.String("tenant_id", req.TenantID.String()),
			zap.String("realm_id", req.RealmID.String()))

		// Audit failed attempt
		h.auditLog(c.Request.Context(), currentUser.ID, currentUser.TenantID, "context_switch_denied", map[string]interface{}{
			"target_tenant": req.TenantID,
			"target_realm":  req.RealmID,
			"reason":        "access_denied",
		}, false)

		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to requested context"})
		return
	}

	// A suspended or no longer active tenant is never a switch target: the
	// token minted below would otherwise outlive the suspension that login,
	// refresh and the tenant token exchange already enforce (LD-R3-TX-3).
	if reason := switchTargetRefusal(contextInfo); reason != "" {
		logger.Log.Warn("Context switch to inactive tenant denied",
			zap.String("user_id", currentUser.ID.String()),
			zap.String("tenant_id", req.TenantID.String()),
			zap.String("reason", reason))
		h.auditLog(c.Request.Context(), currentUser.ID, currentUser.TenantID, "context_switch_denied", map[string]interface{}{
			"target_tenant": req.TenantID,
			"target_realm":  req.RealmID,
			"reason":        reason,
		}, false)
		if reason == "tenant_suspended" {
			respondIfTenantSuspended(c, services.ErrTenantSuspended)
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to requested context"})
		return
	}

	// Get user's roles and permissions in the new context
	roles, err := h.getUserRolesInContext(c.Request.Context(), currentUser.ID, req.TenantID, req.RealmID)
	if err != nil {
		logger.Log.Error("Failed to get user roles",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user roles"})
		return
	}

	permissions, err := h.getUserPermissionsInContext(c.Request.Context(), currentUser.ID, req.TenantID, roles)
	if err != nil {
		logger.Log.Error("Failed to get user permissions",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user permissions"})
		return
	}

	// Get user information
	user, err := h.userRepo.GetByID(c.Request.Context(), currentUser.ID)
	if err != nil {
		logger.Log.Error("Failed to get user",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate new token with new context (preserve session ID for continuity)
	tokenOpts := services.TokenGenerationOptions{
		RealmID:   req.RealmID,
		RealmSlug: contextInfo.RealmSlug,
		RealmType: contextInfo.RealmType,
		Scope:     "tenant",
	}

	// Update user's tenant/realm temporarily for token generation
	userWithNewContext := &models.User{
		ID:       user.ID,
		TenantID: req.TenantID,
		RealmID:  req.RealmID,
		Username: user.Username,
		Email:    user.Email,
	}

	accessToken, err := h.tokenService.GenerateAccessTokenWithOptions(
		c.Request.Context(),
		userWithNewContext,
		currentUser.SessionID,
		roles,
		permissions,
		tokenOpts,
	)
	if err != nil {
		logger.Log.Error("Failed to generate access token",
			zap.Error(err),
			zap.String("user_id", currentUser.ID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Update session in Redis with new context
	if err := h.updateSessionContext(c.Request.Context(), currentUser.SessionID, SessionContextUpdate{
		TenantID:    req.TenantID,
		RealmID:     req.RealmID,
		Roles:       roles,
		Permissions: permissions,
	}); err != nil {
		// Log warning but don't fail - token is already generated
		logger.Log.Warn("Failed to update session cache",
			zap.Error(err),
			zap.String("session_id", currentUser.SessionID.String()))
	}

	// Set new cookie (using helper from auth_handler)
	expiresIn := int64(1800) // 30 minutes
	setAccessTokenCookie(c, accessToken, time.Duration(expiresIn)*time.Second)

	// Audit successful context switch
	h.auditLog(c.Request.Context(), currentUser.ID, currentUser.TenantID, "context_switch", map[string]interface{}{
		"from_tenant": currentUser.TenantID,
		"from_realm":  currentUser.RealmID,
		"to_tenant":   req.TenantID,
		"to_realm":    req.RealmID,
	}, true)

	logger.Log.Info("Context switched successfully",
		zap.String("user_id", currentUser.ID.String()),
		zap.String("from_tenant", currentUser.TenantID.String()),
		zap.String("to_tenant", req.TenantID.String()),
		zap.String("to_realm", req.RealmID.String()))

	c.JSON(http.StatusOK, SwitchContextResponse{
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
		Context: AvailableContext{
			TenantID:   req.TenantID,
			TenantSlug: contextInfo.TenantSlug,
			TenantName: contextInfo.TenantName,
			RealmID:    req.RealmID,
			RealmSlug:  contextInfo.RealmSlug,
			RealmName:  contextInfo.RealmName,
			RealmType:  contextInfo.RealmType,
			Roles:      roles,
			IsCurrent:  true,
		},
	})
}

// setAccessTokenCookie sets the access token cookie
func setAccessTokenCookie(c *gin.Context, token string, ttl time.Duration) {
	domain := getCookieDomain(c)
	secure := isSecureEnvironment()
	sameSite := http.SameSiteStrictMode
	if !secure {
		sameSite = http.SameSiteNoneMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie(
		"falcon_access_token",
		token,
		int(ttl.Seconds()),
		"/",
		domain,
		secure,
		true, // HttpOnly
	)
}

// getUserContextsFromDB fetches user's accessible contexts from database
func (h *ContextHandler) getUserContextsFromDB(ctx context.Context, userID uuid.UUID) ([]UserContext, error) {
	// Query to get all tenant/realm combinations the user has access to:
	// the home tenant (iam_users.tenant_id) plus every tenant holding an
	// active seat_class='external' (an accountant invited from their partner
	// tenant) or seat_class='member' (a person invited into another company
	// with their one global account) membership for the user. Roles are scoped to each listed
	// tenant so one tenant's role names never appear under another.
	query := `
		SELECT
			t.id as tenant_id,
			t.slug as tenant_slug,
			t.name as tenant_name,
			u.realm_id as realm_id,
			'' as realm_slug,
			'' as realm_name,
			'' as realm_type,
			COALESCE(array_agg(DISTINCT ro.name) FILTER (WHERE ro.name IS NOT NULL), '{}') as roles,
			CASE WHEN t.id = u.tenant_id THEN 'home'
			     WHEN bool_or(mm.seat_class = 'external') THEN 'external'
			     ELSE 'member' END as membership_kind,
			max(mm.last_used_at) as last_used_at
		FROM iam_users u
		INNER JOIN iam_tenants t ON t.id = u.tenant_id OR t.id IN (
			SELECT m.tenant_id FROM iam_user_memberships m
			WHERE m.user_id = u.id AND m.seat_class IN ('external', 'member') AND m.status = 'active'
		)
		LEFT JOIN iam_user_memberships mm ON mm.tenant_id = t.id AND mm.user_id = u.id
		LEFT JOIN iam_user_roles ur ON ur.user_id = u.id
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		LEFT JOIN iam_roles ro ON ro.id = ur.role_id AND ro.tenant_id = t.id
		WHERE u.id = $1
			AND (u.is_active = true OR u.is_active IS NULL)
		GROUP BY t.id, t.slug, t.name, u.realm_id, u.tenant_id
		ORDER BY t.name
	`

	// The external memberships live in other tenants: read them under the
	// user's own app.current_user_id so the iam_user_memberships RLS policy
	// exposes them (see repositories.WithUserMembershipScope).
	var contexts []UserContext
	err := repositories.WithUserMembershipScope(ctx, h.db, userID, func(tx pgx.Tx) error {
		var qErr error
		contexts, qErr = scanUserContexts(ctx, tx, query, userID)
		return qErr
	})
	if err != nil {
		return nil, err
	}
	return contexts, nil
}

func scanUserContexts(ctx context.Context, tx pgx.Tx, query string, userID uuid.UUID) ([]UserContext, error) {
	rows, err := tx.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user contexts: %w", err)
	}
	defer rows.Close()

	contexts := make([]UserContext, 0)
	for rows.Next() {
		var uc UserContext
		var realmID *uuid.UUID
		var realmSlug, realmName, realmType *string

		err := rows.Scan(
			&uc.TenantID,
			&uc.TenantSlug,
			&uc.TenantName,
			&realmID,
			&realmSlug,
			&realmName,
			&realmType,
			&uc.Roles,
			&uc.MembershipKind,
			&uc.LastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user context: %w", err)
		}

		// Handle nullable realm fields
		if realmID != nil {
			uc.RealmID = *realmID
		}
		if realmSlug != nil {
			uc.RealmSlug = *realmSlug
		}
		if realmName != nil {
			uc.RealmName = *realmName
		}
		if realmType != nil {
			uc.RealmType = *realmType
		}

		contexts = append(contexts, uc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user contexts: %w", err)
	}

	return contexts, nil
}

// cacheUserContexts stores user's contexts in Redis with 1 hour TTL
func (h *ContextHandler) cacheUserContexts(ctx context.Context, userID uuid.UUID, contexts []UserContext) error {
	key := userContextsCacheKey(userID)
	data, err := json.Marshal(contexts)
	if err != nil {
		return fmt.Errorf("failed to marshal contexts: %w", err)
	}

	return h.redisClient.Redis().Set(ctx, key, data, time.Hour).Err()
}

// getCachedUserContexts retrieves cached user contexts from Redis
func (h *ContextHandler) getCachedUserContexts(ctx context.Context, userID uuid.UUID) ([]UserContext, error) {
	key := userContextsCacheKey(userID)
	data, err := h.redisClient.Redis().Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("getCachedUserContexts: %w", err)
	}

	var contexts []UserContext
	if err := json.Unmarshal(data, &contexts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contexts: %w", err)
	}

	return contexts, nil
}

// switchTargetRefusal returns why a reachable context's tenant may not be
// switched into, or "" when it may. Mirrors the tenant token exchange
// (services.tenantExchangeRefusal): active or trial only, never suspended.
func switchTargetRefusal(info *UserContext) string {
	switch {
	case info.TenantSuspended:
		return "tenant_suspended"
	case info.TenantStatus != "active" && info.TenantStatus != "trial":
		return "tenant_not_active"
	}
	return ""
}

// verifyUserContextAccess checks if user can access a specific tenant/realm
func (h *ContextHandler) verifyUserContextAccess(
	ctx context.Context,
	userID, tenantID, _ uuid.UUID,
) (bool, *UserContext, error) {
	query := `
		SELECT
			t.id as tenant_id,
			t.slug as tenant_slug,
			t.name as tenant_name,
			u.realm_id as realm_id,
			'' as realm_slug,
			'' as realm_name,
			'' as realm_type,
			t.status,
			COALESCE(ts.suspended, false)
		FROM iam_users u
		INNER JOIN iam_tenants t ON t.id = $2
		LEFT JOIN iam_tenant_status ts ON ts.tenant_id = t.id
		WHERE u.id = $1
			AND u.is_active = true
			AND (u.tenant_id = $2 OR EXISTS (
				SELECT 1 FROM iam_user_memberships m
				WHERE m.tenant_id = $2 AND m.user_id = u.id
					AND m.seat_class IN ('external', 'member') AND m.status = 'active'
			))
		LIMIT 1
	`

	var contextInfo UserContext
	var realmIDResult *uuid.UUID
	var realmSlug, realmName, realmType *string

	err := repositories.WithUserMembershipScope(ctx, h.db, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, userID, tenantID).Scan(
			&contextInfo.TenantID,
			&contextInfo.TenantSlug,
			&contextInfo.TenantName,
			&realmIDResult,
			&realmSlug,
			&realmName,
			&realmType,
			&contextInfo.TenantStatus,
			&contextInfo.TenantSuspended,
		)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Neither home tenant nor an active external membership: a plain
		// denial (403), not a server error.
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("verifyUserContextAccess: %w", err)
	}

	// Set realm fields
	if realmIDResult != nil {
		contextInfo.RealmID = *realmIDResult
	}
	if realmSlug != nil {
		contextInfo.RealmSlug = *realmSlug
	}
	if realmName != nil {
		contextInfo.RealmName = *realmName
	}
	if realmType != nil {
		contextInfo.RealmType = *realmType
	}

	return true, &contextInfo, nil
}

// getUserRolesInContext returns user's roles in a specific context
func (h *ContextHandler) getUserRolesInContext(
	ctx context.Context,
	userID, tenantID, _ uuid.UUID,
) ([]string, error) {
	// Scoped to the target tenant: an external accountant who is an
	// administrator in their own partner tenant must not carry that role
	// name into a token minted for a client tenant.
	query := `
		SELECT DISTINCT r.name
		FROM iam_user_roles ur
		INNER JOIN iam_roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
			AND r.tenant_id = $2
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		ORDER BY r.name
	`

	rows, err := h.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	roles := make([]string, 0)
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// getUserPermissionsInContext returns user's permissions in a specific context
func (h *ContextHandler) getUserPermissionsInContext(
	ctx context.Context,
	_, tenantID uuid.UUID,
	roles []string,
) ([]string, error) {
	if len(roles) == 0 {
		return []string{}, nil
	}

	// Build role name placeholders for query
	query := `
		SELECT DISTINCT p.name
		FROM iam_roles r
		INNER JOIN iam_role_permissions rp ON rp.role_id = r.id
		INNER JOIN iam_permissions p ON p.id = rp.permission_id
		WHERE r.name = ANY($1)
			AND r.tenant_id = $2
			AND r.deleted_at IS NULL
		ORDER BY p.name
	`

	rows, err := h.db.Query(ctx, query, roles, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user permissions: %w", err)
	}
	defer rows.Close()

	permissions := make([]string, 0)
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	return permissions, rows.Err()
}

// updateSessionContext updates session context in Redis
func (h *ContextHandler) updateSessionContext(
	ctx context.Context,
	sessionID uuid.UUID,
	update SessionContextUpdate,
) error {
	// Get existing session
	session, err := h.sessionCache.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	if session == nil {
		// Session not in cache, skip update
		return nil
	}

	// Update context fields (immutable approach)
	updatedSession := &redis.CachedSession{ //nolint:staticcheck // intentional: backward-compat session type
		SessionID:   session.SessionID,
		UserID:      session.UserID,
		TenantID:    update.TenantID,
		Username:    session.Username,
		Email:       session.Email,
		Roles:       update.Roles,
		Permissions: update.Permissions,
		DeviceInfo:  session.DeviceInfo,
		IPAddress:   session.IPAddress,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   session.ExpiresAt,
	}

	return h.sessionCache.Set(ctx, updatedSession)
}

// auditLog creates an audit log entry
func (h *ContextHandler) auditLog(
	_ context.Context,
	userID, tenantID uuid.UUID,
	action string,
	details map[string]interface{},
	success bool,
) {
	if h.db == nil {
		return
	}

	// Non-blocking audit logging
	go func() { //nolint:gosec // goroutine must outlive request context
		logCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create audit log directly via database
		query := `
			INSERT INTO audit_logs (tenant_id, user_id, action, details, success)
			VALUES ($1, $2, $3, $4, $5)
		`

		detailsJSON, err := json.Marshal(details)
		if err != nil {
			logger.Log.Warn("Failed to marshal audit log details",
				zap.Error(err),
				zap.String("action", action))
			return
		}

		if _, err := h.db.Exec(logCtx, query, tenantID, userID, action, detailsJSON, success); err != nil {
			logger.Log.Warn("Failed to create audit log",
				zap.Error(err),
				zap.String("action", action))
		}
	}()
}

func userContextsCacheKey(userID uuid.UUID) string {
	// v2: entries carry MembershipKind; older cached lists lack it.
	return fmt.Sprintf("hexxlock:user:%s:contexts:v2", userID.String())
}

// InvalidateUserContextsCache drops a user's cached available-contexts list
// so the tenant switcher reflects a granted or revoked external membership at
// once. Best effort: a failure only delays the change until the cache TTL,
// and SwitchContext re-checks access against PostgreSQL regardless.
func InvalidateUserContextsCache(ctx context.Context, client *redis.Client, userID uuid.UUID) {
	if client == nil {
		return
	}
	if err := client.Redis().Del(ctx, userContextsCacheKey(userID)).Err(); err != nil {
		logger.Log.Warn("Failed to invalidate user contexts cache", zap.Error(err), zap.String("user_id", userID.String()))
	}
}
