// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// Context keys set by AgentAuthMiddleware for downstream handlers.
const (
	AgentIDKey           = "agent_id"
	AgentTypeKey         = "agent_type"
	AgentCapabilitiesKey = "agent_capabilities"
	AgentTenantIDKey     = "agent_tenant_id"
)

// AgentStatusChecker is the minimal interface required by AgentAuthMiddleware
// to verify that an agent is still active and allowed to call the given path.
// Using a narrow interface keeps the middleware decoupled from the full service.
type AgentStatusChecker interface {
	// GetAgentStatus returns the current status string for the agent with the
	// given ID.  Implementors should return ("", error) if the agent is not found.
	GetAgentStatus(ctx context.Context, agentID uuid.UUID) (string, error)

	// ValidateAgentScope returns true if the agent is permitted to call the
	// given path with the given HTTP method.
	ValidateAgentScope(ctx context.Context, agentID uuid.UUID, path, method string) (bool, error)
}

// AgentAuthMiddleware validates JWT tokens that carry the agent identity type
// claim ("type": "agent").  It is designed to be placed on route groups that
// are exclusively consumed by AI agent clients, not human users.
//
// Responsibilities:
//  1. Parse and verify the JWT signature (HS256 with the platform JWT secret).
//  2. Assert `type == "agent"` — reject any human user token.
//  3. Confirm the agent is still active via AgentStatusChecker (real-time DB check).
//  4. Validate API path/method scope if the agent's AllowedAPIs list is non-empty.
//  5. Set context values (agent_id, agent_type, capabilities, tenant_id) for
//     downstream handlers and rate-limit middleware.
type AgentAuthMiddleware struct {
	jwtSecret string
	checker   AgentStatusChecker
}

// NewAgentAuthMiddleware creates a new AgentAuthMiddleware.
func NewAgentAuthMiddleware(jwtSecret string, checker AgentStatusChecker) *AgentAuthMiddleware {
	return &AgentAuthMiddleware{
		jwtSecret: jwtSecret,
		checker:   checker,
	}
}

// RequireAgentAuth returns a gin.HandlerFunc that enforces agent token
// authentication.  The middleware aborts with 401 on any validation failure.
func (m *AgentAuthMiddleware) RequireAgentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		agentID, claims, ok := m.authenticateAgentToken(c)
		if !ok {
			return
		}

		if blocked := m.authorizeAgentRequest(c, agentID); blocked {
			return
		}

		setAgentContext(c, agentID, claims)
		c.Next()
	}
}

// authenticateAgentToken validates the bearer JWT and returns the parsed agent ID and claims.
// Returns false and aborts the request if validation fails.
func (m *AgentAuthMiddleware) authenticateAgentToken(c *gin.Context) (uuid.UUID, jwt.MapClaims, bool) {
	tokenString, err := extractBearerToken(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "agent authentication required"})
		return uuid.Nil, nil, false
	}

	claims, err := m.parseAgentJWT(tokenString)
	if err != nil {
		logger.Warn("Agent JWT validation failed",
			zap.Error(err),
			zap.String("remote_addr", RealClientIP(c)),
		)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent token"})
		return uuid.Nil, nil, false
	}

	agentIDStr, _ := claims["agent_id"].(string)
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "malformed agent token: invalid agent_id"})
		return uuid.Nil, nil, false
	}

	return agentID, claims, true
}

// authorizeAgentRequest performs real-time status and scope checks via the checker.
// Returns true if the request was blocked.
func (m *AgentAuthMiddleware) authorizeAgentRequest(c *gin.Context, agentID uuid.UUID) bool {
	if m.checker == nil {
		return false
	}

	status, err := m.checker.GetAgentStatus(c.Request.Context(), agentID)
	if err != nil {
		logger.Warn("Agent status check failed",
			zap.String("agent_id", agentID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "agent not found"})
		return true
	}
	if status != realmStatusActive {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "agent_not_active", "status": status})
		return true
	}

	allowed, err := m.checker.ValidateAgentScope(c.Request.Context(), agentID, c.Request.URL.Path, c.Request.Method)
	if err != nil {
		logger.Warn("Agent scope validation error",
			zap.String("agent_id", agentID.String()),
			zap.Error(err),
		)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "scope validation failed"})
		return true
	}
	if !allowed {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":  "agent_scope_denied",
			"path":   c.Request.URL.Path,
			"method": c.Request.Method,
		})
		return true
	}

	return false
}

// setAgentContext populates the Gin context with agent identity values.
func setAgentContext(c *gin.Context, agentID uuid.UUID, claims jwt.MapClaims) {
	c.Set(AgentIDKey, agentID)
	if agentType, ok := claims["agent_type"].(string); ok {
		c.Set(AgentTypeKey, agentType)
	}
	if tenantIDStr, ok := claims["tenant_id"].(string); ok {
		if tid, err := uuid.Parse(tenantIDStr); err == nil {
			c.Set(AgentTenantIDKey, tid)
		}
	}
	if caps, ok := claims["capabilities"].([]interface{}); ok {
		strs := make([]string, 0, len(caps))
		for _, v := range caps {
			if s, ok := v.(string); ok {
				strs = append(strs, s)
			}
		}
		c.Set(AgentCapabilitiesKey, strs)
	}
}

// parseAgentJWT validates the JWT signature and asserts it is an agent token.
func (m *AgentAuthMiddleware) parseAgentJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(m.jwtSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("JWT parse error: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	// Assert this is specifically an agent token, not a human user token.
	tokenType, _ := claims["type"].(string)
	if tokenType != "agent" {
		return nil, fmt.Errorf("token type %q is not an agent token", tokenType)
	}

	return claims, nil
}

// extractBearerToken extracts the raw JWT string from the Authorization header.
func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("missing or malformed Authorization header")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	return token, nil
}

// ==================== Context accessors ====================

// GetAgentID extracts the agent UUID set by AgentAuthMiddleware.
// Returns uuid.Nil if the context does not contain an agent identity.
func GetAgentID(c *gin.Context) uuid.UUID {
	v, exists := c.Get(AgentIDKey)
	if !exists {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// GetAgentCapabilities returns the capability slice set by AgentAuthMiddleware.
func GetAgentCapabilities(c *gin.Context) []string {
	v, exists := c.Get(AgentCapabilitiesKey)
	if !exists {
		return nil
	}
	caps, ok := v.([]string)
	if !ok {
		return nil
	}
	return caps
}

// AgentHasCapability returns true if the agent has the specified capability.
func AgentHasCapability(c *gin.Context, capability string) bool {
	caps := GetAgentCapabilities(c)
	for _, cap := range caps {
		if cap == capability {
			return true
		}
	}
	return false
}

// IsAgentRequest returns true if the current request was authenticated via
// the agent token middleware (i.e. it came from an AI agent, not a human).
func IsAgentRequest(c *gin.Context) bool {
	return GetAgentID(c) != uuid.Nil
}

// AgentStatusCheckerFunc is a functional adapter for AgentStatusChecker.
// It allows injecting status and scope checks without a full service dependency.
type AgentStatusCheckerFunc struct {
	GetStatusFn     func(ctx context.Context, agentID uuid.UUID) (string, error)
	ValidateScopeFn func(ctx context.Context, agentID uuid.UUID, path, method string) (bool, error)
}

// GetAgentStatus implements AgentStatusChecker.
func (f *AgentStatusCheckerFunc) GetAgentStatus(ctx context.Context, agentID uuid.UUID) (string, error) {
	if f.GetStatusFn == nil {
		return realmStatusActive, nil
	}
	return f.GetStatusFn(ctx, agentID)
}

// ValidateAgentScope implements AgentStatusChecker.
func (f *AgentStatusCheckerFunc) ValidateAgentScope(ctx context.Context, agentID uuid.UUID, path, method string) (bool, error) {
	if f.ValidateScopeFn == nil {
		return true, nil
	}
	return f.ValidateScopeFn(ctx, agentID, path, method)
}
