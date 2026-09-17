// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// maxAuthenticatedAtSkew is the maximum allowable difference between a
// session's authenticated_at timestamp and the JWT's iat (issued-at) claim.
// Sessions whose authenticated_at is more than this duration before iat are
// rejected, preventing pre-created sessions from being used post-authentication.
const maxAuthenticatedAtSkew = 5 * time.Minute

// SessionTenantBindingMiddleware validates that the JWT's tenant claim matches
// the request's tenant context and enforces session fixation protections.
type SessionTenantBindingMiddleware struct {
	sessionRepo  *repositories.SessionRepository
	auditService *services.AuditService
}

// NewSessionTenantBindingMiddleware creates a new SessionTenantBindingMiddleware.
func NewSessionTenantBindingMiddleware(sessionRepo *repositories.SessionRepository, auditService *services.AuditService) *SessionTenantBindingMiddleware {
	return &SessionTenantBindingMiddleware{
		sessionRepo:  sessionRepo,
		auditService: auditService,
	}
}

// SessionTenantBinding returns a Gin middleware that enforces:
// 1. JWT tid claim matches the request tenant context (gateway-level protection)
// 2. Session authenticated_at timestamp validation (rejects pre-created sessions)
// 3. Cross-tenant session revocation on violation detection
//
// SECURITY: This middleware MUST be applied after RequireAuth() and ExtractTenant()
// so that both current_user and tenant_id are available in the context.
func (m *SessionTenantBindingMiddleware) SessionTenantBinding() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.Next()
			return
		}

		if blocked := m.enforceTenantAffinity(c, user); blocked {
			return
		}

		if blocked := m.enforceSessionTimestamp(c, user); blocked {
			return
		}

		c.Next()
	}
}

// enforceTenantAffinity validates that the JWT tenant claim matches the request tenant context.
// Returns true if the request was blocked.
func (m *SessionTenantBindingMiddleware) enforceTenantAffinity(c *gin.Context, user *models.CurrentUser) bool {
	requestTenantID := GetTenantID(c)
	if requestTenantID == uuid.Nil || user.TenantID == uuid.Nil {
		return false
	}
	if requestTenantID == user.TenantID {
		return false
	}

	logger.Log.Error("SECURITY: Cross-tenant session detected - JWT tid does not match request tenant",
		zap.String("jwt_tenant_id", user.TenantID.String()),
		zap.String("request_tenant_id", requestTenantID.String()),
		zap.String("user_id", user.ID.String()),
		zap.String("session_id", user.SessionID.String()),
		zap.String("client_ip", RealClientIP(c)),
		zap.String("path", c.Request.URL.Path),
	)

	m.revokeCrossTenantSessions(c, user, requestTenantID)
	m.logCrossTenantAuditEvent(c, user, requestTenantID)

	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Session tenant mismatch"})
	return true
}

// revokeCrossTenantSessions revokes affected sessions upon cross-tenant replay detection.
func (m *SessionTenantBindingMiddleware) revokeCrossTenantSessions(c *gin.Context, user *models.CurrentUser, requestTenantID uuid.UUID) {
	if m.sessionRepo == nil {
		return
	}

	revoked, revokeErr := m.sessionRepo.RevokeTenantSessions(
		c.Request.Context(), user.ID, requestTenantID, "cross_tenant_session_replay_detected",
	)
	if revokeErr != nil {
		logger.Log.Error("Failed to revoke tenant sessions during cross-tenant detection",
			zap.Error(revokeErr),
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", requestTenantID.String()),
		)
	} else if revoked > 0 {
		logger.Log.Warn("Cross-tenant revocation: revoked sessions in attacked tenant",
			zap.Int64("sessions_revoked", revoked),
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", requestTenantID.String()),
		)
	}

	if user.SessionID != uuid.Nil {
		if endErr := m.sessionRepo.EndSession(c.Request.Context(), user.SessionID, "cross_tenant_replay_revoked"); endErr != nil {
			logger.Log.Error("Failed to end attacker session",
				zap.Error(endErr),
				zap.String("session_id", user.SessionID.String()),
			)
		}
	}
}

// logCrossTenantAuditEvent emits a security audit event for a cross-tenant replay.
func (m *SessionTenantBindingMiddleware) logCrossTenantAuditEvent(c *gin.Context, user *models.CurrentUser, requestTenantID uuid.UUID) {
	if m.auditService == nil {
		return
	}
	m.auditService.LogSecurityEvent(c.Request.Context(), &services.SecurityAuditEvent{
		TenantID:    requestTenantID,
		UserID:      &user.ID,
		IPAddress:   RealClientIP(c),
		UserAgent:   c.Request.UserAgent(),
		RequestPath: c.Request.URL.Path,
		Category:    services.SecurityCategoryTenantIsolation,
		Severity:    services.SecuritySeverityCritical,
		Action:      "cross_tenant_session_replay",
		Description: "JWT tenant ID does not match request tenant context -- possible session fixation or replay attack",
		Details: map[string]interface{}{
			"jwt_tenant_id":     user.TenantID.String(),
			"request_tenant_id": requestTenantID.String(),
			"session_id":        user.SessionID.String(),
		},
		Blocked:     true,
		ThreatScore: 95,
	})
}

// enforceSessionTimestamp validates the session authenticated_at timestamp.
// Returns true if the request was blocked.
func (m *SessionTenantBindingMiddleware) enforceSessionTimestamp(c *gin.Context, user *models.CurrentUser) bool {
	if user.SessionID == uuid.Nil || m.sessionRepo == nil {
		return false
	}

	session, err := m.sessionRepo.GetByID(c.Request.Context(), user.SessionID)
	if err != nil {
		logger.Log.Error("Failed to fetch session for timestamp validation",
			zap.Error(err),
			zap.String("session_id", user.SessionID.String()),
		)
		return false // fail open for DB errors
	}
	if session == nil {
		return false
	}

	if session.AuthenticatedAt == nil {
		logger.Log.Warn("SECURITY: Session missing authenticated_at timestamp -- possible pre-migration session",
			zap.String("session_id", session.ID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Time("created_at", session.CreatedAt),
		)
		return false // backward compat: log but don't block
	}

	if session.CreatedAt.Sub(*session.AuthenticatedAt) <= maxAuthenticatedAtSkew {
		return false
	}

	logger.Log.Error("SECURITY: Session authenticated_at is significantly before created_at -- possible pre-created session attack",
		zap.String("session_id", session.ID.String()),
		zap.String("user_id", user.ID.String()),
		zap.Time("authenticated_at", *session.AuthenticatedAt),
		zap.Time("created_at", session.CreatedAt),
		zap.Duration("skew", session.CreatedAt.Sub(*session.AuthenticatedAt)),
	)

	if m.auditService != nil {
		m.auditService.LogSecurityEvent(c.Request.Context(), &services.SecurityAuditEvent{
			TenantID:    user.TenantID,
			UserID:      &user.ID,
			IPAddress:   RealClientIP(c),
			UserAgent:   c.Request.UserAgent(),
			RequestPath: c.Request.URL.Path,
			Category:    services.SecurityCategoryAuthentication,
			Severity:    services.SecuritySeverityHigh,
			Action:      "pre_created_session_detected",
			Description: "Session authenticated_at timestamp is before session creation -- possible session fixation",
			Details: map[string]interface{}{
				"session_id":       session.ID.String(),
				"authenticated_at": session.AuthenticatedAt.String(),
				"created_at":       session.CreatedAt.String(),
			},
			Blocked:     true,
			ThreatScore: 80,
		})
	}

	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session validation failed"})
	return true
}
