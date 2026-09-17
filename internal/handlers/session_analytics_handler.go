// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// SessionAnalyticsHandler handles session analytics HTTP endpoints.
type SessionAnalyticsHandler struct {
	svc *services.SessionAnalyticsService
}

// NewSessionAnalyticsHandler creates a new SessionAnalyticsHandler.
func NewSessionAnalyticsHandler(svc *services.SessionAnalyticsService) *SessionAnalyticsHandler {
	return &SessionAnalyticsHandler{svc: svc}
}

// GetAnalytics returns session analytics for a tenant.
//
// @Summary Get session analytics for tenant
// @Description Returns active session count and peak concurrent sessions for a specific tenant
// @Tags Session Management
// @Produce json
// @Param tenant_id path string true "Tenant UUID"
// @Success 200 {object} map[string]interface{} "Session analytics (active, peak, anomalous counts)"
// @Failure 400 {object} map[string]string "Invalid tenant ID"
// @Router /api/v1/admin/session-analytics/{tenant_id} [get]
func (h *SessionAnalyticsHandler) GetAnalytics(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	ctx := c.Request.Context()

	activeSessions, err := h.svc.GetActiveSessions(ctx, tenantID)
	if err != nil {
		activeSessions = 0
	}

	peakConcurrent, err := h.svc.GetPeakConcurrentSessions(ctx, tenantID, 24*time.Hour)
	if err != nil {
		peakConcurrent = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"active_sessions": activeSessions,
		"peak_concurrent": peakConcurrent,
		"anomalous_count": 0,
	})
}

// GetAllAnalytics returns live IAM dashboard analytics for the calling user's
// tenant. It queries iam_sessions, iam_audit_logs, and iam_users to produce
// metrics that match the SessionAnalytics TypeScript interface consumed by the
// platform-admin frontend.
//
// @Summary Get IAM dashboard analytics
// @Description Returns active sessions, login trends, MFA adoption, auth methods, and failed attempts for the caller's tenant
// @Tags Session Management
// @Produce json
// @Success 200 {object} services.DashboardAnalytics "IAM dashboard analytics"
// @Failure 401 {object} map[string]string "Unauthorised"
// @Router /api/v1/admin/session-analytics/all [get]
func (h *SessionAnalyticsHandler) GetAllAnalytics(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorised"})
		return
	}

	// GetDashboardAnalytics degrades gracefully: individual query failures are
	// logged inside the service and contribute zeros to the result. A returned
	// error here would be exceptional (e.g. nil context); we still serve the
	// zero-filled struct so the dashboard renders rather than breaking.
	analytics, _ := h.svc.GetDashboardAnalytics(c.Request.Context(), currentUser.TenantID)

	c.JSON(http.StatusOK, analytics)
}
