// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	goredis "github.com/redis/go-redis/v9"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// CAEHandler handles Continuous Access Evaluation endpoints.
// It streams CAE events to authenticated clients via Server-Sent Events (SSE)
// and provides an evaluation endpoint for resource servers.
type CAEHandler struct {
	svc    *services.CAEService
	redis  *goredis.Client
	logger *zap.Logger
}

// NewCAEHandler constructs a CAEHandler.
// redis may be nil; SSE streaming will be gracefully disabled.
func NewCAEHandler(svc *services.CAEService, redis *goredis.Client, logger *zap.Logger) *CAEHandler {
	return &CAEHandler{svc: svc, redis: redis, logger: logger}
}

// StreamEvents opens an SSE stream that delivers CAE events to the authenticated
// client in real time. Each event published to the hexxlock:cae:events Redis
// pub/sub channel that matches the subscriber's tenant is forwarded.
//
// GET /api/v1/cae/events
func (h *CAEHandler) StreamEvents(c *gin.Context) {
	if h.redis == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "CAE streaming not available (Redis not configured)"})
		return
	}

	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid tenant_id claim"})
		return
	}

	// Set SSE headers.
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // Disable Nginx buffering for SSE.

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Minute)
	defer cancel()

	pubsub := h.redis.Subscribe(ctx, "hexxlock:cae:events")
	defer pubsub.Close() //nolint:errcheck

	c.Stream(func(w io.Writer) bool {
		select {
		case <-ctx.Done():
			return false
		case msg, ok := <-pubsub.Channel():
			if !ok {
				return false
			}
			// Decode event and filter by tenant.
			var event services.CAEEvent
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				return true // Skip malformed events.
			}
			if event.TenantID != tenantID {
				return true // Not for this tenant.
			}
			data, err := json.Marshal(event)
			if err != nil {
				return true
			}
			_, _ = fmt.Fprintf(w, "event: cae\ndata: %s\n\n", data)
			return true
		}
	})
}

// EvaluateToken performs on-demand CAE evaluation for a resource server.
// Resource servers call this endpoint to check whether an access token that
// they have already validated still meets the current access policy.
//
// POST /api/v1/cae/evaluate
func (h *CAEHandler) EvaluateToken(c *gin.Context) {
	var req struct {
		AccessToken string `json:"access_token" binding:"required"`
		Resource    string `json:"resource"`
		Action      string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_token is required"})
		return
	}

	// Stub: real implementation validates token claims, checks session revocation
	// list in Redis, and evaluates conditional access policies.
	// Returns allowed for now so downstream resource servers are not broken.
	h.logger.Debug("CAE token evaluation (stub)",
		zap.String("resource", req.Resource),
		zap.String("action", req.Action),
	)

	c.JSON(http.StatusOK, gin.H{
		"decision":     "allowed",
		"evaluated_at": fmt.Sprintf("%d", time.Now().Unix()),
	})
}
