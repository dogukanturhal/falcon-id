// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
)

// PermissionStreamHandler serves a Server-Sent Events (SSE) stream that
// delivers real-time permission change notifications to authenticated users.
//
// The handler subscribes to the Redis Pub/Sub channel
// "hexxlock:permissions:<userID>" and forwards each message as an SSE event.
// The WatchService writes to that channel whenever SpiceDB reports a
// relationship change for the user (via RegisterUserNotificationHandler), and
// UserHandler.SetRoles writes to it after a direct DB role mutation so that
// changes propagate even when they bypass SpiceDB.
type PermissionStreamHandler struct {
	redis  *goredis.Client
	logger *zap.Logger
}

// NewPermissionStreamHandler constructs a PermissionStreamHandler.
// redis must be a concrete *redis.Client (not a universal client), consistent
// with how every other component in this service uses the go-redis client.
func NewPermissionStreamHandler(redis *goredis.Client, logger *zap.Logger) *PermissionStreamHandler {
	return &PermissionStreamHandler{redis: redis, logger: logger}
}

// Stream handles GET /api/v1/auth/permissions/stream.
//
// The endpoint upgrades the HTTP connection to a long-lived SSE stream.
// Browsers should reconnect automatically on disconnect (SSE semantics).
// The heartbeat tick (every 30 s) keeps the connection alive through proxies
// that aggressively close idle connections.
//
// Events emitted:
//   - "connected"          – immediately after the stream is established
//   - "permission_changed" – when a permission mutation is detected
//   - "heartbeat"          – every 30 seconds to keep the connection alive
func (h *PermissionStreamHandler) Stream(c *gin.Context) {
	if h.redis == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "real-time permission streaming requires Redis",
		})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	userID := currentUser.ID.String()
	channel := fmt.Sprintf("hexxlock:permissions:%s", userID)

	// SSE response headers — must be set before the first write.
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	// Disable Nginx/APISIX response buffering so events are flushed immediately.
	c.Header("X-Accel-Buffering", "no")

	ctx := c.Request.Context()

	sub := h.redis.Subscribe(ctx, channel)
	defer func() {
		// Best-effort close; the context may already be cancelled.
		_ = sub.Close()
	}()

	// Send the initial "connected" event so the client knows the stream is live.
	_, _ = fmt.Fprintf(c.Writer, "event: connected\ndata: {\"user_id\":\"%s\"}\n\n", userID)
	c.Writer.Flush()

	h.logger.Info("Permission stream connected",
		zap.String("user_id", userID),
		zap.String("channel", channel),
	)

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	msgCh := sub.Channel()

	for {
		select {
		case <-ctx.Done():
			h.logger.Info("Permission stream disconnected (client gone)",
				zap.String("user_id", userID),
			)
			return

		case msg, ok := <-msgCh:
			if !ok {
				// Redis unsubscribed or connection dropped.
				h.logger.Warn("Permission stream Redis channel closed",
					zap.String("user_id", userID),
					zap.String("channel", channel),
				)
				return
			}
			_, _ = fmt.Fprintf(c.Writer, "event: permission_changed\ndata: %s\n\n", msg.Payload)
			c.Writer.Flush()

		case t := <-heartbeat.C:
			_, _ = fmt.Fprintf(c.Writer, "event: heartbeat\ndata: {\"ts\":\"%s\"}\n\n", t.UTC().Format(time.RFC3339))
			c.Writer.Flush()
		}
	}
}
