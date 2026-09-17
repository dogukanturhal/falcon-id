// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/worker"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	outboxStatusHealthy   = "healthy"
	outboxStatusDegraded  = "degraded"
	outboxStatusUnhealthy = "unhealthy"
)

// OutboxHandler handles HTTP requests for outbox monitoring
type OutboxHandler struct {
	outboxProcessor *worker.OutboxProcessor
}

// NewOutboxHandler creates a new outbox handler
func NewOutboxHandler(outboxProcessor *worker.OutboxProcessor) *OutboxHandler {
	return &OutboxHandler{
		outboxProcessor: outboxProcessor,
	}
}

// GetStats returns outbox statistics for monitoring
// GET /internal/outbox/stats
func (h *OutboxHandler) GetStats(c *gin.Context) {
	stats, err := h.outboxProcessor.GetStats(c.Request.Context())
	if err != nil {
		logger.Error("Failed to get outbox stats",
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve outbox statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetHealth returns outbox health status
// GET /internal/outbox/health
func (h *OutboxHandler) GetHealth(c *gin.Context) {
	stats, err := h.outboxProcessor.GetStats(c.Request.Context())
	if err != nil {
		logger.Error("Failed to get outbox health",
			zap.Error(err),
		)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": outboxStatusUnhealthy,
			"error":  "Failed to retrieve outbox statistics",
		})
		return
	}

	// Determine health status
	status := outboxStatusHealthy
	warnings := []string{}

	// Check for significant lag (more than 60 seconds)
	if stats.LagSeconds != nil && *stats.LagSeconds > 60 {
		status = outboxStatusDegraded
		warnings = append(warnings, "High outbox lag detected")
	}

	// Check for high failure rate
	totalEvents := stats.PendingCount + stats.ProcessingCount + stats.FailedCount + stats.CompletedCount
	if totalEvents > 0 {
		failureRate := float64(stats.FailedCount) / float64(totalEvents)
		if failureRate > 0.1 { // More than 10% failure rate
			status = outboxStatusDegraded
			warnings = append(warnings, "High failure rate detected")
		}
	}

	// Check for stuck processing events
	if stats.ProcessingCount > 100 {
		status = outboxStatusDegraded
		warnings = append(warnings, "High number of events stuck in processing")
	}

	response := gin.H{
		"status":           status,
		"pending_count":    stats.PendingCount,
		"processing_count": stats.ProcessingCount,
		"failed_count":     stats.FailedCount,
		"completed_count":  stats.CompletedCount,
		"lag_seconds":      stats.LagSeconds,
		"poll_interval":    stats.PollInterval.String(),
		"batch_size":       stats.BatchSize,
	}

	if len(warnings) > 0 {
		response["warnings"] = warnings
	}

	httpStatus := http.StatusOK
	if status == outboxStatusDegraded {
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, response)
}
