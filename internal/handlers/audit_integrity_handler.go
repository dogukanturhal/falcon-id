// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// AuditIntegrityHandler exposes endpoints for verifying the immutable audit chain.
type AuditIntegrityHandler struct {
	service *services.ImmutableAuditService
	logger  *zap.Logger
}

// NewAuditIntegrityHandler creates a new AuditIntegrityHandler.
func NewAuditIntegrityHandler(service *services.ImmutableAuditService, logger *zap.Logger) *AuditIntegrityHandler {
	return &AuditIntegrityHandler{
		service: service,
		logger:  logger,
	}
}

// VerifyChainIntegrity handles GET /audit/verify
//
// Query parameters:
//   - tenant_id  string   (required)
//   - from        RFC3339  (optional, defaults to 30 days ago)
//   - to          RFC3339  (optional, defaults to now)
//
// Response 200: { "ok": true, "entries_in_range": N }
// Response 400: { "error": "..." }
// Response 500: { "error": "..." }
func (h *AuditIntegrityHandler) VerifyChainIntegrity(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id query parameter is required"})
		return
	}

	now := time.Now().UTC()
	from := now.AddDate(0, 0, -30) // default: last 30 days
	to := now

	if fromStr := c.Query("from"); fromStr != "" {
		parsed, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'from' timestamp, expected RFC3339"})
			return
		}
		from = parsed
	}

	if toStr := c.Query("to"); toStr != "" {
		parsed, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'to' timestamp, expected RFC3339"})
			return
		}
		to = parsed
	}

	if from.After(to) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "'from' must be before 'to'"})
		return
	}

	ok, err := h.service.VerifyChainIntegrity(c.Request.Context(), tenantID, from, to)
	if err != nil {
		h.logger.Warn("Audit chain integrity verification failed",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		c.JSON(http.StatusOK, gin.H{
			"ok":    false,
			"error": err.Error(),
			"from":  from,
			"to":    to,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":        ok,
		"tenant_id": tenantID,
		"from":      from,
		"to":        to,
	})
}
