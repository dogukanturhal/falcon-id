// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ITDRHandler handles HTTP requests for Identity Threat Detection and Response.
type ITDRHandler struct {
	svc    *services.ITDRService
	logger *zap.Logger
}

// NewITDRHandler constructs an ITDRHandler.
func NewITDRHandler(svc *services.ITDRService, logger *zap.Logger) *ITDRHandler {
	return &ITDRHandler{svc: svc, logger: logger}
}

// ListThreats returns a paginated list of detected threats.
//
// GET /api/v1/platform/security/threats
func (h *ITDRHandler) ListThreats(c *gin.Context) {
	tenantIDStr := c.Query("tenant_id")
	var tenantID uuid.UUID
	if tenantIDStr != "" {
		var err error
		tenantID, err = uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
			return
		}
	}

	threats, total, err := h.svc.ListThreats(c.Request.Context(), tenantID, 50, 0)
	if err != nil {
		h.logger.Error("ITDRHandler.ListThreats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list threats"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"threats": threats, "total": total})
}

// GetThreat returns a single threat by ID.
//
// GET /api/v1/platform/security/threats/:id
func (h *ITDRHandler) GetThreat(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid threat id"})
		return
	}

	threat, err := h.svc.GetThreat(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "threat not found"})
		} else {
			h.logger.Error("ITDRHandler.GetThreat", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}
	c.JSON(http.StatusOK, threat)
}

// AcknowledgeThreat marks a threat as acknowledged by the authenticated operator.
//
// POST /api/v1/platform/security/threats/:id/acknowledge
func (h *ITDRHandler) AcknowledgeThreat(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid threat id"})
		return
	}

	// Extract operator identity from JWT claims set by auth middleware.
	operatorIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}
	operatorID, ok := operatorIDStr.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user_id claim"})
		return
	}

	if err := h.svc.AcknowledgeThreat(c.Request.Context(), id, operatorID); err != nil {
		h.logger.Error("ITDRHandler.AcknowledgeThreat", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to acknowledge threat"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "acknowledged"})
}

// ListDetectionRules returns all configured detection rules.
//
// GET /api/v1/platform/security/detection-rules
func (h *ITDRHandler) ListDetectionRules(c *gin.Context) {
	rules, total, err := h.svc.ListDetectionRules(c.Request.Context(), 100, 0)
	if err != nil {
		h.logger.Error("ITDRHandler.ListDetectionRules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list detection rules"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": total})
}

// UpdateDetectionRule updates a detection rule's configuration.
//
// PUT /api/v1/platform/security/detection-rules/:id
func (h *ITDRHandler) UpdateDetectionRule(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule id"})
		return
	}

	var rule models.ITDRDetectionRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	rule.ID = id

	if err := h.svc.UpdateDetectionRule(c.Request.Context(), &rule); err != nil {
		h.logger.Error("ITDRHandler.UpdateDetectionRule", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update detection rule"})
		return
	}
	c.JSON(http.StatusOK, &rule)
}
