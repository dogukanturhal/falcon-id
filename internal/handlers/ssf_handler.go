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

const (
	msgSSFInvalidStreamID = "invalid stream id"
)

// SSFHandler handles HTTP requests for Shared Signals Framework stream management.
type SSFHandler struct {
	svc    *services.SSFService
	logger *zap.Logger
}

// NewSSFHandler constructs an SSFHandler.
func NewSSFHandler(svc *services.SSFService, logger *zap.Logger) *SSFHandler {
	return &SSFHandler{svc: svc, logger: logger}
}

// GetConfiguration returns the SSF discovery metadata document.
//
// GET /.well-known/ssf-configuration
func (h *SSFHandler) GetConfiguration(c *gin.Context) {
	cfg := h.svc.GetConfiguration()
	c.JSON(http.StatusOK, cfg)
}

// CreateStream creates a new SSF event stream subscription.
//
// POST /api/v1/ssf/streams
func (h *SSFHandler) CreateStream(c *gin.Context) {
	var stream models.SSFStream
	if err := c.ShouldBindJSON(&stream); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	stream.ID = uuid.New()

	if err := h.svc.CreateStream(c.Request.Context(), &stream); err != nil {
		h.logger.Error("SSFHandler.CreateStream", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create stream"})
		return
	}
	c.JSON(http.StatusCreated, &stream)
}

// ListStreams returns all SSF streams for the requesting tenant.
//
// GET /api/v1/ssf/streams
func (h *SSFHandler) ListStreams(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant context required"})
		return
	}
	var tenantID uuid.UUID
	if id, ok := tenantIDVal.(uuid.UUID); ok {
		tenantID = id
	}

	streams, err := h.svc.ListStreams(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("SSFHandler.ListStreams", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list streams"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"streams": streams})
}

// GetStream returns a single SSF stream by ID.
//
// GET /api/v1/ssf/streams/:id
func (h *SSFHandler) GetStream(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSSFInvalidStreamID})
		return
	}

	stream, err := h.svc.GetStream(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "stream not found"})
		} else {
			h.logger.Error("SSFHandler.GetStream", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}
	c.JSON(http.StatusOK, stream)
}

// UpdateStream updates an existing SSF stream.
//
// PUT /api/v1/ssf/streams/:id
func (h *SSFHandler) UpdateStream(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSSFInvalidStreamID})
		return
	}

	var stream models.SSFStream
	if err := c.ShouldBindJSON(&stream); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	stream.ID = id

	if err := h.svc.UpdateStream(c.Request.Context(), &stream); err != nil {
		h.logger.Error("SSFHandler.UpdateStream", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update stream"})
		return
	}
	c.JSON(http.StatusOK, &stream)
}

// DeleteStream removes an SSF stream.
//
// DELETE /api/v1/ssf/streams/:id
func (h *SSFHandler) DeleteStream(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgSSFInvalidStreamID})
		return
	}

	if err := h.svc.DeleteStream(c.Request.Context(), id); err != nil {
		h.logger.Error("SSFHandler.DeleteStream", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete stream"})
		return
	}
	c.Status(http.StatusNoContent)
}
