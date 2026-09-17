// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgFederationInvalidTrustID = "invalid trust ID"
)

// RealmFederationHandler handles cross-realm federation trust management.
type RealmFederationHandler struct {
	service *services.RealmFederationService
}

// NewRealmFederationHandler constructs a RealmFederationHandler.
func NewRealmFederationHandler(service *services.RealmFederationService) *RealmFederationHandler {
	return &RealmFederationHandler{service: service}
}

// CreateTrust creates a new federation trust between two realms.
// POST /api/v1/platform/federation/trusts
func (h *RealmFederationHandler) CreateTrust(c *gin.Context) {
	var req models.CreateFederationTrustRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	requestedBy := extractActorID(c)

	resp, err := h.service.CreateTrust(c.Request.Context(), &req, requestedBy)
	if err != nil {
		logger.Error("RealmFederationHandler.CreateTrust: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": resp})
}

// ListTrusts returns a paginated list of federation trusts.
// GET /api/v1/platform/federation/trusts
func (h *RealmFederationHandler) ListTrusts(c *gin.Context) {
	filter := models.FederationTrustListFilter{
		Page:     queryInt(c, "page", 1),
		PageSize: queryInt(c, "page_size", 20),
	}

	if v := c.Query("source_realm_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.SourceRealmID = &id
		}
	}
	if v := c.Query("target_realm_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.TargetRealmID = &id
		}
	}
	if v := c.Query("status"); v != "" {
		st := models.FederationTrustStatus(v)
		filter.Status = &st
	}

	resp, err := h.service.ListTrusts(c.Request.Context(), filter)
	if err != nil {
		logger.Error("RealmFederationHandler.ListTrusts: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list federation trusts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// GetTrust retrieves a single federation trust by ID.
// GET /api/v1/platform/federation/trusts/:id
func (h *RealmFederationHandler) GetTrust(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgFederationInvalidTrustID})
		return
	}

	resp, err := h.service.GetTrust(c.Request.Context(), id)
	if err != nil {
		logger.Error("RealmFederationHandler.GetTrust: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to get trust"})
		return
	}
	if resp == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "trust not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// UpdateTrust modifies a federation trust record.
// PUT /api/v1/platform/federation/trusts/:id
func (h *RealmFederationHandler) UpdateTrust(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgFederationInvalidTrustID})
		return
	}

	var req models.UpdateFederationTrustRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	actorID := extractActorID(c)

	resp, err := h.service.UpdateTrust(c.Request.Context(), id, &req, actorID)
	if err != nil {
		logger.Error("RealmFederationHandler.UpdateTrust: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// ApproveTrust activates a pending federation trust.
// POST /api/v1/platform/federation/trusts/:id/approve
func (h *RealmFederationHandler) ApproveTrust(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgFederationInvalidTrustID})
		return
	}

	var req models.ApproveFederationTrustRequest
	_ = c.ShouldBindJSON(&req) // reason is optional

	approvedBy := extractActorID(c)

	resp, err := h.service.ApproveTrust(c.Request.Context(), id, &req, approvedBy)
	if err != nil {
		logger.Error("RealmFederationHandler.ApproveTrust: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// SuspendTrust suspends an active federation trust.
// POST /api/v1/platform/federation/trusts/:id/suspend
func (h *RealmFederationHandler) SuspendTrust(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgFederationInvalidTrustID})
		return
	}

	var req models.SuspendFederationTrustRequest
	_ = c.ShouldBindJSON(&req) // reason is optional

	actorID := extractActorID(c)

	resp, err := h.service.SuspendTrust(c.Request.Context(), id, &req, actorID)
	if err != nil {
		logger.Error("RealmFederationHandler.SuspendTrust: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// DeleteTrust hard-deletes a federation trust.
// DELETE /api/v1/platform/federation/trusts/:id
func (h *RealmFederationHandler) DeleteTrust(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": msgFederationInvalidTrustID})
		return
	}

	actorID := extractActorID(c)

	if err := h.service.DeleteTrust(c.Request.Context(), id, actorID); err != nil {
		logger.Error("RealmFederationHandler.DeleteTrust: failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "federation trust deleted"})
}

// ==================== helpers ====================

// extractActorID pulls the authenticated user's ID from Gin context.
// Returns uuid.Nil when absent (platform-level auth should enforce presence upstream).
func extractActorID(c *gin.Context) uuid.UUID {
	v, _ := c.Get("user_id")
	if s, ok := v.(string); ok {
		if id, err := uuid.Parse(s); err == nil {
			return id
		}
	}
	return uuid.Nil
}
