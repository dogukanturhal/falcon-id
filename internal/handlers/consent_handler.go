// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

const (
	msgInvalidRequestBodyConsent = "invalid request body"
	hdrUserAgentConsent          = "User-Agent"
	msgConsentGranted            = "Consent granted successfully"
	msgConsentRevoked            = "Consent revoked successfully"
)

// ConsentHandler is an exported type.
type ConsentHandler struct {
	consentService *services.ConsentService
}

// NewConsentHandler is an exported function.
func NewConsentHandler(consentService *services.ConsentService) *ConsentHandler {
	return &ConsentHandler{
		consentService: consentService,
	}
}

// GetConsentTypes returns all active consent types for the user's tenant
// @Summary Get consent types
// @Description Returns all active consent types available for the tenant
// @Tags Consent
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.ConsentTypeResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/types [get]
func (h *ConsentHandler) GetConsentTypes(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	types, err := h.consentService.GetConsentTypes(c.Request.Context(), user.TenantID)
	if err != nil {
		logger.Error("Failed to get consent types", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get consent types"})
		return
	}

	responses := make([]models.ConsentTypeResponse, len(types))
	for i, t := range types {
		responses[i] = *t.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// GetUserConsents returns all consents for the current user
// @Summary Get user consents
// @Description Returns all consents for the authenticated user with pending required consents
// @Tags Consent
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.ConsentListResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents [get]
func (h *ConsentHandler) GetUserConsents(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	response, err := h.consentService.GetUserConsents(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		logger.Error("Failed to get user consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user consents"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// UpdateConsent grants or revokes a specific consent
// @Summary Update consent
// @Description Grant or revoke a specific consent type
// @Tags Consent
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param type path string true "Consent type name"
// @Param request body models.UpdateConsentRequest true "Consent update request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/{type} [post]
func (h *ConsentHandler) UpdateConsent(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	consentType := c.Param("type")
	if consentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "consent type is required"})
		return
	}

	var req models.UpdateConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestBodyConsent})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader(hdrUserAgentConsent)

	if err := h.consentService.UpdateConsent(c.Request.Context(), user.ID, user.TenantID, consentType, req.Granted, ipAddress, userAgent); err != nil {
		logger.Error("Failed to update consent",
			zap.Error(err),
			zap.String("consent_type", consentType),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	message := msgConsentGranted
	if !req.Granted {
		message = msgConsentRevoked
	}

	c.JSON(http.StatusOK, gin.H{"message": message})
}

// UpdateConsentByID grants or revokes a consent by ID
// @Summary Update consent by ID
// @Description Grant or revoke a consent by consent type ID
// @Tags Consent
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Consent type ID"
// @Param request body models.UpdateConsentRequest true "Consent update request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/id/{id} [post]
func (h *ConsentHandler) UpdateConsentByID(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	consentTypeID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid consent type ID"})
		return
	}

	var req models.UpdateConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestBodyConsent})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader(hdrUserAgentConsent)

	if err := h.consentService.UpdateConsentByID(c.Request.Context(), user.ID, user.TenantID, consentTypeID, req.Granted, ipAddress, userAgent); err != nil {
		logger.Error("Failed to update consent",
			zap.Error(err),
			zap.String("consent_type_id", consentTypeID.String()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	message := msgConsentGranted
	if !req.Granted {
		message = msgConsentRevoked
	}

	c.JSON(http.StatusOK, gin.H{"message": message})
}

// BulkUpdateConsents updates multiple consents at once
// @Summary Bulk update consents
// @Description Grant or revoke multiple consents at once
// @Tags Consent
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body models.BulkConsentRequest true "Bulk consent update request"
// @Success 200 {object} models.MessageResponse
// @Failure 400 {object} models.ErrorResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/bulk [post]
func (h *ConsentHandler) BulkUpdateConsents(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req models.BulkConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRequestBodyConsent})
		return
	}

	if len(req.Consents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no consents provided"})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader(hdrUserAgentConsent)

	if err := h.consentService.BulkUpdateConsents(c.Request.Context(), user.ID, user.TenantID, req.Consents, ipAddress, userAgent); err != nil {
		logger.Error("Failed to bulk update consents", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Consents updated successfully"})
}

// GetConsentHistory returns consent history for the current user
// @Summary Get consent history
// @Description Returns consent change history for the authenticated user
// @Tags Consent
// @Security BearerAuth
// @Produce json
// @Param days query int false "Number of days to look back" default(30)
// @Success 200 {array} models.UserConsentResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/history [get]
func (h *ConsentHandler) GetConsentHistory(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	days := parseClampedInt(c.Query("days"), 30, 1, 365)

	since := time.Now().AddDate(0, 0, -days)

	history, err := h.consentService.GetConsentHistory(c.Request.Context(), user.ID, since)
	if err != nil {
		logger.Error("Failed to get consent history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get consent history"})
		return
	}

	responses := make([]models.UserConsentResponse, len(history))
	for i, h := range history {
		responses[i] = *h.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// CheckPendingConsents checks if user has pending required consents
// @Summary Check pending consents
// @Description Returns whether the user has any pending required consents
// @Tags Consent
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/pending [get]
func (h *ConsentHandler) CheckPendingConsents(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hasAllRequired, err := h.consentService.HasGrantedAllRequired(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		logger.Error("Failed to check pending consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check pending consents"})
		return
	}

	var pending []models.ConsentTypeResponse
	if !hasAllRequired {
		pendingTypes, err := h.consentService.GetPendingRequiredConsents(c.Request.Context(), user.ID, user.TenantID)
		if err != nil {
			logger.Error("Failed to get pending consents", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get pending consents"})
			return
		}

		pending = make([]models.ConsentTypeResponse, len(pendingTypes))
		for i, p := range pendingTypes {
			pending[i] = *p.ToResponse()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"has_pending_required": !hasAllRequired,
		"pending_consents":     pending,
	})
}

// GetConsentHistoryDetailed returns detailed consent history from the history table
// @Summary Get detailed consent history
// @Description Returns detailed immutable audit trail of consent changes
// @Tags Consent
// @Security BearerAuth
// @Produce json
// @Param limit query int false "Number of records to return" default(50) maximum(100)
// @Success 200 {array} models.ConsentHistoryResponse
// @Failure 401 {object} models.ErrorResponse
// @Failure 500 {object} models.ErrorResponse
// @Router /api/v1/auth/consents/history/detailed [get]
func (h *ConsentHandler) GetConsentHistoryDetailed(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit := parseClampedInt(c.Query("limit"), 50, 1, 100)

	history, err := h.consentService.GetConsentHistoryDetailed(c.Request.Context(), user.ID, user.TenantID, limit)
	if err != nil {
		logger.Error("Failed to get detailed consent history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get consent history"})
		return
	}

	responses := make([]models.ConsentHistoryResponse, len(history))
	for i, h := range history {
		responses[i] = *h.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// parseClampedInt parses a string as an integer, returning defaultVal if the string is
// empty or unparseable, and clamping the result to [lo, hi].
func parseClampedInt(s string, defaultVal, lo, hi int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
