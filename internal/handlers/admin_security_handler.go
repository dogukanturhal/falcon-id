// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgNotAuthenticatedSec           = "Not authenticated"
	msgRateLimitServiceNotConfigured = "Rate limit service not configured"
	msgInvalidRuleID                 = "Invalid rule ID"
	msgIPRuleServiceNotConfigured    = "IP rule service not configured"
)

// ==================== Password Policy Management ====================

// GetPasswordPolicy retrieves the password policy for the tenant
// @Summary Get Password Policy
// @Description Get the password policy settings for the tenant
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.PasswordPolicyResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/security/password-policy [get]
func (h *AdminHandler) GetPasswordPolicy(c *gin.Context) {
	if h.passwordPolicyService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password policy service not configured"})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	policy, err := h.passwordPolicyService.GetPolicy(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to get password policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get password policy"})
		return
	}

	c.JSON(http.StatusOK, policy.ToResponse())
}

// UpdatePasswordPolicy updates the password policy for the tenant
// @Summary Update Password Policy
// @Description Update the password policy settings for the tenant
// @Tags Admin - Security
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.PasswordPolicyRequest true "Password policy settings"
// @Success 200 {object} models.PasswordPolicyResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/security/password-policy [put]
func (h *AdminHandler) UpdatePasswordPolicy(c *gin.Context) {
	if h.passwordPolicyService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password policy service not configured"})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	var req models.PasswordPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.passwordPolicyService.UpdatePolicy(c.Request.Context(), currentUser.TenantID, &req, currentUser.ID)
	if err != nil {
		h.logger.Error("Failed to update password policy", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, policy.ToResponse())
}

// ==================== Rate Limit Management ====================

// ListRateLimitRules lists all rate limit rules for the tenant
// @Summary List Rate Limit Rules
// @Description Get all rate limit rules for the tenant
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.RateLimitRuleResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/security/rate-limits [get]
func (h *AdminHandler) ListRateLimitRules(c *gin.Context) {
	if h.rateLimitService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRateLimitServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	rules, err := h.rateLimitService.ListRules(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list rate limit rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rate limit rules"})
		return
	}

	responses := make([]*models.RateLimitRuleResponse, len(rules))
	for i, rule := range rules {
		responses[i] = rule.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// GetRateLimitRule retrieves a single rate limit rule
// @Summary Get Rate Limit Rule
// @Description Get a specific rate limit rule by ID
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Param id path string true "Rule ID"
// @Success 200 {object} models.RateLimitRuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/security/rate-limits/{id} [get]
func (h *AdminHandler) GetRateLimitRule(c *gin.Context) {
	if h.rateLimitService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRateLimitServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRuleID})
		return
	}

	rule, err := h.rateLimitService.GetRule(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get rate limit rule", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get rate limit rule"})
		return
	}

	if rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rate limit rule not found"})
		return
	}

	if rule.TenantID != nil && *rule.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rate limit rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule.ToResponse())
}

// CreateRateLimitRule creates a new rate limit rule
// @Summary Create Rate Limit Rule
// @Description Create a new rate limit rule for the tenant
// @Tags Admin - Security
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateRateLimitRuleRequest true "Rate limit rule settings"
// @Success 201 {object} models.RateLimitRuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/admin/security/rate-limits [post]
func (h *AdminHandler) CreateRateLimitRule(c *gin.Context) {
	if h.rateLimitService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRateLimitServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	var req models.CreateRateLimitRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.rateLimitService.CreateRule(c.Request.Context(), currentUser.TenantID, currentUser.ID, &req)
	if err != nil {
		h.logger.Error("Failed to create rate limit rule", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, rule.ToResponse())
}

// UpdateRateLimitRule updates an existing rate limit rule
// @Summary Update Rate Limit Rule
// @Description Update a rate limit rule
// @Tags Admin - Security
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Rule ID"
// @Param body body models.UpdateRateLimitRuleRequest true "Rate limit rule settings"
// @Success 200 {object} models.RateLimitRuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/security/rate-limits/{id} [put]
func (h *AdminHandler) UpdateRateLimitRule(c *gin.Context) {
	if h.rateLimitService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRateLimitServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRuleID})
		return
	}

	var req models.UpdateRateLimitRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.rateLimitService.UpdateRule(c.Request.Context(), currentUser.TenantID, currentUser.ID, id, &req)
	if err != nil {
		h.logger.Error("Failed to update rate limit rule", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rule.ToResponse())
}

// DeleteRateLimitRule deletes a rate limit rule
// @Summary Delete Rate Limit Rule
// @Description Delete a rate limit rule
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Param id path string true "Rule ID"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/security/rate-limits/{id} [delete]
func (h *AdminHandler) DeleteRateLimitRule(c *gin.Context) {
	if h.rateLimitService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRateLimitServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRuleID})
		return
	}

	if err := h.rateLimitService.DeleteRule(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to delete rate limit rule", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetRateLimitEvents retrieves rate limit events (blocked requests)
// @Summary Get Rate Limit Events
// @Description Get recent rate limit events for the tenant
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Param blocked_only query boolean false "Show only blocked events"
// @Param limit query int false "Number of events to return (default 100)"
// @Success 200 {array} models.RateLimitEventResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/security/rate-limits/events [get]
func (h *AdminHandler) GetRateLimitEvents(c *gin.Context) {
	if h.rateLimitService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRateLimitServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	blockedOnly := c.Query("blocked_only") == queryBoolTrue
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	events, err := h.rateLimitService.GetEvents(c.Request.Context(), currentUser.TenantID, limit, blockedOnly)
	if err != nil {
		h.logger.Error("Failed to get rate limit events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get rate limit events"})
		return
	}

	responses := make([]*models.RateLimitEventResponse, len(events))
	for i, event := range events {
		responses[i] = &models.RateLimitEventResponse{
			ID:           event.ID,
			RuleID:       event.RuleID,
			TenantID:     event.TenantID,
			Identifier:   event.Identifier,
			Endpoint:     event.Endpoint,
			RequestCount: event.RequestCount,
			Blocked:      event.Blocked,
			BlockedUntil: event.BlockedUntil,
			CreatedAt:    event.CreatedAt,
		}
	}

	c.JSON(http.StatusOK, responses)
}

// ==================== IP Rules Management ====================

// ListIPRules lists all IP rules for the tenant
// @Summary List IP Rules
// @Description Get all IP whitelist/blacklist rules for the tenant
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.IPRuleResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/security/ip-rules [get]
func (h *AdminHandler) ListIPRules(c *gin.Context) {
	if h.ipRuleService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgIPRuleServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	rules, err := h.ipRuleService.ListRules(c.Request.Context(), currentUser.TenantID)
	if err != nil {
		h.logger.Error("Failed to list IP rules", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list IP rules"})
		return
	}

	responses := make([]*models.IPRuleResponse, len(rules))
	for i, rule := range rules {
		responses[i] = rule.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// GetIPRule retrieves a single IP rule
// @Summary Get IP Rule
// @Description Get a specific IP rule by ID
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Param id path string true "Rule ID"
// @Success 200 {object} models.IPRuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/security/ip-rules/{id} [get]
func (h *AdminHandler) GetIPRule(c *gin.Context) {
	if h.ipRuleService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgIPRuleServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRuleID})
		return
	}

	rule, err := h.ipRuleService.GetRule(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get IP rule", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get IP rule"})
		return
	}

	if rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IP rule not found"})
		return
	}

	if rule.TenantID != currentUser.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "IP rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule.ToResponse())
}

// CreateIPRule creates a new IP rule
// @Summary Create IP Rule
// @Description Create a new IP whitelist/blacklist rule for the tenant
// @Tags Admin - Security
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.CreateIPRuleRequest true "IP rule settings"
// @Success 201 {object} models.IPRuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/admin/security/ip-rules [post]
func (h *AdminHandler) CreateIPRule(c *gin.Context) {
	if h.ipRuleService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgIPRuleServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	var req models.CreateIPRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.ipRuleService.CreateRule(c.Request.Context(), currentUser.TenantID, currentUser.ID, &req)
	if err != nil {
		h.logger.Error("Failed to create IP rule", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, rule.ToResponse())
}

// UpdateIPRule updates an existing IP rule
// @Summary Update IP Rule
// @Description Update an IP rule
// @Tags Admin - Security
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Rule ID"
// @Param body body models.UpdateIPRuleRequest true "IP rule settings"
// @Success 200 {object} models.IPRuleResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/security/ip-rules/{id} [put]
func (h *AdminHandler) UpdateIPRule(c *gin.Context) {
	if h.ipRuleService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgIPRuleServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRuleID})
		return
	}

	var req models.UpdateIPRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.ipRuleService.UpdateRule(c.Request.Context(), currentUser.TenantID, currentUser.ID, id, &req)
	if err != nil {
		h.logger.Error("Failed to update IP rule", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rule.ToResponse())
}

// DeleteIPRule deletes an IP rule
// @Summary Delete IP Rule
// @Description Delete an IP rule
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Param id path string true "Rule ID"
// @Success 204
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/security/ip-rules/{id} [delete]
func (h *AdminHandler) DeleteIPRule(c *gin.Context) {
	if h.ipRuleService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgIPRuleServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidRuleID})
		return
	}

	if err := h.ipRuleService.DeleteRule(c.Request.Context(), currentUser.TenantID, id); err != nil {
		h.logger.Error("Failed to delete IP rule", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetIPRuleLogs retrieves IP rule logs
// @Summary Get IP Rule Logs
// @Description Get recent IP rule activity logs for the tenant
// @Tags Admin - Security
// @Produce json
// @Security BearerAuth
// @Param denied_only query boolean false "Show only denied requests"
// @Param limit query int false "Number of logs to return (default 100)"
// @Success 200 {array} models.IPRuleLogResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/security/ip-rules/logs [get]
func (h *AdminHandler) GetIPRuleLogs(c *gin.Context) {
	if h.ipRuleService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgIPRuleServiceNotConfigured})
		return
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedSec})
		return
	}

	deniedOnly := c.Query("denied_only") == queryBoolTrue
	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	logs, err := h.ipRuleService.GetLogs(c.Request.Context(), currentUser.TenantID, limit, deniedOnly)
	if err != nil {
		h.logger.Error("Failed to get IP rule logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get IP rule logs"})
		return
	}

	responses := make([]*models.IPRuleLogResponse, len(logs))
	for i, log := range logs {
		responses[i] = &models.IPRuleLogResponse{
			ID:        log.ID,
			RuleID:    log.RuleID,
			TenantID:  log.TenantID,
			IPAddress: log.IPAddress,
			Action:    log.Action,
			Endpoint:  log.Endpoint,
			UserAgent: log.UserAgent,
			CreatedAt: log.CreatedAt,
		}
	}

	c.JSON(http.StatusOK, responses)
}
