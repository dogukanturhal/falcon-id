// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgRiskInvalidPolicyID = "Invalid policy ID"
	msgRiskPolicyNotFound  = "Policy not found"
	msgRiskInternalError   = "An internal error occurred"
)

// RiskHandler is an exported type.
type RiskHandler struct {
	riskService        *services.RiskService
	userService        *services.UserService
	riskScoringService *services.RiskScoringService
	logger             *zap.SugaredLogger
}

// NewRiskHandler is an exported function.
func NewRiskHandler(riskService *services.RiskService, userService *services.UserService) *RiskHandler {
	return &RiskHandler{
		riskService: riskService,
		userService: userService,
	}
}

// SetRiskScoringService wires the optional Redis-backed risk scoring service.
// When set, the GET /users/:id/risk-score endpoint returns a real-time assessment.
func (h *RiskHandler) SetRiskScoringService(svc *services.RiskScoringService) {
	h.riskScoringService = svc
}

// SetLogger wires a sugared logger for the risk handler.
func (h *RiskHandler) SetLogger(logger *zap.SugaredLogger) {
	h.logger = logger
}

// GetUserRiskScore godoc
// @Summary      Get user risk score
// @Description  Retrieves the current real-time risk assessment for a user based on Redis-backed heuristics.
// @Tags         Risk
// @Security     BearerAuth
// @Produce      json
// @Param        id   path      string  true  "User ID" format(uuid)
// @Success      200  {object}  services.RiskAssessment
// @Failure      400  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/users/{id}/risk-score [get]
func (h *RiskHandler) GetUserRiskScore(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user ID"})
		return
	}

	if h.riskScoringService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "risk scoring service unavailable"})
		return
	}

	assessment, err := h.riskScoringService.GetUserRiskScore(c.Request.Context(), userID)
	if err != nil {
		if h.logger != nil {
			h.logger.Errorw("Failed to get risk score", "error", err, "user_id", userID)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve risk score"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    assessment,
	})
}

// GetPolicies returns all risk policies for the tenant
// @Summary Get risk policies
// @Tags Risk
// @Security BearerAuth
// @Produce json
// @Success 200 {array} models.RiskPolicyResponse
// @Router /api/admin/security/risk-policies [get]
func (h *RiskHandler) GetPolicies(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	policies, err := h.riskService.GetPolicies(c.Request.Context(), user.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get policies"})
		return
	}

	response := make([]*models.RiskPolicyResponse, len(policies))
	for i, policy := range policies {
		response[i] = policy.ToResponse()
	}

	c.JSON(http.StatusOK, response)
}

// GetPolicy returns a risk policy by ID
// @Summary Get risk policy
// @Tags Risk
// @Security BearerAuth
// @Produce json
// @Param id path string true "Policy ID"
// @Success 200 {object} models.RiskPolicyResponse
// @Router /api/admin/security/risk-policies/{id} [get]
func (h *RiskHandler) GetPolicy(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRiskInvalidPolicyID})
		return
	}

	policy, err := h.riskService.GetPolicyByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get policy"})
		return
	}
	if policy == nil || policy.TenantID != user.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRiskPolicyNotFound})
		return
	}

	c.JSON(http.StatusOK, policy.ToResponse())
}

// CreatePolicy creates a new risk policy
// @Summary Create risk policy
// @Tags Risk
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param policy body models.CreateRiskPolicyRequest true "Policy data"
// @Success 201 {object} models.RiskPolicyResponse
// @Router /api/admin/security/risk-policies [post]
func (h *RiskHandler) CreatePolicy(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.CreateRiskPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.riskService.CreatePolicy(c.Request.Context(), user.TenantID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRiskInternalError})
		return
	}

	c.JSON(http.StatusCreated, policy.ToResponse())
}

// UpdatePolicy updates a risk policy
// @Summary Update risk policy
// @Tags Risk
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Param policy body models.UpdateRiskPolicyRequest true "Policy data"
// @Success 200 {object} models.RiskPolicyResponse
// @Router /api/admin/security/risk-policies/{id} [put]
func (h *RiskHandler) UpdatePolicy(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRiskInvalidPolicyID})
		return
	}

	// Verify the policy belongs to the current tenant before updating
	existing, err := h.riskService.GetPolicyByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRiskInternalError})
		return
	}
	if existing == nil || existing.TenantID != user.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRiskPolicyNotFound})
		return
	}

	var req models.UpdateRiskPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.riskService.UpdatePolicy(c.Request.Context(), id, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRiskInternalError})
		return
	}

	c.JSON(http.StatusOK, policy.ToResponse())
}

// DeletePolicy deletes a risk policy
// @Summary Delete risk policy
// @Tags Risk
// @Security BearerAuth
// @Param id path string true "Policy ID"
// @Success 204
// @Router /api/admin/security/risk-policies/{id} [delete]
func (h *RiskHandler) DeletePolicy(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRiskInvalidPolicyID})
		return
	}

	// Verify the policy belongs to the current tenant before deleting
	existing, err := h.riskService.GetPolicyByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}
	if existing == nil || existing.TenantID != user.TenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgRiskPolicyNotFound})
		return
	}

	if err := h.riskService.DeletePolicy(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetThresholds returns risk thresholds for the tenant
// @Summary Get risk thresholds
// @Tags Risk
// @Security BearerAuth
// @Produce json
// @Success 200 {object} models.RiskThresholdResponse
// @Router /api/admin/security/risk-thresholds [get]
func (h *RiskHandler) GetThresholds(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	thresholds, err := h.riskService.GetThresholds(c.Request.Context(), user.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get thresholds"})
		return
	}

	c.JSON(http.StatusOK, thresholds.ToResponse())
}

// UpdateThresholds updates risk thresholds for the tenant
// @Summary Update risk thresholds
// @Tags Risk
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param thresholds body models.UpdateRiskThresholdRequest true "Thresholds data"
// @Success 200 {object} models.RiskThresholdResponse
// @Router /api/admin/security/risk-thresholds [put]
func (h *RiskHandler) UpdateThresholds(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.UpdateRiskThresholdRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	thresholds, err := h.riskService.UpdateThresholds(c.Request.Context(), user.TenantID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgRiskInternalError})
		return
	}

	c.JSON(http.StatusOK, thresholds.ToResponse())
}

// GetUserSignals returns risk signals for a user
// @Summary Get user risk signals
// @Tags Risk
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Param days query int false "Number of days to look back" default(30)
// @Success 200 {array} models.RiskSignalResponse
// @Router /api/admin/users/{id}/risk-signals [get]
func (h *RiskHandler) GetUserSignals(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	idStr := c.Param("id")
	userID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Verify the target user belongs to the current tenant
	if userID != user.ID && h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), userID)
		if err != nil || targetUser == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if targetUser.TenantID != user.TenantID {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
	}

	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		var d int
		if _, err := fmt.Sscanf(daysStr, "%d", &d); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	signals, err := h.riskService.GetUserSignals(c.Request.Context(), userID, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get signals"})
		return
	}

	response := make([]*models.RiskSignalResponse, len(signals))
	for i, signal := range signals {
		response[i] = signal.ToResponse()
	}

	c.JSON(http.StatusOK, response)
}

// ResolveSignal resolves a risk signal
// @Summary Resolve risk signal
// @Tags Risk
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "Signal ID"
// @Param request body models.ResolveRiskSignalRequest true "Resolution data"
// @Success 200 {object} map[string]string
// @Router /api/admin/security/risk-signals/{id}/resolve [post]
func (h *RiskHandler) ResolveSignal(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	idStr := c.Param("id")
	signalID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signal ID"})
		return
	}

	// Verify the signal belongs to a user in the current tenant
	signal, err := h.riskService.GetSignalByID(c.Request.Context(), signalID)
	if err != nil || signal == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Signal not found"})
		return
	}
	if h.userService != nil {
		targetUser, err := h.userService.GetByID(c.Request.Context(), signal.UserID)
		if err != nil || targetUser == nil || targetUser.TenantID != user.TenantID {
			c.JSON(http.StatusNotFound, gin.H{"error": "Signal not found"})
			return
		}
	}

	var req models.ResolveRiskSignalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.riskService.ResolveSignal(c.Request.Context(), signalID, user.ID, req.ResolutionNote); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve signal"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signal resolved successfully"})
}

// GetMyLoginEvents returns the current user's recent login risk events.
// User-facing endpoint that powers accounts.example.com's "Sign-in security
// events" feed — Google-style audit trail of MFA-challenged + blocked logins
// with cumulative score, level, IP, and outcome.
//
// @Summary List my login risk events
// @Description Returns the current user's login risk events from the last `days` days, newest first.
// @Tags Risk
// @Security BearerAuth
// @Produce json
// @Param days query int false "Lookback window in days (default 90)"
// @Param limit query int false "Maximum number of events (default 50, capped at 200)"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/me/risk-events [get]
func (h *RiskHandler) GetMyLoginEvents(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	days := 0
	if v := c.Query("days"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			days = parsed
		}
	}

	limit := 0
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	events, err := h.riskService.GetUserRecentLoginEvents(c.Request.Context(), user.ID, days, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get login events"})
		return
	}

	// Always return a non-nil array so the JSON shape is stable for clients.
	if events == nil {
		events = []models.LoginRiskEvent{}
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}
