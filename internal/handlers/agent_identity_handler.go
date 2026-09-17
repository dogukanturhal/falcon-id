// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgInvalidAgentID = "invalid agent ID"
)

// AgentIdentityHandler exposes the Admin API for AI agent identity management.
//
// Route group: /api/v1/platform/agents
//
//	POST   /                         — create agent
//	GET    /                         — list agents
//	GET    /:id                       — get agent
//	PUT    /:id                       — update agent
//	POST   /:id/suspend               — suspend agent
//	POST   /:id/revoke                — revoke agent
//	POST   /:id/rotate-credentials    — rotate client secret
//	GET    /:id/activity              — activity log
//	POST   /token                     — issue agent access token (client_credentials)
type AgentIdentityHandler struct {
	service *services.AgentIdentityService
}

// NewAgentIdentityHandler creates a new AgentIdentityHandler.
func NewAgentIdentityHandler(svc *services.AgentIdentityService) *AgentIdentityHandler {
	return &AgentIdentityHandler{service: svc}
}

// Create registers a new AI agent identity.
//
// @Summary     Create Agent Identity
// @Description Register a new AI agent with its capability grants and token policy.
// @Tags        Agent Identities
// @Accept      json
// @Produce     json
// @Security    BearerAuth
// @Param       body body models.CreateAgentRequest true "Agent registration data"
// @Success     201  {object} models.CreateAgentResponse
// @Failure     400  {object} map[string]string
// @Failure     401  {object} map[string]string
// @Router      /api/v1/platform/agents [post]
func (h *AgentIdentityHandler) Create(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	var req models.CreateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.CreateAgent(c.Request.Context(), tenantID, &req)
	if err != nil {
		logger.Warn("Failed to create agent identity",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp := models.CreateAgentResponse{
		AgentResponse: result.Agent.ToResponse(),
		ClientSecret:  result.ClientSecret,
	}

	logger.SecurityAudit.Info("Agent identity created",
		zap.String("event", "agent.identity.created"),
		zap.String("agent_id", result.Agent.ID.String()),
		zap.String("tenant_id", tenantID.String()),
		zap.String("ip", GetClientIP(c)),
	)

	c.JSON(http.StatusCreated, resp)
}

// List returns a paginated, filtered list of agent identities for the caller's tenant.
//
// @Summary     List Agent Identities
// @Description List agent identities with optional filters.
// @Tags        Agent Identities
// @Produce     json
// @Security    BearerAuth
// @Param       page      query int    false "Page number"   default(1)
// @Param       page_size query int    false "Page size"     default(20)
// @Param       type      query string false "Agent type filter (autonomous|interactive|mcp_server|workflow)"
// @Param       status    query string false "Status filter (active|suspended|revoked)"
// @Param       search    query string false "Search by name or description"
// @Success     200  {object} models.AgentListResponse
// @Failure     401  {object} map[string]string
// @Router      /api/v1/platform/agents [get]
func (h *AgentIdentityHandler) List(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	page, pageSize, _ := GetPagination(c)

	filters := models.AgentListFilters{
		Search: c.Query("search"),
	}

	if t := c.Query("type"); t != "" {
		at := models.AgentType(t)
		filters.Type = &at
	}
	if s := c.Query("status"); s != "" {
		as := models.AgentStatus(s)
		filters.Status = &as
	}
	if ownerStr := c.Query("owner_user_id"); ownerStr != "" {
		if ownerID, err := uuid.Parse(ownerStr); err == nil {
			filters.OwnerUserID = &ownerID
		}
	}

	resp, err := h.service.ListAgents(c.Request.Context(), tenantID, filters, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetByID retrieves a single agent identity.
//
// @Summary     Get Agent Identity
// @Description Get agent identity by ID.
// @Tags        Agent Identities
// @Produce     json
// @Security    BearerAuth
// @Param       id   path string true "Agent ID"
// @Success     200  {object} models.AgentResponse
// @Failure     400  {object} map[string]string
// @Failure     404  {object} map[string]string
// @Router      /api/v1/platform/agents/{id} [get]
func (h *AgentIdentityHandler) GetByID(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	agentID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAgentID})
		return
	}

	agent, err := h.service.GetAgent(c.Request.Context(), tenantID, agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, agent.ToResponse())
}

// Update applies partial updates to an agent identity.
//
// @Summary     Update Agent Identity
// @Description Update mutable fields of an agent identity.
// @Tags        Agent Identities
// @Accept      json
// @Produce     json
// @Security    BearerAuth
// @Param       id   path string true "Agent ID"
// @Param       body body models.UpdateAgentRequest true "Fields to update"
// @Success     200  {object} models.AgentResponse
// @Failure     400  {object} map[string]string
// @Failure     404  {object} map[string]string
// @Router      /api/v1/platform/agents/{id} [put]
func (h *AgentIdentityHandler) Update(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	agentID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAgentID})
		return
	}

	var req models.UpdateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, err := h.service.UpdateAgent(c.Request.Context(), tenantID, agentID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, agent.ToResponse())
}

// Suspend transitions an active agent to the suspended state.
//
// @Summary     Suspend Agent
// @Description Suspend an active agent — it cannot authenticate until reactivated.
// @Tags        Agent Identities
// @Produce     json
// @Security    BearerAuth
// @Param       id path string true "Agent ID"
// @Success     200 {object} map[string]string
// @Failure     400 {object} map[string]string
// @Failure     404 {object} map[string]string
// @Router      /api/v1/platform/agents/{id}/suspend [post]
func (h *AgentIdentityHandler) Suspend(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	agentID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAgentID})
		return
	}

	actorID := middleware.GetCurrentUserID(c)

	if err := h.service.SuspendAgent(c.Request.Context(), tenantID, agentID, actorID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.SecurityAudit.Info("Agent suspended",
		zap.String("event", "agent.identity.suspended"),
		zap.String("agent_id", agentID.String()),
		zap.Any("actor_id", actorID),
		zap.String("ip", GetClientIP(c)),
	)

	c.JSON(http.StatusOK, gin.H{"message": "agent suspended"})
}

// Revoke permanently revokes an agent identity.
//
// @Summary     Revoke Agent
// @Description Permanently revoke an agent — cannot be undone.
// @Tags        Agent Identities
// @Produce     json
// @Security    BearerAuth
// @Param       id path string true "Agent ID"
// @Success     200 {object} map[string]string
// @Failure     400 {object} map[string]string
// @Failure     404 {object} map[string]string
// @Router      /api/v1/platform/agents/{id}/revoke [post]
func (h *AgentIdentityHandler) Revoke(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	agentID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAgentID})
		return
	}

	actorID := middleware.GetCurrentUserID(c)

	if err := h.service.RevokeAgent(c.Request.Context(), tenantID, agentID, actorID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.SecurityAudit.Info("Agent revoked",
		zap.String("event", "agent.identity.revoked"),
		zap.String("agent_id", agentID.String()),
		zap.Any("actor_id", actorID),
		zap.String("ip", GetClientIP(c)),
	)

	c.JSON(http.StatusOK, gin.H{"message": "agent revoked"})
}

// RotateCredentials generates a new client secret and returns it once.
//
// @Summary     Rotate Agent Credentials
// @Description Generate a new client secret for an agent. The secret is returned once — store it immediately.
// @Tags        Agent Identities
// @Produce     json
// @Security    BearerAuth
// @Param       id path string true "Agent ID"
// @Success     200 {object} map[string]string
// @Failure     400 {object} map[string]string
// @Failure     404 {object} map[string]string
// @Router      /api/v1/platform/agents/{id}/rotate-credentials [post]
func (h *AgentIdentityHandler) RotateCredentials(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	agentID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAgentID})
		return
	}

	newSecret, err := h.service.RotateCredentials(c.Request.Context(), tenantID, agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.SecurityAudit.Info("Agent credentials rotated",
		zap.String("event", "agent.identity.credentials_rotated"),
		zap.String("agent_id", agentID.String()),
		zap.String("ip", GetClientIP(c)),
	)

	c.JSON(http.StatusOK, gin.H{
		"client_secret": newSecret,
		"message":       "credentials rotated — store the new secret immediately, it will not be shown again",
	})
}

// GetActivity returns the paginated activity log for an agent.
//
// @Summary     Get Agent Activity Log
// @Description Retrieve the immutable audit trail for an agent's token issuance and API calls.
// @Tags        Agent Identities
// @Produce     json
// @Security    BearerAuth
// @Param       id        path  string true  "Agent ID"
// @Param       page      query int    false "Page number"  default(1)
// @Param       page_size query int    false "Page size"    default(50)
// @Success     200 {object} models.AgentActivityListResponse
// @Failure     400 {object} map[string]string
// @Failure     404 {object} map[string]string
// @Router      /api/v1/platform/agents/{id}/activity [get]
func (h *AgentIdentityHandler) GetActivity(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)

	agentID, err := parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAgentID})
		return
	}

	page, pageSize, _ := GetPagination(c)

	resp, err := h.service.GetActivityLog(c.Request.Context(), tenantID, agentID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// IssueToken handles the OAuth2 client_credentials grant for agents.
// An agent calls this endpoint directly (not via a human login flow) to obtain
// a short-lived access token.
//
// @Summary     Issue Agent Token
// @Description OAuth2 client_credentials grant for agent identities.
// @Tags        Agent Identities
// @Accept      json
// @Produce     json
// @Param       body body models.AgentTokenRequest true "Agent credentials"
// @Success     200  {object} models.AgentTokenResponse
// @Failure     401  {object} map[string]string
// @Router      /api/v1/platform/agents/token [post]
func (h *AgentIdentityHandler) IssueToken(c *gin.Context) {
	var req models.AgentTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, err := h.service.AuthenticateAgent(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		// Use 401, not 403, so callers can distinguish auth failure from permission failure.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client credentials"})
		return
	}

	token, err := h.service.GenerateAgentToken(c.Request.Context(), agent)
	if err != nil {
		logger.Warn("Failed to generate agent token",
			zap.String("agent_id", agent.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, token)
}
