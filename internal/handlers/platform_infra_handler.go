// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// platform_infra_handler.go provides HTTP handlers for three platform
// infrastructure features:
//
//  1. ShardBalanceHandler — GET /api/v1/platform/shard-balance
//  2. TenantOnboardingHandler — POST /api/v1/platform/tenants/:id/onboard
//
// The distributed rate limiter has no dedicated handler; it operates as Gin
// middleware and exposes its behaviour through response headers.

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// ShardBalanceHandler
// ---------------------------------------------------------------------------

// shardBalancerStatusProvider is the narrow interface the handler needs from
// ShardBalancer. Using an interface keeps the handler decoupled and testable.
type shardBalancerStatusProvider interface {
	Status(ctx context.Context) (*services.ShardBalanceStatus, error)
}

// ShardBalanceHandler exposes shard balance status to the platform admin UI.
type ShardBalanceHandler struct {
	balancer shardBalancerStatusProvider
}

// NewShardBalanceHandler creates the handler. balancer may be nil; the handler
// returns a graceful "not configured" response in that case.
func NewShardBalanceHandler(balancer shardBalancerStatusProvider) *ShardBalanceHandler {
	return &ShardBalanceHandler{balancer: balancer}
}

// GetShardBalance handles GET /api/v1/platform/shard-balance.
//
// Returns the current host load snapshot and recent rebalance events so
// platform operators can assess shard distribution at a glance.
func (h *ShardBalanceHandler) GetShardBalance(c *gin.Context) {
	if h.balancer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "shard balancer not configured — ensure database host registry is initialised",
		})
		return
	}

	status, err := h.balancer.Status(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// TenantOnboardingHandler
// ---------------------------------------------------------------------------

// onboardingPipelineRunner is the narrow interface the handler needs from
// TenantOnboardingPipeline.
type onboardingPipelineRunner interface {
	Onboard(ctx context.Context, req services.OnboardingRequest) (*services.OnboardingResult, error)
}

// TenantOnboardingHandler exposes the self-service provisioning pipeline.
type TenantOnboardingHandler struct {
	pipeline onboardingPipelineRunner
}

// NewTenantOnboardingHandler creates the handler. pipeline may be nil; the
// handler returns a graceful "not configured" response in that case.
func NewTenantOnboardingHandler(pipeline onboardingPipelineRunner) *TenantOnboardingHandler {
	return &TenantOnboardingHandler{pipeline: pipeline}
}

// onboardRequest is the JSON body for POST /api/v1/platform/tenants/:id/onboard.
type onboardRequest struct {
	Plan   string `json:"plan"   binding:"required"`
	Region string `json:"region"`
}

// OnboardTenant handles POST /api/v1/platform/tenants/:id/onboard.
//
// Body:
//
//	{"plan": "enterprise", "region": "tr-ist"}
//
// Response on success (200):
//
//	{
//	  "tenant_id": "...",
//	  "realm_id":  "...",
//	  "database_name": "...",
//	  "database_host": "...",
//	  "status": "completed",
//	  "steps": [...]
//	}
func (h *TenantOnboardingHandler) OnboardTenant(c *gin.Context) {
	if h.pipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "onboarding pipeline not configured",
		})
		return
	}

	tenantID, err := uuid.Parse(c.Param("tenant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant ID"})
		return
	}

	var body onboardRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	// Realm ID is optional in the URL path; when absent we use the tenant ID
	// as a fallback (single-realm tenants share the same ID).
	realmID := tenantID
	if rawRealm := c.Query("realm_id"); rawRealm != "" {
		if parsed, err := uuid.Parse(rawRealm); err == nil {
			realmID = parsed
		}
	}

	req := services.OnboardingRequest{
		TenantID: tenantID,
		RealmID:  realmID,
		Plan:     body.Plan,
		Region:   body.Region,
	}

	result, err := h.pipeline.Onboard(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Choose HTTP status based on pipeline outcome.
	httpStatus := http.StatusOK
	if result.Status == "failed" {
		httpStatus = http.StatusUnprocessableEntity
	}

	c.JSON(httpStatus, result)
}
