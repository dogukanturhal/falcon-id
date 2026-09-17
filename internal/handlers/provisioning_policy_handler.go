// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// provisioningPolicyEngine is the interface satisfied by *services.PolicyEngine.
type provisioningPolicyEngine interface {
	Evaluate(ctx context.Context, input services.PolicyInput) (*services.PolicyResult, error)
	ListRules() []services.PolicyRule
}

// ProvisioningPolicyHandler exposes governance policy evaluation endpoints for
// platform administrators to dry-run policy checks before provisioning.
type ProvisioningPolicyHandler struct {
	engine provisioningPolicyEngine
	log    *zap.Logger
}

// NewProvisioningPolicyHandler creates a handler backed by the given policy engine.
func NewProvisioningPolicyHandler(engine provisioningPolicyEngine, log *zap.Logger) *ProvisioningPolicyHandler {
	if log == nil {
		log = zap.NewNop()
	}
	return &ProvisioningPolicyHandler{engine: engine, log: log}
}

// EvaluatePolicy handles POST /api/v1/platform/policy/evaluate.
//
// Accepts a PolicyInput body and returns the evaluation result without making
// any changes to the system (dry-run).
//
// @Summary Dry-run provisioning policy evaluation
// @Description Evaluates a provisioning request against all active governance policies
// @Tags Provisioning Policy
// @Accept json
// @Produce json
// @Param input body services.PolicyInput true "Provisioning request to evaluate"
// @Success 200 {object} services.PolicyResult "Policy evaluation result"
// @Failure 400 {object} map[string]string "Invalid request body"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/policy/evaluate [post]
func (h *ProvisioningPolicyHandler) EvaluatePolicy(c *gin.Context) {
	var input services.PolicyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	result, err := h.engine.Evaluate(c.Request.Context(), input)
	if err != nil {
		h.log.Error("ProvisioningPolicyHandler.EvaluatePolicy failed",
			zap.String("tenant_id", input.TenantID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "policy evaluation failed"})
		return
	}

	statusCode := http.StatusOK
	if !result.Allowed {
		// Still return 200 — the HTTP status reflects whether the evaluation
		// succeeded, not whether the policy allowed the request. The caller
		// inspects result.allowed to determine next steps.
		statusCode = http.StatusOK
	}
	c.JSON(statusCode, result)
}

// ListRules handles GET /api/v1/platform/policy/rules.
//
// Returns all active governance policy rules with their descriptions.
//
// @Summary List active policy rules
// @Description Returns all registered provisioning governance rules
// @Tags Provisioning Policy
// @Produce json
// @Success 200 {object} map[string]interface{} "List of policy rules"
// @Router /api/v1/platform/policy/rules [get]
func (h *ProvisioningPolicyHandler) ListRules(c *gin.Context) {
	rules := h.engine.ListRules()
	if rules == nil {
		rules = []services.PolicyRule{}
	}
	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}
