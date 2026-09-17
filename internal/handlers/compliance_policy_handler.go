// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// compliancePolicyEngine abstracts the CompliancePolicyEngine methods consumed
// by the handler, enabling straightforward unit testing with mock implementations.
type compliancePolicyEngine interface {
	ListControls(ctx context.Context, framework string) ([]services.ComplianceControl, error)
	CreatePolicy(ctx context.Context, tenantID, controlID uuid.UUID, schedule string) (*services.CompliancePolicy, error)
	ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]services.CompliancePolicy, error)
	GetPolicyByID(ctx context.Context, id uuid.UUID) (*services.CompliancePolicy, error)
	UpdatePolicy(ctx context.Context, id uuid.UUID, schedule string, enabled bool) (*services.CompliancePolicy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	EvaluateAllForTenant(ctx context.Context, tenantID uuid.UUID) ([]services.ComplianceEvaluation, error)
	GetDashboard(ctx context.Context, tenantID uuid.UUID) (*services.ComplianceDashboard, error)
	ListEvaluations(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]services.ComplianceEvaluation, int64, error)
	CaptureBaseline(ctx context.Context, tenantID, controlID uuid.UUID, value float64) error
	GetBaseline(ctx context.Context, tenantID, controlID uuid.UUID) (*services.ComplianceBaseline, error)
	GetDriftAlerts(ctx context.Context, tenantID uuid.UUID) ([]services.ComplianceEvaluation, error)
}

// CompliancePolicyHandler exposes continuous compliance engine operations over
// HTTP. All endpoints require an authenticated tenant context — the tenant_id
// is read from the gin context key set by the auth middleware.
type CompliancePolicyHandler struct {
	engine    compliancePolicyEngine
	scheduler *services.ComplianceScheduler
}

// NewCompliancePolicyHandler wires the handler to its engine and optional scheduler.
func NewCompliancePolicyHandler(engine *services.CompliancePolicyEngine, scheduler *services.ComplianceScheduler) *CompliancePolicyHandler {
	return &CompliancePolicyHandler{
		engine:    engine,
		scheduler: scheduler,
	}
}

// ---------------------------------------------------------------------------
// Controls (read-only catalogue)
// ---------------------------------------------------------------------------

// ListControls handles GET /api/v1/compliance/controls.
//
// @Summary List compliance controls
// @Description Returns the catalogue of available compliance controls, optionally filtered by framework
// @Tags Compliance
// @Produce json
// @Param framework query string false "Framework name (e.g. SOC2, GDPR, HIPAA)"
// @Success 200 {object} map[string]interface{} "List of compliance controls"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/controls [get]
func (h *CompliancePolicyHandler) ListControls(c *gin.Context) {
	framework := c.Query("framework")

	controls, err := h.engine.ListControls(c.Request.Context(), framework)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.ListControls: failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list controls"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"controls": controls,
		"total":    len(controls),
	})
}

// ---------------------------------------------------------------------------
// Policies (tenant control activations)
// ---------------------------------------------------------------------------

// CreatePolicy handles POST /api/v1/compliance/policies.
//
// @Summary Create compliance policy
// @Description Creates a compliance policy activating a control for the current tenant on a schedule
// @Tags Compliance
// @Accept json
// @Produce json
// @Param request body object true "Control ID and schedule"
// @Success 201 {object} services.CompliancePolicy "Created compliance policy"
// @Failure 400 {object} map[string]string "Validation error or invalid control_id"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/policies [post]
func (h *CompliancePolicyHandler) CreatePolicy(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	var req struct {
		ControlID string `json:"control_id" binding:"required"`
		Schedule  string `json:"schedule"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	controlID, err := uuid.Parse(req.ControlID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid control_id"})
		return
	}

	schedule := req.Schedule
	if schedule == "" {
		schedule = "daily"
	}

	policy, err := h.engine.CreatePolicy(c.Request.Context(), tenantID, controlID, schedule)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.CreatePolicy: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// ListPolicies handles GET /api/v1/compliance/policies.
//
// @Summary List compliance policies
// @Description Returns all active compliance policies for the current tenant
// @Tags Compliance
// @Produce json
// @Success 200 {object} map[string]interface{} "List of compliance policies"
// @Failure 400 {object} map[string]string "Missing tenant context"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/policies [get]
func (h *CompliancePolicyHandler) ListPolicies(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	policies, err := h.engine.ListPolicies(c.Request.Context(), tenantID)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.ListPolicies: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		"total":    len(policies),
	})
}

// UpdatePolicy handles PUT /api/v1/compliance/policies/:id.
//
// @Summary Update compliance policy
// @Description Updates the schedule and enabled state of a compliance policy
// @Tags Compliance
// @Accept json
// @Produce json
// @Param id path string true "Policy UUID"
// @Param request body object true "Schedule and enabled flag"
// @Success 200 {object} services.CompliancePolicy "Updated compliance policy"
// @Failure 400 {object} map[string]string "Invalid policy ID or validation error"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/policies/{id} [put]
func (h *CompliancePolicyHandler) UpdatePolicy(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	var req struct {
		Schedule string `json:"schedule" binding:"required"`
		Enabled  bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.engine.UpdatePolicy(c.Request.Context(), id, req.Schedule, req.Enabled)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.UpdatePolicy: failed",
			zap.String("policy_id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// DeletePolicy handles DELETE /api/v1/compliance/policies/:id.
//
// @Summary Delete compliance policy
// @Description Removes a compliance policy for the current tenant
// @Tags Compliance
// @Produce json
// @Param id path string true "Policy UUID"
// @Success 200 {object} map[string]string "Policy deleted"
// @Failure 400 {object} map[string]string "Invalid policy ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/policies/{id} [delete]
func (h *CompliancePolicyHandler) DeletePolicy(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	if err := h.engine.DeletePolicy(c.Request.Context(), id); err != nil {
		logger.Log.Error("CompliancePolicyHandler.DeletePolicy: failed",
			zap.String("policy_id", id.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// TriggerEvaluation handles POST /api/v1/compliance/evaluate.
//
// @Summary Trigger compliance evaluation
// @Description On-demand evaluation of all active compliance policies for the current tenant
// @Tags Compliance
// @Produce json
// @Success 200 {object} map[string]interface{} "Evaluation results with pass/fail/error counts"
// @Failure 400 {object} map[string]string "Missing tenant context"
// @Failure 500 {object} map[string]string "Evaluation failed"
// @Router /api/v1/compliance/evaluate [post]
func (h *CompliancePolicyHandler) TriggerEvaluation(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	evaluations, err := h.engine.EvaluateAllForTenant(c.Request.Context(), tenantID)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.TriggerEvaluation: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "evaluation failed"})
		return
	}

	pass, fail, evalErr := countStatuses(evaluations)
	c.JSON(http.StatusOK, gin.H{
		"evaluations": evaluations,
		"total":       len(evaluations),
		"pass_count":  pass,
		"fail_count":  fail,
		"error_count": evalErr,
	})
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

// GetDashboard handles GET /api/v1/compliance/dashboard.
//
// @Summary Get compliance dashboard
// @Description Returns a compliance posture summary for the current tenant
// @Tags Compliance
// @Produce json
// @Success 200 {object} services.ComplianceDashboard "Compliance posture dashboard"
// @Failure 400 {object} map[string]string "Missing tenant context"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/dashboard [get]
func (h *CompliancePolicyHandler) GetDashboard(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	dashboard, err := h.engine.GetDashboard(c.Request.Context(), tenantID)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.GetDashboard: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build dashboard"})
		return
	}

	c.JSON(http.StatusOK, dashboard)
}

// ---------------------------------------------------------------------------
// Evaluation history
// ---------------------------------------------------------------------------

// ListEvaluations handles GET /api/v1/compliance/evaluations.
//
// @Summary List compliance evaluations
// @Description Returns paginated historical compliance evaluation results for the current tenant
// @Tags Compliance
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Success 200 {object} map[string]interface{} "Paginated evaluation history"
// @Failure 400 {object} map[string]string "Missing tenant context"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/evaluations [get]
func (h *CompliancePolicyHandler) ListEvaluations(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	evaluations, total, err := h.engine.ListEvaluations(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.ListEvaluations: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list evaluations"})
		return
	}

	totalPages := int(total) / pageSize
	if pageSize > 0 && int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"evaluations": evaluations,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// ---------------------------------------------------------------------------
// Baselines
// ---------------------------------------------------------------------------

// CaptureBaseline handles POST /api/v1/compliance/baselines.
//
// @Summary Capture compliance baseline
// @Description Records the current metric value as the known-good baseline for drift detection
// @Tags Compliance
// @Accept json
// @Produce json
// @Param request body object true "Control ID and baseline value"
// @Success 200 {object} services.ComplianceBaseline "Stored baseline"
// @Failure 400 {object} map[string]string "Missing tenant context, invalid control_id, or validation error"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/baselines [post]
func (h *CompliancePolicyHandler) CaptureBaseline(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	var req struct {
		ControlID string  `json:"control_id" binding:"required"`
		Value     float64 `json:"value"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	controlID, err := uuid.Parse(req.ControlID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid control_id"})
		return
	}

	if err := h.engine.CaptureBaseline(c.Request.Context(), tenantID, controlID, req.Value); err != nil {
		logger.Log.Error("CompliancePolicyHandler.CaptureBaseline: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to capture baseline"})
		return
	}

	// Return the stored baseline for confirmation.
	baseline, err := h.engine.GetBaseline(c.Request.Context(), tenantID, controlID)
	if err != nil {
		// Baseline was stored but reading it back failed — non-fatal.
		c.JSON(http.StatusOK, gin.H{"message": "baseline captured", "value": req.Value})
		return
	}

	c.JSON(http.StatusOK, baseline)
}

// ---------------------------------------------------------------------------
// Drift alerts
// ---------------------------------------------------------------------------

// GetDriftAlerts handles GET /api/v1/compliance/drift.
//
// @Summary Get compliance drift alerts
// @Description Returns the most recent evaluation for each control where drift from baseline was detected
// @Tags Compliance
// @Produce json
// @Success 200 {object} map[string]interface{} "List of drift alerts"
// @Failure 400 {object} map[string]string "Missing tenant context"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/compliance/drift [get]
func (h *CompliancePolicyHandler) GetDriftAlerts(c *gin.Context) {
	tenantID, ok := requireTenantID(c)
	if !ok {
		return
	}

	alerts, err := h.engine.GetDriftAlerts(c.Request.Context(), tenantID)
	if err != nil {
		logger.Log.Error("CompliancePolicyHandler.GetDriftAlerts: failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get drift alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// requireTenantID extracts the tenant_id UUID from the gin context. The value
// is set by the auth middleware as either a uuid.UUID or a string. Returns
// (uuid.Nil, false) and writes a 400 response when the value is absent or
// cannot be parsed.
func requireTenantID(c *gin.Context) (uuid.UUID, bool) {
	raw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return uuid.Nil, false
	}

	switch v := raw.(type) {
	case uuid.UUID:
		if v == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
			return uuid.Nil, false
		}
		return v, true
	case string:
		id, err := uuid.Parse(v)
		if err != nil || id == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
			return uuid.Nil, false
		}
		return id, true
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id type"})
		return uuid.Nil, false
	}
}

// countStatuses tallies pass / fail / error counts from a slice of evaluations.
func countStatuses(evals []services.ComplianceEvaluation) (pass, fail, errCount int) {
	for i := range evals {
		switch evals[i].Status {
		case "pass":
			pass++
		case "fail":
			fail++
		default:
			errCount++
		}
	}
	return
}
