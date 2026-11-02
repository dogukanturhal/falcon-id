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
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

const (
	msgPolicyNotAuthenticated = "Not authenticated"
	msgPolicyInvalidPolicyID  = "Invalid policy ID"
	msgPolicyNotFound         = "Policy not found"

	codeCustomRegoUnsupported = "custom_rego_unsupported"
	msgCustomRegoUnsupported  = "Custom Rego is not supported; policies are shipped with the service"
)

// PolicyHandler handles ABAC policy management endpoints
type PolicyHandler struct {
	policyRepo   *repositories.PolicyRepository
	settingsRepo *repositories.SettingsRepository
	opaService   *services.OPAService
	logger       *zap.Logger
}

// NewPolicyHandler creates a new policy handler
func NewPolicyHandler(policyRepo *repositories.PolicyRepository, settingsRepo *repositories.SettingsRepository) *PolicyHandler {
	return &PolicyHandler{
		policyRepo:   policyRepo,
		settingsRepo: settingsRepo,
		logger:       logger.Log,
	}
}

// SetOPAService sets the OPA service for policy reload
func (h *PolicyHandler) SetOPAService(opaService *services.OPAService) {
	h.opaService = opaService
}

// List lists all policies for the current tenant
func (h *PolicyHandler) List(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	policies, total, err := h.policyRepo.GetByTenant(c.Request.Context(), user.TenantID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	c.JSON(http.StatusOK, models.PolicyListResponse{
		Policies:   policies,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// Create creates a new policy
func (h *PolicyHandler) Create(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	var req models.CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.RegoCode != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgCustomRegoUnsupported, "code": codeCustomRegoUnsupported})
		return
	}

	policy := &models.Policy{
		Name:        req.Name,
		Description: req.Description,
		Effect:      req.Effect,
		Priority:    req.Priority,
		Conditions:  req.Conditions,
		RegoCode:    req.RegoCode,
		IsGlobal:    req.IsGlobal,
		IsActive:    req.IsActive,
		CreatedBy:   &user.ID,
	}

	// Non-admin users can only create tenant-specific policies
	if !user.HasPermission("iam:policies:create_global") && req.IsGlobal {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot create global policies"})
		return
	}

	// Set tenant ID for non-global policies
	if !req.IsGlobal {
		policy.TenantID = &user.TenantID
	}

	if err := h.policyRepo.Create(c.Request.Context(), policy); err != nil {
		h.logger.Error("Failed to create policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	// Log audit
	_ = h.policyRepo.LogAudit(c.Request.Context(), &models.PolicyAudit{
		PolicyID:    policy.ID,
		Action:      "create",
		NewValue:    repositories.PolicyToJSON(policy),
		PerformedBy: &user.ID,
	})

	c.JSON(http.StatusCreated, policy)
}

// GetByID retrieves a policy by ID
func (h *PolicyHandler) GetByID(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPolicyInvalidPolicyID})
		return
	}

	policy, err := h.policyRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPolicyNotFound})
		return
	}

	// Check access - must be global or belong to tenant
	if !policy.IsGlobal && (policy.TenantID == nil || *policy.TenantID != user.TenantID) {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPolicyNotFound})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Update updates a policy
func (h *PolicyHandler) Update(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPolicyInvalidPolicyID})
		return
	}

	// Validate the body before touching the repository.
	var req models.UpdatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.RegoCode != nil && *req.RegoCode != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgCustomRegoUnsupported, "code": codeCustomRegoUnsupported})
		return
	}

	policy, err := h.policyRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPolicyNotFound})
		return
	}

	if policy.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot modify system policies"})
		return
	}
	if !policy.IsGlobal && (policy.TenantID == nil || *policy.TenantID != user.TenantID) {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPolicyNotFound})
		return
	}

	oldValue := repositories.PolicyToJSON(policy)
	applyPolicyUpdates(policy, &req, &user.ID)

	if err := h.policyRepo.Update(c.Request.Context(), policy); err != nil {
		h.logger.Error("Failed to update policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}

	_ = h.policyRepo.LogAudit(c.Request.Context(), &models.PolicyAudit{
		PolicyID:    policy.ID,
		Action:      "update",
		OldValue:    oldValue,
		NewValue:    repositories.PolicyToJSON(policy),
		PerformedBy: &user.ID,
	})

	c.JSON(http.StatusOK, policy)
}

// applyPolicyUpdates merges non-nil fields from req into the policy.
func applyPolicyUpdates(policy *models.Policy, req *models.UpdatePolicyRequest, updatedBy *uuid.UUID) {
	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Description != nil {
		policy.Description = *req.Description
	}
	if req.Effect != nil {
		policy.Effect = *req.Effect
	}
	if req.Priority != nil {
		policy.Priority = *req.Priority
	}
	if req.Conditions != nil {
		policy.Conditions = *req.Conditions
	}
	if req.RegoCode != nil {
		policy.RegoCode = *req.RegoCode
	}
	if req.IsActive != nil {
		policy.IsActive = *req.IsActive
	}
	policy.UpdatedBy = updatedBy
}

// Delete deletes a policy
func (h *PolicyHandler) Delete(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgPolicyInvalidPolicyID})
		return
	}

	policy, err := h.policyRepo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPolicyNotFound})
		return
	}

	// Check access
	if policy.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete system policies"})
		return
	}

	if !policy.IsGlobal && (policy.TenantID == nil || *policy.TenantID != user.TenantID) {
		c.JSON(http.StatusNotFound, gin.H{"error": msgPolicyNotFound})
		return
	}

	// Store old value for audit
	oldValue := repositories.PolicyToJSON(policy)

	if err := h.policyRepo.Delete(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to delete policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	// Log audit
	_ = h.policyRepo.LogAudit(c.Request.Context(), &models.PolicyAudit{
		PolicyID:    policy.ID,
		Action:      "delete",
		OldValue:    oldValue,
		PerformedBy: &user.ID,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// TestPolicy tests a policy with sample input
func (h *PolicyHandler) TestPolicy(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	if h.opaService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ABAC service not enabled"})
		return
	}

	var req models.PolicyTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build AuthzInput from request
	input := &services.AuthzInput{
		User: services.AuthzUser{
			ID:          getStringFromMap(req.User, "id"),
			TenantID:    getStringFromMap(req.User, "tenant_id"),
			Username:    getStringFromMap(req.User, "username"),
			Email:       getStringFromMap(req.User, "email"),
			Roles:       getStringSliceFromMap(req.User, "roles"),
			Permissions: getStringSliceFromMap(req.User, "permissions"),
			Groups:      getStringSliceFromMap(req.User, "groups"),
			Department:  getStringFromMap(req.User, "department"),
		},
		Resource: services.AuthzResource{
			Type:       getStringFromMap(req.Resource, "type"),
			ID:         getStringFromMap(req.Resource, "id"),
			OwnerID:    getStringFromMap(req.Resource, "owner_id"),
			TenantID:   getStringFromMap(req.Resource, "tenant_id"),
			Attributes: getMapFromMap(req.Resource, "attributes"),
		},
		Action: req.Action,
		Context: services.AuthzContext{
			IPAddress:   getStringFromMap(req.Context, "ip_address"),
			UserAgent:   getStringFromMap(req.Context, "user_agent"),
			RequestPath: getStringFromMap(req.Context, "request_path"),
		},
	}

	result, err := h.opaService.Evaluate(c.Request.Context(), input)
	if err != nil {
		h.logger.Error("Policy evaluation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy evaluation failed"})
		return
	}

	c.JSON(http.StatusOK, models.PolicyTestResponse{
		Allowed: result.Allowed,
		Reasons: result.Reasons,
	})
}

// ReloadPolicies reloads policies from disk into OPA
func (h *PolicyHandler) ReloadPolicies(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	if h.opaService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ABAC service not enabled"})
		return
	}

	if err := h.opaService.ReloadPolicies(c.Request.Context()); err != nil {
		h.logger.Error("Failed to reload policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Policies reloaded successfully",
		"reloaded_at": h.opaService.GetLastReloadTime(),
	})
}

// GetABACStatus returns the current ABAC engine status
func (h *PolicyHandler) GetABACStatus(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPolicyNotAuthenticated})
		return
	}

	// Get policy count from database
	policyCount, err := h.policyRepo.CountActive(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error("Failed to count policies", zap.Error(err))
		policyCount = 0
	}

	// Check if OPA service is available
	opaAvailable := h.opaService != nil

	// The per-tenant ABACEnabled setting is deprecated and ignored; the
	// engine is enabled globally by USE_ABAC only.
	enabled := h.opaService != nil && h.opaService.IsEnabled()

	var lastReload string
	if opaAvailable {
		lastReload = h.opaService.GetLastReloadTime().Format("2006-01-02T15:04:05Z07:00")
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":       enabled,
		"opa_available": opaAvailable,
		"policy_count":  policyCount,
		"last_reload":   lastReload,
	})
}

// Helper functions
func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringSliceFromMap(m map[string]interface{}, key string) []string {
	if v, ok := m[key]; ok {
		if arr, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(arr))
			for _, item := range arr {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		}
	}
	return []string{}
}

func getMapFromMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if subMap, ok := v.(map[string]interface{}); ok {
			return subMap
		}
	}
	return map[string]interface{}{}
}
