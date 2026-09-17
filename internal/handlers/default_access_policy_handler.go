// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// DefaultAccessPolicyHandler handles HTTP requests for default access policy CRUD.
type DefaultAccessPolicyHandler struct {
	repo *repositories.DefaultAccessPolicyRepository
}

// NewDefaultAccessPolicyHandler creates a new handler.
func NewDefaultAccessPolicyHandler(repo *repositories.DefaultAccessPolicyRepository) *DefaultAccessPolicyHandler {
	return &DefaultAccessPolicyHandler{repo: repo}
}

// Create handles POST /api/v1/admin/default-access-policies
func (h *DefaultAccessPolicyHandler) Create(c *gin.Context) {
	tenantID, ok := extractTenantID(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	var req models.CreateDefaultAccessPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Enforce rule limit per tenant (SR-DAP-05)
	count, err := h.repo.CountByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check policy count"})
		return
	}
	if count >= models.MaxDefaultAccessRulesPerTenant {
		c.JSON(http.StatusConflict, gin.H{"error": "maximum number of default access policies reached"})
		return
	}

	// Set defaults
	scope := models.DefaultAccessPolicyScopeAllUsers
	if req.Scope != "" {
		scope = req.Scope
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	priority := 100
	if req.Priority != nil {
		priority = *req.Priority
	}

	userID := extractUserID(c)

	policy := &models.DefaultAccessPolicy{
		TenantID:   tenantID,
		ProductID:  req.ProductID,
		PolicyType: req.PolicyType,
		TargetID:   req.TargetID,
		Scope:      scope,
		IsActive:   isActive,
		Priority:   priority,
		CreatedBy:  userID,
	}

	if err := h.repo.Create(c.Request.Context(), policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, policy.ToResponse())
}

// List handles GET /api/v1/admin/default-access-policies
func (h *DefaultAccessPolicyHandler) List(c *gin.Context) {
	tenantID, ok := extractTenantID(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	policies, err := h.repo.ListAllByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list policies"})
		return
	}

	var responses []*models.DefaultAccessPolicyResponse
	for i := range policies {
		responses = append(responses, policies[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": responses,
		"total":    len(responses),
	})
}

// Update handles PATCH /api/v1/admin/default-access-policies/:id
func (h *DefaultAccessPolicyHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	var req models.UpdateDefaultAccessPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.repo.Update(c.Request.Context(), id, &req); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch updated policy"})
		return
	}

	c.JSON(http.StatusOK, policy.ToResponse())
}

// Delete handles DELETE /api/v1/admin/default-access-policies/:id
func (h *DefaultAccessPolicyHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// extractTenantID extracts tenant_id from the gin context.
func extractTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil, false
	}
	switch v := tenantIDVal.(type) {
	case uuid.UUID:
		return v, true
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			return uuid.Nil, false
		}
		return id, true
	}
	return uuid.Nil, false
}

// extractUserID extracts user_id from the gin context as a pointer.
func extractUserID(c *gin.Context) *uuid.UUID {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		return nil
	}
	switch v := userIDVal.(type) {
	case uuid.UUID:
		return &v
	case string:
		id, err := uuid.Parse(v)
		if err != nil {
			return nil
		}
		return &id
	}
	return nil
}
