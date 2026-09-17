// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// DynamicGroupRuleHandler handles HTTP requests for dynamic group rule CRUD.
type DynamicGroupRuleHandler struct {
	repo *repositories.DynamicGroupRuleRepository
}

// NewDynamicGroupRuleHandler creates a new handler.
func NewDynamicGroupRuleHandler(repo *repositories.DynamicGroupRuleRepository) *DynamicGroupRuleHandler {
	return &DynamicGroupRuleHandler{repo: repo}
}

// Create handles POST /api/v1/admin/dynamic-group-rules
func (h *DynamicGroupRuleHandler) Create(c *gin.Context) {
	tenantID, ok := extractTenantID(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	var req models.CreateDynamicGroupRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Enforce rule limit
	count, err := h.repo.CountByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check rule count"})
		return
	}
	if count >= models.MaxDynamicGroupRulesPerTenant {
		c.JSON(http.StatusConflict, gin.H{"error": "maximum number of dynamic group rules reached"})
		return
	}

	conditionsJSON, err := json.Marshal(req.Conditions)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid conditions"})
		return
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

	rule := &models.DynamicGroupRule{
		TenantID:    tenantID,
		GroupID:     req.GroupID,
		Name:        req.Name,
		Description: req.Description,
		Conditions:  conditionsJSON,
		IsActive:    isActive,
		Priority:    priority,
		CreatedBy:   userID,
	}

	if err := h.repo.Create(c.Request.Context(), rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rule"})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// List handles GET /api/v1/admin/dynamic-group-rules
func (h *DynamicGroupRuleHandler) List(c *gin.Context) {
	tenantID, ok := extractTenantID(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing tenant context"})
		return
	}

	rules, err := h.repo.ListAllByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// Update handles PATCH /api/v1/admin/dynamic-group-rules/:id
func (h *DynamicGroupRuleHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	var req models.UpdateDynamicGroupRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.repo.Update(c.Request.Context(), id, &req); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch updated rule"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// Delete handles DELETE /api/v1/admin/dynamic-group-rules/:id
func (h *DynamicGroupRuleHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule ID"})
		return
	}

	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}
