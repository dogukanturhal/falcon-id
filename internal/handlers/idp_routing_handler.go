// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgIDPRoutingTenantIDNotFound = "Tenant ID not found in context"
)

// IDPRoutingHandler is an exported identifier.
// IDPRoutingHandler handles IDP routing rule HTTP endpoints.
type IDPRoutingHandler struct {
	routingService *services.IDPRoutingService
}

// NewIDPRoutingHandler is an exported identifier.
// NewIDPRoutingHandler creates a new IDP routing handler.
func NewIDPRoutingHandler(routingService *services.IDPRoutingService) *IDPRoutingHandler {
	return &IDPRoutingHandler{routingService: routingService}
}

// ListRules returns all IDP routing rules for the tenant.
// GET /admin/idp-routing-rules
func (h *IDPRoutingHandler) ListRules(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgIDPRoutingTenantIDNotFound})
		return
	}

	rules, err := h.routingService.ListRules(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list routing rules"})
		return
	}

	if rules == nil {
		rules = []models.IDPRoutingRule{}
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": len(rules),
	})
}

// CreateRule creates a new IDP routing rule.
// POST /admin/idp-routing-rules
func (h *IDPRoutingHandler) CreateRule(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgIDPRoutingTenantIDNotFound})
		return
	}

	var req models.CreateIDPRoutingRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.routingService.CreateRule(c.Request.Context(), tenantID, &req)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "A routing rule with this type and value already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create routing rule"})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// UpdateRule updates an existing IDP routing rule.
// PUT /admin/idp-routing-rules/:id
func (h *IDPRoutingHandler) UpdateRule(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgIDPRoutingTenantIDNotFound})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
		return
	}

	var req models.UpdateIDPRoutingRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.routingService.UpdateRule(c.Request.Context(), id, tenantID, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Routing rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update routing rule"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// DeleteRule deletes an IDP routing rule.
// DELETE /admin/idp-routing-rules/:id
func (h *IDPRoutingHandler) DeleteRule(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgIDPRoutingTenantIDNotFound})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
		return
	}

	if err := h.routingService.DeleteRule(c.Request.Context(), id, tenantID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Routing rule not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete routing rule"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ResolveIDP is an exported identifier.
// ResolveIDP tests which IDP resolves for a given email.
// POST /admin/idp-routing-rules/resolve
func (h *IDPRoutingHandler) ResolveIDP(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgIDPRoutingTenantIDNotFound})
		return
	}

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, err := h.routingService.ResolveIDPForEmail(c.Request.Context(), tenantID, req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if rule == nil {
		c.JSON(http.StatusOK, gin.H{
			"matched":  false,
			"provider": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"matched": true,
		"provider": gin.H{
			"id":           rule.IdentityProviderID,
			"name":         rule.ProviderName,
			"type":         rule.ProviderType,
			"display_name": rule.ProviderDisplayName,
		},
		"rule": gin.H{
			"id":         rule.ID,
			"rule_type":  rule.RuleType,
			"rule_value": rule.RuleValue,
			"priority":   rule.Priority,
		},
	})
}
