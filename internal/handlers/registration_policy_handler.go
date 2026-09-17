// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgRegPolicyInvalidID = "Invalid registration policy ID"
	msgRegPolicyNotFound  = "Registration policy not found"
)

// RegistrationPolicyHandler handles HTTP endpoints for client registration policies.
type RegistrationPolicyHandler struct {
	svc *services.RegistrationPolicyService
}

// NewRegistrationPolicyHandler creates a new RegistrationPolicyHandler.
func NewRegistrationPolicyHandler(svc *services.RegistrationPolicyService) *RegistrationPolicyHandler {
	return &RegistrationPolicyHandler{svc: svc}
}

// Create registers a new registration policy.
// POST /api/v1/platform/registration-policies
func (h *RegistrationPolicyHandler) Create(c *gin.Context) {
	var req models.CreateRegistrationPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.svc.Create(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create registration policy"})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// Get retrieves a registration policy by UUID.
// GET /api/v1/platform/registration-policies/:id
func (h *RegistrationPolicyHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRegPolicyInvalidID})
		return
	}

	policy, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": msgRegPolicyNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve registration policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// GetDefault retrieves the platform default registration policy.
// GET /api/v1/platform/registration-policies/default
func (h *RegistrationPolicyHandler) GetDefault(c *gin.Context) {
	policy, err := h.svc.GetDefault(c.Request.Context())
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "No default registration policy configured"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve default registration policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Update applies partial updates to a registration policy.
// PUT /api/v1/platform/registration-policies/:id
func (h *RegistrationPolicyHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRegPolicyInvalidID})
		return
	}

	var req models.UpdateRegistrationPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.svc.Update(c.Request.Context(), id, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": msgRegPolicyNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update registration policy"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Delete permanently removes a registration policy.
// Deleting the default policy is rejected with 409 Conflict.
// DELETE /api/v1/platform/registration-policies/:id
func (h *RegistrationPolicyHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgRegPolicyInvalidID})
		return
	}

	if err := h.svc.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": msgRegPolicyNotFound})
			return
		}
		if strings.Contains(err.Error(), "cannot delete the default") {
			c.JSON(http.StatusConflict, gin.H{"error": "Cannot delete the default registration policy; reassign the default first"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete registration policy"})
		return
	}

	c.Status(http.StatusNoContent)
}

// List returns all registration policies.
// GET /api/v1/platform/registration-policies
func (h *RegistrationPolicyHandler) List(c *gin.Context) {
	policies, err := h.svc.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list registration policies"})
		return
	}

	if policies == nil {
		policies = []models.RegistrationPolicy{}
	}

	c.JSON(http.StatusOK, gin.H{
		"registration_policies": policies,
		"total":                 len(policies),
	})
}
