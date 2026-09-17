// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// CredentialPolicyHandler handles credential lifetime policy HTTP endpoints.
type CredentialPolicyHandler struct {
	svc *services.CredentialPolicyService
}

// NewCredentialPolicyHandler creates a new handler.
func NewCredentialPolicyHandler(svc *services.CredentialPolicyService) *CredentialPolicyHandler {
	return &CredentialPolicyHandler{svc: svc}
}

// GetPlatformPolicy returns the platform-level credential policy.
//
// @Summary Get platform credential policy
// @Description Returns the platform-level credential lifetime policy
// @Tags Credential Policies
// @Produce json
// @Success 200 {object} models.CredentialPolicy "Platform credential policy"
// @Failure 404 {object} map[string]string "No platform credential policy found"
// @Router /api/v1/admin/credential-policies/platform [get]
func (h *CredentialPolicyHandler) GetPlatformPolicy(c *gin.Context) {
	policy, err := h.svc.GetPlatformPolicy(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No platform credential policy found"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// GetEffectivePolicy returns the effective credential policy for a tenant.
//
// @Summary Get effective credential policy for tenant
// @Description Returns the resolved credential policy for a tenant (tenant override or platform fallback)
// @Tags Credential Policies
// @Produce json
// @Param tenant_id query string true "Tenant UUID"
// @Success 200 {object} models.CredentialPolicy "Effective credential policy"
// @Failure 400 {object} map[string]string "Missing or invalid tenant_id"
// @Failure 404 {object} map[string]string "No effective credential policy found"
// @Router /api/v1/admin/credential-policies/effective [get]
func (h *CredentialPolicyHandler) GetEffectivePolicy(c *gin.Context) {
	tenantIDStr := c.Query("tenant_id")
	if tenantIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id query parameter is required"})
		return
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id"})
		return
	}

	policy, err := h.svc.GetEffectivePolicy(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No effective credential policy found"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// List returns all credential policies.
//
// @Summary List credential policies
// @Description Returns all credential lifetime policies (platform and tenant-level)
// @Tags Credential Policies
// @Produce json
// @Success 200 {object} map[string]interface{} "List of credential policies"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/credential-policies [get]
func (h *CredentialPolicyHandler) List(c *gin.Context) {
	policies, err := h.svc.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list credential policies"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "total": len(policies)})
}

// Upsert creates or updates a credential policy.
//
// @Summary Create or update credential policy
// @Description Creates a new credential policy or updates an existing one for the given scope
// @Tags Credential Policies
// @Accept json
// @Produce json
// @Param request body models.CreateCredentialPolicyRequest true "Credential policy configuration"
// @Success 200 {object} models.CredentialPolicy "Upserted credential policy"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/credential-policies [post]
func (h *CredentialPolicyHandler) Upsert(c *gin.Context) {
	var req models.CreateCredentialPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policy, err := h.svc.UpsertPolicy(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upsert credential policy"})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// Delete removes a credential policy by ID.
//
// @Summary Delete credential policy
// @Description Permanently removes a credential lifetime policy
// @Tags Credential Policies
// @Produce json
// @Param id path string true "Policy UUID"
// @Success 200 {object} map[string]string "Credential policy deleted"
// @Failure 400 {object} map[string]string "Invalid policy ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/credential-policies/{id} [delete]
func (h *CredentialPolicyHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	if err := h.svc.DeletePolicy(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete credential policy"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Credential policy deleted"})
}
