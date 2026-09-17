// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgServicePrincipalInvalidID = "invalid ID"
)

// ServicePrincipalHandler handles service principal HTTP endpoints.
type ServicePrincipalHandler struct {
	service *services.ServicePrincipalService
}

// NewServicePrincipalHandler creates a new ServicePrincipalHandler.
func NewServicePrincipalHandler(service *services.ServicePrincipalService) *ServicePrincipalHandler {
	return &ServicePrincipalHandler{service: service}
}

// Create creates a new service principal.
// POST /api/v1/admin/service-principals
func (h *ServicePrincipalHandler) Create(c *gin.Context) {
	var req models.CreateServicePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.Create(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return the private key only at creation time
	c.JSON(http.StatusCreated, gin.H{
		"service_principal": result.ServicePrincipal.ToResponse(),
		"private_key_pem":   result.PrivateKeyPEM,
	})
}

// List lists all service principals.
// GET /api/v1/admin/service-principals
func (h *ServicePrincipalHandler) List(c *gin.Context) {
	principals, err := h.service.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responses := make([]models.ServicePrincipalResponse, len(principals))
	for i, sp := range principals {
		responses[i] = sp.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"service_principals": responses})
}

// GetByID retrieves a service principal by ID.
// GET /api/v1/admin/service-principals/:id
func (h *ServicePrincipalHandler) GetByID(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServicePrincipalInvalidID})
		return
	}

	sp, err := h.service.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service principal not found"})
		return
	}

	c.JSON(http.StatusOK, sp.ToResponse())
}

// Update updates a service principal.
// PUT /api/v1/admin/service-principals/:id
func (h *ServicePrincipalHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServicePrincipalInvalidID})
		return
	}

	var req models.UpdateServicePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sp, err := h.service.Update(c.Request.Context(), id, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, sp.ToResponse())
}

// Delete deletes a service principal.
// DELETE /api/v1/admin/service-principals/:id
func (h *ServicePrincipalHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServicePrincipalInvalidID})
		return
	}

	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "service principal deleted"})
}

// RotateKey rotates the key pair for a service principal.
// POST /api/v1/admin/service-principals/:id/rotate-key
func (h *ServicePrincipalHandler) RotateKey(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServicePrincipalInvalidID})
		return
	}

	privKey, err := h.service.RotateKey(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "key rotated successfully",
		"private_key_pem": privKey,
	})
}

// RegisterManifest registers a service's endpoints and events.
// POST /api/v1/admin/service-principals/:id/manifest
func (h *ServicePrincipalHandler) RegisterManifest(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgServicePrincipalInvalidID})
		return
	}

	var manifest models.RegisterServiceManifest
	if err := c.ShouldBindJSON(&manifest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.RegisterManifest(c.Request.Context(), id, &manifest); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "manifest registered"})
}
