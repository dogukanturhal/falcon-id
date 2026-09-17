// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgLicenseInvalidID = "Invalid license ID"
	msgLicenseNotFound  = "License not found"
)

// LicenseHandler handles license management HTTP endpoints.
type LicenseHandler struct {
	licenseService *services.LicenseService
}

// NewLicenseHandler creates a new license handler.
func NewLicenseHandler(licenseService *services.LicenseService) *LicenseHandler {
	return &LicenseHandler{licenseService: licenseService}
}

// Create issues a new license.
// POST /licenses
func (h *LicenseHandler) Create(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.CreateLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	license, err := h.licenseService.Create(c.Request.Context(), &req, currentUser.ID)
	if err != nil {
		if errors.Is(err, services.ErrProductNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create license"})
		return
	}

	// Return the full unmasked key only at creation time.
	c.JSON(http.StatusCreated, license.ToResponseWithKey())
}

// Get retrieves a license by ID.
// GET /licenses/:id
func (h *LicenseHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgLicenseInvalidID})
		return
	}

	license, err := h.licenseService.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, services.ErrLicenseNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgLicenseNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve license"})
		return
	}

	c.JSON(http.StatusOK, license.ToResponse())
}

// List returns a paginated list of licenses.
// GET /licenses
func (h *LicenseHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	var productID *uuid.UUID
	if raw := c.Query("product_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product_id"})
			return
		}
		productID = &parsed
	}

	var tenantID *uuid.UUID
	if raw := c.Query("tenant_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id"})
			return
		}
		tenantID = &parsed
	}

	status := c.Query("status")
	licenseType := c.Query("type")

	licenses, total, err := h.licenseService.List(c.Request.Context(), page, pageSize, productID, tenantID, status, licenseType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list licenses"})
		return
	}

	responses := make([]models.LicenseResponse, 0, len(licenses))
	for i := range licenses {
		responses = append(responses, *licenses[i].ToResponse())
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, models.LicenseListResponse{
		Licenses:   responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// Update applies partial updates to a license.
// PUT /licenses/:id
func (h *LicenseHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgLicenseInvalidID})
		return
	}

	var req models.UpdateLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	license, err := h.licenseService.Update(c.Request.Context(), id, &req)
	if err != nil {
		if errors.Is(err, services.ErrLicenseNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgLicenseNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update license"})
		return
	}

	c.JSON(http.StatusOK, license.ToResponse())
}

// Suspend temporarily disables a license.
// POST /licenses/:id/suspend
func (h *LicenseHandler) Suspend(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgLicenseInvalidID})
		return
	}

	if err := h.licenseService.Suspend(c.Request.Context(), id); err != nil {
		if errors.Is(err, services.ErrLicenseNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgLicenseNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to suspend license"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "License suspended"})
}

// Revoke permanently cancels a license.
// POST /licenses/:id/revoke
func (h *LicenseHandler) Revoke(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgLicenseInvalidID})
		return
	}

	if err := h.licenseService.Revoke(c.Request.Context(), id, currentUser.ID); err != nil {
		if errors.Is(err, services.ErrLicenseNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgLicenseNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke license"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "License revoked"})
}

// Validate is a public endpoint used by licensed products to phone home.
// POST /licenses/validate
func (h *LicenseHandler) Validate(c *gin.Context) {
	var req models.LicenseValidationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.licenseService.ValidateLicense(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Validation failed"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Activate registers a machine activation for a license key.
// POST /licenses/activate
func (h *LicenseHandler) Activate(c *gin.Context) {
	var req models.ActivateLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.Request.UserAgent()

	activation, err := h.licenseService.ActivateLicense(c.Request.Context(), &req, ipAddress, userAgent)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrLicenseNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": msgLicenseNotFound})
		case errors.Is(err, services.ErrLicenseNotActive):
			c.JSON(http.StatusForbidden, gin.H{"error": "License is not active"})
		case errors.Is(err, services.ErrLicenseExpired):
			c.JSON(http.StatusForbidden, gin.H{"error": "License has expired"})
		case errors.Is(err, services.ErrMaxSeatsReached):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate license"})
		}
		return
	}

	c.JSON(http.StatusCreated, activation.ToResponse())
}

// Deactivate releases a specific machine activation.
// DELETE /licenses/activations/:id
func (h *LicenseHandler) Deactivate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activation ID"})
		return
	}

	if err := h.licenseService.DeactivateActivation(c.Request.Context(), id); err != nil {
		if errors.Is(err, services.ErrActivationNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Activation not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deactivate activation"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ListActivations returns all activations for a license.
// GET /licenses/:id/activations
func (h *LicenseHandler) ListActivations(c *gin.Context) {
	licenseID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgLicenseInvalidID})
		return
	}

	activations, err := h.licenseService.ListActivations(c.Request.Context(), licenseID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list activations"})
		return
	}

	responses := make([]*models.LicenseActivationResponse, 0, len(activations))
	for i := range activations {
		responses = append(responses, activations[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{"activations": responses})
}
