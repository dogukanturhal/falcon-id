// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgInvalidAppRegistrationID = "Invalid app registration ID"
	msgAppRegistrationNotFound  = "App registration not found"
	msgNotFound                 = "not found"
)

// AppRegistrationHandler handles app registration HTTP endpoints.
type AppRegistrationHandler struct {
	appRegService *services.AppRegistrationService
}

// NewAppRegistrationHandler creates a new app registration handler.
func NewAppRegistrationHandler(appRegService *services.AppRegistrationService) *AppRegistrationHandler {
	return &AppRegistrationHandler{appRegService: appRegService}
}

// Create registers a new application and returns the registration with its plain-text secret.
// The secret is only returned at this point and cannot be recovered later.
//
// @Summary Create app registration
// @Description Registers a new OAuth application; the client secret is returned only once
// @Tags App Registrations
// @Accept json
// @Produce json
// @Param request body models.CreateAppRegistrationRequest true "App registration details"
// @Success 201 {object} models.AppRegistrationResponseWithSecret "Created registration with plain-text secret"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations [post]
func (h *AppRegistrationHandler) Create(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.CreateAppRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reg, plainSecret, err := h.appRegService.Create(c.Request.Context(), &req, currentUser.TenantID, currentUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create app registration"})
		return
	}

	c.JSON(http.StatusCreated, reg.ToResponseWithSecret(plainSecret))
}

// Get retrieves an app registration by ID.
//
// @Summary Get app registration
// @Description Retrieves an app registration by its UUID
// @Tags App Registrations
// @Produce json
// @Param id path string true "App registration UUID"
// @Success 200 {object} models.AppRegistrationResponse "App registration details"
// @Failure 400 {object} map[string]string "Invalid registration ID"
// @Failure 404 {object} map[string]string "App registration not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations/{id} [get]
func (h *AppRegistrationHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAppRegistrationID})
		return
	}

	reg, err := h.appRegService.GetByID(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": msgAppRegistrationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve app registration"})
		return
	}

	c.JSON(http.StatusOK, reg.ToResponse())
}

// List returns a paginated list of app registrations.
//
// @Summary List app registrations
// @Description Returns a paginated list of app registrations with optional filters
// @Tags App Registrations
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param tenant_id query string false "Filter by tenant UUID"
// @Param product_id query string false "Filter by product UUID"
// @Param status query string false "Filter by status"
// @Success 200 {object} models.AppRegistrationListResponse "Paginated list of registrations"
// @Failure 400 {object} map[string]string "Invalid filter parameter"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations [get]
func (h *AppRegistrationHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
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

	var productID *uuid.UUID
	if raw := c.Query("product_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid product_id"})
			return
		}
		productID = &parsed
	}

	status := c.Query("status")

	regs, total, err := h.appRegService.List(c.Request.Context(), page, pageSize, tenantID, productID, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list app registrations"})
		return
	}

	responses := make([]models.AppRegistrationResponse, 0, len(regs))
	for i := range regs {
		responses = append(responses, *regs[i].ToResponse())
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, models.AppRegistrationListResponse{
		AppRegistrations: responses,
		Total:            total,
		Page:             page,
		PageSize:         pageSize,
		TotalPages:       totalPages,
	})
}

// Update applies partial updates to an app registration.
//
// @Summary Update app registration
// @Description Applies partial updates to an existing app registration
// @Tags App Registrations
// @Accept json
// @Produce json
// @Param id path string true "App registration UUID"
// @Param request body models.UpdateAppRegistrationRequest true "Fields to update"
// @Success 200 {object} models.AppRegistrationResponse "Updated app registration"
// @Failure 400 {object} map[string]string "Invalid ID or validation error"
// @Failure 404 {object} map[string]string "App registration not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations/{id} [put]
func (h *AppRegistrationHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAppRegistrationID})
		return
	}

	var req models.UpdateAppRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reg, err := h.appRegService.Update(c.Request.Context(), id, &req)
	if err != nil {
		if strings.Contains(err.Error(), msgNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgAppRegistrationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update app registration"})
		return
	}

	c.JSON(http.StatusOK, reg.ToResponse())
}

// RotateSecret generates a new client secret and returns it in plain text.
// The old secret is immediately invalidated.
//
// @Summary Rotate app registration secret
// @Description Generates a new client secret and immediately invalidates the old one; the new secret is shown once
// @Tags App Registrations
// @Produce json
// @Param id path string true "App registration UUID"
// @Success 200 {object} models.AppRegistrationResponseWithSecret "Registration with new plain-text secret"
// @Failure 400 {object} map[string]string "Invalid registration ID"
// @Failure 404 {object} map[string]string "App registration not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations/{id}/rotate-secret [post]
func (h *AppRegistrationHandler) RotateSecret(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAppRegistrationID})
		return
	}

	reg, plainSecret, err := h.appRegService.RotateSecret(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), msgNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgAppRegistrationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate secret"})
		return
	}

	c.JSON(http.StatusOK, reg.ToResponseWithSecret(plainSecret))
}

// Suspend temporarily disables an app registration.
//
// @Summary Suspend app registration
// @Description Temporarily disables an app registration, preventing new tokens from being issued
// @Tags App Registrations
// @Produce json
// @Param id path string true "App registration UUID"
// @Success 200 {object} map[string]string "App registration suspended"
// @Failure 400 {object} map[string]string "Invalid registration ID"
// @Failure 404 {object} map[string]string "App registration not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations/{id}/suspend [post]
func (h *AppRegistrationHandler) Suspend(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAppRegistrationID})
		return
	}

	if err := h.appRegService.Suspend(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgAppRegistrationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to suspend app registration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "App registration suspended"})
}

// Revoke permanently cancels an app registration.
//
// @Summary Revoke app registration
// @Description Permanently cancels an app registration; all issued tokens are invalidated
// @Tags App Registrations
// @Produce json
// @Param id path string true "App registration UUID"
// @Success 200 {object} map[string]string "App registration revoked"
// @Failure 400 {object} map[string]string "Invalid registration ID"
// @Failure 404 {object} map[string]string "App registration not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations/{id}/revoke [post]
func (h *AppRegistrationHandler) Revoke(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAppRegistrationID})
		return
	}

	if err := h.appRegService.Revoke(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgAppRegistrationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke app registration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "App registration revoked"})
}

// Delete permanently removes an app registration.
//
// @Summary Delete app registration
// @Description Permanently removes an app registration record
// @Tags App Registrations
// @Produce json
// @Param id path string true "App registration UUID"
// @Success 204 "App registration deleted"
// @Failure 400 {object} map[string]string "Invalid registration ID"
// @Failure 404 {object} map[string]string "App registration not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/admin/app-registrations/{id} [delete]
func (h *AppRegistrationHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidAppRegistrationID})
		return
	}

	if err := h.appRegService.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgAppRegistrationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete app registration"})
		return
	}

	c.Status(http.StatusNoContent)
}
