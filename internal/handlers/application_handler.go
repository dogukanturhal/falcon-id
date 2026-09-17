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
	msgNotAuthenticatedApp           = "Not authenticated"
	msgInvalidApplicationID          = "Invalid application ID"
	msgApplicationNotFound           = "Application not found"
	msgAppNotFound                   = "not found"
	msgInvalidServicePrincipalID     = "Invalid service principal ID"
	msgDoesNotBelong                 = "does not belong"
	msgServicePrincipalNotFound      = "Service principal not found"
	msgConsentServiceNotAvailable    = "Consent service not available"
	msgCredentialServiceNotAvailable = "Credential service not available" //nolint:gosec // not a credential, this is a route prefix constant
	msgOwnerServiceNotAvailable      = "Owner service not available"
	msgAppIDPServiceNotAvailable     = "App IdP service not available"
	queryBoolTrue                    = "true"
)

// ApplicationHandler handles Application Object HTTP endpoints.
type ApplicationHandler struct {
	appService     *services.ApplicationService
	consentService *services.AppConsentService
	credService    *services.SPCredentialService
	ownerService   *services.ApplicationOwnerService
	signInService  *services.SPSignInActivityService
	staleDetection *services.StaleAppDetectionService
	appIDPService  *services.AppIdentityProviderService
}

// NewApplicationHandler creates a new application handler.
func NewApplicationHandler(
	appService *services.ApplicationService,
	consentService *services.AppConsentService,
	credService *services.SPCredentialService,
) *ApplicationHandler {
	return &ApplicationHandler{
		appService:     appService,
		consentService: consentService,
		credService:    credService,
	}
}

// SetOwnerService injects the application owner service (P1 enterprise gap).
func (h *ApplicationHandler) SetOwnerService(svc *services.ApplicationOwnerService) {
	h.ownerService = svc
}

// SetSignInActivityService injects the SP sign-in activity service (P1 enterprise gap).
func (h *ApplicationHandler) SetSignInActivityService(svc *services.SPSignInActivityService) {
	h.signInService = svc
}

// SetStaleDetectionService injects the stale app detection service (P1 enterprise gap).
func (h *ApplicationHandler) SetStaleDetectionService(svc *services.StaleAppDetectionService) {
	h.staleDetection = svc
}

// SetAppIDPService is an exported identifier.
// SetAppIDPService injects the per-app IDP enablement service.
func (h *ApplicationHandler) SetAppIDPService(svc *services.AppIdentityProviderService) {
	h.appIDPService = svc
}

// ============================================================================
// Application CRUD
// ============================================================================

// Create registers a new Application Object.
//
// @Summary Create application
// @Description Registers a new Application Object in the platform
// @Tags Applications
// @Accept json
// @Produce json
// @Param request body models.CreateApplicationRequest true "Application details"
// @Success 201 {object} models.ApplicationResponse "Application created"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 409 {object} map[string]string "Application slug already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications [post]
func (h *ApplicationHandler) Create(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedApp})
		return
	}

	var req models.CreateApplicationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	app, err := h.appService.Create(c.Request.Context(), &req, &currentUser.ID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "Application with this slug already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create application"})
		return
	}

	c.JSON(http.StatusCreated, app.ToResponse())
}

// Get retrieves an Application Object by ID.
//
// @Summary Get application
// @Description Retrieves an Application Object by its UUID
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} models.ApplicationResponse "Application details"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id} [get]
func (h *ApplicationHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	app, err := h.appService.GetByID(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve application"})
		return
	}

	resp := app.ToResponse()

	// Enrich with SP count
	spCount, _ := h.appService.GetServicePrincipalCount(c.Request.Context(), id)
	resp.ServicePrincipalCount = int(spCount)

	c.JSON(http.StatusOK, resp)
}

// List returns a paginated list of Application Objects.
//
// @Summary List applications
// @Description Returns a paginated list of Application Objects with optional filters
// @Tags Applications
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Results per page" default(20)
// @Param status query string false "Filter by status"
// @Param publisher_type query string false "Filter by publisher type"
// @Param is_platform_app query bool false "Filter by platform app flag"
// @Success 200 {object} models.ApplicationListResponse "Paginated list of applications"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications [get]
func (h *ApplicationHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	status := c.Query("status")
	publisherType := c.Query("publisher_type")

	var isPlatformApp *bool
	if raw := c.Query("is_platform_app"); raw != "" {
		val := raw == queryBoolTrue
		isPlatformApp = &val
	}

	apps, total, err := h.appService.List(c.Request.Context(), page, pageSize, status, publisherType, isPlatformApp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list applications"})
		return
	}

	responses := make([]models.ApplicationResponse, 0, len(apps))
	for i := range apps {
		resp := apps[i].ToResponse()
		spCount, _ := h.appService.GetServicePrincipalCount(c.Request.Context(), apps[i].ID)
		resp.ServicePrincipalCount = int(spCount)
		responses = append(responses, *resp)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, models.ApplicationListResponse{
		Applications: responses,
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	})
}

// Update applies partial updates to an Application Object.
//
// @Summary Update application
// @Description Applies partial updates to an existing Application Object
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.UpdateApplicationRequest true "Fields to update"
// @Success 200 {object} models.ApplicationResponse "Updated application"
// @Failure 400 {object} map[string]string "Invalid application ID or validation error"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id} [put]
func (h *ApplicationHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.UpdateApplicationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	app, err := h.appService.Update(c.Request.Context(), id, &req)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update application"})
		return
	}

	c.JSON(http.StatusOK, app.ToResponse())
}

// Delete initiates a soft-delete (or hard-deletes if already soft-deleted).
//
// @Summary Delete application
// @Description Initiates a soft-delete of the application; hard-deletes if already soft-deleted
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 204 "Application deleted"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id} [delete]
func (h *ApplicationHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	if err := h.appService.Delete(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete application"})
		return
	}

	c.Status(http.StatusNoContent)
}

// RestoreApplication cancels a pending soft-delete and makes the application active again.
//
// @Summary Restore deleted application
// @Description Cancels a pending soft-delete and restores the application to active status
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} models.ApplicationResponse "Restored application"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 410 {object} map[string]string "Purge window has elapsed; cannot restore"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/restore [post]
func (h *ApplicationHandler) RestoreApplication(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	app, err := h.appService.Restore(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "cannot be restored") || strings.Contains(err.Error(), "purge window") {
			c.JSON(http.StatusGone, gin.H{"error": "Application cannot be restored: purge window has elapsed or application not found"})
			return
		}
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore application"})
		return
	}

	c.JSON(http.StatusOK, app.ToResponse())
}

// ListDeleted returns all soft-deleted applications still within their 30-day grace period.
//
// @Summary List soft-deleted applications
// @Description Returns all applications that are soft-deleted and within the 30-day grace period
// @Tags Applications
// @Produce json
// @Success 200 {object} map[string]interface{} "List of soft-deleted applications"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/deleted [get]
func (h *ApplicationHandler) ListDeleted(c *gin.Context) {
	apps, err := h.appService.ListDeleted(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list deleted applications"})
		return
	}

	responses := make([]models.ApplicationResponse, 0, len(apps))
	for i := range apps {
		responses = append(responses, *apps[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"applications": responses,
		"total":        len(responses),
	})
}

// ============================================================================
// Service Principal Provisioning & Management
// ============================================================================

// ProvisionServicePrincipal creates a service principal for an application in a tenant.
//
// @Summary Provision service principal
// @Description Creates a service principal for an application in the specified tenant
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.ProvisionServicePrincipalRequest true "Provisioning details"
// @Success 201 {object} models.ServicePrincipalResponse "Service principal created"
// @Failure 400 {object} map[string]string "Validation error or unsupported operation"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals [post]
func (h *ApplicationHandler) ProvisionServicePrincipal(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.ProvisionServicePrincipalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.ApplicationID = id

	resp, err := h.appService.ProvisionServicePrincipal(c.Request.Context(), req.ApplicationID, req.TenantID, req.ScopeOverrides)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		if strings.Contains(err.Error(), "not active") || strings.Contains(err.Error(), "not supported") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to provision service principal"})
		return
	}

	c.JSON(http.StatusCreated, resp)
}

// ListServicePrincipals returns all SPs for an application.
//
// @Summary List service principals
// @Description Returns all service principals provisioned for an application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} map[string]interface{} "List of service principals"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals [get]
func (h *ApplicationHandler) ListServicePrincipals(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	sps, err := h.appService.ListServicePrincipals(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service principals"})
		return
	}

	responses := make([]models.ServicePrincipalResponse, 0, len(sps))
	for i := range sps {
		responses = append(responses, sps[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"service_principals": responses,
		"total":              len(responses),
	})
}

// GetServicePrincipal retrieves a single SP belonging to an application.
//
// @Summary Get service principal
// @Description Retrieves a single service principal by ID for an application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Success 200 {object} models.ServicePrincipalResponse "Service principal details"
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 404 {object} map[string]string "Service principal not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id} [get]
func (h *ApplicationHandler) GetServicePrincipal(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	sp, err := h.appService.GetSP(c.Request.Context(), id, spID)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) || strings.Contains(err.Error(), msgDoesNotBelong) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgServicePrincipalNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get service principal"})
		return
	}

	c.JSON(http.StatusOK, sp.ToResponse())
}

// EnableServicePrincipal enables a service principal.
//
// @Summary Enable service principal
// @Description Transitions a service principal to the enabled state
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Success 200 {object} models.ServicePrincipalResponse "Enabled service principal"
// @Failure 400 {object} map[string]string "Invalid ID or invalid state transition"
// @Failure 404 {object} map[string]string "Service principal not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/enable [post]
func (h *ApplicationHandler) EnableServicePrincipal(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	sp, err := h.appService.EnableSP(c.Request.Context(), id, spID)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) || strings.Contains(err.Error(), msgDoesNotBelong) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgServicePrincipalNotFound})
			return
		}
		if strings.Contains(err.Error(), "invalid transition") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable service principal"})
		return
	}

	c.JSON(http.StatusOK, sp.ToResponse())
}

// DisableServicePrincipal disables a service principal.
//
// @Summary Disable service principal
// @Description Transitions a service principal to the disabled state
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Success 200 {object} models.ServicePrincipalResponse "Disabled service principal"
// @Failure 400 {object} map[string]string "Invalid ID or invalid state transition"
// @Failure 404 {object} map[string]string "Service principal not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/disable [post]
func (h *ApplicationHandler) DisableServicePrincipal(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	sp, err := h.appService.DisableSP(c.Request.Context(), id, spID)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) || strings.Contains(err.Error(), msgDoesNotBelong) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgServicePrincipalNotFound})
			return
		}
		if strings.Contains(err.Error(), "invalid transition") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable service principal"})
		return
	}

	c.JSON(http.StatusOK, sp.ToResponse())
}

// DeleteServicePrincipal deletes a service principal.
//
// @Summary Delete service principal
// @Description Permanently deletes a service principal from an application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Success 204 "Service principal deleted"
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 404 {object} map[string]string "Service principal not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id} [delete]
func (h *ApplicationHandler) DeleteServicePrincipal(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	if err := h.appService.DeleteSP(c.Request.Context(), id, spID); err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) || strings.Contains(err.Error(), msgDoesNotBelong) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgServicePrincipalNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service principal"})
		return
	}

	c.Status(http.StatusNoContent)
}

// RotateServicePrincipalCredentials rotates credentials for an SP.
//
// @Summary Rotate service principal credentials
// @Description Rotates the client credentials for the specified service principal
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Success 200 {object} map[string]interface{} "New credentials"
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 404 {object} map[string]string "Service principal not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/rotate-credentials [post]
func (h *ApplicationHandler) RotateServicePrincipalCredentials(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	resp, err := h.appService.RotateSPCredentials(c.Request.Context(), id, spID)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) || strings.Contains(err.Error(), msgDoesNotBelong) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgServicePrincipalNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate credentials"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// BulkProvisionServicePrincipals provisions SPs in multiple tenants.
//
// @Summary Bulk provision service principals
// @Description Provisions service principals for an application across multiple tenants
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.BulkProvisionRequest true "List of tenant IDs"
// @Success 200 {object} map[string]interface{} "Bulk provision results"
// @Failure 400 {object} map[string]string "Invalid application ID or validation error"
// @Router /api/v1/platform/applications/{id}/service-principals/bulk [post]
func (h *ApplicationHandler) BulkProvisionServicePrincipals(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.BulkProvisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results := h.appService.BulkProvisionServicePrincipals(c.Request.Context(), id, req.TenantIDs)

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
	})
}

// ListServicePrincipalsByTenant returns SPs for a tenant across apps.
//
// @Summary List service principals by tenant
// @Description Returns all service principals for a given tenant across all applications
// @Tags Applications
// @Produce json
// @Param tenant_id query string true "Tenant UUID"
// @Success 200 {object} map[string]interface{} "List of service principals"
// @Failure 400 {object} map[string]string "Missing or invalid tenant_id"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/service-principals [get]
func (h *ApplicationHandler) ListServicePrincipalsByTenant(c *gin.Context) {
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

	sps, err := h.appService.ListSPsByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service principals"})
		return
	}

	responses := make([]models.ServicePrincipalResponse, 0, len(sps))
	for i := range sps {
		responses = append(responses, sps[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"service_principals": responses,
		"total":              len(responses),
	})
}

// ============================================================================
// Consent Endpoints (B2)
// ============================================================================

// GrantConsent grants admin consent for an application.
//
// @Summary Grant application consent
// @Description Grants admin or user consent for an application in a tenant
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.GrantConsentRequest true "Consent details"
// @Success 201 {object} models.AppConsentResponse "Consent granted"
// @Failure 400 {object} map[string]string "Validation error or invalid consent type"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 501 {object} map[string]string "Consent service not available"
// @Router /api/v1/platform/applications/{id}/consent [post]
func (h *ApplicationHandler) GrantConsent(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedApp})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.GrantConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default tenant_id to the authenticated user's tenant when not provided.
	if req.TenantID == uuid.Nil {
		req.TenantID = currentUser.TenantID
	}
	// Default consent type to admin when not provided.
	if req.ConsentType == "" {
		req.ConsentType = models.AppConsentTypeAdmin
	}

	if h.consentService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgConsentServiceNotAvailable})
		return
	}

	var consent *models.AppConsent
	switch req.ConsentType {
	case models.AppConsentTypeAdmin:
		consent, err = h.consentService.GrantAdminConsent(c.Request.Context(), id, req.TenantID, currentUser.ID, req.Scopes)
	case models.AppConsentTypeUser:
		consent, err = h.consentService.GrantUserConsent(c.Request.Context(), id, req.TenantID, currentUser.ID, req.Scopes)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid consent type"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to grant consent"})
		return
	}

	c.JSON(http.StatusCreated, consent.ToResponse())
}

// RevokeConsent revokes consent for an application in a tenant.
//
// @Summary Revoke application consent
// @Description Revokes all consent grants for an application in the specified tenant
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param tenant_id query string true "Tenant UUID"
// @Success 204 "Consent revoked"
// @Failure 400 {object} map[string]string "Missing or invalid tenant_id"
// @Failure 501 {object} map[string]string "Consent service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/consent [delete]
func (h *ApplicationHandler) RevokeConsent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

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

	if h.consentService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgConsentServiceNotAvailable})
		return
	}

	if err := h.consentService.RevokeAllForAppInTenant(c.Request.Context(), id, tenantID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke consent"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ListConsents returns all consents for an application.
//
// @Summary List application consents
// @Description Returns all consent records for an application across all tenants
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} models.AppConsentListResponse "List of consents"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 501 {object} map[string]string "Consent service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/consents [get]
func (h *ApplicationHandler) ListConsents(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	if h.consentService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgConsentServiceNotAvailable})
		return
	}

	consents, err := h.consentService.ListByApp(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list consents"})
		return
	}

	responses := make([]models.AppConsentResponse, 0, len(consents))
	for i := range consents {
		responses = append(responses, consents[i].ToResponse())
	}

	c.JSON(http.StatusOK, models.AppConsentListResponse{
		Consents: responses,
		Total:    len(responses),
	})
}

// ============================================================================
// Publisher Verification (C1)
// ============================================================================

// VerifyPublisher marks an application as publisher-verified.
//
// @Summary Verify application publisher
// @Description Marks an application as publisher-verified against a domain
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.VerifyPublisherRequest true "Publisher domain"
// @Success 200 {object} models.ApplicationResponse "Verified application"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/verify-publisher [post]
func (h *ApplicationHandler) VerifyPublisher(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.VerifyPublisherRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	app, err := h.appService.VerifyPublisher(c.Request.Context(), id, req.Domain)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify publisher"})
		return
	}

	c.JSON(http.StatusOK, app.ToResponse())
}

// RevokePublisherVerification removes publisher verification.
//
// @Summary Revoke publisher verification
// @Description Removes the publisher-verified status from an application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} models.ApplicationResponse "Application with verification revoked"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 404 {object} map[string]string "Application not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/verify-publisher [delete]
func (h *ApplicationHandler) RevokePublisherVerification(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	app, err := h.appService.RevokeVerification(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": msgApplicationNotFound})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke verification"})
		return
	}

	c.JSON(http.StatusOK, app.ToResponse())
}

// ============================================================================
// SP Credentials (A3)
// ============================================================================

// ListSPCredentials returns credentials for a service principal.
//
// @Summary List SP credentials
// @Description Returns all credentials registered for a service principal
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Success 200 {object} map[string]interface{} "List of credentials"
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 501 {object} map[string]string "Credential service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/credentials [get]
func (h *ApplicationHandler) ListSPCredentials(c *gin.Context) {
	_, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	if h.credService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgCredentialServiceNotAvailable})
		return
	}

	creds, err := h.credService.ListCredentials(c.Request.Context(), spID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list credentials"})
		return
	}

	responses := make([]models.SPCredentialResponse, 0, len(creds))
	for i := range creds {
		responses = append(responses, creds[i].ToResponse())
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials": responses,
		"total":       len(responses),
	})
}

// AddSPCredential adds a new credential to a service principal.
//
// @Summary Add SP credential
// @Description Adds a new RSA key, client secret, or X.509 certificate credential to a service principal
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Param request body models.AddSPCredentialRequest true "Credential details"
// @Success 201 {object} models.AddSPCredentialResponse "New credential (private key/secret shown once)"
// @Failure 400 {object} map[string]string "Validation error or invalid credential type"
// @Failure 501 {object} map[string]string "Credential service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/credentials [post]
func (h *ApplicationHandler) AddSPCredential(c *gin.Context) {
	_, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	var req models.AddSPCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.credService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgCredentialServiceNotAvailable})
		return
	}

	resp, ok := h.buildSPCredentialResponse(c, spID, &req)
	if !ok {
		return // response already written
	}

	c.JSON(http.StatusCreated, resp)
}

// buildSPCredentialResponse dispatches credential creation by type and builds the response.
// Returns (response, true) on success, or (_, false) after writing an error response.
func (h *ApplicationHandler) buildSPCredentialResponse(c *gin.Context, spID uuid.UUID, req *models.AddSPCredentialRequest) (models.AddSPCredentialResponse, bool) {
	var resp models.AddSPCredentialResponse
	switch req.CredentialType {
	case models.SPCredentialTypeRSAKey:
		cred, privKey, err := h.credService.AddRSAKeyCredential(c.Request.Context(), spID, req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add RSA key credential"})
			return resp, false
		}
		resp.Credential = cred.ToResponse()
		resp.PrivateKey = &privKey
	case models.SPCredentialTypeClientSecret:
		cred, secret, err := h.credService.AddSecretCredential(c.Request.Context(), spID, req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add secret credential"})
			return resp, false
		}
		resp.Credential = cred.ToResponse()
		resp.ClientSecret = &secret
	case models.SPCredentialTypeCertificate:
		if !h.addCertificateCredential(c, spID, req, &resp) {
			return resp, false
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credential type"})
		return resp, false
	}
	return resp, true
}

// addCertificateCredential handles the x509 certificate credential case.
// Returns true on success, false after writing an error response.
func (h *ApplicationHandler) addCertificateCredential(c *gin.Context, spID uuid.UUID, req *models.AddSPCredentialRequest, resp *models.AddSPCredentialResponse) bool {
	if req.CertificatePEM == nil || *req.CertificatePEM == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "certificate_pem is required for x509_certificate type"})
		return false
	}
	cred, certInfo, err := h.credService.AddCertificateCredential(c.Request.Context(), spID, *req.CertificatePEM, req.ExpiresAt)
	if err != nil {
		status, body := classifyCertificateError(err)
		c.JSON(status, body)
		return false
	}
	resp.Credential = cred.ToResponse()
	resp.CertificateInfo = certInfo
	return true
}

// classifyCertificateError maps a certificate credential error to the appropriate HTTP status and body.
func classifyCertificateError(err error) (int, gin.H) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "policy violation"):
		return http.StatusBadRequest, gin.H{"error": msg}
	case strings.Contains(msg, "invalid PEM") || strings.Contains(msg, "parse cert"):
		return http.StatusBadRequest, gin.H{"error": "Invalid X.509 certificate: " + msg}
	default:
		return http.StatusInternalServerError, gin.H{"error": "Failed to add certificate credential"}
	}
}

// RevokeSPCredential revokes a credential.
//
// @Summary Revoke SP credential
// @Description Immediately revokes and removes a credential from a service principal
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Param cred_id path string true "Credential UUID"
// @Success 204 "Credential revoked"
// @Failure 400 {object} map[string]string "Invalid credential ID or already revoked"
// @Failure 404 {object} map[string]string "Credential not found"
// @Failure 501 {object} map[string]string "Credential service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/credentials/{cred_id} [delete]
func (h *ApplicationHandler) RevokeSPCredential(c *gin.Context) {
	credID, err := uuid.Parse(c.Param("cred_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid credential ID"})
		return
	}

	if h.credService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgCredentialServiceNotAvailable})
		return
	}

	if err := h.credService.RevokeCredential(c.Request.Context(), credID); err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Credential not found"})
			return
		}
		if strings.Contains(err.Error(), "already") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke credential"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================================
// Application Owners (P1 Enterprise Gap)
// ============================================================================

// ListOwners returns all owners for an application.
//
// @Summary List application owners
// @Description Returns all registered owners for an application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} models.ApplicationOwnerListResponse "List of owners"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 501 {object} map[string]string "Owner service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/owners [get]
func (h *ApplicationHandler) ListOwners(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	if h.ownerService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgOwnerServiceNotAvailable})
		return
	}

	owners, err := h.ownerService.ListOwners(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list owners"})
		return
	}

	c.JSON(http.StatusOK, models.ApplicationOwnerListResponse{
		Owners: owners,
		Total:  len(owners),
	})
}

// AddOwner adds a new owner to an application.
//
// @Summary Add application owner
// @Description Adds a new owner to an application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.AddOwnerRequest true "Owner details"
// @Success 201 {object} map[string]interface{} "Owner added"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 401 {object} map[string]string "Not authenticated"
// @Failure 409 {object} map[string]string "Owner already exists"
// @Failure 501 {object} map[string]string "Owner service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/owners [post]
func (h *ApplicationHandler) AddOwner(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedApp})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.AddOwnerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.ownerService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgOwnerServiceNotAvailable})
		return
	}

	owner, err := h.ownerService.AddOwner(c.Request.Context(), id, &req, &currentUser.ID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "Owner already exists for this application"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add owner"})
		return
	}

	c.JSON(http.StatusCreated, owner)
}

// RemoveOwner removes an owner from an application.
//
// @Summary Remove application owner
// @Description Removes an owner from an application; fails if this is the last owner
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param owner_id path string true "Owner UUID"
// @Success 204 "Owner removed"
// @Failure 400 {object} map[string]string "Invalid ID or last owner cannot be removed"
// @Failure 501 {object} map[string]string "Owner service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/owners/{owner_id} [delete]
func (h *ApplicationHandler) RemoveOwner(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	ownerID, err := uuid.Parse(c.Param("owner_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid owner ID"})
		return
	}

	if h.ownerService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgOwnerServiceNotAvailable})
		return
	}

	if err := h.ownerService.RemoveOwner(c.Request.Context(), id, ownerID); err != nil {
		if strings.Contains(err.Error(), "last owner") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot remove the last owner of an application"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove owner"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ============================================================================
// SP Sign-in Activity (P1 Enterprise Gap)
// ============================================================================

// ListAppSignIns returns sign-in activity across all SPs for an application.
//
// @Summary List application sign-in activity
// @Description Returns recent sign-in activity across all service principals for an application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param limit query int false "Maximum number of records to return" default(50)
// @Success 200 {object} models.SPSignInActivityListResponse "Sign-in activity"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 501 {object} map[string]string "Sign-in activity service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/sign-in-activity [get]
func (h *ApplicationHandler) ListAppSignIns(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 || limit > 500 {
		limit = 50
	}

	if h.signInService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "Sign-in activity service not available"})
		return
	}

	activities, err := h.signInService.ListByApp(c.Request.Context(), id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list sign-in activity"})
		return
	}

	c.JSON(http.StatusOK, models.SPSignInActivityListResponse{
		Activities: activities,
		Total:      len(activities),
	})
}

// ListSPSignIns returns sign-in activity for a specific service principal.
//
// @Summary List SP sign-in activity
// @Description Returns recent sign-in activity for a specific service principal
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param sp_id path string true "Service principal UUID"
// @Param limit query int false "Maximum number of records to return" default(50)
// @Success 200 {object} models.SPSignInActivityListResponse "SP sign-in activity"
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 501 {object} map[string]string "Sign-in activity service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/service-principals/{sp_id}/sign-in-activity [get]
func (h *ApplicationHandler) ListSPSignIns(c *gin.Context) {
	_, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}
	spID, err := uuid.Parse(c.Param("sp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidServicePrincipalID})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 || limit > 500 {
		limit = 50
	}

	if h.signInService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "Sign-in activity service not available"})
		return
	}

	activities, err := h.signInService.ListBySP(c.Request.Context(), spID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list sign-in activity"})
		return
	}

	c.JSON(http.StatusOK, models.SPSignInActivityListResponse{
		Activities: activities,
		Total:      len(activities),
	})
}

// ============================================================================
// Stale Application Detection (P1 Enterprise Gap)
// ============================================================================

// DetectStaleApps scans all applications and returns those classified as stale.
//
// @Summary Detect stale applications
// @Description Scans all applications and returns those classified as stale based on inactivity
// @Tags Applications
// @Produce json
// @Success 200 {object} map[string]interface{} "Stale application detection results"
// @Failure 501 {object} map[string]string "Stale detection service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/stale [get]
func (h *ApplicationHandler) DetectStaleApps(c *gin.Context) {
	if h.staleDetection == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "Stale detection service not available"})
		return
	}

	result, err := h.staleDetection.DetectStaleApps(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to detect stale applications"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ============================================================================
// Per-App Identity Provider Enablement
// ============================================================================

// ListAppIdentityProviders returns IDPs enabled for an application.
//
// @Summary List application identity providers
// @Description Returns all identity providers enabled for a specific application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Success 200 {object} map[string]interface{} "List of enabled identity providers"
// @Failure 400 {object} map[string]string "Invalid application ID"
// @Failure 501 {object} map[string]string "App IDP service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/identity-providers [get]
func (h *ApplicationHandler) ListAppIdentityProviders(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	if h.appIDPService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgAppIDPServiceNotAvailable})
		return
	}

	idps, err := h.appIDPService.ListEnabledIDPs(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list application identity providers"})
		return
	}

	if idps == nil {
		idps = []models.AppIdentityProvider{}
	}

	c.JSON(http.StatusOK, gin.H{
		"identity_providers": idps,
		"total":              len(idps),
	})
}

// EnableAppIdentityProvider enables an IDP for an application.
//
// @Summary Enable IDP for application
// @Description Enables an identity provider for the specified application
// @Tags Applications
// @Accept json
// @Produce json
// @Param id path string true "Application UUID"
// @Param request body models.CreateAppIdentityProviderRequest true "IDP details"
// @Success 201 {object} models.AppIdentityProvider "Enabled IDP record"
// @Failure 400 {object} map[string]string "Validation error"
// @Failure 409 {object} map[string]string "IDP already enabled for this application"
// @Failure 501 {object} map[string]string "App IDP service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/identity-providers [post]
func (h *ApplicationHandler) EnableAppIdentityProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	var req models.CreateAppIdentityProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.appIDPService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgAppIDPServiceNotAvailable})
		return
	}

	record, err := h.appIDPService.EnableIDPForApp(c.Request.Context(), id, &req)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "IdP is already enabled for this application"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable IdP for application"})
		return
	}

	c.JSON(http.StatusCreated, record)
}

// DisableAppIdentityProvider removes an IDP from an application.
//
// @Summary Disable IDP for application
// @Description Removes an identity provider from the specified application
// @Tags Applications
// @Produce json
// @Param id path string true "Application UUID"
// @Param idp_id path string true "Identity provider UUID"
// @Success 204 "IDP disabled"
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 404 {object} map[string]string "Identity provider not found for this application"
// @Failure 501 {object} map[string]string "App IDP service not available"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/platform/applications/{id}/identity-providers/{idp_id} [delete]
func (h *ApplicationHandler) DisableAppIdentityProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgInvalidApplicationID})
		return
	}

	idpID, err := uuid.Parse(c.Param("idp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid identity provider ID"})
		return
	}

	if h.appIDPService == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": msgAppIDPServiceNotAvailable})
		return
	}

	if err := h.appIDPService.DisableIDPForApp(c.Request.Context(), id, idpID); err != nil {
		if strings.Contains(err.Error(), msgAppNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found for this application"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable IdP for application"})
		return
	}

	c.Status(http.StatusNoContent)
}
