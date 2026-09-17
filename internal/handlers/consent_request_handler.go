// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	msgNotAuthenticatedConsentReq = "Not authenticated"
)

// adminConsentRequestSvc defines the service methods required by ConsentRequestHandler.
type adminConsentRequestSvc interface {
	CreateRequest(ctx context.Context, tenantID uuid.UUID, requesterID uuid.UUID, input models.CreateAdminConsentRequestInput) (*models.AdminConsentRequest, error)
	ApproveRequest(ctx context.Context, requestID uuid.UUID, approverID uuid.UUID) (*models.AdminConsentRequest, error)
	DenyRequest(ctx context.Context, requestID uuid.UUID, approverID uuid.UUID) (*models.AdminConsentRequest, error)
	ListPending(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error)
	ListByApplication(ctx context.Context, appID uuid.UUID) ([]models.AdminConsentRequest, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.AdminConsentRequest, error)
	GetRequest(ctx context.Context, id uuid.UUID) (*models.AdminConsentRequest, error)
}

// ConsentRequestHandler handles HTTP endpoints for the admin consent workflow.
type ConsentRequestHandler struct {
	svc adminConsentRequestSvc
}

// NewConsentRequestHandler creates a new ConsentRequestHandler.
func NewConsentRequestHandler(svc adminConsentRequestSvc) *ConsentRequestHandler {
	return &ConsentRequestHandler{svc: svc}
}

// Create submits a new consent request.
// POST /api/v1/platform/consent-requests
func (h *ConsentRequestHandler) Create(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedConsentReq})
		return
	}

	var input models.CreateAdminConsentRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cr, err := h.svc.CreateRequest(c.Request.Context(), currentUser.TenantID, currentUser.ID, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create consent request"})
		return
	}

	c.JSON(http.StatusCreated, cr)
}

// Approve approves a pending consent request.
// POST /api/v1/platform/consent-requests/:id/approve
func (h *ConsentRequestHandler) Approve(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedConsentReq})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid consent request ID"})
		return
	}

	cr, err := h.svc.ApproveRequest(c.Request.Context(), id, currentUser.ID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Consent request not found"})
			return
		}
		if strings.Contains(err.Error(), "already") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to approve consent request"})
		return
	}

	c.JSON(http.StatusOK, cr)
}

// Deny denies a pending consent request.
// POST /api/v1/platform/consent-requests/:id/deny
func (h *ConsentRequestHandler) Deny(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedConsentReq})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid consent request ID"})
		return
	}

	cr, err := h.svc.DenyRequest(c.Request.Context(), id, currentUser.ID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Consent request not found"})
			return
		}
		if strings.Contains(err.Error(), "already") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deny consent request"})
		return
	}

	c.JSON(http.StatusOK, cr)
}

// ListPending returns all pending consent requests for the caller's tenant.
// GET /api/v1/platform/consent-requests/pending?tenant_id=X
func (h *ConsentRequestHandler) ListPending(c *gin.Context) {
	tenantID, ok := resolveConsentRequestTenantID(c)
	if !ok {
		return
	}

	results, err := h.svc.ListPending(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list pending consent requests"})
		return
	}

	if results == nil {
		results = []models.AdminConsentRequest{}
	}

	c.JSON(http.StatusOK, gin.H{
		"consent_requests": results,
		"total":            len(results),
	})
}

// List returns consent requests filtered by application_id or tenant_id.
// GET /api/v1/platform/consent-requests?application_id=X
// GET /api/v1/platform/consent-requests?tenant_id=X
func (h *ConsentRequestHandler) List(c *gin.Context) {
	if appIDStr := c.Query("application_id"); appIDStr != "" {
		appID, err := uuid.Parse(appIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid application_id"})
			return
		}

		results, err := h.svc.ListByApplication(c.Request.Context(), appID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list consent requests"})
			return
		}

		if results == nil {
			results = []models.AdminConsentRequest{}
		}

		c.JSON(http.StatusOK, gin.H{
			"consent_requests": results,
			"total":            len(results),
		})
		return
	}

	tenantID, ok := resolveConsentRequestTenantID(c)
	if !ok {
		return
	}

	results, err := h.svc.ListByTenant(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list consent requests"})
		return
	}

	if results == nil {
		results = []models.AdminConsentRequest{}
	}

	c.JSON(http.StatusOK, gin.H{
		"consent_requests": results,
		"total":            len(results),
	})
}

// resolveConsentRequestTenantID reads tenant_id from the query string, falling back
// to the caller's own tenant_id from the JWT.  Returns false and writes a JSON error
// response when no tenant can be determined.
func resolveConsentRequestTenantID(c *gin.Context) (uuid.UUID, bool) {
	if raw := c.Query("tenant_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id"})
			return uuid.Nil, false
		}
		return id, true
	}

	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgNotAuthenticatedConsentReq})
		return uuid.Nil, false
	}
	return currentUser.TenantID, true
}
