// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/apierrors"
)

// EmailDomainServiceInterface is the service contract consumed by EmailDomainHandler.
// Declaring it here (rather than importing from services) keeps the handler layer
// decoupled and trivially mockable in tests.
type EmailDomainServiceInterface interface {
	ListDomains(ctx context.Context, tenantID uuid.UUID) ([]*models.EmailDomainRegistry, error)
	RegisterDomain(ctx context.Context, tenantID uuid.UUID, req *models.CreateEmailDomainRequest) (*models.EmailDomainRegistry, error)
	VerifyDomain(ctx context.Context, domainID uuid.UUID) error
	DeleteDomain(ctx context.Context, domainID uuid.UUID) error
	GetDomain(ctx context.Context, domainID uuid.UUID) (*models.EmailDomainRegistry, error)
	UpdateDomain(ctx context.Context, domainID uuid.UUID, autoEnroll bool) (*models.EmailDomainRegistry, error)
}

// EmailDomainHandler exposes admin CRUD endpoints for tenant email domain registrations.
// Routes are mounted under /api/v1/admin/tenants/:tenant_id/domains.
type EmailDomainHandler struct {
	service EmailDomainServiceInterface
}

// NewEmailDomainHandler constructs an EmailDomainHandler with the supplied service.
func NewEmailDomainHandler(service EmailDomainServiceInterface) *EmailDomainHandler {
	return &EmailDomainHandler{service: service}
}

// ListDomains handles GET /api/v1/admin/tenants/:tenant_id/domains.
// Returns all email domain registrations for the specified tenant.
func (h *EmailDomainHandler) ListDomains(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	domains, err := h.service.ListDomains(c.Request.Context(), tenantID)
	if err != nil {
		HandleError(c, err)
		return
	}

	Success(c, domains)
}

// GetDomain handles GET /api/v1/admin/tenants/:tenant_id/domains/:domain_id.
// Returns a single domain registration.
func (h *EmailDomainHandler) GetDomain(c *gin.Context) {
	_, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	domainID, ok := ParseUUIDParam(c, "domain_id")
	if !ok {
		return
	}

	domain, err := h.service.GetDomain(c.Request.Context(), domainID)
	if err != nil {
		HandleError(c, err)
		return
	}
	if domain == nil {
		Error(c, apierrors.NotFound("domain"))
		return
	}

	Success(c, domain)
}

// RegisterDomain handles POST /api/v1/admin/tenants/:tenant_id/domains.
// Creates a new domain registration and returns it with a verification token hint.
func (h *EmailDomainHandler) RegisterDomain(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	var req models.CreateEmailDomainRequest
	if !BindJSON(c, &req) {
		return
	}

	entry, err := h.service.RegisterDomain(c.Request.Context(), tenantID, &req)
	if err != nil {
		HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, Response{
		Success: true,
		Data:    entry,
	})
}

// VerifyDomain handles POST /api/v1/admin/tenants/:tenant_id/domains/:domain_id/verify.
// Marks the domain as verified. The operation is idempotent.
func (h *EmailDomainHandler) VerifyDomain(c *gin.Context) {
	_, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	domainID, ok := ParseUUIDParam(c, "domain_id")
	if !ok {
		return
	}

	if err := h.service.VerifyDomain(c.Request.Context(), domainID); err != nil {
		HandleError(c, err)
		return
	}

	Success(c, gin.H{"message": "domain verified"})
}

// UpdateDomain handles PATCH /api/v1/admin/tenants/:tenant_id/domains/:domain_id.
// Updates a domain registration's auto_enroll setting.
func (h *EmailDomainHandler) UpdateDomain(c *gin.Context) {
	_, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	domainID, ok := ParseUUIDParam(c, "domain_id")
	if !ok {
		return
	}

	var req models.UpdateEmailDomainRequest
	if !BindJSON(c, &req) {
		return
	}

	updated, err := h.service.UpdateDomain(c.Request.Context(), domainID, *req.AutoEnroll)
	if err != nil {
		HandleError(c, err)
		return
	}

	Success(c, updated)
}

// DeleteDomain handles DELETE /api/v1/admin/tenants/:tenant_id/domains/:domain_id.
// Removes a domain registration permanently.
func (h *EmailDomainHandler) DeleteDomain(c *gin.Context) {
	_, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}

	domainID, ok := ParseUUIDParam(c, "domain_id")
	if !ok {
		return
	}

	if err := h.service.DeleteDomain(c.Request.Context(), domainID); err != nil {
		HandleError(c, err)
		return
	}

	NoContent(c)
}
