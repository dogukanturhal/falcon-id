// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/apierrors"
)

// TenantHostAdminServiceIface is the contract the admin handler
// depends on. Narrow interface so the handler is testable against a
// mock without standing up the real cache + DB + DNS resolver.
type TenantHostAdminServiceIface interface {
	ClaimHost(ctx context.Context, req *services.ClaimHostRequest) (*models.TenantHost, error)
	ListHosts(ctx context.Context, tenantID uuid.UUID) ([]*models.TenantHost, error)
	GetHost(ctx context.Context, id uuid.UUID) (*models.TenantHost, error)
	VerifyOne(ctx context.Context, id uuid.UUID) (*models.TenantHost, error)
	SuspendHost(ctx context.Context, id uuid.UUID) error
	DeleteHost(ctx context.Context, id uuid.UUID) error
}

// TenantHostAdminHandler exposes admin CRUD endpoints for tenant
// custom-domain registrations. Routes mount under
// /api/v1/admin/tenants/:tenant_id/hosts and require tenant-admin
// auth + permission `iam.tenant_hosts.manage`.
//
// Flow for claiming a new custom domain (mirrors Auth0 / Okta / Entra
// B2C UX from the discovery research):
//
//  1. Admin POSTs /hosts with {host, canonical_url}
//     → response returns the host record with `verification_token`
//  2. Admin publishes a DNS TXT record under
//     `_hexxlock-verify.<host>` containing the token
//  3. Admin POSTs /hosts/:id/verify
//     → service performs immediate TXT lookup; on match,
//       status flips to active and discovery starts serving 200
//
// The daily cron worker (sibling MR) keeps active hosts re-verified
// + auto-suspends after 14 consecutive failures.
type TenantHostAdminHandler struct {
	service TenantHostAdminServiceIface
}

// NewTenantHostAdminHandler constructs a handler wired to the
// supplied admin service.
func NewTenantHostAdminHandler(service TenantHostAdminServiceIface) *TenantHostAdminHandler {
	return &TenantHostAdminHandler{service: service}
}

// claimRequest is the public input schema for the POST endpoint.
// Validated by Gin's binding annotations before reaching the service.
type claimRequest struct {
	Host             string                 `json:"host" binding:"required"`
	CanonicalURL     string                 `json:"canonical_url" binding:"required,url"`
	DefaultClientID  *string                `json:"default_client_id,omitempty"`
	BrandingOverride map[string]interface{} `json:"branding_override,omitempty"`
}

// ListHosts handles GET /api/v1/admin/tenants/:tenant_id/hosts.
// Returns every host registered to the tenant (pending + active +
// suspended).
func (h *TenantHostAdminHandler) ListHosts(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}
	hosts, err := h.service.ListHosts(c.Request.Context(), tenantID)
	if err != nil {
		HandleError(c, err)
		return
	}
	Success(c, hosts)
}

// GetHost handles GET /api/v1/admin/tenants/:tenant_id/hosts/:host_id.
func (h *TenantHostAdminHandler) GetHost(c *gin.Context) {
	if _, ok := ParseUUIDParam(c, "tenant_id"); !ok {
		return
	}
	hostID, ok := ParseUUIDParam(c, "host_id")
	if !ok {
		return
	}
	host, err := h.service.GetHost(c.Request.Context(), hostID)
	if err != nil {
		HandleError(c, err)
		return
	}
	if host == nil {
		Error(c, apierrors.NotFound("tenant_host"))
		return
	}
	Success(c, host)
}

// ClaimHost handles POST /api/v1/admin/tenants/:tenant_id/hosts.
// Body: { host, canonical_url, default_client_id?, branding_override? }
// Response: the created TenantHost row including `verification_token`.
//
// Per the cross-vendor consensus (Auth0 / Okta / Entra B2C / Cognito):
// the row starts in `pending_verification` until the admin completes
// the DNS proof. discovery handler returns 503 for pending rows so
// clients can show a "DNS propagating" UX.
func (h *TenantHostAdminHandler) ClaimHost(c *gin.Context) {
	tenantID, ok := ParseUUIDParam(c, "tenant_id")
	if !ok {
		return
	}
	var req claimRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"details": err.Error(),
		})
		return
	}

	svcReq := &services.ClaimHostRequest{
		TenantID:        tenantID,
		Host:            req.Host,
		CanonicalURL:    req.CanonicalURL,
		DefaultClientID: req.DefaultClientID,
	}
	// Re-encode branding override map to raw JSON so the service +
	// repo keep their narrow json.RawMessage contract.
	if len(req.BrandingOverride) > 0 {
		if raw, err := marshalJSON(req.BrandingOverride); err == nil {
			svcReq.BrandingOverride = raw
		}
	}

	host, err := h.service.ClaimHost(c.Request.Context(), svcReq)
	if err != nil {
		HandleError(c, err)
		return
	}
	c.JSON(http.StatusCreated, host)
}

// VerifyOne handles POST /api/v1/admin/tenants/:tenant_id/hosts/:host_id/verify.
// Performs an immediate TXT lookup against the customer's DNS for the
// host's `_hexxlock-verify.<host>` record. On match, transitions
// status to active. On miss, increments verification_failures + 409.
//
// Idempotent — calling on an already-active host is a no-op 200.
func (h *TenantHostAdminHandler) VerifyOne(c *gin.Context) {
	if _, ok := ParseUUIDParam(c, "tenant_id"); !ok {
		return
	}
	hostID, ok := ParseUUIDParam(c, "host_id")
	if !ok {
		return
	}
	host, err := h.service.VerifyOne(c.Request.Context(), hostID)
	switch {
	case err == nil:
		Success(c, host)
	case errors.Is(err, services.ErrHostNotFound):
		Error(c, apierrors.NotFound("tenant_host"))
	case errors.Is(err, services.ErrHostVerificationPending):
		c.JSON(http.StatusConflict, gin.H{
			"error":   "host_verification_pending",
			"details": "DNS TXT record not yet observable — confirm `_hexxlock-verify.<host>` and retry after DNS propagation",
		})
	default:
		HandleError(c, err)
	}
}

// SuspendHost handles POST /api/v1/admin/tenants/:tenant_id/hosts/:host_id/suspend.
// Idempotent: suspends an active or pending host; no-op on already-suspended.
func (h *TenantHostAdminHandler) SuspendHost(c *gin.Context) {
	if _, ok := ParseUUIDParam(c, "tenant_id"); !ok {
		return
	}
	hostID, ok := ParseUUIDParam(c, "host_id")
	if !ok {
		return
	}
	if err := h.service.SuspendHost(c.Request.Context(), hostID); err != nil {
		if errors.Is(err, services.ErrHostNotFound) {
			Error(c, apierrors.NotFound("tenant_host"))
			return
		}
		HandleError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// DeleteHost handles DELETE /api/v1/admin/tenants/:tenant_id/hosts/:host_id.
// Hard-deletes the row. Cache is purged so discovery starts returning
// 404 immediately.
func (h *TenantHostAdminHandler) DeleteHost(c *gin.Context) {
	if _, ok := ParseUUIDParam(c, "tenant_id"); !ok {
		return
	}
	hostID, ok := ParseUUIDParam(c, "host_id")
	if !ok {
		return
	}
	if err := h.service.DeleteHost(c.Request.Context(), hostID); err != nil {
		if errors.Is(err, services.ErrHostNotFound) {
			Error(c, apierrors.NotFound("tenant_host"))
			return
		}
		HandleError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// marshalJSON re-encodes a parsed map into raw JSON for the service's
// json.RawMessage field. Wrapped in a package variable so tests can
// stub it. Failure here is non-fatal — the caller drops the field
// rather than failing the request (the row is still valid without
// a branding override).
var marshalJSON = func(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
