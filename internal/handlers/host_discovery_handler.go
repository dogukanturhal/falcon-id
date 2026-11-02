// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// HostDiscoveryServiceIface is the contract the handler depends on.
// Narrow interface so the handler is testable against a mock — keeps
// the handler test fast and free of real DB / cache state.
type HostDiscoveryServiceIface interface {
	Discover(ctx context.Context, rawHost string) (*models.HostDiscoveryResponse, error)
}

// HostDiscoveryHandler serves the internal host-based tenant discovery
// endpoint. Mounted under `/internal/v1/` so APISIX (the public edge)
// will NOT route to it from off-cluster — the research consensus
// explicitly warns "never expose the internal endpoint at the edge —
// host header injection becomes trivial otherwise."
//
// The Next.js SDK middleware on the unified-dashboard tenants
// deployment is the canonical caller, hitting
// `http://falcon-id-falcon-id.falcon-id.svc.cluster.local/internal/v1/
// tenant-discovery?host=<host>` from its server-side middleware.
type HostDiscoveryHandler struct {
	service HostDiscoveryServiceIface
}

// NewHostDiscoveryHandler constructs a handler wired to the given service.
func NewHostDiscoveryHandler(service HostDiscoveryServiceIface) *HostDiscoveryHandler {
	return &HostDiscoveryHandler{service: service}
}

// Discover handles GET /internal/v1/tenant-discovery?host=<host>.
//
// Status code policy (synthesized from Auth0 / Okta / Entra B2C /
// Cognito custom-domain handling):
//
//	200 OK                    — host is registered + active
//	400 Bad Request           — missing or malformed host param
//	404 Not Found             — host not registered (no silent fallback)
//	410 Gone                  — host registered but suspended
//	503 Service Unavailable   — host registered, awaiting DNS verification
//	500 Internal Server Error — unexpected service error
//
// Cache hints emitted to allow the SDK to layer its own short-lived
// in-process cache on top without rebuilding the policy:
//
//	200 → Cache-Control: public, max-age=300   (5 min positive)
//	404 → Cache-Control: public, max-age=30    (30 s negative)
//	410 → Cache-Control: public, max-age=30
//	503 → Cache-Control: no-store              (DNS state churns)
func (h *HostDiscoveryHandler) Discover(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"details": "missing required query parameter `host`",
		})
		return
	}

	resp, err := h.service.Discover(c.Request.Context(), host)
	switch {
	case err == nil:
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, resp)
	case errors.Is(err, services.ErrHostNotFound):
		c.Header("Cache-Control", "public, max-age=30")
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "host_not_found",
			"details": "no tenant_host registered for the supplied host",
		})
	case errors.Is(err, services.ErrHostSuspended):
		c.Header("Cache-Control", "public, max-age=30")
		c.JSON(http.StatusGone, gin.H{
			"error":   "host_suspended",
			"details": "the registered tenant_host is suspended",
		})
	case errors.Is(err, services.ErrHostPending):
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "host_pending_verification",
			"details": "tenant_host exists but DNS verification has not completed",
		})
	default:
		// Service-level malformed-host errors arrive here.
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "discovery_failed",
		})
	}
}

// TenantSlugDiscoveryServiceIface is the contract for
// GET /internal/v1/tenant-discovery/by-slug. Narrow interface, mirroring
// HostDiscoveryServiceIface above, so TenantSlugDiscoveryHandler is
// mockable against a fast unit test double instead of a real DB.
type TenantSlugDiscoveryServiceIface interface {
	DiscoverBySlug(ctx context.Context, slug string) (*models.TenantSlugDiscoveryResponse, error)
}

// TenantSlugDiscoveryHandler serves the internal SLUG-based tenant
// discovery endpoint — the companion of HostDiscoveryHandler above.
//
// HostDiscoveryHandler answers "is this HOST an active tenant host"
// against iam_tenant_hosts, which in production holds essentially only
// custom/vanity domains (tenants that completed the onboarding "choose
// your subdomain" step). It does NOT hold an entry for every tenant's
// `<slug>.<baseDomain>` subdomain, so routing subdomain traffic through
// it would 404 real customers (e.g. `hexxlock.example.com`).
//
// This handler instead answers "is this SLUG a real tenant" against
// iam_tenants directly — the check the Next.js SDK middleware's
// subdomain branch needs to close its fail-open gap: today ANY
// shape-valid, non-reserved `<label>.example.com` renders the full app
// regardless of whether `label` is a real tenant slug.
//
// Mounted under the same /internal/v1/tenant-discovery group as
// Discover — ServiceAuth-gated, never exposed at the public edge.
type TenantSlugDiscoveryHandler struct {
	service TenantSlugDiscoveryServiceIface
}

// NewTenantSlugDiscoveryHandler constructs a handler wired to the given service.
func NewTenantSlugDiscoveryHandler(service TenantSlugDiscoveryServiceIface) *TenantSlugDiscoveryHandler {
	return &TenantSlugDiscoveryHandler{service: service}
}

// DiscoverBySlug handles GET /internal/v1/tenant-discovery/by-slug?slug=<slug>.
//
// Status code policy mirrors Discover (host-based) above as closely as
// the different underlying table allows:
//
//	200 OK                    — slug resolves to an active/trial tenant
//	400 Bad Request           — missing or empty slug param
//	404 Not Found             — no tenant with this slug (no silent fallback)
//	410 Gone                  — slug resolves to a suspended/cancelled tenant
//	500 Internal Server Error — unexpected service error, INCLUDING the
//	                            service being unconfigured (SetTenantRepository
//	                            never called at startup) — a wiring bug
//	                            must surface loudly, not silently 404
//	                            every subdomain platform-wide.
//
// Cache hints mirror Discover so the SDK can layer the same short-lived
// in-process cache policy on top:
//
//	200 → Cache-Control: public, max-age=300   (5 min positive)
//	404 → Cache-Control: public, max-age=30    (30 s negative)
//	410 → Cache-Control: public, max-age=30
func (h *TenantSlugDiscoveryHandler) DiscoverBySlug(c *gin.Context) {
	slug := c.Query("slug")
	if slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"details": "missing required query parameter `slug`",
		})
		return
	}

	resp, err := h.service.DiscoverBySlug(c.Request.Context(), slug)
	switch {
	case err == nil:
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, resp)
	case errors.Is(err, services.ErrTenantSlugNotFound):
		c.Header("Cache-Control", "public, max-age=30")
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "tenant_slug_not_found",
			"details": "no tenant registered for the supplied slug",
		})
	case errors.Is(err, services.ErrTenantSlugSuspended):
		c.Header("Cache-Control", "public, max-age=30")
		c.JSON(http.StatusGone, gin.H{
			"error":   "tenant_suspended",
			"details": "the tenant resolved from this slug is suspended",
		})
	default:
		// Covers services.ErrTenantSlugUnconfigured (startup wiring bug)
		// and genuine unexpected service/DB errors alike — both are
		// operational failures the caller (and its fail-open contract)
		// must treat identically to a network failure, never as a
		// definitive "not found".
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "discovery_failed",
		})
	}
}

// ─── Internal service-to-service host registration ──────────────────────────

// HostRegistrarIface is the narrow contract for the internal
// registration endpoint (separate from HostDiscoveryServiceIface so
// the read-only Discover handler stays mockable without write
// methods).
type HostRegistrarIface interface {
	RegisterVerifiedHost(ctx context.Context, req *services.RegisterVerifiedHostRequest) (*models.TenantHost, error)
	SuspendByHost(ctx context.Context, tenantID uuid.UUID, host string) error
}

// InternalTenantHostHandler serves POST /internal/v1/tenant-hosts —
// the bridge by which platform services (canonically domain-management,
// after ITS OWN domain-ownership verification + edge-TLS provisioning)
// promote a customer hostname into tenant-discovery. ServiceAuth-gated;
// never exposed at the edge.
type InternalTenantHostHandler struct {
	registrar HostRegistrarIface
}

// NewInternalTenantHostHandler constructs the handler.
func NewInternalTenantHostHandler(registrar HostRegistrarIface) *InternalTenantHostHandler {
	return &InternalTenantHostHandler{registrar: registrar}
}

// Register handles POST /internal/v1/tenant-hosts.
//
//	201 → host registered (or re-activated) and resolving in discovery
//	400 → malformed body / host
//	409 → host already claimed by a different tenant
func (h *InternalTenantHostHandler) Register(c *gin.Context) {
	var req services.RegisterVerifiedHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "details": err.Error()})
		return
	}
	host, err := h.registrar.RegisterVerifiedHost(c.Request.Context(), &req)
	switch {
	case err == nil:
		c.JSON(http.StatusCreated, host)
	case errors.Is(err, services.ErrHostClaimed):
		c.JSON(http.StatusConflict, gin.H{
			"error":   "host_claimed",
			"details": "host is already registered to a different tenant",
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "registration_failed", "details": err.Error()})
	}
}

// Unregister handles DELETE /internal/v1/tenant-hosts?host=<host>&tenant_id=<uuid>.
// Suspends the host so discovery returns 410 — called when the owning
// service removes the customer's custom domain.
//
//	204 → suspended
//	404 → no such host
//	409 → host belongs to a different tenant
func (h *InternalTenantHostHandler) Unregister(c *gin.Context) {
	host := c.Query("host")
	tenantIDStr := c.Query("tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if host == "" || err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "details": "host and tenant_id query parameters are required"})
		return
	}
	if sErr := h.registrar.SuspendByHost(c.Request.Context(), tenantID, host); sErr != nil {
		switch {
		case errors.Is(sErr, services.ErrHostNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "host_not_found"})
		case errors.Is(sErr, services.ErrHostClaimed):
			c.JSON(http.StatusConflict, gin.H{"error": "host_claimed", "details": "host is registered to a different tenant"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "unregister_failed", "details": sErr.Error()})
		}
		return
	}
	c.Status(http.StatusNoContent)
}
