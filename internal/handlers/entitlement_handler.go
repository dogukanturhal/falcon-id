// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// EntitlementHandler serves GET /api/v1/tenant/entitlements (public,
// JWT/session-derived tenant) and the internal S2S
// GET/PUT /internal/v1/tenants/{id}/module-entitlements endpoints
// (the product roadmap §4.1).
type EntitlementHandler struct {
	svc    *services.TenantEntitlementService
	logger *zap.Logger
}

// NewEntitlementHandler creates a new handler.
func NewEntitlementHandler(svc *services.TenantEntitlementService, logger *zap.Logger) *EntitlementHandler {
	return &EntitlementHandler{svc: svc, logger: logger}
}

// GetTenantEntitlements handles GET /api/v1/tenant/entitlements.
//
// Tenant is derived EXCLUSIVELY from the validated session/JWT via
// middleware.GetCurrentUser (never from a header) — this endpoint sits
// behind authMiddleware.RequireAuth() in cmd/routes.go's tenant group,
// following the same pattern as GetCurrentTenant in tenant_handler.go.
//
// @Summary Get tenant module entitlements
// @Tags Tenant
// @Produce json
// @Success 200 {object} services.EntitlementEnvelope
// @Failure 401 {object} map[string]string
// @Router /api/v1/tenant/entitlements [get]
func (h *EntitlementHandler) GetTenantEntitlements(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	envelope, err := h.svc.GetEntitlements(c.Request.Context(), user.TenantID)
	if err != nil {
		// GetEntitlements' own fail-closed contract means this branch
		// should be unreachable in practice (it always returns
		// emptyEnvelope(), nil on any downstream failure) — but if it
		// ever DOES return an error, the safe response is still a
		// fail-closed empty envelope, never a 5xx that a caller might
		// mishandle as "assume allowed" upstream (e.g. in a CDN/proxy
		// that treats 5xx as pass-through).
		h.logger.Error("entitlements: unexpected error from GetEntitlements, failing closed",
			zap.String("tenant_id", user.TenantID.String()), zap.Error(err))
		c.JSON(http.StatusOK, services.EntitlementEnvelope{
			Stale:            true,
			Modules:          []services.EntitlementModule{},
			Flags:            map[string]bool{},
			Limits:           map[string]int64{},
			TrialEligibility: map[string]bool{},
		})
		return
	}

	c.JSON(http.StatusOK, envelope)
}

// moduleEntitlementPutRequest is the PUT
// /internal/v1/tenants/{id}/module-entitlements request body: a full
// per-tenant snapshot, mirroring the example.tenant.modules.sync wire
// shape so ops tooling can replay a snapshot byte-for-byte through either
// path (see internal/entitlementsync's identical payload shape).
type moduleEntitlementPutRequest struct {
	EventVersion int64                        `json:"event_version" binding:"required"`
	Modules      []moduleEntitlementPutModule `json:"modules"`
	Flags        map[string]bool              `json:"flags,omitempty"`
	// Limits: integer plan limits (migration 0020), -1 = unlimited.
	Limits map[string]int64 `json:"limits,omitempty"`
}

type moduleEntitlementPutModule struct {
	ModuleCode     string  `json:"module_code" binding:"required"`
	Status         string  `json:"status" binding:"required"`
	Seats          *int    `json:"seats,omitempty"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
	EverTrialed    bool    `json:"ever_trialed"`
	EverSubscribed bool    `json:"ever_subscribed"`
	Source         *string `json:"source,omitempty"`
	TierCode       *string `json:"tier_code,omitempty"`
	ReadOnly       bool    `json:"read_only"`
}

// PutModuleEntitlements handles PUT
// /internal/v1/tenants/{id}/module-entitlements. ServiceAuth +
// RequireScope("iam:entitlements:write") are enforced by middleware
// registered on this route in cmd/routes_admin.go, ahead of this handler.
//
// @Summary Replace a tenant's module entitlement snapshot (S2S, ops/backfill)
// @Tags Internal
// @Router /internal/v1/tenants/{id}/module-entitlements [put]
func (h *EntitlementHandler) PutModuleEntitlements(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}

	var req moduleEntitlementPutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if err := models.ValidateEntitlementLimits(req.Limits); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limits: " + err.Error()})
		return
	}

	ctx := c.Request.Context()
	for _, m := range req.Modules {
		status := models.ModuleEntitlementStatus(m.Status)
		if !status.IsValid() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status for module " + m.ModuleCode + ": " + m.Status})
			return
		}
		if m.ReadOnly && status != models.ModuleEntitlementStatusGrace {
			c.JSON(http.StatusBadRequest, gin.H{"error": "read_only is only allowed with status grace for module " + m.ModuleCode})
			return
		}

		entitlement := &models.ModuleEntitlement{
			TenantID:       tenantID,
			ModuleCode:     m.ModuleCode,
			Status:         status,
			Seats:          m.Seats,
			EverTrialed:    m.EverTrialed,
			EverSubscribed: m.EverSubscribed,
			Source:         m.Source,
			TierCode:       m.TierCode,
			ReadOnly:       m.ReadOnly,
			EventVersion:   req.EventVersion,
		}
		if m.ExpiresAt != nil {
			t, parseErr := time.Parse(time.RFC3339, *m.ExpiresAt)
			if parseErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid expires_at for module " + m.ModuleCode})
				return
			}
			entitlement.ExpiresAt = &t
		}
		entitlement.SourceUpdatedAt = time.Now().UTC()

		if err := h.svc.PutSnapshot(ctx, entitlement); err != nil {
			h.logger.Error("PutModuleEntitlements: PutSnapshot failed",
				zap.String("tenant_id", tenantID.String()), zap.String("module_code", m.ModuleCode), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply entitlement"})
			return
		}
	}

	if req.Flags != nil || req.Limits != nil {
		flags := &models.TenantEntitlementFlags{
			TenantID:        tenantID,
			Flags:           req.Flags,
			Limits:          req.Limits,
			EventVersion:    req.EventVersion,
			SourceUpdatedAt: time.Now().UTC(),
		}
		if err := h.svc.PutFlagsSnapshot(ctx, flags); err != nil {
			h.logger.Error("PutModuleEntitlements: PutFlagsSnapshot failed",
				zap.String("tenant_id", tenantID.String()), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply flags"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "applied"})
}

// GetModuleEntitlements handles GET
// /internal/v1/tenants/{id}/module-entitlements (S2S, read scope).
//
// @Summary Read a tenant's module entitlement snapshot (S2S)
// @Tags Internal
// @Router /internal/v1/tenants/{id}/module-entitlements [get]
func (h *EntitlementHandler) GetModuleEntitlements(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}

	// This ops/support endpoint calls the same GetEntitlements chain as the
	// public route (fresh cache -> Postgres -> LKG -> fail-closed empty).
	// GetEntitlements' own contract means it should never actually return
	// a non-nil error (see its doc comment); this branch exists only as a
	// defensive backstop in case that contract is ever violated, and on an
	// internal/ops route we intentionally let that surface as a real 5xx
	// rather than silently masking it as an empty envelope, since an
	// operator debugging via this endpoint needs to know source-of-truth
	// reads are failing, not see a deceptively "empty but healthy" 200.
	envelope, err := h.svc.GetEntitlements(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("GetModuleEntitlements failed", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read entitlements"})
		return
	}

	c.JSON(http.StatusOK, envelope)
}
