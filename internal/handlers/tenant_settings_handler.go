// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// TenantSettingsHandler exposes GET/PATCH /api/v1/tenants/me/settings
// for the Phase 2 AcmeWeb General settings page.
type TenantSettingsHandler struct {
	tenantRepo *repositories.TenantRepository
	logger     *zap.Logger
	namePusher WorkspaceNamePusher
}

// WorkspaceNamePusher mirrors a saved workspace name into tenant-management
// (best effort). Satisfied by *services.TenantWorkspaceNameService.
type WorkspaceNamePusher interface {
	PushName(ctx context.Context, tenantID uuid.UUID, name string)
}

// SetWorkspaceNamePusher wires the tenant-management mirror; nil disables it.
func (h *TenantSettingsHandler) SetWorkspaceNamePusher(p WorkspaceNamePusher) {
	h.namePusher = p
}

// NewTenantSettingsHandler creates a new TenantSettingsHandler.
func NewTenantSettingsHandler(tenantRepo *repositories.TenantRepository, logger *zap.Logger) *TenantSettingsHandler {
	return &TenantSettingsHandler{
		tenantRepo: tenantRepo,
		logger:     logger,
	}
}

// TenantSettingsResponse is the wire shape returned by GET and PATCH.
//
// Name is the tenant's internal/immutable identifier (iam_tenants.name,
// e.g. "hexxlock") and stays read-only here — it is never accepted by
// PatchTenantSettingsRequest. DisplayName (iam_tenants.display_name) is the
// editable "Workspace name" shown and changed on the Settings > General page.
type TenantSettingsResponse struct {
	Name                  string     `json:"name"`
	DisplayName           string     `json:"displayName"`
	Slug                  string     `json:"slug"`
	Timezone              string     `json:"timezone"`
	DefaultSenderDomainID *uuid.UUID `json:"defaultSenderDomainId"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

// PatchTenantSettingsRequest is the body accepted by PATCH.
// All fields are optional; only non-nil fields are applied.
type PatchTenantSettingsRequest struct {
	// DisplayName is the editable workspace name shown in the UI. Trimmed;
	// must be non-empty and at most 200 characters after trimming.
	DisplayName *string `json:"displayName"`
	// Timezone must be a valid IANA TZ identifier, e.g. "Europe/Istanbul".
	Timezone *string `json:"timezone"`
	// DefaultSenderDomainId may be set to null to clear the current value.
	DefaultSenderDomainID *uuid.UUID `json:"defaultSenderDomainId"`
	// ClearDefaultSenderDomain, when true, sets the column to NULL even if
	// defaultSenderDomainId is absent from the body. This avoids the
	// JSON-null vs field-absent ambiguity with *uuid.UUID.
	ClearDefaultSenderDomain bool `json:"clearDefaultSenderDomain"`
}

// GetSettings handles GET /api/v1/tenants/me/settings.
//
// @Summary Get tenant settings
// @Description Returns the current tenant's name, slug, timezone, and default sender domain.
// @Tags Tenant
// @Security BearerAuth
// @Produce json
// @Success 200 {object} TenantSettingsResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/tenants/me/settings [get]
func (h *TenantSettingsHandler) GetSettings(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	tenant, err := h.tenantRepo.GetByID(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error("GetSettings: failed to load tenant", zap.Error(err), zap.String("tenant_id", user.TenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant"})
		return
	}
	if tenant == nil {
		h.logger.Error("GetSettings: tenant row missing", zap.String("tenant_id", user.TenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant integrity error"})
		return
	}

	c.JSON(http.StatusOK, TenantSettingsResponse{
		Name:                  tenant.Name,
		DisplayName:           tenant.DisplayName,
		Slug:                  tenant.Slug,
		Timezone:              tenant.Timezone,
		DefaultSenderDomainID: tenant.DefaultSenderDomainID,
		UpdatedAt:             tenant.UpdatedAt,
	})
}

// PatchSettings handles PATCH /api/v1/tenants/me/settings.
//
// @Summary Update tenant settings
// @Description Updates the workspace display name, timezone and/or default sender domain for the current tenant.
// @Tags Tenant
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body PatchTenantSettingsRequest true "Fields to update (all optional)"
// @Success 200 {object} TenantSettingsResponse
// @Failure 400 {object} map[string]string "Invalid request or invalid IANA timezone"
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/tenants/me/settings [patch]
func (h *TenantSettingsHandler) PatchSettings(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req PatchTenantSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate timezone if provided.
	if req.Timezone != nil {
		if err := validateIANATimezone(*req.Timezone); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// Validate display name if provided. It is trimmed before both the
	// length check and persistence so whitespace-only input is rejected
	// rather than silently accepted.
	var trimmedDisplayName string
	if req.DisplayName != nil {
		trimmedDisplayName = strings.TrimSpace(*req.DisplayName)
		if trimmedDisplayName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "displayName must not be empty"})
			return
		}
		if len(trimmedDisplayName) > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "displayName must be at most 200 characters"})
			return
		}
	}

	tenant, err := h.tenantRepo.GetByID(c.Request.Context(), user.TenantID)
	if err != nil {
		h.logger.Error("PatchSettings: failed to load tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant"})
		return
	}
	if tenant == nil {
		h.logger.Error("PatchSettings: tenant row missing", zap.String("tenant_id", user.TenantID.String()))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant integrity error"})
		return
	}

	// Apply only supplied fields.
	if req.DisplayName != nil {
		tenant.DisplayName = trimmedDisplayName
	}
	if req.Timezone != nil {
		tenant.Timezone = *req.Timezone
	}
	if req.ClearDefaultSenderDomain {
		tenant.DefaultSenderDomainID = nil
	} else if req.DefaultSenderDomainID != nil {
		tenant.DefaultSenderDomainID = req.DefaultSenderDomainID
	}

	if err := h.tenantRepo.UpdateSettings(c.Request.Context(), tenant); err != nil {
		h.logger.Error("PatchSettings: failed to persist settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update settings"})
		return
	}
	if req.DisplayName != nil && h.namePusher != nil {
		h.namePusher.PushName(c.Request.Context(), tenant.ID, tenant.DisplayName)
	}

	c.JSON(http.StatusOK, TenantSettingsResponse{
		Name:                  tenant.Name,
		DisplayName:           tenant.DisplayName,
		Slug:                  tenant.Slug,
		Timezone:              tenant.Timezone,
		DefaultSenderDomainID: tenant.DefaultSenderDomainID,
		UpdatedAt:             tenant.UpdatedAt,
	})
}
