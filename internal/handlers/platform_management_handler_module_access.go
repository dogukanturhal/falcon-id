// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// moduleAccessReconciler is the subset of services.ModuleAccessProvisioner
// the reconcile endpoints need.
type moduleAccessReconciler interface {
	ReconcileTenant(ctx context.Context, tenantID uuid.UUID) (*services.ModuleAccessReconcileSummary, error)
	ReconcileAll(ctx context.Context) (*services.ModuleAccessReconcileSummary, error)
}

// ReconcileModuleAccess is the operator-triggered form of the module-access
// reconcile that also runs at startup: for every granting module entitlement
// it materializes the module's role templates and grants the module's
// owner-admin roles to the tenant's owners (see
// services.ModuleAccessProvisioner). Idempotent.
//
// POST /api/platform/management/tenants/:tenant_id/module-access/reconcile
// POST /api/platform/management/module-access/reconcile (all tenants)
func (h *PlatformManagementHandler) ReconcileModuleAccess(c *gin.Context) {
	currentUser := middleware.GetCurrentUser(c)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": msgPlatMgmtNotAuthenticated})
		return
	}

	if h.moduleAccess == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "module access provisioner not configured"})
		return
	}

	// A full reconcile can outlive the HTTP request (client or proxy
	// timeout); it is idempotent, so let it finish on its own deadline.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Minute)
	defer cancel()

	var (
		summary *services.ModuleAccessReconcileSummary
		err     error
	)
	if raw := c.Param("tenant_id"); raw != "" {
		tenantID, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": msgPlatMgmtInvalidTenantID})
			return
		}
		summary, err = h.moduleAccess.ReconcileTenant(ctx, tenantID)
	} else {
		summary, err = h.moduleAccess.ReconcileAll(ctx)
	}
	if err != nil {
		h.logger.Error("Failed to reconcile module access", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgPlatMgmtInternalError, "summary": summary})
		return
	}

	c.JSON(http.StatusOK, summary)
}
