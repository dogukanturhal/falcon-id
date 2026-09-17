// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// TenantMeteringHandler exposes HTTP endpoints for per-tenant cost attribution
// metering and noisy-neighbor resource snapshots.
type TenantMeteringHandler struct {
	pool    *pgxpool.Pool
	monitor *services.TenantResourceMonitor // may be nil
}

// NewTenantMeteringHandler creates a TenantMeteringHandler.
// monitor may be nil; in that case the resource snapshot endpoint returns an
// empty list rather than failing.
func NewTenantMeteringHandler(pool *pgxpool.Pool, monitor *services.TenantResourceMonitor) *TenantMeteringHandler {
	return &TenantMeteringHandler{
		pool:    pool,
		monitor: monitor,
	}
}

// GetTenantResources returns the latest per-tenant database resource snapshots
// collected by the TenantResourceMonitor.
//
// @Summary List tenant resource snapshots
// @Description Returns the most recent pg_stat_activity-based resource snapshot for every active tenant.
// @Tags Platform Metering
// @Produce json
// @Success 200 {object} map[string]interface{} "List of tenant resource snapshots"
// @Router /api/v1/platform/tenant-resources [get]
func (h *TenantMeteringHandler) GetTenantResources(c *gin.Context) {
	if h.monitor == nil {
		c.JSON(http.StatusOK, gin.H{"snapshots": []struct{}{}})
		return
	}

	ctx := c.Request.Context()
	snapshots, err := h.monitor.GetSnapshots(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "resource_monitor_unavailable",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"snapshots": snapshots,
		"count":     len(snapshots),
	})
}

// GetTenantMetering returns hourly usage records for a specific tenant.
// Query params: from (RFC3339), to (RFC3339).  Defaults to the last 24 hours.
//
// @Summary Get tenant metering records
// @Description Returns hourly API consumption records for a tenant within the requested time window.
// @Tags Platform Metering
// @Produce json
// @Param tenant_id path string true "Tenant UUID"
// @Param from query string false "Start time (RFC3339)"
// @Param to query string false "End time (RFC3339)"
// @Success 200 {object} map[string]interface{} "Tenant metering records"
// @Failure 400 {object} map[string]string "Bad request"
// @Router /api/v1/platform/metering/tenant/{tenant_id} [get]
func (h *TenantMeteringHandler) GetTenantMetering(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required"})
		return
	}

	from, to, ok := parseMeteringTimeRange(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	records, err := services.GetTenantUsage(ctx, h.pool, tenantID, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "metering_query_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id": tenantID,
		"from":      from.UTC().Format(time.RFC3339),
		"to":        to.UTC().Format(time.RFC3339),
		"records":   records,
		"count":     len(records),
	})
}

// GetMeteringSummary returns aggregated usage records across all tenants for
// the current period.
// Query params: from (RFC3339), to (RFC3339).  Defaults to the current hour.
//
// @Summary Get metering summary across all tenants
// @Description Returns API consumption records for all tenants within the requested time window, ordered by highest consumers first.
// @Tags Platform Metering
// @Produce json
// @Param from query string false "Start time (RFC3339)"
// @Param to query string false "End time (RFC3339)"
// @Success 200 {object} map[string]interface{} "Metering summary"
// @Failure 400 {object} map[string]string "Bad request"
// @Router /api/v1/platform/metering/summary [get]
func (h *TenantMeteringHandler) GetMeteringSummary(c *gin.Context) {
	from, to, ok := parseMeteringTimeRange(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	records, err := services.GetMeteringSummary(ctx, h.pool, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "metering_summary_failed",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"from":    from.UTC().Format(time.RFC3339),
		"to":      to.UTC().Format(time.RFC3339),
		"records": records,
		"count":   len(records),
	})
}

// parseMeteringTimeRange extracts and validates from/to query parameters.
// Returns the parsed times and true on success; on failure it writes a 400
// response and returns false.  When parameters are absent, defaults to the
// last 24 hours.
func parseMeteringTimeRange(c *gin.Context) (from, to time.Time, ok bool) {
	now := time.Now().UTC()
	from = now.Add(-24 * time.Hour)
	to = now

	if raw := c.Query("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_from",
				"message": "from must be a valid RFC3339 timestamp",
			})
			return time.Time{}, time.Time{}, false
		}
		from = t
	}

	if raw := c.Query("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_to",
				"message": "to must be a valid RFC3339 timestamp",
			})
			return time.Time{}, time.Time{}, false
		}
		to = t
	}

	if to.Before(from) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_range",
			"message": "to must be after from",
		})
		return time.Time{}, time.Time{}, false
	}

	return from, to, true
}
