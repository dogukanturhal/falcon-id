// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// warmPoolStatusProvider is the narrow interface the handler needs from
// WarmPoolManager. Using an interface keeps the handler decoupled and testable.
type warmPoolStatusProvider interface {
	GetStatus(ctx context.Context) (map[string][]services.WarmHost, error)
}

// WarmPoolHandler exposes warm pool status to the platform admin UI and
// monitoring systems.
type WarmPoolHandler struct {
	manager warmPoolStatusProvider
}

// NewWarmPoolHandler creates the handler. manager may be nil; the handler
// returns a graceful "not configured" response in that case.
func NewWarmPoolHandler(manager warmPoolStatusProvider) *WarmPoolHandler {
	return &WarmPoolHandler{manager: manager}
}

// GetStatus handles GET /api/v1/platform/warmpool.
//
// Returns the current warm pool state per region, including counts of hosts
// in each status (provisioning, warm, assigned). Used by the platform admin
// dashboard and Prometheus alerting (via JSON scraping).
//
// Response shape:
//
//	{
//	  "istanbul": [
//	    {"id": "...", "region": "istanbul", "status": "warm", "database_name": "...", "created_at": "..."},
//	    ...
//	  ],
//	  "ankara": [...]
//	}
func (h *WarmPoolHandler) GetStatus(c *gin.Context) {
	if h.manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "warm pool manager not configured — ensure WarmPoolRepository is initialised",
		})
		return
	}

	status, err := h.manager.GetStatus(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Augment with summary counts per region for dashboard convenience.
	type regionSummary struct {
		Hosts        []services.WarmHost `json:"hosts"`
		WarmCount    int                 `json:"warm_count"`
		Provisioning int                 `json:"provisioning_count"`
		Assigned     int                 `json:"assigned_count"`
		Total        int                 `json:"total_count"`
	}

	summary := make(map[string]regionSummary, len(status))
	for region, hosts := range status {
		var warm, provisioning, assigned int
		for _, h := range hosts {
			switch h.Status {
			case "warm":
				warm++
			case "provisioning":
				provisioning++
			case "assigned":
				assigned++
			}
		}
		summary[region] = regionSummary{
			Hosts:        hosts,
			WarmCount:    warm,
			Provisioning: provisioning,
			Assigned:     assigned,
			Total:        len(hosts),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"warm_pool": summary,
	})
}
