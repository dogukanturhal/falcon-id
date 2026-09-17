// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// RealmDiscoveryServiceInterface is the service contract consumed by RealmDiscoveryHandler.
// Declaring the interface at the handler level keeps the handler decoupled from
// the concrete service and trivially mockable in tests.
type RealmDiscoveryServiceInterface interface {
	Discover(ctx context.Context, req *models.RealmDiscoveryRequest) (*models.RealmDiscoveryResponse, error)
}

// RealmDiscoveryHandler serves the identifier-first realm discovery endpoint.
//
// POST /api/v1/auth/realm-discovery
//
// This endpoint is PUBLIC — no authentication required. The user has not yet
// logged in; we are merely identifying which tenant and auth flow they belong to.
type RealmDiscoveryHandler struct {
	service RealmDiscoveryServiceInterface
}

// NewRealmDiscoveryHandler constructs a RealmDiscoveryHandler wired to the given service.
func NewRealmDiscoveryHandler(service RealmDiscoveryServiceInterface) *RealmDiscoveryHandler {
	return &RealmDiscoveryHandler{service: service}
}

// Discover handles POST /api/v1/auth/realm-discovery.
//
// Request body:
//
//	{ "login_hint": "user@example.com" }
//
// Response:
//
//	200 OK with RealmDiscoveryResponse on success.
//	400 Bad Request when the body is missing or the login_hint is not a valid email.
//	500 Internal Server Error when discovery fails unexpectedly.
func (h *RealmDiscoveryHandler) Discover(c *gin.Context) {
	var req models.RealmDiscoveryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"details": err.Error(),
		})
		return
	}

	resp, err := h.service.Discover(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "realm_discovery_failed",
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}
