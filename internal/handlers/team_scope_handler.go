// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ScopeTeamsRead is the service-token scope required by the team-scope route.
const ScopeTeamsRead = "iam:teams:read"

// TeamScopeReader resolves the teams (and member user IDs) a user can see.
type TeamScopeReader interface {
	GetTeamScope(ctx context.Context, tenantID, userID uuid.UUID) (*models.TeamScope, error)
}

// TeamScopeHandler serves GET /internal/v1/tenants/:id/users/:user_id/team-scope.
type TeamScopeHandler struct {
	scope TeamScopeReader
}

func NewTeamScopeHandler(scope TeamScopeReader) *TeamScopeHandler {
	return &TeamScopeHandler{scope: scope}
}

func (h *TeamScopeHandler) GetTeamScope(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_tenant"})
		return
	}
	userID, err := uuid.Parse(c.Param("user_id"))
	if err != nil || userID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_user"})
		return
	}
	if !authorizeDirectoryTenant(c, tenantID) {
		return
	}
	if h.scope == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "team_scope_unavailable"})
		return
	}
	res, err := h.scope.GetTeamScope(c.Request.Context(), tenantID, userID)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"code": "team_scope_unavailable"})
		return
	}
	c.JSON(http.StatusOK, res)
}
