// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

type teamScopeFake struct {
	res *models.TeamScope
	err error
}

func (f *teamScopeFake) GetTeamScope(context.Context, uuid.UUID, uuid.UUID) (*models.TeamScope, error) {
	return f.res, f.err
}

func teamScopeRequest(h *TeamScopeHandler, tenantPath, tenantJWT, scopes, auth string) *httptest.ResponseRecorder {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CtxKeyAuthMethod, auth)
		c.Set(middleware.CtxKeyServiceTenantID, tenantJWT)
		c.Set(middleware.CtxKeyServiceScopes, scopes)
	})
	r.GET("/tenants/:id/users/:user_id/team-scope", middleware.RequireScope(ScopeTeamsRead), h.GetTeamScope)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/tenants/"+tenantPath+"/users/"+approvalUser.String()+"/team-scope", nil))
	return rec
}

func TestTeamScopeHandler(t *testing.T) {
	res := &models.TeamScope{TenantID: approvalTenant, UserID: approvalUser, HasTeam: true, MemberUserIDs: []uuid.UUID{approvalUser}, Teams: []models.TeamScopeTeam{}}
	h := NewTeamScopeHandler(&teamScopeFake{res: res})
	tid := approvalTenant.String()

	rec := teamScopeRequest(h, tid, tid, ScopeTeamsRead, "service_jwt")
	require.Equal(t, 200, rec.Code)
	require.Contains(t, rec.Body.String(), `"has_team":true`)

	require.Equal(t, 403, teamScopeRequest(h, tid, tid, "iam:members:read", "service_jwt").Code, "wrong scope")
	require.Equal(t, 401, teamScopeRequest(h, tid, tid, ScopeTeamsRead, "user").Code, "not a service jwt")
	require.Equal(t, 403, teamScopeRequest(h, tid, uuid.NewString(), ScopeTeamsRead, "service_jwt").Code, "cross tenant without act-as")
	require.Equal(t, 200, teamScopeRequest(h, tid, uuid.NewString(), ScopeTeamsRead+" tenant:act-as", "service_jwt").Code)

	bad := NewTeamScopeHandler(&teamScopeFake{err: errors.New("db")})
	require.Equal(t, 503, teamScopeRequest(bad, tid, tid, ScopeTeamsRead, "service_jwt").Code)
}
