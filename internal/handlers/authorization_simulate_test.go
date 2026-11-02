// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// newSimulateRouter mounts the real handlers behind the REAL
// RequireTenantAdmin middleware, exactly as cmd/routes.go does.
func newSimulateRouter(svc authorizationServiceAPI, users userLookupAPI, current *models.CurrentUser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := NewAuthorizationHandler(svc, users)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if current != nil {
			c.Set(middleware.CurrentUserKey, current)
		}
		c.Next()
	})
	am := &middleware.AuthMiddleware{}
	r.POST("/api/v1/authorize/simulate", am.RequireTenantAdmin(), h.Simulate)
	r.GET("/api/v1/authorize/effective-permissions", am.RequireTenantAdmin(), h.GetEffectivePermissionsByQuery)
	return r
}

func adminUser(tenantID uuid.UUID) *models.CurrentUser {
	u := buildCurrentUser(uuid.New(), tenantID)
	u.Roles = []string{"admin"}
	return u
}

func usersIn(tenantID uuid.UUID) *mockUserLookup {
	return &mockUserLookup{getByIDFn: func(_ context.Context, id uuid.UUID) (*models.UserResponse, error) {
		return &models.UserResponse{ID: id, TenantID: tenantID}, nil
	}}
}

func TestSimulate_NonAdminForbidden(t *testing.T) {
	tenant := uuid.New()
	called := false
	svc := &mockAuthzSvc{simulateFn: func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*models.SimulateResponse, error) {
		called = true
		return &models.SimulateResponse{}, nil
	}}
	member := buildCurrentUser(uuid.New(), tenant)
	member.Roles = []string{"marketing_manager"}
	r := newSimulateRouter(svc, usersIn(tenant), member)

	w := authzDoRequest(r, http.MethodPost, "/api/v1/authorize/simulate", authzJSONBody(t, models.SimulateRequest{UserID: uuid.New(), Permission: "marketing:leads:read"}))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, called, "service must not run for a non-admin")

	w = authzDoRequest(r, http.MethodGet, "/api/v1/authorize/effective-permissions?userId="+uuid.NewString(), nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSimulate_CrossTenantTargetIsNotFound(t *testing.T) {
	tenant, other := uuid.New(), uuid.New()
	called := false
	svc := &mockAuthzSvc{simulateFn: func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (*models.SimulateResponse, error) {
		called = true
		return &models.SimulateResponse{}, nil
	}}
	// target lives in ANOTHER tenant
	r := newSimulateRouter(svc, usersIn(other), adminUser(tenant))

	w := authzDoRequest(r, http.MethodPost, "/api/v1/authorize/simulate", authzJSONBody(t, models.SimulateRequest{UserID: uuid.New(), Permission: "marketing:leads:read"}))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.False(t, called)

	w = authzDoRequest(r, http.MethodGet, "/api/v1/authorize/effective-permissions?userId="+uuid.NewString(), nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSimulate_FailsClosedWithoutUserLookup(t *testing.T) {
	tenant := uuid.New()
	r := newSimulateRouter(&mockAuthzSvc{}, nil, adminUser(tenant))
	w := authzDoRequest(r, http.MethodPost, "/api/v1/authorize/simulate", authzJSONBody(t, models.SimulateRequest{UserID: uuid.New(), Permission: "marketing:leads:read"}))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSimulate_AdminSameTenantUsesSessionTenant(t *testing.T) {
	tenant := uuid.New()
	admin := adminUser(tenant)
	target := uuid.New()
	var gotActor, gotUser, gotTenant uuid.UUID
	svc := &mockAuthzSvc{simulateFn: func(_ context.Context, actor, user, ten uuid.UUID, perm string) (*models.SimulateResponse, error) {
		gotActor, gotUser, gotTenant = actor, user, ten
		return &models.SimulateResponse{UserID: user, Permission: perm, Decision: models.PermissionDecision{Reason: models.DecisionReasonCaveatFailed, Caveat: "approval_limit"}}, nil
	}}
	r := newSimulateRouter(svc, usersIn(tenant), admin)

	w := authzDoRequest(r, http.MethodPost, "/api/v1/authorize/simulate", authzJSONBody(t, models.SimulateRequest{UserID: target, Permission: "preaccounting:invoice:approve"}))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, admin.ID, gotActor)
	assert.Equal(t, target, gotUser)
	assert.Equal(t, tenant, gotTenant, "tenant comes from the session, never the body")
	assert.Contains(t, w.Body.String(), `"caveat":"approval_limit"`)
}

func TestEffectivePermissionsByQuery_BadUserID(t *testing.T) {
	r := newSimulateRouter(&mockAuthzSvc{}, usersIn(uuid.New()), adminUser(uuid.New()))
	w := authzDoRequest(r, http.MethodGet, "/api/v1/authorize/effective-permissions?userId=nope", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
