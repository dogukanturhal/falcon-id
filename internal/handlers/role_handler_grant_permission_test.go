// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// setupInternalRoleRouter mounts only the internal
// POST /internal/v1/roles/:id/actions/grant-permission action, matching
// how cmd/routes_admin.go wires it (ServiceAuth-gated; no per-request
// tenant is injected into context — the handler/service resolves the
// tenant from the target role itself, looked up server-side by :id).
func setupInternalRoleRouter(h *RoleHandler) *gin.Engine {
	// Boundary tests: a cross-tenant-capable service token.
	return setupInternalRoleRouterAs(h, "service_jwt", uuid.New(), "tenant:act-as")
}

// setupInternalRoleRouterAs stands in for ServiceAuth by stamping the context
// values it would set.
func setupInternalRoleRouterAs(h *RoleHandler, authMethod string, svcTenant uuid.UUID, scopes string) *gin.Engine {
	router := gin.New()
	g := router.Group("/internal/v1/roles")
	g.Use(func(c *gin.Context) {
		c.Set(middleware.CtxKeyAuthMethod, authMethod)
		c.Set(middleware.CtxKeyServiceTenantID, svcTenant.String())
		c.Set(middleware.CtxKeyServiceScopes, scopes)
		c.Next()
	})
	g.POST("/:id/actions/grant-permission", h.GrantPermission)
	return router
}

// ---------------------------------------------------------------------------
// ADR-A10 acceptance test: a tenant admin cannot escalate beyond their own
// boundary/entitlements via
// POST /internal/v1/roles/{id}/actions/grant-permission.
// ---------------------------------------------------------------------------

func TestRoleHandler_GrantPermission_EntitlementMissing_Returns403WithCode(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)
	permID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	permRepo.On("GetByID", mock.Anything, permID).
		Return(&models.Permission{ID: permID, Name: "accounting:journal_entries:approve", Module: "accounting"}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	// No entitlement checker wired: EntitledModules fails closed to
	// UniversalModules (core, iam) — "accounting" is not among them, so
	// the grant must be refused regardless of caller identity.
	h := NewRoleHandler(svc)
	router := setupInternalRoleRouter(h)

	body := fmt.Sprintf(`{"permission_id":%q}`, permID.String())
	w := doRequest(router, http.MethodPost, "/internal/v1/roles/"+r.ID.String()+"/actions/grant-permission", body)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "entitlement_missing_for_module")
}

func TestRoleHandler_GrantPermission_PlatformRoleOutsideInternalTenant_Returns403WithCode(t *testing.T) {
	tenantID := uuid.New() // any tenant other than 00000000-0000-0000-0000-000000000002
	r := makeTestRole(tenantID, false)
	permID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	permRepo.On("GetByID", mock.Anything, permID).
		Return(&models.Permission{ID: permID, Name: "platform:tenants:suspend", Module: "platform"}, nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupInternalRoleRouter(h)

	body := fmt.Sprintf(`{"permission_id":%q}`, permID.String())
	w := doRequest(router, http.MethodPost, "/internal/v1/roles/"+r.ID.String()+"/actions/grant-permission", body)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "platform_role_requires_internal_tenant")
}

func TestRoleHandler_GrantPermission_EntitledCoreModule_Returns200(t *testing.T) {
	tenantID := uuid.New()
	r := makeTestRole(tenantID, false)
	permID := uuid.New()

	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	permRepo.On("GetByID", mock.Anything, permID).
		Return(&models.Permission{ID: permID, Name: "core:users:read", Module: "core"}, nil)
	roleRepo.On("GrantPermissionsByName", mock.Anything, r.ID, []string{"core:users:read"}).Return(nil)

	svc := newTestRoleSvc(t, roleRepo, permRepo)
	h := NewRoleHandler(svc)
	router := setupInternalRoleRouter(h)

	body := fmt.Sprintf(`{"permission_id":%q}`, permID.String())
	w := doRequest(router, http.MethodPost, "/internal/v1/roles/"+r.ID.String()+"/actions/grant-permission", body)

	assert.Equal(t, http.StatusOK, w.Code)
}

func grantTenantFixture(t *testing.T, roleTenant uuid.UUID) (*RoleHandler, *models.Role, string) {
	t.Helper()
	r := makeTestRole(roleTenant, false)
	permID := uuid.New()
	roleRepo := new(mockRoleHandlerRoleRepo)
	permRepo := new(mockRoleHandlerPermRepo)
	roleRepo.On("GetByID", mock.Anything, r.ID).Return(r, nil)
	permRepo.On("GetByID", mock.Anything, permID).
		Return(&models.Permission{ID: permID, Name: "core:users:read", Module: "core"}, nil)
	roleRepo.On("GrantPermissionsByName", mock.Anything, r.ID, []string{"core:users:read"}).Return(nil)
	h := NewRoleHandler(newTestRoleSvc(t, roleRepo, permRepo))
	return h, r, fmt.Sprintf(`{"permission_id":%q}`, permID.String())
}

func TestRoleHandler_GrantPermission_TenantScoping(t *testing.T) {
	own := uuid.New()
	cases := []struct {
		name       string
		authMethod string
		svcTenant  uuid.UUID
		scopes     string
		want       int
	}{
		{"same tenant", "service_jwt", own, "", http.StatusOK},
		{"other tenant without act-as", "service_jwt", uuid.New(), "", http.StatusForbidden},
		{"other tenant with act-as", "service_jwt", uuid.New(), "tenant:act-as", http.StatusOK},
		{"legacy internal key", "internal_key", uuid.Nil, "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, r, body := grantTenantFixture(t, own)
			router := setupInternalRoleRouterAs(h, tc.authMethod, tc.svcTenant, tc.scopes)
			w := doRequest(router, http.MethodPost, "/internal/v1/roles/"+r.ID.String()+"/actions/grant-permission", body)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}
