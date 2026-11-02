// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// A tenant admin must not reach the OPA test/reload endpoints or the policy
// mutation routes (custom Rego CRUD), and the tenant ABAC toggle is gone.
func TestRegisterPolicyRoutes_PlatformAdminOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func(user *models.CurrentUser) *gin.Engine {
		r := gin.New()
		admin := r.Group("/admin")
		admin.Use(func(c *gin.Context) {
			c.Set(middleware.CurrentUserKey, user)
			c.Next()
		})
		h := &Handlers{Policy: handlers.NewPolicyHandler(nil, nil)}
		registerPolicyRoutes(admin, h, middleware.NewAuthMiddleware(nil, nil))
		return r
	}

	tenantAdmin := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Roles: []string{"admin"}}

	guarded := []struct{ method, path string }{
		{http.MethodPost, "/admin/policies/test"},
		{http.MethodPost, "/admin/policies/reload"},
		{http.MethodPost, "/admin/policies"},
		{http.MethodPut, "/admin/policies/" + uuid.NewString()},
		{http.MethodDelete, "/admin/policies/" + uuid.NewString()},
	}
	for _, tc := range guarded {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(`{}`))
		newRouter(tenantAdmin).ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code, "%s %s", tc.method, tc.path)
	}

	// The tenant toggle endpoint no longer exists.
	w := httptest.NewRecorder()
	newRouter(tenantAdmin).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/abac/toggle", bytes.NewBufferString(`{"enabled":true}`)))
	assert.Equal(t, http.StatusNotFound, w.Code)

	// A platform admin passes the guard (reload then 503: no OPA service wired).
	platform := &models.CurrentUser{
		ID: uuid.New(), TenantID: uuid.MustParse(models.HexxlockInternalTenantID),
		Roles: []string{"platform_admin"}, IsPlatformAdmin: true,
	}
	w = httptest.NewRecorder()
	newRouter(platform).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/policies/reload", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
