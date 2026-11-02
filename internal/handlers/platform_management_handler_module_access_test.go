// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type fakeModuleAccessReconciler struct {
	tenantCalls []uuid.UUID
	allCalls    int
	err         error
}

func (f *fakeModuleAccessReconciler) ReconcileTenant(_ context.Context, id uuid.UUID) (*services.ModuleAccessReconcileSummary, error) {
	f.tenantCalls = append(f.tenantCalls, id)
	return &services.ModuleAccessReconcileSummary{Tenants: 1, GrantsMade: 2}, f.err
}

func (f *fakeModuleAccessReconciler) ReconcileAll(context.Context) (*services.ModuleAccessReconcileSummary, error) {
	f.allCalls++
	return &services.ModuleAccessReconcileSummary{Tenants: 3}, f.err
}

func newModuleAccessRouter(h *PlatformManagementHandler, authed bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if authed {
			c.Set(middleware.CurrentUserKey, &models.CurrentUser{ID: uuid.New()})
		}
	})
	r.POST("/tenants/:tenant_id/module-access/reconcile", h.ReconcileModuleAccess)
	r.POST("/module-access/reconcile", h.ReconcileModuleAccess)
	return r
}

func doModuleAccessPost(r *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
	return w
}

func TestReconcileModuleAccess_Tenant(t *testing.T) {
	fake := &fakeModuleAccessReconciler{}
	h := &PlatformManagementHandler{logger: zap.NewNop()}
	h.SetModuleAccessReconciler(fake)
	tid := uuid.New()

	w := doModuleAccessPost(newModuleAccessRouter(h, true), "/tenants/"+tid.String()+"/module-access/reconcile")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []uuid.UUID{tid}, fake.tenantCalls)
	assert.Contains(t, w.Body.String(), `"grants_made":2`)
}

func TestReconcileModuleAccess_All(t *testing.T) {
	fake := &fakeModuleAccessReconciler{}
	h := &PlatformManagementHandler{logger: zap.NewNop()}
	h.SetModuleAccessReconciler(fake)

	w := doModuleAccessPost(newModuleAccessRouter(h, true), "/module-access/reconcile")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, fake.allCalls)
}

func TestReconcileModuleAccess_Errors(t *testing.T) {
	h := &PlatformManagementHandler{logger: zap.NewNop()}

	w := doModuleAccessPost(newModuleAccessRouter(h, false), "/module-access/reconcile")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = doModuleAccessPost(newModuleAccessRouter(h, true), "/module-access/reconcile")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	h.SetModuleAccessReconciler(&fakeModuleAccessReconciler{})
	w = doModuleAccessPost(newModuleAccessRouter(h, true), "/tenants/not-a-uuid/module-access/reconcile")
	assert.Equal(t, http.StatusBadRequest, w.Code)

	h.SetModuleAccessReconciler(&fakeModuleAccessReconciler{err: errors.New("boom")})
	w = doModuleAccessPost(newModuleAccessRouter(h, true), "/module-access/reconcile")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	// The partial summary rides along with the error.
	assert.Contains(t, w.Body.String(), `"summary"`)
	assert.Contains(t, w.Body.String(), `"tenants":3`)
}
