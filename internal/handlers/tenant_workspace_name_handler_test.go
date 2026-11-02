// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type wsStore struct{ tenant *models.Tenant }

func (s *wsStore) GetByID(_ context.Context, id uuid.UUID) (*models.Tenant, error) {
	if s.tenant != nil && s.tenant.ID == id {
		return s.tenant, nil
	}
	return nil, nil
}
func (s *wsStore) RenameDisplayNameIfPlaceholder(_ context.Context, _ uuid.UUID, name string) (bool, error) {
	if !models.IsPlaceholderTenantName(s.tenant.DisplayName) {
		return false, nil
	}
	s.tenant.DisplayName = name
	return true, nil
}
func (s *wsStore) ListNameStates(context.Context) ([]repositories.TenantNameState, error) {
	return []repositories.TenantNameState{{ID: s.tenant.ID, Slug: "s", DisplayName: s.tenant.DisplayName}}, nil
}

type wsCompany struct{}

func (wsCompany) DefaultCompanyName(context.Context, uuid.UUID) (string, bool, error) {
	return "Acme Yazilim", true, nil
}

func wsRouter(store *wsStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := NewTenantWorkspaceNameHandler(services.NewTenantWorkspaceNameService(store, nil, wsCompany{}, nil), zap.NewNop())
	r := gin.New()
	r.PUT("/internal/v1/tenants/:id/workspace-name", h.RenameIfPlaceholder)
	r.POST("/backfill", h.Backfill)
	return r
}

func wsDo(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestWorkspaceNameHandler_BackfillDefaultsToDryRun(t *testing.T) {
	store := &wsStore{tenant: &models.Tenant{ID: uuid.New(), DisplayName: models.PlaceholderTenantName}}
	r := wsRouter(store)

	for _, body := range []string{"", "{}", `{"dryRun":true}`} {
		rec := wsDo(r, http.MethodPost, "/backfill", body)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"dryRun":true`)
		assert.True(t, models.IsPlaceholderTenantName(store.tenant.DisplayName), "dry run must not write (body %q)", body)
	}

	rec := wsDo(r, http.MethodPost, "/backfill", `{"dryRun":false}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Acme Yazilim", store.tenant.DisplayName)
}

func TestWorkspaceNameHandler_Rename(t *testing.T) {
	id := uuid.New()
	store := &wsStore{tenant: &models.Tenant{ID: id, DisplayName: models.PlaceholderTenantName}}
	r := wsRouter(store)
	path := "/internal/v1/tenants/" + id.String() + "/workspace-name"

	assert.Equal(t, http.StatusBadRequest, wsDo(r, http.MethodPut, path, `{"name":"My Company"}`).Code)
	assert.Equal(t, http.StatusNotFound, wsDo(r, http.MethodPut, "/internal/v1/tenants/"+uuid.NewString()+"/workspace-name", `{"name":"Acme"}`).Code)

	rec := wsDo(r, http.MethodPut, path, `{"name":"Acme"}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"renamed"`)

	rec = wsDo(r, http.MethodPut, path, `{"name":"Other"}`)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"already_named"`)
	assert.Equal(t, "Acme", store.tenant.DisplayName)
}
