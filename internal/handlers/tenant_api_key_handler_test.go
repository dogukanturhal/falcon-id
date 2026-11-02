// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

func tenantKeyRouter(h *TenantAPIKeyHandler, user *models.CurrentUser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if user != nil {
		r.Use(injectCurrentUser(user))
	}
	r.GET("/api/v1/developer/api-keys", h.List)
	r.POST("/api/v1/developer/api-keys", h.Create)
	r.GET("/api/v1/developer/api-keys/:id", h.Get)
	r.POST("/api/v1/developer/api-keys/:id/rotate", h.Rotate)
	r.POST("/api/v1/developer/api-keys/:id/revoke", h.Revoke)
	r.DELETE("/api/v1/developer/api-keys/:id", h.Delete)
	r.POST("/oauth/token/api-key", h.TokenEndpoint)
	return r
}

func tenantKeyDo(r *gin.Engine, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTenantAPIKeyHandler_FlagOffIs404(t *testing.T) {
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()}
	flagOffSvc := services.NewTenantAPIKeyService(&config.Config{}, services.TenantAPIKeyDeps{})

	for name, h := range map[string]*TenantAPIKeyHandler{
		"nil service":      NewTenantAPIKeyHandler(nil, zap.NewNop()),
		"flag off service": NewTenantAPIKeyHandler(flagOffSvc, zap.NewNop()),
	} {
		t.Run(name, func(t *testing.T) {
			r := tenantKeyRouter(h, user)
			id := uuid.NewString()
			for _, tc := range []struct{ method, path, body string }{
				{http.MethodGet, "/api/v1/developer/api-keys", ""},
				{http.MethodPost, "/api/v1/developer/api-keys", `{}`},
				{http.MethodGet, "/api/v1/developer/api-keys/" + id, ""},
				{http.MethodPost, "/api/v1/developer/api-keys/" + id + "/rotate", ""},
				{http.MethodPost, "/api/v1/developer/api-keys/" + id + "/revoke", ""},
				{http.MethodDelete, "/api/v1/developer/api-keys/" + id, ""},
			} {
				w := tenantKeyDo(r, tc.method, tc.path, "application/json", tc.body)
				assert.Equal(t, http.StatusNotFound, w.Code, tc.method+" "+tc.path)
				assert.Contains(t, w.Body.String(), "api_keys_disabled")
			}
		})
	}
}

func TestTenantAPIKeyHandler_RequiresAuthenticatedUser(t *testing.T) {
	r := tenantKeyRouter(NewTenantAPIKeyHandler(nil, zap.NewNop()), nil)
	w := tenantKeyDo(r, http.MethodGet, "/api/v1/developer/api-keys", "", "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTenantAPIKeyHandler_TokenEndpoint(t *testing.T) {
	h := NewTenantAPIKeyHandler(services.NewTenantAPIKeyService(&config.Config{}, services.TenantAPIKeyDeps{}), zap.NewNop())
	r := tenantKeyRouter(h, nil)
	form := "application/x-www-form-urlencoded"

	t.Run("wrong grant type", func(t *testing.T) {
		w := tenantKeyDo(r, http.MethodPost, "/oauth/token/api-key", form, url.Values{"grant_type": {"password"}}.Encode())
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "unsupported_grant_type")
	})
	t.Run("garbage credentials are a uniform invalid_client", func(t *testing.T) {
		w := tenantKeyDo(r, http.MethodPost, "/oauth/token/api-key", form, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {"lgk_live_nope"}, "client_secret": {"nope"},
		}.Encode())
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_client")
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})
	t.Run("multipart is 415", func(t *testing.T) {
		w := tenantKeyDo(r, http.MethodPost, "/oauth/token/api-key", "multipart/form-data; boundary=x", "--x--")
		assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
	})
	t.Run("nil service is 404", func(t *testing.T) {
		nilRouter := tenantKeyRouter(NewTenantAPIKeyHandler(nil, zap.NewNop()), nil)
		w := tenantKeyDo(nilRouter, http.MethodPost, "/oauth/token/api-key", form, url.Values{"grant_type": {"client_credentials"}}.Encode())
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestTenantAPIKeyHandler_InvalidIDIs400(t *testing.T) {
	cfg := &config.Config{DeveloperKeysEnabled: true}
	h := NewTenantAPIKeyHandler(services.NewTenantAPIKeyService(cfg, services.TenantAPIKeyDeps{}), zap.NewNop())
	r := tenantKeyRouter(h, &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/developer/api-keys/not-a-uuid"},
		{http.MethodPost, "/api/v1/developer/api-keys/not-a-uuid/rotate"},
		{http.MethodPost, "/api/v1/developer/api-keys/not-a-uuid/revoke"},
		{http.MethodDelete, "/api/v1/developer/api-keys/not-a-uuid"},
	} {
		w := tenantKeyDo(r, tc.method, tc.path, "application/json", "")
		assert.Equal(t, http.StatusBadRequest, w.Code, tc.method+" "+tc.path)
	}
}

func TestTenantAPIKeyHandler_CreateRejectsMalformedBody(t *testing.T) {
	cfg := &config.Config{DeveloperKeysEnabled: true}
	h := NewTenantAPIKeyHandler(services.NewTenantAPIKeyService(cfg, services.TenantAPIKeyDeps{}), zap.NewNop())
	r := tenantKeyRouter(h, &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()})
	w := tenantKeyDo(r, http.MethodPost, "/api/v1/developer/api-keys", "application/json", `{not json`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}
