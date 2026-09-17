// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// injectCurrentUser is a test-only middleware that injects a CurrentUser into the Gin context.
func injectCurrentUser(u *models.CurrentUser) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("current_user", u)
		c.Next()
	}
}

// TestTenantSettingsHandler_GetSettings_Unauthorized verifies 401 when no user is set.
func TestTenantSettingsHandler_GetSettings_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTenantSettingsHandler(nil, zap.NewNop())
	r := gin.New()
	r.GET("/tenants/me/settings", h.GetSettings)

	req := httptest.NewRequest(http.MethodGet, "/tenants/me/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTenantSettingsHandler_PatchSettings_Unauthorized verifies 401 when no user is set.
func TestTenantSettingsHandler_PatchSettings_Unauthorized(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTenantSettingsHandler(nil, zap.NewNop())
	r := gin.New()
	r.PATCH("/tenants/me/settings", h.PatchSettings)

	body, _ := json.Marshal(map[string]string{"timezone": "UTC"})
	req := httptest.NewRequest(http.MethodPatch, "/tenants/me/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestTenantSettingsHandler_PatchSettings_InvalidTimezone verifies 400 for bad timezone.
// The handler exits with 400 before touching the DB, so a nil repo is safe.
func TestTenantSettingsHandler_PatchSettings_InvalidTimezone(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	h := handlers.NewTenantSettingsHandler(nil, zap.NewNop())
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New()}

	r := gin.New()
	r.Use(injectCurrentUser(user))
	r.PATCH("/tenants/me/settings", h.PatchSettings)

	body, _ := json.Marshal(map[string]string{"timezone": "Not/A/Valid/TZ"})
	req := httptest.NewRequest(http.MethodPatch, "/tenants/me/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestTenantSettingsHandler_PatchSettings_ClearSenderDomain verifies the model field is accessible.
func TestTenantSettingsHandler_PatchSettings_ClearSenderDomain(t *testing.T) {
	t.Parallel()

	req := handlers.PatchTenantSettingsRequest{
		ClearDefaultSenderDomain: true,
	}
	if req.DefaultSenderDomainID != nil {
		t.Error("expected nil DefaultSenderDomainID when not set")
	}
	if !req.ClearDefaultSenderDomain {
		t.Error("expected ClearDefaultSenderDomain=true")
	}
}
