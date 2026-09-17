// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// tenantBrandingServiceFake – in-process test double
// ---------------------------------------------------------------------------

type tenantBrandingServiceFake struct {
	getResp    *models.TenantBranding
	getErr     error
	updateResp *models.TenantBranding
	updateErr  error
	deleteErr  error
}

func (f *tenantBrandingServiceFake) GetBranding(_ context.Context, _ uuid.UUID) (*models.TenantBranding, error) {
	return f.getResp, f.getErr
}

func (f *tenantBrandingServiceFake) UpdateBranding(_ context.Context, _ uuid.UUID, _ *models.UpdateTenantBrandingRequest) (*models.TenantBranding, error) {
	return f.updateResp, f.updateErr
}

func (f *tenantBrandingServiceFake) DeleteBranding(_ context.Context, _ uuid.UUID) error {
	return f.deleteErr
}

// ---------------------------------------------------------------------------
// Router helper
// ---------------------------------------------------------------------------

func newTenantBrandingTestRouter(svc *tenantBrandingServiceFake) *gin.Engine {
	r := gin.New()
	h := NewTenantBrandingHandler(svc)

	tenant := r.Group("/api/v1/admin/tenants/:tenant_id")
	tenant.GET("/branding", h.GetBranding)
	tenant.PUT("/branding", h.UpdateBranding)
	tenant.DELETE("/branding", h.DeleteBranding)

	return r
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func performBrandingRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeBrandingBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func buildBranding(tenantID uuid.UUID) *models.TenantBranding {
	logo := "https://cdn.acme.io/logo.png"
	accent := "#ff0000"
	now := time.Now()
	return &models.TenantBranding{
		ID:              uuid.New(),
		TenantID:        tenantID,
		LogoURL:         &logo,
		PrimaryColor:    "#2563eb",
		BackgroundColor: "#ffffff",
		AccentColor:     &accent,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// ---------------------------------------------------------------------------
// Tests: GetBranding (GET /api/v1/admin/tenants/:tenant_id/branding)
// ---------------------------------------------------------------------------

func TestTenantBrandingHandler_GetBranding_Success(t *testing.T) {
	tenantID := uuid.New()
	branding := buildBranding(tenantID)

	svc := &tenantBrandingServiceFake{getResp: branding}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusOK, w.Code)
	body := decodeBrandingBody(t, w)
	assert.Equal(t, true, body["success"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, branding.ID.String(), data["id"])
	assert.Equal(t, "#2563eb", data["primary_color"])
}

func TestTenantBrandingHandler_GetBranding_ReturnsDefaults(t *testing.T) {
	tenantID := uuid.New()
	defaults := &models.TenantBranding{
		TenantID:        tenantID,
		PrimaryColor:    "#2563eb",
		BackgroundColor: "#ffffff",
	}

	svc := &tenantBrandingServiceFake{getResp: defaults}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusOK, w.Code)
	body := decodeBrandingBody(t, w)
	assert.Equal(t, true, body["success"])
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "#2563eb", data["primary_color"])
	assert.Equal(t, "#ffffff", data["background_color"])
}

func TestTenantBrandingHandler_GetBranding_InvalidTenantID(t *testing.T) {
	r := newTenantBrandingTestRouter(&tenantBrandingServiceFake{})
	w := performBrandingRequest(r, http.MethodGet, "/api/v1/admin/tenants/bad-uuid/branding", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantBrandingHandler_GetBranding_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	svc := &tenantBrandingServiceFake{getErr: errors.New("db error")}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodGet, path, "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	body := decodeBrandingBody(t, w)
	assert.Equal(t, false, body["success"])
}

// ---------------------------------------------------------------------------
// Tests: UpdateBranding (PUT /api/v1/admin/tenants/:tenant_id/branding)
// ---------------------------------------------------------------------------

func TestTenantBrandingHandler_UpdateBranding_Success(t *testing.T) {
	tenantID := uuid.New()
	updated := buildBranding(tenantID)
	updated.PrimaryColor = "#123456"

	svc := &tenantBrandingServiceFake{updateResp: updated}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	body := `{"primary_color":"#123456"}`
	w := performBrandingRequest(r, http.MethodPut, path, body)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeBrandingBody(t, w)
	assert.Equal(t, true, resp["success"])
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "#123456", data["primary_color"])
}

func TestTenantBrandingHandler_UpdateBranding_AllFields(t *testing.T) {
	tenantID := uuid.New()
	updated := buildBranding(tenantID)
	logoURL := "https://cdn.example.com/logo.png"
	updated.LogoURL = &logoURL
	updated.PrimaryColor = "#aabbcc"
	updated.HideHexxlockBranding = true

	svc := &tenantBrandingServiceFake{updateResp: updated}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	body := `{
		"logo_url":"https://cdn.example.com/logo.png",
		"primary_color":"#aabbcc",
		"background_color":"#ffffff",
		"hide_hexxlock_branding":true
	}`
	w := performBrandingRequest(r, http.MethodPut, path, body)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeBrandingBody(t, w)
	assert.Equal(t, true, resp["success"])
}

func TestTenantBrandingHandler_UpdateBranding_EmptyBody(t *testing.T) {
	tenantID := uuid.New()
	// An empty JSON object is a valid partial update (no fields to apply).
	defaults := buildBranding(tenantID)
	svc := &tenantBrandingServiceFake{updateResp: defaults}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodPut, path, `{}`)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantBrandingHandler_UpdateBranding_MalformedJSON(t *testing.T) {
	tenantID := uuid.New()
	r := newTenantBrandingTestRouter(&tenantBrandingServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodPut, path, `not-json`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantBrandingHandler_UpdateBranding_InvalidTenantID(t *testing.T) {
	r := newTenantBrandingTestRouter(&tenantBrandingServiceFake{})
	w := performBrandingRequest(r, http.MethodPut, "/api/v1/admin/tenants/bad/branding", `{"primary_color":"#000000"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantBrandingHandler_UpdateBranding_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	svc := &tenantBrandingServiceFake{updateErr: errors.New("db write error")}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodPut, path, `{"primary_color":"#112233"}`)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := decodeBrandingBody(t, w)
	assert.Equal(t, false, resp["success"])
}

func TestTenantBrandingHandler_UpdateBranding_ValidationError_InvalidColor(t *testing.T) {
	tenantID := uuid.New()
	// Gin's binding:"hexcolor" tag rejects non-hex color strings.
	r := newTenantBrandingTestRouter(&tenantBrandingServiceFake{})
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	// "red" is not a valid hex color according to the binding tag.
	w := performBrandingRequest(r, http.MethodPut, path, `{"primary_color":"red"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Tests: DeleteBranding (DELETE /api/v1/admin/tenants/:tenant_id/branding)
// ---------------------------------------------------------------------------

func TestTenantBrandingHandler_DeleteBranding_Success(t *testing.T) {
	tenantID := uuid.New()
	svc := &tenantBrandingServiceFake{}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodDelete, path, "")

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.Bytes())
}

func TestTenantBrandingHandler_DeleteBranding_InvalidTenantID(t *testing.T) {
	r := newTenantBrandingTestRouter(&tenantBrandingServiceFake{})
	w := performBrandingRequest(r, http.MethodDelete, "/api/v1/admin/tenants/not-a-uuid/branding", "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantBrandingHandler_DeleteBranding_ServiceError(t *testing.T) {
	tenantID := uuid.New()
	svc := &tenantBrandingServiceFake{deleteErr: errors.New("db error")}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodDelete, path, "")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := decodeBrandingBody(t, w)
	assert.Equal(t, false, resp["success"])
}

func TestTenantBrandingHandler_DeleteBranding_NotFound(t *testing.T) {
	tenantID := uuid.New()
	svc := &tenantBrandingServiceFake{deleteErr: errors.New("not found")}
	r := newTenantBrandingTestRouter(svc)
	path := "/api/v1/admin/tenants/" + tenantID.String() + "/branding"
	w := performBrandingRequest(r, http.MethodDelete, path, "")

	// HandleError maps "not found" -> 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}
