// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ─── mock ────────────────────────────────────────────────────────────────────

type mockHostDiscoveryService struct{ mock.Mock }

func (m *mockHostDiscoveryService) Discover(ctx context.Context, host string) (*models.HostDiscoveryResponse, error) {
	args := m.Called(ctx, host)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.HostDiscoveryResponse), args.Error(1)
}

func setupHostDiscoveryRouter(svc HostDiscoveryServiceIface) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewHostDiscoveryHandler(svc)
	r.GET("/internal/v1/tenant-discovery", h.Discover)
	return r
}

func getDiscovery(r *gin.Engine, query string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/internal/v1/tenant-discovery"+query, nil)
	r.ServeHTTP(w, req)
	return w
}

// ─── 200 OK ──────────────────────────────────────────────────────────────────

func TestHostDiscoveryHandler_200_Active(t *testing.T) {
	svc := new(mockHostDiscoveryService)
	tenantID := uuid.New()
	svc.On("Discover", mock.Anything, "crm.acme-corp.com").Return(&models.HostDiscoveryResponse{
		TenantID:     tenantID,
		Host:         "crm.acme-corp.com",
		CanonicalURL: "https://crm.acme-corp.com",
		Issuer:       "https://crm.acme-corp.com",
		Status:       models.TenantHostStatusActive,
	}, nil)

	w := getDiscovery(setupHostDiscoveryRouter(svc), "?host=crm.acme-corp.com")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))
	var body models.HostDiscoveryResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, tenantID, body.TenantID)
	assert.Equal(t, "https://crm.acme-corp.com", body.Issuer)
}

// ─── 400 missing host ────────────────────────────────────────────────────────

func TestHostDiscoveryHandler_400_MissingHost(t *testing.T) {
	svc := new(mockHostDiscoveryService)
	w := getDiscovery(setupHostDiscoveryRouter(svc), "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	// Service must NOT be called when the param is absent.
	svc.AssertNotCalled(t, "Discover", mock.Anything, mock.Anything)
}

// ─── 404 unknown ─────────────────────────────────────────────────────────────

func TestHostDiscoveryHandler_404_NotFound(t *testing.T) {
	svc := new(mockHostDiscoveryService)
	svc.On("Discover", mock.Anything, "missing.example.com").Return(nil, services.ErrHostNotFound)

	w := getDiscovery(setupHostDiscoveryRouter(svc), "?host=missing.example.com")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "public, max-age=30", w.Header().Get("Cache-Control"))
}

// ─── 410 suspended ───────────────────────────────────────────────────────────

func TestHostDiscoveryHandler_410_Suspended(t *testing.T) {
	svc := new(mockHostDiscoveryService)
	svc.On("Discover", mock.Anything, "old.example.com").Return(nil, services.ErrHostSuspended)

	w := getDiscovery(setupHostDiscoveryRouter(svc), "?host=old.example.com")
	assert.Equal(t, http.StatusGone, w.Code)
	assert.Equal(t, "public, max-age=30", w.Header().Get("Cache-Control"))
}

// ─── 503 pending ─────────────────────────────────────────────────────────────

func TestHostDiscoveryHandler_503_Pending(t *testing.T) {
	svc := new(mockHostDiscoveryService)
	svc.On("Discover", mock.Anything, "new.example.com").Return(nil, services.ErrHostPending)

	w := getDiscovery(setupHostDiscoveryRouter(svc), "?host=new.example.com")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	// DNS state churns — no-store is the right Cache-Control.
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

// ─── 500 unexpected ──────────────────────────────────────────────────────────

func TestHostDiscoveryHandler_500_InternalError(t *testing.T) {
	svc := new(mockHostDiscoveryService)
	svc.On("Discover", mock.Anything, "broken.example.com").Return(nil,
		assert.AnError /* any non-sentinel error */)

	w := getDiscovery(setupHostDiscoveryRouter(svc), "?host=broken.example.com")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
