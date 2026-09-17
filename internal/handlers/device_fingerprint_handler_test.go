// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Auth-envelope tests for DeviceFingerprintHandler. These verify the
// authentication gate on all 3 endpoints + invalid-UUID branches.
// Service-side behaviour is covered by the existing
// device_fingerprint_service tests on master — these tests catch
// regressions in the route wiring (handler 404 → 401/400 mapping).

// nilFingerprintService satisfies deviceFingerprintServiceIface with
// nil-safe no-op implementations. Used to construct the handler
// without a real DB; every test path short-circuits BEFORE reaching
// these methods, so they panic-on-call is a feature (catches
// accidental service-side reach from a future regression).
type nilFingerprintService struct{}

func (nilFingerprintService) ListUserDevices(_ context.Context, _, _ uuid.UUID) ([]models.DeviceFingerprintRecord, error) {
	panic("test: ListUserDevices should not be reached on the auth-failure path")
}
func (nilFingerprintService) TrustDevice(_ context.Context, _, _ uuid.UUID) error {
	panic("test: TrustDevice should not be reached on the auth-failure path")
}
func (nilFingerprintService) RevokeDevice(_ context.Context, _, _ uuid.UUID) error {
	panic("test: RevokeDevice should not be reached on the auth-failure path")
}

func newFingerprintTestHandler() *DeviceFingerprintHandler {
	return NewDeviceFingerprintHandler(nilFingerprintService{})
}

func fireFingerprintRequest(t *testing.T, handler gin.HandlerFunc, method, path string, user *models.CurrentUser, params gin.Params) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	c.Request = req
	c.Params = params
	if user != nil {
		c.Set(middleware.CurrentUserKey, user)
	}
	handler(c)
	return rec
}

func TestDeviceFingerprintHandler_ListDeviceFingerprints_RejectsUnauthenticated(t *testing.T) {
	h := newFingerprintTestHandler()
	rec := fireFingerprintRequest(t, h.ListDeviceFingerprints, http.MethodGet, "/fingerprints", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDeviceFingerprintHandler_TrustDeviceFingerprint_RejectsUnauthenticated(t *testing.T) {
	h := newFingerprintTestHandler()
	rec := fireFingerprintRequest(t, h.TrustDeviceFingerprint, http.MethodPost,
		"/fingerprints/abc/trust", nil,
		gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDeviceFingerprintHandler_TrustDeviceFingerprint_RejectsInvalidUUID(t *testing.T) {
	h := newFingerprintTestHandler()
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	rec := fireFingerprintRequest(t, h.TrustDeviceFingerprint, http.MethodPost,
		"/fingerprints/not-a-uuid/trust", user,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDeviceFingerprintHandler_RevokeDeviceFingerprint_RejectsUnauthenticated(t *testing.T) {
	h := newFingerprintTestHandler()
	rec := fireFingerprintRequest(t, h.RevokeDeviceFingerprint, http.MethodDelete,
		"/fingerprints/abc", nil,
		gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDeviceFingerprintHandler_RevokeDeviceFingerprint_RejectsInvalidUUID(t *testing.T) {
	h := newFingerprintTestHandler()
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	rec := fireFingerprintRequest(t, h.RevokeDeviceFingerprint, http.MethodDelete,
		"/fingerprints/not-a-uuid", user,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
