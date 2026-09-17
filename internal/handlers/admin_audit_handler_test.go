// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
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

// Auth-envelope tests for AdminAuditHandler. These verify the
// authentication gate on all 3 endpoints + the invalid-UUID branch
// on GetAdminAuditLog. Service-side behaviour (the actual query +
// filter logic) is covered by services/admin_audit_service_test.go.
//
// Why nil services are acceptable here: each handler method
// short-circuits on `currentUser == nil` before touching the
// service, so the 401 path doesn't require a wired service. The
// GetAdminAuditLog 400 (invalid UUID) also fires before any service
// call. These are exactly the regression-coverage cases that catch
// a route-registration regression — a misregistered route surfaces
// as 404 instead of 401/400.

func newAdminAuditTestHandler() *AdminAuditHandler {
	return NewAdminAuditHandler(nil, nil)
}

func fireAdminAuditRequest(t *testing.T, handler gin.HandlerFunc, method, path string, user *models.CurrentUser, params gin.Params) *httptest.ResponseRecorder {
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

func TestAdminAuditHandler_ListAdminAuditLogs_RejectsUnauthenticated(t *testing.T) {
	h := newAdminAuditTestHandler()
	rec := fireAdminAuditRequest(t, h.ListAdminAuditLogs, http.MethodGet, "/audit/admin-actions", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAdminAuditHandler_GetAdminAuditLog_RejectsUnauthenticated(t *testing.T) {
	h := newAdminAuditTestHandler()
	rec := fireAdminAuditRequest(t, h.GetAdminAuditLog, http.MethodGet,
		"/audit/admin-actions/abc", nil,
		gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAdminAuditHandler_GetAdminAuditLog_RejectsInvalidUUID(t *testing.T) {
	h := newAdminAuditTestHandler()
	user := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"admin"},
	}
	rec := fireAdminAuditRequest(t, h.GetAdminAuditLog, http.MethodGet,
		"/audit/admin-actions/not-a-uuid", user,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminAuditHandler_GetAdminAuditStats_RejectsUnauthenticated(t *testing.T) {
	h := newAdminAuditTestHandler()
	rec := fireAdminAuditRequest(t, h.GetAdminAuditStats, http.MethodGet,
		"/audit/admin-actions/stats", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
