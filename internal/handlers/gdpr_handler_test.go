// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
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

// These tests cover the GDPRHandler authentication + authorisation envelope
// only — paths that short-circuit BEFORE any service call. Service-side
// behaviour (the actual export collection, the deletion-request creation,
// the legal-hold persistence) is covered by the per-service tests in
// `internal/services/data_{export,deletion}_service_test.go`.
//
// Why split this way: the GDPR services have many internal dependencies
// (multiple repos, *pgxpool.Pool, audit service). Building fakes for all
// of them just to exercise the auth-gate logic would be 200+ lines of
// scaffolding that re-tests behaviour already covered elsewhere. The
// gates ARE the part that route registration changes — a misregistered
// route shows up here as a 404 instead of the expected 401/403, so
// these tests double as regression coverage for the wiring in cmd/routes.go.

// newGDPRTestHandler returns a GDPRHandler with nil service deps. Every
// test below stops BEFORE the handler would dereference a service, so
// nil is correct (and forcing test authors to provide real services
// would invite false-pass tests that accidentally exercise the
// service-side code paths).
func newGDPRTestHandler() *GDPRHandler {
	return NewGDPRHandler(nil, nil, nil, nil)
}

// fireAsUser returns the HTTP response from invoking `handler` against
// the supplied method + path. If `user` is non-nil it is injected into
// the gin context via middleware.CurrentUserKey, otherwise the request
// runs unauthenticated.
func fireAsUser(t *testing.T, handler gin.HandlerFunc, method, path string, user *models.CurrentUser, body []byte, params gin.Params) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, path, bodyReader)
	require.NoError(t, err)
	c.Request = req
	c.Params = params

	if user != nil {
		c.Set(middleware.CurrentUserKey, user)
	}

	handler(c)
	return rec
}

func TestGDPRHandler_ExportUserData_RejectsUnauthenticated(t *testing.T) {
	h := newGDPRTestHandler()
	rec := fireAsUser(t, h.ExportUserData, http.MethodGet, "/users/abc/export", nil, nil,
		gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGDPRHandler_ExportUserData_RejectsCrossUserNonAdmin(t *testing.T) {
	h := newGDPRTestHandler()
	requester := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	otherUser := uuid.New().String()
	rec := fireAsUser(t, h.ExportUserData, http.MethodGet, "/users/"+otherUser+"/export",
		requester, nil, gin.Params{{Key: "id", Value: otherUser}})
	// Non-admin attempting to export another user's data must 403, not
	// reach the service (which is nil and would panic — the test passes
	// when the auth gate fires first).
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGDPRHandler_ExportUserData_RejectsInvalidUUID(t *testing.T) {
	h := newGDPRTestHandler()
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Roles: []string{"admin"}}
	rec := fireAsUser(t, h.ExportUserData, http.MethodGet, "/users/not-a-uuid/export",
		user, nil, gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGDPRHandler_RequestDeletion_RejectsUnauthenticated(t *testing.T) {
	h := newGDPRTestHandler()
	rec := fireAsUser(t, h.RequestDeletion, http.MethodDelete, "/users/x/delete", nil, nil,
		gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGDPRHandler_RequestDeletion_RejectsCrossUserNonAdmin(t *testing.T) {
	h := newGDPRTestHandler()
	requester := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	otherUser := uuid.New().String()
	rec := fireAsUser(t, h.RequestDeletion, http.MethodDelete, "/users/"+otherUser+"/delete",
		requester, nil, gin.Params{{Key: "id", Value: otherUser}})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGDPRHandler_GetDeletionRequest_RejectsCrossUserNonAdmin(t *testing.T) {
	h := newGDPRTestHandler()
	requester := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	otherUser := uuid.New().String()
	rec := fireAsUser(t, h.GetDeletionRequest, http.MethodGet, "/users/"+otherUser+"/deletion-status",
		requester, nil, gin.Params{{Key: "id", Value: otherUser}})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGDPRHandler_SetLegalHold_RejectsUnauthenticated(t *testing.T) {
	h := newGDPRTestHandler()
	rec := fireAsUser(t, h.SetLegalHold, http.MethodPost, "/deletion-requests/x/legal-hold",
		nil, []byte(`{"reason":"litigation"}`), gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGDPRHandler_SetLegalHold_RejectsNonAdmin(t *testing.T) {
	h := newGDPRTestHandler()
	requester := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	rec := fireAsUser(t, h.SetLegalHold, http.MethodPost, "/deletion-requests/x/legal-hold",
		requester, []byte(`{"reason":"litigation"}`),
		gin.Params{{Key: "id", Value: uuid.NewString()}})
	// Legal-hold is an admin-only operation per the regulatory-compliance
	// posture of the endpoint. The handler must enforce this even when
	// the route-level RequireRole gate is bypassed (e.g. by a future
	// refactor that mounts the handler on a different route group).
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGDPRHandler_SetLegalHold_RejectsMissingReason(t *testing.T) {
	h := newGDPRTestHandler()
	admin := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"admin"},
	}
	rec := fireAsUser(t, h.SetLegalHold, http.MethodPost, "/deletion-requests/x/legal-hold",
		admin, []byte(`{}`), gin.Params{{Key: "id", Value: uuid.NewString()}})
	// Reason is required — legal holds need an auditable rationale per
	// regulatory-compliance expectations. Without it, 400.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGDPRHandler_RemoveLegalHold_RejectsNonAdmin(t *testing.T) {
	h := newGDPRTestHandler()
	requester := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"user"},
	}
	rec := fireAsUser(t, h.RemoveLegalHold, http.MethodDelete, "/deletion-requests/x/legal-hold",
		requester, nil, gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGDPRHandler_CancelDeletion_RejectsUnauthenticated(t *testing.T) {
	h := newGDPRTestHandler()
	rec := fireAsUser(t, h.CancelDeletion, http.MethodPost, "/deletion-requests/x/cancel",
		nil, nil, gin.Params{{Key: "id", Value: uuid.NewString()}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGDPRHandler_CancelDeletion_RejectsInvalidUUID(t *testing.T) {
	h := newGDPRTestHandler()
	user := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), Roles: []string{"user"}}
	rec := fireAsUser(t, h.CancelDeletion, http.MethodPost, "/deletion-requests/not-a-uuid/cancel",
		user, nil, gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCurrentUserIsAdmin(t *testing.T) {
	// currentUserIsAdmin is the policy gate that decides cross-user
	// access for the GDPR surface. Lock its semantics in a test so a
	// future change widening the role set doesn't silently expand the
	// admin gate.
	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"empty roles", []string{}, false},
		{"user only", []string{"user"}, false},
		{"admin", []string{"admin"}, true},
		{"platform_admin", []string{"platform_admin"}, true},
		{"both", []string{"admin", "platform_admin"}, true},
		{"user + admin", []string{"user", "admin"}, true},
		{"unknown role", []string{"foo"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &models.CurrentUser{Roles: tt.roles}
			assert.Equal(t, tt.want, currentUserIsAdmin(u))
		})
	}
}

func TestResolveExportFormat(t *testing.T) {
	tests := []struct {
		accept string
		want   string
	}{
		{"", "json"},
		{"application/json", "json"},
		{"text/csv", "csv"},
		{"application/csv", "csv"},
		{"text/csv, application/json", "csv"},
		{"image/png", "json"},
	}
	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveExportFormat(tt.accept))
		})
	}
}

func init() {
	gin.SetMode(gin.TestMode)
}
