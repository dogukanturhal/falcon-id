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

// Auth-envelope tests for AuditHandler. Verify the 401 gate on all 5
// endpoints + the 503 graceful-degradation path on the archive
// endpoints when the AuditArchiverService is nil (matches the
// production wiring while S3/MinIO config isn't plumbed yet).
//
// Service-side behaviour is covered by the existing audit_service +
// audit_archiver_service tests on master.

// newAuditTestHandler constructs an AuditHandler with nil services.
// All test paths short-circuit on the auth gate (401) BEFORE
// reaching the service, so nil is safe. Archive-side tests pass
// a non-nil auth user to confirm the nil-archiver 503 path.
func newAuditTestHandler() *AuditHandler {
	return NewAuditHandler(nil, nil)
}

func fireAuditRequest(t *testing.T, handler gin.HandlerFunc, method, path string, user *models.CurrentUser, params gin.Params, query string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	if query != "" {
		path = path + "?" + query
	}
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

func testAuditUser() *models.CurrentUser {
	return &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Roles:    []string{"admin"},
	}
}

// ---------------------------------------------------------------
// 401 paths — every endpoint must reject unauthenticated requests
// ---------------------------------------------------------------

func TestAuditHandler_GetAuditLogs_RejectsUnauthenticated(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.GetAuditLogs, http.MethodGet, "/audit/logs", nil, nil, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditHandler_ArchiveTenantLogs_RejectsUnauthenticated(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.ArchiveTenantLogs, http.MethodPost, "/audit/archive", nil, nil, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditHandler_GetArchiveMetadata_RejectsUnauthenticated(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.GetArchiveMetadata, http.MethodGet, "/audit/archives", nil, nil, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditHandler_VerifyArchiveIntegrity_RejectsUnauthenticated(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.VerifyArchiveIntegrity, http.MethodPost,
		"/audit/archives/abc/verify", nil,
		gin.Params{{Key: "batch_id", Value: uuid.NewString()}}, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditHandler_ExportAuditReport_RejectsUnauthenticated(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.ExportAuditReport, http.MethodGet, "/audit/export", nil, nil, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---------------------------------------------------------------
// 503 graceful-degradation paths — archive endpoints must return
// ServiceUnavailable when AuditArchiverService is nil (current
// production wiring while S3/MinIO config layer is pending)
// ---------------------------------------------------------------

func TestAuditHandler_ArchiveTenantLogs_NilArchiverReturns503(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.ArchiveTenantLogs, http.MethodPost, "/audit/archive",
		testAuditUser(), nil, "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"with archiver nil, ArchiveTenantLogs must surface 503 so callers can retry once S3 config is plumbed — NOT 500 or 200")
}

func TestAuditHandler_VerifyArchiveIntegrity_NilArchiverReturns503(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.VerifyArchiveIntegrity, http.MethodPost,
		"/audit/archives/abc/verify", testAuditUser(),
		gin.Params{{Key: "batch_id", Value: uuid.NewString()}}, "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"with archiver nil, VerifyArchiveIntegrity must surface 503 — the bytes the verifier needs live in S3/MinIO which isn't reachable")
}

// ---------------------------------------------------------------
// 400 paths — export needs from/to query params
// ---------------------------------------------------------------

func TestAuditHandler_ExportAuditReport_MissingFromTo_Returns400(t *testing.T) {
	h := newAuditTestHandler()
	rec := fireAuditRequest(t, h.ExportAuditReport, http.MethodGet, "/audit/export",
		testAuditUser(), nil, "") // no query params
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------
// 400 path — invalid batch_id UUID on VerifyArchiveIntegrity. Note:
// this fires AFTER the nil-archiver check (handler currently checks
// archiver first), so when archiver is nil we get 503 not 400. Lock
// the ordering — a future refactor could swap the checks and inadvertently
// surface the invalid UUID before the archiver gate, but the existing
// order is correct because invalid-UUID is cheap to detect.
// ---------------------------------------------------------------
// (Skipped: with nil archiver the 503 path eats the UUID parse;
// re-add this test when AuditArchiverService is wired.)
