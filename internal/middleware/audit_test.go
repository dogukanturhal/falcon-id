// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ==================== AuditMiddleware pass-through ====================

// TestAuditAdmin_NonAdminPathPassesThrough verifies that the AuditAdmin middleware
// does NOT block requests to paths outside /api/admin.
func TestAuditAdmin_NonAdminPathPassesThrough(t *testing.T) {
	// AuditMiddleware requires an AdminAuditService, but with a nil service the
	// middleware still short-circuits for non-admin paths (it calls c.Next() right
	// away). We test that behaviour here without needing a real DB.
	m := NewAuditMiddleware(nil)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.AuditAdmin())
	router.GET("/api/users/me", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/users/me", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"AuditAdmin must not block non-admin paths")
}

// TestAuditAdmin_AdminGetNonSensitivePassesThrough verifies that GET requests to
// non-sensitive admin endpoints are passed through without attempting to log.
func TestAuditAdmin_AdminGetNonSensitivePassesThrough(t *testing.T) {
	m := NewAuditMiddleware(nil)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.AuditAdmin())
	router.GET("/api/admin/overview", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/overview", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"non-sensitive admin GET must not be blocked")
}

// TestAuditAdmin_AdminPostWithoutUserPassesThrough verifies that admin POST
// requests without an authenticated user in context still pass through (auth
// middleware will handle rejection later in the real pipeline).
func TestAuditAdmin_AdminPostWithoutUserPassesThrough(t *testing.T) {
	m := NewAuditMiddleware(nil)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.AuditAdmin())
	router.POST("/api/admin/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users", nil)
	router.ServeHTTP(w, req)

	// No user in context — middleware calls c.Next() without logging.
	assert.Equal(t, http.StatusOK, w.Code,
		"admin POST without user must pass through (auth handles rejection)")
}

// TestAuditAdmin_SensitiveGetPassesThrough verifies that GET requests to
// sensitive read endpoints pass through when no user is in context.
func TestAuditAdmin_SensitiveGetPassesThrough(t *testing.T) {
	m := NewAuditMiddleware(nil)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(m.AuditAdmin())
	router.GET("/api/admin/audit-logs", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"logs": []interface{}{}})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/audit-logs", nil)
	router.ServeHTTP(w, req)

	// No user in context — c.Next() is called without attempting async logging.
	assert.Equal(t, http.StatusOK, w.Code)
}

// ==================== determineAction ====================

// TestDetermineAction_TableDriven verifies that determineAction maps HTTP method
// and path combinations to the expected action and resource strings.
func TestDetermineAction_TableDriven(t *testing.T) {
	tests := []struct {
		method           string
		path             string
		idParam          string
		expectedAction   string
		expectedResource string
	}{
		{http.MethodPost, "/api/admin/users", "", "user.create", "user"},
		{http.MethodPut, "/api/admin/users/123", "123", "user.update", "user"},
		{http.MethodDelete, "/api/admin/users/123", "123", "user.delete", "user"},
		{http.MethodPost, "/api/admin/roles", "", "role.create", "role"},
		{http.MethodPut, "/api/admin/roles/456", "456", "role.update", "role"},
		{http.MethodDelete, "/api/admin/roles/456", "456", "role.delete", "role"},
		{http.MethodDelete, "/api/admin/sessions/789", "789", "session.revoke", "session"},
		{http.MethodPost, "/api/admin/identity-providers", "", "identity_provider.create", "identity_provider"},
		{http.MethodPost, "/api/admin/impersonate", "", "admin.impersonate", "impersonation"},
		{http.MethodGet, "/api/admin/something-unknown", "", "admin.unknown_action", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedAction, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, nil)
			c.Request = req

			if tt.idParam != "" {
				c.Params = gin.Params{{Key: "id", Value: tt.idParam}}
			}

			action, resource, _ := determineAction(c)

			assert.Equal(t, tt.expectedAction, action)
			assert.Equal(t, tt.expectedResource, resource)
		})
	}
}

// TestDetermineAction_UUIDResourceID verifies that a valid UUID :id param is
// parsed and returned as the resourceID.
func TestDetermineAction_UUIDResourceID(t *testing.T) {
	id := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/admin/users/"+id.String(), nil)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: id.String()}}

	_, _, resourceID := determineAction(c)

	assert.NotNil(t, resourceID)
	assert.Equal(t, id, *resourceID)
}

// TestDetermineAction_InvalidUUIDResourceID verifies that a non-UUID :id param
// results in a nil resourceID (not a panic).
func TestDetermineAction_InvalidUUIDResourceID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/admin/users/not-a-uuid", nil)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}

	_, _, resourceID := determineAction(c)

	assert.Nil(t, resourceID, "invalid UUID param must produce nil resourceID")
}

// ==================== isSensitiveReadEndpoint ====================

// TestIsSensitiveReadEndpoint_TableDriven verifies that sensitive read endpoints
// are correctly identified.
func TestIsSensitiveReadEndpoint_TableDriven(t *testing.T) {
	tests := []struct {
		path      string
		sensitive bool
	}{
		{"/api/admin/audit-logs", true},
		{"/api/admin/sessions", true},
		{"/api/admin/api-keys", true},
		{"/api/admin/oauth-clients", true},
		{"/api/admin/service-accounts", true},
		{"/api/admin/security/password-policy", true},
		{"/api/admin/impersonation", true},
		{"/api/admin/users", false},
		{"/api/admin/roles", false},
		{"/api/admin/overview", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isSensitiveReadEndpoint(tt.path)
			assert.Equal(t, tt.sensitive, got,
				"isSensitiveReadEndpoint(%q) must return %v", tt.path, tt.sensitive)
		})
	}
}

// ==================== getRequestID ====================

// TestGetRequestID_FromXRequestIDHeader verifies that the X-Request-ID header
// is used when present.
func TestGetRequestID_FromXRequestIDHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "req-id-123")
	c.Request = req

	id := getRequestID(c)
	assert.Equal(t, "req-id-123", id)
}

// TestGetRequestID_FromXCorrelationIDHeader verifies fallback to X-Correlation-ID.
func TestGetRequestID_FromXCorrelationIDHeader(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("X-Correlation-ID", "corr-id-456")
	c.Request = req

	id := getRequestID(c)
	assert.Equal(t, "corr-id-456", id)
}

// TestGetRequestID_FromContextValue verifies fallback to the context "request_id"
// key (set by CorrelationID middleware).
func TestGetRequestID_FromContextValue(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	c.Request = req
	c.Set("request_id", "ctx-req-id-789")

	id := getRequestID(c)
	assert.Equal(t, "ctx-req-id-789", id)
}

// TestGetRequestID_GeneratesUUIDWhenAbsent verifies that when no ID is available
// from headers or context, a new UUID is generated.
func TestGetRequestID_GeneratesUUIDWhenAbsent(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	c.Request = req

	id := getRequestID(c)
	assert.NotEmpty(t, id)

	_, err := uuid.Parse(id)
	assert.NoError(t, err, "fallback request ID must be a valid UUID")
}

// ==================== responseWriter ====================

// TestResponseWriter_CapturesStatusCode verifies the custom responseWriter
// records the correct status code.
func TestResponseWriter_CapturesStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	ginWriter := &gin.Context{}
	_ = ginWriter

	// Use the response writer through a real Gin context.
	_, router := gin.CreateTestContext(w)
	var capturedStatus int
	router.GET("/test", func(c *gin.Context) {
		rw := newResponseWriter(c.Writer)
		c.Writer = rw
		c.Status(http.StatusAccepted)
		capturedStatus = rw.statusCode
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, capturedStatus)
}

// TestResponseWriter_CapturesBody verifies the custom responseWriter captures
// the response body bytes.
func TestResponseWriter_CapturesBody(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	var capturedBody string
	router.GET("/test", func(c *gin.Context) {
		rw := newResponseWriter(c.Writer)
		c.Writer = rw
		c.JSON(http.StatusOK, gin.H{"hello": "world"})
		capturedBody = rw.body.String()
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Contains(t, capturedBody, "hello",
		"responseWriter must capture the response body")
}

// TestAuditAdmin_AdminPathWithUserInContext_HandlerRuns verifies that when the
// AuditMiddleware is called on an admin path and a current user IS in context,
// the downstream handler still runs (status 200). This test sets the user in
// context AFTER the middleware has already checked for it (via a late-setting
// handler), so AuditAdmin's GetCurrentUser call returns nil, the middleware
// short-circuits and c.Next() is called — ensuring no goroutine is spawned and
// the nil AuditService is never accessed.
func TestAuditAdmin_AdminPathWithUserInContext_HandlerRuns(t *testing.T) {
	// Middleware is given a nil service — the test only reaches the short-circuit
	// branch because the user is not set at the time AuditAdmin reads it.
	m := NewAuditMiddleware(nil)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	// AuditAdmin is registered first; it calls GetCurrentUser before c.Next().
	// At that point the user is NOT yet in context, so the middleware takes the
	// "currentUser == nil → c.Next()" branch and the goroutine is never spawned.
	router.POST("/api/admin/users", m.AuditAdmin(), func(c *gin.Context) {
		// User set inside the final handler, after audit middleware has already run.
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Email:    "admin@test.com",
		})
		c.JSON(http.StatusCreated, gin.H{"id": uuid.New().String()})
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code,
		"handler must run even when audit middleware short-circuits")
}
