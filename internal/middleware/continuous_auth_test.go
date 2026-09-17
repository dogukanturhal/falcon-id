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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

// newTestOrchestrator creates a ZeroTrustOrchestrator for middleware tests.
// All dependencies are nil; the stub implementation always returns allow.
func newTestOrchestrator(enabled bool) *services.ZeroTrustOrchestrator {
	cfg := services.ZeroTrustOrchestratorConfig{
		Enabled:                enabled,
		RiskThresholdDeny:      0.9,
		RiskThresholdChallenge: 0.6,
	}
	return services.NewZeroTrustOrchestrator(nil, nil, cfg, zap.NewNop())
}

// runContinuousAuth routes a GET /test through the ContinuousAuth middleware.
// sessionIDVal may be a uuid.UUID, a string, or nil (key not set at all).
func runContinuousAuth(
	t *testing.T,
	orch *services.ZeroTrustOrchestrator,
	sessionIDVal interface{},
	ip string,
	ua string, //nolint:unparam // ua is always "Chrome/120" currently but kept for flexibility
) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	router.GET("/test",
		func(c *gin.Context) {
			if sessionIDVal != nil {
				c.Set("session_id", sessionIDVal)
			}
		},
		ContinuousAuth(orch),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	require.NoError(t, err)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	if ip != "" {
		req.RemoteAddr = ip + ":12345"
	}

	router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// ContinuousAuth middleware tests
// ---------------------------------------------------------------------------

func TestContinuousAuth_NoSessionID_PassThrough(t *testing.T) {
	o := newTestOrchestrator(true)
	w := runContinuousAuth(t, o, nil, "1.2.3.4", "Chrome/120")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestContinuousAuth_EmptyUUIDSession_PassThrough(t *testing.T) {
	o := newTestOrchestrator(true)
	w := runContinuousAuth(t, o, uuid.Nil, "1.2.3.4", "Chrome/120")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestContinuousAuth_DisabledOrchestrator_Allow(t *testing.T) {
	o := newTestOrchestrator(false)
	sessionID := uuid.New()
	w := runContinuousAuth(t, o, sessionID, "1.2.3.4", "Chrome/120")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestContinuousAuth_EnabledOrchestrator_StubAlwaysAllow(t *testing.T) {
	// Current implementation is a stub — EvaluateRequest always returns "allow".
	o := newTestOrchestrator(true)
	sessionID := uuid.New()
	w := runContinuousAuth(t, o, sessionID, "1.2.3.4", "Chrome/120")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestContinuousAuth_SessionIDAsString_Handled(t *testing.T) {
	o := newTestOrchestrator(true)
	sessionID := uuid.New().String()
	w := runContinuousAuth(t, o, sessionID, "127.0.0.1", "Chrome/120")
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// extractSessionID helper tests
// ---------------------------------------------------------------------------

func TestExtractSessionID_UUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	id := uuid.New()
	c.Set("session_id", id)

	assert.Equal(t, id.String(), extractSessionID(c))
}

func TestExtractSessionID_String(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("session_id", "my-session-string")

	assert.Equal(t, "my-session-string", extractSessionID(c))
}

func TestExtractSessionID_NilUUID_ReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("session_id", uuid.Nil)

	assert.Equal(t, "", extractSessionID(c))
}

func TestExtractSessionID_Missing_ReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	assert.Equal(t, "", extractSessionID(c))
}
