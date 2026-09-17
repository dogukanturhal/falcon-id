// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

type mockStepUpRepo struct {
	mock.Mock
}

func (m *mockStepUpRepo) HasRecentVerification(
	ctx context.Context,
	sessionID uuid.UUID,
	action string,
	maxAge time.Duration,
) (bool, error) {
	args := m.Called(ctx, sessionID, action, maxAge)
	return args.Bool(0), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// runStepUp routes a GET /protected through the RequireStepUp middleware and
// returns the recorded response. If sessionID is non-nil it is placed in the
// gin context under "session_id" before the middleware runs.
func runStepUp(
	t *testing.T,
	repo StepUpVerificationRepo,
	action string,
	maxAge time.Duration,
	sessionID *uuid.UUID,
) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	mw := NewStepUpMiddleware(repo, zap.NewNop())

	router.GET("/protected",
		func(c *gin.Context) {
			if sessionID != nil {
				c.Set("session_id", *sessionID)
			}
			c.Next()
		},
		mw.RequireStepUp(action, maxAge),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	require.NoError(t, err)
	router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestStepUpRequired_NoRecentMFA_Returns401WithRFC9470Header(t *testing.T) {
	repo := new(mockStepUpRepo)
	sessionID := uuid.New()
	action := "delete_user"
	maxAge := 5 * time.Minute

	repo.On("HasRecentVerification", mock.Anything, sessionID, action, maxAge).Return(false, nil)

	w := runStepUp(t, repo, action, maxAge, &sessionID)

	// RFC 9470 §3 / IAM-05: status MUST be 401 (was 403 through 2026-04-29);
	// WWW-Authenticate MUST contain Bearer + error=insufficient_user_authentication.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, `error="insufficient_user_authentication"`)
	assert.Contains(t, wwwAuth, "max_age=300") // 5min = 300s
	body := w.Body.String()
	assert.Contains(t, body, "step_up_required")
	assert.Contains(t, body, action)
	repo.AssertExpectations(t)
}

func TestStepUpRequired_FreshMFA_Passes(t *testing.T) {
	repo := new(mockStepUpRepo)
	sessionID := uuid.New()
	action := "export_data"
	maxAge := 10 * time.Minute

	repo.On("HasRecentVerification", mock.Anything, sessionID, action, maxAge).Return(true, nil)

	w := runStepUp(t, repo, action, maxAge, &sessionID)

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}

func TestStepUpRequired_NoSessionID_Returns401(t *testing.T) {
	repo := new(mockStepUpRepo)

	// nil sessionID — the "session_id" key is never set in context.
	w := runStepUp(t, repo, "some_action", 5*time.Minute, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")
	repo.AssertNotCalled(t, "HasRecentVerification")
}

func TestStepUpRequired_RepoError_Returns503(t *testing.T) {
	repo := new(mockStepUpRepo)
	sessionID := uuid.New()
	action := "sensitive_action"
	maxAge := 5 * time.Minute
	repoErr := errors.New("database connection timeout")

	repo.On("HasRecentVerification", mock.Anything, sessionID, action, maxAge).Return(false, repoErr)

	w := runStepUp(t, repo, action, maxAge, &sessionID)

	// Fail-closed: a repo error must deny access.
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "unable to verify")
	repo.AssertExpectations(t)
}

func TestStepUpRequired_ExpiredMFA_Returns401WithRFC9470Header(t *testing.T) {
	// The repository is responsible for applying the maxAge filter.
	// When no qualifying verification exists it returns false.
	repo := new(mockStepUpRepo)
	sessionID := uuid.New()
	action := "change_password"
	maxAge := 2 * time.Minute

	repo.On("HasRecentVerification", mock.Anything, sessionID, action, maxAge).Return(false, nil)

	w := runStepUp(t, repo, action, maxAge, &sessionID)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_user_authentication"`)
	assert.Contains(t, wwwAuth, "max_age=120") // 2min = 120s
	body := w.Body.String()
	assert.Contains(t, body, `"step_up_required":true`)
	assert.Contains(t, body, action)
	repo.AssertExpectations(t)
}

func TestStepUpRequired_ActionFieldInResponse(t *testing.T) {
	repo := new(mockStepUpRepo)
	sessionID := uuid.New()
	const action = "bulk_delete"
	maxAge := 5 * time.Minute

	repo.On("HasRecentVerification", mock.Anything, sessionID, action, maxAge).Return(false, nil)

	w := runStepUp(t, repo, action, maxAge, &sessionID)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"action":"bulk_delete"`)
	assert.Contains(t, body, `"step_up_required":true`)
	// RFC 9470 §3: error_description should carry the action so an
	// SDK consumer surfacing the WWW-Authenticate header to the user
	// has operator-meaningful context.
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "bulk_delete")
	repo.AssertExpectations(t)
}

func TestStepUpRequired_MaxAgeForwarded(t *testing.T) {
	// Ensure the exact maxAge value is forwarded to the repository.
	repo := new(mockStepUpRepo)
	sessionID := uuid.New()
	action := "critical_op"
	maxAge := 30 * time.Second

	repo.On("HasRecentVerification", mock.Anything, sessionID, action, maxAge).Return(true, nil)

	w := runStepUp(t, repo, action, maxAge, &sessionID)

	assert.Equal(t, http.StatusOK, w.Code)
	repo.AssertExpectations(t)
}
