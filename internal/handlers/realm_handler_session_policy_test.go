// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type stubSessionPolicyRepo struct {
	secs *int
	err  error
}

func (s *stubSessionPolicyRepo) GetSessionAbsoluteTTLSeconds(context.Context, uuid.UUID) (*int, error) {
	return s.secs, s.err
}

func (s *stubSessionPolicyRepo) SetSessionAbsoluteTTLSeconds(_ context.Context, _ uuid.UUID, v *int) error {
	if s.err != nil {
		return s.err
	}
	s.secs = v
	return nil
}

func sessionPolicyRouter(repo *stubSessionPolicyRepo) *gin.Engine {
	gin.SetMode(gin.TestMode)
	svc := services.NewRealmService(&mockRealmRepo{
		logAuditFn: func(context.Context, *models.RealmAuditLog) error { return nil },
	}, newTestCfg(), zap.NewNop())
	if repo != nil {
		svc.SetSessionPolicyRepository(repo)
	}
	h := NewRealmHandler(svc, zap.NewNop())
	r := gin.New()
	r.GET("/realms/:id/session-policy", h.GetSessionPolicy)
	r.PUT("/realms/:id/session-policy", h.UpdateSessionPolicy)
	return r
}

func putSessionPolicy(r *gin.Engine, id, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/realms/"+id+"/session-policy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestRealmHandler_SessionPolicy_Validation(t *testing.T) {
	id := uuid.NewString()
	repo := &stubSessionPolicyRepo{}
	r := sessionPolicyRouter(repo)

	for _, tc := range []struct {
		name, body string
		code       int
	}{
		{"24h ok", `{"session_absolute_ttl_seconds":86400}`, http.StatusOK},
		{"min 1h ok", `{"session_absolute_ttl_seconds":3600}`, http.StatusOK},
		{"max 90d ok", `{"session_absolute_ttl_seconds":7776000}`, http.StatusOK},
		{"null clears", `{"session_absolute_ttl_seconds":null}`, http.StatusOK},
		{"below 1h", `{"session_absolute_ttl_seconds":3599}`, http.StatusBadRequest},
		{"above 90d", `{"session_absolute_ttl_seconds":7776001}`, http.StatusBadRequest},
		{"negative", `{"session_absolute_ttl_seconds":-1}`, http.StatusBadRequest},
		{"missing field", `{}`, http.StatusBadRequest},
		{"wrong type", `{"session_absolute_ttl_seconds":"x"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.code, putSessionPolicy(r, id, tc.body).Code)
		})
	}

	assert.Equal(t, http.StatusBadRequest, putSessionPolicy(r, "bad-id", `{"session_absolute_ttl_seconds":86400}`).Code)
}

func TestRealmHandler_SessionPolicy_RoundTrip(t *testing.T) {
	id := uuid.NewString()
	repo := &stubSessionPolicyRepo{}
	r := sessionPolicyRouter(repo)

	require.Equal(t, http.StatusOK, putSessionPolicy(r, id, `{"session_absolute_ttl_seconds":86400}`).Code)
	require.NotNil(t, repo.secs)
	assert.Equal(t, 86400, *repo.secs)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+id+"/session-policy", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"session_absolute_ttl_seconds":86400}`, w.Body.String())
}

func TestRealmHandler_SessionPolicy_UnwiredAndNotFound(t *testing.T) {
	id := uuid.NewString()
	assert.Equal(t, http.StatusServiceUnavailable,
		putSessionPolicy(sessionPolicyRouter(nil), id, `{"session_absolute_ttl_seconds":86400}`).Code)

	r := sessionPolicyRouter(&stubSessionPolicyRepo{err: errors.New("realm not found")})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/realms/"+id+"/session-policy", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}
