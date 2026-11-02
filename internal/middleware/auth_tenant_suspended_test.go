// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type suspendedFake struct{ on atomic.Bool }

func (f *suspendedFake) IsSuspended(context.Context, uuid.UUID) bool { return f.on.Load() }

// A valid bearer token of a suspended tenant is rejected with 403
// tenant_suspended (session validation), and works again after resume.
func TestRequireAuth_TenantSuspended_Returns403ThenResumeAllows(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	fake := &suspendedFake{}
	svc.SetTenantSuspensionChecker(fake)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)
	token := buildValidToken(t, cfg, uuid.New(), uuid.New(), uuid.New(), nil, nil)

	call := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		return w
	}

	assert.Equal(t, http.StatusOK, call().Code)

	fake.on.Store(true)
	w := call()
	require.Equal(t, http.StatusForbidden, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "tenant_suspended", body["error"])

	fake.on.Store(false)
	assert.Equal(t, http.StatusOK, call().Code)
}
