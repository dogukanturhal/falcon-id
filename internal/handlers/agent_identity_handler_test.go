// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AgentIdentityHandler relies on route-level RequireAuth +
// RequirePlatformAdmin for the auth gate — the handler itself only
// reads middleware.GetTenantID(c). These tests cover the handler's
// own input-validation surface (UUID parsing on path params + JSON
// body parsing). Service-side behaviour is covered by the existing
// agent_identity_service tests on master.

func newAgentIdentityTestHandler() *AgentIdentityHandler {
	// Nil service is acceptable for tests that short-circuit BEFORE
	// the service call (input validation). Any test that reaches
	// the service would surface as a nil-deref panic — a feature,
	// not a bug, since the existing tests on master cover the
	// service-side branches.
	return NewAgentIdentityHandler(nil)
}

func fireAgentRequest(t *testing.T, handler gin.HandlerFunc, method, path string, body []byte, params gin.Params) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.Request = req
	c.Params = params
	handler(c)
	return rec
}

func TestAgentIdentityHandler_Create_RejectsInvalidJSON(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.Create, http.MethodPost, "/agents", []byte(`{not json`), nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_GetByID_RejectsInvalidUUID(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.GetByID, http.MethodGet, "/agents/not-a-uuid", nil,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_Update_RejectsInvalidUUID(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.Update, http.MethodPut, "/agents/not-a-uuid", []byte(`{}`),
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_Suspend_RejectsInvalidUUID(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.Suspend, http.MethodPost, "/agents/not-a-uuid/suspend", nil,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_Revoke_RejectsInvalidUUID(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.Revoke, http.MethodPost, "/agents/not-a-uuid/revoke", nil,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_RotateCredentials_RejectsInvalidUUID(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.RotateCredentials, http.MethodPost,
		"/agents/not-a-uuid/rotate-credentials", nil,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_GetActivity_RejectsInvalidUUID(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.GetActivity, http.MethodGet,
		"/agents/not-a-uuid/activity", nil,
		gin.Params{{Key: "id", Value: "not-a-uuid"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAgentIdentityHandler_IssueToken_RejectsInvalidJSON(t *testing.T) {
	h := newAgentIdentityTestHandler()
	rec := fireAgentRequest(t, h.IssueToken, http.MethodPost, "/agents/token",
		[]byte(`{not json`), nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
