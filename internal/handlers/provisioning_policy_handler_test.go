// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ProvisioningPolicyHandler relies on route-level RequireAuth +
// RequirePlatformAdmin for the auth gate — the handler itself
// reads no user context. These tests cover the handler's own
// input-validation surface (JSON body parsing). Service-side
// behaviour is covered by the existing PolicyEngine tests.

func TestProvisioningPolicyHandler_EvaluatePolicy_RejectsInvalidJSON(t *testing.T) {
	h := NewProvisioningPolicyHandler(nil, zap.NewNop())
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodPost, "/policy/evaluate",
		bytes.NewReader([]byte(`{"this": "is": invalid`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	h.EvaluatePolicy(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "invalid request body")
}

func TestProvisioningPolicyHandler_EvaluatePolicy_EmptyBody(t *testing.T) {
	// An actually empty stream is EOF, not the valid JSON object {}.
	h := NewProvisioningPolicyHandler(nil, zap.NewNop())
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/policy/evaluate", nil)
	h.EvaluatePolicy(c)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestProvisioningPolicyHandler_ListRules_PanicWithoutEngine(t *testing.T) {
	// Documents the wiring invariant: ListRules unconditionally
	// calls h.engine.ListRules(), so a nil engine surfaces as a
	// runtime panic. Production wiring always provides a non-nil
	// PolicyEngine (constructed in cmd/services.go regardless of
	// optional infra), so this is not a production concern — but
	// the test locks the contract so a future refactor introducing
	// a nil-safe path doesn't silently degrade.
	h := NewProvisioningPolicyHandler(nil, zap.NewNop())
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, _ := http.NewRequest(http.MethodGet, "/policy/rules", nil)
	c.Request = req

	defer func() {
		r := recover()
		assert.NotNil(t, r, "ListRules with nil engine must panic — adding a nil-safe path here would mask a wiring regression")
	}()
	h.ListRules(c)
}
