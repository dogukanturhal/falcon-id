// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/services"
)

func TestRespondIfTenantSuspended(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Wrapped the way Login / CompleteMFALogin / SSO callbacks wrap it.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	require.True(t, respondIfTenantSuspended(c, fmt.Errorf("check user status: %w", services.ErrTenantSuspended)))
	assert.Equal(t, http.StatusForbidden, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "tenant_suspended", body["error"])

	// Anything else is left to the caller.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	assert.False(t, respondIfTenantSuspended(c2, errors.New("boom")))
	assert.False(t, respondIfTenantSuspended(c2, nil))
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Empty(t, w2.Body.String())
}
