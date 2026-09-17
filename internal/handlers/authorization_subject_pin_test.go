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

// Regression cover for the Broken Object Level Authorization fix on
// /api/v1/authorize and /api/v1/authorize/batch.
//
// Both request models carry a client-supplied userId/tenantId, and both the
// handler and AuthorizationService previously passed them straight to the
// permission engine behind RequireAuth() with no permission gate — so any
// authenticated caller could enumerate any user's permissions in any tenant.
//
// NOTE ON EXISTING COVERAGE: authorization_handler_test.go now exercises the
// real AuthorizationHandler.Authorize/AuthorizeBatch (via the
// authorizationServiceAPI interface AuthorizationHandler now depends on,
// instead of a concrete *services.AuthorizationService), including a
// cross-subject 403 case. This file additionally tests pinSubjectToSession's
// decision table directly and in isolation, which is where the security
// decision actually lives.
func pinTestContext(t *testing.T, current *models.CurrentUser) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/authorize/batch", nil)
	if current != nil {
		c.Set(middleware.CurrentUserKey, current)
	}
	return c, rec
}

func TestPinSubjectToSession(t *testing.T) {
	callerID := uuid.New()
	callerTenant := uuid.New()
	caller := &models.CurrentUser{ID: callerID, TenantID: callerTenant, Username: "caller"}

	t.Run("unauthenticated is rejected", func(t *testing.T) {
		c, rec := pinTestContext(t, nil)
		userID, tenantID := uuid.New(), uuid.New()
		require.False(t, pinSubjectToSession(c, &userID, &tenantID))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("another user's subject is refused, not silently answered", func(t *testing.T) {
		c, rec := pinTestContext(t, caller)
		victim, tenantID := uuid.New(), callerTenant
		require.False(t, pinSubjectToSession(c, &victim, &tenantID))
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("another tenant is refused", func(t *testing.T) {
		c, rec := pinTestContext(t, caller)
		userID, otherTenant := callerID, uuid.New()
		require.False(t, pinSubjectToSession(c, &userID, &otherTenant))
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("caller asking about itself is allowed", func(t *testing.T) {
		c, rec := pinTestContext(t, caller)
		userID, tenantID := callerID, callerTenant
		require.True(t, pinSubjectToSession(c, &userID, &tenantID))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, callerID, userID)
		assert.Equal(t, callerTenant, tenantID)
	})

	t.Run("omitted ids are filled from the session, never left zero", func(t *testing.T) {
		c, _ := pinTestContext(t, caller)
		var userID, tenantID uuid.UUID
		require.True(t, pinSubjectToSession(c, &userID, &tenantID))
		assert.Equal(t, callerID, userID, "subject must come from the token, not the body")
		assert.Equal(t, callerTenant, tenantID)
	})
}
