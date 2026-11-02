// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
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

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

type fakeAMRSessions struct{ amr []string }

func (f fakeAMRSessions) GetByID(_ context.Context, id uuid.UUID) (*models.Session, error) {
	return &models.Session{ID: id, AuthMethodsUsed: f.amr}, nil
}
func (f fakeAMRSessions) GetByIDWithRealmContext(ctx context.Context, id, _ uuid.UUID) (*models.Session, error) {
	return f.GetByID(ctx, id)
}

func pfAdmin() *models.CurrentUser {
	return &models.CurrentUser{
		ID: uuid.New(), TenantID: hexxlockTenantID, IsPlatformAdmin: true,
		Roles: []string{"platform_admin"}, SessionID: uuid.New(),
	}
}

func pfMW(flag bool, amr []string) *AuthMiddleware {
	m := NewAuthMiddleware(nil, &config.Config{PlatformAdminRequirePhishingResistantMFA: flag})
	m.SetIdpSessionReader(fakeAMRSessions{amr: amr})
	return m
}

func TestRequirePlatformAdmin_PhishingResistantFlag(t *testing.T) {
	cases := []struct {
		name string
		flag bool
		amr  []string
		code int
	}{
		{"flag off, otp session unchanged", false, []string{"pwd", "otp", "mfa"}, http.StatusOK},
		{"flag on, passkey passes", true, []string{"pwd", "hwk", "mfa"}, http.StatusOK},
		{"flag on, otp denied", true, []string{"pwd", "otp", "mfa"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := runRequest(injectUser(pfAdmin()), pfMW(tc.flag, tc.amr).RequirePlatformAdmin(), okHandler)
			assert.Equal(t, tc.code, w.Code)
			if tc.code == http.StatusForbidden {
				assert.Contains(t, w.Body.String(), ErrCodePhishingResistantMFARequired)
				assert.Contains(t, w.Header().Get("WWW-Authenticate"), "insufficient_user_authentication")
			}
		})
	}
}

func TestRequirePlatformAdmin_FlagOnFailsClosedWithoutSessionReader(t *testing.T) {
	m := NewAuthMiddleware(nil, &config.Config{PlatformAdminRequirePhishingResistantMFA: true})
	w := runRequest(injectUser(pfAdmin()), m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestStepUp_FlagOnRejectsNonPasskeyPlatformAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(amr []string) *httptest.ResponseRecorder {
		repo := new(mockStepUpRepo)
		sid := uuid.New()
		repo.On("HasRecentVerification", mock.Anything, sid, "admin_user_mutation", 5*time.Minute).Return(true, nil).Maybe()
		mw := NewStepUpMiddleware(repo, zap.NewNop())
		mw.SetPhishingResistantPolicy(true, fakeAMRSessions{amr: amr})
		u := pfAdmin()
		u.SessionID = sid
		w := httptest.NewRecorder()
		_, router := gin.CreateTestContext(w)
		router.GET("/p", func(c *gin.Context) { c.Set(CurrentUserKey, u); c.Set("session_id", sid); c.Next() },
			mw.RequireStepUp("admin_user_mutation", 5*time.Minute), okHandler)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/p", nil)
		require.NoError(t, err)
		router.ServeHTTP(w, req)
		return w
	}
	w := run([]string{"pwd", "otp", "mfa"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), ErrCodePhishingResistantMFARequired)
	assert.Equal(t, http.StatusOK, run([]string{"pwd", "mfa", "hwk"}).Code)
}

type errAMRSessions struct{}

func (errAMRSessions) GetByID(context.Context, uuid.UUID) (*models.Session, error) {
	return nil, assert.AnError
}
func (errAMRSessions) GetByIDWithRealmContext(context.Context, uuid.UUID, uuid.UUID) (*models.Session, error) {
	return nil, assert.AnError
}

func TestRequirePlatformAdmin_SessionLookupErrorIs503(t *testing.T) {
	m := NewAuthMiddleware(nil, &config.Config{PlatformAdminRequirePhishingResistantMFA: true})
	m.SetIdpSessionReader(errAMRSessions{})
	w := runRequest(injectUser(pfAdmin()), m.RequirePlatformAdmin(), okHandler)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotContains(t, w.Body.String(), ErrCodePhishingResistantMFARequired)
}
