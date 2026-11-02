// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

type witnessRouteStub struct{ hit int }

func (s *witnessRouteStub) BeginTOTP(context.Context, *models.CurrentUser, string, string, string, string) (string, time.Duration, error) {
	s.hit++
	return "abc", time.Second, nil
}

func (s *witnessRouteStub) FinishTOTP(context.Context, *models.CurrentUser, string, string, string, string, string) (*services.FinishTOTPResult, error) {
	s.hit++
	return nil, &services.WitnessError{Status: http.StatusTeapot, Code: "stub", Message: "stub"}
}

func (s *witnessRouteStub) Status(context.Context, *models.CurrentUser) services.WitnessTOTPStatus {
	return services.WitnessTOTPStatus{}
}

func witnessRouteEngine(user *models.CurrentUser, stub *witnessRouteStub) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/auth")
	g.Use(func(c *gin.Context) {
		c.Set(middleware.CurrentUserKey, user)
		c.Set("session_id", uuid.New())
		c.Next()
	})
	h := &Handlers{
		WebAuthn:    &handlers.WebAuthnHandler{},
		WitnessTOTP: handlers.NewWitnessTOTPHandler(stub, zap.NewNop()),
	}
	registerWitnessRoutes(g, h, (&middleware.AuthMiddleware{}).RequirePlatformAdmin())
	return r
}

// TestWitnessAPIRoutes_RequirePlatformAdmin pins the P0 fix: the /witness/*
// API routes used to require login only, so any signed-in user could mint a
// witness for an arbitrary device. Non-admins must be refused before any
// handler runs, on all four routes.
func TestWitnessAPIRoutes_RequirePlatformAdmin(t *testing.T) {
	tenantUser := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.New(), IsPlatformAdmin: false}
	internalNonAdmin := &models.CurrentUser{ID: uuid.New(), TenantID: uuid.MustParse(models.HexxlockInternalTenantID)}
	for name, u := range map[string]*models.CurrentUser{"regular user": tenantUser, "internal non-admin": internalNonAdmin} {
		for _, path := range []string{
			"/api/v1/auth/webauthn/witness/begin",
			"/api/v1/auth/webauthn/witness/finish",
			"/api/v1/auth/witness/totp/begin",
			"/api/v1/auth/witness/totp/finish",
		} {
			stub := &witnessRouteStub{}
			w := httptest.NewRecorder()
			witnessRouteEngine(u, stub).ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
			require.Equal(t, http.StatusForbidden, w.Code, "%s -> %s", name, path)
			require.Zero(t, stub.hit, "handler must not run for %s on %s", name, path)
		}
	}
}

func TestWitnessTOTPRoutes_PlatformAdminReachesHandler(t *testing.T) {
	admin := &models.CurrentUser{
		ID: uuid.New(), TenantID: uuid.MustParse(models.HexxlockInternalTenantID),
		IsPlatformAdmin: true, Roles: []string{"platform_admin"}, PlatformAuthorityVerified: true,
	}
	stub := &witnessRouteStub{}
	w := httptest.NewRecorder()
	body := `{"device_uuid":"33333333-3333-3333-3333-333333333333","ek_pubkey_hash":"` + strings.Repeat("a", 64) + `"}`
	witnessRouteEngine(admin, stub).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/witness/totp/begin", strings.NewReader(body)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, stub.hit)
}
