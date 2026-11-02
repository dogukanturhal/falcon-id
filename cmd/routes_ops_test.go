// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/dogukanturhal/platform-shared/operatorauth"

	"github.com/dogukanturhal/falcon-id/internal/handlers"
	"github.com/dogukanturhal/falcon-id/internal/opsconsole"
)

// The operator-chain routes must register without gin route conflicts, and
// every one must sit behind ServiceAuth + RequireScope + RequireOperator: with
// no service credential or assertion they answer 401/403, never reach a
// handler.
func TestOpsConsoleRoutesRegisterAndAreGuarded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verifier, err := operatorauth.NewVerifier(operatorauth.Config{JWKSURL: "http://127.0.0.1:1/jwks", Issuer: "https://id.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Handlers are nil pointers: method values on them are fine to take, and a
	// guarded route must never call them.
	hs := &Handlers{
		Admin:              (*handlers.AdminHandler)(nil),
		Impersonation:      (*handlers.ImpersonationHandler)(nil),
		PlatformJIT:        (*handlers.PlatformJITHandler)(nil),
		PlatformManagement: (*handlers.PlatformManagementHandler)(nil),
		Ops:                opsconsole.New(opsconsole.Deps{Verifier: verifier}),
	}
	deny := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no_service_token"})
	}
	r := gin.New()
	registerOpsConsoleRoutes(r.Group("/internal/v1"), hs, deny)

	routes := r.Routes()
	if len(routes) < 40 {
		t.Fatalf("expected the full ops surface, got %d routes", len(routes))
	}
	for _, rt := range routes {
		req := httptest.NewRequest(rt.Method, rt.Path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s reachable without credentials: %d", rt.Method, rt.Path, w.Code)
		}
	}
}

func TestOpsConsoleRoutesAbsentWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerOpsConsoleRoutes(r.Group("/internal/v1"), &Handlers{}, func(c *gin.Context) {})
	if len(r.Routes()) != 0 {
		t.Fatal("routes mounted without a Console")
	}
}
