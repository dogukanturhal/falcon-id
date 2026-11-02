// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/shared/database"
	sharedmiddleware "github.com/dogukanturhal/falcon-id/internal/shared/middleware"
)

// zzReproTestDBURL points at a throwaway local Postgres (schema not
// required -- RLSMiddleware only needs to be able to BEGIN a
// transaction, it never queries a table for a request that carries no
// tenant_id).
//
// Scope of this repro: it exercises the exact sequence of global
// router.Use() calls from applyGlobalMiddleware in cmd/routes.go,
// substituting no-op stand-ins ONLY for the four middlewares that (a)
// require live service/repo wiring to construct and (b) were NOT
// touched by commits 13745b5/1d8e076 (ipFilter, rateLimitMW, apiKeyMW,
// authMiddleware's OptionalAuth, CSRF). Every middleware that WAS
// touched or added by the diff (CorrelationID, RequestLogger,
// Recovery, ErrorHandler, APISecurityHeaders, CORS, ExtractTenant,
// RLSMiddleware) is the real production function.
func TestRLSMiddleware_HealthRouteNot404dWhenMounted(t *testing.T) {
	dbURL := os.Getenv("RLS_MIDDLEWARE_LOCAL_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("RLS_MIDDLEWARE_LOCAL_TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("pool.Ping: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()

	router.Use(middleware.CorrelationID())
	router.Use(middleware.RequestLogger())
	router.Use(sharedmiddleware.Recovery())
	router.Use(sharedmiddleware.ErrorHandler())
	router.Use(sharedmiddleware.APISecurityHeaders(true))
	router.Use(middleware.CORS())
	router.Use(middleware.ExtractTenant())
	// ExtractRealm intentionally omitted: handlers.RealmMiddleware is nil
	// in prod today (REALM_ENABLED unset on the falcon-id Rollout, verified
	// via `kubectl -n falcon-id get pod ... -o jsonpath='{.spec.containers[*].env[*]}'`
	// against a live stable pod), so cmd/routes.go's nil guard means
	// router.Use(handlers.RealmMiddleware.ExtractRealm()) never ran in the
	// actual incident either.
	router.Use(func(c *gin.Context) { c.Next() }) // stand-in: ipFilter.IPFilter() (unchanged by diff)
	router.Use(func(c *gin.Context) { c.Next() }) // stand-in: rateLimitMW.RateLimit() (unchanged by diff)
	router.Use(func(c *gin.Context) { c.Next() }) // stand-in: apiKeyMW.APIKeyAuth() (unchanged by diff)
	router.Use(func(c *gin.Context) { c.Next() }) // stand-in: authMiddleware.OptionalAuth() (unchanged by diff)
	router.Use(func(c *gin.Context) { c.Next() }) // stand-in: CSRFMiddleware.CSRF() (unchanged by diff)
	// The one new piece of production code that DOES mount unconditionally
	// in prod (infra.DB.Pool is always non-nil there): the real RLSMiddleware.
	router.Use(database.RLSMiddleware(pool))

	// Registered AFTER applyGlobalMiddleware, exactly like registerHealthRoutes.
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	t.Logf("GET /health -> %d body=%s", rec.Code, rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /health with RLSMiddleware mounted and no tenant context, got %d: %s", rec.Code, rec.Body.String())
	}
}
