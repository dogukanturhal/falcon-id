// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRLSMiddleware_PanicDoesNotLeakConnection proves that, with the CURRENT (no-defer)
// RLSMiddleware, a downstream handler panic leaves the request's pgx.Tx
// (and its checked-out pool connection) neither committed nor rolled back.
// It does this by driving pool.Stat().AcquiredConns() through a panicking
// request under a pool capped at MaxConns=1: if the connection is properly
// released, a second request can acquire it; if it leaked, the second
// request deadlocks/times out acquiring a connection.
func TestRLSMiddleware_PanicDoesNotLeakConnection(t *testing.T) {
	dbURL := os.Getenv("RLS_MIDDLEWARE_LOCAL_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("RLS_MIDDLEWARE_LOCAL_TEST_DATABASE_URL not set")
	}
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer pool.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	tenantID := uuid.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})
	router.Use(func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	})
	router.Use(RLSMiddleware(pool))
	router.GET("/panics", func(c *gin.Context) {
		panic("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/panics", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	t.Logf("first (panicking) request -> %d", rec.Code)

	stat := pool.Stat()
	t.Logf("pool stat after panic: AcquiredConns=%d TotalConns=%d", stat.AcquiredConns(), stat.TotalConns())
	if stat.AcquiredConns() != 0 {
		t.Errorf("connection leaked after panic: AcquiredConns=%d (want 0) -- the transaction opened by RLSMiddleware was never committed or rolled back", stat.AcquiredConns())
	}
}
