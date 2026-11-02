// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration
// +build integration

// This file exercises RLSMiddleware through an ACTUAL HTTP request (gin's
// httptest, not a direct function call) against a real Postgres connection,
// asserting that current_setting('app.current_tenant_id', true) is
// populated INSIDE the transaction the handler observes -- i.e. that the
// GUC genuinely took effect on the request's own transaction, not merely
// that RLSMiddleware ran without erroring.
//
// It carries a negative control
// (TestRLSMiddleware_LiveRequest_NegativeControl_MiddlewareAbsent) that
// builds the identical router MINUS RLSMiddleware and asserts the GUC comes
// back unset. Without this control, a test that always observed a
// populated GUC (e.g. because of a stale connection-pool leak, or because
// the assertion itself is vacuous) would pass for the wrong reason.
//
// Run with:
//
//	DATABASE_URL=postgres://... go test -tags=integration ./internal/shared/database/... -run TestRLSMiddleware_LiveRequest
package database_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/shared/database"
)

// gucResponse is what the stub handler reports back about what it observed
// on ITS OWN transaction (the one RLSMiddleware stashed in gin context, if
// any) — never queried on a separate connection, which would prove nothing
// about whether the request's own transaction actually carries the GUC.
type gucResponse struct {
	TenantSetting string `json:"tenant_setting"`
	HadTx         bool   `json:"had_tx"`
}

func TestRLSMiddleware_LiveRequest_GUCPopulatedOnHandlerTransaction(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping live-request integration test")
	}
	pool := getTestDB(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	tenantID := uuid.New()

	// Simulate the ordering of the real middleware chain: something upstream
	// of RLSMiddleware (ExtractTenant / OptionalAuth in the real chain) has
	// already resolved and stored tenant_id in gin context by the time
	// RLSMiddleware runs.
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})
	router.Use(database.RLSMiddleware(pool))
	router.GET("/probe", func(c *gin.Context) {
		txVal, exists := c.Get("pgx_tx")
		require.True(t, exists, "RLSMiddleware did not stash pgx_tx in gin context on a live request")
		tx, ok := txVal.(pgx.Tx)
		require.True(t, ok, "pgx_tx context value is not a pgx.Tx")

		var actual string
		err := tx.QueryRow(c.Request.Context(),
			"SELECT current_setting('app.current_tenant_id', true)").Scan(&actual)
		require.NoError(t, err)
		c.JSON(http.StatusOK, gucResponse{TenantSetting: actual, HadTx: true})
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "unexpected status; body: %s", rec.Body.String())
	var resp gucResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.True(t, resp.HadTx, "handler observed no request-scoped transaction")
	require.Equal(t, tenantID.String(), resp.TenantSetting,
		"current_setting('app.current_tenant_id', true) inside the handler's own transaction did not match the tenant_id set upstream of RLSMiddleware")
}

// TestRLSMiddleware_LiveRequest_NegativeControl_MiddlewareAbsent builds the
// identical router MINUS database.RLSMiddleware and asserts the handler
// sees no transaction and no GUC at all. If this control ever observes a
// populated GUC, the positive test above is not measuring what it claims to
// measure (e.g. a shared/leaked connection, or a stale role-level default),
// and both must be treated as broken.
func TestRLSMiddleware_LiveRequest_NegativeControl_MiddlewareAbsent(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping live-request integration test")
	}
	pool := getTestDB(t)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	tenantID := uuid.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})
	// Deliberately NOT registering database.RLSMiddleware(pool) here.
	router.GET("/probe", func(c *gin.Context) {
		_, exists := c.Get("pgx_tx")
		if exists {
			c.JSON(http.StatusOK, gucResponse{TenantSetting: "unexpected-tx-present", HadTx: true})
			return
		}
		// No request-scoped transaction was established. Confirm, on a
		// throwaway connection from the same pool, that the GUC is indeed
		// unset at the session/pool level too -- i.e. nothing upstream
		// accidentally set it some other way. current_setting(..., true)
		// returns SQL NULL (not empty string) when the GUC has never been
		// set on this backend, so this must scan into a nullable type.
		var actual sql.NullString
		err := pool.QueryRow(c.Request.Context(),
			"SELECT current_setting('app.current_tenant_id', true)").Scan(&actual)
		require.NoError(t, err)
		c.JSON(http.StatusOK, gucResponse{TenantSetting: actual.String, HadTx: false})
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp gucResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.False(t, resp.HadTx, "no RLSMiddleware was registered, but a request-scoped transaction was present anyway")
	require.Empty(t, resp.TenantSetting,
		"negative control: with RLSMiddleware removed, app.current_tenant_id must be unset, got %q", resp.TenantSetting)
}
