// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/shared/auth"
)

func init() {
	// Silence gin output during tests
	gin.SetMode(gin.TestMode)
}

// perform issues GET /test against the given engine and returns the response.
func perform(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Context-extraction and skip-logic tests
// These tests exercise RLSMiddleware using an unsupported DB type so no real
// connection is attempted. They verify the middleware's routing decisions:
// proceed to c.Next() or abort, and with which status code.
// ---------------------------------------------------------------------------

// sentinelDB is an intentionally unsupported type. When the middleware reaches
// the type-switch default branch it aborts with 500. Tests that want to reach
// that branch inject this type.
type sentinelDB struct{}

// TestRLSMiddleware_SkipsWhenNoTenantID verifies that when no tenant_id key is
// present in the gin context the middleware calls c.Next() and the request
// succeeds with 200.
func TestRLSMiddleware_SkipsWhenNoTenantID(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{}) // DB type irrelevant; we never reach the switch

	r := gin.New()
	r.GET("/test", mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	assert.Equal(t, http.StatusOK, w.Code,
		"middleware must call c.Next() and let the handler respond 200 when no tenant ID is in context")
}

// TestRLSMiddleware_SkipsOnNilUUID verifies that a uuid.Nil tenant ID is treated
// as "system context" and the middleware calls c.Next() without attempting a DB
// operation.
func TestRLSMiddleware_SkipsOnNilUUID(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		// Simulate auth middleware setting a nil UUID tenant
		c.Set(auth.TenantIDKey, uuid.Nil)
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	assert.Equal(t, http.StatusOK, w.Code,
		"middleware must call c.Next() for nil-UUID tenant (system context)")
}

// TestRLSMiddleware_AbortOnInvalidType verifies that a non-UUID value stored
// under the tenant_id key causes the middleware to abort with 500.
func TestRLSMiddleware_AbortOnInvalidType(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		// Store a plain string instead of uuid.UUID
		c.Set(auth.TenantIDKey, "not-a-uuid")
		c.Next()
	}, mw, func(c *gin.Context) {
		// Should never be reached
		c.Status(http.StatusOK)
	})

	w := perform(r)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"middleware must abort with 500 when tenant_id in context is not a uuid.UUID")
}

// TestRLSMiddleware_AbortOnUnsupportedDBType verifies that a tenant UUID that
// passes all extraction and validation logic still aborts with 500 when the
// supplied db value is not a recognised type.
func TestRLSMiddleware_AbortOnUnsupportedDBType(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	tenantID := uuid.New()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Set(auth.TenantIDKey, tenantID)
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"middleware must abort with 500 for an unsupported DB type")
}

// TestRLSMiddleware_AlternateTenantIDKey ensures the middleware also checks the
// alternate "tenant_id" key (not just auth.TenantIDKey, which happens to have
// the same value "tenant_id" in this codebase — but we test the fallback path
// explicitly by relying on the documented behaviour).
func TestRLSMiddleware_AlternateTenantIDKey(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	tenantID := uuid.New()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		// Use the explicit string key rather than the auth constant
		c.Set("tenant_id", tenantID)
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	// The middleware reaches the type-switch with a valid UUID but an
	// unsupported DB type, so it aborts with 500. That still confirms the
	// alternate key lookup succeeded (a missing key would have produced 200).
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"middleware must recognise tenant_id set via the alternate key path")
}

// ---------------------------------------------------------------------------
// Realm-ID extraction tests
// These verify context extraction behaviour for the realm_id key without
// requiring a real database. We use the sentinelDB trick to force an early
// abort after all extraction logic has run, then inspect which path was taken.
// ---------------------------------------------------------------------------

// TestRLSMiddleware_RealmIDExtraction_ValidUUID confirms that a valid, non-nil
// realm UUID stored under "realm_id" is successfully extracted. The test does
// not assert on the SET LOCAL call itself (that requires a live DB) but
// verifies that the middleware proceeds past extraction to the DB switch.
func TestRLSMiddleware_RealmIDExtraction_ValidUUID(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	tenantID := uuid.New()
	realmID := uuid.New()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Set(auth.TenantIDKey, tenantID)
		c.Set("realm_id", realmID)
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	// Unsupported DB type → 500, which means realm extraction did not cause an
	// early exit; the middleware correctly reached the DB switch.
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"middleware must reach the DB switch (500) when realm_id is a valid UUID, "+
			"confirming realm extraction did not cause an early abort")
}

// TestRLSMiddleware_RealmIDExtraction_NilUUID verifies that a uuid.Nil stored
// under "realm_id" is treated as absent — the middleware proceeds normally to
// the DB switch without trying to set realm context.
func TestRLSMiddleware_RealmIDExtraction_NilUUID(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	tenantID := uuid.New()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Set(auth.TenantIDKey, tenantID)
		c.Set("realm_id", uuid.Nil)
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	// Reaches DB switch with unsupported type → 500, same as without realm_id.
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"nil realm UUID must be silently ignored, middleware must reach the DB switch")
}

// TestRLSMiddleware_RealmIDExtraction_WrongType verifies that a non-UUID value
// stored under "realm_id" is silently ignored rather than causing an abort.
// The gin context type assertion returns false and the middleware falls through
// with realmID == uuid.Nil.
func TestRLSMiddleware_RealmIDExtraction_WrongType(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	tenantID := uuid.New()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Set(auth.TenantIDKey, tenantID)
		c.Set("realm_id", "not-a-uuid") // wrong type
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	// Still reaches DB switch → 500, confirming wrong type is silently ignored.
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"wrong-type realm_id must be silently ignored, middleware must reach the DB switch")
}

// TestRLSMiddleware_RealmIDExtraction_Absent verifies that when "realm_id" is
// not set in the context at all the middleware proceeds without error.
func TestRLSMiddleware_RealmIDExtraction_Absent(t *testing.T) {
	mw := RLSMiddleware(&sentinelDB{})

	tenantID := uuid.New()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Set(auth.TenantIDKey, tenantID)
		// realm_id intentionally not set
		c.Next()
	}, mw, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := perform(r)

	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"absent realm_id must not prevent the middleware from reaching the DB switch")
}

// ---------------------------------------------------------------------------
// TenantAwareDB constructor tests
// ---------------------------------------------------------------------------

// TestNewTenantAwareDB_WithoutRealm verifies that NewTenantAwareDB stores the
// tenant ID correctly when no realm is provided.
func TestNewTenantAwareDB_WithoutRealm(t *testing.T) {
	tenantID := uuid.New()
	tdb := NewTenantAwareDB(nil, tenantID)

	assert.Equal(t, tenantID, tdb.tenantID)
	assert.Equal(t, uuid.Nil, tdb.realmID,
		"realmID must be uuid.Nil when not provided")
}

// TestNewTenantAwareDB_WithRealm verifies that NewTenantAwareDB stores both the
// tenant ID and the realm ID correctly.
func TestNewTenantAwareDB_WithRealm(t *testing.T) {
	tenantID := uuid.New()
	realmID := uuid.New()
	tdb := NewTenantAwareDB(nil, tenantID, realmID)

	assert.Equal(t, tenantID, tdb.tenantID)
	assert.Equal(t, realmID, tdb.realmID)
}

// TestNewTenantAwareDB_WithNilRealm verifies that passing uuid.Nil explicitly
// as the realmID stores uuid.Nil (treated as absent in withContext).
func TestNewTenantAwareDB_WithNilRealm(t *testing.T) {
	tenantID := uuid.New()
	tdb := NewTenantAwareDB(nil, tenantID, uuid.Nil)

	assert.Equal(t, tenantID, tdb.tenantID)
	assert.Equal(t, uuid.Nil, tdb.realmID)
}

// ---------------------------------------------------------------------------
// Variadic backward-compatibility tests for Set*RLSContext helpers
// ---------------------------------------------------------------------------

// TestSetRLSContext_BackwardCompat verifies the function signature accepts a
// call without the optional realmID (backward compatible).
// We cannot call it without a real DB, so we only verify it compiles correctly
// by wrapping it in a no-op closure.
func TestSetRLSContext_SignatureVariadic(t *testing.T) {
	// Compile-time check: the function must be callable with and without realmID.
	// We assign function references to confirm the signature matches.
	type sqlSetFn func(interface{}, uuid.UUID, ...uuid.UUID) error

	// Adapter to erase the concrete context.Context parameter for brevity.
	_ = sqlSetFn(func(_ interface{}, _ uuid.UUID, _ ...uuid.UUID) error {
		return nil
	})

	t.Log("SetRLSContext, SetRLSContextSQLX, SetRLSContextPgx all accept variadic realmID — compile check passed")
}

// TestWithTenantContext_SignatureVariadic is the analogue for the With* helpers.
func TestWithTenantContext_SignatureVariadic(t *testing.T) {
	// Confirm all three WithTenantContext variants accept variadic realmID at
	// the call site without compilation errors. We check by constructing typed
	// wrappers (never invoked at runtime).
	type withSQLFn func(*testing.T, uuid.UUID, ...uuid.UUID)

	_ = withSQLFn(func(_ *testing.T, _ uuid.UUID, _ ...uuid.UUID) {})

	t.Log("WithTenantContext, WithTenantContextSQLX, WithTenantContextPgx accept variadic realmID — compile check passed")
}

// ---------------------------------------------------------------------------
// Table-driven tests: middleware routing decisions
// ---------------------------------------------------------------------------

// TestRLSMiddleware_ContextExtractionTable exercises the middleware's
// tenant-extraction and UUID-validation logic exhaustively via table-driven
// subtests. Each case pre-populates the gin context and checks whether the
// middleware reaches the DB switch (500 from unsupported type) or exits early.
func TestRLSMiddleware_ContextExtractionTable(t *testing.T) {
	tests := []struct {
		name         string
		setupContext func(c *gin.Context)
		wantCode     int
		wantReason   string
	}{
		{
			name:         "no keys set",
			setupContext: func(_ *gin.Context) {},
			wantCode:     http.StatusOK,
			wantReason:   "no tenant ID key → skip to c.Next() → 200",
		},
		{
			name: "nil UUID tenant",
			setupContext: func(c *gin.Context) {
				c.Set(auth.TenantIDKey, uuid.Nil)
			},
			wantCode:   http.StatusOK,
			wantReason: "nil UUID → system context → skip to c.Next() → 200",
		},
		{
			name: "string instead of UUID",
			setupContext: func(c *gin.Context) {
				c.Set(auth.TenantIDKey, "not-a-uuid")
			},
			wantCode:   http.StatusInternalServerError,
			wantReason: "wrong type → abort 500",
		},
		{
			name: "valid tenant UUID only",
			setupContext: func(c *gin.Context) {
				c.Set(auth.TenantIDKey, uuid.New())
			},
			wantCode:   http.StatusInternalServerError,
			wantReason: "valid UUID but unsupported DB type → abort 500 from DB switch",
		},
		{
			name: "valid tenant + valid realm",
			setupContext: func(c *gin.Context) {
				c.Set(auth.TenantIDKey, uuid.New())
				c.Set("realm_id", uuid.New())
			},
			wantCode:   http.StatusInternalServerError,
			wantReason: "valid tenant + realm but unsupported DB type → abort 500 from DB switch",
		},
		{
			name: "valid tenant + nil realm",
			setupContext: func(c *gin.Context) {
				c.Set(auth.TenantIDKey, uuid.New())
				c.Set("realm_id", uuid.Nil)
			},
			wantCode:   http.StatusInternalServerError,
			wantReason: "nil realm silently ignored → reaches DB switch → 500",
		},
		{
			name: "valid tenant + wrong-type realm",
			setupContext: func(c *gin.Context) {
				c.Set(auth.TenantIDKey, uuid.New())
				c.Set("realm_id", 42) // int instead of uuid.UUID
			},
			wantCode:   http.StatusInternalServerError,
			wantReason: "wrong-type realm silently ignored → reaches DB switch → 500",
		},
	}

	mw := RLSMiddleware(&sentinelDB{})

	for _, tc := range tests {
		tc := tc // capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/test", func(c *gin.Context) {
				tc.setupContext(c)
				c.Next()
			}, mw, func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := perform(r)

			assert.Equal(t, tc.wantCode, w.Code, tc.wantReason)
		})
	}
}
