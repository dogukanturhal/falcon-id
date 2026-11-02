// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== ExtractTenant tests ====================

func TestExtractTenant_ValidHeader_SetsTenantIDInContext(t *testing.T) {
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	var capturedTenantID uuid.UUID
	router.GET("/test", ExtractTenant(), func(c *gin.Context) {
		capturedTenantID = GetTenantID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, tenantID, capturedTenantID)
}

func TestExtractTenant_InvalidUUIDInHeader_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", ExtractTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", "not-a-uuid")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractTenant_MissingHeader_InDevelopment_PassesThrough(t *testing.T) {
	// Ensure we are in development mode (no ENVIRONMENT set)
	_ = os.Unsetenv("ENVIRONMENT")

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	reached := false
	router.GET("/test", ExtractTenant(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached, "handler should be called when tenant header is missing in development")
}

func TestExtractTenant_MissingHeader_InProduction_Returns400ForNonPublicPath(t *testing.T) {
	_ = os.Setenv("ENVIRONMENT", "production")
	defer os.Unsetenv("ENVIRONMENT") //nolint:errcheck

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/users", ExtractTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/users", nil)
	// No X-Tenant-ID header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractTenant_MissingHeader_InProduction_AllowsPublicEndpoints(t *testing.T) {
	_ = os.Setenv("ENVIRONMENT", "production")
	defer os.Unsetenv("ENVIRONMENT") //nolint:errcheck

	publicPaths := []string{
		"/health",
		"/ready",
		"/metrics",
		"/api/auth/login",
		"/api/auth/refresh",
		"/api/auth/logout",
	}

	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, router := gin.CreateTestContext(w)
			reached := false
			router.GET(path, ExtractTenant(), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			// No X-Tenant-ID header
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "public endpoint %s should be allowed without tenant header", path)
			assert.True(t, reached)
		})
	}
}

func TestExtractTenant_MissingHeader_InStaging_Returns400ForNonPublicPath(t *testing.T) {
	_ = os.Setenv("ENVIRONMENT", "staging")
	defer os.Unsetenv("ENVIRONMENT") //nolint:errcheck

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/roles", ExtractTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/roles", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExtractTenant_ValidHeader_TenantIDAccessibleViaGetTenantID(t *testing.T) {
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	var extracted uuid.UUID
	router.GET("/test", ExtractTenant(), func(c *gin.Context) {
		extracted = GetTenantID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, tenantID, extracted)
}

// ==================== RequireTenant tests ====================

func TestRequireTenant_WhenTenantSet_Passes(t *testing.T) {
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(TenantIDKey, tenantID)
	}, RequireTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireTenant_WhenTenantMissing_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", RequireTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRequireTenant_WhenTenantIsWrongType_Returns500(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(TenantIDKey, "not-a-uuid-object") // stored as string, not uuid.UUID
	}, RequireTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==================== GetTenantID tests ====================

func TestGetTenantID_WhenSet_ReturnsTenantID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	expected := uuid.New()
	c.Set(TenantIDKey, expected)

	got := GetTenantID(c)
	assert.Equal(t, expected, got)
}

func TestGetTenantID_WhenNotSet_ReturnsNilUUID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	got := GetTenantID(c)
	assert.Equal(t, uuid.Nil, got)
}

func TestGetTenantID_WhenWrongType_ReturnsNilUUID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(TenantIDKey, 12345) // wrong type

	got := GetTenantID(c)
	assert.Equal(t, uuid.Nil, got)
}

// ==================== ExtractTenant + RequireTenant pipeline ====================

func TestExtractAndRequireTenant_ValidHeader_AllowsRequest(t *testing.T) {
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	var extracted uuid.UUID
	router.GET("/test", ExtractTenant(), RequireTenant(), func(c *gin.Context) {
		extracted = GetTenantID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, tenantID, extracted)
}

func TestExtractAndRequireTenant_NoHeader_InDevelopment_RequireTenantBlocks(t *testing.T) {
	_ = os.Unsetenv("ENVIRONMENT")

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", ExtractTenant(), RequireTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	// ExtractTenant passes in dev mode, RequireTenant blocks because context is missing
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==================== isPublicEndpoint helper ====================

func TestIsPublicEndpoint_HealthPaths(t *testing.T) {
	require.True(t, isPublicEndpoint("/health"))
	require.True(t, isPublicEndpoint("/ready"))
	require.True(t, isPublicEndpoint("/metrics"))
}

func TestIsPublicEndpoint_AuthPaths(t *testing.T) {
	require.True(t, isPublicEndpoint("/api/auth/login"))
	require.True(t, isPublicEndpoint("/api/auth/refresh"))
	require.True(t, isPublicEndpoint("/api/auth/logout"))
	require.True(t, isPublicEndpoint("/api/auth/magic-link"))
	require.True(t, isPublicEndpoint("/api/auth/providers"))
}

func TestIsPublicEndpoint_NonPublicPaths(t *testing.T) {
	require.False(t, isPublicEndpoint("/api/users"))
	require.False(t, isPublicEndpoint("/api/roles"))
	require.False(t, isPublicEndpoint("/api/tenants"))
	require.False(t, isPublicEndpoint("/internal/sync"))
}

// TestIsPublicEndpoint_IAMDevicesInternal verifies the ZTNA device-enrollment
// s2s registry is exempt from X-Tenant-ID. iam_devices is a GLOBAL registry
// (no tenant_id; keyed by device_uuid / ek_pubkey_hash), so the jess
// controller's lookups must not require tenant context — otherwise every
// device-cert attestation fails with "400 Tenant context required". A
// non-iam-devices /internal path stays tenant-required.
func TestIsPublicEndpoint_IAMDevicesInternal(t *testing.T) {
	require.True(t, isPublicEndpoint("/internal/v1/iam-devices/enroll"))
	require.True(t, isPublicEndpoint("/internal/v1/iam-devices/by-ek-hash/"+
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	// Guard: the exemption must not leak to other /internal/v1 routes.
	require.False(t, isPublicEndpoint("/internal/v1/users"))
}

// TestIsPublicEndpoint_InternalTenantsAdminSurface is the regression test
// for the 2026-09-27 orphan_tenant_reap_usercount_check_failed production
// incident: tenant-management's ReapOrphanTenants reconciler called
// GET /internal/v1/tenants/:id/users/count and got 400 "Tenant context
// required" from this global gate before ServiceAuth() or the handler ever
// ran, even with a valid service JWT and a valid tenant UUID path param.
// Every handler in this route group (internal/handlers/tenant_handler.go)
// derives the subject tenant strictly from the :id path param, never from
// TenantIDKey, so exempting the prefix does not re-open header-trust
// authorization — ServiceAuth()'s JWT validation remains the actual gate.
func TestIsPublicEndpoint_InternalTenantsAdminSurface(t *testing.T) {
	require.True(t, isPublicEndpoint("/internal/v1/tenants/"+
		"029a3c7e-0000-0000-0000-000000000000/users/count"))
	require.True(t, isPublicEndpoint("/internal/v1/tenants/"+
		"029a3c7e-0000-0000-0000-000000000000/connection-info"))
	require.True(t, isPublicEndpoint("/internal/v1/tenants/"+
		"029a3c7e-0000-0000-0000-000000000000/smtp-config"))
	// Guard: the exemption is a prefix match requiring the trailing slash,
	// so the bare collection endpoint (POST /internal/v1/tenants,
	// CreateTenant) stays tenant-required, and the exemption must not leak
	// to unrelated /internal/v1 routes.
	require.False(t, isPublicEndpoint("/internal/v1/tenants"))
	require.False(t, isPublicEndpoint("/internal/v1/users"))
}

// ==================== RFC 8414 / OIDC Discovery public-path tests ====================

// TestIsPublicEndpoint_WellKnownPaths verifies that all /.well-known/* paths bypass
// the tenant middleware. Per RFC 8414 §3 and OpenID Connect Discovery 1.0 §4, the
// discovery document and JWKS endpoints MUST be reachable without any authentication
// or additional headers. Blocking them breaks every OIDC client (Backstage, ArgoCD,
// Grafana, Atlantis, Harbor, SonarQube, …).
func TestIsPublicEndpoint_WellKnownPaths(t *testing.T) {
	wellKnownPaths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/.well-known/platform-jwks.json",
		"/.well-known/oauth-authorization-server",
		"/.well-known/ssf-configuration",
	}
	for _, path := range wellKnownPaths {
		t.Run(path, func(t *testing.T) {
			require.True(t, isPublicEndpoint(path),
				"RFC 8414: %s must be publicly reachable without X-Tenant-ID", path)
		})
	}
}

// TestExtractTenant_WellKnownPaths_NoTenantHeader_Production verifies that the full
// ExtractTenant middleware returns 200 for /.well-known/* even in production mode
// and without an X-Tenant-ID header. This is the integration-level regression test
// for the OIDC discovery bug: curl https://auth.hexxlock.com/.well-known/openid-configuration
// must return 200, not 400 "Tenant context required".
func TestExtractTenant_WellKnownPaths_NoTenantHeader_Production(t *testing.T) {
	_ = os.Setenv("ENVIRONMENT", "production")
	defer os.Unsetenv("ENVIRONMENT") //nolint:errcheck

	discoveryPaths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/.well-known/platform-jwks.json",
		"/.well-known/oauth-authorization-server",
	}

	for _, path := range discoveryPaths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, router := gin.CreateTestContext(w)
			reached := false
			router.GET(path, ExtractTenant(), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			// Deliberately no X-Tenant-ID header — simulates OIDC client discovery.
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code,
				"OIDC discovery path %s must return 200 without X-Tenant-ID (RFC 8414)", path)
			assert.True(t, reached, "handler must be invoked for %s", path)
		})
	}
}

// TestIsPublicEndpoint_PermissionRegistration verifies the service-level
// module registration route (what platform-shared permissions.Client calls)
// is exempt from X-Tenant-ID, while sibling permission routes stay
// tenant-required.
func TestIsPublicEndpoint_PermissionRegistration(t *testing.T) {
	require.True(t, isPublicEndpoint("/internal/v1/permissions/register"))
	require.True(t, isPublicEndpoint("/internal/permissions/register"))

	require.False(t, isPublicEndpoint("/internal/v1/permissions"))
	require.False(t, isPublicEndpoint("/internal/v1/permissions/other"))
	require.False(t, isPublicEndpoint("/api/permissions/register"))
	require.False(t, isPublicEndpoint("/api/v1/permissions/register"))
}

// TestPermissionRegistration_ProductionNoTenantHeader exercises the real
// middleware chain in production: the registration route reaches ServiceAuth
// without X-Tenant-ID (and rejects a caller with no service credential with
// 401, not the tenant 400), while a sibling /internal/v1 route without the
// header is still stopped by the tenant gate.
func TestPermissionRegistration_ProductionNoTenantHeader(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	gin.SetMode(gin.TestMode)

	svc := NewServiceAuthMiddleware(nil, "legacy-key")
	router := gin.New()
	router.Use(ExtractTenant())
	g := router.Group("/internal/v1")
	g.POST("/permissions/register", svc.ServiceAuth(), func(c *gin.Context) { c.Status(http.StatusOK) })
	g.POST("/permissions/other", svc.ServiceAuth(), func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(path, internalKey string) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil)
		if internalKey != "" {
			req.Header.Set("X-Internal-Key", internalKey)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	require.Equal(t, http.StatusOK, do("/internal/v1/permissions/register", "legacy-key"))
	require.Equal(t, http.StatusUnauthorized, do("/internal/v1/permissions/register", ""))
	require.Equal(t, http.StatusBadRequest, do("/internal/v1/permissions/other", "legacy-key"))
}
