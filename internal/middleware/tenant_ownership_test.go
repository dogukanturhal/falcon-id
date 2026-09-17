// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// makeUser builds a CurrentUser for a specific tenant.
func makeUser(tenantID uuid.UUID, roles ...string) *models.CurrentUser {
	return &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: tenantID,
		Username: "testuser",
		Roles:    roles,
	}
}

// ==================== ValidateTenantOwnership tests ====================

func TestValidateTenantOwnership_MatchingTenantHeader_Allowed(t *testing.T) {
	tenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(tenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_DifferentTenantHeader_Returns403(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestValidateTenantOwnership_PlatformAdminRole_AllowsCrossTenant(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		// platform_admin role should bypass tenant ownership check
		c.Set(CurrentUserKey, makeUser(userTenantID, "platform_admin"))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_SuperAdminRole_AllowsCrossTenant(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID, "super_admin"))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_IsPlatformAdminContextFlag_AllowsCrossTenant(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID)) // no admin role
		c.Set("is_platform_admin", true)              // but flag is set
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_NoUser_PassesThrough(t *testing.T) {
	// No authenticated user means no tenant to enforce, let RequireAuth deal with it
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	reached := false
	router.GET("/api/resources", m.ValidateTenantOwnership(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", uuid.New().String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached, "should pass through when there is no authenticated user")
}

func TestValidateTenantOwnership_SkipsMethods_OPTIONS(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.OPTIONS("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodOptions, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	// OPTIONS is in SkipMethods by default, so it should pass through even with mismatched tenant
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_SkipsPaths_Health(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/health", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_SkipsPaths_AuthPrefix(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.POST("/api/auth/login", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_URLPathTenantParam_Matching_Allowed(t *testing.T) {
	tenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/tenants/:tenant_id/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(tenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/tenants/"+tenantID.String()+"/resources", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_URLPathTenantParam_Mismatched_Returns403(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/tenants/:tenant_id/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/tenants/"+otherTenantID.String()+"/resources", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestValidateTenantOwnership_URLPathTenantParam_PlatformAdmin_Allowed(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/tenants/:tenant_id/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID, "platform_admin"))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/tenants/"+otherTenantID.String()+"/resources", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_QueryParamTenantID_Mismatched_Returns403(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources?tenant_id="+otherTenantID.String(), nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestValidateTenantOwnership_QueryParamTenantID_Matching_Allowed(t *testing.T) {
	tenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(tenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources?tenant_id="+tenantID.String(), nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_SetsValidatedTenantIDInContext(t *testing.T) {
	tenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	var validatedTenantID interface{}
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(tenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		validatedTenantID, _ = c.Get("validated_tenant_id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	router.ServeHTTP(w, req)

	require.NotNil(t, validatedTenantID)
	assert.Equal(t, tenantID, validatedTenantID.(uuid.UUID))
}

func TestValidateTenantOwnership_AllowCrossTenantConfig_OverridesCheck(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()

	cfg := DefaultTenantOwnershipConfig()
	cfg.AllowCrossTenantAccess = true
	m := NewTenantOwnershipMiddlewareWithConfig(cfg)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateTenantOwnership_TenantFromContextDirectly_Respected(t *testing.T) {
	tenantID := uuid.New()
	otherTenantID := uuid.New()
	m := NewTenantOwnershipMiddleware()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/api/resources", func(c *gin.Context) {
		// Set tenant_id directly without CurrentUser (another middleware pattern)
		c.Set("tenant_id", tenantID)
	}, m.ValidateTenantOwnership(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/resources", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ==================== RequireSameTenant tests ====================

func TestRequireSameTenant_SameTenant_Allowed(t *testing.T) {
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(tenantID))
	}, RequireSameTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", tenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireSameTenant_DifferentTenant_Returns403(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID))
	}, RequireSameTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireSameTenant_PlatformAdmin_AllowsCrossTenant(t *testing.T) {
	userTenantID := uuid.New()
	otherTenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(userTenantID, "platform_admin"))
	}, RequireSameTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", otherTenantID.String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireSameTenant_NoHeader_PassesThrough(t *testing.T) {
	// No X-Tenant-ID header means no explicit tenant to validate
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	reached := false
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(tenantID))
	}, RequireSameTenant(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached)
}

func TestRequireSameTenant_NoUser_Returns401(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", RequireSameTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", uuid.New().String())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireSameTenant_InvalidTenantIDHeader_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, makeUser(uuid.New()))
	}, RequireSameTenant(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant-ID", "not-a-valid-uuid")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==================== ValidateResourceTenantOwnership tests ====================

func TestValidateResourceTenantOwnership_SameTenant_ReturnsTrue(t *testing.T) {
	tenantID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(CurrentUserKey, makeUser(tenantID))

	result := ValidateResourceTenantOwnership(c, tenantID)
	assert.True(t, result)
}

func TestValidateResourceTenantOwnership_DifferentTenant_ReturnsFalse(t *testing.T) {
	userTenantID := uuid.New()
	resourceTenantID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(CurrentUserKey, makeUser(userTenantID))

	result := ValidateResourceTenantOwnership(c, resourceTenantID)
	assert.False(t, result)
}

func TestValidateResourceTenantOwnership_PlatformAdmin_ReturnsTrue(t *testing.T) {
	userTenantID := uuid.New()
	resourceTenantID := uuid.New()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set(CurrentUserKey, makeUser(userTenantID, "platform_admin"))

	result := ValidateResourceTenantOwnership(c, resourceTenantID)
	assert.True(t, result)
}

func TestValidateResourceTenantOwnership_NoUser_ReturnsFalse(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	result := ValidateResourceTenantOwnership(c, uuid.New())
	assert.False(t, result)
}

// ==================== DefaultTenantOwnershipConfig ====================

func TestDefaultTenantOwnershipConfig_HasSensibleDefaults(t *testing.T) {
	cfg := DefaultTenantOwnershipConfig()

	assert.False(t, cfg.AllowCrossTenantAccess)
	assert.Equal(t, "id", cfg.ResourceIDParam)
	assert.Contains(t, cfg.SkipMethods, "OPTIONS")
	assert.NotEmpty(t, cfg.SkipPaths)

	// Verify default skip paths include common internal/public routes
	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}
	assert.True(t, skipPathMap["/health"])
	assert.True(t, skipPathMap["/api/auth/"])
	assert.True(t, skipPathMap["/internal/"])
}
