// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

func init() {
	// Initialize a no-op logger for tests to prevent nil pointer panics
	logger.Log, _ = zap.NewDevelopment()
}

func TestRequireTenantScopedAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test tenant IDs
	tenantA := uuid.New()
	tenantB := uuid.New()
	hexxlockInternal, _ := uuid.Parse(models.HexxlockInternalTenantID)

	tests := []struct {
		name               string
		user               *models.CurrentUser
		tenantParamName    string
		urlParam           string
		queryParam         string
		bodyParam          string
		expectedStatusCode int
		expectedError      string
	}{
		{
			name: "Platform admin can access any tenant",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        hexxlockInternal,
				Username:        "platform-admin",
				Roles:           []string{"platform_admin"},
				IsPlatformAdmin: true,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "Tenant admin can access own tenant via URL param",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "tenant-admin",
				Roles:           []string{"admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "Tenant admin CANNOT access different tenant (CVE-HEXX-IAM-001)",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "tenant-admin",
				Roles:           []string{"admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantB.String(), // Different tenant
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "Access denied: tenant mismatch",
		},
		{
			name: "User without admin role is denied",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "regular-user",
				Roles:           []string{"user"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantA.String(),
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "Tenant admin access required",
		},
		{
			name: "Missing tenant_id fails closed",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "tenant-admin",
				Roles:           []string{"admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           "", // No tenant_id provided
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "Invalid or missing tenant identifier",
		},
		{
			name: "Tenant admin can access via query param",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "tenant-admin",
				Roles:           []string{"admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			queryParam:         tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "Tenant admin can access via body param (POST)",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "tenant-admin",
				Roles:           []string{"admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			bodyParam:          tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "org_admin role is recognized",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "org-admin",
				Roles:           []string{"org_admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "owner role is recognized",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "owner",
				Roles:           []string{"owner"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "super_admin role is recognized",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				Username:        "super-admin",
				Roles:           []string{"super_admin"},
				IsPlatformAdmin: false,
			},
			tenantParamName:    "tenant_id",
			urlParam:           tenantA.String(),
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test router
			router := gin.New()
			cfg := &config.Config{}
			authMiddleware := NewAuthMiddleware(nil, cfg)

			// Mock endpoint that requires tenant-scoped admin
			router.GET("/tenants/:tenant_id/users", func(c *gin.Context) {
				// Set user in context (normally done by RequireAuth middleware)
				c.Set(CurrentUserKey, tt.user)
				c.Next()
			}, authMiddleware.RequireTenantScopedAdmin(tt.tenantParamName), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			router.POST("/users", func(c *gin.Context) {
				c.Set(CurrentUserKey, tt.user)
				c.Next()
			}, authMiddleware.RequireTenantScopedAdmin(tt.tenantParamName), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Route for query param testing
			router.GET("/users", func(c *gin.Context) {
				c.Set(CurrentUserKey, tt.user)
				c.Next()
			}, authMiddleware.RequireTenantScopedAdmin(tt.tenantParamName), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Build request URL
			var url string
			var method string
			var body []byte

			switch {
			case tt.urlParam != "":
				url = "/tenants/" + tt.urlParam + "/users"
				method = http.MethodGet
			case tt.queryParam != "":
				url = "/users?tenant_id=" + tt.queryParam
				method = http.MethodGet
			case tt.bodyParam != "":
				url = "/users"
				method = http.MethodPost
				bodyData := map[string]string{"tenant_id": tt.bodyParam}
				body, _ = json.Marshal(bodyData)
			default:
				url = "/tenants/dummy/users"
				method = http.MethodGet
			}

			// Create request
			req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewBuffer(body))
			require.NoError(t, err)
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			// Execute request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response["error"], tt.expectedError)
			}
		})
	}
}

func TestValidateTenantAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantA := uuid.New()
	tenantB := uuid.New()
	hexxlockInternal, _ := uuid.Parse(models.HexxlockInternalTenantID)

	tests := []struct {
		name            string
		user            *models.CurrentUser
		targetTenantID  uuid.UUID
		expectedError   bool
		expectedErrText string
	}{
		{
			name: "Platform admin can access any tenant",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        hexxlockInternal,
				IsPlatformAdmin: true,
			},
			targetTenantID: tenantA,
			expectedError:  false,
		},
		{
			name: "User can access own tenant",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				IsPlatformAdmin: false,
			},
			targetTenantID: tenantA,
			expectedError:  false,
		},
		{
			name: "User CANNOT access different tenant",
			user: &models.CurrentUser{
				ID:              uuid.New(),
				TenantID:        tenantA,
				IsPlatformAdmin: false,
			},
			targetTenantID:  tenantB,
			expectedError:   true,
			expectedErrText: "tenant mismatch",
		},
		{
			name:            "No user in context fails",
			user:            nil,
			targetTenantID:  tenantA,
			expectedError:   true,
			expectedErrText: "not authenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test context
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Set user in context if provided
			if tt.user != nil {
				c.Set(CurrentUserKey, tt.user)
			}

			// Call ValidateTenantAccess
			err := ValidateTenantAccess(c, tt.targetTenantID)

			// Assertions
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrText)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractTenantID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()

	tests := []struct {
		name          string
		setupContext  func(*gin.Context)
		paramName     string
		expectedID    *uuid.UUID
		expectedError bool
	}{
		{
			name:      "Extract from URL param",
			paramName: "tenant_id",
			setupContext: func(c *gin.Context) {
				c.Params = gin.Params{{Key: "tenant_id", Value: tenantID.String()}}
			},
			expectedID:    &tenantID,
			expectedError: false,
		},
		{
			name:      "Extract from query param",
			paramName: "tenant_id",
			setupContext: func(c *gin.Context) {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/?tenant_id="+tenantID.String(), nil)
				c.Request = req
			},
			expectedID:    &tenantID,
			expectedError: false,
		},
		{
			name:      "Extract from request body (POST)",
			paramName: "tenant_id",
			setupContext: func(c *gin.Context) {
				body := map[string]string{"tenant_id": tenantID.String()}
				jsonBody, _ := json.Marshal(body)
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "/", bytes.NewBuffer(jsonBody))
				req.Header.Set("Content-Type", "application/json")
				c.Request = req
			},
			expectedID:    &tenantID,
			expectedError: false,
		},
		{
			name:      "Extract from X-Tenant-ID header",
			paramName: "tenant_id",
			setupContext: func(c *gin.Context) {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
				req.Header.Set("X-Tenant-ID", tenantID.String())
				c.Request = req
			},
			expectedID:    &tenantID,
			expectedError: false,
		},
		{
			name:      "Fail when tenant_id not found",
			paramName: "tenant_id",
			setupContext: func(c *gin.Context) {
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
				c.Request = req
			},
			expectedID:    nil,
			expectedError: true,
		},
		{
			name:      "Fail when tenant_id is invalid UUID",
			paramName: "tenant_id",
			setupContext: func(c *gin.Context) {
				c.Params = gin.Params{{Key: "tenant_id", Value: "not-a-uuid"}}
			},
			expectedID:    nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			tt.setupContext(c)

			extractedID, err := extractTenantID(c, tt.paramName)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, extractedID)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, extractedID)
				assert.Equal(t, *tt.expectedID, *extractedID)
			}
		})
	}
}

func TestCVEHEXXIAM001_CrossTenantAdminAccessPrevention(t *testing.T) {
	// CRITICAL SECURITY TEST: Verify CVE-HEXX-IAM-001 fix
	// This test ensures that a tenant admin from one tenant CANNOT access
	// resources from another tenant, even if they have admin privileges.

	gin.SetMode(gin.TestMode)

	// Two separate tenants
	acmeCorpTenant := uuid.New()
	globexTenant := uuid.New()

	// Create a malicious admin from ACME Corp trying to access Globex resources
	maliciousAdmin := &models.CurrentUser{
		ID:              uuid.New(),
		TenantID:        acmeCorpTenant,
		Username:        "malicious-admin@acme.com",
		Email:           "malicious-admin@acme.com",
		Roles:           []string{"admin", "super_admin"}, // Has full admin roles
		IsPlatformAdmin: false,
	}

	// Setup router with tenant-scoped middleware
	router := gin.New()
	cfg := &config.Config{}
	authMiddleware := NewAuthMiddleware(nil, cfg)

	// Endpoint to get users for a specific tenant
	router.GET("/api/tenants/:tenant_id/users", func(c *gin.Context) {
		c.Set(CurrentUserKey, maliciousAdmin)
		c.Next()
	}, authMiddleware.RequireTenantScopedAdmin("tenant_id"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Users retrieved successfully",
			"users":   []string{"user1@globex.com", "user2@globex.com"},
		})
	})

	// Attempt 1: Try to access Globex tenant's users
	t.Run("Prevent cross-tenant admin access to user listing", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/tenants/"+globexTenant.String()+"/users", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should be FORBIDDEN
		assert.Equal(t, http.StatusForbidden, w.Code)

		var response map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "tenant mismatch")
	})

	// Attempt 2: Verify access to OWN tenant works
	t.Run("Allow access to own tenant", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/tenants/"+acmeCorpTenant.String()+"/users", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should be OK
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Attempt 3: Verify platform admin bypass works
	t.Run("Allow platform admin to access any tenant", func(t *testing.T) {
		hexxlockInternal, _ := uuid.Parse(models.HexxlockInternalTenantID)
		platformAdmin := &models.CurrentUser{
			ID:              uuid.New(),
			TenantID:        hexxlockInternal,
			Username:        "platform-admin@example.com",
			IsPlatformAdmin: true,
		}

		router2 := gin.New()
		router2.GET("/api/tenants/:tenant_id/users", func(c *gin.Context) {
			c.Set(CurrentUserKey, platformAdmin)
			c.Next()
		}, authMiddleware.RequireTenantScopedAdmin("tenant_id"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/api/tenants/"+globexTenant.String()+"/users", nil)
		w := httptest.NewRecorder()
		router2.ServeHTTP(w, req)

		// Should be OK for platform admin
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
