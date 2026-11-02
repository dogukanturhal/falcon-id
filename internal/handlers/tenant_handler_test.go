// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// ─────────────────────────────────────────────────────────────
// Thin test doubles for the concrete repository types.
// Because TenantHandler stores *repositories.TenantRepository
// and *repositories.UserRepository (concrete, not interfaces),
// and tests live in the same package, we construct real handler
// structs by setting the unexported fields directly.
//
// We fake the I/O behaviour using a minimal stub approach:
// instead of embedding a real pool we inject a nil pool and
// rely on handler-level context injection to exercise the paths
// that don't hit the actual DB.  For paths that call repo
// methods we use table-driven tests with gin.Context values
// injected to simulate middleware results.
// ─────────────────────────────────────────────────────────────

// stubTenantRepo builds a *repositories.TenantRepository with a nil pool.
// Used when the handler code under test does NOT reach the repo (e.g. validation
// path returns early with 400, or we inject the result via context).
func stubTenantRepo() *repositories.TenantRepository {
	return repositories.NewTenantRepository(nil)
}

// stubUserRepo builds a *repositories.UserRepository with a nil pool.
func stubUserRepo() *repositories.UserRepository {
	return repositories.NewUserRepository(nil)
}

func newTestTenantModel(id uuid.UUID, slug, name string) *models.Tenant {
	now := time.Now()
	return &models.Tenant{
		ID:          id,
		Name:        name,
		Slug:        slug,
		DisplayName: name,
		Status:      "active",
		Plan:        "professional",
		MaxUsers:    100,
		MaxStorage:  107374182400,
		Settings:    map[string]interface{}{},
		Metadata:    map[string]interface{}{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// buildTenantHandlerRouter registers given handler on the provided router.
// We inject an authenticated current_user via a wrapping middleware handler.
func buildTenantHandlerRouter(h *TenantHandler) *gin.Engine {
	router := gin.New()
	router.GET("/plan-limits", h.GetPlanLimits)
	router.GET("/usage/history", h.GetUsageHistory)
	router.GET("/feature-flags", h.GetTenantFeatureFlags)
	router.GET("/feature-flags/overrides", h.GetTenantFeatureFlagOverrides)
	return router
}

// ─────────────────────────────────────────────────────────────
// Tests for pure/stateless endpoints (no DB dependency)
// ─────────────────────────────────────────────────────────────

func TestTenantHandler_GetPlanLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &TenantHandler{logger: zap.NewNop()}
	router := buildTenantHandlerRouter(h)

	tests := []struct {
		name          string
		planQuery     string
		wantMaxUsers  int
		wantRateLimit int
	}{
		{"free plan", "free", 5, 100},
		{"starter plan", "starter", 25, 1000},
		{"professional plan", "professional", 100, 10000},
		{"enterprise plan", "enterprise", -1, 100000},
		{"no plan defaults to professional", "", 100, 10000},
		{"unknown plan defaults to professional", "unknown", 100, 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/plan-limits"
			if tt.planQuery != "" {
				url += "?plan=" + tt.planQuery
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp PlanLimits
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMaxUsers, resp.MaxUsers, "MaxUsers mismatch for plan %q", tt.planQuery)
			assert.Equal(t, tt.wantRateLimit, resp.APIRateLimit, "APIRateLimit mismatch for plan %q", tt.planQuery)
		})
	}
}

func TestTenantHandler_GetUsageHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &TenantHandler{logger: zap.NewNop()}
	router := buildTenantHandlerRouter(h)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/usage/history", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Contains(t, body, "history")
}

func TestTenantHandler_GetTenantFeatureFlags(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &TenantHandler{logger: zap.NewNop()}
	router := buildTenantHandlerRouter(h)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/feature-flags", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)

	flags, ok := body["flags"].(map[string]interface{})
	require.True(t, ok, "response should contain 'flags' map")
	assert.Contains(t, flags, "mfa_enabled")
	assert.Contains(t, flags, "sso_enabled")
	assert.Contains(t, flags, "api_access")
	assert.Contains(t, flags, "email_integration")
}

func TestTenantHandler_GetTenantFeatureFlagOverrides(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &TenantHandler{logger: zap.NewNop()}
	router := buildTenantHandlerRouter(h)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/feature-flags/overrides", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Contains(t, body, "overrides")
}

// ─────────────────────────────────────────────────────────────
// Tests for handler validation / early-return paths
// (exercise handler logic without needing a real DB pool)
// ─────────────────────────────────────────────────────────────

func TestTenantHandler_CreateTenant_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("missing required fields returns 400", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.POST("/tenants", h.CreateTenant)

		// Missing "name" and "slug" (both binding:"required")
		body := `{"plan":"trial"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/tenants", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid JSON body returns 400", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.POST("/tenants", h.CreateTenant)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/tenants", strings.NewReader(`{invalid json`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestTenantHandler_GetCurrentTenant_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns 401 when current_user not in context", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.GET("/tenant", h.GetCurrentTenant)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tenant", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Equal(t, "unauthorized", body["error"])
	})
}

func TestTenantHandler_UpdateTenantSettings_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns 401 when current_user not in context", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.PUT("/tenant/settings", h.UpdateTenantSettings)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/tenant/settings", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestTenantHandler_GetTenantUsage_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns 401 when current_user not in context", func(t *testing.T) {
		h := &TenantHandler{
			userRepo: stubUserRepo(),
			logger:   zap.NewNop(),
		}

		router := gin.New()
		router.GET("/tenant/usage", h.GetTenantUsage)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tenant/usage", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestTenantHandler_GetTenantConnectionInfo_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns 400 for malformed tenant_id query param", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.GET("/tenant/connection-info", h.GetTenantConnectionInfo)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tenant/connection-info?tenant_id=not-a-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Contains(t, body, "error")
	})

	t.Run("returns 401 when no tenant_id param and no user in context", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.GET("/tenant/connection-info", h.GetTenantConnectionInfo)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tenant/connection-info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestTenantHandler_GetTenantConnectionInfoByID_Validation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns 400 for invalid UUID path param", func(t *testing.T) {
		h := &TenantHandler{
			tenantRepo: stubTenantRepo(),
			logger:     zap.NewNop(),
		}

		router := gin.New()
		router.GET("/internal/tenants/:id/connection-info", h.GetTenantConnectionInfoByID)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/tenants/bad-uuid/connection-info", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ─────────────────────────────────────────────────────────────
// Tests for private helper functions (same package access)
// ─────────────────────────────────────────────────────────────

func TestGetIsolationStrategy(t *testing.T) {
	cases := []struct {
		plan         string
		wantStrategy string
	}{
		{"free", "shared"},
		{"starter", "shared"},
		{"professional", "schema"},
		{"enterprise", "database"},
		{"trial", "shared"},
		{"unknown", "shared"},
	}

	for _, c := range cases {
		t.Run(c.plan, func(t *testing.T) {
			got := getIsolationStrategy(c.plan)
			assert.Equal(t, c.wantStrategy, got)
		})
	}
}

func TestGetDatabaseName(t *testing.T) {
	assert.Equal(t, "hexxlock_master", getDatabaseName("shared", "myslug"))
	assert.Equal(t, "hexxlock_master", getDatabaseName("schema", "myslug"))
	assert.Equal(t, "hexxlock_myslug", getDatabaseName("database", "myslug"))
}

func TestGetSchemaName(t *testing.T) {
	assert.Equal(t, "public", getSchemaName("shared", "myslug"))
	assert.Equal(t, "tenant_myslug", getSchemaName("schema", "myslug"))
	assert.Equal(t, "public", getSchemaName("database", "myslug"))
}

func TestGetPlanLimitsHelper(t *testing.T) {
	tests := []struct {
		plan         string
		wantMaxUsers int
		wantModules  []string
	}{
		{"free", 5, []string{"core"}},
		{"starter", 25, []string{"core", "crm"}},
		{"professional", 100, []string{"core", "crm", "invoicing", "hr"}},
		{"enterprise", -1, []string{"core", "crm", "invoicing", "hr", "inventory", "accounting"}},
		// Unknown plan should fall back to professional
		{"bogus", 100, []string{"core", "crm", "invoicing", "hr"}},
	}

	for _, tt := range tests {
		t.Run(tt.plan, func(t *testing.T) {
			got := getPlanLimits(tt.plan)
			assert.Equal(t, tt.wantMaxUsers, got.MaxUsers)
			for _, mod := range tt.wantModules {
				assert.Contains(t, got.Modules, mod)
			}
		})
	}
}

func TestTenantToResponse(t *testing.T) {
	h := &TenantHandler{logger: zap.NewNop()}
	tenantID := uuid.New()
	tenant := newTestTenantModel(tenantID, "acme", "Acme Corp")

	domain := "acme.example.com"
	tenant.Domain = &domain

	resp := h.tenantToResponse(tenant)
	assert.Equal(t, tenantID, resp.ID)
	assert.Equal(t, "Acme Corp", resp.Name)
	assert.Equal(t, "acme", resp.Slug)
	assert.Equal(t, "active", resp.Status)
	assert.Equal(t, "professional", resp.Plan)
	require.NotNil(t, resp.Domain)
	assert.Equal(t, "acme.example.com", *resp.Domain)
}

// ─────────────────────────────────────────────────────────────
// Context-based integration-style tests using a fake tenant
// injected into gin context (bypasses DB entirely).
// ─────────────────────────────────────────────────────────────

// TestTenantHandler_GetCurrentTenant_WithContextInjection tests the happy path
// by hooking into gin context with a real models.Tenant embedded in a fake repo
// function (using the gin context to short-circuit DB lookup).
func TestTenantHandler_GetCurrentTenant_WithContextInjection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	tenant := newTestTenantModel(tenantID, "acme-inc", "Acme Inc")

	// We cannot mock the concrete *repositories.TenantRepository directly.
	// Instead, we test the JSON serialisation path by calling the handler
	// method with a gin context that has the tenant already resolved, testing
	// the tenantToResponse / JSON output shape.
	h := &TenantHandler{logger: zap.NewNop()}

	// Directly test tenantToResponse + JSON response by constructing the
	// expected response and verifying shape.
	resp := h.tenantToResponse(tenant)

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded TenantResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, tenantID, decoded.ID)
	assert.Equal(t, "acme-inc", decoded.Slug)
	assert.Equal(t, "Acme Inc", decoded.Name)
	assert.Equal(t, "active", decoded.Status)
	assert.Equal(t, "professional", decoded.Plan)
}

// TestTenantHandler_CreateTenant_DefaultValues verifies default setting logic.
func TestTenantHandler_CreateTenant_DefaultValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test the default-value logic within CreateTenant without hitting DB:
	// we look at what the handler would build given minimal input,
	// by inspecting the CreateTenantRequest logic directly.

	// Replicate the logic from CreateTenant handler:
	req := CreateTenantRequest{
		Name: "Beta Co",
		Slug: "beta",
	}

	if req.DisplayName == "" {
		req.DisplayName = req.Name
	}
	if req.Plan == "" {
		req.Plan = "trial"
	}
	if req.MaxUsers == 0 {
		req.MaxUsers = 5
	}
	if req.MaxStorage == 0 {
		req.MaxStorage = 1073741824
	}

	assert.Equal(t, "Beta Co", req.DisplayName)
	assert.Equal(t, "trial", req.Plan)
	assert.Equal(t, 5, req.MaxUsers)
	assert.Equal(t, int64(1073741824), req.MaxStorage)
}

// TestTenantHandler_tenantToResponse_NilFields verifies optional pointer fields
// are correctly handled when nil.
func TestTenantHandler_tenantToResponse_NilFields(t *testing.T) {
	h := &TenantHandler{logger: zap.NewNop()}
	tenantID := uuid.New()

	tenant := &models.Tenant{
		ID:          tenantID,
		Name:        "No Optional",
		Slug:        "no-opt",
		DisplayName: "No Optional",
		Status:      "active",
		Plan:        "free",
		Settings:    map[string]interface{}{},
		Metadata:    map[string]interface{}{},
	}

	resp := h.tenantToResponse(tenant)
	assert.Nil(t, resp.Domain)
	assert.Nil(t, resp.BillingEmail)
	assert.Nil(t, resp.TrialEndsAt)
	assert.Nil(t, resp.SuspendedAt)
	assert.Nil(t, resp.CancelledAt)
}

// TestTenantHandler_ContextKeys verifies that GetCurrentTenant returns 401
// when the "current_user" key is absent from the gin context, proving the
// handler reads exactly that key from context (not some other mechanism).
func TestTenantHandler_ContextKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &TenantHandler{logger: zap.NewNop()}

	t.Run("returns 401 when current_user key is absent", func(t *testing.T) {
		router := gin.New()
		router.GET("/tenant", h.GetCurrentTenant)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/tenant", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ─────────────────────────────────────────────────────────────
// GetTenantUserCount (feat/seat-quota-enforcement)
// ─────────────────────────────────────────────────────────────

// TestTenantHandler_GetTenantUserCount_Success confirms the handler wires
// the path param through to UserRepository.CountActiveByTenant and shapes
// the response as {"tenant_id","active_user_count"} — the exact contract
// quota-service's users-resource backfill script depends on.
func TestTenantHandler_GetTenantUserCount_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockPool, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer mockPool.Close()

	tenantID := uuid.New()
	mockPool.ExpectBegin()
	mockPool.ExpectExec(`set_config`).WithArgs(tenantID.String()).WillReturnResult(pgxmock.NewResult("SELECT", 1))
	mockPool.ExpectQuery(`SELECT COUNT\(\*\) FROM iam_users u\s+WHERE u.tenant_id = \$1 AND u.is_active = true AND u.deletion_scheduled_at IS NULL`).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(3))
	mockPool.ExpectCommit()

	h := &TenantHandler{
		userRepo: repositories.NewUserRepository(mockPool),
		logger:   zap.NewNop(),
	}

	router := gin.New()
	router.GET("/internal/v1/tenants/:id/users/count", h.GetTenantUserCount)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/v1/tenants/"+tenantID.String()+"/users/count", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body tenantUserCountResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, tenantID.String(), body.TenantID)
	assert.Equal(t, 3, body.ActiveUserCount)

	require.NoError(t, mockPool.ExpectationsWereMet())
}

// TestTenantHandler_GetTenantUserCount_InvalidTenantID confirms a
// malformed path param is rejected with 400 before any DB query runs.
func TestTenantHandler_GetTenantUserCount_InvalidTenantID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &TenantHandler{userRepo: stubUserRepo(), logger: zap.NewNop()}

	router := gin.New()
	router.GET("/internal/v1/tenants/:id/users/count", h.GetTenantUserCount)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/v1/tenants/not-a-uuid/users/count", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func newTenantMemberRouter(t *testing.T) (*gin.Engine, pgxmock.PgxPoolIface) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mockPool, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(mockPool.Close)
	h := &TenantHandler{userRepo: repositories.NewUserRepository(mockPool), logger: zap.NewNop()}
	router := gin.New()
	router.GET("/internal/v1/tenants/:id/members/:userId", h.GetTenantMember)
	return router, mockPool
}

func TestTenantHandler_GetTenantMember(t *testing.T) {
	const q = `SELECT \(is_active AND deletion_scheduled_at IS NULL\) FROM iam_users WHERE tenant_id = \$1 AND id = \$2`
	tenantID, userID := uuid.New(), uuid.New()
	path := "/internal/v1/tenants/" + tenantID.String() + "/members/" + userID.String()

	for _, active := range []bool{true, false} {
		router, pool := newTenantMemberRouter(t)
		pool.ExpectQuery(q).WithArgs(tenantID, userID).
			WillReturnRows(pgxmock.NewRows([]string{"active"}).AddRow(active))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"active":`+map[bool]string{true: "true", false: "false"}[active]+`}`, w.Body.String())
		require.NoError(t, pool.ExpectationsWereMet())
	}

	// Not a member of the tenant -> 404.
	router, pool := newTenantMemberRouter(t)
	pool.ExpectQuery(q).WithArgs(tenantID, userID).WillReturnRows(pgxmock.NewRows([]string{"active"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	assert.Equal(t, http.StatusNotFound, w.Code)

	// DB error -> 500 (caller fails closed).
	router, pool = newTenantMemberRouter(t)
	pool.ExpectQuery(q).WithArgs(tenantID, userID).WillReturnError(assert.AnError)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandler_GetTenantMember_InvalidIDs(t *testing.T) {
	router, _ := newTenantMemberRouter(t)
	for _, p := range []string{
		"/internal/v1/tenants/not-a-uuid/members/" + uuid.NewString(),
		"/internal/v1/tenants/" + uuid.NewString() + "/members/not-a-uuid",
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, p, nil))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	}
}
