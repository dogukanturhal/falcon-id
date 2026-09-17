// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

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

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupDebugRouter(_ *SpiceDBDebugHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

func setCurrentUser(c *gin.Context, userID, tenantID uuid.UUID) {
	c.Set(middleware.CurrentUserKey, &models.CurrentUser{
		ID:       userID,
		TenantID: tenantID,
	})
}

// ---------------------------------------------------------------------------
// DebugPermission
// ---------------------------------------------------------------------------

func TestDebugPermission_NilEngine_Returns503(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/permission", handler.DebugPermission)

	body := DebugPermissionRequest{
		UserID:     uuid.New().String(),
		TenantID:   uuid.New().String(),
		Permission: "crm.view",
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/permission", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp DebugPermissionResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "authorization engine not initialized")
}

func TestDebugPermission_InvalidUserID_Returns400(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/permission", handler.DebugPermission)

	body := DebugPermissionRequest{
		UserID:     "not-a-uuid",
		TenantID:   uuid.New().String(),
		Permission: "crm.view",
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/permission", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDebugPermission_InvalidTenantID_Returns400(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/permission", handler.DebugPermission)

	body := DebugPermissionRequest{
		UserID:     uuid.New().String(),
		TenantID:   "not-a-uuid",
		Permission: "crm.view",
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/permission", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDebugPermission_MissingFields_Returns400(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/permission", handler.DebugPermission)

	body := map[string]string{"user_id": uuid.New().String()}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/permission", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDebugPermission_EngineAllows_ReturnsAllowed(t *testing.T) {
	mockEngine := &mockAuthzEngine{
		checkResult: &services.PermissionResult{
			Allowed: true,
			Source:  "spicedb",
		},
	}

	handler := NewSpiceDBDebugHandler(mockEngine, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/permission", handler.DebugPermission)

	body := DebugPermissionRequest{
		UserID:     uuid.New().String(),
		TenantID:   uuid.New().String(),
		Permission: "crm.view",
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/permission", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp DebugPermissionResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, "spicedb", resp.Source)
}

func TestDebugPermission_EngineDenies_ReturnsDenied(t *testing.T) {
	mockEngine := &mockAuthzEngine{
		checkResult: &services.PermissionResult{
			Allowed: false,
			Source:  "spicedb",
		},
	}

	handler := NewSpiceDBDebugHandler(mockEngine, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/permission", handler.DebugPermission)

	body := DebugPermissionRequest{
		UserID:     uuid.New().String(),
		TenantID:   uuid.New().String(),
		Permission: "crm.view",
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/permission", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp DebugPermissionResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Allowed)
}

// ---------------------------------------------------------------------------
// GetReconcilerStatus
// ---------------------------------------------------------------------------

func TestGetReconcilerStatus_NilReconciler_Returns503(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.GET("/debug/reconciler/status", handler.GetReconcilerStatus)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/debug/reconciler/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ---------------------------------------------------------------------------
// TriggerReconciliation
// ---------------------------------------------------------------------------

func TestTriggerReconciliation_NilReconciler_Returns503(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/reconciler/trigger", handler.TriggerReconciliation)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/reconciler/trigger", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ---------------------------------------------------------------------------
// GetEffectivePermissions
// ---------------------------------------------------------------------------

func TestGetEffectivePermissions_InvalidUserID_Returns400(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/users/:id/effective-permissions", handler.GetEffectivePermissions)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/users/not-a-uuid/effective-permissions", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetEffectivePermissions_NoCurrentUser_Returns401(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/users/:id/effective-permissions", handler.GetEffectivePermissions)

	userID := uuid.New()
	body := EffectivePermissionsRequest{Permissions: []string{"crm.view"}}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/users/"+userID.String()+"/effective-permissions", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetEffectivePermissions_NilEngine_Returns503(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)

	userID := uuid.New()
	tenantID := uuid.New()

	router.POST("/debug/users/:id/effective-permissions", func(c *gin.Context) {
		setCurrentUser(c, userID, tenantID)
		handler.GetEffectivePermissions(c)
	})

	body := EffectivePermissionsRequest{Permissions: []string{"crm.view"}}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/users/"+userID.String()+"/effective-permissions", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestGetEffectivePermissions_Returns200WithResults(t *testing.T) {
	mockEngine := &mockAuthzEngine{
		batchResult: map[string]bool{
			"crm.view": true,
			"crm.edit": false,
			"hr.view":  true,
		},
	}

	handler := NewSpiceDBDebugHandler(mockEngine, nil, nil, nil)
	router := setupDebugRouter(handler)

	userID := uuid.New()
	tenantID := uuid.New()

	router.POST("/debug/users/:id/effective-permissions", func(c *gin.Context) {
		setCurrentUser(c, userID, tenantID)
		handler.GetEffectivePermissions(c)
	})

	body := EffectivePermissionsRequest{
		Permissions: []string{"crm.view", "crm.edit", "hr.view"},
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/users/"+userID.String()+"/effective-permissions", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp EffectivePermissionsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), resp.UserID)
	assert.True(t, resp.Permissions["crm.view"])
	assert.False(t, resp.Permissions["crm.edit"])
	assert.True(t, resp.Permissions["hr.view"])
}

// ---------------------------------------------------------------------------
// BulkAssign
// ---------------------------------------------------------------------------

func TestBulkAssign_NilBootstrap_Returns503(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/bulk-assign", handler.BulkAssign)

	body := BulkAssignRequest{
		TenantID: uuid.New().String(),
		Assignments: []AssignmentItem{
			{Type: "user_tenant", UserID: uuid.New().String()},
		},
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/bulk-assign", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestBulkAssign_InvalidTenantID_Returns400(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, services.NewTenantBootstrapService(nil))
	router := setupDebugRouter(handler)
	router.POST("/debug/bulk-assign", handler.BulkAssign)

	body := BulkAssignRequest{
		TenantID: "not-a-uuid",
		Assignments: []AssignmentItem{
			{Type: "user_tenant", UserID: uuid.New().String()},
		},
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/bulk-assign", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkAssign_MissingAssignments_Returns400(t *testing.T) {
	handler := NewSpiceDBDebugHandler(nil, nil, nil, nil)
	router := setupDebugRouter(handler)
	router.POST("/debug/bulk-assign", handler.BulkAssign)

	body := map[string]interface{}{
		"tenant_id": uuid.New().String(),
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/debug/bulk-assign", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Mock authorization engine
// ---------------------------------------------------------------------------

type mockAuthzEngine struct {
	checkResult *services.PermissionResult
	checkErr    error
	batchResult map[string]bool
	batchErr    error
}

func (m *mockAuthzEngine) CheckPermission(_ context.Context, _ services.PermissionRequest) (*services.PermissionResult, error) {
	return m.checkResult, m.checkErr
}

func (m *mockAuthzEngine) CheckResourcePermission(_ context.Context, _ services.ResourcePermissionRequest) (*services.PermissionResult, error) {
	return m.checkResult, m.checkErr
}

func (m *mockAuthzEngine) CheckContextualPermission(_ context.Context, _ services.ContextualPermissionRequest) (*services.PermissionResult, error) {
	return m.checkResult, m.checkErr
}

func (m *mockAuthzEngine) BatchCheckPermissions(_ context.Context, _, _ uuid.UUID, _ []string) (map[string]bool, error) {
	return m.batchResult, m.batchErr
}

func (m *mockAuthzEngine) CheckProductAccess(_ context.Context, _ services.ProductAccessRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: true, Source: "spicedb", Reason: "granted via SpiceDB"}, nil
}
