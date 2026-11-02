// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ============================================================================
// Mocks
// ============================================================================

// MockPermissionRepository is a mock for PermissionRepositoryInterface
type MockPermissionRepository struct {
	mock.Mock
}

func (m *MockPermissionRepository) GetUserPermissions(ctx context.Context, userID, _ uuid.UUID) ([]models.Permission, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Permission), args.Error(1)
}

func (m *MockPermissionRepository) GetUserRoles(ctx context.Context, userID, _ uuid.UUID) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// MockOPAService is a mock for OPAServiceInterface
type MockOPAService struct {
	mock.Mock
}

func (m *MockOPAService) IsEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockOPAService) EvaluatePermission(ctx context.Context, userID, tenantID uuid.UUID, username, email string, roles, permissions, groups []string, permission, resourceType, resourceID, ownerID string, resourceAttrs map[string]interface{}, ipAddress, userAgent, requestPath string) (*AuthzResult, error) {
	args := m.Called(ctx, userID, tenantID, username, email, roles, permissions, groups, permission, resourceType, resourceID, ownerID, resourceAttrs, ipAddress, userAgent, requestPath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthzResult), args.Error(1)
}

// MockAuditService is a mock for AuditServiceInterface
type MockAuditService struct {
	mock.Mock
}

// MockSpiceDBChecker implements SpiceDBChecker for testing.
type MockSpiceDBChecker struct {
	mock.Mock
}

func (m *MockSpiceDBChecker) CheckPermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (bool, error) {
	args := m.Called(ctx, tenantID, userID, objectType, objectID, permission)
	return args.Bool(0), args.Error(1)
}

func (m *MockSpiceDBChecker) CheckPermissionConsistent(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission, zedToken string) (bool, error) {
	args := m.Called(ctx, tenantID, userID, objectType, objectID, permission, zedToken)
	return args.Bool(0), args.Error(1)
}

func (m *MockSpiceDBChecker) CheckBulkPermissions(ctx context.Context, tenantID, userID uuid.UUID, objectType string, objectIDs []string, permission string) (map[string]bool, error) {
	args := m.Called(ctx, tenantID, userID, objectType, objectIDs, permission)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]bool), args.Error(1)
}

// ============================================================================
// Helpers
// ============================================================================

// newTestEngine creates an authorizationEngine with mock dependencies.
// spicedb may be nil for tests that verify nil-guard / fail-closed behavior.
func newTestEngine(permRepo PermissionRepositoryInterface, opa OPAServiceInterface, spicedb SpiceDBChecker) AuthorizationEngine {
	cfg := &config.Config{}
	return NewAuthorizationEngine(permRepo, opa, nil, nil, spicedb, cfg)
}

// ============================================================================
// CheckPermission — SpiceDB is the sole authority for module-level permissions
// ============================================================================

func TestCheckPermission_SpiceDB_Allowed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockPermRepo := new(MockPermissionRepository)
	engine := newTestEngine(mockPermRepo, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	// Permission name "crm:contacts:read" is translated to "crm__contacts__read" at the SpiceDB boundary
	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "granted via SpiceDB")

	mockSpiceDB.AssertExpectations(t)
	mockPermRepo.AssertNotCalled(t, "GetUserPermissions") // No DB fallback
}

func TestCheckPermission_SpiceDB_Denied(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__delete", "check").
		Return(false, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:delete",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "denied")
}

func TestCheckPermission_SpiceDB_Error_FailClosed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockPermRepo := new(MockPermissionRepository)
	engine := newTestEngine(mockPermRepo, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(false, errors.New("SpiceDB connection refused"))

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
	})

	// Fail-closed: return denied result, NOT an error
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "fail-closed")

	// CRITICAL: must never fall back to RBAC/PostgreSQL
	mockPermRepo.AssertNotCalled(t, "GetUserPermissions")
}

func TestCheckPermission_NilUserID_Denied(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.Nil,
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "user ID is required")
}

func TestCheckPermission_EmptyPermission_Denied(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "permission is required")
}

func TestCheckPermission_NilSpiceDBClient_FailClosed(t *testing.T) {
	// SpiceDB is required — nil client means deny
	engine := newTestEngine(nil, nil, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "fail-closed")
}

// ============================================================================
// CheckResourcePermission — SpiceDB resource-level checks
// ============================================================================

func TestCheckResourcePermission_SpiceDB_Allowed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	resourceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"invoice", resourceID, "edit").
		Return(true, nil)

	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "edit",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "granted via SpiceDB")
}

func TestCheckResourcePermission_SpiceDB_Denied(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	resourceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"invoice", resourceID, "delete").
		Return(false, nil)

	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "delete",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
}

func TestCheckResourcePermission_SpiceDB_Error_FailClosed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	resourceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"invoice", resourceID, "edit").
		Return(false, errors.New("SpiceDB timeout"))

	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "edit",
	})

	// Fail-closed: deny on error
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "fail-closed")
}

func TestCheckResourcePermission_NilSpiceDBClient_FailClosed(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		UserID:       uuid.New(),
		TenantID:     uuid.New(),
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
		Action:       "edit",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "fail-closed")
}

func TestCheckResourcePermission_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		req  ResourcePermissionRequest
	}{
		{
			name: "nil user ID",
			req: ResourcePermissionRequest{
				UserID:       uuid.Nil,
				ResourceType: "invoice",
				ResourceID:   "123",
				Action:       "edit",
			},
		},
		{
			name: "missing resource type",
			req: ResourcePermissionRequest{
				UserID:     uuid.New(),
				ResourceID: "123",
				Action:     "edit",
			},
		},
		{
			name: "missing action",
			req: ResourcePermissionRequest{
				UserID:       uuid.New(),
				ResourceType: "invoice",
				ResourceID:   "123",
			},
		},
		{
			name: "missing resource ID",
			req: ResourcePermissionRequest{
				UserID:       uuid.New(),
				ResourceType: "invoice",
				Action:       "edit",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := newTestEngine(nil, nil, nil)

			result, err := engine.CheckResourcePermission(context.Background(), tt.req)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.False(t, result.Allowed)
		})
	}
}

// ============================================================================
// BatchCheckPermissions — native CheckBulkPermissions API (Phase 4)
// ============================================================================

func TestBatchCheckPermissions_SpiceDB_AllAllowed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	perms := []string{"crm:contacts:read", "crm:contacts:write"}
	// Permission names are translated to SpiceDB-safe IDs for the bulk check
	translatedPerms := []string{"crm__contacts__read", "crm__contacts__write"}

	mockSpiceDB.On("CheckBulkPermissions", mock.Anything, tenantID, userID,
		"access_grant", translatedPerms, "check").Return(
		map[string]bool{
			"crm__contacts__read":  true,
			"crm__contacts__write": true,
		}, nil)

	results, err := engine.BatchCheckPermissions(context.Background(), userID, tenantID, perms)

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.True(t, results["crm:contacts:read"])
	assert.True(t, results["crm:contacts:write"])
	mockSpiceDB.AssertCalled(t, "CheckBulkPermissions", mock.Anything, tenantID, userID,
		"access_grant", translatedPerms, "check")
}

func TestBatchCheckPermissions_SpiceDB_Mixed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	perms := []string{"crm:contacts:read", "crm:contacts:delete", "invoicing:invoices:create"}
	translatedPerms := []string{"crm__contacts__read", "crm__contacts__delete", "invoicing__invoices__create"}

	mockSpiceDB.On("CheckBulkPermissions", mock.Anything, tenantID, userID,
		"access_grant", translatedPerms, "check").Return(
		map[string]bool{
			"crm__contacts__read":         true,
			"crm__contacts__delete":       true,
			"invoicing__invoices__create": false,
		}, nil)

	results, err := engine.BatchCheckPermissions(context.Background(), userID, tenantID, perms)

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.True(t, results["crm:contacts:read"])
	assert.True(t, results["crm:contacts:delete"])
	assert.False(t, results["invoicing:invoices:create"])
}

func TestBatchCheckPermissions_SpiceDB_Error_FailClosed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	perms := []string{"crm:contacts:read", "crm:contacts:delete"}
	translatedPerms := []string{"crm__contacts__read", "crm__contacts__delete"}

	// Bulk check returns an error
	mockSpiceDB.On("CheckBulkPermissions", mock.Anything, tenantID, userID,
		"access_grant", translatedPerms, "check").Return(
		map[string]bool(nil), errors.New("spicedb unavailable"))

	// All permissions denied on error (fail-closed)
	results, err := engine.BatchCheckPermissions(context.Background(), userID, tenantID, perms)

	require.NoError(t, err) // engine doesn't propagate bulk error — denies all
	require.NotNil(t, results)
	assert.False(t, results["crm:contacts:read"])
	assert.False(t, results["crm:contacts:delete"])
}

func TestBatchCheckPermissions_NilSpiceDBClient_AllDenied(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	perms := []string{"crm:contacts:read", "crm:contacts:write"}

	results, err := engine.BatchCheckPermissions(context.Background(), uuid.New(), uuid.New(), perms)

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.False(t, results["crm:contacts:read"])
	assert.False(t, results["crm:contacts:write"])
}

func TestBatchCheckPermissions_EmptyList(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	results, err := engine.BatchCheckPermissions(context.Background(), uuid.New(), uuid.New(), []string{})

	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestBatchCheckPermissions_NilUserID_Error(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	results, err := engine.BatchCheckPermissions(context.Background(), uuid.Nil, uuid.New(), []string{"crm:contacts:read"})

	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "user ID is required")
}

// ============================================================================
// CheckContextualPermission — OPA for policy-based + SpiceDB fallback
// ============================================================================

func TestCheckContextualPermission_OPAEnabled_Allowed(t *testing.T) {
	mockPermRepo := new(MockPermissionRepository)
	mockOPA := new(MockOPAService)
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(mockPermRepo, mockOPA, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	resourceID := uuid.New().String()

	// OPA is deny-only: a grant still needs ReBAC.
	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID, "access_grant", "invoicing__invoices__approve", "check").Return(true, nil)
	mockOPA.On("IsEnabled").Return(true)
	mockPermRepo.On("GetUserRoles", mock.Anything, userID).Return([]string{"manager"}, nil)
	mockPermRepo.On("GetUserPermissions", mock.Anything, userID).
		Return([]models.Permission{{Name: "invoicing:invoices:approve"}}, nil)

	mockOPA.On("EvaluatePermission",
		mock.Anything, userID, tenantID,
		"", "",
		[]string{"manager"},
		[]string{"invoicing:invoices:approve"},
		([]string)(nil),
		"approve", "invoice", resourceID, "",
		mock.Anything, "", "", "",
	).Return(&AuthzResult{
		Allowed: true,
		Reasons: []string{"role matches policy"},
	}, nil)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Attributes:   map[string]interface{}{"amount": 5000},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "opa", result.Source)
}

func TestCheckContextualPermission_OPAEnabled_Denied(t *testing.T) {
	mockPermRepo := new(MockPermissionRepository)
	mockOPA := new(MockOPAService)
	engine := newTestEngine(mockPermRepo, mockOPA, nil)

	userID := uuid.New()
	tenantID := uuid.New()

	mockOPA.On("IsEnabled").Return(true)
	mockPermRepo.On("GetUserRoles", mock.Anything, userID).Return([]string{"viewer"}, nil)
	mockPermRepo.On("GetUserPermissions", mock.Anything, userID).
		Return([]models.Permission{{Name: "invoicing:invoices:read"}}, nil)

	mockOPA.On("EvaluatePermission",
		mock.Anything, userID, tenantID,
		"", "",
		[]string{"viewer"},
		[]string{"invoicing:invoices:read"},
		([]string)(nil),
		"approve", "invoice", mock.AnythingOfType("string"), "",
		mock.Anything, "", "", "",
	).Return(&AuthzResult{
		Allowed: false,
		Reasons: []string{"amount exceeds limit"},
	}, nil)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
		Attributes:   map[string]interface{}{"amount": 50000},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "opa", result.Source)
}

func TestCheckContextualPermission_OPAEnabled_Error(t *testing.T) {
	mockPermRepo := new(MockPermissionRepository)
	mockOPA := new(MockOPAService)
	engine := newTestEngine(mockPermRepo, mockOPA, nil)

	userID := uuid.New()
	tenantID := uuid.New()

	mockOPA.On("IsEnabled").Return(true)
	mockPermRepo.On("GetUserRoles", mock.Anything, userID).Return([]string{"manager"}, nil)
	mockPermRepo.On("GetUserPermissions", mock.Anything, userID).
		Return([]models.Permission{{Name: "invoicing:invoices:approve"}}, nil)

	mockOPA.On("EvaluatePermission",
		mock.Anything, userID, tenantID,
		"", "",
		[]string{"manager"},
		[]string{"invoicing:invoices:approve"},
		([]string)(nil),
		"approve", "invoice", mock.AnythingOfType("string"), "",
		mock.Anything, "", "", "",
	).Return(nil, errors.New("opa policy evaluation failed"))

	_, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "OPA evaluation failed")
}

func TestCheckContextualPermission_OPADisabled_FallbackToSpiceDB_Allowed(t *testing.T) {
	mockOPA := new(MockOPAService)
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, mockOPA, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	mockOPA.On("IsEnabled").Return(false)

	// OPA disabled → falls back to SpiceDB module-level check
	// resourceToModulePermission("invoice", "approve") → "invoicing:invoices:approve"
	// → translated to "invoicing__invoices__approve" for SpiceDB
	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "invoicing__invoices__approve", "check").Return(true, nil)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
}

func TestCheckContextualPermission_OPADisabled_FallbackToSpiceDB_Denied(t *testing.T) {
	mockOPA := new(MockOPAService)
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, mockOPA, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	mockOPA.On("IsEnabled").Return(false)

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "invoicing__invoices__approve", "check").Return(false, nil)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
}

func TestCheckContextualPermission_OPANil_FallbackToSpiceDB(t *testing.T) {
	// OPA service is nil (not just disabled)
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "invoicing__invoices__approve", "check").Return(true, nil)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
}

func TestCheckContextualPermission_OPADisabled_NilSpiceDB_FailClosed(t *testing.T) {
	mockOPA := new(MockOPAService)
	// Both OPA disabled and SpiceDB nil → fail-closed
	engine := newTestEngine(nil, mockOPA, nil)

	mockOPA.On("IsEnabled").Return(false)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       uuid.New(),
		TenantID:     uuid.New(),
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "fail-closed")
}

func TestCheckContextualPermission_NilUserID(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	result, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       uuid.Nil,
		TenantID:     uuid.New(),
		Action:       "approve",
		ResourceType: "invoice",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
}

func TestCheckContextualPermission_GetRolesError(t *testing.T) {
	mockPermRepo := new(MockPermissionRepository)
	mockOPA := new(MockOPAService)
	engine := newTestEngine(mockPermRepo, mockOPA, nil)

	userID := uuid.New()

	mockOPA.On("IsEnabled").Return(true)
	mockPermRepo.On("GetUserRoles", mock.Anything, userID).Return(nil, errors.New("db error"))

	_, err := engine.CheckContextualPermission(context.Background(), ContextualPermissionRequest{
		UserID:       userID,
		TenantID:     uuid.New(),
		Action:       "approve",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user roles")
}

// ============================================================================
// Helper: resourceToModulePermission
// ============================================================================

func TestResourceToModulePermission(t *testing.T) {
	engine := &authorizationEngine{}

	tests := []struct {
		resourceType string
		action       string
		expected     string
	}{
		{resourceType: "invoice", action: "edit", expected: "invoicing:invoices:edit"},
		{resourceType: "contact", action: "delete", expected: "crm:contacts:delete"},
		{resourceType: "document", action: "view", expected: "documents:documents:view"},
		{resourceType: "project", action: "edit", expected: "projects:projects:edit"},
		{resourceType: "task", action: "create", expected: "projects:tasks:create"},
		{resourceType: "account", action: "view", expected: "accounting:accounts:view"},
		{resourceType: "lead", action: "manage", expected: "crm:leads:manage"},
		{resourceType: "unknown", action: "read", expected: "unknown:unknowns:read"},
	}

	for _, tt := range tests {
		t.Run(tt.resourceType+"_"+tt.action, func(t *testing.T) {
			result := engine.resourceToModulePermission(tt.resourceType, tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// GetMetrics
// ============================================================================

func TestGetMetrics(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	// Access concrete type for GetMetrics
	concreteEngine, ok := engine.(*authorizationEngine)
	require.True(t, ok)

	m := concreteEngine.GetMetrics()
	assert.Contains(t, m, "spicedb_checks")
	assert.Contains(t, m, "opa_checks")
	assert.Equal(t, int64(0), m["spicedb_checks"])
	assert.Equal(t, int64(0), m["opa_checks"])
}

// ============================================================================
// ZedToken propagation — New Enemy Problem prevention (Phase 3)
// ============================================================================

func TestCheckPermission_WithZedToken_UsesConsistentCheck(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	token := "zedtoken_abc123"

	// Should call CheckPermissionConsistent (NOT CheckPermission)
	mockSpiceDB.On("CheckPermissionConsistent", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check", token).
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
		ZedToken:   token,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)

	// Must have called the consistent check, NOT the regular one
	mockSpiceDB.AssertCalled(t, "CheckPermissionConsistent", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check", token)
	mockSpiceDB.AssertNotCalled(t, "CheckPermission")
}

func TestCheckPermission_WithoutZedToken_UsesRegularCheck(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()

	// When no ZedToken, uses regular MinimizeLatency check
	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check").
		Return(true, nil)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
		// No ZedToken — should use regular CheckPermission
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)

	// Must have called regular check, NOT consistent check
	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check")
	mockSpiceDB.AssertNotCalled(t, "CheckPermissionConsistent")
}

func TestCheckPermission_WithZedToken_Error_FailClosed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	token := "zedtoken_xyz789"

	mockSpiceDB.On("CheckPermissionConsistent", mock.Anything, tenantID, userID,
		"access_grant", "crm__contacts__read", "check", token).
		Return(false, errors.New("SpiceDB consistency check failed"))

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     userID,
		TenantID:   tenantID,
		Permission: "crm:contacts:read",
		ZedToken:   token,
	})

	// Fail-closed: deny, no error
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "fail-closed")
}

func TestCheckResourcePermission_WithZedToken_UsesConsistentCheck(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	resourceID := uuid.New().String()
	token := "zedtoken_resource_456" //nolint:gosec // test fixture value, not a real credential

	mockSpiceDB.On("CheckPermissionConsistent", mock.Anything, tenantID, userID,
		"invoice", resourceID, "edit", token).
		Return(true, nil)

	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "edit",
		ZedToken:     token,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)

	mockSpiceDB.AssertCalled(t, "CheckPermissionConsistent", mock.Anything, tenantID, userID,
		"invoice", resourceID, "edit", token)
	mockSpiceDB.AssertNotCalled(t, "CheckPermission")
}

// ============================================================================
// CheckProductAccess — product instance access via SpiceDB
// ============================================================================

func TestCheckProductAccess_Allowed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	instanceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"platform_product_instance", instanceID, "use").
		Return(true, nil)

	result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
		UserID:     userID,
		TenantID:   tenantID,
		InstanceID: instanceID,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "granted")
}

func TestCheckProductAccess_Denied(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	instanceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"platform_product_instance", instanceID, "use").
		Return(false, nil)

	result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
		UserID:     userID,
		TenantID:   tenantID,
		InstanceID: instanceID,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "denied")
}

func TestCheckProductAccess_CustomAction(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	instanceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"platform_product_instance", instanceID, "admin").
		Return(true, nil)

	result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
		UserID:     userID,
		TenantID:   tenantID,
		InstanceID: instanceID,
		Action:     "admin",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
}

func TestCheckProductAccess_NilSpiceDB_FailClosed(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		InstanceID: uuid.New().String(),
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "fail-closed")
}

func TestCheckProductAccess_SpiceDBError_FailClosed(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	instanceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"platform_product_instance", instanceID, "use").
		Return(false, errors.New("connection refused"))

	result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
		UserID:     userID,
		TenantID:   tenantID,
		InstanceID: instanceID,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "fail-closed")
}

func TestCheckProductAccess_MissingFields(t *testing.T) {
	engine := newTestEngine(nil, nil, nil)

	t.Run("nil user ID", func(t *testing.T) {
		result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
			UserID:     uuid.Nil,
			TenantID:   uuid.New(),
			InstanceID: uuid.New().String(),
		})
		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.Contains(t, result.Reason, "user ID is required")
	})

	t.Run("empty instance ID", func(t *testing.T) {
		result, err := engine.CheckProductAccess(context.Background(), ProductAccessRequest{
			UserID:   uuid.New(),
			TenantID: uuid.New(),
		})
		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.Contains(t, result.Reason, "instance ID is required")
	})
}

func TestCheckResourcePermission_WithoutZedToken_UsesRegularCheck(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	engine := newTestEngine(nil, nil, mockSpiceDB)

	userID := uuid.New()
	tenantID := uuid.New()
	resourceID := uuid.New().String()

	mockSpiceDB.On("CheckPermission", mock.Anything, tenantID, userID,
		"invoice", resourceID, "edit").
		Return(true, nil)

	result, err := engine.CheckResourcePermission(context.Background(), ResourcePermissionRequest{
		UserID:       userID,
		TenantID:     tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "edit",
		// No ZedToken
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)

	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, tenantID, userID,
		"invoice", resourceID, "edit")
	mockSpiceDB.AssertNotCalled(t, "CheckPermissionConsistent")
}
