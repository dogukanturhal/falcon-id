// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// rbac_integration_test.go — Integration tests for the RBAC authorization flow.
//
// These tests exercise the full role-based access control path:
//   create role → assign permissions → check permission → remove access → check denied
//
// The authorization authority is SpiceDB (mocked).  OPA is disabled so every
// decision routes through SpiceDB, matching the production SpiceDB-only path.
//
// Filter with:
//
//	go test ./internal/services/... -run "IntegrationRBAC"

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// rbacFixture bundles all the components needed for RBAC flow tests.
type rbacFixture struct {
	userID    uuid.UUID
	tenantID  uuid.UUID
	roleID    uuid.UUID
	permName  string // e.g. "crm:contacts:read"
	spicedbID string // translated permission ID used in SpiceDB calls
	engine    AuthorizationEngine
	spiceDB   *MockSpiceDBChecker
	permRepo  *MockPermissionRepository
}

// newRBACFixture creates a test fixture with mock SpiceDB wired into the engine.
// OPA is disabled (nil) so all decisions go through SpiceDB.
func newRBACFixture() *rbacFixture {
	spiceDB := new(MockSpiceDBChecker)
	permRepo := new(MockPermissionRepository)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(permRepo, nil /* OPA disabled */, nil, nil, spiceDB, cfg)

	return &rbacFixture{
		userID:    uuid.New(),
		tenantID:  uuid.New(),
		roleID:    uuid.New(),
		permName:  "crm:contacts:read",
		spicedbID: "crm__contacts__read", // colon-to-double-underscore translation
		engine:    engine,
		spiceDB:   spiceDB,
		permRepo:  permRepo,
	}
}

// ---------------------------------------------------------------------------
// Scenario 1: Happy path — user has permission, check succeeds
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_CheckPermission_Granted(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	// Simulate: role has permission "crm:contacts:read", user is assigned the role,
	// SpiceDB reflects the grant.
	f.spiceDB.On("CheckPermission",
		mock.Anything,
		f.tenantID, f.userID,
		"access_grant", f.spicedbID, "check",
	).Return(true, nil)

	result, err := f.engine.CheckPermission(ctx, PermissionRequest{
		UserID:     f.userID,
		TenantID:   f.tenantID,
		Permission: f.permName,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "user with the role should have the permission")
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "granted via SpiceDB")

	f.spiceDB.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Scenario 2: Role removed — permission is denied
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_CheckPermission_DeniedAfterRoleRemoval(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	// SpiceDB no longer has the relationship (role was removed from user)
	f.spiceDB.On("CheckPermission",
		mock.Anything,
		f.tenantID, f.userID,
		"access_grant", f.spicedbID, "check",
	).Return(false, nil)

	result, err := f.engine.CheckPermission(ctx, PermissionRequest{
		UserID:     f.userID,
		TenantID:   f.tenantID,
		Permission: f.permName,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed, "user whose role was removed must not have the permission")
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "denied")

	f.spiceDB.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Scenario 3: Multiple permissions — batch check returns correct map
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_BatchCheck_MixedResults(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	perms := []string{
		"crm:contacts:read",
		"crm:contacts:write",
		"invoicing:invoices:read",
	}

	// Translate permission names to SpiceDB IDs
	spicedbPermsIDs := []string{
		"crm__contacts__read",
		"crm__contacts__write",
		"invoicing__invoices__read",
	}

	// User has read access to CRM and invoicing but not write
	bulkResult := map[string]bool{
		"crm__contacts__read":       true,
		"crm__contacts__write":      false,
		"invoicing__invoices__read": true,
	}

	f.spiceDB.On("CheckBulkPermissions",
		mock.Anything,
		f.tenantID, f.userID,
		"access_grant", spicedbPermsIDs, "check",
	).Return(bulkResult, nil)

	results, err := f.engine.BatchCheckPermissions(ctx, f.userID, f.tenantID, perms)
	require.NoError(t, err)
	require.Len(t, results, 3)

	assert.True(t, results["crm:contacts:read"], "read permission should be granted")
	assert.False(t, results["crm:contacts:write"], "write permission should be denied")
	assert.True(t, results["invoicing:invoices:read"], "invoicing read should be granted")

	f.spiceDB.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Scenario 4: Resource-level permission check (object-level authz)
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_ResourcePermission_OwnerGranted(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	resourceID := uuid.New().String()

	// User owns the invoice, SpiceDB grants "edit"
	f.spiceDB.On("CheckPermission",
		mock.Anything,
		f.tenantID, f.userID,
		"invoice", resourceID, "edit",
	).Return(true, nil)

	result, err := f.engine.CheckResourcePermission(ctx, ResourcePermissionRequest{
		UserID:       f.userID,
		TenantID:     f.tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "edit",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "invoice owner should be able to edit")
	assert.Equal(t, "spicedb", result.Source)

	f.spiceDB.AssertExpectations(t)
}

func TestIntegrationRBAC_ResourcePermission_NonOwnerDenied(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	resourceID := uuid.New().String()

	// User does NOT own the invoice, SpiceDB denies "edit"
	f.spiceDB.On("CheckPermission",
		mock.Anything,
		f.tenantID, f.userID,
		"invoice", resourceID, "edit",
	).Return(false, nil)

	result, err := f.engine.CheckResourcePermission(ctx, ResourcePermissionRequest{
		UserID:       f.userID,
		TenantID:     f.tenantID,
		ResourceType: "invoice",
		ResourceID:   resourceID,
		Action:       "edit",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Allowed, "non-owner must not be able to edit")
	assert.Equal(t, "spicedb", result.Source)

	f.spiceDB.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Scenario 5: Fail-closed — SpiceDB unavailable denies access
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_CheckPermission_FailClosed_SpiceDBNil(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}

	// Engine constructed with nil SpiceDB client (simulates unavailability)
	engine := NewAuthorizationEngine(nil, nil, nil, nil, nil, cfg)

	result, err := engine.CheckPermission(ctx, PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	require.NoError(t, err, "fail-closed must not return an error — it returns a denied result")
	require.NotNil(t, result)
	assert.False(t, result.Allowed, "access must be denied when SpiceDB is unavailable (fail-closed)")
	assert.Contains(t, result.Reason, "unavailable")
}

// ---------------------------------------------------------------------------
// Scenario 6: Contextual permission (OPA disabled — falls back to SpiceDB)
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_ContextualPermission_OPADisabled_SpiceDBFallback(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	// When OPA is nil, CheckContextualPermission falls back to SpiceDB
	// "invoice" + "edit" maps to "invoicing:invoices:edit" module permission
	f.spiceDB.On("CheckPermission",
		mock.Anything,
		f.tenantID, f.userID,
		"access_grant", "invoicing__invoices__edit", "check",
	).Return(true, nil)

	result, err := f.engine.CheckContextualPermission(ctx, ContextualPermissionRequest{
		UserID:       f.userID,
		TenantID:     f.tenantID,
		Action:       "edit",
		ResourceType: "invoice",
		ResourceID:   uuid.New().String(),
		Attributes:   map[string]interface{}{"amount": 100},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed)
	assert.Equal(t, "spicedb", result.Source)
	assert.Contains(t, result.Reason, "OPA unavailable")

	f.spiceDB.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Scenario 7: ZedToken consistency — fresh write is visible on re-check
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_CheckPermission_WithZedToken_Consistent(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	zedToken := "CAESAggB" // example ZedToken value

	// After assigning the role, caller passes ZedToken to guarantee consistency
	f.spiceDB.On("CheckPermissionConsistent",
		mock.Anything,
		f.tenantID, f.userID,
		"access_grant", f.spicedbID, "check", zedToken,
	).Return(true, nil)

	result, err := f.engine.CheckPermission(ctx, PermissionRequest{
		UserID:     f.userID,
		TenantID:   f.tenantID,
		Permission: f.permName,
		ZedToken:   zedToken,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "freshly assigned permission must be visible when ZedToken is used")

	// CheckPermission (eventual) must NOT have been called — only Consistent was used
	f.spiceDB.AssertNotCalled(t, "CheckPermission")
	f.spiceDB.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Scenario 8: Tracing wrappers return same result as underlying methods
// ---------------------------------------------------------------------------

func TestIntegrationRBAC_Tracing_CheckPermissionTraced_SameResult(t *testing.T) {
	f := newRBACFixture()
	ctx := context.Background()

	// Cast to concrete type to access traced methods
	concreteEngine, ok := f.engine.(*authorizationEngine)
	require.True(t, ok, "engine must be *authorizationEngine")

	f.spiceDB.On("CheckPermission",
		mock.Anything,
		f.tenantID, f.userID,
		"access_grant", f.spicedbID, "check",
	).Return(true, nil)

	result, err := concreteEngine.CheckPermissionTraced(ctx, PermissionRequest{
		UserID:     f.userID,
		TenantID:   f.tenantID,
		Permission: f.permName,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Allowed, "traced wrapper must return the same result as untraced CheckPermission")

	f.spiceDB.AssertExpectations(t)
}

// Compile-time guards — keep unused imports from causing build failures.
var _ *models.Role = (*models.Role)(nil)
