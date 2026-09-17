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
)

// ---------------------------------------------------------------------------
// Mock: AuthorizationEngine (for AuthorizeBatch delegation tests)
// ---------------------------------------------------------------------------

type mockAuthorizationEngine struct {
	mock.Mock
}

func (m *mockAuthorizationEngine) CheckPermission(ctx context.Context, req PermissionRequest) (*PermissionResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PermissionResult), args.Error(1)
}

func (m *mockAuthorizationEngine) CheckResourcePermission(ctx context.Context, req ResourcePermissionRequest) (*PermissionResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PermissionResult), args.Error(1)
}

func (m *mockAuthorizationEngine) CheckContextualPermission(ctx context.Context, req ContextualPermissionRequest) (*PermissionResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PermissionResult), args.Error(1)
}

func (m *mockAuthorizationEngine) BatchCheckPermissions(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]bool, error) {
	args := m.Called(ctx, userID, tenantID, permissions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]bool), args.Error(1)
}

func (m *mockAuthorizationEngine) CheckProductAccess(ctx context.Context, req ProductAccessRequest) (*PermissionResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*PermissionResult), args.Error(1)
}

// ---------------------------------------------------------------------------
// Mock: authorizationServicePermRepo (thin wrapper — satisfies only what
// AuthorizationService.AuthorizeBatch() needs via permissionRepo.GetUserPermissions)
// ---------------------------------------------------------------------------

// We reuse the concrete *repositories.PermissionRepository through the service, but
// AuthorizationService holds it as a concrete type. For the fallback path tests we
// build a minimal stub via a local interface.

// ---------------------------------------------------------------------------
// Helper: newAuthzServiceForTest — builds an AuthorizationService with nil repos
// (suitable only for the AuthorizeBatch delegation tests)
// ---------------------------------------------------------------------------

func newAuthzServiceForTest() *AuthorizationService {
	return NewAuthorizationService(nil, nil, nil, nil)
}

// ============================================================================
// GAP 2: AuthorizeBatch — delegation to AuthorizationEngine
// ============================================================================

// TestAuthorizeBatch_DelegatesToEngine verifies that when an AuthorizationEngine
// is wired, AuthorizeBatch forwards the call to BatchCheckPermissions and returns
// its result directly — without touching PostgreSQL.
func TestAuthorizeBatch_DelegatesToEngine(t *testing.T) {
	ctx := context.Background()

	svc := newAuthzServiceForTest()
	engine := new(mockAuthorizationEngine)
	svc.SetAuthorizationEngine(engine)

	userID := uuid.New()
	tenantID := uuid.New()
	permissions := []string{"crm:contacts:read", "crm:contacts:write", "invoicing:invoices:create"}

	engineResults := map[string]bool{
		"crm:contacts:read":         true,
		"crm:contacts:write":        false,
		"invoicing:invoices:create": true,
	}

	engine.On("BatchCheckPermissions", ctx, userID, tenantID, permissions).Return(engineResults, nil)

	resp, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{
		UserID:      userID,
		TenantID:    tenantID,
		Permissions: permissions,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, engineResults, resp.Results)

	engine.AssertCalled(t, "BatchCheckPermissions", ctx, userID, tenantID, permissions)
}

// TestAuthorizeBatch_EngineError_ReturnsError verifies that an error from the
// engine is propagated to the caller.
func TestAuthorizeBatch_EngineError_ReturnsError(t *testing.T) {
	ctx := context.Background()

	svc := newAuthzServiceForTest()
	engine := new(mockAuthorizationEngine)
	svc.SetAuthorizationEngine(engine)

	userID := uuid.New()
	tenantID := uuid.New()
	permissions := []string{"crm:contacts:read"}

	engine.On("BatchCheckPermissions", ctx, userID, tenantID, permissions).
		Return(map[string]bool(nil), errors.New("spicedb unavailable"))

	resp, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{
		UserID:      userID,
		TenantID:    tenantID,
		Permissions: permissions,
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "spicedb unavailable")
}

// TestAuthorizeBatch_NilEngine_FallsBackToPostgres verifies backward compatibility:
// when no engine is set, AuthorizeBatch falls through to the original PostgreSQL
// path (the authzEngine branch is bypassed). The concrete permissionRepo in the
// test service is nil so the call panics, which confirms the engine branch was
// NOT taken (if the engine branch were taken, there would be no panic).
func TestAuthorizeBatch_NilEngine_FallsBackToPostgres(t *testing.T) {
	// No engine wired → falls back to permissionRepo path.
	// Because permissionRepo is a concrete nil *repositories.PermissionRepository,
	// calling its method panics — this proves the code took the fallback (non-engine)
	// path rather than the engine delegation path.
	svc := newAuthzServiceForTest()

	userID := uuid.New()
	tenantID := uuid.New()

	assert.Panics(t, func() {
		_, _ = svc.AuthorizeBatch(context.Background(), &models.BatchAuthorizeRequest{
			UserID:      userID,
			TenantID:    tenantID,
			Permissions: []string{"crm:contacts:read"},
		})
	}, "nil permissionRepo fallback path should panic (proving engine branch was skipped)")
}

// TestAuthorizeBatch_ValidationPassesBeforeEngineDelegate verifies that the
// existing validation (nil userID, empty permissions) fires before the engine
// delegation — meaning the engine is never called for invalid input.
func TestAuthorizeBatch_NilUserID_ReturnsError(t *testing.T) {
	ctx := context.Background()

	svc := newAuthzServiceForTest()
	engine := new(mockAuthorizationEngine)
	svc.SetAuthorizationEngine(engine)

	_, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{
		UserID:      uuid.Nil,
		TenantID:    uuid.New(),
		Permissions: []string{"crm:contacts:read"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
	// Engine must not be called for invalid requests
	engine.AssertNotCalled(t, "BatchCheckPermissions")
}

func TestAuthorizeBatch_EmptyPermissions_ReturnsError(t *testing.T) {
	ctx := context.Background()

	svc := newAuthzServiceForTest()
	engine := new(mockAuthorizationEngine)
	svc.SetAuthorizationEngine(engine)

	_, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{
		UserID:      uuid.New(),
		TenantID:    uuid.New(),
		Permissions: []string{},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one permission is required")
	engine.AssertNotCalled(t, "BatchCheckPermissions")
}

// TestAuthorizeBatch_EngineReturnsAllDenied ensures we correctly handle an engine
// result where every permission is denied — not confused with an error.
func TestAuthorizeBatch_EngineReturnsAllDenied(t *testing.T) {
	ctx := context.Background()

	svc := newAuthzServiceForTest()
	engine := new(mockAuthorizationEngine)
	svc.SetAuthorizationEngine(engine)

	userID := uuid.New()
	tenantID := uuid.New()
	permissions := []string{"crm:contacts:read", "crm:contacts:write"}

	engine.On("BatchCheckPermissions", ctx, userID, tenantID, permissions).Return(
		map[string]bool{
			"crm:contacts:read":  false,
			"crm:contacts:write": false,
		}, nil)

	resp, err := svc.AuthorizeBatch(ctx, &models.BatchAuthorizeRequest{
		UserID:      userID,
		TenantID:    tenantID,
		Permissions: permissions,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Results["crm:contacts:read"])
	assert.False(t, resp.Results["crm:contacts:write"])
}
