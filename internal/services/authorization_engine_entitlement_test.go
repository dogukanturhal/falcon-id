// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// --- Mock ---

type mockModuleEntitlementChecker struct {
	entitled bool
	err      error
	module   string
}

func (m *mockModuleEntitlementChecker) IsTenantEntitled(_ context.Context, _ uuid.UUID, module string) (bool, error) {
	m.module = module
	return m.entitled, m.err
}

// --- Tests ---

func TestAuthorizationEngine_CheckPermission_EntitlementDenied(t *testing.T) {
	checker := &mockModuleEntitlementChecker{entitled: false}
	mockSpiceDB := new(MockSpiceDBChecker)
	// SpiceDB should NOT be called when entitlement denies
	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	assert.NoError(t, err)
	assert.False(t, result.Allowed, "should deny when module not entitled")
	assert.Contains(t, result.Reason, "module not entitled")
	assert.Equal(t, "crm", checker.module)
	mockSpiceDB.AssertNotCalled(t, "CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthorizationEngine_CheckPermission_EntitlementGranted(t *testing.T) {
	checker := &mockModuleEntitlementChecker{entitled: true}
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSpiceDB.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	assert.NoError(t, err)
	assert.True(t, result.Allowed, "should proceed to SpiceDB when entitled")
	mockSpiceDB.AssertCalled(t, "CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthorizationEngine_CheckPermission_NilEntitlementChecker_SkipsCheck(t *testing.T) {
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSpiceDB.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	// No entitlement checker set

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	assert.NoError(t, err)
	assert.True(t, result.Allowed, "should proceed to SpiceDB when no checker set")
}

// TestAuthorizationEngine_CheckPermission_EntitlementError_FailClosed is the
// spec 23 §1.4 regression test: an entitlement-checker error must deny the
// permission with a distinct reason code, not silently proceed to SpiceDB.
// SpiceDB is never even consulted, proving the guard — not SpiceDB — is
// what denies the request.
func TestAuthorizationEngine_CheckPermission_EntitlementError_FailClosed(t *testing.T) {
	checker := &mockModuleEntitlementChecker{err: fmt.Errorf("redis unavailable")}
	mockSpiceDB := new(MockSpiceDBChecker)
	// SpiceDB should NOT be called when the entitlement check itself errors.

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})

	assert.NoError(t, err)
	assert.False(t, result.Allowed, "entitlement-checker errors must fail-closed (deny), never proceed to SpiceDB")
	assert.Contains(t, result.Reason, "entitlement check unavailable")
	mockSpiceDB.AssertNotCalled(t, "CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestBatchCheckPermissions_EntitlementError_FailClosed mirrors the
// CheckPermission case above for the batch path (POST /authorize/batch):
// an entitlement-checker error must exclude the permission from the result
// (i.e. deny it), never let the bulk SpiceDB call decide alone.
func TestBatchCheckPermissions_EntitlementError_FailClosed(t *testing.T) {
	checker := &mockModuleEntitlementChecker{err: fmt.Errorf("redis unavailable")}
	mockSpiceDB := new(MockSpiceDBChecker)
	// If consulted, SpiceDB would grant it — proving the guard, not SpiceDB,
	// denies "crm:contacts:read" below.
	mockSpiceDB.On("CheckBulkPermissions", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(map[string]bool{"crm__contacts__read": true}, nil)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	results, err := engine.BatchCheckPermissions(context.Background(), uuid.New(), uuid.New(), []string{"crm:contacts:read"})
	assert.NoError(t, err)
	assert.False(t, results["crm:contacts:read"], "entitlement-checker errors must fail-closed (deny) in the batch path too")
}

func TestAuthorizationEngine_CheckPermission_NonModulePermission_SkipsEntitlement(t *testing.T) {
	checker := &mockModuleEntitlementChecker{entitled: false}
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSpiceDB.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	// Permission without module:resource:action format should skip entitlement
	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "admin_access",
	})

	assert.NoError(t, err)
	assert.True(t, result.Allowed, "non-module permissions should skip entitlement check")
}

// TestAuthorizationEngine_CheckPermission_UniversalModule_SkipsEntitlement
// reproduces the Settings -> Team bug: a tenant whose only active product
// instance is a paid module (e.g. "acmeweb") is reported "not entitled" for
// "iam"/"core" by DefaultModuleEntitlementChecker (its manifest declares no
// iam/core resources), yet every tenant must always have core/iam
// permissions regardless of subscription — that's exactly what
// UniversalModules documents and what RoleService.getEntitledModules /
// PermissionService's module listing already special-case. CheckPermission
// must agree with them.
func TestAuthorizationEngine_CheckPermission_UniversalModule_SkipsEntitlement(t *testing.T) {
	checker := &mockModuleEntitlementChecker{entitled: false} // tenant not entitled to ANY module
	mockSpiceDB := new(MockSpiceDBChecker)
	mockSpiceDB.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	for _, perm := range []string{"iam:users:read", "iam:invitations:read", "core:roles:read"} {
		result, err := engine.CheckPermission(context.Background(), PermissionRequest{
			UserID:     uuid.New(),
			TenantID:   uuid.New(),
			Permission: perm,
		})
		assert.NoError(t, err)
		assert.True(t, result.Allowed, "%s is a universal module and must never be denied for lack of entitlement", perm)
	}

	// Control: the entitlement guard must still fire for a NON-universal
	// module even with the same "not entitled" checker — otherwise the fix
	// would be a blanket bypass rather than the documented core/iam carve-out.
	result, err := engine.CheckPermission(context.Background(), PermissionRequest{
		UserID:     uuid.New(),
		TenantID:   uuid.New(),
		Permission: "crm:contacts:read",
	})
	assert.NoError(t, err)
	assert.False(t, result.Allowed, "control: non-universal module must still be denied when not entitled")
	assert.Contains(t, result.Reason, "module not entitled")
}

// TestBatchCheckPermissions_AgreesWithCheckPermission_OnEntitlement is the
// direct regression test for the Settings -> Team divergence: before this
// fix, BatchCheckPermissions (POST /authorize/batch) never ran the
// sunset/entitlement guards CheckPermission (RequirePermission middleware)
// applies, so batch could report a permission "allowed" purely from
// SpiceDB while the real endpoint denied it as not-entitled. This asserts
// both authorities now agree, with a control (a non-universal, not-entitled
// module) proving the guard still denies when it should.
func TestBatchCheckPermissions_AgreesWithCheckPermission_OnEntitlement(t *testing.T) {
	checker := &mockModuleEntitlementChecker{entitled: false} // no active core/iam-declaring product
	mockSpiceDB := new(MockSpiceDBChecker)
	// SpiceDB, if consulted, would grant everything — proving the guard, not
	// SpiceDB, is what denies "crm:contacts:read" below.
	mockSpiceDB.On("CheckBulkPermissions", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(map[string]bool{
			"iam__users__read":       true,
			"iam__invitations__read": true,
			"core__roles__read":      true,
			"crm__contacts__read":    true,
		}, nil)

	cfg := &config.Config{}
	engine := NewAuthorizationEngine(nil, nil, nil, nil, mockSpiceDB, cfg)
	engine.(*authorizationEngine).SetModuleEntitlementChecker(checker)

	userID, tenantID := uuid.New(), uuid.New()
	results, err := engine.BatchCheckPermissions(context.Background(), userID, tenantID, []string{
		"iam:users:read", "iam:invitations:read", "core:roles:read", "crm:contacts:read",
	})
	assert.NoError(t, err)

	assert.True(t, results["iam:users:read"], "universal module permission must be allowed, matching CheckPermission")
	assert.True(t, results["iam:invitations:read"], "universal module permission must be allowed, matching CheckPermission")
	assert.True(t, results["core:roles:read"], "universal module permission must be allowed, matching CheckPermission")
	// Control: crm is NOT a universal module and the checker says
	// not-entitled, so this must be denied even though the mocked SpiceDB
	// bulk call above would have granted it — proving the guard fires.
	assert.False(t, results["crm:contacts:read"], "control: non-universal not-entitled module must be denied pre-SpiceDB")
}
