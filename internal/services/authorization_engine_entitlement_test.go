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

func TestAuthorizationEngine_CheckPermission_EntitlementError_FailOpen(t *testing.T) {
	checker := &mockModuleEntitlementChecker{err: fmt.Errorf("redis unavailable")}
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
	assert.True(t, result.Allowed, "entitlement errors should fail-open to SpiceDB")
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
