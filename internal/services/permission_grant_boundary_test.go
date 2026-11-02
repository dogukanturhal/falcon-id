// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// CheckPermissionGrantBoundary
// ---------------------------------------------------------------------------

func TestCheckPermissionGrantBoundary_PlatformPermission_InternalTenant_Allowed(t *testing.T) {
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	internalTenantID := uuid.MustParse(models.HexxlockInternalTenantID)
	perm := &models.Permission{ID: uuid.New(), Name: "platform:applications:read", Module: "platform"}

	err := svc.CheckPermissionGrantBoundary(context.Background(), internalTenantID, perm)

	assert.NoError(t, err)
}

func TestCheckPermissionGrantBoundary_PlatformPermission_OutsideInternalTenant_Rejected(t *testing.T) {
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	tenantID := uuid.New() // any tenant other than the internal one
	perm := &models.Permission{ID: uuid.New(), Name: "platform:applications:read", Module: "platform"}

	err := svc.CheckPermissionGrantBoundary(context.Background(), tenantID, perm)

	require.Error(t, err)
	var boundaryErr *PermissionGrantBoundaryError
	require.ErrorAs(t, err, &boundaryErr)
	assert.Equal(t, CodePlatformRoleRequiresInternalTenant, boundaryErr.Code)
}

func TestCheckPermissionGrantBoundary_EntitledModule_Allowed(t *testing.T) {
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	tenantID := uuid.New()
	checker := &mockModuleEntitlementChecker{entitled: true}
	svc.SetModuleEntitlementChecker(checker)
	permRepo.On("GetModules", context.Background()).Return([]string{"crm"}, nil)

	perm := &models.Permission{ID: uuid.New(), Name: "crm:contacts:read", Module: "crm"}

	err := svc.CheckPermissionGrantBoundary(context.Background(), tenantID, perm)

	assert.NoError(t, err)
	assert.Equal(t, "crm", checker.module)
}

// TestCheckPermissionGrantBoundary_UnentitledModule_Rejected is the ADR-A10
// acceptance test called out by the task: a tenant admin cannot escalate a
// role's permissions beyond their own tenant's module entitlements, even
// when nothing else about the request (caller identity, role ownership)
// is malformed.
func TestCheckPermissionGrantBoundary_UnentitledModule_Rejected(t *testing.T) {
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	tenantID := uuid.New()
	checker := &mockModuleEntitlementChecker{entitled: false}
	svc.SetModuleEntitlementChecker(checker)
	permRepo.On("GetModules", context.Background()).Return([]string{"accounting"}, nil)

	perm := &models.Permission{ID: uuid.New(), Name: "accounting:journal_entries:approve", Module: "accounting"}

	err := svc.CheckPermissionGrantBoundary(context.Background(), tenantID, perm)

	require.Error(t, err)
	var boundaryErr *PermissionGrantBoundaryError
	require.ErrorAs(t, err, &boundaryErr)
	assert.Equal(t, CodeEntitlementMissingForModule, boundaryErr.Code)
}

func TestCheckPermissionGrantBoundary_NoEntitlementCheckerWired_FailsClosedToUniversalModules(t *testing.T) {
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)
	// Deliberately no SetModuleEntitlementChecker call — simulates
	// r1-entitlements not being merged yet, per the task's explicit
	// instruction to "go through an interface with the current source,
	// fail closed" in that case.

	tenantID := uuid.New()

	universalPerm := &models.Permission{ID: uuid.New(), Name: "core:users:read", Module: "core"}
	require.NoError(t, svc.CheckPermissionGrantBoundary(context.Background(), tenantID, universalPerm))

	nonUniversalPerm := &models.Permission{ID: uuid.New(), Name: "crm:contacts:read", Module: "crm"}
	err := svc.CheckPermissionGrantBoundary(context.Background(), tenantID, nonUniversalPerm)
	require.Error(t, err)
	var boundaryErr *PermissionGrantBoundaryError
	require.ErrorAs(t, err, &boundaryErr)
	assert.Equal(t, CodeEntitlementMissingForModule, boundaryErr.Code)
}

func TestCheckPermissionGrantBoundary_NilPermission_Errors(t *testing.T) {
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	err := svc.CheckPermissionGrantBoundary(context.Background(), uuid.New(), nil)

	require.Error(t, err)
	var boundaryErr *PermissionGrantBoundaryError
	assert.False(t, errors.As(err, &boundaryErr), "a nil-permission programming error should not be reported as a boundary violation")
}

// ---------------------------------------------------------------------------
// GrantPermission (POST /internal/v1/roles/{id}/actions/grant-permission)
// ---------------------------------------------------------------------------

func TestRoleService_GrantPermission_EntitlementMissing_Returns403Code(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	permID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)
	checker := &mockModuleEntitlementChecker{entitled: false}
	svc.SetModuleEntitlementChecker(checker)
	permRepo.On("GetModules", ctx).Return([]string{"accounting"}, nil)

	role := &models.Role{ID: roleID, TenantID: tenantID, Name: "editor"}
	perm := &models.Permission{ID: permID, Name: "accounting:journal_entries:approve", Module: "accounting"}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	permRepo.On("GetByID", ctx, permID).Return(perm, nil)

	_, err := svc.GrantPermission(ctx, roleID, permID, nil)

	require.Error(t, err)
	var boundaryErr *PermissionGrantBoundaryError
	require.ErrorAs(t, err, &boundaryErr)
	assert.Equal(t, CodeEntitlementMissingForModule, boundaryErr.Code)
	roleRepo.AssertNotCalled(t, "GrantPermissionsByName")
}

func TestRoleService_GrantPermission_PlatformOutsideInternalTenant_Returns403Code(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New() // not the internal tenant
	permID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)

	role := &models.Role{ID: roleID, TenantID: tenantID, Name: "platform-admin"}
	perm := &models.Permission{ID: permID, Name: "platform:tenants:suspend", Module: "platform"}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	permRepo.On("GetByID", ctx, permID).Return(perm, nil)

	_, err := svc.GrantPermission(ctx, roleID, permID, nil)

	require.Error(t, err)
	var boundaryErr *PermissionGrantBoundaryError
	require.ErrorAs(t, err, &boundaryErr)
	assert.Equal(t, CodePlatformRoleRequiresInternalTenant, boundaryErr.Code)
}

func TestRoleService_GrantPermission_Entitled_Succeeds(t *testing.T) {
	ctx := context.Background()
	roleID := uuid.New()
	tenantID := uuid.New()
	permID := uuid.New()

	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)
	checker := &mockModuleEntitlementChecker{entitled: true}
	svc.SetModuleEntitlementChecker(checker)
	permRepo.On("GetModules", ctx).Return([]string{"crm"}, nil)

	role := &models.Role{ID: roleID, TenantID: tenantID, Name: "editor"}
	perm := &models.Permission{ID: permID, Name: "crm:contacts:read", Module: "crm"}

	roleRepo.On("GetByID", ctx, roleID).Return(role, nil)
	permRepo.On("GetByID", ctx, permID).Return(perm, nil)
	roleRepo.On("GrantPermissionsByName", ctx, roleID, []string{perm.Name}).Return(nil)

	got, err := svc.GrantPermission(ctx, roleID, permID, nil)

	require.NoError(t, err)
	assert.Equal(t, perm.Name, got.Name)
}
