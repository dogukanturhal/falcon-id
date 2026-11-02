// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

type fakeRoleAPIKeyUsage struct{ n int }

func (f fakeRoleAPIKeyUsage) CountActiveTenantKeysByRole(context.Context, uuid.UUID, uuid.UUID) (int, error) {
	return f.n, nil
}

func guardFixture(t *testing.T, keys int) (*RoleService, *mockRoleServiceRoleRepo, *models.Role, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	role := &models.Role{ID: uuid.New(), TenantID: uuid.New(), Name: "reporting"}
	okID, badID := uuid.New(), uuid.New()
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)
	svc.SetAPIKeyRoleUsage(fakeRoleAPIKeyUsage{n: keys})
	roleRepo.On("GetByID", ctx, role.ID).Return(role, nil)
	roleRepo.On("GetRolePermissions", ctx, role.ID).Return([]models.Permission{{Name: "core:contacts:read"}}, nil)
	permRepo.On("GetPermissionNamesByIDs", ctx, []uuid.UUID{okID, badID}).
		Return(map[uuid.UUID]string{okID: "core:contacts:read", badID: "iam:users:manage"}, nil)
	return svc, roleRepo, role, okID, badID
}

func TestAssignPermissions_ForbiddenForAPIKey_RefusedWhenKeysHoldRole(t *testing.T) {
	svc, roleRepo, role, okID, badID := guardFixture(t, 2)

	err := svc.AssignPermissions(context.Background(), role.ID, []uuid.UUID{okID, badID}, nil)

	var keyErr *RoleUsedByAPIKeysError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, 2, keyErr.KeyCount)
	assert.Equal(t, "iam:users:manage", keyErr.Permission)
	roleRepo.AssertNotCalled(t, "AssignPermissions")
}

func TestGuardAPIKeyRoleGrant_AllowedWhenNoKeyHoldsRole(t *testing.T) {
	svc, _, role, okID, badID := guardFixture(t, 0)

	require.NoError(t, svc.guardAPIKeyRoleGrant(context.Background(), role, []uuid.UUID{okID, badID}))
}

func TestAssignPermissions_AlreadyHeldForbiddenPermissionIsNotAnAddition(t *testing.T) {
	ctx := context.Background()
	role := &models.Role{ID: uuid.New(), TenantID: uuid.New(), Name: "legacy"}
	badID := uuid.New()
	roleRepo := new(mockRoleServiceRoleRepo)
	permRepo := new(mockRoleServicePermissionRepo)
	svc, _ := newRoleServiceForTest(t, roleRepo, permRepo)
	svc.SetAPIKeyRoleUsage(fakeRoleAPIKeyUsage{n: 3})
	roleRepo.On("GetRolePermissions", ctx, role.ID).Return([]models.Permission{{Name: "iam:users:manage"}}, nil)
	permRepo.On("GetPermissionNamesByIDs", ctx, []uuid.UUID{badID}).Return(map[uuid.UUID]string{badID: "iam:users:manage"}, nil)

	require.NoError(t, svc.guardAPIKeyRoleGrant(ctx, role, []uuid.UUID{badID}))
}
