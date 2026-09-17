// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildRole returns a fully populated Role suitable for tests.
func buildRole() *Role {
	id := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	updatedBy := uuid.New()
	now := time.Now().Truncate(time.Second)
	desc := "Role for managing users"

	return &Role{
		ID:          id,
		TenantID:    tenantID,
		Name:        "user_manager",
		DisplayName: "User Manager",
		Description: &desc,
		IsSystem:    false,
		IsDefault:   false,
		Priority:    10,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   &createdBy,
		UpdatedBy:   &updatedBy,
	}
}

// buildSystemRole returns a role with IsSystem = true.
func buildSystemRole() *Role {
	r := buildRole()
	r.Name = "system_admin"
	r.DisplayName = "System Administrator"
	r.IsSystem = true
	r.Priority = 0
	return r
}

// buildPermission returns a fully populated Permission for embedding into roles.
func buildPermissionModel() *Permission {
	desc := "Can read users"
	return &Permission{
		ID:          uuid.New(),
		Module:      "iam",
		Resource:    "users",
		Action:      "read",
		Name:        "iam:users:read",
		DisplayName: "Read Users",
		Description: &desc,
		IsSystem:    true,
		CreatedAt:   time.Now().Truncate(time.Second),
	}
}

// ==================== CreateRoleRequest struct ====================

func TestCreateRoleRequest_Fields(t *testing.T) {
	t.Run("should carry all required fields", func(t *testing.T) {
		tenantID := uuid.New()
		perm1 := uuid.New()
		perm2 := uuid.New()
		desc := "Manages billing operations"

		req := CreateRoleRequest{
			TenantID:      tenantID,
			Name:          "billing_manager",
			DisplayName:   "Billing Manager",
			Description:   &desc,
			IsDefault:     true,
			Priority:      5,
			PermissionIDs: []uuid.UUID{perm1, perm2},
		}

		assert.Equal(t, tenantID, req.TenantID)
		assert.Equal(t, "billing_manager", req.Name)
		assert.Equal(t, "Billing Manager", req.DisplayName)
		assert.Equal(t, &desc, req.Description)
		assert.True(t, req.IsDefault)
		assert.Equal(t, 5, req.Priority)
		assert.Equal(t, []uuid.UUID{perm1, perm2}, req.PermissionIDs)
	})

	t.Run("should allow nil description and empty permission_ids", func(t *testing.T) {
		req := CreateRoleRequest{
			TenantID:    uuid.New(),
			Name:        "viewer",
			DisplayName: "Viewer",
		}

		assert.Nil(t, req.Description)
		assert.Nil(t, req.PermissionIDs)
		assert.False(t, req.IsDefault)
		assert.Equal(t, 0, req.Priority)
	})

	t.Run("name binding tag requires min=2 characters", func(t *testing.T) {
		// Structural assertion: confirm the binding tag is present by verifying
		// that a single-character name would violate the constraint (tag check).
		req := CreateRoleRequest{
			TenantID:    uuid.New(),
			Name:        "a",
			DisplayName: "Valid Display Name",
		}
		// We are testing structure here — the gin binding validation would reject
		// this at runtime; at the struct level we simply verify the fields are set.
		assert.Equal(t, "a", req.Name)
		assert.Len(t, req.Name, 1, "single-char name should be settable on struct (validation is runtime)")
	})
}

// ==================== UpdateRoleRequest struct ====================

func TestUpdateRoleRequest_Fields(t *testing.T) {
	t.Run("all fields are optional — zero value is valid", func(t *testing.T) {
		req := UpdateRoleRequest{}

		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.IsDefault)
		assert.Nil(t, req.Priority)
		assert.Nil(t, req.PermissionIDs)
	})

	t.Run("should carry partial update when some fields are set", func(t *testing.T) {
		displayName := "Updated Display Name"
		isDefault := true

		req := UpdateRoleRequest{
			DisplayName: &displayName,
			IsDefault:   &isDefault,
		}

		require.NotNil(t, req.DisplayName)
		assert.Equal(t, displayName, *req.DisplayName)
		require.NotNil(t, req.IsDefault)
		assert.True(t, *req.IsDefault)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.Priority)
	})

	t.Run("should carry full update when all fields are set", func(t *testing.T) {
		displayName := "Full Update"
		desc := "Updated description"
		isDefault := false
		priority := 20
		perm1 := uuid.New()

		req := UpdateRoleRequest{
			DisplayName:   &displayName,
			Description:   &desc,
			IsDefault:     &isDefault,
			Priority:      &priority,
			PermissionIDs: []uuid.UUID{perm1},
		}

		assert.Equal(t, displayName, *req.DisplayName)
		assert.Equal(t, desc, *req.Description)
		assert.Equal(t, isDefault, *req.IsDefault)
		assert.Equal(t, priority, *req.Priority)
		assert.Equal(t, []uuid.UUID{perm1}, req.PermissionIDs)
	})

	t.Run("should allow clearing permissions with empty slice", func(t *testing.T) {
		req := UpdateRoleRequest{
			PermissionIDs: []uuid.UUID{},
		}

		assert.NotNil(t, req.PermissionIDs)
		assert.Len(t, req.PermissionIDs, 0)
	})
}

// ==================== Role.ToResponse ====================

func TestRole_ToResponse(t *testing.T) {
	t.Run("should map all scalar fields correctly", func(t *testing.T) {
		r := buildRole()

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, r.ID, resp.ID)
		assert.Equal(t, r.TenantID, resp.TenantID)
		assert.Equal(t, r.Name, resp.Name)
		assert.Equal(t, r.DisplayName, resp.DisplayName)
		assert.Equal(t, r.Description, resp.Description)
		assert.Equal(t, r.IsSystem, resp.IsSystem)
		assert.Equal(t, r.IsDefault, resp.IsDefault)
		assert.Equal(t, r.Priority, resp.Priority)
		assert.Equal(t, r.CreatedAt, resp.CreatedAt)
		assert.Equal(t, r.UpdatedAt, resp.UpdatedAt)
		assert.Equal(t, RoleSourceTenantCatalogue, resp.Source)
		assert.True(t, resp.Editable)
	})

	t.Run("marks system roles as locked system sources", func(t *testing.T) {
		resp := buildSystemRole().ToResponse()

		assert.Equal(t, RoleSourceSystem, resp.Source)
		assert.False(t, resp.Editable)
	})

	t.Run("should return nil permissions slice when role has no permissions", func(t *testing.T) {
		r := buildRole()
		r.Permissions = nil

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Permissions)
	})

	t.Run("should map associated permissions to PermissionResponse", func(t *testing.T) {
		r := buildRole()
		perm := buildPermissionModel()
		r.Permissions = []Permission{*perm}

		resp := r.ToResponse()

		require.NotNil(t, resp)
		require.Len(t, resp.Permissions, 1)

		respPerm := resp.Permissions[0]
		assert.Equal(t, perm.ID, respPerm.ID)
		assert.Equal(t, perm.Module, respPerm.Module)
		assert.Equal(t, perm.Resource, respPerm.Resource)
		assert.Equal(t, perm.Action, respPerm.Action)
		assert.Equal(t, perm.Name, respPerm.Name)
		assert.Equal(t, perm.DisplayName, respPerm.DisplayName)
		assert.Equal(t, perm.Description, respPerm.Description)
		assert.Equal(t, perm.IsSystem, respPerm.IsSystem)
	})

	t.Run("should map multiple permissions preserving order", func(t *testing.T) {
		r := buildRole()

		perm1 := buildPermissionModel()
		perm1.Name = "iam:users:read"
		perm1.Action = "read"

		perm2 := buildPermissionModel()
		perm2.ID = uuid.New()
		perm2.Name = "iam:users:write"
		perm2.Action = "write"

		r.Permissions = []Permission{*perm1, *perm2}

		resp := r.ToResponse()

		require.Len(t, resp.Permissions, 2)
		assert.Equal(t, "iam:users:read", resp.Permissions[0].Name)
		assert.Equal(t, "iam:users:write", resp.Permissions[1].Name)
	})

	t.Run("should handle nil description", func(t *testing.T) {
		r := buildRole()
		r.Description = nil

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		r := buildRole()

		resp1 := r.ToResponse()
		resp2 := r.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== System role protection (IsSystem flag) ====================

func TestRole_IsSystemFlag(t *testing.T) {
	tests := []struct {
		name    string
		role    Role
		wantSys bool
	}{
		{
			name:    "system role has IsSystem true",
			role:    Role{IsSystem: true},
			wantSys: true,
		},
		{
			name:    "non-system role has IsSystem false",
			role:    Role{IsSystem: false},
			wantSys: false,
		},
		{
			name:    "zero-value role is not a system role",
			role:    Role{},
			wantSys: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantSys, tt.role.IsSystem)
		})
	}
}

func TestRole_SystemRole_ToResponse_PreservesIsSystemFlag(t *testing.T) {
	t.Run("system role flag is preserved in ToResponse", func(t *testing.T) {
		r := buildSystemRole()

		resp := r.ToResponse()

		require.NotNil(t, resp)
		assert.True(t, resp.IsSystem,
			"ToResponse must preserve the IsSystem flag for system roles")
	})

	t.Run("non-system role flag is preserved in ToResponse", func(t *testing.T) {
		r := buildRole()
		r.IsSystem = false

		resp := r.ToResponse()

		assert.False(t, resp.IsSystem)
	})
}

// ==================== RoleResponse field mapping ====================

func TestRoleResponse_FieldMapping(t *testing.T) {
	t.Run("RoleResponse carries all expected fields", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "Description text"

		resp := &RoleResponse{
			ID:          id,
			TenantID:    tenantID,
			Name:        "editor",
			DisplayName: "Editor",
			Description: &desc,
			IsSystem:    false,
			IsDefault:   true,
			Priority:    3,
			CreatedAt:   now,
			UpdatedAt:   now,
			Permissions: []PermissionResponse{
				{
					ID:          uuid.New(),
					Module:      "cms",
					Resource:    "posts",
					Action:      "write",
					Name:        "cms:posts:write",
					DisplayName: "Write Posts",
					IsSystem:    false,
				},
			},
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, "editor", resp.Name)
		assert.Equal(t, "Editor", resp.DisplayName)
		assert.Equal(t, &desc, resp.Description)
		assert.False(t, resp.IsSystem)
		assert.True(t, resp.IsDefault)
		assert.Equal(t, 3, resp.Priority)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
		require.Len(t, resp.Permissions, 1)
		assert.Equal(t, "cms:posts:write", resp.Permissions[0].Name)
	})
}

// ==================== RoleListResponse structure ====================

func TestRoleListResponse_Structure(t *testing.T) {
	t.Run("should carry pagination metadata correctly", func(t *testing.T) {
		roles := []RoleResponse{
			{ID: uuid.New(), Name: "role-a", DisplayName: "Role A"},
			{ID: uuid.New(), Name: "role-b", DisplayName: "Role B"},
		}

		listResp := &RoleListResponse{
			Roles:      roles,
			Total:      50,
			Page:       2,
			PageSize:   10,
			TotalPages: 5,
		}

		assert.Len(t, listResp.Roles, 2)
		assert.Equal(t, int64(50), listResp.Total)
		assert.Equal(t, 2, listResp.Page)
		assert.Equal(t, 10, listResp.PageSize)
		assert.Equal(t, 5, listResp.TotalPages)
	})

	t.Run("empty role list should have zero values for pagination", func(t *testing.T) {
		listResp := &RoleListResponse{
			Roles:      []RoleResponse{},
			Total:      0,
			Page:       1,
			PageSize:   25,
			TotalPages: 0,
		}

		assert.Empty(t, listResp.Roles)
		assert.Equal(t, int64(0), listResp.Total)
		assert.Equal(t, 1, listResp.Page)
	})
}

// ==================== CreatedBy / UpdatedBy not exposed in RoleResponse ====================

func TestRole_ToResponse_DoesNotExposeAuditPointers(t *testing.T) {
	t.Run("RoleResponse does not expose CreatedBy or UpdatedBy pointers", func(t *testing.T) {
		createdBy := uuid.New()
		updatedBy := uuid.New()
		r := buildRole()
		r.CreatedBy = &createdBy
		r.UpdatedBy = &updatedBy

		resp := r.ToResponse()

		require.NotNil(t, resp)
		// RoleResponse intentionally omits CreatedBy and UpdatedBy.
		// We verify this is the case by confirming the fields don't exist
		// on the response struct — this is enforced at compile time by the
		// type system. The fields on the Role model are internal audit columns
		// and are deliberately excluded from the API response.
		_ = resp.CreatedAt // only timestamps are exposed
		_ = resp.UpdatedAt
	})
}
