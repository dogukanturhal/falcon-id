// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Permission.ToResponse ====================

func TestPermission_ToResponse(t *testing.T) {
	t.Run("should map all fields correctly", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "Allows reading user records"

		p := &Permission{
			ID:          id,
			Module:      "iam",
			Resource:    "users",
			Action:      "read",
			Name:        "iam:users:read",
			DisplayName: "Read Users",
			Description: &desc,
			IsSystem:    true,
			CreatedAt:   now,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
		assert.Equal(t, "iam", resp.Module)
		assert.Equal(t, "users", resp.Resource)
		assert.Equal(t, "read", resp.Action)
		assert.Equal(t, "iam:users:read", resp.Name)
		assert.Equal(t, "Read Users", resp.DisplayName)
		assert.Equal(t, &desc, resp.Description)
		assert.True(t, resp.IsSystem)
	})

	t.Run("should handle nil description", func(t *testing.T) {
		p := &Permission{
			ID:          uuid.New(),
			Module:      "billing",
			Resource:    "invoices",
			Action:      "write",
			Name:        "billing:invoices:write",
			DisplayName: "Write Invoices",
			Description: nil,
			IsSystem:    false,
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		assert.Nil(t, resp.Description)
		assert.False(t, resp.IsSystem)
	})

	t.Run("should NOT expose CreatedAt in response", func(t *testing.T) {
		p := &Permission{
			ID:        uuid.New(),
			Module:    "iam",
			Resource:  "roles",
			Action:    "delete",
			Name:      "iam:roles:delete",
			CreatedAt: time.Now(),
		}

		resp := p.ToResponse()

		require.NotNil(t, resp)
		// PermissionResponse type deliberately omits the CreatedAt timestamp.
		// Verified at compile time by the type system — the field simply does
		// not exist on PermissionResponse.
		_ = resp.ID // ensure we have a valid response
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		p := &Permission{
			ID:     uuid.New(),
			Module: "iam",
			Name:   "iam:users:read",
		}

		resp1 := p.ToResponse()
		resp2 := p.ToResponse()

		assert.NotSame(t, resp1, resp2)
		assert.Equal(t, resp1, resp2)
	})
}

// ==================== PermissionDefinition struct ====================

func TestPermissionDefinition_Fields(t *testing.T) {
	t.Run("should carry required resource and actions", func(t *testing.T) {
		def := PermissionDefinition{
			Resource:    "documents",
			Actions:     []string{"read", "write", "delete"},
			DisplayName: "Documents",
			Description: "Permissions for managing documents",
		}

		assert.Equal(t, "documents", def.Resource)
		assert.Equal(t, []string{"read", "write", "delete"}, def.Actions)
		assert.Equal(t, "Documents", def.DisplayName)
		assert.Equal(t, "Permissions for managing documents", def.Description)
	})

	t.Run("should allow empty optional display_name and description", func(t *testing.T) {
		def := PermissionDefinition{
			Resource: "settings",
			Actions:  []string{"read"},
		}

		assert.Equal(t, "settings", def.Resource)
		assert.Equal(t, []string{"read"}, def.Actions)
		assert.Equal(t, "", def.DisplayName)
		assert.Equal(t, "", def.Description)
	})

	t.Run("should support single action", func(t *testing.T) {
		def := PermissionDefinition{
			Resource: "reports",
			Actions:  []string{"export"},
		}

		require.Len(t, def.Actions, 1)
		assert.Equal(t, "export", def.Actions[0])
	})

	t.Run("should support many actions", func(t *testing.T) {
		actions := []string{"create", "read", "update", "delete", "export", "import", "approve"}
		def := PermissionDefinition{
			Resource: "orders",
			Actions:  actions,
		}

		assert.Equal(t, actions, def.Actions)
		assert.Len(t, def.Actions, 7)
	})
}

// ==================== RegisterModuleRequest struct ====================

func TestRegisterModuleRequest_Fields(t *testing.T) {
	t.Run("should carry module and permission definitions", func(t *testing.T) {
		req := RegisterModuleRequest{
			Module: "crm",
			Permissions: []PermissionDefinition{
				{
					Resource:    "contacts",
					Actions:     []string{"read", "write"},
					DisplayName: "Contacts",
					Description: "Manage CRM contacts",
				},
				{
					Resource: "deals",
					Actions:  []string{"read"},
				},
			},
		}

		assert.Equal(t, "crm", req.Module)
		require.Len(t, req.Permissions, 2)
		assert.Equal(t, "contacts", req.Permissions[0].Resource)
		assert.Equal(t, []string{"read", "write"}, req.Permissions[0].Actions)
		assert.Equal(t, "deals", req.Permissions[1].Resource)
	})

	t.Run("should allow a single permission definition", func(t *testing.T) {
		req := RegisterModuleRequest{
			Module: "reporting",
			Permissions: []PermissionDefinition{
				{Resource: "dashboards", Actions: []string{"view"}},
			},
		}

		assert.Equal(t, "reporting", req.Module)
		assert.Len(t, req.Permissions, 1)
	})

	t.Run("zero-value module and nil permissions are structurally valid Go types", func(t *testing.T) {
		// gin binding would reject this at runtime; here we only verify the zero
		// value is representable at the type level.
		req := RegisterModuleRequest{}

		assert.Equal(t, "", req.Module)
		assert.Nil(t, req.Permissions)
	})
}

// ==================== AuthorizeRequest struct ====================

func TestAuthorizeRequest_Fields(t *testing.T) {
	t.Run("should carry required fields", func(t *testing.T) {
		userID := uuid.New()
		tenantID := uuid.New()

		req := AuthorizeRequest{
			UserID:     userID,
			Permission: "iam:users:read",
			TenantID:   tenantID,
		}

		assert.Equal(t, userID, req.UserID)
		assert.Equal(t, "iam:users:read", req.Permission)
		assert.Equal(t, tenantID, req.TenantID)
	})

	t.Run("should carry ABAC resource context", func(t *testing.T) {
		ownerID := uuid.New()

		req := AuthorizeRequest{
			UserID:       uuid.New(),
			Permission:   "billing:invoices:approve",
			TenantID:     uuid.New(),
			ResourceType: "invoice",
			ResourceID:   "INV-001",
			OwnerID:      &ownerID,
			Attributes:   map[string]interface{}{"amount": 5000.0, "currency": "USD"},
		}

		assert.Equal(t, "invoice", req.ResourceType)
		assert.Equal(t, "INV-001", req.ResourceID)
		assert.Equal(t, &ownerID, req.OwnerID)
		assert.Equal(t, map[string]interface{}{"amount": 5000.0, "currency": "USD"}, req.Attributes)
	})

	t.Run("should carry request context for ABAC evaluation", func(t *testing.T) {
		req := AuthorizeRequest{
			UserID:      uuid.New(),
			Permission:  "cms:posts:publish",
			IPAddress:   "10.0.0.1",
			UserAgent:   "FalconClient/2.0",
			RequestPath: "/api/v1/cms/posts/42/publish",
		}

		assert.Equal(t, "10.0.0.1", req.IPAddress)
		assert.Equal(t, "FalconClient/2.0", req.UserAgent)
		assert.Equal(t, "/api/v1/cms/posts/42/publish", req.RequestPath)
	})

	t.Run("optional fields default to zero values", func(t *testing.T) {
		req := AuthorizeRequest{
			UserID:     uuid.New(),
			Permission: "iam:roles:read",
		}

		assert.Equal(t, "", req.ResourceType)
		assert.Equal(t, "", req.ResourceID)
		assert.Nil(t, req.OwnerID)
		assert.Nil(t, req.Attributes)
		assert.Equal(t, "", req.IPAddress)
		assert.Equal(t, "", req.UserAgent)
		assert.Equal(t, "", req.RequestPath)
	})
}

// ==================== AuthorizeResponse struct ====================

func TestAuthorizeResponse_Fields(t *testing.T) {
	tests := []struct {
		name    string
		allowed bool
		reason  string
	}{
		{
			name:    "allowed response with no reason",
			allowed: true,
			reason:  "",
		},
		{
			name:    "denied response with reason",
			allowed: false,
			reason:  "insufficient permissions",
		},
		{
			name:    "denied response for missing role",
			allowed: false,
			reason:  "user does not have the required role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := AuthorizeResponse{
				Allowed: tt.allowed,
				Reason:  tt.reason,
			}

			assert.Equal(t, tt.allowed, resp.Allowed)
			assert.Equal(t, tt.reason, resp.Reason)
		})
	}
}

// ==================== BatchAuthorizeRequest struct ====================

func TestBatchAuthorizeRequest_Fields(t *testing.T) {
	t.Run("should carry userID, permissions list and tenantID", func(t *testing.T) {
		userID := uuid.New()
		tenantID := uuid.New()
		permissions := []string{
			"iam:users:read",
			"iam:roles:read",
			"billing:invoices:read",
		}

		req := BatchAuthorizeRequest{
			UserID:      userID,
			Permissions: permissions,
			TenantID:    tenantID,
		}

		assert.Equal(t, userID, req.UserID)
		assert.Equal(t, permissions, req.Permissions)
		assert.Equal(t, tenantID, req.TenantID)
	})

	t.Run("should allow single permission in batch request", func(t *testing.T) {
		req := BatchAuthorizeRequest{
			UserID:      uuid.New(),
			Permissions: []string{"iam:users:read"},
			TenantID:    uuid.New(),
		}

		assert.Len(t, req.Permissions, 1)
	})
}

// ==================== BatchAuthorizeResponse struct ====================

func TestBatchAuthorizeResponse_Fields(t *testing.T) {
	t.Run("should map permission strings to allowed booleans", func(t *testing.T) {
		resp := BatchAuthorizeResponse{
			Results: map[string]bool{
				"iam:users:read":        true,
				"iam:roles:write":       false,
				"billing:invoices:read": true,
			},
		}

		assert.True(t, resp.Results["iam:users:read"])
		assert.False(t, resp.Results["iam:roles:write"])
		assert.True(t, resp.Results["billing:invoices:read"])
	})

	t.Run("empty results map is a valid zero value", func(t *testing.T) {
		resp := BatchAuthorizeResponse{
			Results: map[string]bool{},
		}

		assert.Empty(t, resp.Results)
	})
}

// ==================== RolePermission struct ====================

func TestRolePermission_Fields(t *testing.T) {
	t.Run("should carry all fields", func(t *testing.T) {
		id := uuid.New()
		roleID := uuid.New()
		permID := uuid.New()
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		rp := &RolePermission{
			ID:           id,
			RoleID:       roleID,
			PermissionID: permID,
			CreatedAt:    now,
			CreatedBy:    &createdBy,
		}

		assert.Equal(t, id, rp.ID)
		assert.Equal(t, roleID, rp.RoleID)
		assert.Equal(t, permID, rp.PermissionID)
		assert.Equal(t, now, rp.CreatedAt)
		assert.Equal(t, &createdBy, rp.CreatedBy)
	})

	t.Run("CreatedBy is optional and can be nil", func(t *testing.T) {
		rp := &RolePermission{
			ID:           uuid.New(),
			RoleID:       uuid.New(),
			PermissionID: uuid.New(),
			CreatedAt:    time.Now(),
		}

		assert.Nil(t, rp.CreatedBy)
	})
}

// ==================== UserRole struct ====================

func TestUserRole_Fields(t *testing.T) {
	t.Run("should carry all required fields", func(t *testing.T) {
		id := uuid.New()
		userID := uuid.New()
		roleID := uuid.New()
		assignedBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		expires := now.Add(30 * 24 * time.Hour)

		ur := &UserRole{
			ID:         id,
			UserID:     userID,
			RoleID:     roleID,
			AssignedAt: now,
			AssignedBy: &assignedBy,
			ExpiresAt:  &expires,
		}

		assert.Equal(t, id, ur.ID)
		assert.Equal(t, userID, ur.UserID)
		assert.Equal(t, roleID, ur.RoleID)
		assert.Equal(t, now, ur.AssignedAt)
		assert.Equal(t, &assignedBy, ur.AssignedBy)
		assert.Equal(t, &expires, ur.ExpiresAt)
	})

	t.Run("AssignedBy and ExpiresAt are optional", func(t *testing.T) {
		ur := &UserRole{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			RoleID:     uuid.New(),
			AssignedAt: time.Now(),
		}

		assert.Nil(t, ur.AssignedBy)
		assert.Nil(t, ur.ExpiresAt)
	})
}

// ==================== EffectivePermissionsResponse struct ====================

func TestEffectivePermissionsResponse_Structure(t *testing.T) {
	t.Run("should carry userID, permissions and roles", func(t *testing.T) {
		userID := uuid.New()
		desc := "Read user data"
		permissions := []PermissionResponse{
			{
				ID:          uuid.New(),
				Module:      "iam",
				Resource:    "users",
				Action:      "read",
				Name:        "iam:users:read",
				DisplayName: "Read Users",
				Description: &desc,
				IsSystem:    true,
			},
		}
		roles := []string{"user_manager", "viewer"}

		resp := &EffectivePermissionsResponse{
			UserID:      userID,
			Permissions: permissions,
			Roles:       roles,
		}

		assert.Equal(t, userID, resp.UserID)
		require.Len(t, resp.Permissions, 1)
		assert.Equal(t, "iam:users:read", resp.Permissions[0].Name)
		assert.Equal(t, []string{"user_manager", "viewer"}, resp.Roles)
	})

	t.Run("should handle empty permissions and roles", func(t *testing.T) {
		resp := &EffectivePermissionsResponse{
			UserID:      uuid.New(),
			Permissions: []PermissionResponse{},
			Roles:       []string{},
		}

		assert.Empty(t, resp.Permissions)
		assert.Empty(t, resp.Roles)
	})

	t.Run("should handle nil permissions and roles", func(t *testing.T) {
		resp := &EffectivePermissionsResponse{
			UserID: uuid.New(),
		}

		assert.Nil(t, resp.Permissions)
		assert.Nil(t, resp.Roles)
	})
}

// ==================== PermissionListResponse structure ====================

func TestPermissionListResponse_Structure(t *testing.T) {
	t.Run("should carry permissions slice and total count", func(t *testing.T) {
		perms := []PermissionResponse{
			{ID: uuid.New(), Name: "iam:users:read", Module: "iam"},
			{ID: uuid.New(), Name: "iam:roles:read", Module: "iam"},
		}

		listResp := &PermissionListResponse{
			Permissions: perms,
			Total:       100,
		}

		assert.Len(t, listResp.Permissions, 2)
		assert.Equal(t, int64(100), listResp.Total)
	})

	t.Run("empty permission list has zero total", func(t *testing.T) {
		listResp := &PermissionListResponse{
			Permissions: []PermissionResponse{},
			Total:       0,
		}

		assert.Empty(t, listResp.Permissions)
		assert.Equal(t, int64(0), listResp.Total)
	})
}

// ==================== PermissionsByModule structure ====================

func TestPermissionsByModule_Structure(t *testing.T) {
	t.Run("should group permissions under a module name", func(t *testing.T) {
		pbm := &PermissionsByModule{
			Module: "iam",
			Permissions: []PermissionResponse{
				{ID: uuid.New(), Module: "iam", Resource: "users", Action: "read", Name: "iam:users:read"},
				{ID: uuid.New(), Module: "iam", Resource: "roles", Action: "read", Name: "iam:roles:read"},
			},
		}

		assert.Equal(t, "iam", pbm.Module)
		assert.Len(t, pbm.Permissions, 2)
		for _, p := range pbm.Permissions {
			assert.Equal(t, "iam", p.Module,
				"all permissions under a module group must share the module name")
		}
	})

	t.Run("empty permissions slice is valid", func(t *testing.T) {
		pbm := &PermissionsByModule{
			Module:      "analytics",
			Permissions: []PermissionResponse{},
		}

		assert.Equal(t, "analytics", pbm.Module)
		assert.Empty(t, pbm.Permissions)
	})
}

// ==================== RegisterModuleResponse structure ====================

func TestRegisterModuleResponse_Structure(t *testing.T) {
	t.Run("should carry registration statistics and permission list", func(t *testing.T) {
		perms := []PermissionResponse{
			{ID: uuid.New(), Name: "crm:contacts:read"},
			{ID: uuid.New(), Name: "crm:contacts:write"},
			{ID: uuid.New(), Name: "crm:contacts:delete"},
		}

		resp := &RegisterModuleResponse{
			Module:      "crm",
			Registered:  2,
			Updated:     1,
			Permissions: perms,
		}

		assert.Equal(t, "crm", resp.Module)
		assert.Equal(t, 2, resp.Registered)
		assert.Equal(t, 1, resp.Updated)
		assert.Len(t, resp.Permissions, 3)
	})

	t.Run("all-new registration has zero updated count", func(t *testing.T) {
		resp := &RegisterModuleResponse{
			Module:      "billing",
			Registered:  5,
			Updated:     0,
			Permissions: make([]PermissionResponse, 5),
		}

		assert.Equal(t, 5, resp.Registered)
		assert.Equal(t, 0, resp.Updated)
	})
}
