// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Organization type constants ====================

func TestOrgTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "company org type has correct string value",
			constant: OrgTypeCompany,
			expected: "company",
		},
		{
			name:     "division org type has correct string value",
			constant: OrgTypeDivision,
			expected: "division",
		},
		{
			name:     "department org type has correct string value",
			constant: OrgTypeDepartment,
			expected: "department",
		},
		{
			name:     "team org type has correct string value",
			constant: OrgTypeTeam,
			expected: "team",
		},
		{
			name:     "project org type has correct string value",
			constant: OrgTypeProject,
			expected: "project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// ==================== Organization member role constants ====================

func TestOrgRoleConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{
			name:     "member role has correct string value",
			constant: OrgRoleMember,
			expected: "member",
		},
		{
			name:     "manager role has correct string value",
			constant: OrgRoleManager,
			expected: "manager",
		},
		{
			name:     "lead role has correct string value",
			constant: OrgRoleLead,
			expected: "lead",
		},
		{
			name:     "owner role has correct string value",
			constant: OrgRoleOwner,
			expected: "owner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// ==================== ValidOrgTypes ====================

func TestValidOrgTypes(t *testing.T) {
	t.Run("should return exactly five org types", func(t *testing.T) {
		types := ValidOrgTypes()
		assert.Len(t, types, 5)
	})

	t.Run("should contain all expected org types", func(t *testing.T) {
		types := ValidOrgTypes()
		expected := []string{
			OrgTypeCompany,
			OrgTypeDivision,
			OrgTypeDepartment,
			OrgTypeTeam,
			OrgTypeProject,
		}
		assert.ElementsMatch(t, expected, types)
	})

	t.Run("should return a new slice on each call (not a shared reference)", func(t *testing.T) {
		types1 := ValidOrgTypes()
		types2 := ValidOrgTypes()
		// Mutating one must not affect the other (test for slice aliasing).
		types1[0] = "mutated"
		assert.NotEqual(t, "mutated", types2[0], "ValidOrgTypes must not return a shared slice")
	})
}

// ==================== ValidOrgRoles ====================

func TestValidOrgRoles(t *testing.T) {
	t.Run("should return exactly four org roles", func(t *testing.T) {
		roles := ValidOrgRoles()
		assert.Len(t, roles, 4)
	})

	t.Run("should contain all expected org roles", func(t *testing.T) {
		roles := ValidOrgRoles()
		expected := []string{
			OrgRoleMember,
			OrgRoleManager,
			OrgRoleLead,
			OrgRoleOwner,
		}
		assert.ElementsMatch(t, expected, roles)
	})

	t.Run("should return a new slice on each call", func(t *testing.T) {
		roles1 := ValidOrgRoles()
		roles2 := ValidOrgRoles()
		roles1[0] = "mutated"
		assert.NotEqual(t, "mutated", roles2[0], "ValidOrgRoles must not return a shared slice")
	})
}

// ==================== IsValidOrgType ====================

func TestIsValidOrgType(t *testing.T) {
	tests := []struct {
		name     string
		orgType  string
		expected bool
	}{
		{
			name:     "company is a valid org type",
			orgType:  OrgTypeCompany,
			expected: true,
		},
		{
			name:     "division is a valid org type",
			orgType:  OrgTypeDivision,
			expected: true,
		},
		{
			name:     "department is a valid org type",
			orgType:  OrgTypeDepartment,
			expected: true,
		},
		{
			name:     "team is a valid org type",
			orgType:  OrgTypeTeam,
			expected: true,
		},
		{
			name:     "project is a valid org type",
			orgType:  OrgTypeProject,
			expected: true,
		},
		{
			name:     "empty string is not a valid org type",
			orgType:  "",
			expected: false,
		},
		{
			name:     "arbitrary string is not a valid org type",
			orgType:  "branch",
			expected: false,
		},
		{
			name:     "uppercase COMPANY is not valid (case-sensitive)",
			orgType:  "COMPANY",
			expected: false,
		},
		{
			name:     "mixed-case Team is not valid",
			orgType:  "Team",
			expected: false,
		},
		{
			name:     "organisation (alternative spelling) is not valid",
			orgType:  "organisation",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidOrgType(tt.orgType))
		})
	}
}

// ==================== IsValidOrgRole ====================

func TestIsValidOrgRole(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		expected bool
	}{
		{
			name:     "member is a valid role",
			role:     OrgRoleMember,
			expected: true,
		},
		{
			name:     "manager is a valid role",
			role:     OrgRoleManager,
			expected: true,
		},
		{
			name:     "lead is a valid role",
			role:     OrgRoleLead,
			expected: true,
		},
		{
			name:     "owner is a valid role",
			role:     OrgRoleOwner,
			expected: true,
		},
		{
			name:     "empty string is not a valid role",
			role:     "",
			expected: false,
		},
		{
			name:     "admin is not a valid org role",
			role:     "admin",
			expected: false,
		},
		{
			name:     "MEMBER uppercase is not valid (case-sensitive)",
			role:     "MEMBER",
			expected: false,
		},
		{
			name:     "supervisor is not a valid role",
			role:     "supervisor",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidOrgRole(tt.role))
		})
	}
}

// ==================== CreateOrganizationRequest ====================

func TestCreateOrganizationRequest(t *testing.T) {
	t.Run("should hold required name and optional fields", func(t *testing.T) {
		displayName := "Engineering Division"
		description := "Handles all engineering activities"
		parentID := uuid.New()
		code := "ENG"

		req := CreateOrganizationRequest{
			Name:        "Engineering",
			DisplayName: &displayName,
			Description: &description,
			ParentID:    &parentID,
			OrgType:     OrgTypeDivision,
			Code:        &code,
			Metadata:    map[string]interface{}{"region": "APAC"},
		}

		assert.Equal(t, "Engineering", req.Name)
		assert.Equal(t, &displayName, req.DisplayName)
		assert.Equal(t, &description, req.Description)
		assert.Equal(t, &parentID, req.ParentID)
		assert.Equal(t, OrgTypeDivision, req.OrgType)
		assert.Equal(t, &code, req.Code)
		assert.Equal(t, map[string]interface{}{"region": "APAC"}, req.Metadata)
	})

	t.Run("should be valid with only required name field", func(t *testing.T) {
		req := CreateOrganizationRequest{
			Name: "Minimal Org",
		}

		assert.Equal(t, "Minimal Org", req.Name)
		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.ParentID)
		assert.Empty(t, req.OrgType)
		assert.Nil(t, req.Code)
		assert.Nil(t, req.Metadata)
	})

	t.Run("zero value has empty name — required enforced at handler level", func(t *testing.T) {
		req := CreateOrganizationRequest{}
		assert.Empty(t, req.Name)
	})
}

// ==================== UpdateOrganizationRequest ====================

func TestUpdateOrganizationRequest(t *testing.T) {
	t.Run("should be valid with all nil fields (no-op update)", func(t *testing.T) {
		req := UpdateOrganizationRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.ParentID)
		assert.Nil(t, req.OrgType)
		assert.Nil(t, req.Code)
		assert.Nil(t, req.Metadata)
		assert.Nil(t, req.IsActive)
	})

	t.Run("should allow partial field updates", func(t *testing.T) {
		newName := "Renamed Team"
		isActive := false

		req := UpdateOrganizationRequest{
			Name:     &newName,
			IsActive: &isActive,
		}

		require.NotNil(t, req.Name)
		assert.Equal(t, "Renamed Team", *req.Name)
		require.NotNil(t, req.IsActive)
		assert.False(t, *req.IsActive)
		assert.Nil(t, req.Description)
	})

	t.Run("should allow updating org type to any valid type", func(t *testing.T) {
		for _, ot := range ValidOrgTypes() {
			captured := ot
			req := UpdateOrganizationRequest{
				OrgType: &captured,
			}
			require.NotNil(t, req.OrgType)
			assert.Equal(t, ot, *req.OrgType)
		}
	})

	t.Run("should allow metadata update", func(t *testing.T) {
		meta := map[string]interface{}{"cost_center": "CC-100", "active": true}
		req := UpdateOrganizationRequest{
			Metadata: meta,
		}
		assert.Equal(t, meta, req.Metadata)
	})
}

// ==================== AddOrgMemberRequest ====================

func TestAddOrgMemberRequest(t *testing.T) {
	t.Run("should hold all member request fields correctly", func(t *testing.T) {
		userID := uuid.New()
		title := "Senior Engineer"

		req := AddOrgMemberRequest{
			UserID:    userID,
			Role:      OrgRoleManager,
			Title:     &title,
			IsPrimary: true,
		}

		assert.Equal(t, userID, req.UserID)
		assert.Equal(t, OrgRoleManager, req.Role)
		assert.Equal(t, &title, req.Title)
		assert.True(t, req.IsPrimary)
	})

	t.Run("should be valid with only required UserID", func(t *testing.T) {
		userID := uuid.New()
		req := AddOrgMemberRequest{
			UserID: userID,
		}

		assert.Equal(t, userID, req.UserID)
		assert.Empty(t, req.Role)
		assert.Nil(t, req.Title)
		assert.False(t, req.IsPrimary)
	})

	t.Run("should accept all valid org roles", func(t *testing.T) {
		userID := uuid.New()
		for _, role := range ValidOrgRoles() {
			req := AddOrgMemberRequest{
				UserID: userID,
				Role:   role,
			}
			assert.Equal(t, role, req.Role)
		}
	})
}

// ==================== OrganizationTreeNode ====================

func TestOrganizationTreeNode(t *testing.T) {
	t.Run("should embed Organization and hold child nodes", func(t *testing.T) {
		parentID := uuid.New()
		child1ID := uuid.New()
		child2ID := uuid.New()
		grandchildID := uuid.New()

		grandchild := &OrganizationTreeNode{
			Organization: &Organization{
				ID:      grandchildID,
				Name:    "Grandchild Team",
				OrgType: OrgTypeTeam,
				Level:   2,
			},
		}

		child1 := &OrganizationTreeNode{
			Organization: &Organization{
				ID:      child1ID,
				Name:    "Child Department A",
				OrgType: OrgTypeDepartment,
				Level:   1,
			},
			Children: []*OrganizationTreeNode{grandchild},
		}

		child2 := &OrganizationTreeNode{
			Organization: &Organization{
				ID:      child2ID,
				Name:    "Child Department B",
				OrgType: OrgTypeDepartment,
				Level:   1,
			},
		}

		root := &OrganizationTreeNode{
			Organization: &Organization{
				ID:      parentID,
				Name:    "Root Division",
				OrgType: OrgTypeDivision,
				Level:   0,
			},
			Children: []*OrganizationTreeNode{child1, child2},
		}

		require.NotNil(t, root.Organization)
		assert.Equal(t, parentID, root.ID)
		assert.Equal(t, "Root Division", root.Name)
		assert.Equal(t, 0, root.Level)
		assert.Len(t, root.Children, 2)

		assert.Equal(t, child1ID, root.Children[0].ID)
		assert.Equal(t, "Child Department A", root.Children[0].Name)
		assert.Len(t, root.Children[0].Children, 1)
		assert.Equal(t, grandchildID, root.Children[0].Children[0].ID)

		assert.Equal(t, child2ID, root.Children[1].ID)
		assert.Empty(t, root.Children[1].Children)
	})

	t.Run("should allow leaf node with no children", func(t *testing.T) {
		node := &OrganizationTreeNode{
			Organization: &Organization{
				ID:   uuid.New(),
				Name: "Leaf Team",
			},
		}

		assert.Nil(t, node.Children)
	})

	t.Run("should allow access to embedded Organization fields via promotion", func(t *testing.T) {
		orgID := uuid.New()
		tenantID := uuid.New()
		createdBy := uuid.New()
		displayName := "Engineering Team"
		now := time.Now().Truncate(time.Second)

		node := &OrganizationTreeNode{
			Organization: &Organization{
				ID:          orgID,
				TenantID:    tenantID,
				Name:        "Engineering",
				DisplayName: &displayName,
				OrgType:     OrgTypeTeam,
				IsActive:    true,
				Level:       3,
				MemberCount: 8,
				ChildCount:  2,
				CreatedAt:   now,
				UpdatedAt:   now,
				CreatedBy:   &createdBy,
			},
		}

		// Promoted fields accessible directly via embedding.
		assert.Equal(t, orgID, node.ID)
		assert.Equal(t, tenantID, node.TenantID)
		assert.Equal(t, "Engineering", node.Name)
		assert.Equal(t, &displayName, node.DisplayName)
		assert.Equal(t, OrgTypeTeam, node.OrgType)
		assert.True(t, node.IsActive)
		assert.Equal(t, 3, node.Level)
		assert.Equal(t, 8, node.MemberCount)
		assert.Equal(t, 2, node.ChildCount)
		assert.Equal(t, now, node.CreatedAt)
		assert.Equal(t, &createdBy, node.CreatedBy)
	})
}

// ==================== Organization struct ====================

func TestOrganization(t *testing.T) {
	t.Run("should hold all org fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		parentID := uuid.New()
		createdBy := uuid.New()
		displayName := "Finance Department"
		description := "Manages company finances"
		code := "FIN"
		path := "/root/finance"
		now := time.Now().Truncate(time.Second)

		org := Organization{
			ID:          id,
			TenantID:    tenantID,
			ParentID:    &parentID,
			Name:        "Finance",
			DisplayName: &displayName,
			Description: &description,
			OrgType:     OrgTypeDepartment,
			Code:        &code,
			Path:        &path,
			Level:       1,
			Metadata:    map[string]interface{}{"budget_code": "B001"},
			IsActive:    true,
			CreatedAt:   now,
			UpdatedAt:   now,
			CreatedBy:   &createdBy,
			MemberCount: 15,
			ChildCount:  3,
		}

		assert.Equal(t, id, org.ID)
		assert.Equal(t, tenantID, org.TenantID)
		assert.Equal(t, &parentID, org.ParentID)
		assert.Equal(t, "Finance", org.Name)
		assert.Equal(t, &displayName, org.DisplayName)
		assert.Equal(t, &description, org.Description)
		assert.Equal(t, OrgTypeDepartment, org.OrgType)
		assert.Equal(t, &code, org.Code)
		assert.Equal(t, &path, org.Path)
		assert.Equal(t, 1, org.Level)
		assert.Equal(t, map[string]interface{}{"budget_code": "B001"}, org.Metadata)
		assert.True(t, org.IsActive)
		assert.Equal(t, now, org.CreatedAt)
		assert.Equal(t, now, org.UpdatedAt)
		assert.Equal(t, &createdBy, org.CreatedBy)
		assert.Equal(t, 15, org.MemberCount)
		assert.Equal(t, 3, org.ChildCount)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		org := Organization{
			ID:   uuid.New(),
			Name: "Simple Org",
		}

		assert.Nil(t, org.ParentID)
		assert.Nil(t, org.DisplayName)
		assert.Nil(t, org.Description)
		assert.Nil(t, org.Code)
		assert.Nil(t, org.Path)
		assert.Nil(t, org.Metadata)
		assert.Nil(t, org.CreatedBy)
		assert.Nil(t, org.Parent)
		assert.Nil(t, org.Children)
		assert.Nil(t, org.Members)
		assert.Nil(t, org.Ancestors)
	})
}

// ==================== OrgMember struct ====================

func TestOrgMember(t *testing.T) {
	t.Run("should hold all member fields correctly", func(t *testing.T) {
		id := uuid.New()
		orgID := uuid.New()
		userID := uuid.New()
		joinedBy := uuid.New()
		title := "Team Lead"
		now := time.Now().Truncate(time.Second)

		m := OrgMember{
			ID:             id,
			OrganizationID: orgID,
			UserID:         userID,
			Role:           OrgRoleLead,
			Title:          &title,
			IsPrimary:      true,
			JoinedAt:       now,
			JoinedBy:       &joinedBy,
		}

		assert.Equal(t, id, m.ID)
		assert.Equal(t, orgID, m.OrganizationID)
		assert.Equal(t, userID, m.UserID)
		assert.Equal(t, OrgRoleLead, m.Role)
		assert.Equal(t, &title, m.Title)
		assert.True(t, m.IsPrimary)
		assert.Equal(t, now, m.JoinedAt)
		assert.Equal(t, &joinedBy, m.JoinedBy)
	})

	t.Run("should allow nil optional title and joined-by fields", func(t *testing.T) {
		m := OrgMember{
			ID:             uuid.New(),
			OrganizationID: uuid.New(),
			UserID:         uuid.New(),
			Role:           OrgRoleMember,
		}

		assert.Nil(t, m.Title)
		assert.Nil(t, m.JoinedBy)
		assert.Nil(t, m.User)
		assert.Nil(t, m.Organization)
	})
}

// ==================== IsValidOrgType and IsValidOrgRole exhaustive coverage ====================

func TestIsValidOrgType_ExhaustiveCoverage(t *testing.T) {
	// Every type returned by ValidOrgTypes must be accepted by IsValidOrgType.
	for _, ot := range ValidOrgTypes() {
		t.Run("valid: "+ot, func(t *testing.T) {
			assert.True(t, IsValidOrgType(ot),
				"IsValidOrgType should accept %q which is returned by ValidOrgTypes", ot)
		})
	}
}

func TestIsValidOrgRole_ExhaustiveCoverage(t *testing.T) {
	// Every role returned by ValidOrgRoles must be accepted by IsValidOrgRole.
	for _, role := range ValidOrgRoles() {
		t.Run("valid: "+role, func(t *testing.T) {
			assert.True(t, IsValidOrgRole(role),
				"IsValidOrgRole should accept %q which is returned by ValidOrgRoles", role)
		})
	}
}

// ==================== Paginaged list response structs ====================

func TestOrganizationListResponse(t *testing.T) {
	t.Run("should hold pagination fields correctly", func(t *testing.T) {
		orgs := []*Organization{
			{ID: uuid.New(), Name: "Org A"},
			{ID: uuid.New(), Name: "Org B"},
		}

		resp := OrganizationListResponse{
			Organizations: orgs,
			Total:         100,
			Page:          2,
			PageSize:      20,
			TotalPages:    5,
		}

		assert.Len(t, resp.Organizations, 2)
		assert.Equal(t, 100, resp.Total)
		assert.Equal(t, 2, resp.Page)
		assert.Equal(t, 20, resp.PageSize)
		assert.Equal(t, 5, resp.TotalPages)
	})
}

func TestOrgMembersResponse(t *testing.T) {
	t.Run("should hold members and pagination fields correctly", func(t *testing.T) {
		members := []*OrgMember{
			{ID: uuid.New(), Role: OrgRoleMember},
			{ID: uuid.New(), Role: OrgRoleOwner},
		}

		resp := OrgMembersResponse{
			Members:    members,
			Total:      50,
			Page:       1,
			PageSize:   10,
			TotalPages: 5,
		}

		assert.Len(t, resp.Members, 2)
		assert.Equal(t, 50, resp.Total)
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, 10, resp.PageSize)
		assert.Equal(t, 5, resp.TotalPages)
	})
}
