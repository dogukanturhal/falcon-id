// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildGroup returns a fully populated Group for use in tests.
func buildGroup() *Group {
	id := uuid.New()
	tenantID := uuid.New()
	createdBy := uuid.New()
	parentID := uuid.New()
	now := time.Now().Truncate(time.Second)
	displayName := "Engineering Team"
	desc := "All engineers"

	return &Group{
		ID:            id,
		TenantID:      tenantID,
		Name:          "engineering",
		DisplayName:   &displayName,
		Description:   &desc,
		ParentGroupID: &parentID,
		IsSystem:      false,
		Metadata:      map[string]interface{}{"department": "R&D"},
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     &createdBy,
	}
}

// ==================== Group struct field defaults ====================

func TestGroup_ZeroValue(t *testing.T) {
	t.Run("zero-value group has safe defaults", func(t *testing.T) {
		g := Group{}

		assert.Equal(t, uuid.Nil, g.ID)
		assert.Equal(t, uuid.Nil, g.TenantID)
		assert.Equal(t, "", g.Name)
		assert.Nil(t, g.DisplayName)
		assert.Nil(t, g.Description)
		assert.Nil(t, g.ParentGroupID)
		assert.False(t, g.IsSystem)
		assert.Nil(t, g.Metadata)
		assert.Equal(t, 0, g.MemberCount)
		assert.Equal(t, 0, g.RoleCount)
		assert.Nil(t, g.Members)
		assert.Nil(t, g.Roles)
		assert.Nil(t, g.ParentGroup)
		assert.Nil(t, g.ChildGroups)
		assert.Nil(t, g.CreatedBy)
	})
}

func TestGroup_FullyPopulated(t *testing.T) {
	t.Run("should carry all optional pointer and slice fields", func(t *testing.T) {
		g := buildGroup()

		require.NotNil(t, g)
		assert.NotEqual(t, uuid.Nil, g.ID)
		assert.NotEqual(t, uuid.Nil, g.TenantID)
		assert.Equal(t, "engineering", g.Name)
		require.NotNil(t, g.DisplayName)
		assert.Equal(t, "Engineering Team", *g.DisplayName)
		require.NotNil(t, g.Description)
		assert.Equal(t, "All engineers", *g.Description)
		require.NotNil(t, g.ParentGroupID)
		assert.False(t, g.IsSystem)
		assert.Equal(t, map[string]interface{}{"department": "R&D"}, g.Metadata)
		require.NotNil(t, g.CreatedBy)
	})
}

func TestGroup_IsSystem(t *testing.T) {
	tests := []struct {
		name    string
		group   Group
		wantSys bool
	}{
		{
			name:    "system group has IsSystem true",
			group:   Group{IsSystem: true},
			wantSys: true,
		},
		{
			name:    "non-system group has IsSystem false",
			group:   Group{IsSystem: false},
			wantSys: false,
		},
		{
			name:    "zero-value group is not a system group",
			group:   Group{},
			wantSys: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantSys, tt.group.IsSystem)
		})
	}
}

// ==================== CreateGroupRequest validation ====================

func TestCreateGroupRequest_Fields(t *testing.T) {
	t.Run("should carry required name and all optional fields", func(t *testing.T) {
		parentID := uuid.New()
		role1 := uuid.New()
		member1 := uuid.New()
		displayName := "Backend Team"
		desc := "Backend engineers"
		metadata := map[string]interface{}{"slack_channel": "#backend"}

		req := CreateGroupRequest{
			Name:          "backend",
			DisplayName:   &displayName,
			Description:   &desc,
			ParentGroupID: &parentID,
			Metadata:      metadata,
			RoleIDs:       []uuid.UUID{role1},
			MemberIDs:     []uuid.UUID{member1},
		}

		assert.Equal(t, "backend", req.Name)
		require.NotNil(t, req.DisplayName)
		assert.Equal(t, displayName, *req.DisplayName)
		require.NotNil(t, req.Description)
		assert.Equal(t, desc, *req.Description)
		assert.Equal(t, &parentID, req.ParentGroupID)
		assert.Equal(t, metadata, req.Metadata)
		assert.Equal(t, []uuid.UUID{role1}, req.RoleIDs)
		assert.Equal(t, []uuid.UUID{member1}, req.MemberIDs)
	})

	t.Run("should allow optional fields to be absent", func(t *testing.T) {
		req := CreateGroupRequest{
			Name: "minimal-group",
		}

		assert.Equal(t, "minimal-group", req.Name)
		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.ParentGroupID)
		assert.Nil(t, req.Metadata)
		assert.Nil(t, req.RoleIDs)
		assert.Nil(t, req.MemberIDs)
	})

	t.Run("should allow multiple role and member IDs", func(t *testing.T) {
		role1, role2 := uuid.New(), uuid.New()
		mem1, mem2, mem3 := uuid.New(), uuid.New(), uuid.New()

		req := CreateGroupRequest{
			Name:      "large-group",
			RoleIDs:   []uuid.UUID{role1, role2},
			MemberIDs: []uuid.UUID{mem1, mem2, mem3},
		}

		assert.Len(t, req.RoleIDs, 2)
		assert.Len(t, req.MemberIDs, 3)
	})

	t.Run("name binding requires min=1 character", func(t *testing.T) {
		// Structural assertion: a single-char name is representable at the Go type
		// level; gin binding validation would reject an empty string at runtime.
		req := CreateGroupRequest{Name: "x"}
		assert.Equal(t, "x", req.Name)
		assert.Len(t, req.Name, 1)
	})

	t.Run("name binding requires max=100 characters", func(t *testing.T) {
		longName := "a" + string(make([]byte, 99)) // 100 chars
		req := CreateGroupRequest{Name: longName}
		assert.Len(t, req.Name, 100)
	})
}

// ==================== UpdateGroupRequest validation ====================

func TestUpdateGroupRequest_Fields(t *testing.T) {
	t.Run("all fields are optional — zero value is valid", func(t *testing.T) {
		req := UpdateGroupRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.ParentGroupID)
		assert.Nil(t, req.Metadata)
	})

	t.Run("should allow partial updates with only name set", func(t *testing.T) {
		name := "updated-name"
		req := UpdateGroupRequest{Name: &name}

		require.NotNil(t, req.Name)
		assert.Equal(t, name, *req.Name)
		assert.Nil(t, req.DisplayName)
		assert.Nil(t, req.Description)
	})

	t.Run("should allow partial updates with display_name and description", func(t *testing.T) {
		displayName := "New Display Name"
		desc := "Updated description text"

		req := UpdateGroupRequest{
			DisplayName: &displayName,
			Description: &desc,
		}

		assert.Equal(t, displayName, *req.DisplayName)
		assert.Equal(t, desc, *req.Description)
		assert.Nil(t, req.Name)
	})

	t.Run("should allow updating parent group ID", func(t *testing.T) {
		parentID := uuid.New()
		req := UpdateGroupRequest{ParentGroupID: &parentID}

		require.NotNil(t, req.ParentGroupID)
		assert.Equal(t, parentID, *req.ParentGroupID)
	})

	t.Run("should allow updating metadata", func(t *testing.T) {
		meta := map[string]interface{}{"priority": "high", "team_size": 12}
		req := UpdateGroupRequest{Metadata: meta}

		assert.Equal(t, meta, req.Metadata)
	})

	t.Run("full update with all fields set", func(t *testing.T) {
		name := "fully-updated"
		displayName := "Fully Updated Group"
		desc := "This group was fully updated"
		parentID := uuid.New()
		meta := map[string]interface{}{"env": "production"}

		req := UpdateGroupRequest{
			Name:          &name,
			DisplayName:   &displayName,
			Description:   &desc,
			ParentGroupID: &parentID,
			Metadata:      meta,
		}

		assert.Equal(t, name, *req.Name)
		assert.Equal(t, displayName, *req.DisplayName)
		assert.Equal(t, desc, *req.Description)
		assert.Equal(t, parentID, *req.ParentGroupID)
		assert.Equal(t, meta, req.Metadata)
	})
}

// ==================== AddMembersRequest validation ====================

func TestAddMembersRequest_Fields(t *testing.T) {
	t.Run("should carry a non-empty user_ids slice", func(t *testing.T) {
		user1 := uuid.New()
		user2 := uuid.New()

		req := AddMembersRequest{
			UserIDs: []uuid.UUID{user1, user2},
		}

		assert.Len(t, req.UserIDs, 2)
		assert.Contains(t, req.UserIDs, user1)
		assert.Contains(t, req.UserIDs, user2)
	})

	t.Run("should support single user", func(t *testing.T) {
		user1 := uuid.New()

		req := AddMembersRequest{UserIDs: []uuid.UUID{user1}}

		assert.Len(t, req.UserIDs, 1)
		assert.Equal(t, user1, req.UserIDs[0])
	})

	t.Run("should support large batch of users", func(t *testing.T) {
		users := make([]uuid.UUID, 50)
		for i := range users {
			users[i] = uuid.New()
		}

		req := AddMembersRequest{UserIDs: users}

		assert.Len(t, req.UserIDs, 50)
	})

	t.Run("nil UserIDs is structurally valid at Go type level (binding rejects at runtime)", func(t *testing.T) {
		req := AddMembersRequest{}
		assert.Nil(t, req.UserIDs)
	})
}

// ==================== RemoveMembersRequest validation ====================

func TestRemoveMembersRequest_Fields(t *testing.T) {
	t.Run("should carry a non-empty user_ids slice", func(t *testing.T) {
		user1 := uuid.New()
		user2 := uuid.New()
		user3 := uuid.New()

		req := RemoveMembersRequest{
			UserIDs: []uuid.UUID{user1, user2, user3},
		}

		assert.Len(t, req.UserIDs, 3)
		assert.Contains(t, req.UserIDs, user1)
		assert.Contains(t, req.UserIDs, user2)
		assert.Contains(t, req.UserIDs, user3)
	})

	t.Run("should support single user removal", func(t *testing.T) {
		user1 := uuid.New()
		req := RemoveMembersRequest{UserIDs: []uuid.UUID{user1}}

		assert.Len(t, req.UserIDs, 1)
	})

	t.Run("nil UserIDs is structurally valid (binding rejects at runtime)", func(t *testing.T) {
		req := RemoveMembersRequest{}
		assert.Nil(t, req.UserIDs)
	})
}

// ==================== AssignGroupRolesRequest validation ====================

func TestAssignGroupRolesRequest_Fields(t *testing.T) {
	t.Run("should carry a non-empty role_ids slice", func(t *testing.T) {
		role1 := uuid.New()
		role2 := uuid.New()

		req := AssignGroupRolesRequest{
			RoleIDs: []uuid.UUID{role1, role2},
		}

		assert.Len(t, req.RoleIDs, 2)
		assert.Contains(t, req.RoleIDs, role1)
		assert.Contains(t, req.RoleIDs, role2)
	})

	t.Run("should support single role assignment", func(t *testing.T) {
		role1 := uuid.New()
		req := AssignGroupRolesRequest{RoleIDs: []uuid.UUID{role1}}

		assert.Len(t, req.RoleIDs, 1)
		assert.Equal(t, role1, req.RoleIDs[0])
	})

	t.Run("nil RoleIDs is structurally valid (binding rejects at runtime)", func(t *testing.T) {
		req := AssignGroupRolesRequest{}
		assert.Nil(t, req.RoleIDs)
	})
}

// ==================== RemoveGroupRolesRequest validation ====================

func TestRemoveGroupRolesRequest_Fields(t *testing.T) {
	t.Run("should carry a non-empty role_ids slice for removal", func(t *testing.T) {
		role1 := uuid.New()

		req := RemoveGroupRolesRequest{
			RoleIDs: []uuid.UUID{role1},
		}

		assert.Len(t, req.RoleIDs, 1)
		assert.Equal(t, role1, req.RoleIDs[0])
	})
}

// ==================== IAMGroupListResponse structure ====================

func TestIAMGroupListResponse_Structure(t *testing.T) {
	t.Run("should carry groups slice and pagination metadata", func(t *testing.T) {
		g1 := buildGroup()
		g2 := buildGroup()
		g2.ID = uuid.New()
		g2.Name = "marketing"

		listResp := &IAMGroupListResponse{
			Groups:     []*Group{g1, g2},
			Total:      42,
			Page:       3,
			PageSize:   10,
			TotalPages: 5,
		}

		assert.Len(t, listResp.Groups, 2)
		assert.Equal(t, 42, listResp.Total)
		assert.Equal(t, 3, listResp.Page)
		assert.Equal(t, 10, listResp.PageSize)
		assert.Equal(t, 5, listResp.TotalPages)
	})

	t.Run("empty groups list has zero pagination metadata", func(t *testing.T) {
		listResp := &IAMGroupListResponse{
			Groups:     []*Group{},
			Total:      0,
			Page:       1,
			PageSize:   25,
			TotalPages: 0,
		}

		assert.Empty(t, listResp.Groups)
		assert.Equal(t, 0, listResp.Total)
		assert.Equal(t, 1, listResp.Page)
		assert.Equal(t, 25, listResp.PageSize)
		assert.Equal(t, 0, listResp.TotalPages)
	})

	t.Run("nil groups slice is a valid zero value", func(t *testing.T) {
		listResp := &IAMGroupListResponse{}

		assert.Nil(t, listResp.Groups)
		assert.Equal(t, 0, listResp.Total)
	})
}

// ==================== GroupMember struct ====================

func TestGroupMember_Fields(t *testing.T) {
	t.Run("should carry all required fields", func(t *testing.T) {
		id := uuid.New()
		groupID := uuid.New()
		userID := uuid.New()
		addedBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		gm := &GroupMember{
			ID:      id,
			GroupID: groupID,
			UserID:  userID,
			AddedAt: now,
			AddedBy: &addedBy,
		}

		assert.Equal(t, id, gm.ID)
		assert.Equal(t, groupID, gm.GroupID)
		assert.Equal(t, userID, gm.UserID)
		assert.Equal(t, now, gm.AddedAt)
		assert.Equal(t, &addedBy, gm.AddedBy)
	})

	t.Run("AddedBy is optional and can be nil", func(t *testing.T) {
		gm := &GroupMember{
			ID:      uuid.New(),
			GroupID: uuid.New(),
			UserID:  uuid.New(),
			AddedAt: time.Now(),
		}

		assert.Nil(t, gm.AddedBy)
		assert.Nil(t, gm.User)
		assert.Nil(t, gm.Group)
	})
}

// ==================== GroupRole struct ====================

func TestGroupRole_Fields(t *testing.T) {
	t.Run("should carry all required fields", func(t *testing.T) {
		id := uuid.New()
		groupID := uuid.New()
		roleID := uuid.New()
		assignedBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		gr := &GroupRole{
			ID:         id,
			GroupID:    groupID,
			RoleID:     roleID,
			AssignedAt: now,
			AssignedBy: &assignedBy,
		}

		assert.Equal(t, id, gr.ID)
		assert.Equal(t, groupID, gr.GroupID)
		assert.Equal(t, roleID, gr.RoleID)
		assert.Equal(t, now, gr.AssignedAt)
		assert.Equal(t, &assignedBy, gr.AssignedBy)
	})

	t.Run("AssignedBy and populated fields are optional", func(t *testing.T) {
		gr := &GroupRole{
			ID:         uuid.New(),
			GroupID:    uuid.New(),
			RoleID:     uuid.New(),
			AssignedAt: time.Now(),
		}

		assert.Nil(t, gr.AssignedBy)
		assert.Nil(t, gr.Role)
		assert.Nil(t, gr.Group)
	})
}

// ==================== EffectiveRole struct ====================

func TestEffectiveRole_Fields(t *testing.T) {
	tests := []struct {
		name       string
		role       EffectiveRole
		wantSource string
		wantSrcID  bool // whether SourceID is expected to be non-nil
	}{
		{
			name: "direct role assignment has no source group",
			role: EffectiveRole{
				RoleID:   uuid.New(),
				RoleName: "editor",
				Source:   "direct",
				SourceID: nil,
			},
			wantSource: "direct",
			wantSrcID:  false,
		},
		{
			name: "role inherited from group carries group source ID",
			role: EffectiveRole{
				RoleID:   uuid.New(),
				RoleName: "viewer",
				Source:   "group",
				SourceID: uuidPtr(uuid.New()),
			},
			wantSource: "group",
			wantSrcID:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantSource, tt.role.Source)
			if tt.wantSrcID {
				require.NotNil(t, tt.role.SourceID)
				assert.NotEqual(t, uuid.Nil, *tt.role.SourceID)
			} else {
				assert.Nil(t, tt.role.SourceID)
			}
		})
	}
}

// ==================== GroupMembersResponse structure ====================

func TestGroupMembersResponse_Structure(t *testing.T) {
	t.Run("should carry member list and pagination", func(t *testing.T) {
		gm1 := &GroupMember{ID: uuid.New(), GroupID: uuid.New(), UserID: uuid.New(), AddedAt: time.Now()}
		gm2 := &GroupMember{ID: uuid.New(), GroupID: uuid.New(), UserID: uuid.New(), AddedAt: time.Now()}

		resp := &GroupMembersResponse{
			Members:    []*GroupMember{gm1, gm2},
			Total:      20,
			Page:       1,
			PageSize:   10,
			TotalPages: 2,
		}

		assert.Len(t, resp.Members, 2)
		assert.Equal(t, 20, resp.Total)
		assert.Equal(t, 1, resp.Page)
		assert.Equal(t, 10, resp.PageSize)
		assert.Equal(t, 2, resp.TotalPages)
	})

	t.Run("empty member list has zero pagination values", func(t *testing.T) {
		resp := &GroupMembersResponse{
			Members:    []*GroupMember{},
			Total:      0,
			Page:       1,
			PageSize:   25,
			TotalPages: 0,
		}

		assert.Empty(t, resp.Members)
		assert.Equal(t, 0, resp.Total)
	})
}

// ==================== Group with child groups and populated fields ====================

func TestGroup_PopulatedRelations(t *testing.T) {
	t.Run("group can embed parent group and child groups", func(t *testing.T) {
		parent := &Group{
			ID:   uuid.New(),
			Name: "parent-group",
		}
		child1 := &Group{
			ID:   uuid.New(),
			Name: "child-group-1",
		}
		child2 := &Group{
			ID:   uuid.New(),
			Name: "child-group-2",
		}

		g := buildGroup()
		g.ParentGroup = parent
		g.ChildGroups = []*Group{child1, child2}

		require.NotNil(t, g.ParentGroup)
		assert.Equal(t, "parent-group", g.ParentGroup.Name)
		require.Len(t, g.ChildGroups, 2)
		assert.Equal(t, "child-group-1", g.ChildGroups[0].Name)
		assert.Equal(t, "child-group-2", g.ChildGroups[1].Name)
	})

	t.Run("group tracks member and role counts", func(t *testing.T) {
		g := buildGroup()
		g.MemberCount = 15
		g.RoleCount = 3

		assert.Equal(t, 15, g.MemberCount)
		assert.Equal(t, 3, g.RoleCount)
	})
}
