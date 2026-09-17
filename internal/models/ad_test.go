// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== ADUser struct ====================

func TestADUser_Instantiation(t *testing.T) {
	t.Run("should create a fully populated ADUser", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		changed := now.Add(-1 * time.Hour)

		user := &ADUser{
			DN:                "CN=John Doe,OU=Users,DC=corp,DC=com",
			SAMAccountName:    "jdoe",
			UserPrincipalName: "jdoe@corp.com",
			Email:             "john.doe@corp.com",
			FirstName:         "John",
			LastName:          "Doe",
			DisplayName:       "John Doe",
			Department:        "Engineering",
			Title:             "Software Engineer",
			Phone:             "+1-555-0100",
			Manager:           "CN=Jane Manager,OU=Users,DC=corp,DC=com",
			MemberOf: []string{
				"CN=Developers,OU=Groups,DC=corp,DC=com",
				"CN=AllUsers,OU=Groups,DC=corp,DC=com",
			},
			Enabled:     true,
			ObjectGUID:  "6f0a2c98-3c4d-4e2f-a1b2-c3d4e5f60011",
			WhenCreated: now,
			WhenChanged: changed,
			Attributes: map[string]string{
				"extensionAttribute1": "ProjectAlpha",
			},
		}

		assert.Equal(t, "CN=John Doe,OU=Users,DC=corp,DC=com", user.DN)
		assert.Equal(t, "jdoe", user.SAMAccountName)
		assert.Equal(t, "jdoe@corp.com", user.UserPrincipalName)
		assert.Equal(t, "john.doe@corp.com", user.Email)
		assert.Equal(t, "John", user.FirstName)
		assert.Equal(t, "Doe", user.LastName)
		assert.Equal(t, "John Doe", user.DisplayName)
		assert.Equal(t, "Engineering", user.Department)
		assert.Equal(t, "Software Engineer", user.Title)
		assert.Equal(t, "+1-555-0100", user.Phone)
		assert.NotEmpty(t, user.Manager)
		assert.Len(t, user.MemberOf, 2)
		assert.True(t, user.Enabled)
		assert.Equal(t, "6f0a2c98-3c4d-4e2f-a1b2-c3d4e5f60011", user.ObjectGUID)
		assert.Equal(t, now, user.WhenCreated)
		assert.Equal(t, changed, user.WhenChanged)
		assert.Equal(t, "ProjectAlpha", user.Attributes["extensionAttribute1"])
	})

	t.Run("should create a minimal ADUser with empty optional fields", func(t *testing.T) {
		user := &ADUser{
			DN:                "CN=Min User,OU=Users,DC=corp,DC=com",
			SAMAccountName:    "minuser",
			UserPrincipalName: "minuser@corp.com",
			Email:             "minuser@corp.com",
			FirstName:         "Min",
			LastName:          "User",
			DisplayName:       "Min User",
			Enabled:           true,
			ObjectGUID:        "aaaa-bbbb-cccc-dddd",
			MemberOf:          []string{},
		}

		assert.Empty(t, user.Department)
		assert.Empty(t, user.Title)
		assert.Empty(t, user.Phone)
		assert.Empty(t, user.Manager)
		assert.Empty(t, user.MemberOf)
		assert.Nil(t, user.Attributes)
	})

	t.Run("should support a disabled user account", func(t *testing.T) {
		user := &ADUser{
			SAMAccountName: "disabled_user",
			Enabled:        false,
		}

		assert.False(t, user.Enabled)
	})

	t.Run("should support multiple group memberships", func(t *testing.T) {
		user := &ADUser{
			SAMAccountName: "multigroup",
			MemberOf: []string{
				"CN=GroupA,OU=Groups,DC=corp,DC=com",
				"CN=GroupB,OU=Groups,DC=corp,DC=com",
				"CN=GroupC,OU=Groups,DC=corp,DC=com",
			},
		}

		assert.Len(t, user.MemberOf, 3)
	})
}

func TestADUser_JSONRoundTrip(t *testing.T) {
	t.Run("should marshal and unmarshal ADUser preserving all fields", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		original := &ADUser{
			DN:                "CN=Test,OU=Users,DC=corp,DC=com",
			SAMAccountName:    "testuser",
			UserPrincipalName: "testuser@corp.com",
			Email:             "test@corp.com",
			FirstName:         "Test",
			LastName:          "User",
			DisplayName:       "Test User",
			Department:        "IT",
			Enabled:           true,
			ObjectGUID:        "guid-001",
			WhenCreated:       now,
			WhenChanged:       now,
			MemberOf:          []string{"CN=IT,DC=corp,DC=com"},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored ADUser
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, original.DN, restored.DN)
		assert.Equal(t, original.SAMAccountName, restored.SAMAccountName)
		assert.Equal(t, original.Email, restored.Email)
		assert.Equal(t, original.Enabled, restored.Enabled)
		assert.Equal(t, original.MemberOf, restored.MemberOf)
	})
}

// ==================== ADGroup struct ====================

func TestADGroup_Instantiation(t *testing.T) {
	t.Run("should create a fully populated ADGroup", func(t *testing.T) {
		group := &ADGroup{
			DN:          "CN=Developers,OU=Groups,DC=corp,DC=com",
			Name:        "Developers",
			Description: "Software development team",
			Members: []string{
				"CN=Alice,OU=Users,DC=corp,DC=com",
				"CN=Bob,OU=Users,DC=corp,DC=com",
			},
			ObjectGUID: "group-guid-001",
		}

		assert.Equal(t, "CN=Developers,OU=Groups,DC=corp,DC=com", group.DN)
		assert.Equal(t, "Developers", group.Name)
		assert.Equal(t, "Software development team", group.Description)
		assert.Len(t, group.Members, 2)
		assert.Contains(t, group.Members, "CN=Alice,OU=Users,DC=corp,DC=com")
		assert.Equal(t, "group-guid-001", group.ObjectGUID)
	})

	t.Run("should create a group with no description", func(t *testing.T) {
		group := &ADGroup{
			DN:         "CN=Empty,OU=Groups,DC=corp,DC=com",
			Name:       "Empty Group",
			Members:    []string{},
			ObjectGUID: "guid-empty",
		}

		assert.Empty(t, group.Description)
		assert.Empty(t, group.Members)
	})
}

func TestADGroup_JSONRoundTrip(t *testing.T) {
	t.Run("should marshal and unmarshal ADGroup correctly", func(t *testing.T) {
		original := &ADGroup{
			DN:      "CN=Ops,OU=Groups,DC=corp,DC=com",
			Name:    "Ops",
			Members: []string{"CN=Charlie,DC=corp,DC=com"},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored ADGroup
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, original.DN, restored.DN)
		assert.Equal(t, original.Name, restored.Name)
		assert.Equal(t, original.Members, restored.Members)
	})
}

// ==================== CreateEmployeeRequest ====================

func TestCreateEmployeeRequest_Fields(t *testing.T) {
	t.Run("should set all required and optional fields", func(t *testing.T) {
		req := &CreateEmployeeRequest{
			Username:   "newuser",
			Password:   "SecurePass123!",
			Email:      "newuser@corp.com",
			FirstName:  "New",
			LastName:   "User",
			Department: "Engineering",
			Title:      "Engineer",
			Groups: []string{
				"CN=Developers,OU=Groups,DC=corp,DC=com",
			},
		}

		assert.Equal(t, "newuser", req.Username)
		assert.Equal(t, "SecurePass123!", req.Password)
		assert.Equal(t, "newuser@corp.com", req.Email)
		assert.Equal(t, "New", req.FirstName)
		assert.Equal(t, "User", req.LastName)
		assert.Equal(t, "Engineering", req.Department)
		assert.Equal(t, "Engineer", req.Title)
		assert.Len(t, req.Groups, 1)
	})

	t.Run("should create a minimal request with only required fields", func(t *testing.T) {
		req := &CreateEmployeeRequest{
			Username:  "minimal",
			Password:  "Pass1234!",
			Email:     "minimal@corp.com",
			FirstName: "Min",
			LastName:  "Mal",
		}

		assert.Empty(t, req.Department)
		assert.Empty(t, req.Title)
		assert.Empty(t, req.Groups)
	})

	t.Run("should allow multiple group assignments", func(t *testing.T) {
		req := &CreateEmployeeRequest{
			Username:  "multigroup",
			Password:  "Pass1234!",
			Email:     "mg@corp.com",
			FirstName: "Multi",
			LastName:  "Group",
			Groups: []string{
				"CN=GroupA,DC=corp,DC=com",
				"CN=GroupB,DC=corp,DC=com",
				"CN=GroupC,DC=corp,DC=com",
			},
		}

		assert.Len(t, req.Groups, 3)
	})
}

// ==================== UpdateEmployeeRequest ====================

func TestUpdateEmployeeRequest_Fields(t *testing.T) {
	t.Run("should update all optional fields", func(t *testing.T) {
		email := "updated@corp.com"
		firstName := "Updated"
		lastName := "Name"
		department := "Marketing"
		title := "Manager"
		phone := "+1-555-0200"

		req := &UpdateEmployeeRequest{
			UserDN:     "CN=Old Name,OU=Users,DC=corp,DC=com",
			Email:      &email,
			FirstName:  &firstName,
			LastName:   &lastName,
			Department: &department,
			Title:      &title,
			Phone:      &phone,
		}

		assert.Equal(t, "CN=Old Name,OU=Users,DC=corp,DC=com", req.UserDN)
		require.NotNil(t, req.Email)
		assert.Equal(t, "updated@corp.com", *req.Email)
		require.NotNil(t, req.FirstName)
		assert.Equal(t, "Updated", *req.FirstName)
		require.NotNil(t, req.Department)
		assert.Equal(t, "Marketing", *req.Department)
		require.NotNil(t, req.Phone)
		assert.Equal(t, "+1-555-0200", *req.Phone)
	})

	t.Run("should allow a partial update with only UserDN set", func(t *testing.T) {
		req := &UpdateEmployeeRequest{
			UserDN: "CN=Someone,OU=Users,DC=corp,DC=com",
		}

		assert.Equal(t, "CN=Someone,OU=Users,DC=corp,DC=com", req.UserDN)
		assert.Nil(t, req.Email)
		assert.Nil(t, req.FirstName)
		assert.Nil(t, req.LastName)
		assert.Nil(t, req.Department)
		assert.Nil(t, req.Title)
		assert.Nil(t, req.Phone)
	})
}

// ==================== ResetPasswordRequest ====================

func TestResetPasswordRequest_Fields(t *testing.T) {
	t.Run("should set all fields with force change", func(t *testing.T) {
		req := &ResetPasswordRequest{
			UserDN:             "CN=User,OU=Users,DC=corp,DC=com",
			NewPassword:        "NewSecure123!",
			MustChangePassword: true,
		}

		assert.Equal(t, "CN=User,OU=Users,DC=corp,DC=com", req.UserDN)
		assert.Equal(t, "NewSecure123!", req.NewPassword)
		assert.True(t, req.MustChangePassword)
	})

	t.Run("should default MustChangePassword to false", func(t *testing.T) {
		req := &ResetPasswordRequest{
			UserDN:      "CN=User,OU=Users,DC=corp,DC=com",
			NewPassword: "NewPass123!",
		}

		assert.False(t, req.MustChangePassword)
	})
}

// ==================== AccountStatusRequest ====================

func TestAccountStatusRequest_Fields(t *testing.T) {
	tests := []struct {
		name    string
		userDN  string
		enabled bool
	}{
		{
			name:    "should enable an account",
			userDN:  "CN=Disabled,OU=Users,DC=corp,DC=com",
			enabled: true,
		},
		{
			name:    "should disable an account",
			userDN:  "CN=Active,OU=Users,DC=corp,DC=com",
			enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AccountStatusRequest{
				UserDN:  tt.userDN,
				Enabled: tt.enabled,
			}

			assert.Equal(t, tt.userDN, req.UserDN)
			assert.Equal(t, tt.enabled, req.Enabled)
		})
	}
}

// ==================== DeleteEmployeeRequest ====================

func TestDeleteEmployeeRequest_Fields(t *testing.T) {
	t.Run("should set the required UserDN", func(t *testing.T) {
		req := &DeleteEmployeeRequest{
			UserDN: "CN=ToDelete,OU=Users,DC=corp,DC=com",
		}

		assert.Equal(t, "CN=ToDelete,OU=Users,DC=corp,DC=com", req.UserDN)
	})
}

// ==================== GroupMembershipRequest ====================

func TestGroupMembershipRequest_Fields(t *testing.T) {
	t.Run("should set UserDN and GroupDN for adding to group", func(t *testing.T) {
		req := &GroupMembershipRequest{
			UserDN:  "CN=User,OU=Users,DC=corp,DC=com",
			GroupDN: "CN=Admins,OU=Groups,DC=corp,DC=com",
		}

		assert.Equal(t, "CN=User,OU=Users,DC=corp,DC=com", req.UserDN)
		assert.Equal(t, "CN=Admins,OU=Groups,DC=corp,DC=com", req.GroupDN)
	})
}

// ==================== EmployeeListResponse ====================

func TestEmployeeListResponse_Instantiation(t *testing.T) {
	t.Run("should create a list response with multiple employees", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		resp := &EmployeeListResponse{
			Employees: []ADUser{
				{
					DN:             "CN=Alice,OU=Users,DC=corp,DC=com",
					SAMAccountName: "alice",
					Email:          "alice@corp.com",
					FirstName:      "Alice",
					LastName:       "Smith",
					DisplayName:    "Alice Smith",
					Enabled:        true,
					ObjectGUID:     "guid-alice",
					WhenCreated:    now,
					WhenChanged:    now,
					MemberOf:       []string{},
				},
				{
					DN:             "CN=Bob,OU=Users,DC=corp,DC=com",
					SAMAccountName: "bob",
					Email:          "bob@corp.com",
					FirstName:      "Bob",
					LastName:       "Jones",
					DisplayName:    "Bob Jones",
					Enabled:        false,
					ObjectGUID:     "guid-bob",
					WhenCreated:    now,
					WhenChanged:    now,
					MemberOf:       []string{},
				},
			},
			Total: 2,
		}

		assert.Len(t, resp.Employees, 2)
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, "alice", resp.Employees[0].SAMAccountName)
		assert.Equal(t, "bob", resp.Employees[1].SAMAccountName)
		assert.True(t, resp.Employees[0].Enabled)
		assert.False(t, resp.Employees[1].Enabled)
	})

	t.Run("should allow empty employee list", func(t *testing.T) {
		resp := &EmployeeListResponse{
			Employees: []ADUser{},
			Total:     0,
		}

		assert.Empty(t, resp.Employees)
		assert.Equal(t, 0, resp.Total)
	})

	t.Run("total should reflect actual pagination count not slice length", func(t *testing.T) {
		// Simulate a paginated response: 2 items in page but 100 total.
		resp := &EmployeeListResponse{
			Employees: []ADUser{
				{SAMAccountName: "user1", MemberOf: []string{}, ObjectGUID: "g1"},
				{SAMAccountName: "user2", MemberOf: []string{}, ObjectGUID: "g2"},
			},
			Total: 100,
		}

		assert.Len(t, resp.Employees, 2)
		assert.Equal(t, 100, resp.Total)
	})
}

// ==================== GroupListResponse ====================

func TestGroupListResponse_Instantiation(t *testing.T) {
	t.Run("should create a list response with multiple groups", func(t *testing.T) {
		resp := &GroupListResponse{
			Groups: []ADGroup{
				{
					DN:         "CN=Developers,OU=Groups,DC=corp,DC=com",
					Name:       "Developers",
					Members:    []string{"CN=Alice,DC=corp,DC=com"},
					ObjectGUID: "guid-devs",
				},
				{
					DN:         "CN=Ops,OU=Groups,DC=corp,DC=com",
					Name:       "Ops",
					Members:    []string{},
					ObjectGUID: "guid-ops",
				},
			},
			Total: 2,
		}

		assert.Len(t, resp.Groups, 2)
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, "Developers", resp.Groups[0].Name)
	})

	t.Run("should allow an empty group list", func(t *testing.T) {
		resp := &GroupListResponse{
			Groups: []ADGroup{},
			Total:  0,
		}

		assert.Empty(t, resp.Groups)
		assert.Equal(t, 0, resp.Total)
	})
}
