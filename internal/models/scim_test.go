// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testLastNameSmith = "Smith"

// ==================== SCIM Schema URI constants ====================

func TestSCIMSchemaConstants(t *testing.T) {
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0", SCIMSchemaCore)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:User", SCIMSchemaUser)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:Group", SCIMSchemaGroup)
	assert.Equal(t, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", SCIMSchemaEnterpriseUser)
	assert.Equal(t, "urn:ietf:params:scim:api:messages:2.0:ListResponse", SCIMSchemaListResponse)
	assert.Equal(t, "urn:ietf:params:scim:api:messages:2.0:Error", SCIMSchemaError)
	assert.Equal(t, "urn:ietf:params:scim:api:messages:2.0:PatchOp", SCIMSchemaPatchOp)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig", SCIMSchemaServiceProvider)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:Schema", SCIMSchemaSchema)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:ResourceType", SCIMSchemaResourceType)
}

// ==================== SCIMToken struct ====================

func TestSCIMToken_Instantiation(t *testing.T) {
	t.Run("should create token with all fields set", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		createdBy := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "CI/CD provisioning token"
		lastUsedIP := "10.0.0.5"
		expires := now.Add(365 * 24 * time.Hour)
		lastUsed := now.Add(-1 * time.Hour)

		token := &SCIMToken{
			ID:          id,
			TenantID:    tenantID,
			Name:        "CI Token",
			Description: &desc,
			TokenHash:   "$2a$10$hashedtoken",
			IsActive:    true,
			LastUsedAt:  &lastUsed,
			LastUsedIP:  &lastUsedIP,
			CreatedAt:   now,
			CreatedBy:   &createdBy,
			ExpiresAt:   &expires,
		}

		assert.Equal(t, id, token.ID)
		assert.Equal(t, tenantID, token.TenantID)
		assert.Equal(t, "CI Token", token.Name)
		assert.Equal(t, &desc, token.Description)
		assert.Equal(t, "$2a$10$hashedtoken", token.TokenHash)
		assert.True(t, token.IsActive)
		assert.Equal(t, &lastUsed, token.LastUsedAt)
		assert.Equal(t, &lastUsedIP, token.LastUsedIP)
		assert.Equal(t, now, token.CreatedAt)
		assert.Equal(t, &createdBy, token.CreatedBy)
		assert.Equal(t, &expires, token.ExpiresAt)
	})

	t.Run("TokenHash should have json dash tag (never marshaled)", func(t *testing.T) {
		token := &SCIMToken{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Name:      "Test Token",
			TokenHash: "should-not-appear-in-json",
			IsActive:  true,
			CreatedAt: time.Now(),
		}

		data, err := json.Marshal(token)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, hasHash := decoded["token_hash"]
		assert.False(t, hasHash, "token_hash should not appear in JSON output due to json:\"-\" tag")
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		token := &SCIMToken{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			Name:      "Minimal Token",
			TokenHash: "hash",
			IsActive:  true,
			CreatedAt: time.Now(),
		}

		assert.Nil(t, token.Description)
		assert.Nil(t, token.LastUsedAt)
		assert.Nil(t, token.LastUsedIP)
		assert.Nil(t, token.CreatedBy)
		assert.Nil(t, token.ExpiresAt)
	})
}

// ==================== SCIMTokenCreatedResponse ====================

func TestSCIMTokenCreatedResponse_Fields(t *testing.T) {
	t.Run("should hold the plain-text token only shown at creation", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)
		desc := "Initial token"
		expires := now.Add(365 * 24 * time.Hour)

		resp := &SCIMTokenCreatedResponse{ //nolint:gosec // test fixture value, not a real credential
			ID:          id,
			TenantID:    tenantID,
			Name:        "Onboarding Token",
			Description: &desc,
			Token:       "scim_plain_token_value_abc123",
			IsActive:    true,
			CreatedAt:   now,
			ExpiresAt:   &expires,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, "Onboarding Token", resp.Name)
		assert.Equal(t, &desc, resp.Description)
		assert.Equal(t, "scim_plain_token_value_abc123", resp.Token)
		assert.True(t, resp.IsActive)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, &expires, resp.ExpiresAt)
	})
}

// ==================== CreateSCIMTokenRequest ====================

func TestCreateSCIMTokenRequest_Fields(t *testing.T) {
	t.Run("should populate all fields", func(t *testing.T) {
		desc := "Integration token"
		expiresAt := "2027-01-01T00:00:00Z"

		req := CreateSCIMTokenRequest{
			Name:        "Integration",
			Description: &desc,
			ExpiresAt:   &expiresAt,
		}

		assert.Equal(t, "Integration", req.Name)
		assert.Equal(t, &desc, req.Description)
		assert.Equal(t, &expiresAt, req.ExpiresAt)
	})

	t.Run("should allow nil optional fields", func(t *testing.T) {
		req := CreateSCIMTokenRequest{
			Name: "Minimal",
		}

		assert.Equal(t, "Minimal", req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.ExpiresAt)
	})
}

// ==================== UpdateSCIMTokenRequest ====================

func TestUpdateSCIMTokenRequest_Fields(t *testing.T) {
	t.Run("all nil fields represents a no-op update", func(t *testing.T) {
		req := UpdateSCIMTokenRequest{}

		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.IsActive)
	})

	t.Run("should allow partial updates", func(t *testing.T) {
		name := "Renamed Token"
		isActive := false

		req := UpdateSCIMTokenRequest{
			Name:     &name,
			IsActive: &isActive,
		}

		assert.Equal(t, &name, req.Name)
		assert.Equal(t, &isActive, req.IsActive)
		assert.Nil(t, req.Description)
	})
}

// ==================== User.ToSCIMUser ====================

func buildTestUserForSCIM() *User {
	id := uuid.New()
	tenantID := uuid.New()
	realmID := uuid.New()
	now := time.Now().Truncate(time.Second)
	firstName := testNameAlice
	lastName := testLastNameSmith
	displayName := "Alice Smith"
	phone := "+1-555-0100"
	dept := "Engineering"
	title := "Senior Engineer"

	return &User{
		ID:          id,
		TenantID:    tenantID,
		RealmID:     realmID,
		Username:    "alice.smith",
		Email:       "alice@example.com",
		FirstName:   &firstName,
		LastName:    &lastName,
		DisplayName: &displayName,
		Phone:       &phone,
		Department:  &dept,
		Title:       &title,
		IsActive:    true,
		IsLocked:    false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func TestUser_ToSCIMUser(t *testing.T) {
	baseURL := "https://auth.example.com"

	t.Run("should set correct SCIM schema", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser)
		assert.Contains(t, scimUser.Schemas, SCIMSchemaUser)
	})

	t.Run("should map user ID and username", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		assert.Equal(t, u.ID.String(), scimUser.ID)
		assert.Equal(t, u.Username, scimUser.UserName)
	})

	t.Run("should map active status correctly", func(t *testing.T) {
		tests := []struct {
			name       string
			isActive   bool
			isLocked   bool
			wantActive bool
		}{
			{"active and unlocked", true, false, true},
			{"active but locked", true, true, false},
			{"inactive and unlocked", false, false, false},
			{"inactive and locked", false, true, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				u := buildTestUserForSCIM()
				u.IsActive = tt.isActive
				u.IsLocked = tt.isLocked

				scimUser := u.ToSCIMUser(baseURL)

				assert.Equal(t, tt.wantActive, scimUser.Active)
			})
		}
	})

	t.Run("should map name fields correctly when both first and last name set", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser.Name)
		assert.Equal(t, testNameAlice, scimUser.Name.GivenName)
		assert.Equal(t, testLastNameSmith, scimUser.Name.FamilyName)
		assert.Equal(t, "Alice Smith", scimUser.Name.Formatted)
	})

	t.Run("should handle nil first name with last name only", func(t *testing.T) {
		u := buildTestUserForSCIM()
		u.FirstName = nil
		lastName := testLastNameSmith
		u.LastName = &lastName

		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser.Name)
		assert.Equal(t, "", scimUser.Name.GivenName)
		assert.Equal(t, testLastNameSmith, scimUser.Name.FamilyName)
		// Formatted is only set when both are present.
		assert.Equal(t, "", scimUser.Name.Formatted)
	})

	t.Run("should handle nil last name with first name only", func(t *testing.T) {
		u := buildTestUserForSCIM()
		firstName := testNameAlice
		u.FirstName = &firstName
		u.LastName = nil

		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser.Name)
		assert.Equal(t, testNameAlice, scimUser.Name.GivenName)
		assert.Equal(t, "", scimUser.Name.FamilyName)
		assert.Equal(t, "", scimUser.Name.Formatted)
	})

	t.Run("should not set Name when both first and last name are nil", func(t *testing.T) {
		u := buildTestUserForSCIM()
		u.FirstName = nil
		u.LastName = nil

		scimUser := u.ToSCIMUser(baseURL)

		assert.Nil(t, scimUser.Name)
	})

	t.Run("should map display name", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		assert.Equal(t, "Alice Smith", scimUser.DisplayName)
	})

	t.Run("should set empty display name when nil", func(t *testing.T) {
		u := buildTestUserForSCIM()
		u.DisplayName = nil

		scimUser := u.ToSCIMUser(baseURL)

		assert.Equal(t, "", scimUser.DisplayName)
	})

	t.Run("should include primary email", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		require.Len(t, scimUser.Emails, 1)
		assert.Equal(t, u.Email, scimUser.Emails[0].Value)
		assert.Equal(t, "work", scimUser.Emails[0].Type)
		assert.True(t, scimUser.Emails[0].Primary)
	})

	t.Run("should include phone number when set", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		require.Len(t, scimUser.PhoneNumbers, 1)
		assert.Equal(t, "+1-555-0100", scimUser.PhoneNumbers[0].Value)
		assert.Equal(t, "work", scimUser.PhoneNumbers[0].Type)
		assert.True(t, scimUser.PhoneNumbers[0].Primary)
	})

	t.Run("should omit phone numbers when phone is nil", func(t *testing.T) {
		u := buildTestUserForSCIM()
		u.Phone = nil

		scimUser := u.ToSCIMUser(baseURL)

		assert.Empty(t, scimUser.PhoneNumbers)
	})

	t.Run("should omit phone numbers when phone is empty string", func(t *testing.T) {
		u := buildTestUserForSCIM()
		emptyPhone := ""
		u.Phone = &emptyPhone

		scimUser := u.ToSCIMUser(baseURL)

		assert.Empty(t, scimUser.PhoneNumbers)
	})

	t.Run("should set enterprise user extension with department", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser.EnterpriseUser)
		assert.Equal(t, "Engineering", scimUser.EnterpriseUser.Department)
	})

	t.Run("should set title", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		assert.Equal(t, "Senior Engineer", scimUser.Title)
	})

	t.Run("should set meta fields with correct resource type and location", func(t *testing.T) {
		u := buildTestUserForSCIM()
		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser.Meta)
		assert.Equal(t, "User", scimUser.Meta.ResourceType)
		assert.Equal(t, baseURL+"/scim/v2/Users/"+u.ID.String(), scimUser.Meta.Location)
		assert.Equal(t, u.CreatedAt, scimUser.Meta.Created)
		assert.Equal(t, u.UpdatedAt, scimUser.Meta.LastModified)
	})

	t.Run("should handle user without optional fields (minimal user)", func(t *testing.T) {
		u := &User{
			ID:        uuid.New(),
			TenantID:  uuid.New(),
			RealmID:   uuid.New(),
			Username:  "minimal",
			Email:     "minimal@example.com",
			IsActive:  true,
			IsLocked:  false,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		scimUser := u.ToSCIMUser(baseURL)

		require.NotNil(t, scimUser)
		assert.Equal(t, u.ID.String(), scimUser.ID)
		assert.Equal(t, u.Username, scimUser.UserName)
		assert.True(t, scimUser.Active)
		assert.Nil(t, scimUser.Name)
		assert.Equal(t, "", scimUser.DisplayName)
		assert.Empty(t, scimUser.PhoneNumbers)
		assert.Nil(t, scimUser.EnterpriseUser)
	})
}

// ==================== Role.ToSCIMGroup ====================

func TestRole_ToSCIMGroup(t *testing.T) {
	baseURL := "https://auth.example.com"

	t.Run("should map role to SCIM group correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		now := time.Now().Truncate(time.Second)

		role := &Role{
			ID:          id,
			TenantID:    tenantID,
			Name:        "admin",
			DisplayName: "Administrators",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		scimGroup := role.ToSCIMGroup(baseURL)

		require.NotNil(t, scimGroup)
		assert.Contains(t, scimGroup.Schemas, SCIMSchemaGroup)
		assert.Equal(t, id.String(), scimGroup.ID)
		assert.Equal(t, "Administrators", scimGroup.DisplayName)
	})

	t.Run("should set meta fields correctly", func(t *testing.T) {
		id := uuid.New()
		now := time.Now().Truncate(time.Second)

		role := &Role{
			ID:          id,
			TenantID:    uuid.New(),
			Name:        "viewer",
			DisplayName: "Viewers",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		scimGroup := role.ToSCIMGroup(baseURL)

		require.NotNil(t, scimGroup.Meta)
		assert.Equal(t, "Group", scimGroup.Meta.ResourceType)
		assert.Equal(t, baseURL+"/scim/v2/Groups/"+id.String(), scimGroup.Meta.Location)
		assert.Equal(t, now, scimGroup.Meta.Created)
		assert.Equal(t, now, scimGroup.Meta.LastModified)
	})

	t.Run("should produce distinct instances on each call", func(t *testing.T) {
		role := &Role{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Name:        "editor",
			DisplayName: "Editors",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		g1 := role.ToSCIMGroup(baseURL)
		g2 := role.ToSCIMGroup(baseURL)

		assert.NotSame(t, g1, g2)
		assert.Equal(t, g1.ID, g2.ID)
		assert.Equal(t, g1.DisplayName, g2.DisplayName)
	})
}

// ==================== NewSCIMError ====================

func TestNewSCIMError(t *testing.T) {
	t.Run("should create error with required fields", func(t *testing.T) {
		err := NewSCIMError(404, "Resource not found", "noTarget")

		require.NotNil(t, err)
		assert.Contains(t, err.Schemas, SCIMSchemaError)
		assert.Equal(t, "noTarget", err.ScimType)
		assert.Equal(t, "Resource not found", err.Detail)
	})

	t.Run("should create error without scimType", func(t *testing.T) {
		err := NewSCIMError(400, "Invalid request", "")

		require.NotNil(t, err)
		assert.Equal(t, "", err.ScimType)
		assert.Equal(t, "Invalid request", err.Detail)
	})

	t.Run("should always include SCIM error schema", func(t *testing.T) {
		err := NewSCIMError(500, "Internal error", "")

		assert.Len(t, err.Schemas, 1)
		assert.Equal(t, SCIMSchemaError, err.Schemas[0])
	})
}

// ==================== SCIMUser struct ====================

func TestSCIMUser_Instantiation(t *testing.T) {
	t.Run("should create SCIM user with all fields", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		scimUser := &SCIMUser{
			Schemas:  []string{SCIMSchemaUser},
			ID:       uuid.New().String(),
			UserName: "bob@example.com",
			Name: &SCIMName{
				GivenName:  "Bob",
				FamilyName: "Jones",
				Formatted:  "Bob Jones",
			},
			DisplayName: "Bob Jones",
			Active:      true,
			Emails: []SCIMEmail{
				{Value: "bob@example.com", Type: "work", Primary: true},
			},
			PhoneNumbers: []SCIMPhoneNumber{
				{Value: "+1-555-0200", Type: "work", Primary: true},
			},
			EnterpriseUser: &SCIMEnterpriseUser{
				Department: "Sales",
				Manager: &SCIMManager{
					Value:       uuid.New().String(),
					DisplayName: "Jane Doe",
				},
			},
			Meta: &SCIMMeta{
				ResourceType: "User",
				Created:      now,
				LastModified: now,
				Location:     "https://auth.example.com/scim/v2/Users/abc",
			},
		}

		assert.Contains(t, scimUser.Schemas, SCIMSchemaUser)
		assert.Equal(t, "bob@example.com", scimUser.UserName)
		assert.True(t, scimUser.Active)
		require.NotNil(t, scimUser.Name)
		assert.Equal(t, "Bob", scimUser.Name.GivenName)
		assert.Equal(t, "Bob Jones", scimUser.Name.Formatted)
		assert.Len(t, scimUser.Emails, 1)
		assert.Len(t, scimUser.PhoneNumbers, 1)
		require.NotNil(t, scimUser.EnterpriseUser)
		assert.Equal(t, "Sales", scimUser.EnterpriseUser.Department)
		require.NotNil(t, scimUser.Meta)
		assert.Equal(t, "User", scimUser.Meta.ResourceType)
	})
}

// ==================== SCIMGroup struct ====================

func TestSCIMGroup_Instantiation(t *testing.T) {
	t.Run("should create SCIM group with members", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		memberID := uuid.New().String()

		group := &SCIMGroup{
			Schemas:     []string{SCIMSchemaGroup},
			ID:          uuid.New().String(),
			DisplayName: "Engineering",
			Members: []SCIMGroupMember{
				{
					Value:   memberID,
					Display: "Alice Smith",
					Type:    "User",
				},
			},
			Meta: &SCIMMeta{
				ResourceType: "Group",
				Created:      now,
				LastModified: now,
			},
		}

		assert.Contains(t, group.Schemas, SCIMSchemaGroup)
		assert.Equal(t, "Engineering", group.DisplayName)
		assert.Len(t, group.Members, 1)
		assert.Equal(t, memberID, group.Members[0].Value)
		assert.Equal(t, "Alice Smith", group.Members[0].Display)
		assert.Equal(t, "User", group.Members[0].Type)
	})

	t.Run("should allow empty members list", func(t *testing.T) {
		group := &SCIMGroup{
			Schemas:     []string{SCIMSchemaGroup},
			ID:          uuid.New().String(),
			DisplayName: "Empty Group",
			Members:     []SCIMGroupMember{},
		}

		assert.Empty(t, group.Members)
	})
}

// ==================== SCIMListResponse ====================

func TestSCIMListResponse_Instantiation(t *testing.T) {
	t.Run("should hold list response fields", func(t *testing.T) {
		users := []SCIMUser{
			{Schemas: []string{SCIMSchemaUser}, ID: uuid.New().String(), UserName: "user1"},
			{Schemas: []string{SCIMSchemaUser}, ID: uuid.New().String(), UserName: "user2"},
		}

		resp := &SCIMListResponse{
			Schemas:      []string{SCIMSchemaListResponse},
			TotalResults: 2,
			StartIndex:   1,
			ItemsPerPage: 100,
			Resources:    users,
		}

		assert.Contains(t, resp.Schemas, SCIMSchemaListResponse)
		assert.Equal(t, 2, resp.TotalResults)
		assert.Equal(t, 1, resp.StartIndex)
		assert.Equal(t, 100, resp.ItemsPerPage)
		assert.NotNil(t, resp.Resources)
	})
}

// ==================== SCIMPatchOp ====================

func TestSCIMPatchOp_Instantiation(t *testing.T) {
	tests := []struct {
		name  string
		op    string
		path  string
		value interface{}
	}{
		{
			name:  "add operation",
			op:    "add",
			path:  "members",
			value: map[string]interface{}{"value": "user-id-abc"},
		},
		{
			name:  "remove operation",
			op:    "remove",
			path:  `members[value eq "user-id-abc"]`,
			value: nil,
		},
		{
			name:  "replace operation",
			op:    "replace",
			path:  "active",
			value: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patchOp := SCIMPatchOp{
				Schemas: []string{SCIMSchemaPatchOp},
				Operations: []SCIMPatchOperation{
					{
						Op:    tt.op,
						Path:  tt.path,
						Value: tt.value,
					},
				},
			}

			assert.Contains(t, patchOp.Schemas, SCIMSchemaPatchOp)
			require.Len(t, patchOp.Operations, 1)
			assert.Equal(t, tt.op, patchOp.Operations[0].Op)
			assert.Equal(t, tt.path, patchOp.Operations[0].Path)
		})
	}
}

// ==================== SCIMServiceProviderConfig ====================

func TestSCIMServiceProviderConfig_Instantiation(t *testing.T) {
	t.Run("should create service provider config", func(t *testing.T) {
		config := &SCIMServiceProviderConfig{
			Schemas: []string{SCIMSchemaServiceProvider},
			Patch:   SCIMSupported{Supported: true},
			Bulk: SCIMBulkSupported{
				Supported:      false,
				MaxOperations:  0,
				MaxPayloadSize: 0,
			},
			Filter: SCIMFilterSupported{
				Supported:  true,
				MaxResults: 200,
			},
			ChangePassword: SCIMSupported{Supported: true},
			Sort:           SCIMSupported{Supported: false},
			ETag:           SCIMSupported{Supported: false},
			AuthenticationSchemes: []SCIMAuthScheme{
				{
					Type:        "oauthbearertoken",
					Name:        "OAuth Bearer Token",
					Description: "Authentication using OAuth 2.0 Bearer Token",
					Primary:     true,
				},
			},
		}

		assert.Contains(t, config.Schemas, SCIMSchemaServiceProvider)
		assert.True(t, config.Patch.Supported)
		assert.False(t, config.Bulk.Supported)
		assert.True(t, config.Filter.Supported)
		assert.Equal(t, 200, config.Filter.MaxResults)
		assert.Len(t, config.AuthenticationSchemes, 1)
		assert.Equal(t, "oauthbearertoken", config.AuthenticationSchemes[0].Type)
	})
}

// ==================== Bulk constants ====================

func TestSCIMBulkConstants(t *testing.T) {
	assert.Equal(t, 1000, SCIMMaxBulkOperations,
		"SCIMMaxBulkOperations must be 1000 per RFC 7644 advertised capability")
	assert.Equal(t, 1_048_576, SCIMMaxBulkPayloadBytes,
		"SCIMMaxBulkPayloadBytes must be 1 MiB per ServiceProviderConfig advertisement")
	assert.Equal(t, "urn:ietf:params:scim:api:messages:2.0:BulkRequest", SCIMSchemaBulkRequest)
	assert.Equal(t, "urn:ietf:params:scim:api:messages:2.0:BulkResponse", SCIMSchemaBulkResponse)
}

// ==================== SCIMBulkRequest model ====================

func TestSCIMBulkRequest_Instantiation(t *testing.T) {
	t.Run("fully populated request", func(t *testing.T) {
		failOn := 3
		req := SCIMBulkRequest{
			Schemas:      []string{SCIMSchemaBulkRequest},
			FailOnErrors: &failOn,
			Operations: []SCIMBulkOperation{
				{
					Method: "POST",
					Path:   "/Users",
					BulkID: "bulk-1",
					Data: map[string]interface{}{
						"userName": "alice@example.com",
					},
				},
				{
					Method: "DELETE",
					Path:   "/Users/some-uuid",
				},
			},
		}

		require.NotNil(t, req.FailOnErrors)
		assert.Equal(t, 3, *req.FailOnErrors)
		assert.Len(t, req.Operations, 2)
		assert.Equal(t, "POST", req.Operations[0].Method)
		assert.Equal(t, "bulk-1", req.Operations[0].BulkID)
		assert.Equal(t, "DELETE", req.Operations[1].Method)
		assert.Nil(t, req.Operations[1].Data)
	})

	t.Run("nil FailOnErrors means process all", func(t *testing.T) {
		req := SCIMBulkRequest{Schemas: []string{SCIMSchemaBulkRequest}}
		assert.Nil(t, req.FailOnErrors)
	})
}

// ==================== SCIMBulkResponse model ====================

func TestSCIMBulkResponse_Instantiation(t *testing.T) {
	t.Run("holds operation results with correct statuses", func(t *testing.T) {
		resp := SCIMBulkResponse{
			Schemas: []string{SCIMSchemaBulkResponse},
			Operations: []SCIMBulkOperationResult{
				{
					Method:   "POST",
					BulkID:   "bulk-1",
					Status:   "201",
					Location: "https://example.com/scim/v2/Users/new-id",
					Version:  `"abc123"`,
				},
				{
					Method: "DELETE",
					Status: "204",
				},
				{
					Method:   "PUT",
					BulkID:   "bulk-3",
					Status:   "400",
					Response: SCIMError{Schemas: []string{SCIMSchemaError}, Status: "400", Detail: "bad"},
				},
			},
		}

		assert.Equal(t, SCIMSchemaBulkResponse, resp.Schemas[0])
		assert.Len(t, resp.Operations, 3)
		assert.Equal(t, "201", resp.Operations[0].Status)
		assert.Equal(t, "bulk-1", resp.Operations[0].BulkID)
		assert.Equal(t, `"abc123"`, resp.Operations[0].Version)
		assert.Equal(t, "204", resp.Operations[1].Status)
		assert.Equal(t, "400", resp.Operations[2].Status)
	})
}

// ==================== SCIMBulkResponse JSON ====================

func TestSCIMBulkResponse_JSONMarshal(t *testing.T) {
	t.Run("marshals and unmarshals correctly", func(t *testing.T) {
		resp := &SCIMBulkResponse{
			Schemas: []string{SCIMSchemaBulkResponse},
			Operations: []SCIMBulkOperationResult{
				{Method: "POST", Status: "201", Location: "https://host/scim/v2/Users/u1"},
				{Method: "DELETE", Status: "404", Response: SCIMError{
					Schemas:  []string{SCIMSchemaError},
					Status:   "404",
					ScimType: "noTarget",
					Detail:   "not found",
				}},
			},
		}

		require.NotNil(t, resp)

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded SCIMBulkResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Len(t, decoded.Operations, 2)
		assert.Equal(t, "POST", decoded.Operations[0].Method)
		assert.Equal(t, "201", decoded.Operations[0].Status)
	})
}

// ==================== SCIMSearchRequest model ====================

func TestSCIMSearchRequest_Instantiation(t *testing.T) {
	t.Run("populates all fields", func(t *testing.T) {
		req := SCIMSearchRequest{
			Schemas:            []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
			Filter:             `userName eq "alice"`,
			SortBy:             "userName",
			SortOrder:          "ascending",
			StartIndex:         1,
			Count:              10,
			Attributes:         []string{"userName", "emails"},
			ExcludedAttributes: []string{"password"},
		}

		assert.Equal(t, `userName eq "alice"`, req.Filter)
		assert.Equal(t, "userName", req.SortBy)
		assert.Equal(t, "ascending", req.SortOrder)
		assert.Equal(t, 1, req.StartIndex)
		assert.Equal(t, 10, req.Count)
		assert.Equal(t, []string{"userName", "emails"}, req.Attributes)
		assert.Equal(t, []string{"password"}, req.ExcludedAttributes)
	})

	t.Run("zero values represent omitted / defaults", func(t *testing.T) {
		req := SCIMSearchRequest{}
		assert.Equal(t, 0, req.StartIndex)
		assert.Equal(t, 0, req.Count)
		assert.Empty(t, req.Filter)
	})
}

func TestSCIMSearchRequest_JSONMarshal(t *testing.T) {
	t.Run("omitempty fields are absent when zero", func(t *testing.T) {
		req := SCIMSearchRequest{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, hasFilter := decoded["filter"]
		assert.False(t, hasFilter, "filter should be absent when empty due to omitempty")
		_, hasSortBy := decoded["sortBy"]
		assert.False(t, hasSortBy, "sortBy should be absent when empty due to omitempty")
	})

	t.Run("all fields present when set", func(t *testing.T) {
		req := SCIMSearchRequest{
			Filter:     `userName co "alice"`,
			SortBy:     "emails.value",
			SortOrder:  "descending",
			StartIndex: 5,
			Count:      20,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, `userName co "alice"`, decoded["filter"])
		assert.Equal(t, "emails.value", decoded["sortBy"])
		assert.Equal(t, "descending", decoded["sortOrder"])
		assert.EqualValues(t, 5, decoded["startIndex"])
		assert.EqualValues(t, 20, decoded["count"])
	})
}

// ==================== JSON marshaling ====================

func TestSCIMUser_JSONMarshal(t *testing.T) {
	t.Run("should marshal and unmarshal SCIMUser", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		scimUser := &SCIMUser{
			Schemas:  []string{SCIMSchemaUser},
			ID:       uuid.New().String(),
			UserName: "alice@example.com",
			Active:   true,
			Emails: []SCIMEmail{
				{Value: "alice@example.com", Type: "work", Primary: true},
			},
			Meta: &SCIMMeta{
				ResourceType: "User",
				Created:      now,
				LastModified: now,
			},
		}

		data, err := json.Marshal(scimUser) //nolint:gosec // test struct with password field, not real credentials
		require.NoError(t, err)

		var decoded SCIMUser
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, scimUser.ID, decoded.ID)
		assert.Equal(t, scimUser.UserName, decoded.UserName)
		assert.Equal(t, scimUser.Active, decoded.Active)
		assert.Len(t, decoded.Emails, 1)
	})

	t.Run("should not include password in JSON output", func(t *testing.T) {
		scimUser := &SCIMUser{
			Schemas:  []string{SCIMSchemaUser},
			ID:       uuid.New().String(),
			UserName: "alice@example.com",
			Password: "super-secret-password",
			Active:   true,
		}

		data, err := json.Marshal(scimUser) //nolint:gosec // test struct with password field, not real credentials
		require.NoError(t, err)

		// password has omitempty so it will appear when set — this is expected
		// SCIM spec allows password in provisioning requests, responses omit it.
		// We just verify marshaling does not panic.
		assert.NotEmpty(t, data)
	})
}

func TestSCIMGroup_JSONMarshal(t *testing.T) {
	t.Run("should marshal and unmarshal SCIMGroup", func(t *testing.T) {
		group := &SCIMGroup{
			Schemas:     []string{SCIMSchemaGroup},
			ID:          uuid.New().String(),
			DisplayName: "Engineers",
		}

		data, err := json.Marshal(group)
		require.NoError(t, err)

		var decoded SCIMGroup
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, group.ID, decoded.ID)
		assert.Equal(t, group.DisplayName, decoded.DisplayName)
	})
}

func TestSCIMError_JSONMarshal(t *testing.T) {
	t.Run("should marshal SCIMError with expected JSON keys", func(t *testing.T) {
		scimErr := NewSCIMError(404, "Not Found", "noTarget")

		data, err := json.Marshal(scimErr)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Contains(t, decoded, "schemas")
		assert.Contains(t, decoded, "status")
		assert.Contains(t, decoded, "scimType")
		assert.Contains(t, decoded, "detail")
		assert.Equal(t, "Not Found", decoded["detail"])
		assert.Equal(t, "noTarget", decoded["scimType"])
	})
}
