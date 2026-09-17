// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const (
	scimAttrUsername    = "username"
	scimAttrDisplayName = "displayname"
)

// ==================== SCIM Discovery ====================

// GetServiceProviderConfig returns the SCIM service provider configuration
func (s *SCIMService) GetServiceProviderConfig() *models.SCIMServiceProviderConfig {
	return &models.SCIMServiceProviderConfig{
		Schemas:          []string{models.SCIMSchemaServiceProvider},
		DocumentationURI: "https://docs.hexxlock.com/scim",
		Patch:            models.SCIMSupported{Supported: true},
		Bulk: models.SCIMBulkSupported{
			Supported:      true,
			MaxOperations:  models.SCIMMaxBulkOperations,
			MaxPayloadSize: models.SCIMMaxBulkPayloadBytes,
		},
		Filter: models.SCIMFilterSupported{
			Supported:  true,
			MaxResults: 200,
		},
		ChangePassword: models.SCIMSupported{Supported: true},
		Sort:           models.SCIMSupported{Supported: false},
		ETag:           models.SCIMSupported{Supported: true},
		AuthenticationSchemes: []models.SCIMAuthScheme{
			{
				Type:        "oauthbearertoken",
				Name:        "OAuth Bearer Token",
				Description: "Authentication scheme using the OAuth Bearer Token Standard",
				Primary:     true,
			},
		},
		Meta: &models.SCIMMeta{
			ResourceType: "ServiceProviderConfig",
			Location:     s.getBaseURL() + "/scim/v2/ServiceProviderConfig",
		},
	}
}

// GetSchemas returns the SCIM schemas
func (s *SCIMService) GetSchemas() *models.SCIMListResponse {
	schemas := []models.SCIMSchema{
		{
			Schemas:     []string{models.SCIMSchemaSchema},
			ID:          models.SCIMSchemaUser,
			Name:        "User",
			Description: "User Account",
			Meta: &models.SCIMMeta{
				ResourceType: "Schema",
				Location:     s.getBaseURL() + "/scim/v2/Schemas/" + models.SCIMSchemaUser,
			},
		},
		{
			Schemas:     []string{models.SCIMSchemaSchema},
			ID:          models.SCIMSchemaGroup,
			Name:        "Group",
			Description: "Group",
			Meta: &models.SCIMMeta{
				ResourceType: "Schema",
				Location:     s.getBaseURL() + "/scim/v2/Schemas/" + models.SCIMSchemaGroup,
			},
		},
	}

	return &models.SCIMListResponse{
		Schemas:      []string{models.SCIMSchemaListResponse},
		TotalResults: len(schemas),
		StartIndex:   1,
		ItemsPerPage: len(schemas),
		Resources:    schemas,
	}
}

// GetResourceTypes returns the SCIM resource types
func (s *SCIMService) GetResourceTypes() *models.SCIMListResponse {
	resourceTypes := []models.SCIMResourceType{
		{
			Schemas:     []string{models.SCIMSchemaResourceType},
			ID:          "User",
			Name:        "User",
			Description: "User Account",
			Endpoint:    "/Users",
			Schema:      models.SCIMSchemaUser,
			SchemaExtensions: []models.SCIMSchemaExtension{
				{
					Schema:   models.SCIMSchemaEnterpriseUser,
					Required: false,
				},
			},
			Meta: &models.SCIMMeta{
				ResourceType: "ResourceType",
				Location:     s.getBaseURL() + "/scim/v2/ResourceTypes/User",
			},
		},
		{
			Schemas:     []string{models.SCIMSchemaResourceType},
			ID:          "Group",
			Name:        "Group",
			Description: "Group",
			Endpoint:    "/Groups",
			Schema:      models.SCIMSchemaGroup,
			Meta: &models.SCIMMeta{
				ResourceType: "ResourceType",
				Location:     s.getBaseURL() + "/scim/v2/ResourceTypes/Group",
			},
		},
	}

	return &models.SCIMListResponse{
		Schemas:      []string{models.SCIMSchemaListResponse},
		TotalResults: len(resourceTypes),
		StartIndex:   1,
		ItemsPerPage: len(resourceTypes),
		Resources:    resourceTypes,
	}
}

// ==================== Helper Functions ====================

func (s *SCIMService) getBaseURL() string {
	baseURL := os.Getenv("SCIM_BASE_URL")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%s", s.cfg.ServicePort)
	}
	return baseURL
}

func (s *SCIMService) filterUsers(users []*models.User, filter string) []*models.User {
	// Simple filter parsing: userName eq "value"
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return users
	}

	parts := strings.SplitN(filter, " ", 3)
	if len(parts) < 3 {
		return users
	}

	attr := strings.ToLower(parts[0])
	op := strings.ToLower(parts[1])
	value := strings.Trim(parts[2], "\"")

	var filtered []*models.User
	for _, user := range users {
		match := false
		switch attr {
		case scimAttrUsername:
			switch op {
			case "eq":
				match = strings.EqualFold(user.Username, value)
			case "co":
				match = strings.Contains(strings.ToLower(user.Username), strings.ToLower(value))
			case "sw":
				match = strings.HasPrefix(strings.ToLower(user.Username), strings.ToLower(value))
			}
		case authMethodEmail, "emails.value":
			switch op {
			case "eq":
				match = strings.EqualFold(user.Email, value)
			case "co":
				match = strings.Contains(strings.ToLower(user.Email), strings.ToLower(value))
			}
		case "active":
			boolValue, _ := strconv.ParseBool(value)
			match = user.IsActive == boolValue
		}
		if match {
			filtered = append(filtered, user)
		}
	}

	return filtered
}

func (s *SCIMService) filterGroups(roles []*models.Role, filter string) []*models.Role {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return roles
	}

	parts := strings.SplitN(filter, " ", 3)
	if len(parts) < 3 {
		return roles
	}

	attr := strings.ToLower(parts[0])
	op := strings.ToLower(parts[1])
	value := strings.Trim(parts[2], "\"")

	var filtered []*models.Role
	for _, role := range roles {
		match := false
		if attr == scimAttrDisplayName {
			switch op {
			case "eq":
				match = strings.EqualFold(role.DisplayName, value)
			case "co":
				match = strings.Contains(strings.ToLower(role.DisplayName), strings.ToLower(value))
			}
		}
		if match {
			filtered = append(filtered, role)
		}
	}

	return filtered
}

func (s *SCIMService) applyUserPatchReplace(user *models.User, path string, value interface{}) {
	switch strings.ToLower(path) {
	case scimAttrUsername:
		if str, ok := value.(string); ok {
			user.Username = str
		}
	case "active":
		if b, ok := value.(bool); ok {
			user.IsActive = b
		}
	case "name.givenname":
		if str, ok := value.(string); ok {
			user.FirstName = &str
		}
	case "name.familyname":
		if str, ok := value.(string); ok {
			user.LastName = &str
		}
	case scimAttrDisplayName:
		if str, ok := value.(string); ok {
			user.DisplayName = &str
		}
	case "title":
		if str, ok := value.(string); ok {
			user.Title = &str
		}
	case "":
		// Replace entire user object
		if userMap, ok := value.(map[string]interface{}); ok {
			if active, ok := userMap["active"].(bool); ok {
				user.IsActive = active
			}
		}
	}
}

func (s *SCIMService) applyUserPatchAdd(user *models.User, path string, value interface{}) {
	// Add operations work similar to replace for single-valued attributes
	s.applyUserPatchReplace(user, path, value)
}

func (s *SCIMService) applyUserPatchRemove(user *models.User, path string) {
	switch strings.ToLower(path) {
	case "name.givenname":
		user.FirstName = nil
	case "name.familyname":
		user.LastName = nil
	case scimAttrDisplayName:
		user.DisplayName = nil
	case "title":
		user.Title = nil
	case "phonenumbers":
		user.Phone = nil
	}
}

func (s *SCIMService) addGroupMembers(ctx context.Context, groupID uuid.UUID, value interface{}) {
	// Get user IDs to add
	var userIDs []uuid.UUID

	switch v := value.(type) {
	case []interface{}:
		for _, member := range v {
			if m, ok := member.(map[string]interface{}); ok {
				if userID, ok := m["value"].(string); ok {
					uid, err := uuid.Parse(userID)
					if err == nil {
						userIDs = append(userIDs, uid)
					}
				}
			}
		}
	case map[string]interface{}:
		if userID, ok := v["value"].(string); ok {
			uid, err := uuid.Parse(userID)
			if err == nil {
				userIDs = append(userIDs, uid)
			}
		}
	}

	// Assign role to each user
	for _, userID := range userIDs {
		// Get current roles and add the new one
		currentRoles, err := s.userRepo.GetUserRoles(ctx, userID)
		if err != nil {
			continue
		}

		roleIDs := make([]uuid.UUID, 0, len(currentRoles)+1)
		for _, role := range currentRoles {
			roleIDs = append(roleIDs, role.ID)
		}
		roleIDs = append(roleIDs, groupID)

		_ = s.userRepo.AssignRoles(ctx, userID, roleIDs, nil)
	}
}

func (s *SCIMService) removeGroupMembers(ctx context.Context, groupID uuid.UUID, path string) {
	// Path format: members[value eq "user-id"]
	if !strings.Contains(path, "value eq") {
		return
	}
	start := strings.Index(path, `"`)
	end := strings.LastIndex(path, `"`)
	if start == -1 || end <= start {
		return
	}
	userID, err := uuid.Parse(path[start+1 : end])
	if err != nil {
		return
	}
	currentRoles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return
	}
	roleIDs := make([]uuid.UUID, 0, len(currentRoles))
	for _, role := range currentRoles {
		if role.ID != groupID {
			roleIDs = append(roleIDs, role.ID)
		}
	}
	_ = s.userRepo.AssignRoles(ctx, userID, roleIDs, nil)
}
