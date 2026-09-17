// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== AppAccessRoleAssignment struct ====================

func TestAppAccessRoleAssignment_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		userID := uuid.New()
		clientID := uuid.New()
		roleID := uuid.New()
		assignedBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		assignment := AppAccessRoleAssignment{
			ID:         id,
			TenantID:   tenantID,
			UserID:     userID,
			ClientID:   clientID,
			RoleID:     roleID,
			AssignedBy: &assignedBy,
			CreatedAt:  now,
			RoleName:   "editor",
			Username:   "alice@example.com",
		}

		assert.Equal(t, id, assignment.ID)
		assert.Equal(t, tenantID, assignment.TenantID)
		assert.Equal(t, userID, assignment.UserID)
		assert.Equal(t, clientID, assignment.ClientID)
		assert.Equal(t, roleID, assignment.RoleID)
		require.NotNil(t, assignment.AssignedBy)
		assert.Equal(t, assignedBy, *assignment.AssignedBy)
		assert.Equal(t, now, assignment.CreatedAt)
		assert.Equal(t, "editor", assignment.RoleName)
		assert.Equal(t, "alice@example.com", assignment.Username)
	})

	t.Run("should allow nil AssignedBy", func(t *testing.T) {
		assignment := AppAccessRoleAssignment{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			UserID:   uuid.New(),
			ClientID: uuid.New(),
			RoleID:   uuid.New(),
		}

		assert.Nil(t, assignment.AssignedBy)
	})

	t.Run("should allow empty joined fields", func(t *testing.T) {
		assignment := AppAccessRoleAssignment{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			UserID:   uuid.New(),
			ClientID: uuid.New(),
			RoleID:   uuid.New(),
		}

		assert.Empty(t, assignment.RoleName)
		assert.Empty(t, assignment.Username)
	})
}

// ==================== AppAuthPolicy struct ====================

func TestAppAuthPolicy_StructFields(t *testing.T) {
	t.Run("should carry all fields correctly", func(t *testing.T) {
		id := uuid.New()
		clientID := uuid.New()
		tenantID := uuid.New()
		maxDuration := 3600
		now := time.Now().Truncate(time.Second)

		policy := AppAuthPolicy{
			ID:                        id,
			ClientID:                  clientID,
			TenantID:                  tenantID,
			RequireMFA:                true,
			RequireAssignment:         true,
			AllowedIPRanges:           []string{"10.0.0.0/8", "192.168.0.0/16"},
			MaxSessionDurationSeconds: &maxDuration,
			CreatedAt:                 now,
			UpdatedAt:                 now,
		}

		assert.Equal(t, id, policy.ID)
		assert.Equal(t, clientID, policy.ClientID)
		assert.Equal(t, tenantID, policy.TenantID)
		assert.True(t, policy.RequireMFA)
		assert.True(t, policy.RequireAssignment)
		assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, policy.AllowedIPRanges)
		require.NotNil(t, policy.MaxSessionDurationSeconds)
		assert.Equal(t, 3600, *policy.MaxSessionDurationSeconds)
		assert.Equal(t, now, policy.CreatedAt)
		assert.Equal(t, now, policy.UpdatedAt)
	})

	t.Run("should allow nil MaxSessionDurationSeconds and empty IP ranges", func(t *testing.T) {
		policy := AppAuthPolicy{
			ID:                uuid.New(),
			ClientID:          uuid.New(),
			TenantID:          uuid.New(),
			RequireMFA:        false,
			RequireAssignment: false,
		}

		assert.Nil(t, policy.MaxSessionDurationSeconds)
		assert.Nil(t, policy.AllowedIPRanges)
	})
}

// ==================== CreateAppRoleAssignmentRequest ====================

func TestCreateAppRoleAssignmentRequest_StructFields(t *testing.T) {
	t.Run("should carry UserID, RoleID and TenantID", func(t *testing.T) {
		userID := uuid.New()
		roleID := uuid.New()
		tenantID := uuid.New()

		req := CreateAppRoleAssignmentRequest{
			UserID:   userID,
			RoleID:   roleID,
			TenantID: tenantID,
		}

		assert.Equal(t, userID, req.UserID)
		assert.Equal(t, roleID, req.RoleID)
		assert.Equal(t, tenantID, req.TenantID)
	})
}

// ==================== AppAccessRoleAssignmentResponse ====================

func TestAppAccessRoleAssignmentResponse_StructFields(t *testing.T) {
	t.Run("should carry all response fields", func(t *testing.T) {
		id := uuid.New()
		tenantID := uuid.New()
		userID := uuid.New()
		clientID := uuid.New()
		roleID := uuid.New()
		assignedBy := uuid.New()
		now := time.Now().Truncate(time.Second)

		resp := AppAccessRoleAssignmentResponse{
			ID:         id,
			TenantID:   tenantID,
			UserID:     userID,
			ClientID:   clientID,
			RoleID:     roleID,
			RoleName:   "admin",
			Username:   "bob@example.com",
			AssignedBy: &assignedBy,
			CreatedAt:  now,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.Equal(t, userID, resp.UserID)
		assert.Equal(t, clientID, resp.ClientID)
		assert.Equal(t, roleID, resp.RoleID)
		assert.Equal(t, "admin", resp.RoleName)
		assert.Equal(t, "bob@example.com", resp.Username)
		require.NotNil(t, resp.AssignedBy)
		assert.Equal(t, assignedBy, *resp.AssignedBy)
		assert.Equal(t, now, resp.CreatedAt)
	})

	t.Run("should allow nil AssignedBy and empty string joined fields", func(t *testing.T) {
		resp := AppAccessRoleAssignmentResponse{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			UserID:   uuid.New(),
			ClientID: uuid.New(),
			RoleID:   uuid.New(),
		}

		assert.Nil(t, resp.AssignedBy)
		assert.Empty(t, resp.RoleName)
		assert.Empty(t, resp.Username)
	})
}

// ==================== CreateAppAuthPolicyRequest ====================

func TestCreateAppAuthPolicyRequest_StructFields(t *testing.T) {
	t.Run("should carry all creation fields", func(t *testing.T) {
		tenantID := uuid.New()
		maxDuration := 7200

		req := CreateAppAuthPolicyRequest{
			TenantID:                  tenantID,
			RequireMFA:                true,
			RequireAssignment:         false,
			AllowedIPRanges:           []string{"0.0.0.0/0"},
			MaxSessionDurationSeconds: &maxDuration,
		}

		assert.Equal(t, tenantID, req.TenantID)
		assert.True(t, req.RequireMFA)
		assert.False(t, req.RequireAssignment)
		assert.Equal(t, []string{"0.0.0.0/0"}, req.AllowedIPRanges)
		require.NotNil(t, req.MaxSessionDurationSeconds)
		assert.Equal(t, 7200, *req.MaxSessionDurationSeconds)
	})

	t.Run("should allow nil MaxSessionDurationSeconds and no IP ranges", func(t *testing.T) {
		req := CreateAppAuthPolicyRequest{
			TenantID: uuid.New(),
		}

		assert.Nil(t, req.MaxSessionDurationSeconds)
		assert.Nil(t, req.AllowedIPRanges)
	})
}

// ==================== UpdateAppAuthPolicyRequest ====================

func TestUpdateAppAuthPolicyRequest_StructFields(t *testing.T) {
	t.Run("should carry optional update fields", func(t *testing.T) {
		requireMFA := true
		requireAssignment := false
		maxDuration := 1800

		req := UpdateAppAuthPolicyRequest{
			RequireMFA:                &requireMFA,
			RequireAssignment:         &requireAssignment,
			AllowedIPRanges:           []string{"172.16.0.0/12"},
			MaxSessionDurationSeconds: &maxDuration,
		}

		require.NotNil(t, req.RequireMFA)
		assert.True(t, *req.RequireMFA)
		require.NotNil(t, req.RequireAssignment)
		assert.False(t, *req.RequireAssignment)
		assert.Equal(t, []string{"172.16.0.0/12"}, req.AllowedIPRanges)
		require.NotNil(t, req.MaxSessionDurationSeconds)
		assert.Equal(t, 1800, *req.MaxSessionDurationSeconds)
	})

	t.Run("should allow all nil for partial patch", func(t *testing.T) {
		req := UpdateAppAuthPolicyRequest{}

		assert.Nil(t, req.RequireMFA)
		assert.Nil(t, req.RequireAssignment)
		assert.Nil(t, req.AllowedIPRanges)
		assert.Nil(t, req.MaxSessionDurationSeconds)
	})
}

// ==================== AppAuthPolicyResponse ====================

func TestAppAuthPolicyResponse_StructFields(t *testing.T) {
	t.Run("should carry all response fields", func(t *testing.T) {
		id := uuid.New()
		clientID := uuid.New()
		tenantID := uuid.New()
		maxDuration := 3600
		now := time.Now().Truncate(time.Second)

		resp := AppAuthPolicyResponse{
			ID:                        id,
			ClientID:                  clientID,
			TenantID:                  tenantID,
			RequireMFA:                true,
			RequireAssignment:         true,
			AllowedIPRanges:           []string{"10.0.0.0/8"},
			MaxSessionDurationSeconds: &maxDuration,
			CreatedAt:                 now,
			UpdatedAt:                 now,
		}

		assert.Equal(t, id, resp.ID)
		assert.Equal(t, clientID, resp.ClientID)
		assert.Equal(t, tenantID, resp.TenantID)
		assert.True(t, resp.RequireMFA)
		assert.True(t, resp.RequireAssignment)
		assert.Equal(t, []string{"10.0.0.0/8"}, resp.AllowedIPRanges)
		require.NotNil(t, resp.MaxSessionDurationSeconds)
		assert.Equal(t, 3600, *resp.MaxSessionDurationSeconds)
		assert.Equal(t, now, resp.CreatedAt)
		assert.Equal(t, now, resp.UpdatedAt)
	})

	t.Run("should allow nil MaxSessionDurationSeconds and empty IP ranges", func(t *testing.T) {
		resp := AppAuthPolicyResponse{
			ID:       uuid.New(),
			ClientID: uuid.New(),
			TenantID: uuid.New(),
		}

		assert.Nil(t, resp.MaxSessionDurationSeconds)
		assert.Nil(t, resp.AllowedIPRanges)
	})
}

// ==================== IP range variations ====================

func TestAppAuthPolicy_IPRangeVariations(t *testing.T) {
	tests := []struct {
		name   string
		ranges []string
	}{
		{
			name:   "single IP CIDR",
			ranges: []string{"192.168.1.0/24"},
		},
		{
			name:   "multiple CIDRs",
			ranges: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},
		{
			name:   "allow all IPv4",
			ranges: []string{"0.0.0.0/0"},
		},
		{
			name:   "empty list means no restriction",
			ranges: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := AppAuthPolicy{
				ID:              uuid.New(),
				ClientID:        uuid.New(),
				TenantID:        uuid.New(),
				AllowedIPRanges: tt.ranges,
			}

			assert.Equal(t, tt.ranges, policy.AllowedIPRanges)
		})
	}
}
