// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// --- Mocks ---

type mockDefaultAccessPolicyRepo struct {
	policies []models.DefaultAccessPolicy
	count    int
	err      error
}

func (m *mockDefaultAccessPolicyRepo) ListByTenant(_ context.Context, tenantID uuid.UUID) ([]models.DefaultAccessPolicy, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Filter by tenant_id to simulate tenant isolation
	var result []models.DefaultAccessPolicy
	for _, p := range m.policies {
		if p.TenantID == tenantID {
			result = append(result, p)
		}
	}
	return result, nil
}

func (m *mockDefaultAccessPolicyRepo) CountByTenant(_ context.Context, _ uuid.UUID) (int, error) {
	return m.count, nil
}

type mockGranterRoleRepo struct {
	roles map[uuid.UUID]*models.Role
}

func (m *mockGranterRoleRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Role, error) {
	if role, ok := m.roles[id]; ok {
		return role, nil
	}
	return nil, fmt.Errorf("role not found")
}

type mockGranterGroupService struct {
	addMemberCalls []addMemberCall
	addMemberErr   error
}

type addMemberCall struct {
	GroupID uuid.UUID
	UserID  uuid.UUID
}

func (m *mockGranterGroupService) AddMember(_ context.Context, groupID, userID uuid.UUID) error {
	m.addMemberCalls = append(m.addMemberCalls, addMemberCall{GroupID: groupID, UserID: userID})
	return m.addMemberErr
}

type mockGranterRoleAssigner struct {
	assignCalls []roleAssignCall
	assignErr   error
}

type roleAssignCall struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	RoleID   uuid.UUID
}

func (m *mockGranterRoleAssigner) AssignRoleToUser(_ context.Context, tenantID, userID, roleID uuid.UUID) error {
	m.assignCalls = append(m.assignCalls, roleAssignCall{TenantID: tenantID, UserID: userID, RoleID: roleID})
	return m.assignErr
}

type mockGranterUserValidator struct {
	validPairs map[string]bool // "tenantID:userID" -> true
}

func (m *mockGranterUserValidator) UserBelongsToTenant(_ context.Context, tenantID, userID uuid.UUID) (bool, error) {
	key := tenantID.String() + ":" + userID.String()
	return m.validPairs[key], nil
}

// --- Tests ---

func TestDefaultAccessGranter_GrantDefaultAccess_NoActivePolicies(t *testing.T) {
	policyRepo := &mockDefaultAccessPolicyRepo{policies: nil}
	roleRepo := &mockGranterRoleRepo{roles: map[uuid.UUID]*models.Role{}}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	tenantID := uuid.New()
	userID := uuid.New()
	validator.validPairs[tenantID.String()+":"+userID.String()] = true

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	assert.NoError(t, err)
	assert.Empty(t, roleAssigner.assignCalls)
	assert.Empty(t, groupSvc.addMemberCalls)
}

func TestDefaultAccessGranter_GrantDefaultAccess_RolePolicy_AssignsRole(t *testing.T) {
	roleID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	policyRepo := &mockDefaultAccessPolicyRepo{
		policies: []models.DefaultAccessPolicy{
			{
				TenantID:   tenantID,
				PolicyType: models.DefaultAccessPolicyTypeRole,
				TargetID:   roleID,
				IsActive:   true,
			},
		},
	}
	roleRepo := &mockGranterRoleRepo{
		roles: map[uuid.UUID]*models.Role{
			roleID: {ID: roleID, Name: "viewer"},
		},
	}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{
		tenantID.String() + ":" + userID.String(): true,
	}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	assert.NoError(t, err)
	assert.Len(t, roleAssigner.assignCalls, 1)
	assert.Equal(t, tenantID, roleAssigner.assignCalls[0].TenantID)
	assert.Equal(t, userID, roleAssigner.assignCalls[0].UserID)
	assert.Equal(t, roleID, roleAssigner.assignCalls[0].RoleID)
}

func TestDefaultAccessGranter_GrantDefaultAccess_GroupPolicy_AddsToGroup(t *testing.T) {
	groupID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	policyRepo := &mockDefaultAccessPolicyRepo{
		policies: []models.DefaultAccessPolicy{
			{
				TenantID:   tenantID,
				PolicyType: models.DefaultAccessPolicyTypeGroup,
				TargetID:   groupID,
				IsActive:   true,
			},
		},
	}
	roleRepo := &mockGranterRoleRepo{roles: map[uuid.UUID]*models.Role{}}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{
		tenantID.String() + ":" + userID.String(): true,
	}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	assert.NoError(t, err)
	assert.Len(t, groupSvc.addMemberCalls, 1)
	assert.Equal(t, groupID, groupSvc.addMemberCalls[0].GroupID)
	assert.Equal(t, userID, groupSvc.addMemberCalls[0].UserID)
}

func TestDefaultAccessGranter_GrantDefaultAccess_MixedPolicies_BothApplied(t *testing.T) {
	roleID := uuid.New()
	groupID := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	policyRepo := &mockDefaultAccessPolicyRepo{
		policies: []models.DefaultAccessPolicy{
			{TenantID: tenantID, PolicyType: models.DefaultAccessPolicyTypeRole, TargetID: roleID, IsActive: true},
			{TenantID: tenantID, PolicyType: models.DefaultAccessPolicyTypeGroup, TargetID: groupID, IsActive: true},
		},
	}
	roleRepo := &mockGranterRoleRepo{
		roles: map[uuid.UUID]*models.Role{
			roleID: {ID: roleID, Name: "editor"},
		},
	}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{
		tenantID.String() + ":" + userID.String(): true,
	}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	assert.NoError(t, err)
	assert.Len(t, roleAssigner.assignCalls, 1)
	assert.Len(t, groupSvc.addMemberCalls, 1)
}

func TestDefaultAccessGranter_GrantDefaultAccess_RejectsAdminRoles(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	blockedRoles := []string{"admin", "org_admin", "owner", "platform_admin", "super_admin", "iam_admin"}
	for _, roleName := range blockedRoles {
		t.Run(roleName, func(t *testing.T) {
			roleID := uuid.New()
			policyRepo := &mockDefaultAccessPolicyRepo{
				policies: []models.DefaultAccessPolicy{
					{TenantID: tenantID, PolicyType: models.DefaultAccessPolicyTypeRole, TargetID: roleID, IsActive: true},
				},
			}
			roleRepo := &mockGranterRoleRepo{
				roles: map[uuid.UUID]*models.Role{
					roleID: {ID: roleID, Name: roleName},
				},
			}
			roleAssigner := &mockGranterRoleAssigner{}
			groupSvc := &mockGranterGroupService{}
			validator := &mockGranterUserValidator{validPairs: map[string]bool{
				tenantID.String() + ":" + userID.String(): true,
			}}

			granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

			err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

			// Should succeed (best-effort) but NOT assign the blocked role
			assert.NoError(t, err)
			assert.Empty(t, roleAssigner.assignCalls, "blocked role %q should not be assigned", roleName)
		})
	}
}

func TestDefaultAccessGranter_GrantDefaultAccess_CrossTenantIsolation(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	userID := uuid.New()

	policyRepo := &mockDefaultAccessPolicyRepo{
		policies: []models.DefaultAccessPolicy{
			{TenantID: tenantA, PolicyType: models.DefaultAccessPolicyTypeRole, TargetID: uuid.New(), IsActive: true},
		},
	}
	roleRepo := &mockGranterRoleRepo{roles: map[uuid.UUID]*models.Role{}}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	// User belongs to tenant B, NOT tenant A
	validator := &mockGranterUserValidator{validPairs: map[string]bool{
		tenantB.String() + ":" + userID.String(): true,
	}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	err := granter.GrantDefaultAccess(context.Background(), tenantA, userID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong to tenant")
	assert.Empty(t, roleAssigner.assignCalls)
}

func TestDefaultAccessGranter_GrantDefaultAccess_RoleAssignError_ContinuesOthers(t *testing.T) {
	roleID1 := uuid.New()
	roleID2 := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()

	policyRepo := &mockDefaultAccessPolicyRepo{
		policies: []models.DefaultAccessPolicy{
			{TenantID: tenantID, PolicyType: models.DefaultAccessPolicyTypeRole, TargetID: roleID1, IsActive: true},
			{TenantID: tenantID, PolicyType: models.DefaultAccessPolicyTypeRole, TargetID: roleID2, IsActive: true},
		},
	}
	roleRepo := &mockGranterRoleRepo{
		roles: map[uuid.UUID]*models.Role{
			roleID1: {ID: roleID1, Name: "viewer"},
			roleID2: {ID: roleID2, Name: "editor"},
		},
	}
	// First call fails, second succeeds
	callCount := 0
	roleAssigner := &mockGranterRoleAssigner{}
	roleAssigner.assignErr = nil // we'll handle per-call below

	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{
		tenantID.String() + ":" + userID.String(): true,
	}}

	// Use a custom assigner that fails on first call
	customAssigner := &failFirstRoleAssigner{callCount: &callCount}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, customAssigner, groupSvc, validator)

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	// Should succeed (best-effort pattern)
	assert.NoError(t, err)
	// Both calls attempted
	assert.Equal(t, 2, callCount)
}

type failFirstRoleAssigner struct {
	callCount *int
}

func (m *failFirstRoleAssigner) AssignRoleToUser(_ context.Context, _, _, _ uuid.UUID) error {
	*m.callCount++
	if *m.callCount == 1 {
		return fmt.Errorf("transient error")
	}
	return nil
}

func TestDefaultAccessGranter_GrantDefaultAccess_AssignmentLimitEnforced(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()

	// Create 25 policies (exceeds MaxDefaultAccessAssignmentsPerUser = 20)
	var policies []models.DefaultAccessPolicy
	roles := make(map[uuid.UUID]*models.Role)
	for i := 0; i < 25; i++ {
		roleID := uuid.New()
		policies = append(policies, models.DefaultAccessPolicy{
			TenantID:   tenantID,
			PolicyType: models.DefaultAccessPolicyTypeRole,
			TargetID:   roleID,
			IsActive:   true,
		})
		roles[roleID] = &models.Role{ID: roleID, Name: fmt.Sprintf("role_%d", i)}
	}

	policyRepo := &mockDefaultAccessPolicyRepo{policies: policies}
	roleRepo := &mockGranterRoleRepo{roles: roles}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{
		tenantID.String() + ":" + userID.String(): true,
	}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	assert.NoError(t, err)
	// Should stop at MaxDefaultAccessAssignmentsPerUser
	assert.LessOrEqual(t, len(roleAssigner.assignCalls)+len(groupSvc.addMemberCalls), models.MaxDefaultAccessAssignmentsPerUser)
}

func TestDefaultAccessGranter_GrantDefaultAccess_RepoError_ReturnsError(t *testing.T) {
	policyRepo := &mockDefaultAccessPolicyRepo{err: fmt.Errorf("database unavailable")}
	roleRepo := &mockGranterRoleRepo{roles: map[uuid.UUID]*models.Role{}}
	roleAssigner := &mockGranterRoleAssigner{}
	groupSvc := &mockGranterGroupService{}
	validator := &mockGranterUserValidator{validPairs: map[string]bool{}}

	granter := NewDefaultAccessGranter(policyRepo, roleRepo, roleAssigner, groupSvc, validator)

	tenantID := uuid.New()
	userID := uuid.New()
	validator.validPairs[tenantID.String()+":"+userID.String()] = true

	err := granter.GrantDefaultAccess(context.Background(), tenantID, userID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database unavailable")
}
