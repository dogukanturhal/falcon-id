// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestOrganizationService_GetTeamScope(t *testing.T) {
	ctx := t.Context()
	tenant, other := uuid.New(), uuid.New()
	me, peer, report := uuid.New(), uuid.New(), uuid.New()
	team := &models.Organization{ID: uuid.New(), TenantID: tenant, Name: "Sales", OrgType: models.OrgTypeTeam, IsActive: true}
	sub := &models.Organization{ID: uuid.New(), TenantID: tenant, Name: "Sub", OrgType: models.OrgTypeTeam, IsActive: true}
	foreign := &models.Organization{ID: uuid.New(), TenantID: other, Name: "X", OrgType: models.OrgTypeTeam, IsActive: true}
	project := &models.Organization{ID: uuid.New(), TenantID: tenant, Name: "P", OrgType: models.OrgTypeProject, IsActive: true}

	repo := new(MockOrgRepo)
	repo.On("GetUserOrganizations", mock.Anything, me).Return([]*models.OrgMember{
		{OrganizationID: team.ID, UserID: me, Role: models.OrgRoleManager},
		{OrganizationID: foreign.ID, UserID: me, Role: models.OrgRoleMember},
		{OrganizationID: project.ID, UserID: me, Role: models.OrgRoleMember},
	}, nil)
	for _, o := range []*models.Organization{team, foreign, project} {
		repo.On("GetByID", mock.Anything, o.ID).Return(o, nil)
	}
	repo.On("GetMembers", mock.Anything, team.ID, 1, teamScopePageSize).Return([]*models.OrgMember{{UserID: me}, {UserID: peer}}, 2, nil)
	repo.On("GetMembers", mock.Anything, sub.ID, 1, teamScopePageSize).Return([]*models.OrgMember{{UserID: report}}, 1, nil)
	repo.On("GetDescendants", mock.Anything, team.ID).Return([]*models.Organization{sub}, nil)

	svc := NewOrganizationService(repo, nil)
	scope, err := svc.GetTeamScope(ctx, tenant, me)
	require.NoError(t, err)
	require.True(t, scope.HasTeam)
	require.Len(t, scope.Teams, 1)
	require.True(t, scope.Teams[0].Manages)
	require.ElementsMatch(t, []uuid.UUID{me, peer, report}, scope.MemberUserIDs)
}

func TestOrganizationService_GetTeamScope_NoTeam(t *testing.T) {
	repo := new(MockOrgRepo)
	me := uuid.New()
	repo.On("GetUserOrganizations", mock.Anything, me).Return([]*models.OrgMember{}, nil)
	scope, err := NewOrganizationService(repo, nil).GetTeamScope(t.Context(), uuid.New(), me)
	require.NoError(t, err)
	require.False(t, scope.HasTeam)
	require.Empty(t, scope.MemberUserIDs)
}
