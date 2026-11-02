// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const teamScopePageSize = 100

// allOrgMemberIDs pages through every member of an organization.
func (s *OrganizationService) allOrgMemberIDs(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	for page := 1; ; page++ {
		members, total, err := s.orgRepo.GetMembers(ctx, orgID, page, teamScopePageSize)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			ids = append(ids, m.UserID)
		}
		if len(members) == 0 || page*teamScopePageSize >= total {
			return ids, nil
		}
	}
}

// GetTeamScope returns the teams/departments the user belongs to and the user
// IDs visible through them. Plain members see every member of their own team;
// managers/leads/owners also see members of all descendant organizations.
func (s *OrganizationService) GetTeamScope(ctx context.Context, tenantID, userID uuid.UUID) (*models.TeamScope, error) {
	memberships, err := s.orgRepo.GetUserOrganizations(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetTeamScope: %w", err)
	}

	scope := &models.TeamScope{TenantID: tenantID, UserID: userID, MemberUserIDs: []uuid.UUID{}, Teams: []models.TeamScopeTeam{}}
	union := map[uuid.UUID]struct{}{}

	for _, m := range memberships {
		org, err := s.orgRepo.GetByID(ctx, m.OrganizationID)
		if err != nil {
			return nil, fmt.Errorf("GetTeamScope: %w", err)
		}
		if org.TenantID != tenantID || !org.IsActive {
			continue
		}
		if org.OrgType != models.OrgTypeTeam && org.OrgType != models.OrgTypeDepartment {
			continue
		}

		ids, err := s.allOrgMemberIDs(ctx, org.ID)
		if err != nil {
			return nil, fmt.Errorf("GetTeamScope: %w", err)
		}
		manages := models.IsOrgManagerRole(m.Role)
		if manages {
			descendants, err := s.orgRepo.GetDescendants(ctx, org.ID)
			if err != nil {
				return nil, fmt.Errorf("GetTeamScope: %w", err)
			}
			for _, d := range descendants {
				if d.TenantID != tenantID || !d.IsActive {
					continue
				}
				dIDs, err := s.allOrgMemberIDs(ctx, d.ID)
				if err != nil {
					return nil, fmt.Errorf("GetTeamScope: %w", err)
				}
				ids = append(ids, dIDs...)
			}
		}

		ids = dedupeSortedUUIDs(ids)
		for _, id := range ids {
			union[id] = struct{}{}
		}
		scope.Teams = append(scope.Teams, models.TeamScopeTeam{
			ID: org.ID, Name: org.Name, OrgType: org.OrgType, Role: m.Role, Manages: manages, MemberUserIDs: ids,
		})
	}

	if len(scope.Teams) > 0 {
		scope.HasTeam = true
		union[userID] = struct{}{}
		for id := range union {
			scope.MemberUserIDs = append(scope.MemberUserIDs, id)
		}
		sort.Slice(scope.MemberUserIDs, func(i, j int) bool { return scope.MemberUserIDs[i].String() < scope.MemberUserIDs[j].String() })
	}
	return scope, nil
}

func dedupeSortedUUIDs(in []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(in))
	out := make([]uuid.UUID, 0, len(in))
	for _, id := range in {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
