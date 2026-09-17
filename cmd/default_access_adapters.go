// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// userRepoForGranter is the subset of UserRepository needed by the adapters.
type userRepoForGranter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
}

// groupSvcForGranter is the subset of GroupService needed by the adapters.
type groupSvcForGranter interface {
	AddMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID, addedBy *uuid.UUID) error
}

// --- granterUserValidator adapter ---

type userTenantValidator struct {
	userRepo userRepoForGranter
}

func (v *userTenantValidator) UserBelongsToTenant(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	user, err := v.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	return user.TenantID == tenantID, nil
}

// --- granterRoleAssigner adapter ---

type roleAssignerAdapter struct {
	userRepo userRepoForGranter
}

func (a *roleAssignerAdapter) AssignRoleToUser(ctx context.Context, _, userID, roleID uuid.UUID) error {
	return a.userRepo.AssignRoles(ctx, userID, []uuid.UUID{roleID}, nil)
}

// --- granterGroupService adapter ---

type groupServiceAdapter struct {
	groupSvc groupSvcForGranter
}

func (a *groupServiceAdapter) AddMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return a.groupSvc.AddMembers(ctx, groupID, []uuid.UUID{userID}, nil)
}
