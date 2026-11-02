// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// granterPolicyRepo defines the repository interface needed by the granter.
type granterPolicyRepo interface {
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.DefaultAccessPolicy, error)
}

// granterRoleRepo resolves role details for security validation.
type granterRoleRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
}

// granterRoleAssigner assigns a role to a user within a tenant.
type granterRoleAssigner interface {
	AssignRoleToUser(ctx context.Context, tenantID, userID, roleID uuid.UUID) error
}

// granterGroupService adds a user to a group.
type granterGroupService interface {
	AddMember(ctx context.Context, groupID, userID uuid.UUID) error
}

// granterUserValidator checks if a user belongs to a tenant.
type granterUserValidator interface {
	UserBelongsToTenant(ctx context.Context, tenantID, userID uuid.UUID) (bool, error)
}

// DefaultAccessGranter implements DefaultAppAccessGranter by evaluating
// tenant-level default access policies and creating role/group assignments.
//
// Security invariants (from security audit):
//   - SR-DAP-01: Blocked roles (admin, owner, etc.) are never assigned
//   - SR-DAP-02: Cross-tenant isolation verified before any assignment
//   - SR-DAP-05: Assignment count capped at MaxDefaultAccessAssignmentsPerUser
type DefaultAccessGranter struct {
	policyRepo    granterPolicyRepo
	roleRepo      granterRoleRepo
	roleAssigner  granterRoleAssigner
	groupSvc      granterGroupService
	userValidator granterUserValidator
}

// NewDefaultAccessGranter creates a new granter.
func NewDefaultAccessGranter(
	policyRepo granterPolicyRepo,
	roleRepo granterRoleRepo,
	roleAssigner granterRoleAssigner,
	groupSvc granterGroupService,
	userValidator granterUserValidator,
) *DefaultAccessGranter {
	return &DefaultAccessGranter{
		policyRepo:    policyRepo,
		roleRepo:      roleRepo,
		roleAssigner:  roleAssigner,
		groupSvc:      groupSvc,
		userValidator: userValidator,
	}
}

// GrantDefaultAccess evaluates active policies for the tenant and grants
// the corresponding roles/group memberships to the user.
// Individual assignment errors are non-fatal (logged and skipped).
func (g *DefaultAccessGranter) GrantDefaultAccess(ctx context.Context, tenantID, userID uuid.UUID) error {
	// SR-DAP-02: Verify user belongs to tenant before any assignments
	belongs, err := g.userValidator.UserBelongsToTenant(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("default access: validate user tenant: %w", err)
	}
	if !belongs {
		return fmt.Errorf("default access: user %s does not belong to tenant %s", userID, tenantID)
	}

	// Fetch active policies
	policies, err := g.policyRepo.ListByTenant(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("default access: list policies: %w", err)
	}

	if len(policies) == 0 {
		return nil
	}

	assignmentCount := 0

	for _, policy := range policies {
		// SR-DAP-05: Cap assignments per user
		if assignmentCount >= models.MaxDefaultAccessAssignmentsPerUser {
			logger.Warn("Default access: assignment limit reached, skipping remaining policies",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.Int("limit", models.MaxDefaultAccessAssignmentsPerUser),
			)
			break
		}

		switch policy.PolicyType {
		case models.DefaultAccessPolicyTypeRole:
			if g.applyRolePolicy(ctx, tenantID, userID, policy) {
				assignmentCount++
			}
		case models.DefaultAccessPolicyTypeGroup:
			if g.applyGroupPolicy(ctx, userID, policy) {
				assignmentCount++
			}
		default:
			logger.Warn("Default access: unknown policy type",
				zap.String("policy_type", string(policy.PolicyType)),
			)
		}
	}

	logger.Info("Default access grants completed",
		zap.String("tenant_id", tenantID.String()),
		zap.String("user_id", userID.String()),
		zap.Int("assignments_created", assignmentCount),
		zap.Int("policies_evaluated", len(policies)),
	)

	return nil
}

// applyRolePolicy validates and assigns a role. Returns true if assignment was made.
func (g *DefaultAccessGranter) applyRolePolicy(ctx context.Context, tenantID, userID uuid.UUID, policy models.DefaultAccessPolicy) bool {
	// SR-DAP-01: Validate role is not blocked
	role, err := g.roleRepo.GetByID(ctx, policy.TargetID)
	if err == nil && role == nil {
		err = fmt.Errorf("role %s not found", policy.TargetID)
	}
	if err != nil {
		logger.Warn("Default access: role not found, skipping",
			zap.String("role_id", policy.TargetID.String()),
			zap.Error(err),
		)
		return false
	}

	if models.BlockedDefaultRoles[role.Name] {
		logger.Warn("Default access: blocked admin role in policy, skipping",
			zap.String("role_name", role.Name),
			zap.String("tenant_id", tenantID.String()),
			zap.String("policy_id", policy.ID.String()),
		)
		return false
	}

	if err := g.roleAssigner.AssignRoleToUser(ctx, tenantID, userID, policy.TargetID); err != nil {
		logger.Warn("Default access: role assignment failed (non-fatal)",
			zap.String("role_id", policy.TargetID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false
	}

	return true
}

// applyGroupPolicy adds user to a group. Returns true if membership was added.
func (g *DefaultAccessGranter) applyGroupPolicy(ctx context.Context, userID uuid.UUID, policy models.DefaultAccessPolicy) bool {
	if err := g.groupSvc.AddMember(ctx, policy.TargetID, userID); err != nil {
		logger.Warn("Default access: group membership failed (non-fatal)",
			zap.String("group_id", policy.TargetID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return false
	}

	return true
}
