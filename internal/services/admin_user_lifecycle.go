// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/quota"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// Admin user lifecycle: soft-delete, restore, hard-delete.
//
// This is distinct from the pre-existing self-service GDPR flow
// (auth_account_deletion_service.go: ScheduleAccountDeletion /
// CancelAccountDeletion) and from the legacy UserService.Delete (a raw,
// irreversible hard delete with no guardrails, still used unchanged by
// the two DELETE routes registered before this change).
//
// Both this flow and the self-service flow write the SAME four columns
// (activation_status, deletion_scheduled_at, deletion_grace_period_ends_at,
// deletion_reason) through the same UserRepository.SetDeletionState
// method, but use two different activation_status values so the two
// origins stay distinguishable in the data and in audit logs:
//   - "pending_deletion" — self-service, user-initiated, password-verified
//   - "admin_deleted"    — admin-triggered soft-delete
//
// checkUserStatus (auth_service.go) blocks login for BOTH values.
// UserRepository.List / PlatformManagementHandler.GetTenantUser exclude
// BOTH values from ordinary list/read paths.

// ErrUserAlreadyDeleted is returned by AdminSoftDeleteUser when the
// target is already in a soft-deleted state (admin_deleted or
// pending_deletion). Idempotent retries should call AdminRestoreUser
// first if they want to re-delete with a new reason.
var ErrUserAlreadyDeleted = errors.New("user_already_deleted")

// ErrUserNotSoftDeleted is returned by AdminRestoreUser and by
// AdminHardDeleteUser (unless force=true) when the target is not
// currently soft-deleted.
var ErrUserNotSoftDeleted = errors.New("user_not_soft_deleted")

// ErrProtectedTenant is returned when an admin lifecycle action targets a
// user who belongs to the exampletenant platform tenant
// (models.HexxlockInternalTenantID). Refused outright, force included —
// there is no legitimate reason to soft- or hard-delete a user in the
// platform's own operating tenant via this API.
var ErrProtectedTenant = errors.New("protected_tenant")

// ErrLastOwner is the service-layer re-export of
// repositories.ErrLastOwner, returned when the target is the tenant's
// only holder of the "owner" role.
var ErrLastOwner = errors.New("cannot delete the last owner of the tenant")

// ErrConfirmationMismatch is returned by AdminHardDeleteUser when the
// caller-supplied confirmation string does not exactly equal the target
// user's username. Hard delete is irreversible; this forces the caller
// to state, in the request body, exactly which account they are
// destroying — mirroring the existing self-service "DELETE MY ACCOUNT"
// literal-text pattern (auth_handler_account_deletion.go), adapted here
// to echo the target's own username since an admin operates on accounts
// that are not their own.
var ErrConfirmationMismatch = errors.New("confirmation_mismatch")

func isProtectedTenantUser(user *models.User) bool {
	return user.TenantID.String() == models.HexxlockInternalTenantID
}

// checkLastOwnerGuard refuses the action if user currently holds the
// literal "owner" role and is the tenant's only active holder of it.
func (s *UserService) checkLastOwnerGuard(ctx context.Context, user *models.User) error {
	isOwner, err := s.userRepo.HasRole(ctx, user.ID, "owner")
	if err != nil {
		return fmt.Errorf("checkLastOwnerGuard: %w", err)
	}
	if !isOwner {
		return nil
	}
	count, err := s.userRepo.CountActiveOwners(ctx, user.TenantID)
	if err != nil {
		return fmt.Errorf("checkLastOwnerGuard: %w", err)
	}
	if count <= 1 {
		return ErrLastOwner
	}
	return nil
}

// AdminSoftDeleteUser reversibly deletes a user: blocks login, excludes
// the user from List()/GetTenantUser(), releases their tenant seat, and
// revokes their active OAuth tokens + sessions (via the same
// cascadeAdminDisable fan-out the active→disabled Update transition
// already uses). Restorable via AdminRestoreUser.
//
// Guards, in order: target exists; target is not in the protected
// exampletenant tenant; target is not already soft-deleted; target
// is not the tenant's last "owner".
func (s *UserService) AdminSoftDeleteUser(ctx context.Context, actorID, targetUserID uuid.UUID, reason string) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("AdminSoftDeleteUser: get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if isProtectedTenantUser(user) {
		return nil, ErrProtectedTenant
	}
	if user.ActivationStatus == "admin_deleted" || user.ActivationStatus == "pending_deletion" {
		return nil, ErrUserAlreadyDeleted
	}
	if err := s.checkLastOwnerGuard(ctx, user); err != nil {
		return nil, err
	}

	seatFree := s.isSeatFree(ctx, user.TenantID, targetUserID) // employee-class users were never counted
	now := time.Now().UTC()
	gracePeriodEnd := now.Add(DefaultDeletionGracePeriod)
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}

	if err := s.userRepo.SetDeletionState(ctx, targetUserID, "admin_deleted", &now, &gracePeriodEnd, reasonPtr); err != nil {
		return nil, fmt.Errorf("AdminSoftDeleteUser: set deletion state: %w", err)
	}

	// The soft-deleted user no longer occupies a seat (idempotent: only an active member membership releases one).
	s.releaseMemberSeat(ctx, user.TenantID, targetUserID)

	wasActive := user.IsActive
	user.IsActive = false
	user.UpdatedBy = &actorID
	if err := s.userRepo.Update(ctx, user); err != nil {
		// Deletion-state flip already committed and is authoritative for
		// login-blocking (checkUserStatus checks activation_status
		// first); log and continue rather than leave the row half-done.
		s.logger.Error("AdminSoftDeleteUser: failed to flip is_active",
			zap.String("user_id", targetUserID.String()), zap.Error(err))
	} else if wasActive {
		s.cascadeAdminDisable(ctx, user)
	}

	user.ActivationStatus = "admin_deleted"
	user.DeletionScheduledAt = &now
	user.DeletionGracePeriodEndsAt = &gracePeriodEnd
	user.DeletionReason = reasonPtr

	s.auditService.LogUserAction(ctx, user.TenantID, &actorID, &targetUserID, "user_admin_soft_deleted", true, map[string]interface{}{
		"reason": reason,
	})

	// Status change, not a new event name: example.iam.user.* topics are a closed,
	// pre-created set (internal/iamevents.Topics).
	s.publishUserStatusEvent(user, "admin_soft_deleted")

	if s.quotaClient != nil && s.config.QuotaEnforcementEnabled && !seatFree {
		go func(tenantID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
			decCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.quotaClient.DecrementUsage(decCtx, tenantID, quota.ResourceTypeUsers, 1); err != nil {
				s.logger.Warn("AdminSoftDeleteUser: failed to decrement seat usage",
					zap.String("tenant_id", tenantID.String()), zap.Error(err))
			}
		}(user.TenantID)
	}

	if s.redisCache != nil {
		_ = s.redisCache.Delete(ctx, fmt.Sprintf("iam:user:%s", targetUserID.String()))
	}

	return user, nil
}

// AdminRestoreUser reverses AdminSoftDeleteUser: clears the deletion
// state, re-activates the account, and re-claims the tenant seat. Fails
// with ErrUserNotSoftDeleted if the target isn't currently soft-deleted
// (by either origin — admin or self-service).
func (s *UserService) AdminRestoreUser(ctx context.Context, actorID, targetUserID uuid.UUID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("AdminRestoreUser: get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if user.ActivationStatus != "admin_deleted" && user.ActivationStatus != "pending_deletion" {
		return nil, ErrUserNotSoftDeleted
	}

	// Restoring re-occupies a member seat first; a full tenant is refused (409) before any state changes.
	if err := s.occupyMemberSeat(ctx, user.TenantID, targetUserID); err != nil {
		return nil, fmt.Errorf("AdminRestoreUser: %w", err)
	}
	if err := s.userRepo.SetDeletionState(ctx, targetUserID, "active", nil, nil, nil); err != nil {
		return nil, fmt.Errorf("AdminRestoreUser: set deletion state: %w", err)
	}

	user.IsActive = true
	user.UpdatedBy = &actorID
	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.Error("AdminRestoreUser: failed to flip is_active",
			zap.String("user_id", targetUserID.String()), zap.Error(err))
	}

	if s.accessTerminator != nil {
		s.accessTerminator.ClearUserBlock(ctx, targetUserID)
	}

	user.ActivationStatus = "active"
	user.DeletionScheduledAt = nil
	user.DeletionGracePeriodEndsAt = nil
	user.DeletionReason = nil

	s.auditService.LogUserAction(ctx, user.TenantID, &actorID, &targetUserID, "user_admin_restored", true, nil)
	s.publishUserStatusEvent(user, "admin_restored")

	if s.quotaClient != nil && s.config.QuotaEnforcementEnabled && !s.isSeatFree(ctx, user.TenantID, targetUserID) {
		go func(tenantID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
			incCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := s.quotaClient.IncrementUsage(incCtx, tenantID, quota.ResourceTypeUsers, 1); err != nil {
				s.logger.Warn("AdminRestoreUser: failed to re-increment seat usage",
					zap.String("tenant_id", tenantID.String()), zap.Error(err))
			}
		}(user.TenantID)
	}

	if s.redisCache != nil {
		_ = s.redisCache.Delete(ctx, fmt.Sprintf("iam:user:%s", targetUserID.String()))
	}

	return user, nil
}

// AdminHardDeleteUser irreversibly erases a user row plus its directly
// owned child rows (see UserRepository.HardDeleteUserTx /
// CountResidualRowsTx — FK-cascade walk, verified via a value-sweep
// residual-row check inside the same transaction before commit).
//
// Guards, in order:
//  1. target exists
//  2. target is not in the protected exampletenant tenant (refused
//     even with force=true — there is no override for this one)
//  3. confirmUsername exactly equals the target's username (case
//     sensitive, no trimming) — states, in the request, precisely which
//     account is being destroyed
//  4. target is not the tenant's last "owner"
//  5. target is already soft-deleted, UNLESS force=true skips this one
//     specific gate (force never skips guards 2-4)
func (s *UserService) AdminHardDeleteUser(ctx context.Context, actorID, targetUserID uuid.UUID, confirmUsername string, force bool, reason string) (map[string]int, error) {
	user, err := s.userRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("AdminHardDeleteUser: get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if isProtectedTenantUser(user) {
		return nil, ErrProtectedTenant
	}
	if confirmUsername != user.Username {
		return nil, ErrConfirmationMismatch
	}
	if err := s.checkLastOwnerGuard(ctx, user); err != nil {
		return nil, err
	}
	if !force && user.ActivationStatus != "admin_deleted" && user.ActivationStatus != "pending_deletion" {
		return nil, ErrUserNotSoftDeleted
	}

	seatFree := s.isSeatFree(ctx, user.TenantID, targetUserID) // before the delete: the membership row goes with the user
	residual, err := s.userRepo.HardDeleteUser(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("AdminHardDeleteUser: %w", err)
	}

	// Row is gone; best-effort fan-out cleanup on anything that might
	// still reference the (now-deleted) user id downstream — same
	// posture as cascadeAdminDisable (detached background context,
	// failure logged not fatal).
	bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if s.accessTerminator != nil {
		if err := s.accessTerminator.TerminateUserAccess(bgCtx, targetUserID, user.TenantID, "admin_hard_delete", nil); err != nil {
			s.logger.Warn("AdminHardDeleteUser: access termination incomplete",
				zap.String("user_id", targetUserID.String()), zap.Error(err))
		}
	} else {
		if s.tokenService != nil {
			if err := s.tokenService.RevokeAllUserOAuthTokens(bgCtx, targetUserID, "admin_hard_delete"); err != nil {
				s.logger.Warn("AdminHardDeleteUser: RevokeAllUserOAuthTokens failed",
					zap.String("user_id", targetUserID.String()), zap.Error(err))
			}
		}
		if s.backchannelLogout != nil {
			if err := s.backchannelLogout.NotifyLogout(bgCtx, targetUserID, "", user.TenantID); err != nil {
				s.logger.Warn("AdminHardDeleteUser: BCL fan-out failed",
					zap.String("user_id", targetUserID.String()), zap.Error(err))
			}
		}
	}

	s.auditService.LogUserAction(ctx, user.TenantID, &actorID, &targetUserID, "user_admin_hard_deleted", true, map[string]interface{}{
		"reason":         reason,
		"force":          force,
		"residual_rows":  residual,
		"confirmed_name": confirmUsername,
	})

	s.publishUserStatusEvent(user, "hard_deleted")

	if s.quotaClient != nil && s.config.QuotaEnforcementEnabled && user.IsActive && !seatFree {
		// Only release a seat here if the user was never soft-deleted
		// first (soft-delete already released it) — avoid double-freeing.
		go func(tenantID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
			decCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.quotaClient.DecrementUsage(decCtx, tenantID, quota.ResourceTypeUsers, 1); err != nil {
				s.logger.Warn("AdminHardDeleteUser: failed to decrement seat usage",
					zap.String("tenant_id", tenantID.String()), zap.Error(err))
			}
		}(user.TenantID)
	}

	if s.redisCache != nil {
		_ = s.redisCache.Delete(ctx, fmt.Sprintf("iam:user:%s", targetUserID.String()))
	}

	return residual, nil
}
