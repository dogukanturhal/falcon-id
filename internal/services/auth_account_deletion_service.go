// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ErrPasswordIncorrect is returned when the password check fails during a
// sensitive operation (delete-account, password change, etc.). Mapped to
// HTTP 403 with a stable code so the frontend can distinguish "wrong
// password" from "missing field" without parsing free-text messages.
var ErrPasswordIncorrect = errors.New("password_incorrect")

// ErrDeletionAlreadyScheduled is returned when delete-account is called on
// a user whose row is already in pending_deletion. The caller should
// instead surface the existing grace period to the user (or call
// CancelAccountDeletion if they want to start over).
var ErrDeletionAlreadyScheduled = errors.New("deletion_already_scheduled")

// ErrDeletionNotScheduled is returned by cancel-deletion when the user
// row is NOT in pending_deletion — there is nothing to cancel. Mapped to
// HTTP 409 (Conflict) at the handler layer.
var ErrDeletionNotScheduled = errors.New("deletion_not_scheduled")

// ErrFederatedAccountCannotDelete is returned when an SSO / SAML federated
// user attempts to schedule deletion via the self-service path. Those
// accounts must be deprovisioned upstream (the IdP) — deleting them in
// Falcon-ID while the upstream still issues fresh assertions would just
// re-create the row on next login. Tier-1 invariant: federation owns the
// lifecycle of federated identities.
var ErrFederatedAccountCannotDelete = errors.New("federated_account_cannot_delete")

// DefaultDeletionGracePeriod is the user-visible cooling-off window during
// which the deletion can be cancelled. 30 days mirrors what every
// major IdP (Google, Microsoft, Auth0) does for consumer accounts and is
// the value referenced in the privacy-policy + accounts portal UI copy.
const DefaultDeletionGracePeriod = 30 * 24 * time.Hour

// ScheduleAccountDeletion marks the user's row for deferred deletion. It
// verifies the supplied password (preventing CSRF / drive-by deletion),
// flips activation_status to "pending_deletion", and stamps the grace
// window so the background purger can finalise after the window expires.
//
// Side effects:
//   - All sessions for the user are revoked immediately. This logs the
//     user out of every device the moment they confirm — they re-login
//     during the grace period (via /api/v1/auth/login) hits an extra
//     check that surfaces the pending-deletion banner on every page.
//   - No tokens / passkeys / MFA factors are wiped here — purging happens
//     after the grace period. This way Cancel can restore everything.
//
// Federation: LDAP / SAML / OIDC-federated users are blocked because the
// upstream IdP owns the lifecycle. Their deletion path goes through SCIM
// deprovisioning, not self-service.
func (s *AuthService) ScheduleAccountDeletion(
	ctx context.Context,
	userID uuid.UUID,
	password string,
	reason string,
) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("ScheduleAccountDeletion: get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Federation gate: federated accounts must be deprovisioned upstream.
	if user.FederationType != nil && *user.FederationType != "" {
		return nil, ErrFederatedAccountCannotDelete
	}

	// Already in pending_deletion — caller should call CancelAccountDeletion
	// first if they want to re-schedule.
	if user.ActivationStatus == "pending_deletion" {
		return nil, ErrDeletionAlreadyScheduled
	}

	// Verify password. Constant-time path matches ChangePassword.
	if user.PasswordHash == nil {
		return nil, ErrPasswordIncorrect
	}
	valid, err := crypto.VerifyPassword(password, *user.PasswordHash)
	if err != nil || !valid {
		return nil, ErrPasswordIncorrect
	}

	now := time.Now().UTC()
	gracePeriodEnd := now.Add(DefaultDeletionGracePeriod)

	user.ActivationStatus = "pending_deletion"
	user.DeletionScheduledAt = &now
	user.DeletionGracePeriodEndsAt = &gracePeriodEnd
	var reasonPtr *string
	if reason != "" {
		user.DeletionReason = &reason
		reasonPtr = &reason
	}

	// NOTE: intentionally NOT s.userRepo.Update(ctx, user) — that method's
	// write-all-columns SQL does not include activation_status /
	// deletion_scheduled_at / deletion_grace_period_ends_at /
	// deletion_reason, so it silently dropped this exact write. Use the
	// narrow, dedicated SetDeletionState instead (see repository docstring).
	if err := s.userRepo.SetDeletionState(ctx, userID, user.ActivationStatus, user.DeletionScheduledAt, user.DeletionGracePeriodEndsAt, reasonPtr); err != nil {
		return nil, fmt.Errorf("ScheduleAccountDeletion: update user: %w", err)
	}

	// Revoke every active session — the user is logging themselves out
	// of every device. Best-effort: log on failure, don't roll back the
	// flag-flip (the deletion is the user-visible commit point).
	if err := s.sessionRepo.EndAllUserSessions(ctx, userID, "account_deletion_scheduled"); err != nil {
		logger.Warn("ScheduleAccountDeletion: failed to end sessions",
			zap.String("user_id", userID.String()), zap.Error(err))
	}
	// Same for refresh tokens: a scheduled deletion signs out every device
	// for good, bound or legacy.
	if s.tokenService != nil {
		if err := s.tokenService.RevokeAllUserOAuthTokens(ctx, userID, "account_deletion_scheduled"); err != nil {
			logger.Warn("ScheduleAccountDeletion: failed to revoke OAuth tokens",
				zap.String("user_id", userID.String()), zap.Error(err))
		}
	}

	logger.SecurityAudit.Info("Security audit: account deletion scheduled",
		zap.String("event", "user.account.deletion_scheduled"),
		zap.String("user_id", userID.String()),
		zap.Time("grace_ends_at", gracePeriodEnd),
		zap.String("reason", reason),
		zap.Time("timestamp", now),
	)

	return user, nil
}

// CancelAccountDeletion reverses ScheduleAccountDeletion as long as the
// grace period hasn't elapsed yet. The user's row returns to
// activation_status='active' and the deletion timestamps are cleared so
// the purger ignores it. Sessions revoked at scheduling time are NOT
// restored — the user re-authenticates on next access.
//
// SECURITY: doesn't require a password re-check. Tier-1 reasoning: the
// canceller is already authenticated, AND the deletion path always wipes
// existing sessions, so the only way to reach this endpoint is to log
// back in with valid credentials. Re-prompting for the password adds
// friction without raising the floor.
func (s *AuthService) CancelAccountDeletion(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("CancelAccountDeletion: get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if user.ActivationStatus != "pending_deletion" {
		return nil, ErrDeletionNotScheduled
	}

	now := time.Now().UTC()

	user.ActivationStatus = "active"
	user.DeletionScheduledAt = nil
	user.DeletionGracePeriodEndsAt = nil
	user.DeletionReason = nil

	// See ScheduleAccountDeletion: Update() drops these columns, so use
	// the dedicated SetDeletionState write path instead.
	if err := s.userRepo.SetDeletionState(ctx, userID, "active", nil, nil, nil); err != nil {
		return nil, fmt.Errorf("CancelAccountDeletion: update user: %w", err)
	}

	logger.SecurityAudit.Info("Security audit: account deletion cancelled",
		zap.String("event", "user.account.deletion_cancelled"),
		zap.String("user_id", userID.String()),
		zap.Time("timestamp", now),
	)

	return user, nil
}
