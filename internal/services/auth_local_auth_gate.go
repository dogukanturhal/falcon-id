// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_local_auth_gate.go implements t-431: a tenant-level gate that lets a
// tenant require SSO and disable local username/password login entirely.
//
// BACKGROUND (t-346, m-630, d-169): DiscoverResponse.LocalAuthDisabled
// (internal/models/discover.go) existed but was never set or read — the
// field gestured at this feature without implementing it. Separately,
// AuthService.Login had an SSO hint (resolveTenantContext's HRD branch,
// gated on discoverResp.AuthMethod == "sso") that only fires when the
// client resolves the tenant via email-domain discovery; a client that
// posts tenant_slug/tenant_id straight to /login skips that hint entirely
// and authenticates exactly like any other tenant — "the SSO button works,
// the password path is untested" (t-346's framing). enforceLocalAuthAllowed
// is the actual boundary: it runs on every Login regardless of how the
// tenant was resolved, driven by an explicit admin-set policy flag rather
// than incidental provider configuration.
//
// c-265 governs here: this is an auth-boundary gate. There is no default or
// implicit break-glass (d-169 Q4) — a real operational exemption need would
// be a separate, explicit, admin-set, audited, per-user flag (shaped like
// FeatureKeyRequirePasskeyForAdmin), never a bypass baked into this path.

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// FeatureKeyLocalAuthDisabled is the iam_feature_flags key that, when
// enabled for a tenant, disables username/password login for every user in
// that tenant. Users must authenticate via SSO (or LDAP, which continues to
// bind through the same password form by design — see discover_service.go's
// findEnforcedSSO comment) instead.
const FeatureKeyLocalAuthDisabled = "local_auth_disabled"

// enforceLocalAuthAllowed is t-431's SSO-only login gate. Called from Login
// AFTER credentials have already been verified correct (step 3, right after
// checkUserStatus) — user is a real, authenticated *models.User at this
// point, not an unauthenticated guess.
//
// Returns nil when local auth is permitted (flag store unwired, or the
// tenant does not have local_auth_disabled set). Returns an error — which
// Login propagates as a rejected login, no session issued — when the
// tenant requires SSO-only auth, OR when the flag store is wired but
// cannot be queried (c-265: fail closed on an auth boundary that IS
// deployed, rather than silently permitting local auth because the check
// itself failed).
func (s *AuthService) enforceLocalAuthAllowed(ctx context.Context, tenantCtx *tenantContext, user *models.User, ipAddress, userAgent string) error {
	if s.featureFlagRepo == nil {
		// Feature not deployed in this environment — matches every other
		// optional dependency in this file (e.g. maybePasskeyEnrollmentInterrupt's
		// identical nil guard on the same field).
		return nil
	}

	disabled, err := s.featureFlagRepo.IsEnabled(ctx, tenantCtx.TenantID, FeatureKeyLocalAuthDisabled)
	if err != nil {
		logger.Error("local auth gate: policy check failed, failing closed",
			zap.String("tenant_id", tenantCtx.TenantID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		s.auditService.LogLogin(ctx, tenantCtx.TenantID, &user.ID, ipAddress, userAgent, false, "local auth policy check failed")
		return fmt.Errorf("local auth policy check failed: %w", err)
	}
	if !disabled {
		return nil
	}

	// Q3 (d-169): this user has a live, correctly-verified local password
	// under a tenant that has since declared SSO-only policy — e.g. signed
	// up before the tenant's domain was claimed, or before the policy was
	// turned on. Ruling: do NOT auto-migrate, do NOT silently keep the
	// password path working (same shape as c-035's rejection of silent
	// identity resolution). Reject, AND flag the account for admin review
	// — visible, reversible, audited.
	reason := fmt.Sprintf("local password verified successfully at %s but tenant has local_auth_disabled=true — needs admin decision (link/deactivate/exempt), see d-169 Q3", time.Now().UTC().Format(time.RFC3339))
	if s.userRepo != nil {
		if flagErr := s.userRepo.FlagForAdminReview(ctx, user.ID, reason); flagErr != nil {
			// Do not let a bookkeeping failure turn into a silent local-auth
			// bypass: the login is still rejected below regardless.
			logger.Error("local auth gate: failed to flag account for admin review",
				zap.String("user_id", user.ID.String()),
				zap.Error(flagErr),
			)
		}
	}

	s.auditService.LogLogin(ctx, tenantCtx.TenantID, &user.ID, ipAddress, userAgent, false, "local auth disabled for tenant (SSO required)")
	s.auditService.LogUserAction(ctx, tenantCtx.TenantID, &user.ID, &user.ID, "auth.login.rejected_local_auth_disabled", false, map[string]interface{}{
		"reason": "tenant requires SSO; local login rejected and account flagged for admin review",
	})
	logger.SecurityAudit.Warn("Security audit: login denied - local auth disabled for tenant",
		zap.String("event", "auth.login.failed"),
		zap.String("user_id", user.ID.String()),
		zap.String("tenant_id", tenantCtx.TenantID.String()),
		zap.String("ip", ipAddress),
		zap.String("reason", "local_auth_disabled"),
		zap.Time("timestamp", time.Now().UTC()),
	)

	return fmt.Errorf("local authentication is disabled for this tenant; sign in via SSO")
}
