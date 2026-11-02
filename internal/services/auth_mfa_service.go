// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_mfa_service.go contains all MFA-related methods of AuthService.
// Extracted from auth_service.go to keep files under 800 lines.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

// IssueSessionAfterEnrollment runs the post-enrollment session-issuance path
// for the registration-interrupt MFA flow (MFAEnrollmentService.VerifyTOTP /
// VerifyEmail just flipped the user's MFA flags + persisted the binding).
// Mirrors CompleteMFALogin from step 5 onwards — the MFA verification has
// already happened upstream, we just need to mint the session + tokens and
// return a normal LoginResponse so the BFF can plumb cookies + redirect.
//
// authMethods is the RFC 8176 AMR set to record on the session — typically
// ["pwd","otp"] for TOTP enrollment or ["pwd","mfa"] for email enrollment,
// matching CompleteMFALogin's behavior so downstream RPs see a consistent
// AMR shape regardless of whether the second factor was bound on this login
// or a previous one. The enrollment-completed event is captured separately
// in the security audit log (auth.mfa.enrollment_completed) so SIEM can
// distinguish the two cases without reading AMR.
func (s *AuthService) IssueSessionAfterEnrollment(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
	authMethods []string,
	rememberMe bool,
	deviceID string,
	ipAddress, userAgent string,
) (*models.LoginResponse, error) {
	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session: user_id")
	}
	tenantID, err := uuid.Parse(sess.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session: tenant_id")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles and permissions: %w", err)
	}

	appClientID := sess.ClientID
	if appClientID != "" && s.appAccessService != nil {
		_, filteredRoles, filteredPerms, appErr := s.appAccessService.ValidateAppAccess(
			ctx, userID, tenantID, appClientID, roleNames, permNames,
		)
		if appErr != nil {
			s.auditService.LogLogin(ctx, tenantID, &userID, ipAddress, userAgent, false, appErr.Error())
			return nil, fmt.Errorf("app access denied: %w", appErr)
		}
		roleNames = filteredRoles
		permNames = filteredPerms
	}

	// rememberMe drives the session TTL bifurcation — see
	// AuthService.sessionTTLForLogin / Config.SessionTTLRememberMe.
	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, authMethods, rememberMe)
	if err != nil {
		return nil, fmt.Errorf("create session with invalidation: %w", err)
	}

	isTrustedDevice := s.handleDeviceTrust(ctx, user.ID, &models.LoginRequest{
		RememberMe: rememberMe,
		DeviceID:   deviceID,
	}, userAgent, ipAddress)

	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, appClientID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("Failed to update user login info", zap.Error(err))
	}

	tenantCtx := &tenantContext{
		TenantID:   tenantID,
		TenantSlug: sess.TenantSlug,
	}
	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, isTrustedDevice, false, nil)
	if err != nil {
		return nil, err
	}
	resp.IsRememberMeSession = rememberMe
	return resp, nil
}

// SkipMFAEnrollment completes the "Remind me later" path on the
// registration-interrupt enrollment flow. Validates the
// enrollment_token, atomically increments the user's skip count under
// SQL-level locks (gated on deadline > now AND mfa_enabled = false AND
// the realm's skip budget hasn't been exhausted), and on success issues
// a normal session + access token so the user proceeds without MFA for
// the rest of their grace window.
//
// Trade-off (documented for SIEM/audit consumers): the user authenticates
// at AMR ["pwd"] only. Risk-based MFA was demanded; this endpoint
// explicitly defers it. That's the contract of "grace period" — the
// realm-admin opts in by setting MFAGracePeriodDays > 0 AND
// MFAEnrollmentMaxSkips > 0, accepting the temporary AMR downgrade
// during rollout. Matches Microsoft Entra Registration Campaign "snooze"
// + Okta MFA Enrollment grace + Auth0 onExecutePostLogin
// `app_metadata.mfa_enrollment_deadline` patterns.
//
// Failure modes:
//   - Invalid/expired token → 401 (handler-level)
//   - Skip budget exhausted, deadline passed, or user already enrolled →
//     401 (forces a fresh login + interrupt, no leak about which gate fired)
//   - Realm policy not loadable → fall through to a hard error (do NOT
//     silently grant a skip when policy is unknown)
func (s *AuthService) SkipMFAEnrollment(
	ctx context.Context,
	sess *models.MFAEnrollmentSession,
	enrollmentToken, ipAddress, userAgent string,
	rememberMe bool,
	deviceID string,
) (*models.LoginResponse, error) {
	if s.realmRepo == nil {
		return nil, fmt.Errorf("grace period not configured")
	}

	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session: user_id")
	}
	tenantID, err := uuid.Parse(sess.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment session: tenant_id")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Look up the realm so we can read the max-skips budget. The
	// security policy lives on the realm, not the tenant — multiple
	// tenants in a shared realm get the same grace contract by design.
	// The user.RealmID is the authoritative anchor (not tenantCtx,
	// which doesn't pass through enrollment-session state).
	policy, err := s.realmRepo.GetSecurityPolicy(ctx, user.RealmID)
	if err != nil {
		return nil, fmt.Errorf("load realm security policy: %w", err)
	}
	if policy == nil || policy.MFAGracePeriodDays == nil || *policy.MFAGracePeriodDays <= 0 || policy.MFAEnrollmentMaxSkips <= 0 {
		// Defensive: a client that arrived here without the realm
		// admitting skips. Fail closed so the frontend re-renders the
		// hard-block UI rather than granting silently.
		logger.SecurityAudit.Warn("Security audit: MFA enrollment skip rejected — realm does not permit skip",
			zap.String("event", "auth.mfa.enrollment_skip_rejected"),
			zap.String("user_id", user.ID.String()),
			zap.String("realm_id", user.RealmID.String()),
			zap.String("ip", ipAddress),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, fmt.Errorf("skip not permitted")
	}

	// Atomic increment. Returns the post-increment count, or 0 when
	// the row was not updated (deadline elapsed, already enrolled, or
	// the increment would have driven count past max_skips — actually
	// we check that AFTER, see below).
	now := time.Now().UTC()
	newCount, err := s.userRepo.IncrementMFAEnrollmentSkipCount(ctx, user.ID, now)
	if err != nil {
		return nil, fmt.Errorf("increment skip count: %w", err)
	}
	if newCount == 0 {
		// SQL guard rejected the increment — deadline passed or user
		// already enrolled in a concurrent flow. Force re-login.
		logger.SecurityAudit.Info("Security audit: MFA enrollment skip rejected — deadline or already enrolled",
			zap.String("event", "auth.mfa.enrollment_skip_rejected"),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, fmt.Errorf("skip not permitted")
	}
	if newCount > policy.MFAEnrollmentMaxSkips {
		// Increment succeeded SQL-side but pushed past budget. Roll
		// back by re-stamping to the prior count would be racy; the
		// less-bad path is to reject this skip attempt and force the
		// user to either enrol or wait for the deadline. Decrementing
		// is intentionally NOT done — the increment is the audit-trail
		// of "user tried to skip past their budget".
		logger.SecurityAudit.Warn("Security audit: MFA enrollment skip past budget — forcing enrollment",
			zap.String("event", "auth.mfa.enrollment_skip_budget_exhausted"),
			zap.String("user_id", user.ID.String()),
			zap.Int("max_skips", policy.MFAEnrollmentMaxSkips),
			zap.Int("attempted_count", newCount),
			zap.String("ip", ipAddress),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, fmt.Errorf("skip budget exhausted")
	}

	// Consume the enrollment session — single-use, same model as
	// VerifyTOTP/VerifyEmail. Even if session-issuance below fails the
	// session must be consumed: a leaked token must not be re-skipped.
	if s.mfaEnrollmentSvc != nil {
		s.mfaEnrollmentSvc.DeleteSession(ctx, enrollmentToken)
	}

	logger.SecurityAudit.Info("Security audit: MFA enrollment skipped",
		zap.String("event", "auth.mfa.enrollment_skipped"),
		zap.String("user_id", user.ID.String()),
		zap.String("username", user.Username),
		zap.Int("skip_count", newCount),
		zap.Int("max_skips", policy.MFAEnrollmentMaxSkips),
		zap.String("ip", ipAddress),
		zap.String("user_agent", userAgent),
		zap.Time("timestamp", time.Now().UTC()),
	)
	metrics.MFAEnrollmentInitiated.WithLabelValues("skip", "deferred").Inc()

	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles and permissions: %w", err)
	}

	appClientID := sess.ClientID
	if appClientID != "" && s.appAccessService != nil {
		_, filteredRoles, filteredPerms, appErr := s.appAccessService.ValidateAppAccess(
			ctx, userID, tenantID, appClientID, roleNames, permNames,
		)
		if appErr != nil {
			s.auditService.LogLogin(ctx, tenantID, &userID, ipAddress, userAgent, false, appErr.Error())
			return nil, fmt.Errorf("app access denied: %w", appErr)
		}
		roleNames = filteredRoles
		permNames = filteredPerms
	}

	// AMR is ["pwd"] only — see method doc-comment trade-off.
	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, []string{"pwd"}, rememberMe)
	if err != nil {
		return nil, fmt.Errorf("create session with invalidation: %w", err)
	}

	isTrustedDevice := s.handleDeviceTrust(ctx, user.ID, &models.LoginRequest{
		RememberMe: rememberMe,
		DeviceID:   deviceID,
	}, userAgent, ipAddress)

	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, appClientID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("Failed to update user login info", zap.Error(err))
	}

	tenantCtx := &tenantContext{
		TenantID:   tenantID,
		TenantSlug: sess.TenantSlug,
	}
	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, isTrustedDevice, false, nil)
	if err != nil {
		return nil, err
	}

	// Surface the post-skip state so the UI can update its countdown
	// without an extra roundtrip — same fields as the original
	// interrupt response but with the decremented budget.
	resp.MFAEnrollmentDeadline = user.MFAEnrollmentDeadline
	remaining := policy.MFAEnrollmentMaxSkips - newCount
	if remaining < 0 {
		remaining = 0
	}
	resp.MFAEnrollmentSkipsRemaining = remaining
	resp.MFAEnrollmentCanSkip = remaining > 0 && user.MFAEnrollmentDeadline != nil && user.MFAEnrollmentDeadline.After(now)
	resp.IsRememberMeSession = rememberMe
	return resp, nil
}

// CompleteMFALogin completes the MFA login flow using a session ID (no password re-send).
// SECURITY: This prevents storing the password in the client during MFA challenges.
//
// MFA retry semantics: a single MFA challenge session permits up to
// `mfaMaxAttempts` code verification attempts. The Redis counter
// `mfa:session:<id>:attempts` is incremented on EVERY entry to this
// function regardless of outcome; the session value (`mfa:session:<id>`)
// is only consumed (deleted) on either successful verification or
// attempt-cap exhaustion. This matches Auth0 / Okta / Cognito retry
// behaviour and NIST SP 800-63B §5.2.2 (rate-limit MFA verification
// attempts rather than single-use challenges) — previously the session
// was deleted on first read, which made a wrong-then-correct retry
// fail with "MFA session expired or invalid" on attempt #2.
func (s *AuthService) CompleteMFALogin(ctx context.Context, req *models.MFACompleteRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// Finish the bounded issuance even when the browser disconnects, otherwise
	// TOTP is consumed but no replayable result ever gets published.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if resp, err := s.replayMFACompletion(ctx, req, ipAddress, userAgent); resp != nil || err != nil {
		return resp, err
	}
	// Serialize completion per challenge across replicas. A concurrent retry
	// gets a retryable error, not a second session or a TOTP replay failure.
	lockKey := "mfa:session:" + req.SessionID + ":completing"
	lockOwner := uuid.NewString()
	locked, err := s.sessionCache.Client().Redis().SetNX(ctx, lockKey, lockOwner, time.Minute).Result()
	if err != nil {
		return nil, fmt.Errorf("lock MFA completion: %w", err)
	}
	if !locked {
		return nil, &MFAFlowError{Code: "mfa_rate_limited"}
	}
	defer s.sessionCache.Client().Redis().Eval(context.WithoutCancel(ctx), `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0`, []string{lockKey}, lockOwner)
	if resp, err := s.replayMFACompletion(ctx, req, ipAddress, userAgent); resp != nil || err != nil {
		return resp, err
	}
	// 1. Retrieve MFA session (read-only — do not consume yet).
	mfaSession, err := s.retrieveMFASession(ctx, req.SessionID)
	if err != nil {
		return nil, err
	}

	// 1b. Increment the per-session attempts counter. Exhaustion path
	// consumes the session immediately so a retry-storm can't keep
	// incrementing forever.
	attempts, exhausted, attemptsErr := s.incrementMFAAttempts(ctx, req.SessionID)
	if attemptsErr != nil {
		logger.Warn("Failed to track MFA attempts counter; failing closed",
			zap.String("session_id", req.SessionID), zap.Error(attemptsErr))
		_ = s.consumeMFASession(ctx, req.SessionID)
		return nil, fmt.Errorf("MFA session unavailable")
	}
	if exhausted {
		logger.Warn("MFA attempts exhausted; consuming session",
			zap.String("session_id", req.SessionID), zap.Int64("attempts", attempts))
		_ = s.consumeMFASession(ctx, req.SessionID)
		return nil, &MFAFlowError{Code: "mfa_rate_limited"}
	}

	// 2. Parse user and tenant IDs
	userID, err := uuid.Parse(mfaSession.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session")
	}
	tenantID, err := uuid.Parse(mfaSession.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session")
	}

	// 3. Look up the user
	if s.userRepo == nil {
		return nil, fmt.Errorf("user lookup unavailable")
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// 4. Verify the MFA code. On failure: leave the session intact so
	// the user can retry (up to mfaMaxAttempts total — see step 1b).
	valid := false
	if s.mfaService == nil {
		return nil, fmt.Errorf("MFA service unavailable")
	}
	valid, err = s.mfaService.VerifyMFACodeForMethod(ctx, user.ID, req.MFACode, mfaSession.MFAMethod)
	if err != nil {
		return nil, fmt.Errorf("verify MFA code: %w", err)
	}
	if !valid {
		remaining := mfaMaxAttempts - int(attempts)
		return nil, &MFAFlowError{Code: "mfa_code_invalid", RemainingAttempts: remaining}
	}
	if mfaSession.MFAMethod == authMethodTOTP {
		fresh, err := s.claimLoginTOTP(ctx, user.ID, req.MFACode)
		if err != nil {
			return nil, fmt.Errorf("track TOTP replay: %w", err)
		}
		if !fresh {
			return nil, &MFAFlowError{Code: "mfa_code_invalid", RemainingAttempts: mfaMaxAttempts - int(attempts)}
		}
	}

	// 4b. Successful verification — consume the session so the (now
	// proven) credentials cannot be replayed.

	// 5. Get user roles and permissions (reuse Login helper)
	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles and permissions: %w", err)
	}

	// 5b. App access control: filter roles/permissions if client_id was provided in original login
	appClientID := mfaSession.ClientID
	if appClientID != "" && s.appAccessService != nil {
		_, filteredRoles, filteredPerms, appErr := s.appAccessService.ValidateAppAccess(
			ctx, userID, tenantID, appClientID, roleNames, permNames,
		)
		if appErr != nil {
			s.auditService.LogLogin(ctx, tenantID, &userID, ipAddress, userAgent, false, appErr.Error())
			return nil, fmt.Errorf("app access denied: %w", appErr)
		}
		roleNames = filteredRoles
		permNames = filteredPerms
	}

	// 6. Create session with invalidation (reuse Login helper).
	// RFC 8176: pwd + mfa indicates a multi-factor authentication event.
	// `otp` is emitted instead of `mfa` when TOTP was the specific second
	// factor — inferred from the user's MFAPreferredMethod. Email-based MFA
	// stays under the generic `mfa` umbrella per the spec.
	mfaFactor := "mfa"
	if mfaSession.MFAMethod == authMethodTOTP || (mfaSession.MFAMethod == "" && user.MFAPreferredMethod != nil && *user.MFAPreferredMethod == authMethodTOTP) {
		mfaFactor = "otp"
	}
	// req.RememberMe carries the checkbox state from the original
	// password step — the BFF passes it through on /api/v1/auth/mfa/complete
	// so a user who ticked "Remember me" at password entry keeps the
	// extended TTL post-MFA. Without this thread-through, every MFA
	// login would silently default to the short TTL, defeating the UX.
	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, []string{"pwd", mfaFactor}, req.RememberMe)
	if err != nil {
		return nil, fmt.Errorf("create session with invalidation: %w", err)
	}

	// 7. Handle device trust (reuse Login helper)
	isTrustedDevice := s.handleDeviceTrust(ctx, user.ID, &models.LoginRequest{
		RememberMe: req.RememberMe,
		DeviceID:   req.DeviceID,
	}, userAgent, ipAddress)

	// 8. Generate access token (refresh issuance removed Phase 3).
	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, appClientID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 9. Update user login info (reuse Login helper)
	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("Failed to update user login info", zap.Error(err))
	}

	// 10. Build login response (reuse Login helper)
	tenantCtx := &tenantContext{
		TenantID:   tenantID,
		TenantSlug: mfaSession.TenantSlug,
	}

	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, isTrustedDevice, false, nil)
	if err != nil {
		return nil, err
	}
	// Threads the rememberMe state through to the handler so it can
	// set falcon_idp_session cookie Max-Age to the matching long TTL
	// (cookie + DB row stay lock-step — see comment in
	// sessionTTLForLogin).
	resp.IsRememberMeSession = req.RememberMe
	if err := s.saveMFACompletion(context.WithoutCancel(ctx), req, resp, ipAddress, userAgent); err != nil {
		return nil, fmt.Errorf("save MFA completion: %w", err)
	}
	return resp, nil
}

// mfaMaxAttempts is the per-session cap on MFA code verification
// retries. Aligned with NIST SP 800-63B §5.2.2 (rate-limit MFA
// verification attempts) and matches the Auth0 / Okta / Cognito
// default of 5 retries per challenge before invalidation.
const mfaMaxAttempts = 5

// mfaSessionAttemptsKey is the Redis key suffix carrying the per-
// session attempts counter. Kept as a sibling to `mfa:session:<id>`
// so the existing TTL on the main key bounds it implicitly (we also
// set an explicit TTL on first increment for safety).
const mfaSessionAttemptsKeySuffix = ":attempts"

// retrieveMFASession reads the MFA session payload WITHOUT consuming
// it. Callers that observe a successful MFA verification MUST follow
// up with consumeMFASession to prevent replay; the bounded-retry
// helper incrementMFAAttempts caps the wrong-code retry loop
// independently.
func (s *AuthService) retrieveMFASession(ctx context.Context, sessionID string) (*models.MFASessionData, error) {
	if s.sessionCache == nil {
		return nil, fmt.Errorf("session cache not available")
	}

	// Validate session ID format to prevent oversized Redis key attacks
	if _, err := uuid.Parse(sessionID); err != nil {
		return nil, fmt.Errorf("invalid MFA session ID")
	}

	redisKey := "mfa:session:" + sessionID
	sessionJSON, err := s.sessionCache.Client().Get(ctx, redisKey)
	if err != nil {
		logger.Warn("MFA session not found or expired", zap.String("session_id", sessionID), zap.Error(err))
		if errors.Is(err, redis.Nil) {
			return nil, &MFAFlowError{Code: "mfa_session_expired"}
		}
		return nil, fmt.Errorf("read MFA session: %w", err)
	}

	var mfaSession models.MFASessionData
	if err := json.Unmarshal([]byte(sessionJSON), &mfaSession); err != nil {
		return nil, fmt.Errorf("invalid MFA session data")
	}

	return &mfaSession, nil
}

// consumeMFASession deletes the MFA session and its attempts counter.
// Called after either a successful MFA verification (to prevent
// replay) or attempt-cap exhaustion (to force re-auth). Idempotent —
// safe to call when the keys have already expired or been deleted.
func (s *AuthService) consumeMFASession(ctx context.Context, sessionID string) error {
	if s.sessionCache == nil {
		return nil
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return nil
	}
	redisKey := "mfa:session:" + sessionID
	attemptsKey := redisKey + mfaSessionAttemptsKeySuffix
	return s.sessionCache.Client().Del(ctx, redisKey, attemptsKey)
}

// incrementMFAAttempts increments the per-session attempt counter
// and returns (newCount, exhausted, err). `exhausted == true` means
// the caller MUST consume the session and reject — including for
// what would otherwise have been a correct code. The TTL on the
// counter key is set to a generous 10 minutes on first increment so
// it persists at least as long as the parent session (5 min TTL +
// safety margin) and self-cleans afterward.
func (s *AuthService) incrementMFAAttempts(ctx context.Context, sessionID string) (int64, bool, error) {
	if s.sessionCache == nil {
		return 0, false, fmt.Errorf("session cache not available")
	}
	if _, err := uuid.Parse(sessionID); err != nil {
		return 0, false, fmt.Errorf("invalid MFA session ID")
	}
	attemptsKey := "mfa:session:" + sessionID + mfaSessionAttemptsKeySuffix
	count, err := s.sessionCache.Client().Incr(ctx, attemptsKey)
	if err != nil {
		return 0, false, fmt.Errorf("increment attempts: %w", err)
	}
	// Set TTL on first increment. Subsequent INCRs leave TTL untouched
	// (Redis preserves TTL across INCR). Best-effort — a TTL miss only
	// means the counter outlives its session, which is harmless.
	if count == 1 {
		if err := s.sessionCache.Client().Expire(ctx, attemptsKey, 10*time.Minute); err != nil {
			logger.Warn("Failed to set MFA attempts TTL",
				zap.String("session_id", sessionID), zap.Error(err))
		}
	}
	return count, count > mfaMaxAttempts, nil
}

// SwitchMFALoginMethod switches the MFA method during login and resends the code if needed.
// SECURITY: Uses session ID to identify the MFA flow without requiring password re-send.
func (s *AuthService) SwitchMFALoginMethod(ctx context.Context, sessionID, method string) (*models.LoginResponse, error) {
	if s.sessionCache == nil {
		return nil, fmt.Errorf("session cache not available")
	}

	// SECURITY: Validate session ID format to prevent oversized Redis key attacks.
	if _, err := uuid.Parse(sessionID); err != nil {
		return nil, fmt.Errorf("invalid MFA session ID")
	}

	mfaSession, err := s.retrieveMFASession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(mfaSession.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session")
	}

	lookup := s.mfaUserLookup
	if lookup == nil {
		if s.userRepo == nil {
			return nil, fmt.Errorf("user lookup unavailable")
		}
		lookup = s.userRepo
	}
	user, err := lookup.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Validate the requested method is available. Source-of-truth
	// passkey check (matches createMFAChallenge path) so "switch to
	// webauthn" is rejected for users without an enrolled credential.
	hasPasskey := false
	if has, err := lookup.HasActiveWebAuthnCredential(ctx, user.ID); err == nil {
		hasPasskey = has
	}
	availableMethods := s.getAvailableMFAMethods(user, hasPasskey)

	methodValid := false
	for _, m := range availableMethods {
		if m == method {
			methodValid = true
			break
		}
	}
	if !methodValid {
		return nil, fmt.Errorf("requested MFA method is not available")
	}

	// A separate switch/resend cooldown does not consume code attempts. It
	// also prevents using method switches to spam the user's mailbox.
	if method == authMethodEmail {
		allowed, err := s.sessionCache.Client().Redis().SetNX(ctx, "mfa:session:"+sessionID+":resend", "1", 60*time.Second).Result()
		if err != nil {
			return nil, fmt.Errorf("MFA resend unavailable: %w", err)
		}
		if !allowed {
			return nil, &MFAFlowError{Code: "mfa_rate_limited"}
		}
	}
	// If switching to email, send the code
	if method == authMethodEmail {
		if s.mfaService == nil {
			return nil, fmt.Errorf("email verification not configured")
		}
		if err := s.mfaService.SendEmailMFACode(ctx, user.ID); err != nil {
			logger.Error("Failed to send MFA email code for method switch", zap.Error(err))
			return nil, fmt.Errorf("send MFA code: %w", err)
		}
	}

	// Keep the original challenge, expiry and attempt budget. Rotating IDs on
	// switch used to reset rate limits and made a lost response unrecoverable.
	ttl, err := s.sessionCache.Client().Redis().TTL(ctx, "mfa:session:"+sessionID).Result()
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		return nil, &MFAFlowError{Code: "mfa_session_expired"}
	}
	mfaSession.MFAMethod = method
	payload, err := json.Marshal(mfaSession)
	if err != nil {
		return nil, err
	}
	// XX + KEEPTTL is atomic: a concurrent completion/expiry cannot be
	// resurrected by switching, and neither attempts nor expiry are reset.
	if err := s.sessionCache.Client().Redis().SetArgs(ctx, "mfa:session:"+sessionID, string(payload), redis.SetArgs{Mode: "XX", KeepTTL: true}).Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, &MFAFlowError{Code: "mfa_session_expired"}
		}
		return nil, fmt.Errorf("switch MFA method: %w", err)
	}

	return &models.LoginResponse{
		RequiresMFA:         true,
		MFAMethod:           method,
		AvailableMFAMethods: availableMethods,
		SessionID:           sessionID,
		MaskedEmail:         maskMFAEmail(user.Email),
		MFAExpiresIn:        int64(ttl.Seconds()),
		ResendAfterSeconds:  60,
	}, nil
}
