// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// MFAWebAuthnContext is what /api/v1/auth/mfa/webauthn/begin returns —
// a WebAuthn assertion challenge bound to the temp MFA session. The
// frontend feeds PublicKey into @simplewebauthn/browser
// startAuthentication() and returns the resulting assertion to the
// /finish endpoint along with WaSessionID. Separate session id from
// the outer mfa_session_id so the webauthn library's own challenge
// state (stored under WaSessionID in WebAuthnService.sessions) can be
// consumed independently of the MFA-session lifecycle.
type MFAWebAuthnContext struct {
	PublicKey   any    `json:"publicKey"`
	WaSessionID string `json:"wa_session_id"`
}

// BeginWebAuthnMFA opens a WebAuthn assertion ceremony for a user
// already mid-login (password verified, MFA challenge pending). Looks
// up the temp MFA session in Redis to resolve user + tenant — the
// frontend can't pass user_id directly because it doesn't know it
// (the discover→login flow keeps userID server-side until the full
// LoginResponse comes back).
//
// The webauthn library stores its own per-ceremony session under
// WaSessionID. FinishWebAuthnMFA consumes that to verify the assertion.
func (s *AuthService) BeginWebAuthnMFA(ctx context.Context, mfaSessionID string) (*MFAWebAuthnContext, error) {
	if s.webAuthnService == nil {
		return nil, errors.New("webauthn service not configured")
	}

	mfaSession, err := s.retrieveMFASession(ctx, mfaSessionID)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(mfaSession.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session: user_id")
	}
	tenantID, err := uuid.Parse(mfaSession.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session: tenant_id")
	}

	challenge, err := s.webAuthnService.BeginAuthentication(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("webauthn begin: %w", err)
	}

	return &MFAWebAuthnContext{
		PublicKey:   challenge.PublicKey,
		WaSessionID: challenge.SessionID,
	}, nil
}

// CompleteWebAuthnMFA verifies the assertion, consumes the temp MFA
// session, mints the full LoginResponse. Mirrors CompleteMFALogin
// (which handles code-based MFA) — same post-verification ladder so
// audit logs / device trust / RFC 8176 AMR all match exactly.
//
// AMR composition: ["pwd","hwk","mfa"]. `pwd` from the password leg
// (verified in /api/v1/auth/login), `hwk` per RFC 8176 §2 for hardware
// keys (passkey ceremony), `mfa` per RFC 8176 §2 as the umbrella that
// downstream resource servers gate on. Matches the AMR emitted by the
// passkey primary-login path (WebAuthnHandler.FinishAuthentication)
// so an OAuth /authorize re-evaluation after this MFA-completion
// path sees the same acr/amr surface either way.
//
// MFA-attempts counter (incrementMFAAttempts) is shared with the code-
// based flow — a brute-force passkey assertion attempt counts against
// the same per-session 5-attempt cap. Library-level user verification
// + signature checks already gate this hard; the counter is defense-
// in-depth against pathological clients that retry-spam.
func (s *AuthService) CompleteWebAuthnMFA(
	ctx context.Context,
	mfaSessionID, waSessionID string,
	r *http.Request,
	ipAddress, userAgent string,
	rememberMe bool,
	deviceID string,
) (*models.LoginResponse, error) {
	if s.webAuthnService == nil {
		return nil, errors.New("webauthn service not configured")
	}

	// 1. Retrieve MFA session (read-only — do not consume yet).
	mfaSession, err := s.retrieveMFASession(ctx, mfaSessionID)
	if err != nil {
		return nil, err
	}

	// 1b. Per-session attempts counter (shared with code-based path).
	attempts, exhausted, attemptsErr := s.incrementMFAAttempts(ctx, mfaSessionID)
	if attemptsErr != nil {
		logger.Warn("Failed to track MFA attempts counter; failing closed",
			zap.String("session_id", mfaSessionID), zap.Error(attemptsErr))
		_ = s.consumeMFASession(ctx, mfaSessionID)
		return nil, fmt.Errorf("MFA session unavailable")
	}
	if exhausted {
		logger.Warn("MFA attempts exhausted; consuming session",
			zap.String("session_id", mfaSessionID), zap.Int64("attempts", attempts))
		_ = s.consumeMFASession(ctx, mfaSessionID)
		return nil, fmt.Errorf("MFA session exhausted: too many failed attempts, please sign in again")
	}

	// 2. Parse IDs
	userID, err := uuid.Parse(mfaSession.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session: user_id")
	}
	tenantID, err := uuid.Parse(mfaSession.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid MFA session: tenant_id")
	}

	// 3. Verify the assertion. WebAuthnService.FinishAuthentication
	//    reads the assertion JSON from r.Body, validates origin /
	//    signature / sign-count anomaly, returns the matched
	//    credential + user.
	_, user, err := s.webAuthnService.FinishAuthentication(ctx, userID, tenantID, waSessionID, r)
	if err != nil {
		// Leave the MFA session intact so the user can retry up to the
		// per-session cap. Library errors carry their own surface (clone
		// signal, signature failure, etc.) and are already SIEM-visible
		// via WebAuthnService's own structured logging.
		return nil, fmt.Errorf("webauthn verify: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("webauthn verify: user not found post-assertion")
	}

	// 4. Successful verification — consume the MFA session.
	_ = s.consumeMFASession(ctx, mfaSessionID)

	// 5. Roles + permissions (reuse Login helper).
	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles and permissions: %w", err)
	}

	// 5b. App access control filter.
	appClientID := mfaSession.ClientID
	if appClientID != "" && s.appAccessService != nil {
		_, filteredRoles, filteredPerms, appErr := s.appAccessService.ValidateAppAccess(
			ctx, userID, tenantID, appClientID, roleNames, permNames,
		)
		if appErr != nil {
			if s.auditService != nil {
				s.auditService.LogLogin(ctx, tenantID, &userID, ipAddress, userAgent, false, appErr.Error())
			}
			return nil, fmt.Errorf("app access denied: %w", appErr)
		}
		roleNames = filteredRoles
		permNames = filteredPerms
	}

	// 6. Create session. AMR: ["pwd","hwk","mfa"] — matches passkey
	//    primary-login surface so downstream OAuth /authorize ACR
	//    evaluation cannot distinguish the two paths.
	//    rememberMe flows from the original password step (the BFF
	//    forwards it on /api/v1/auth/mfa/webauthn/finish), keeping
	//    parity with code-based MFA completion.
	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, []string{"pwd", "hwk", "mfa"}, rememberMe)
	if err != nil {
		return nil, fmt.Errorf("create session with invalidation: %w", err)
	}

	// 7. Device trust (reuse helper).
	isTrustedDevice := s.handleDeviceTrust(ctx, user.ID, &models.LoginRequest{
		RememberMe: rememberMe,
		DeviceID:   deviceID,
	}, userAgent, ipAddress)

	// 8. Access token (reuse helper).
	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, appClientID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 9. Update user login info.
	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("Failed to update user login info", zap.Error(err))
	}

	tenantCtx := &tenantContext{
		TenantID:   tenantID,
		TenantSlug: mfaSession.TenantSlug,
	}
	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, isTrustedDevice, false, nil)
	if err != nil {
		return nil, err
	}
	resp.IsRememberMeSession = rememberMe
	return resp, nil
}
