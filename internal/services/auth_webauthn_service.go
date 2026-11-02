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
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// FeatureKeyRequirePasskeyForAdmin is the iam_feature_flags key that, when
// enabled for a tenant (or globally), forces any user with an admin role to
// authenticate with a FIDO2 / WebAuthn passkey before a session is issued.
//
// NIST SP 800-63B-4 §5.1.7 + OMB M-22-09 reference path: phishing-resistant
// MFA for moderate-and-higher-risk systems. Falcon-ID treats admin roles as
// moderate-or-higher by definition; tenants opt in by flipping this flag.
const FeatureKeyRequirePasskeyForAdmin = "require_passkey_for_admin"

// LoginViaWebAuthn mints a session and token envelope for a user who has
// just completed a WebAuthn (FIDO2 / passkey) ceremony.
//
// Pre-condition: the caller (typically WebAuthnHandler) has run the full
// W3C ceremony — challenge issued server-side, response cryptographically
// verified by go-webauthn, sign-count regression checked. By the time this
// method runs, the holder of the credential has demonstrated:
//
//   - possession of the authenticator (signed challenge),
//   - user-verification (UV=required at registration AND assertion).
//
// That combination satisfies NIST SP 800-63B-4 §5.1.7 (Multi-Factor
// Cryptographic Authenticator), so the session records `amr=["hwk","user"]`
// (RFC 8176) which the OAuth /authorize → /token flow then maps to
// `acr=urn:hexxlock:aal3` on the resulting id_token.
//
// LoginViaWebAuthn is deliberately MFA-free: the passkey ceremony IS the
// authentication factor. Any subsequent prompt would degrade UX without
// adding assurance — re-confirming a hardware-bound, UV-verified credential
// with a phishable second factor is a downgrade, not an upgrade.
func (s *AuthService) LoginViaWebAuthn(
	ctx context.Context,
	user *models.User,
	ipAddress, userAgent, clientID string,
	rememberMe bool,
) (*models.LoginResponse, error) {
	if user == nil {
		return nil, errors.New("LoginViaWebAuthn: user is nil")
	}

	// 1. Defence-in-depth: the WebAuthn ceremony already verified the
	//    user is the rightful credential owner, but a credential could have
	//    been registered before the user was locked. Re-check here.
	if !user.IsActive {
		return nil, fmt.Errorf("LoginViaWebAuthn: user %s is inactive", user.ID)
	}
	if user.IsLocked {
		return nil, fmt.Errorf("LoginViaWebAuthn: user %s is locked", user.ID)
	}

	// 2. Resolve tenant + realm context for the response. Mirrors the
	//    fallback behaviour of password Login when slug/realm are unknown.
	tenantCtx := &tenantContext{TenantID: user.TenantID}
	if s.tenantRepo != nil {
		if tenant, err := s.tenantRepo.GetByID(ctx, user.TenantID); err == nil && tenant != nil {
			tenantCtx.TenantSlug = tenant.Slug
		}
	}
	if user.RealmID != uuid.Nil {
		tenantCtx.RealmID = user.RealmID
	}

	// 3. Roles, permissions, and app-access filtering. Same gating as the
	//    password path — passkey-authenticated users still need explicit
	//    app access for any client_id they're targeting.
	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("LoginViaWebAuthn: roles/permissions: %w", err)
	}
	var appClientID string
	if clientID != "" && s.appAccessService != nil {
		oauthClient, filteredRoles, filteredPerms, appErr := s.appAccessService.ValidateAppAccess(
			ctx, user.ID, user.TenantID, clientID, roleNames, permNames,
		)
		if appErr != nil {
			s.auditService.LogLogin(ctx, user.TenantID, &user.ID, ipAddress, userAgent, false, appErr.Error())
			return nil, fmt.Errorf("LoginViaWebAuthn: app access denied: %w", appErr)
		}
		roleNames = filteredRoles
		permNames = filteredPerms
		appClientID = oauthClient.ClientID
	}

	// 4. Create session with the WebAuthn AMR snapshot. The session row
	//    is the source of truth for `amr`: when /oauth/authorize derives
	//    a code from this session, it copies AuthMethodsUsed onto the
	//    code, and /oauth/token then emits `amr` + the derived `acr`
	//    (urn:hexxlock:aal3) onto the id_token.
	authMethods := []string{AMRValueHardwareKey, AMRValueUserVerification}
	// rememberMe (opt-in checkbox on the login page) selects the long
	// session TTL; the IdP cookie Max-Age follows IsRememberMeSession.
	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, authMethods, rememberMe)
	if err != nil {
		return nil, fmt.Errorf("LoginViaWebAuthn: create session: %w", err)
	}

	// 5. Mint the access JWT. Phase 3 (mig 233) removed auth-service
	//    refresh tokens — rotation flows through OIDC /oauth/token at
	//    the BFF after the redirect. Device-trust (Remember Me) is not
	//    applicable to passkey login — the credential itself is bound
	//    to a hardware-backed key store, so cookie-based device trust
	//    adds no assurance.
	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, appClientID)
	if err != nil {
		return nil, fmt.Errorf("LoginViaWebAuthn: generate access token: %w", err)
	}

	// 6. Update last-login bookkeeping. PII fields go through encrypt-in-
	//    place via userRepo.Update, so we save the decrypted values and
	//    restore them on the response object (same pattern as Login).
	savedEmail := user.Email
	savedFirstName := user.FirstName
	savedLastName := user.LastName
	savedDisplayName := user.DisplayName
	savedPhone := user.Phone
	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("LoginViaWebAuthn: updateUserLoginInfo failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
	}
	user.Email = savedEmail
	user.FirstName = savedFirstName
	user.LastName = savedLastName
	user.DisplayName = savedDisplayName
	user.Phone = savedPhone

	// 7. Audit-log the successful authentication. The amr snapshot in
	//    the audit record matches what's on the session, so a security
	//    investigation can correlate the assurance level of any token
	//    with the originating login event.
	s.auditService.LogUserAction(ctx, user.TenantID, &user.ID, nil, "auth.login.webauthn", true, map[string]interface{}{
		"session_id": session.ID.String(),
		"amr":        authMethods,
		"ip_address": ipAddress,
	})

	// 8. buildLoginResponse runs the standard envelope so RPs see the
	//    same shape regardless of which authenticator the user picked.
	//    isNewDevice=false / riskAssessment=nil because the passkey
	//    flow doesn't run risk evaluation — possession + UV is its own
	//    risk story.
	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, false, false, nil)
	if err != nil {
		return nil, err
	}
	resp.IsRememberMeSession = rememberMe
	return resp, nil
}

// maybePasskeyEnrollmentInterrupt evaluates the admin-passkey-required gate
// and, when it fires, issues a registration-interrupt LoginResponse with
// EnrollmentMethods=["webauthn"]. Returns (nil, nil) when the gate is
// inapplicable so the caller proceeds with normal login.
//
// Gate predicate (all four must be true):
//
//  1. featureFlagRepo + webAuthnRepo are wired (configuration prereq).
//  2. The tenant has require_passkey_for_admin enabled (per-tenant or
//     global default).
//  3. The user has at least one role flagged as admin-tier — currently
//     the role name matches roleNameAdmin ("admin"). Tenants with
//     additional admin-equivalent roles can extend this list.
//  4. The user has zero active passkeys (CountActiveByUser == 0).
//
// When the gate fires, mfaEnrollmentSvc must be wired — otherwise we fail
// closed (an unwired enrollment service cannot drive the user through
// passkey registration, and silently skipping the gate would defeat the
// policy). Operators fix the wiring; users don't bypass the policy.
func (s *AuthService) maybePasskeyEnrollmentInterrupt(
	ctx context.Context,
	tenantCtx *tenantContext,
	user *models.User,
	req *models.LoginRequest,
	ipAddress, userAgent string,
	isNewDevice bool,
	riskAssessment *models.RiskAssessment,
	roleNames []string,
) (*models.LoginResponse, error) {
	if s.featureFlagRepo == nil || s.webAuthnRepo == nil {
		return nil, nil
	}
	if !hasAdminRole(roleNames) {
		return nil, nil
	}
	enabled, err := s.featureFlagRepo.IsEnabled(ctx, tenantCtx.TenantID, FeatureKeyRequirePasskeyForAdmin)
	if err != nil {
		// Treat a flag-store outage as fail-open for login availability —
		// the policy is preventive, not detective. A persistent outage
		// should be alerted on independently; the alternative (lock all
		// admins out on a Redis blip) is worse.
		logger.Warn("admin-passkey gate: feature flag lookup failed; allowing login",
			zap.String("tenant_id", tenantCtx.TenantID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return nil, nil
	}
	if !enabled {
		return nil, nil
	}
	count, err := s.webAuthnRepo.CountActiveByUser(ctx, user.ID, user.TenantID)
	if err != nil {
		// Same fail-open rationale as above. A passkey-enrolled admin who
		// can't be confirmed-as-enrolled gets logged in normally; the
		// gate re-fires on the next login when the repo is healthy.
		logger.Warn("admin-passkey gate: credential count lookup failed; allowing login",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return nil, nil
	}
	if count > 0 {
		return nil, nil
	}
	return s.createPasskeyEnrollmentInterrupt(ctx, tenantCtx, user, req, ipAddress, userAgent, isNewDevice, riskAssessment)
}

// hasAdminRole returns true when any of the supplied role names matches the
// admin marker. Centralised so future expansion (e.g. tenant-defined
// admin-tier roles, platform-admin) is a single edit.
func hasAdminRole(roleNames []string) bool {
	for _, r := range roleNames {
		if r == roleNameAdmin {
			return true
		}
	}
	return false
}

// createPasskeyEnrollmentInterrupt mints an enrollment_token bound to the
// originating request and returns a LoginResponse with
// EnrollmentMethods=["webauthn"] so the frontend can drive the user
// through /api/v1/auth/mfa/enrollment/webauthn/{begin,finish}.
//
// Mirrors createMFAEnrollmentInterrupt verbatim except for the methods
// list and the audit event tag. Fail-closes when the enrollment service
// isn't wired — a tenant that turns the policy on without operator
// follow-through to wire MFAEnrollmentService gets a clear error rather
// than silent passthrough.
func (s *AuthService) createPasskeyEnrollmentInterrupt(
	ctx context.Context,
	tenantCtx *tenantContext,
	user *models.User,
	req *models.LoginRequest,
	ipAddress, userAgent string,
	isNewDevice bool,
	riskAssessment *models.RiskAssessment,
) (*models.LoginResponse, error) {
	if s.mfaEnrollmentSvc == nil {
		logger.SecurityAudit.Error("Security audit: passkey enrollment service not wired — admin-passkey gate cannot interrupt",
			zap.String("event", "auth.passkey.enrollment_misconfigured"),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, errors.New("passkey enrollment is required but the enrollment service is unavailable")
	}

	riskScore := 0
	riskLevel := ""
	if riskAssessment != nil {
		riskScore = riskAssessment.TotalScore
		riskLevel = string(riskAssessment.Level)
	}

	token, expiresIn, err := s.mfaEnrollmentSvc.CreateSession(
		ctx,
		user.ID,
		tenantCtx.TenantID,
		tenantCtx.TenantSlug,
		ipAddress,
		userAgent,
		req.ClientID,
		riskScore,
		riskLevel,
	)
	if err != nil {
		return nil, fmt.Errorf("create passkey enrollment session: %w", err)
	}

	logger.SecurityAudit.Info("Security audit: passkey registration interrupt issued",
		zap.String("event", "auth.passkey.enrollment_interrupt"),
		zap.String("user_id", user.ID.String()),
		zap.String("username", user.Username),
		zap.String("ip", ipAddress),
		zap.String("user_agent", userAgent),
		zap.String("client_id", req.ClientID),
		zap.Time("timestamp", time.Now().UTC()),
	)

	resp := &models.LoginResponse{
		RequiresMFAEnrollment: true,
		EnrollmentToken:       token,
		EnrollmentMethods:     []string{"webauthn"},
		EnrollmentExpiresIn:   expiresIn,
		IsNewDevice:           isNewDevice,
	}
	if riskAssessment != nil {
		resp.RiskScore = riskAssessment.TotalScore
		resp.RiskLevel = string(riskAssessment.Level)
		resp.RiskWarnings = riskAssessment.Warnings
	}
	return resp, nil
}

