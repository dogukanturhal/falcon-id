// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// auth_credentials_service.go contains credential verification, session lifecycle,
// and security-critical authentication methods of AuthService.
// Extracted from auth_service.go to keep files under 800 lines.

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/clientctx"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"go.uber.org/zap"
)

// dummyPasswordHash is used to maintain constant-time authentication.
// SECURITY: This prevents timing attacks that could enumerate valid usernames.
// Generated at init time in argon2id format to match crypto.VerifyPassword expectations.
var dummyPasswordHash string

func init() {
	hash, err := crypto.HashPassword("dummy_password_for_timing_attack_prevention", nil)
	if err != nil {
		panic("failed to generate dummy password hash: " + err.Error())
	}
	dummyPasswordHash = hash
}

// authenticateLocal authenticates against local database
// SECURITY: Uses constant-time comparison to prevent timing attacks
func (s *AuthService) authenticateLocal(ctx context.Context, tenantID uuid.UUID, username, password string) (*models.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, tenantID, username)
	if err != nil {
		// SECURITY: Always verify against dummy hash to maintain constant timing
		_, _ = crypto.VerifyPassword(password, dummyPasswordHash)
		return nil, fmt.Errorf("invalid credentials")
	}

	if user == nil {
		// Try email within the same tenant
		user, err = s.userRepo.GetByEmail(ctx, tenantID, username)
		if err != nil {
			// SECURITY: Always verify against dummy hash to maintain constant timing
			_, _ = crypto.VerifyPassword(password, dummyPasswordHash)
			return nil, fmt.Errorf("invalid credentials")
		}
	}

	// SECURITY: No global email lookup - users must authenticate within their tenant context
	// Cross-tenant authentication is not allowed

	// SECURITY: Determine which hash to verify against
	// If user doesn't exist or has no password, use dummy hash to maintain constant timing
	var hashToVerify string
	if user == nil || user.PasswordHash == nil || *user.PasswordHash == "" {
		hashToVerify = dummyPasswordHash
	} else {
		hashToVerify = *user.PasswordHash
	}

	// SECURITY: Always perform password verification to prevent timing attacks
	valid, err := crypto.VerifyPassword(password, hashToVerify)
	if err != nil {
		// Log error internally but return generic message
		logger.Warn("Password verification error", zap.Error(err))
		return nil, fmt.Errorf("invalid credentials")
	}

	// SECURITY: Return generic error AFTER password verification to prevent timing leaks
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is federated (should use LDAP instead)
	if user.FederationType != nil && *user.FederationType == federationTypeLDAP {
		return nil, fmt.Errorf("user should authenticate via LDAP")
	}

	if user.PasswordHash == nil || *user.PasswordHash == "" {
		// SECURITY: this condition covers two cases that look identical to
		// the caller but are operationally very different — (a) a
		// self-service signup that was meant to set a local password but
		// didn't (see CompleteSignupInput / signup_service.go provisionUser
		// — falcon-id!<pwfix> makes Password required there to close this
		// off going forward, but existing rows and any other path that
		// creates a user without one still land here), and (b) a
		// legitimately federated/social account with no local password by
		// design (FederationType set, non-LDAP). Either way the user
		// cannot authenticate with a password, and a wrong-password retry
		// loop here is unwinnable — that is worth a distinct, greppable
		// server-side signal so an operator (or a future automated check)
		// can tell "this account can never succeed with any password" apart
		// from an ordinary typo, WITHOUT the HTTP response revealing
		// anything: the handler's client-facing body is the fixed literal
		// "Invalid username or password" (auth_handler.go Login), never
		// derived from this error string, so this stays internal-only.
		isFederated := user.FederationType != nil && *user.FederationType != ""
		logger.SecurityAudit.Warn("Security audit: login denied - no local password set",
			zap.String("event", "auth.login.failed"),
			zap.String("user_id", user.ID.String()),
			zap.String("reason", "no_local_password"),
			zap.Bool("is_federated", isFederated),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, fmt.Errorf("invalid credentials: no local password set")
	}

	if !valid {
		// SECURITY: Increment failed attempts synchronously using atomic DB operation.
		// The previous async goroutine used a stale in-memory FailedLoginAttempts value,
		// creating a race condition where concurrent requests could bypass the lockout.
		newCount, incrErr := s.userRepo.IncrementFailedAttempts(ctx, user.ID)
		if incrErr != nil {
			logger.Warn("Failed to increment failed login attempts", zap.Error(incrErr))
		} else if newCount >= s.config.MaxLoginAttempts {
			lockUntil := time.Now().Add(s.config.LockoutDuration)
			if lockErr := s.userRepo.LockUser(ctx, user.ID, "too many failed login attempts", &lockUntil); lockErr != nil {
				logger.Warn("Failed to lock user account", zap.Error(lockErr))
			} else {
				if s.caeService != nil {
					// Publish CAEAccountLocked so receivers (Talon IAP, SSE
					// subscribers) revoke any active session for the now-
					// locked account immediately, instead of letting it
					// run until the cached access token expires. The DB
					// LockUser above already prevents NEW logins; this
					// closes the existing-session window. Lock is
					// time-bound (LockoutDuration); after expiry a normal
					// login flow re-authenticates the user.
					_ = s.caeService.PublishEvent(ctx, CAEEvent{
						Type:      CAEAccountLocked,
						UserID:    user.ID,
						TenantID:  user.TenantID,
						Timestamp: time.Now().UTC(),
						Metadata: map[string]string{
							"reason":            "too_many_failed_login_attempts",
							"failed_attempts":   fmt.Sprintf("%d", newCount),
							"lock_until":        lockUntil.UTC().Format(time.RFC3339),
							"lockout_duration":  s.config.LockoutDuration.String(),
						},
					})
				}
				// Phase C (2026-05-26): out-of-band email so the
				// legitimate account holder knows their account just
				// locked. Signal: "someone is trying to guess your
				// password" — prompts them to rotate the password
				// and review active sessions. IP/UA are empty here
				// (authenticateLocal doesn't currently receive them);
				// caller higher up may surface them in a follow-up.
				if s.securityNotifier != nil {
					unlockAt := lockUntil
					s.securityNotifier.NotifyAccountLocked(
						ctx, user,
						"too_many_failed_login_attempts",
						&unlockAt,
						BuildEventContext("", "", ""),
					)
				}
			}
		}

		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}

// authenticateLDAP authenticates using internal LDAP service
func (s *AuthService) authenticateLDAP(ctx context.Context, tenantID uuid.UUID, username, password string) (*models.User, error) {
	// Check if LDAP service is available
	if s.ldapService == nil {
		return nil, fmt.Errorf("LDAP authentication not available")
	}

	// Get active LDAP providers for the tenant
	providers, err := s.ldapService.GetActiveLDAPProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP providers: %w", err)
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no LDAP providers configured")
	}

	// Try each LDAP provider until one succeeds
	var lastErr error
	for _, provider := range providers {
		user, err := s.ldapService.Authenticate(ctx, tenantID, provider.ID, username, password)
		if err != nil {
			lastErr = err
			continue
		}
		return user, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("LDAP authentication failed: %w", lastErr)
	}
	return nil, fmt.Errorf("LDAP authentication failed")
}

// invalidateExistingSessionsBeforeLogin invalidates any active sessions from the same IP/device
// before creating a new session. This prevents session fixation attacks.
// SECURITY: This is a critical security control to prevent session fixation vulnerabilities.
func (s *AuthService) invalidateExistingSessionsBeforeLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	// Get all active sessions for this user
	activeSessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get active sessions: %w", err)
	}

	// Invalidate sessions from the same IP address (likely same device/browser)
	// This prevents an attacker from using a pre-authenticated session
	for _, session := range activeSessions {
		if session.IPAddress != nil && *session.IPAddress == ipAddress {
			// End the old session
			if err := s.sessionRepo.EndSession(ctx, session.ID, "session_regenerated_on_login"); err != nil {
				logger.Warn("Failed to end old session during login",
					zap.Error(err),
					zap.String("session_id", session.ID.String()),
				)
				continue
			}

			// Clear session from cache if available
			if s.sessionCache != nil {
				if err := s.sessionCache.Delete(ctx, session.ID); err != nil {
					logger.Warn("Failed to clear session from cache",
						zap.Error(err),
						zap.String("session_id", session.ID.String()),
					)
				}
			}

			logger.Info("Invalidated existing session before creating new one",
				zap.String("user_id", userID.String()),
				zap.String("old_session_id", session.ID.String()),
				zap.String("ip_address", ipAddress),
			)
		}
	}

	return nil
}

// sessionTTLForLogin returns the iam_sessions.expires_at horizon for a
// login event. When rememberMe is true AND the config has a non-zero
// SessionTTLRememberMe (env override SESSION_TTL_REMEMBER_ME, default
// 720h / 30d), the extended TTL is applied. Otherwise the short TTL
// (config.SessionTTLDefault → falls back to SessionExpiry in Load when
// SESSION_TTL_DEFAULT is unset) is used — exactly preserving the
// pre-remember-me behaviour for users who don't tick the checkbox.
//
// The same TTL drives the falcon_idp_session cookie's Max-Age in the
// handler (see auth_handler.go establishIdpSession), so DB row expiry
// and browser cookie expiry stay in lock-step. RPs only ever see "is
// the IdP session still valid?" via /oauth/authorize bounce, so a
// matched pair is essential — a long DB row with a short cookie would
// silently re-prompt and a long cookie with a short DB row would
// produce hard-to-debug "valid cookie but no session" 401s.
func (s *AuthService) sessionTTLForLogin(rememberMe bool) time.Duration {
	if rememberMe && s.config.SessionTTLRememberMe > 0 {
		return s.config.SessionTTLRememberMe
	}
	if s.config.SessionTTLDefault > 0 {
		return s.config.SessionTTLDefault
	}
	// Final fallback — defensive guard for tests / partial configs that
	// don't populate the new fields. Equivalent to the pre-feature
	// behaviour (every call site used s.config.SessionExpiry directly).
	return s.config.SessionExpiry
}

// createSession creates a new authenticated session with a secure token.
// SECURITY: Sets AuthenticatedAt to the current time to enable session creation
// timestamp validation -- sessions without a valid authenticated_at are rejected
// by the session tenant binding middleware, preventing pre-created session attacks.
//
// authMethods carries the RFC 8176 Authentication Method References that
// describe how the user authenticated. This is snapshotted onto the row so
// id_tokens derived from subsequent /oauth/authorize flows can emit an
// `amr` claim that reflects the actual login event (see migration 211 and
// docs/oidc-claims-groups-amr.md). Pass nil for session-create paths that
// do not have first-class auth-method context (e.g. admin impersonation) —
// id_tokens issued through such paths will simply omit `amr`.
//
// rememberMe controls the ExpiresAt horizon via sessionTTLForLogin:
//   - false (and the legacy zero-value callers) → SessionTTLDefault /
//     SessionExpiry — short TTL, preserves pre-feature behaviour.
//   - true → SessionTTLRememberMe (default 30d) — extended TTL so the
//     session survives browser restart for the "Remember me" UX.
func (s *AuthService) createSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, authMethods []string, rememberMe bool) (*models.Session, error) {
	sessionToken, err := crypto.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("createSession: failed to generate session token: %w", err)
	}

	deviceInfo := parseDeviceInfo(userAgent)

	sessionTokenHash, err := crypto.HashToken(sessionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash session token: %w", err)
	}

	now := time.Now()
	session := &models.Session{
		UserID:           userID,
		SessionTokenHash: sessionTokenHash,
		DeviceInfo:       &deviceInfo,
		IPAddress:        &ipAddress,
		UserAgent:        &userAgent,
		ExpiresAt:        now.Add(s.sessionTTLForLogin(rememberMe)),
		AuthenticatedAt:  &now,
		AuthMethodsUsed:  append([]string(nil), authMethods...),
	}

	// Persist the originating client country (Cloudflare CF-IPCountry,
	// stamped on ctx by the handler via clientctx.WithCountry). Empty
	// string → leave the column NULL rather than storing a meaningless
	// empty value. CountryCode is the typed varchar(2) column added in
	// platform migration v0.232.245; the legacy free-form Location is
	// left nil for new sessions.
	if cc := clientctx.CountryFromContext(ctx); cc != "" {
		session.CountryCode = &cc
	}

	// Persist the edge-stamped geo enrichment (Cloudflare Worker
	// id-hexxlock-geo-stamp, infrastructure-iac MR-114, surfaced via
	// middleware.ClientGeo → clientctx.WithGeo at the handler boundary).
	// Each field is stamped only when present — leaving the column
	// NULL on absence (pre-Worker, internal service path, etc.) rather
	// than overloading "" as a magic empty marker. Columns added in
	// platform migration v0.232.246.
	if geo := clientctx.GeoFromContext(ctx); geo != (clientctx.Geo{}) {
		if geo.ASN != "" {
			v := geo.ASN
			session.ASN = &v
		}
		if geo.ASNOrg != "" {
			v := geo.ASNOrg
			session.ASNOrg = &v
		}
		if geo.City != "" {
			v := geo.City
			session.City = &v
		}
		if geo.Region != "" {
			v := geo.Region
			session.Region = &v
		}
		// IsVPNHint is only meaningful when we actually observed an
		// ASN org to classify against. Without ASNOrg we don't know
		// "yes" or "no" — leave the column NULL rather than stamp
		// false and pretend we checked.
		if geo.ASNOrg != "" {
			v := geo.IsVPNHint
			session.IsVPNHint = &v
		}
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("createSession: failed to store session: %w", err)
	}

	return session, nil
}

// CreateSessionFromRefresh cuts a new iam_sessions row when an OAuth
// refresh-token rotation produces drift vs the linked session row
// (see OAuthProviderService.RefreshTokens). The new row inherits the
// AMR snapshot from the rotating token (so id_tokens emitted post-
// rotation still reflect the original credential strength) but is
// otherwise re-stamped with the inbound request's context — IP from
// requestIPFromContext, UA from requestUserAgentFromContext, country
// and geo from clientctx.
//
// This satisfies the sessionContextService interface in the OAuth
// provider service (declared there to avoid an import cycle).
//
// Context expectations (set by the /oauth/token handler):
//
//   - services.WithRequestIP             — gateway-resolved client IP
//   - services.WithRequestUserAgent      — current request User-Agent
//   - clientctx.WithCountry              — CF-IPCountry (free tier)
//   - clientctx.WithGeo                  — id-hexxlock-geo-stamp output
//
// Any of those missing → that column stays NULL on the new row,
// preserving the same "absent = NULL not empty-string" invariant the
// initial-login createSession path uses.
func (s *AuthService) CreateSessionFromRefresh(ctx context.Context, userID uuid.UUID, authMethods []string) (*models.Session, error) {
	ip := requestIPFromContext(ctx)
	ua := requestUserAgentFromContext(ctx)
	// Refresh-driven session creation always uses the short TTL — a
	// long-lived "remember me" session row should never resurrect by
	// rotation alone. If the original session was remember-me, its
	// expires_at is already long; this path only fires when the OAuth
	// token-endpoint detects drift and needs a fresh row, and the
	// refreshed row should NOT silently inherit the long horizon
	// without re-authentication.
	return s.createSession(ctx, userID, ip, ua, authMethods, false)
}

// GetSessionByID returns the iam_sessions row by primary key. Returns
// (nil, nil) when the row doesn't exist — the OAuth refresh drift
// detector treats that as a "session_missing" signal and cuts a new
// row. Errors propagate.
//
// This satisfies the sessionContextService interface in the OAuth
// provider service.
func (s *AuthService) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	if s.sessionRepo == nil {
		return nil, nil
	}
	return s.sessionRepo.GetByID(ctx, sessionID)
}

// GetSessionAuthMethods returns the RFC 8176 Authentication Method References
// recorded for the given session at login / MFA completion time (migration
// 211, docs/oidc-claims-groups-amr.md). Used by /oauth/authorize to snapshot
// `amr` onto the resulting authorization code so id_tokens derived from the
// flow emit a `amr` claim consistent with the original login event.
//
// Errors and unknown sessions yield an empty slice; the caller's id_token
// will then simply omit `amr` — spec-compliant per OIDC Core §2 which
// treats `amr` as OPTIONAL.
func (s *AuthService) GetSessionAuthMethods(ctx context.Context, sessionID uuid.UUID) []string {
	if sessionID == uuid.Nil {
		return nil
	}
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil || session == nil {
		return nil
	}
	return append([]string(nil), session.AuthMethodsUsed...)
}

// verifyMFACode verifies a user's MFA code using the MFA service
func (s *AuthService) verifyMFACode(ctx context.Context, user *models.User, code string) bool {
	if s.mfaService == nil {
		logger.Error("MFA service not configured")
		return false
	}

	valid, err := s.mfaService.VerifyMFACode(ctx, user.ID, code)
	if err != nil {
		logger.Error("Failed to verify MFA code", zap.Error(err))
		return false
	}

	return valid
}
