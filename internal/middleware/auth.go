// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	// CurrentUserKey is an exported identifier.
	CurrentUserKey = "current_user"
	// CurrentSessionKey is an exported identifier.
	CurrentSessionKey = "current_session"
	// ImpersonatorIDKey is an exported identifier.
	ImpersonatorIDKey = "impersonator_id"
	// ImpersonationSessionIDKey is an exported identifier.
	ImpersonationSessionIDKey = "impersonation_session_id"
)

// circuitBreakerState represents the state of the Redis circuit breaker
type circuitBreakerState struct {
	mu              sync.RWMutex
	failures        int
	lastFailureTime time.Time
	isOpen          bool
}

// AuthMiddleware is an exported type.
type AuthMiddleware struct {
	tokenService   *services.TokenService
	authzEngine    services.AuthorizationEngine
	config         *config.Config
	circuitBreaker *circuitBreakerState
	sessionCache   *redispkg.SessionCache
	// tenantSuspension rejects IdP-SSO cookie sessions of suspended tenants
	// (R1-GAPS row 27). Optional; nil disables the check.
	tenantSuspension services.TenantSuspensionChecker
	// stepUpRepo backs RequireFreshAuthForAction. When set, the
	// middleware consults iam_step_up_verifications for an in-place
	// step-up record matching (session_id, action) before failing.
	// Enables the canonical in-place step-up modal (Auth0 / Google /
	// Okta pattern) instead of forcing a full OAuth redirect dance.
	// Wired via SetStepUpRepo; nil-safe — when unset, action-scoped
	// middleware falls through to JWT + sessionRepo paths only.
	stepUpRepo *repositories.StepUpVerificationRepository
	// sessionRepo backs the RequireFreshAuth DB fallback (2026-05-17).
	// When set, RequireFreshAuth consults iam_sessions.authenticated_at
	// when JWT auth_time is missing/stale — closes the "user stuck behind
	// freshAuth after successful step-up" trap. Optional; legacy
	// JWT-only behaviour when nil. Wire via SetSessionRepository.
	sessionRepo *repositories.SessionRepository
	// activityTracker is optional. When set, every successful RequireAuth
	// pass fires a fire-and-forget Touch — the tracker itself applies a
	// Redis-gated per-session throttle so the DB sees at most one write
	// per session per minute. Required for idle-timeout enforcement to
	// be accurate (otherwise LastActivityAt only updates on explicit
	// /heartbeat calls, which the UI may not send reliably).
	activityTracker *SessionActivityTracker
	// dpop enforces RFC 9449 token-to-key binding when wired. It runs
	// inside RequireAuth after successful token validation:
	//   (a) If a DPoP proof header is present, validate it and claim the
	//       JTI (replay protection).
	//   (b) If the token carries cnf.jkt (claims.CnfJKT != ""), require a
	//       matching proof JKT and matching ath. Missing/mismatched proof
	//       → 401. Bare bearer tokens (no cnf) continue to work unchanged.
	// Leave nil to disable — the middleware is gated by cfg.DPoPEnabled
	// at construction.
	dpop *DPoPMiddleware
	// idpUsers backs the SSO-cookie eligibility check (disabled / deleted /
	// locked users must not be resurrected by a surviving cookie). Optional.
	idpUsers idpUserLookup
	// idpSessions backs the "is the iam_sessions row behind this SSO cookie
	// still live" check. Optional.
	idpSessions idpSessionReader
}

// idpSessionReader is the session-row read the SSO cookie path needs;
// satisfied by *repositories.SessionRepository.
type idpSessionReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	GetByIDWithRealmContext(ctx context.Context, id uuid.UUID, realmID uuid.UUID) (*models.Session, error)
}

// SetIdpSessionReader wires the session-row reader used to verify that an SSO
// cookie's backing login session has not ended.
func (m *AuthMiddleware) SetIdpSessionReader(r idpSessionReader) {
	m.idpSessions = r
}

// idpUserLookup is the user read the SSO cookie path needs; satisfied by
// *repositories.UserRepository.
type idpUserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// SetIdpUserLookup wires the user lookup used to re-check account status on
// the IdP SSO cookie path.
func (m *AuthMiddleware) SetIdpUserLookup(l idpUserLookup) {
	m.idpUsers = l
}

// idpBackingCheckTTL bounds how long a successful session-row/user check is
// reused by the SSO cookie path.
const idpBackingCheckTTL = 45 * time.Second

const (
	// Circuit breaker configuration
	circuitBreakerThreshold    = 5                // Open circuit after 5 consecutive failures
	circuitBreakerResetTimeout = 30 * time.Second // Try to close circuit after 30 seconds
	circuitBreakerOpenDuration = 60 * time.Second // Keep circuit open for 60 seconds minimum
)

// SetTenantSuspensionChecker wires the tenant-suspension gate used by the IdP
// SSO cookie path (bearer tokens are gated in TokenService validation).
func (m *AuthMiddleware) SetTenantSuspensionChecker(c services.TenantSuspensionChecker) {
	m.tenantSuspension = c
}

// NewAuthMiddleware is an exported function.
func NewAuthMiddleware(tokenService *services.TokenService, cfg *config.Config) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
		config:       cfg,
		circuitBreaker: &circuitBreakerState{
			failures: 0,
			isOpen:   false,
		},
	}
}

// SetSessionRepository wires the iam_sessions DB repo so RequireFreshAuth
// can fall back to session.authenticated_at when the JWT auth_time claim
// is missing or stale. See the RequireFreshAuth doc for the rationale
// and the two production scenarios this guards against. Optional —
// when unset, RequireFreshAuth retains the legacy JWT-only behaviour.
//
// 2026-05-17 — added as the interim fix while the canonical token-
// re-issuance pattern (Layer 1 of the MFA step-up tier-1 refactor) is
// designed and shipped.
func (m *AuthMiddleware) SetSessionRepository(repo *repositories.SessionRepository) {
	m.sessionRepo = repo
}

// SetStepUpRepository wires the iam_step_up_verifications repo so
// RequireFreshAuthForAction can pass when an in-place step-up
// verification (POST /api/v1/auth/mfa/step-up/verify) for the same
// action has recently completed. Without this, all step-up flows are
// forced through full OAuth re-auth, which industry tier-1 IdPs
// (Auth0, Google, Okta, Microsoft Entra) do NOT do — they use
// in-context single-factor prompts. Optional; when unset, action-
// scoped middleware behaves identically to the legacy RequireFreshAuth.
func (m *AuthMiddleware) SetStepUpRepository(repo *repositories.StepUpVerificationRepository) {
	m.stepUpRepo = repo
}

// SetSessionCache wires the Redis session cache so OptionalAuth can resolve
// the falcon_idp_session SSO cookie when no valid access token is present.
func (m *AuthMiddleware) SetSessionCache(cache *redispkg.SessionCache) {
	m.sessionCache = cache
}

// SetActivityTracker wires the session-activity tracker. When set, every
// successful RequireAuth pass records activity on the associated session.
// The tracker throttles DB writes via Redis so the hot path stays cheap.
func (m *AuthMiddleware) SetActivityTracker(tracker *SessionActivityTracker) {
	m.activityTracker = tracker
}

// SetDPoPMiddleware wires RFC 9449 enforcement into RequireAuth. See the
// `dpop` field doc on AuthMiddleware for behaviour details. Pass nil or
// leave unset to keep RequireAuth as a plain bearer-token gate.
func (m *AuthMiddleware) SetDPoPMiddleware(dp *DPoPMiddleware) {
	m.dpop = dp
}

// recordRedisFailure records a Redis failure and potentially opens the circuit breaker
func (m *AuthMiddleware) recordRedisFailure() {
	m.circuitBreaker.mu.Lock()
	defer m.circuitBreaker.mu.Unlock()

	m.circuitBreaker.failures++
	m.circuitBreaker.lastFailureTime = time.Now()

	if m.circuitBreaker.failures >= circuitBreakerThreshold && !m.circuitBreaker.isOpen {
		m.circuitBreaker.isOpen = true
		logger.Log.Error("SECURITY: Redis circuit breaker OPENED - multiple failures detected",
			zap.Int("failure_count", m.circuitBreaker.failures),
			zap.Time("last_failure", m.circuitBreaker.lastFailureTime),
		)
	}
}

// recordRedisSuccess records a successful Redis operation and potentially closes the circuit breaker
func (m *AuthMiddleware) recordRedisSuccess() {
	m.circuitBreaker.mu.Lock()
	defer m.circuitBreaker.mu.Unlock()

	if m.circuitBreaker.isOpen {
		logger.Log.Info("Redis circuit breaker CLOSED - operation successful",
			zap.Int("previous_failures", m.circuitBreaker.failures),
		)
	}

	m.circuitBreaker.failures = 0
	m.circuitBreaker.isOpen = false
}

// isCircuitBreakerOpen checks if the circuit breaker is open
func (m *AuthMiddleware) isCircuitBreakerOpen() bool {
	m.circuitBreaker.mu.RLock()
	defer m.circuitBreaker.mu.RUnlock()

	if !m.circuitBreaker.isOpen {
		return false
	}

	// Check if enough time has passed to attempt recovery
	if time.Since(m.circuitBreaker.lastFailureTime) > circuitBreakerResetTimeout {
		return false // Allow one attempt to check if Redis is back
	}

	return true
}

// SetAuthorizationEngine sets the authorization engine for unified permission checks.
// SECURITY: This must be called during startup — fail-closed when nil.
func (m *AuthMiddleware) SetAuthorizationEngine(authzEngine services.AuthorizationEngine) {
	m.authzEngine = authzEngine
}

// RequireAuth middleware that requires a valid JWT token
// SECURITY (CVE-HEXX-IAM-004): Enforces fail-closed session validation
// - Redis unavailable -> 503 Service Unavailable (not 401 Unauthorized)
// - Circuit breaker pattern prevents cascading failures
// - Cannot verify session blacklist -> deny access
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Real client public IP (X-Real-IP, APISIX-stamped from CF-Connecting-IP)
		// — for SECURITY-log lines on circuit-breaker abort + token validation
		// failure, the attacker's actual public IP is the audit value, not the
		// APISIX pod IP which is identical across every request.
		clientIP := ClientIP(c.Request)

		// Spring Security's SecurityContextHolder pattern: when an
		// upstream authentication filter (in our case OptionalAuth,
		// mounted globally in cmd/routes.go applyGlobalMiddleware
		// BEFORE the CSRF middleware) has already validated the
		// access token and populated the auth context, short-circuit
		// the duplicate ValidateAccessTokenWithContext call. The
		// upstream validation is the authoritative one for this
		// request — re-running it would burn ~10-20ms (signature
		// verify + Redis blacklist check + per-session lookup) for
		// no security gain.
		//
		// We still run DPoP enforcement + activity-tracker steps
		// against the upstream-populated context. Reference:
		// docs.spring.io/spring-security/reference/servlet/architecture.html
		// — "If the repository contains a security context, the
		// filter does nothing. If it doesn't, and the SecurityContext
		// contains a (non-anonymous) Authentication object, the
		// filter assumes they have been authenticated by a previous
		// filter in the stack."
		if existing := GetCurrentUser(c); existing != nil {
			if m.dpop != nil {
				if !m.dpop.ValidateProofIntoContext(c) {
					return
				}
				if !VerifyTokenBindingInline(c) {
					return
				}
			}
			if m.activityTracker != nil {
				m.activityTracker.Touch(existing.SessionID)
			}
			c.Next()
			return
		}

		// Defensive fall-through: when OptionalAuth didn't run (some
		// route group mounted RequireAuth without the global chain) or
		// its validation failed (e.g. token missing/invalid), do the
		// full validation here. Behavior unchanged from pre-Spring-
		// SecurityContextHolder-refactor.
		tokenString, ok := extractToken(c)
		if !ok {
			return
		}

		if m.isCircuitBreakerOpen() {
			logger.Log.Error("SECURITY: Authentication blocked - Redis circuit breaker is OPEN (fail-closed)",
				zap.String("client_ip", clientIP),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":  "Service temporarily unavailable",
				"detail": "Session validation service is experiencing issues. Please try again in a few moments.",
			})
			return
		}

		claims, err := m.tokenService.ValidateAccessTokenWithContext(c.Request.Context(), tokenString)
		if err != nil {
			m.handleTokenValidationError(c, err, clientIP)
			return
		}

		m.recordRedisSuccess()
		setAuthContext(c, claims)
		// RFC 8693 §4.1 delegation-chain audit. When the token was
		// minted via the token-exchange grant, the `act` claim carries
		// the actor identity (the BFF / IAP bridge). Emit a structured
		// log line so Wazuh / Loki can join subject ↔ actor across
		// the request lifetime. §4.1 explicitly forbids using `act` for
		// access control, so we LOG ONLY — never reject on it. Absent
		// `act` is the steady state for non-delegated tokens
		// (password / refresh / client_credentials grants).
		logDelegationActor(c, claims)
		// DPoP hooks — raw access token and cnf.jkt are needed by the
		// VerifyTokenBinding middleware (RFC 9449 §6). Always set these
		// when present; VerifyTokenBinding itself is a no-op when either
		// is missing, so unbound tokens pass through unchanged.
		c.Set(ginContextKeyRawToken, tokenString)
		if claims.CnfJKT != "" {
			c.Set("token_cnf_jkt", claims.CnfJKT)
		}
		// RFC 9449 enforcement. When the middleware is wired, run the
		// optional-proof validator (extracts + replay-checks the proof)
		// and then the binding verifier inline — using the *Inline
		// helpers that do NOT advance the gin chain, so our own c.Next()
		// at the bottom runs once. Either step can abort the request
		// with 4xx; if it does, stop immediately.
		if m.dpop != nil {
			if !m.dpop.ValidateProofIntoContext(c) {
				return
			}
			if !VerifyTokenBindingInline(c) {
				return
			}
		}
		// Record activity AFTER DPoP checks so a spoofed request never
		// bumps activity and extends a session it shouldn't have.
		if m.activityTracker != nil {
			m.activityTracker.Touch(claims.SessionID)
		}
		c.Next()
	}
}

// extractToken reads the bearer token from the Authorization header or the falcon_access_token cookie.
// Returns the token string and true on success; aborts the request and returns false on failure.
func extractToken(c *gin.Context) (string, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return "", false
		}
		return parts[1], true
	}

	cookie, err := c.Cookie("falcon_access_token")
	if err != nil || cookie == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		return "", false
	}
	return cookie, true
}

// handleTokenValidationError responds appropriately depending on whether the error is a Redis outage.
func (m *AuthMiddleware) handleTokenValidationError(c *gin.Context, err error, clientIP string) {
	if redispkg.IsRedisUnavailableError(err) {
		m.recordRedisFailure()
		logger.Log.Error("SECURITY: Redis unavailable during token validation - denying access (fail-closed)",
			zap.Error(err),
			zap.String("client_ip", clientIP),
			zap.String("path", c.Request.URL.Path),
		)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error":  "Service temporarily unavailable",
			"detail": "Session validation service is currently unavailable. Please try again later.",
		})
		return
	}

	// Suspended tenant (R1-GAPS row 27): distinct, stable code so clients can
	// show "organization suspended" instead of looping on re-auth.
	if errors.Is(err, services.ErrTenantSuspended) {
		logger.Log.Info("Token rejected: tenant suspended", zap.String("client_ip", clientIP))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":             "tenant_suspended",
			"error_description": "This organization's account is suspended. Contact your administrator or support.",
		})
		return
	}

	logger.Log.Info("Token validation failed",
		zap.Error(err),
		zap.String("client_ip", clientIP),
	)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
}

// setAuthContext populates the Gin context with all identity values derived from validated claims.
func setAuthContext(c *gin.Context, claims *models.Claims) {
	currentUser := &models.CurrentUser{
		ID:              claims.UserID,
		TenantID:        claims.TenantID,
		Username:        claims.Username,
		Email:           claims.Email,
		Roles:           claims.Roles,
		Permissions:     claims.Permissions,
		SessionID:       claims.SessionID,
		RealmID:         claims.RealmID,
		RealmSlug:       claims.RealmSlug,
		RealmType:       claims.RealmType,
		IsPlatformAdmin: claims.IsPlatformAdmin,
		AuthMethod:      models.AuthMethodAccessToken,
		AuthTime:        claims.AuthTime,
	}
	applyStrictPlatformAuthority(c, currentUser)

	c.Set(CurrentUserKey, currentUser)
	c.Set(CurrentSessionKey, claims.SessionID)
	c.Set("user_id", claims.UserID)
	c.Set("tenant_id", claims.TenantID)
	c.Set("session_id", claims.SessionID)
	// RLS bootstrap: internal/shared/database.RLSMiddleware reads "realm_id"
	// (via its realm fallback path) to set app.current_realm_id for the
	// request's transaction. Without this, every authenticated request would
	// silently run with realm_id unset, which is fail-open for any RLS
	// policy that is realm-scoped only (e.g. iam_sessions' strict_realm_sessions).
	if claims.RealmID != uuid.Nil {
		c.Set("realm_id", claims.RealmID)
	}

	if claims.ImpersonatorID != nil {
		c.Set(ImpersonatorIDKey, *claims.ImpersonatorID)
		c.Set("impersonator_id", *claims.ImpersonatorID)
	}
	if claims.ImpersonationSessionID != nil {
		c.Set(ImpersonationSessionIDKey, *claims.ImpersonationSessionID)
		c.Set("impersonation_session_id", *claims.ImpersonationSessionID)
	}
}

// logDelegationActor emits a structured INFO line every time an
// authenticated request carries the RFC 8693 §4.1 `act` claim. The line
// is keyed on `delegation_actor=true` so Loki / Wazuh dashboards can
// pivot to "every request a given BFF performed on a given subject"
// without parsing the JWT itself. Cardinality is bounded by the
// ServiceClientClaim allocation (one client_id per BFF, ~10 total).
//
// SECURITY: This function MUST NOT influence authorisation. RFC 8693
// §4.1 — "the consumer of a token MUST only consider the token's top-
// level claims and the party identified as the current actor by the
// `act` claim" — explicitly forbids using prior actors in nested chains
// for access control. We log only.
func logDelegationActor(c *gin.Context, claims *models.Claims) {
	if claims == nil || claims.Actor == nil {
		return
	}
	a := claims.Actor
	logger.Log.Info("RFC 8693 delegation",
		zap.Bool("delegation_actor", true),
		zap.String("subject", claims.UserID.String()),
		zap.String("subject_email", claims.Email),
		zap.String("actor_sub", a.Sub),
		zap.String("actor_client_id", a.ClientID),
		zap.String("actor_iss", a.Iss),
		zap.String("session_id", claims.SessionID.String()),
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
		zap.String("client_ip", ClientIP(c.Request)),
	)
}

// RequireFreshAuth enforces RFC 9470 (OAuth 2.0 Step Up Authentication
// Challenge Protocol) `max_age` style freshness on sensitive endpoints:
// password change, MFA disable, session revocation, etc. The user MUST
// have authenticated within the last `maxAge` window — refreshing the
// access token does NOT count, because the `auth_time` claim is
// preserved across refresh-token rotations (RFC 9470 §6.1) precisely
// so resource servers can make this distinction.
//
// Wire behaviour on stale auth: 401 with the canonical RFC 9470 §4
// `WWW-Authenticate: Bearer error="insufficient_user_authentication"`
// challenge carrying the required `max_age` (in seconds). RFC-compliant
// clients (frontend-login + Talon + downstream SPAs) parse this and
// kick the user through /oauth/authorize with `max_age=<n>` +
// `prompt=login`, satisfying the freshness requirement on return.
//
// Cookie-only auth (AuthMethodIdpSession) carries the IdP session's
// AuthTime captured at login. A 7-day-old session with a recent
// AuthTime will pass; a 7-day-old session whose AuthTime is also
// 7 days old will not.
//
// DB fallback (2026-05-17): when JWT auth_time is missing/stale, the
// middleware consults iam_sessions.authenticated_at directly. This
// covers two real production cases:
//
//   1. The user holds an access token issued before the AuthTime claim
//      shipped (token rotation hasn't refreshed it yet). The claim is
//      0; the JWT-only path would reject. The DB has a valid
//      authenticated_at recorded at the login that issued the token.
//
//   2. The user just completed a step-up MFA flow (/api/v1/auth/mfa/
//      step-up/verify), which bumps iam_sessions.authenticated_at but
//      doesn't re-issue the JWT. The JWT-only path would still reject
//      on the retry, looping the user forever. The DB now reflects the
//      fresh elevation; the fallback passes the retry.
//
// The DB fallback only fires when the JWT path WOULD have rejected.
// 2xx requests pay no extra cost — the JWT-only path is checked first
// and short-circuits on the common case. DB-fallback rejections still
// emit the canonical RFC 9470 challenge.
//
// Defense-in-depth note: the canonical enterprise pattern (Auth0/Okta/
// Duende) is to re-issue the access token immediately after step-up
// verification so the JWT-only path keeps working without a DB consult.
// That fix is tracked separately (full Layer 1+3 token re-issuance);
// this fallback is the interim "user with stale JWT can still escape
// the trap" guard until that lands.
//
// Mount AFTER RequireAuth so CurrentUserKey is guaranteed populated.
// Wire `SetSessionRepository` in main.go to enable the DB fallback;
// when unset, the middleware retains the legacy JWT-only behaviour.
func (m *AuthMiddleware) RequireFreshAuth(maxAge time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "not authenticated",
			})
			return
		}

		// Primary path: JWT auth_time claim. Cheap, stateless.
		if user.AuthTime > 0 {
			age := time.Since(time.Unix(user.AuthTime, 0))
			if age <= maxAge {
				c.Next()
				return
			}
			// JWT claim is stale. Fall through to DB.
		}

		// DB fallback path. Only runs when JWT path WOULD have rejected.
		if m.sessionRepo != nil {
			if m.fallbackToSessionDB(c, maxAge) {
				c.Next()
				return
			}
		}

		// Both paths agree the auth is too old / unknown. Emit the
		// challenge with the appropriate message so the client knows
		// whether it's a "never recorded" vs "expired" situation.
		if user.AuthTime == 0 {
			emitStepUpChallenge(c, maxAge, "authentication time unknown for this session; re-authentication required")
		} else {
			emitStepUpChallenge(c, maxAge, "authentication too old for this operation; re-authentication required")
		}
	}
}

// RequireFreshAuthForAction is the canonical in-place-step-up-aware
// freshness gate. Same RFC 9470 semantics as RequireFreshAuth but
// adds a third validation path: when JWT auth_time + session DB
// authenticated_at are both stale, consult iam_step_up_verifications
// for a row matching (session_id, action) that's still within the
// maxAge window. This is the mechanism that lets the frontend ship
// an in-place step-up modal (Auth0 / Google / Okta pattern) instead
// of forcing a disruptive full OAuth-redirect re-login.
//
// Flow:
//  1. User clicks "Disable Email MFA" on accounts.example.com
//  2. POST /mfa/disable/email → freshAuth rejects (stale auth_time)
//  3. Frontend portalFetch detects step-up challenge → opens modal
//  4. User provides single factor (passkey via WebAuthn OR OTP)
//  5. POST /api/v1/auth/mfa/step-up/verify {code, action:"mfa.disable"}
//  6. Handler validates factor → INSERT iam_step_up_verifications
//  7. Frontend retries POST /mfa/disable/email
//  8. THIS middleware now passes because step-up row exists for
//     (session_id, "mfa.disable") within maxAge
//
// Empty action is treated as "any" — equivalent to RequireFreshAuth
// (no step-up table consult). Routes that want per-action gating
// MUST supply a non-empty action string; routes that just want time-
// based freshness can pass empty.
//
// Action strings should namespace by resource to avoid replay across
// different sensitive operations. Recommended:
//
//	mfa.disable          — POST /mfa/disable, /mfa/disable/totp, /mfa/disable/email
//	mfa.push.unregister  — DELETE /mfa/push/devices/:id
//	password.change      — POST /password/change
//	session.revoke       — DELETE /sessions/:id
//	webauthn.delete      — DELETE /webauthn/credentials/:id
//	account.delete       — POST /users/me/delete-account
//
// Mount AFTER RequireAuth so session_id is in context.
func (m *AuthMiddleware) RequireFreshAuthForAction(maxAge time.Duration, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetCurrentUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "not authenticated",
			})
			return
		}

		// Path 1: JWT auth_time. Cheap, stateless. Common case.
		if user.AuthTime > 0 {
			age := time.Since(time.Unix(user.AuthTime, 0))
			if age <= maxAge {
				c.Next()
				return
			}
		}

		// Path 2: session DB authenticated_at. Catches the post-step-up
		// case where iam_sessions.authenticated_at was bumped by
		// VerifyStepUp but the JWT wasn't re-issued.
		if m.sessionRepo != nil && m.fallbackToSessionDB(c, maxAge) {
			c.Next()
			return
		}

		// Path 3 (NEW): in-place step-up verification. Match by
		// (session_id, action) so a step-up for one resource does not
		// silently authorize a different resource. Only fires when an
		// action string was supplied — empty action means "no per-
		// action elevation table consult; act like RequireFreshAuth".
		if m.stepUpRepo != nil && action != "" {
			sessionVal, ok := c.Get(CurrentSessionKey)
			if ok {
				if sessionID, isUUID := sessionVal.(uuid.UUID); isUUID {
					ok, err := m.stepUpRepo.HasRecentVerification(c.Request.Context(), sessionID, action, maxAge)
					if err == nil && ok {
						c.Next()
						return
					}
					if err != nil {
						logger.Log.Warn("RequireFreshAuthForAction: step-up lookup failed (treating as no step-up)",
							zap.String("action", action),
							zap.String("session_id", sessionID.String()),
							zap.Error(err),
						)
					}
				}
			}
		}

		// All three paths agree the auth is too old. Emit canonical
		// RFC 9470 challenge. Carry the action so the client knows
		// which step-up to perform on retry.
		desc := "authentication too old for this operation; re-authentication required"
		if user.AuthTime == 0 {
			desc = "authentication time unknown for this session; re-authentication required"
		}
		emitStepUpChallengeForAction(c, maxAge, action, desc)
	}
}

// fallbackToSessionDB looks up iam_sessions.authenticated_at for the
// current session and reports whether it satisfies the maxAge window.
// Returns false on any error / missing session / NULL authenticated_at
// (fail-closed); the caller emits the step-up challenge in that case.
func (m *AuthMiddleware) fallbackToSessionDB(c *gin.Context, maxAge time.Duration) bool {
	sessionVal, exists := c.Get(CurrentSessionKey)
	if !exists {
		return false
	}
	sessionID, ok := sessionVal.(uuid.UUID)
	if !ok {
		return false
	}
	session, err := m.sessionRepo.GetByID(c.Request.Context(), sessionID)
	if err != nil || session == nil || session.AuthenticatedAt == nil {
		return false
	}
	age := time.Since(*session.AuthenticatedAt)
	return age <= maxAge
}

// emitStepUpChallenge writes the RFC 9470 §4 `insufficient_user_authentication`
// challenge. Header form matches the RFC exactly so off-the-shelf clients
// (Auth0 SDK, oauth2-proxy, modern SPA OIDC libs) detect the step-up
// requirement without bespoke code. JSON body mirrors the same fields so
// fetch-based callers without WWW-Authenticate parsing can react too.
func emitStepUpChallenge(c *gin.Context, maxAge time.Duration, desc string) {
	emitStepUpChallengeForAction(c, maxAge, "", desc)
}

// emitStepUpChallengeForAction is the action-aware variant. When action
// is non-empty it is included in the JSON body and as a custom
// `action_required="..."` parameter on the WWW-Authenticate header. The
// frontend uses this to know which action string to pass through to
// /api/v1/auth/mfa/step-up/verify on the subsequent retry — without it
// the client would have to guess based on the path, which couples the
// client to server route shapes.
func emitStepUpChallengeForAction(c *gin.Context, maxAge time.Duration, action, desc string) {
	maxAgeSec := int(maxAge.Seconds())
	header := fmt.Sprintf(
		`Bearer error="insufficient_user_authentication", error_description=%q, max_age=%d`,
		desc, maxAgeSec,
	)
	if action != "" {
		header += fmt.Sprintf(`, action_required=%q`, action)
	}
	c.Header("WWW-Authenticate", header)
	body := gin.H{
		"error":             "insufficient_user_authentication",
		"error_description": desc,
		"max_age":           maxAgeSec,
	}
	if action != "" {
		body["action_required"] = action
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, body)
}

// RequirePermission middleware that requires specific permission(s)
// Supports both RBAC (default) and ABAC (when USE_ABAC=true)
func (m *AuthMiddleware) RequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userVal, exists := c.Get(CurrentUserKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		user, ok := userVal.(*models.CurrentUser)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			return
		}

		// Check permissions - try ABAC if enabled, fall back to RBAC
		hasPermission := m.checkPermissions(c, user, permissions...)
		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}

		c.Next()
	}
}

// checkPermissions checks if user has any of the required permissions via SpiceDB.
// SECURITY: SpiceDB is the sole authority. Fail-closed when authzEngine is nil.
// Exception: Platform admins (exampletenant tenant, holding platform_admin
// or iam_admin) bypass SpiceDB for platform-scoped permissions.
func (m *AuthMiddleware) checkPermissions(c *gin.Context, user *models.CurrentUser, permissions ...string) bool {
	// Platform admins have implicit access to all platform-scoped permissions.
	// This avoids requiring every platform:* permission to be seeded in SpiceDB.
	//
	// SECURITY (R0 platform-admin audit finding F1): tenant membership alone
	// used to be sufficient here, which meant every account in the
	// exampletenant tenant — including non-admin service accounts —
	// implicitly got every platform:* permission. Require the platform-plane
	// role too; a bare tenant match no longer bypasses SpiceDB.
	//
	// OPS_STRICT_PLATFORM_ROLES: platformPlaneRoleOK swaps the legacy tenant
	// role (platform_admin / iam_admin) for the live iam_platform_roles
	// verdict; with the flag off it is exactly the old role check.
	if user.IsPlatformAdmin && user.TenantID.String() == models.HexxlockInternalTenantID &&
		platformPlaneRoleOK(user) {
		return true
	}

	if m.authzEngine == nil {
		// SECURITY: fail-closed — no authorization engine means deny all
		logger.Log.Error("SECURITY: checkPermissions called but authzEngine is nil — fail-closed",
			zap.String("user_id", user.ID.String()),
			zap.String("path", c.Request.URL.Path),
		)
		return false
	}

	for _, permission := range permissions {
		result, err := m.authzEngine.CheckPermission(c.Request.Context(), services.PermissionRequest{
			UserID:     user.ID,
			TenantID:   user.TenantID,
			Permission: permission,
		})
		if err != nil {
			logger.Log.Warn("SpiceDB permission check error",
				zap.Error(err),
				zap.String("permission", permission),
				zap.String("user_id", user.ID.String()),
			)
			continue
		}
		if result.Allowed {
			return true
		}
	}
	return false
}

// RequireAllPermissions middleware that requires all specified permissions via SpiceDB.
// SECURITY: Every permission is checked individually against SpiceDB. Fail-closed when authzEngine is nil.
func (m *AuthMiddleware) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userVal, exists := c.Get(CurrentUserKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		user, ok := userVal.(*models.CurrentUser)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			return
		}

		// Check every permission via SpiceDB — all must be granted
		for _, permission := range permissions {
			if !m.checkPermissions(c, user, permission) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
				return
			}
		}

		c.Next()
	}
}

// RequireRole middleware that requires specific role(s)
func (m *AuthMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userVal, exists := c.Get(CurrentUserKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		user, ok := userVal.(*models.CurrentUser)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			return
		}

		hasRole := false
		for _, required := range roles {
			// OPS_STRICT_PLATFORM_ROLES: the platform-plane role names are
			// decided by iam_platform_roles, not by tenant-role membership.
			if strictPlatformRoles() && isPlatformPlaneRoleName(required) {
				if user.PlatformAuthorityVerified {
					hasRole = true
					break
				}
				continue
			}
			if user.HasRole(required) {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient role"})
			return
		}

		c.Next()
	}
}

// OptionalAuth middleware that extracts user if token present but doesn't require it
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				c.Next()
				return
			}
			tokenString = parts[1]
		} else {
			// Fallback: check HttpOnly cookie (browser-based auth)
			cookie, err := c.Cookie("falcon_access_token")
			if err != nil || cookie == "" {
				// No access token — check the IdP SSO session cookie so that a user
				// who completed login via /oauth/login is recognised without requiring
				// a fresh access token issuance (e.g. on the /oauth/authorize redirect
				// back after login).
				m.resolveIdpSessionCookie(c)
				c.Next()
				return
			}
			tokenString = cookie
		}

		claims, err := m.tokenService.ValidateAccessTokenWithContext(c.Request.Context(), tokenString)
		if err == nil {
			// Delegate identity-context wiring to setAuthContext so this
			// path stays bit-for-bit identical to RequireAuth's. The
			// previous inline construction silently drifted from
			// setAuthContext — dropped AuthMethod + AuthTime + the
			// ImpersonatorID / ImpersonationSessionID mirrors — causing
			// every RFC 9470 freshness gate to fail closed (AuthTime==0
			// → "infinitely stale") on the OptionalAuth code path while
			// the RequireAuth path worked. Live repro 2026-05-24
			// immediately after the max_age enforcement landed in
			// falcon-id!241: dogukanturhal password+OTP login looped on
			// every max_age=300 OIDC request from accounts.example.com
			// because /oauth/authorize is mounted under OptionalAuth +
			// every just-minted token was misclassified as stale.
			//
			// Single-source the construction so the next field added to
			// CurrentUser cannot silently regress this path again.
			setAuthContext(c, claims)
			// Mirror DPoP context keys so downstream RequireAuth (which
			// short-circuits when CurrentUser is already populated, per
			// the canonical Spring Security SecurityContextHolder pattern
			// — single authentication step, multiple authorization checks)
			// can still drive its DPoP-binding verifier without re-
			// extracting the raw token. Matches setAuthContext + the
			// post-validation block in RequireAuth (lines ~197-200).
			c.Set(ginContextKeyRawToken, tokenString)
			if claims.CnfJKT != "" {
				c.Set("token_cnf_jkt", claims.CnfJKT)
			}
			// RFC 8693 §4.1 delegation-chain audit on the OptionalAuth
			// fast path — RequireAuth's SecurityContextHolder short-
			// circuit skips its own logDelegationActor call when the
			// current-user is already set, so we MUST emit here or the
			// audit line is silently dropped for the (very common) path
			// where OptionalAuth ran globally.
			logDelegationActor(c, claims)
		} else {
			// Access-token validation failed (expired / revoked / malformed).
			// Fall back to the IdP SSO cookie so the user stays signed in
			// across client flows for the duration of the longer-lived
			// falcon_idp_session window.
			m.resolveIdpSessionCookie(c)
		}

		c.Next()
	}
}

// resolveIdpSessionCookie attempts to populate the Gin context with identity from the
// falcon_idp_session cookie.  This provides SSO continuity for browser-initiated OIDC
// flows: once the user has authenticated at the IdP, subsequent /oauth/authorize
// requests within the cookie's lifetime skip the login prompt.
//
// It also populates CurrentUserKey + CurrentSessionKey with a minimal CurrentUser
// (UserID + TenantID + SessionID, no roles/permissions) so that downstream guards
// — RequireAuth's SecurityContextHolder short-circuit, CSRF's synchronizer-token
// path, GetCurrentUser-based handler logic — accept the IdP session cookie as the
// canonical authenticated principal during mid-OAuth-flow states where the user
// has no access token yet. This is required for the /auth/mfa/enrollment landing
// page: the ACR step-up gate redirects there BEFORE any token is issued, so the
// only proof of identity the user holds is the falcon_idp_session cookie, and
// the enrollment frontend must be able to call /auth/csrf-token, /auth/mfa/status,
// and /webauthn/registration/begin with cookie-only auth. Roles/permissions stay
// empty by design — the IdP session payload is intentionally lightweight, and
// RequirePermission/RequireRole guards must continue to fail closed for
// cookie-only callers (no role grants from a bare session marker).
//
// Non-fatal by design: failures (Redis down, expired cookie) are silently ignored so
// the authorize endpoint falls back to redirecting the user to /oauth/login.
func (m *AuthMiddleware) resolveIdpSessionCookie(c *gin.Context) {
	if m.sessionCache == nil {
		return
	}
	cookieVal, err := c.Cookie("falcon_idp_session")
	if err != nil || cookieVal == "" {
		return
	}
	sessionID, err := uuid.Parse(cookieVal)
	if err != nil {
		return
	}
	// GetIdpSession returns nil (and deletes the record) once the absolute
	// cap from AuthTime has passed, so an over-age cookie falls through to login.
	data, err := m.sessionCache.GetIdpSession(c.Request.Context(), sessionID)
	if err != nil || data == nil {
		return
	}
	if !m.idpSessionStillValid(c, sessionID, data) {
		return
	}
	m.slideIdpSessionCookie(c, sessionID, data)
	// Suspended tenant: the SSO cookie must not resurrect an identity
	// (R1-GAPS row 27). Leave the context unauthenticated; downstream
	// RequireAuth then returns the 403 tenant_suspended via token validation
	// or 401 when there is no bearer token at all.
	if m.tenantSuspension != nil && m.tenantSuspension.IsSuspended(c.Request.Context(), data.TenantID) {
		return
	}
	c.Set("user_id", data.UserID)
	c.Set("tenant_id", data.TenantID)
	// session_id MUST be the iam_user_sessions.id, NOT the IdP cookie
	// UUID (which is the Redis key of the IdP session record itself).
	// Downstream MFA step-up code (MFAHandler.elevateCurrentSessionAMR
	// → sessionRepo.AppendAuthMethod) UPDATEs iam_user_sessions WHERE
	// id = session_id; passing the cookie UUID matches no row and the
	// UPDATE silently affects 0 rows, leaving auth_methods_used at
	// ["pwd"] forever — the OAuth step-up gate then keeps firing.
	// Live repro 2026-05-12.
	//
	// data.SessionID is uuid.Nil only for IdP sessions written before
	// this field landed. We deliberately do NOT fall back to a cookie-
	// UUID stand-in here — every consumer (AppendAuthMethod, the
	// SessionActivityTracker, the OIDC `sid` claim emitter) is a
	// no-op-on-nil at this commit, so the failure surface is the same
	// as on the legacy code path. Affected users will re-login within
	// the 7-day session TTL and resume on the new code path.
	c.Set("session_id", data.SessionID)
	idpUser := &models.CurrentUser{
		ID:         data.UserID,
		TenantID:   data.TenantID,
		Username:   data.Username,
		Email:      data.Email,
		SessionID:  data.SessionID,
		AuthMethod: models.AuthMethodIdpSession,
		AuthTime:   data.AuthTime,
		// IsPlatformAdmin is a tenant-scoped flag, NOT a role grant: it is
		// computed identically at token issuance as
		// `user.TenantID == HexxlockInternalTenantID` (services/token_service.go).
		// The IdP SSO session record carries the authentic TenantID, so we
		// derive the same flag here. Without it, the cookie-only OptionalAuth
		// path (the only credential a browser holds on the WebAuthn witness
		// enrollment page, where the access token lives in the Tauri app rather
		// than the browser) always saw IsPlatformAdmin=false and 403'd genuine
		// platform admins. Roles/Permissions deliberately stay empty (so
		// RequireRole/RequirePermission keep failing closed for bare cookie
		// callers); IsPlatformAdmin is orthogonal to those role/permission
		// grants and safe to derive from the already-trusted session tenant.
		IsPlatformAdmin: data.TenantID.String() == models.HexxlockInternalTenantID,
	}
	applyStrictPlatformAuthority(c, idpUser)
	c.Set(CurrentUserKey, idpUser)
	c.Set(CurrentSessionKey, data.SessionID)
}

// idpSessionStillValid enforces that an SSO cookie is still backed by a live
// login session and an eligible user. On a definitive failure it deletes the
// SSO record and clears the cookie; on a lookup error it just refuses (fail
// closed) and leaves the record for the next attempt.
func (m *AuthMiddleware) idpSessionStillValid(c *gin.Context, idpID uuid.UUID, data *redispkg.IdpSessionData) bool {
	ctx := c.Request.Context()
	reject := func() bool {
		_ = m.sessionCache.DeleteIdpSession(ctx, idpID)
		SetIdpSessionCookie(c, "", -time.Second)
		return false
	}
	// Records written before the row id was stored carry no session binding to
	// verify; they cannot be proven live, so force a fresh login.
	if data.SessionID == uuid.Nil {
		return reject()
	}
	if m.sessionCache.IdpBackingKnownGood(ctx, data.SessionID) {
		return true
	}
	var user *models.User
	if m.idpUsers != nil {
		u, err := m.idpUsers.GetByID(ctx, data.UserID)
		if err != nil {
			return false
		}
		if u == nil || !u.EligibleForTokens(time.Now()) {
			return reject()
		}
		user = u
	}
	if m.idpSessions != nil {
		var (
			sess *models.Session
			err  error
		)
		if user != nil && user.RealmID != uuid.Nil {
			sess, err = m.idpSessions.GetByIDWithRealmContext(ctx, data.SessionID, user.RealmID)
		} else {
			sess, err = m.idpSessions.GetByID(ctx, data.SessionID)
		}
		if err != nil {
			return false
		}
		// A missing row is not proof of an ended session (realm-scoped RLS can
		// hide it): accept, but do not cache. Reject only on a row that is
		// provably someone else's or was explicitly ended.
		if sess == nil {
			return true
		}
		if sess.UserID != data.UserID ||
			(!sess.IsActive && sess.EndReason != nil && models.IsExplicitSessionEnd(*sess.EndReason)) {
			return reject()
		}
	}
	m.sessionCache.MarkIdpBackingGood(ctx, data.SessionID, idpBackingCheckTTL)
	return true
}

// idpCookieDefaultIdle is the cookie idle window when SESSION_TTL_DEFAULT is unset.
const idpCookieDefaultIdle = 7 * 24 * time.Hour

// slideIdpSessionCookie re-issues falcon_idp_session with a fresh Max-Age so
// the browser cookie slides together with the server-side record. Without
// this the cookie dies at its original sign-in Max-Age even though the Redis
// record (which slides on read) is still valid. Max-Age =
// min(idle TTL, absolute deadline - now). The issue time is not knowable, so
// re-issue is limited to /oauth/authorize requests (silent-SSO hops).
func (m *AuthMiddleware) slideIdpSessionCookie(c *gin.Context, sessionID uuid.UUID, data *redispkg.IdpSessionData) {
	if c.Request.Method != http.MethodGet || !strings.HasSuffix(c.Request.URL.Path, "/oauth/authorize") {
		return
	}
	maxAge := idpCookieDefaultIdle
	if m.config != nil && m.config.SessionTTLDefault > 0 {
		maxAge = m.config.SessionTTLDefault
	}
	if deadline, ok := m.sessionCache.IdpAbsoluteDeadline(data); ok {
		if remaining := time.Until(deadline); remaining < maxAge {
			maxAge = remaining
		}
	}
	if maxAge < time.Second {
		return
	}
	SetIdpSessionCookie(c, sessionID.String(), maxAge)
}

// GetCurrentUser extracts current user from context
func GetCurrentUser(c *gin.Context) *models.CurrentUser {
	userVal, exists := c.Get(CurrentUserKey)
	if !exists {
		return nil
	}

	user, ok := userVal.(*models.CurrentUser)
	if !ok {
		return nil
	}

	return user
}

// GetCurrentUserID extracts current user ID from context
func GetCurrentUserID(c *gin.Context) *uuid.UUID {
	user := GetCurrentUser(c)
	if user == nil {
		return nil
	}
	return &user.ID
}

// GetCurrentTenantID extracts current tenant ID from context
func GetCurrentTenantID(c *gin.Context) *uuid.UUID {
	user := GetCurrentUser(c)
	if user == nil {
		return nil
	}
	return &user.TenantID
}

// GetCurrentSessionID extracts current session ID from context
func GetCurrentSessionID(c *gin.Context) *uuid.UUID {
	sessionVal, exists := c.Get(CurrentSessionKey)
	if !exists {
		return nil
	}

	sessionID, ok := sessionVal.(uuid.UUID)
	if !ok {
		return nil
	}

	return &sessionID
}

// Platform admin, tenant admin, resource permission, tenant-scoped admin middlewares,
// and tenant extraction helpers are in auth_admin.go
