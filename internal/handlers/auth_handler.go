// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/clientctx"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

// Cookie configuration constants
const (
	accessTokenCookieName = "falcon_access_token"
	defaultAccessTokenTTL = 15 * time.Minute
	hdrUserAgent          = "User-Agent"

	envProduction = "production"
	hostLocalhost = "localhost"
	idpTypeLDAP   = "ldap"
)

// getCookieDomain returns the cookie Domain attribute for Set-Cookie responses.
//
// Resolution order:
//  1. COOKIE_DOMAIN env var, if set. This is the only correct source when
//     Falcon-ID sits behind a same-origin BFF (apps/login on id.example.com)
//     that proxies to us via an in-cluster Service URL — `c.Request.Host`
//     on the upstream hop is the cluster-internal hostname (e.g.
//     `falcon-id-falcon-id.falcon-id.svc.cluster.local`), and a cookie
//     bearing that Domain is rejected by browsers per RFC 6265 §5.3.6.
//  2. Otherwise fall back to `c.Request.Host` (sans port). This is correct
//     for direct browser→Falcon-ID hits (legacy /oauth/login form-submit,
//     id.example.com-direct API calls), where Host is the public hostname.
//  3. localhost / 127.0.0.1 short-circuit for dev-server cross-port sharing.
func getCookieDomain(c *gin.Context) string {
	return middleware.CookieDomain(c)
}

// isSecureEnvironment returns true if we should use secure cookies
func isSecureEnvironment() bool {
	return middleware.IsSecureEnvironment()
}

// setAuthCookies sets the HttpOnly access-token cookie. Refresh tokens are
// no longer issued by the auth-service path (Phase 3 / mig 233 dropped
// iam_refresh_tokens); OAuth refresh-token rotation flows through the BFF's
// /oauth/token call instead and never lands here.
func setAuthCookies(c *gin.Context, accessToken string, accessTTL time.Duration) {
	domain := getCookieDomain(c)
	secure := isSecureEnvironment()

	// Use SameSite=None in development for cross-origin XHR requests (localhost:3000 -> localhost:9080)
	// Chrome allows SameSite=None without Secure for localhost specifically
	// Use SameSite=Strict in production for better security
	sameSite := http.SameSiteStrictMode
	if !secure {
		sameSite = http.SameSiteLaxMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie(
		accessTokenCookieName,
		accessToken,
		int(accessTTL.Seconds()),
		"/",
		domain,
		secure,
		true, // HttpOnly
	)
}

// clearAuthCookies removes the access-token cookie.
//
// NOTE: this does NOT clear the falcon_idp_session SSO cookie — that is
// handled separately by clearIdpSessionCookie because most token-clear
// paths (token rotation, refresh failure, etc.) must keep the SSO
// session alive. Only the dedicated logout flow (OIDC RP-Initiated
// /oauth/logout, plus the API /api/v1/auth/logout) calls
// clearIdpSessionCookie + sessionCache.DeleteIdpSession to actually
// end the SSO session.
func clearAuthCookies(c *gin.Context) {
	domain := getCookieDomain(c)
	secure := isSecureEnvironment()

	// Use SameSite=None in development for cross-origin requests, Strict in production
	sameSite := http.SameSiteStrictMode
	if !secure {
		sameSite = http.SameSiteLaxMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie(accessTokenCookieName, "", -1, "/", domain, secure, true)
}

// clearIdpSessionCookie expires the falcon_idp_session SSO cookie on
// the response. Caller is responsible for also calling
// SessionCache.DeleteIdpSession on the cookie's UUID so a replayed
// pre-clear cookie value can't resurrect the session.
//
// Required from RP-Initiated Logout (/oauth/logout) + API logout
// (/api/v1/auth/logout). Without it, the SSO session persists and
// subsequent /oauth/authorize requests silently auto-consent — user-
// visible symptom: "logout doesn't work; I'm still signed in".
func clearIdpSessionCookie(c *gin.Context) {
	domain := getCookieDomain(c)
	secure := isSecureEnvironment()
	// falcon_idp_session is always SameSite=Lax, in every environment — see
	// establishIdpSession (d-254). Not gated on isSecureEnvironment like
	// the other cookies in this file.
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("falcon_idp_session", "", -1, "/", domain, secure, true)
}

// TenantLookup resolves tenant slugs to tenant IDs (used by public endpoints).
type TenantLookup interface {
	GetBySlug(ctx context.Context, slug string) (*models.Tenant, error)
}

// AuthHandler is an exported type.
type AuthHandler struct {
	authService          *services.AuthService
	mfaEnrollmentSvc     *services.MFAEnrollmentService
	tokenService         *services.TokenService
	passwordResetService *services.PasswordResetService
	idpRepo              IdpRepository
	csrfMiddleware       CSRFMiddleware
	idpRoutingService    *services.IDPRoutingService
	appIDPService        *services.AppIdentityProviderService
	tenantLookup         TenantLookup
	// dpop is wired when DPOP_ENABLED=true. Used at token-issuance
	// endpoints (login, refresh) to validate the presented DPoP proof
	// once and stash the resulting JKT on the request context so the
	// token generators bind cnf.jkt into the new access token.
	dpop *middleware.DPoPMiddleware
	// sessionCache, when wired, lets /api/v1/auth/login establish the
	// `falcon_idp_session` SSO cookie so a subsequent /oauth/authorize
	// in the same browser session does not bounce back to the login UI.
	// Mirrors OAuthProviderHandler.sessionCache; required once the
	// universal-login carve-out is on (OAUTH_LOGIN_REDIRECT_URL=/login)
	// because the legacy in-process /oauth/login form-submit no longer
	// runs and was the only other site writing this cookie.
	sessionCache *redispkg.SessionCache
	// tokenBlacklist, when wired, lets /api/v1/auth/logout publish the
	// user's session_id to the Redis session blacklist so the still-valid
	// `falcon_access_token` JWT cookie that may survive the response's
	// Set-Cookie clear directive (SDK race window between POST /logout
	// and a follow-up GET /oauth/authorize) is rejected by
	// enforceBlacklist inside ValidateAccessTokenWithContext. Session-
	// level (not user-level) on purpose: re-login mints a new session_id
	// so the blacklist does not leak into the next login attempt. Mirrors
	// the wire-up pattern on AdminHandler.SetTokenBlacklist
	// (admin_handler.go:83).
	tokenBlacklist *redispkg.TokenBlacklist
	// sessionRepo, when wired, lets /api/v1/auth/logout fan-out the
	// session-blacklist write across every active session for the user
	// when the calling JWT carries no `sid` claim. OAuth access tokens
	// minted to RPs (e.g. accounts.example.com) deliberately omit `sid`
	// per OIDC, so the BFF's server-side `Authorization: Bearer …`
	// logout call gives us only `user_id`. Without the fan-out, the
	// per-session BlacklistSession is skipped and the still-valid
	// `falcon_access_token` JWT cookie silent-SSOs the next
	// /oauth/authorize. Mirrors DeleteAllIdpSessionsByUser intent: a
	// user clicking Sign Out from one RP expects every browser session
	// they own to die.
	sessionRepo SessionRepository

	// config exposes the SessionTTLDefault / SessionTTLRememberMe knobs
	// that drive the falcon_idp_session cookie Max-Age (see
	// idpSessionCookieMaxAge / establishIdpSession). Optional — when
	// nil the legacy hardcoded 7d (default) / 30d (remember-me) values
	// apply so tests that don't inject a config keep working. Wire via
	// SetConfig from cmd/services.go once the config is constructed.
	config *config.Config
}

// SessionRepository is the subset of the session repository used by
// /api/v1/auth/logout for the fan-out blacklist path.
type SessionRepository interface {
	GetActiveSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error)
}

// CSRFMiddleware is an exported type.
type CSRFMiddleware interface {
	GenerateTokenForSession(c *gin.Context, sessionID uuid.UUID) (string, error)
	// WriteCookie sets the hexxlock_csrf cookie on the response so the
	// CSRF validator's double-submit fallback has a value to compare
	// against. Called from GetCSRFToken alongside the JSON token return.
	WriteCookie(c *gin.Context, token string)
}

// IdpRepository interface for identity provider operations needed by auth handler
type IdpRepository interface {
	GetEnabledSocialProviders(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) ([]*models.IdentityProvider, error)
	GetEnabledLoginProviders(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) ([]*models.IdentityProvider, error)
}

// NewAuthHandler is an exported function.
func NewAuthHandler(authService *services.AuthService, tokenService *services.TokenService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		tokenService: tokenService,
	}
}

// SetPasswordResetService sets the password reset service (called after initialization)
func (h *AuthHandler) SetPasswordResetService(service *services.PasswordResetService) {
	h.passwordResetService = service
}

// SetConfig wires the global config so the handler can read the
// SessionTTLDefault / SessionTTLRememberMe knobs that drive the
// falcon_idp_session cookie Max-Age (see establishIdpSession /
// idpSessionCookieMaxAge). Optional — handler stays functional with
// legacy hardcoded defaults when unset.
func (h *AuthHandler) SetConfig(cfg *config.Config) {
	h.config = cfg
}

// SetMFAEnrollmentService wires the registration-interrupt enrollment service.
// Drives /api/v1/auth/mfa/enrollment/{init,verify} — the unauthenticated
// enrollment endpoints used when risk-based MFA fires for a user without
// an enrolled authenticator.
func (h *AuthHandler) SetMFAEnrollmentService(svc *services.MFAEnrollmentService) {
	h.mfaEnrollmentSvc = svc
}

// SetDPoPMiddleware wires RFC 9449 issue-side enforcement. When set, Login
// and Refresh extract + validate the DPoP proof on the incoming request
// and pass the resulting JWK thumbprint to the token service via context,
// causing the issued access token to carry `cnf.jkt` and be sender-
// constrained to that key. No-op when nil (plain bearer-token issuance).
func (h *AuthHandler) SetDPoPMiddleware(mw *middleware.DPoPMiddleware) {
	h.dpop = mw
}

// SetSessionCache wires the Redis session cache used by /api/v1/auth/login to
// establish the IdP-level SSO session (`falcon_idp_session` cookie). Without
// it, a successful login still issues access/refresh tokens but the next
// /oauth/authorize will not see an SSO session and will bounce the browser
// back to /login. Mirrors OAuthProviderHandler.SetSessionCache.
func (h *AuthHandler) SetSessionCache(cache *redispkg.SessionCache) {
	h.sessionCache = cache
}

// SetTokenBlacklist wires the Redis token blacklist used by /api/v1/auth/logout
// to revoke the calling session at the validation layer. Without it, the
// access-token JWT in `falcon_access_token` survives the cookie clear (15-min
// TTL) and silent-SSOs the next /oauth/authorize call, closing the logout loop
// (production trace 2026-04-28: accounts.example.com Sign Out → /home).
//
// Session-scoped (not user-scoped) so that an immediate re-login still works:
// the new session has a new ID and is not in the blacklist. The user-scoped
// IsUserBlacklisted primitive is a flat-key existence check with no
// issued-before-T semantics — using it here would lock the user out of
// re-login for the TTL window.
func (h *AuthHandler) SetTokenBlacklist(blacklist *redispkg.TokenBlacklist) {
	h.tokenBlacklist = blacklist
}

// SetSessionRepository wires the session repository so /api/v1/auth/logout
// can fan-out the session-blacklist write across every active session for
// the user when the calling JWT has no `sid` claim. OAuth Bearer-token
// logout is the path that needs this — RP access tokens (e.g. issued to
// accounts.example.com) carry sub/aud/scope but not the IdP session ID.
// Without the fan-out, the per-session BlacklistSession in Logout is
// skipped on the Bearer path and the still-valid `falcon_access_token`
// JWT cookie silent-SSOs the next /oauth/authorize.
func (h *AuthHandler) SetSessionRepository(repo SessionRepository) {
	h.sessionRepo = repo
}

// SetLoginResponseCookies writes the HttpOnly access-token cookie + the
// falcon_idp_session SSO cookie (and its Redis-backed IdpSessionData
// entry) for any handler that produced a LoginResponse. Exported so
// WebAuthn / SSO / SAML completion handlers can avoid duplicating the
// cookie ritual the password-login path performs inline at Login().
//
// Without this call, the LoginResponse JSON is returned to the browser
// but no cookies are set, so the subsequent navigation back through
// /oauth/authorize sees no session → bounces to /oauth/login → infinite
// loop. Live repro 2026-05-25: passkey login on iOS Safari completed
// /webauthn/conditional/complete with a fresh LoginResponse but the
// very next /oauth/authorize bounced because neither falcon_access_token
// nor falcon_idp_session had ever been set — handler returned plain JSON.
//
// No-op when AccessToken is empty (e.g. requires_mfa intermediate response).
func (h *AuthHandler) SetLoginResponseCookies(c *gin.Context, response *models.LoginResponse) {
	if response == nil || response.AccessToken == "" {
		return
	}
	accessTTL := defaultAccessTokenTTL
	if response.ExpiresIn > 0 {
		accessTTL = time.Duration(response.ExpiresIn) * time.Second
	}
	setAuthCookies(c, response.AccessToken, accessTTL)
	h.establishIdpSession(c, response.User, h.sessionIDFromAccessToken(response.AccessToken), response.IsRememberMeSession)
}

// sessionIDFromAccessToken extracts the session_id claim out of an
// access token we just minted. We don't re-validate the signature
// because we just signed the JWT ourselves; the goal is to surface
// the UUID we already wrote into the claim, NOT to admit unsigned
// tokens. Returns uuid.Nil if the token is malformed or absent —
// callers degrade to "no SessionID in IdP session", which only
// breaks downstream MFA-step-up writes for that login.
func (h *AuthHandler) sessionIDFromAccessToken(accessToken string) uuid.UUID {
	if accessToken == "" || h.tokenService == nil {
		return uuid.Nil
	}
	claims, err := h.tokenService.ValidateAccessToken(accessToken)
	if err != nil || claims == nil {
		return uuid.Nil
	}
	return claims.SessionID
}

// idpSessionDefaultMaxAge is the cookie Max-Age applied to
// falcon_idp_session when "Remember me" was NOT requested. 7 days
// matches the prior hardcoded value (preserves pre-feature behaviour)
// AND the legacy /oauth/login form-submit's hardcoded value, so a
// single cookie schema continues to work whether SSO is established
// via the universal-login API path or the legacy form. Operators
// MAY shorten this via SESSION_TTL_DEFAULT to align it with the DB
// session row (see Config.SessionTTLDefault). The cookie is not a fixed
// deadline: resolveIdpSessionCookie re-issues it with a fresh Max-Age on each
// silent /oauth/authorize, bounded by the absolute cap (AuthTime +
// SESSION_TTL_REMEMBER_ME, default 7d), so active SSO outlives this value.
const idpSessionDefaultMaxAge = 7 * 24 * time.Hour

// establishIdpSession persists an IdP SSO entry in Redis and writes
// the matching falcon_idp_session cookie on the response. Called from
// Login, CompleteMFALogin, WebAuthn login completion, SSO completion,
// and MFA enrollment completion paths after tokens have been issued.
// No-op when sessionCache is unwired or no user is on the response.
//
// sessionID is the iam_user_sessions.id row that AuthService created
// for this login — pulled from the access token's session_id claim by
// the caller. Storing it in IdpSessionData lets cookie-only auth
// (resolveIdpSessionCookie) populate the canonical iam_user_sessions.id
// in the gin context, which downstream code (MFAHandler step-up,
// SessionActivityTracker, etc.) keys on. Pass uuid.Nil when not known
// (legacy non-cookie flows); callers that DO know it MUST pass it or
// MFA step-up will silently no-op.
//
// Cookie attributes mirror oauth_provider_handler.go's HandleLogin
// branch (HttpOnly, Secure in prod, SameSite=Strict in prod / Lax in
// dev) so a single cookie schema continues to work whether SSO is
// established via the universal-login API path or the legacy
// /oauth/login form.
//
// rememberMe bifurcates the cookie Max-Age:
//
//   - false → Max-Age = SessionTTLDefault (falls back to 7d, matching
//     pre-feature behaviour). The cookie is browser-restart-persistent
//     for the configured short TTL, mirroring how every other IdP
//     ships their default. NOTE: "browser session cookie" (Max-Age
//     omitted entirely) would clear on close, but that breaks the
//     refresh-token / OIDC silent-SSO flow because closing one tab
//     would log the user out of every RP. The default short TTL with
//     an explicit Max-Age is the canonical Auth0 / Microsoft Entra
//     compromise — set Max-Age, but keep it relatively short.
//
//   - true → Max-Age = SessionTTLRememberMe (default 30d). The cookie
//     survives browser restarts for the full remember-me window,
//     keeping browser cookie expiry in lock-step with the
//     iam_sessions.expires_at horizon set by AuthService.createSession.
//     A long DB row with a short cookie would silently re-prompt; a
//     short DB row with a long cookie would 401 on the next /oauth/
//     authorize bounce. They must match.
func (h *AuthHandler) establishIdpSession(c *gin.Context, user *models.UserResponse, sessionID uuid.UUID, rememberMe bool, proofTime ...int64) {
	if h.sessionCache == nil || user == nil {
		return
	}
	idpSessionID := uuid.New()
	authTime := time.Now().Unix()
	if len(proofTime) > 0 && proofTime[0] > 0 && proofTime[0] <= authTime {
		authTime = proofTime[0]
	}
	if err := h.sessionCache.SetIdpSession(c.Request.Context(), idpSessionID, &redispkg.IdpSessionData{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Username:  user.Username,
		Email:     user.Email,
		AuthTime:  authTime,
		SessionID: sessionID,
	}); err != nil {
		// Non-fatal: tokens already minted; SSO degrades to re-prompt on
		// the next /oauth/authorize rather than failing the whole flow.
		logger.Log.Warn("failed to store IdP session in Redis", zap.Error(err))
		return
	}
	// Attributes (incl. SameSite=Lax, d-254/t-520) live in
	// middleware.SetIdpSessionCookie, shared with the sliding re-issue.
	middleware.SetIdpSessionCookie(c, idpSessionID.String(), h.idpSessionCookieMaxAge(rememberMe))
}

// idpSessionCookieMaxAge resolves the falcon_idp_session cookie
// Max-Age. Reads from h.config when available; falls back to the
// legacy hardcoded constants otherwise so the handler stays usable in
// test wiring that doesn't inject a config (e.g. existing handler
// tests that pre-date the remember-me feature). See establishIdpSession
// for the contract.
func (h *AuthHandler) idpSessionCookieMaxAge(rememberMe bool) time.Duration {
	if rememberMe {
		if h.config != nil && h.config.SessionTTLRememberMe > 0 {
			return h.config.SessionTTLRememberMe
		}
		return 30 * 24 * time.Hour
	}
	if h.config != nil && h.config.SessionTTLDefault > 0 {
		return h.config.SessionTTLDefault
	}
	return idpSessionDefaultMaxAge
}

// SetIdpRepository sets the identity provider repository (called after initialization)
func (h *AuthHandler) SetIdpRepository(repo IdpRepository) {
	h.idpRepo = repo
}

// SetCSRFMiddleware sets the CSRF middleware (called after initialization)
func (h *AuthHandler) SetCSRFMiddleware(middleware CSRFMiddleware) {
	h.csrfMiddleware = middleware
}

// SetIDPRoutingService is an exported identifier.
// SetIDPRoutingService sets the IDP routing service for email-domain-based discovery.
func (h *AuthHandler) SetIDPRoutingService(svc *services.IDPRoutingService) {
	h.idpRoutingService = svc
}

// SetAppIDPService is an exported identifier.
// SetAppIDPService sets the per-app IDP enablement service for filtering providers.
func (h *AuthHandler) SetAppIDPService(svc *services.AppIdentityProviderService) {
	h.appIDPService = svc
}

// SetTenantLookup sets the tenant lookup for resolving slugs on public endpoints.
func (h *AuthHandler) SetTenantLookup(lookup TenantLookup) {
	h.tenantLookup = lookup
}

// SocialProviderPublicInfo is a minimal response for public social provider listing
type SocialProviderPublicInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// GetEnabledSocialProviders returns enabled social login providers for the login screen.
// Accepts optional `application_id` query param to filter by per-app IDP enablement.
// @Summary Get Enabled Social Providers
// @Description Get list of enabled social login providers (Google, Microsoft, GitHub, etc.) for the login screen
// @Tags Auth
// @Produce json
// @Param application_id query string false "Application ID to filter IDPs"
// @Success 200 {object} map[string][]SocialProviderPublicInfo
// @Router /api/v1/auth/social-providers [get]
func (h *AuthHandler) GetEnabledSocialProviders(c *gin.Context) {
	if h.idpRepo == nil {
		c.JSON(http.StatusOK, gin.H{"providers": []SocialProviderPublicInfo{}})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		tenantID = models.WellKnownTenantDefaultID
	}

	realmID := getRealmIDFromContext(c)
	providers, err := h.idpRepo.GetEnabledSocialProviders(c.Request.Context(), tenantID, realmID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"providers": []SocialProviderPublicInfo{}})
		return
	}

	providers = h.filterProvidersByApp(c, providers)

	publicProviders := toSocialProviderPublicInfoList(providers)
	c.JSON(http.StatusOK, gin.H{"providers": publicProviders})
}

// filterProvidersByApp filters the provider list to only those enabled for a specific application,
// when the application_id query parameter is present and the appIDPService is configured.
func (h *AuthHandler) filterProvidersByApp(c *gin.Context, providers []*models.IdentityProvider) []*models.IdentityProvider {
	appIDStr := c.Query("application_id")
	if appIDStr == "" || h.appIDPService == nil {
		return providers
	}
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return providers
	}
	enabledIDs, err := h.appIDPService.GetEnabledIDPIDs(c.Request.Context(), appID)
	if err != nil || len(enabledIDs) == 0 {
		return providers
	}
	enabledSet := make(map[uuid.UUID]struct{}, len(enabledIDs))
	for _, id := range enabledIDs {
		enabledSet[id] = struct{}{}
	}
	filtered := make([]*models.IdentityProvider, 0, len(providers))
	for _, p := range providers {
		if _, ok := enabledSet[p.ID]; ok {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// toSocialProviderPublicInfoList converts a slice of IdentityProviders to public info structs.
func toSocialProviderPublicInfoList(providers []*models.IdentityProvider) []SocialProviderPublicInfo {
	out := make([]SocialProviderPublicInfo, 0, len(providers))
	for _, p := range providers {
		out = append(out, SocialProviderPublicInfo{
			ID:          p.ID.String(),
			Type:        p.Type,
			Name:        p.Name,
			DisplayName: p.DisplayName,
		})
	}
	return out
}

// DiscoverIDP is an exported identifier.
// DiscoverIDP resolves which IDP should handle authentication for a given email address.
// POST /auth/discover-idp
func (h *AuthHandler) DiscoverIDP(c *gin.Context) {
	var req models.DiscoverIDPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.idpRoutingService == nil {
		c.JSON(http.StatusOK, gin.H{"matched": false, "provider": nil})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		tenantID = models.WellKnownTenantDefaultID
	}

	rule, err := h.idpRoutingService.ResolveIDPForEmail(c.Request.Context(), tenantID, req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if rule == nil {
		c.JSON(http.StatusOK, gin.H{"matched": false, "provider": nil})
		return
	}

	// If application_id provided, verify the resolved IDP is enabled for that app
	if req.ApplicationID != nil && h.appIDPService != nil {
		enabled, checkErr := h.appIDPService.IsIDPEnabledForApp(c.Request.Context(), *req.ApplicationID, rule.IdentityProviderID)
		if checkErr == nil && !enabled {
			c.JSON(http.StatusOK, gin.H{
				"matched":  false,
				"provider": nil,
				"reason":   "IdP matched by routing rule but not enabled for this application",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"matched": true,
		"provider": SocialProviderPublicInfo{
			ID:          rule.IdentityProviderID.String(),
			Type:        rule.ProviderType,
			Name:        rule.ProviderName,
			DisplayName: rule.ProviderDisplayName,
		},
	})
}

// LoginMethodPublicInfo is a minimal response for public login provider listing
type LoginMethodPublicInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// LoginMethodsResponse returns available authentication methods for a tenant
type LoginMethodsResponse struct {
	TenantID         string                  `json:"tenant_id"`
	LocalAuthEnabled bool                    `json:"local_auth_enabled"`
	SocialProviders  []LoginMethodPublicInfo `json:"social_providers"`
	SAMLProviders    []LoginMethodPublicInfo `json:"saml_providers"`
	LDAPProviders    []LoginMethodPublicInfo `json:"ldap_providers"`
}

// GetLoginMethods returns all available authentication methods for the login page.
// This is a public endpoint (no auth required).
// @Summary Get Login Methods
// @Description Get available authentication methods (social, SAML, LDAP) for the login screen
// @Tags Auth
// @Produce json
// @Success 200 {object} LoginMethodsResponse
// @Router /api/v1/auth/login-methods [get]
func (h *AuthHandler) GetLoginMethods(c *gin.Context) {
	fallback := LoginMethodsResponse{
		LocalAuthEnabled: true,
		SocialProviders:  []LoginMethodPublicInfo{},
		SAMLProviders:    []LoginMethodPublicInfo{},
		LDAPProviders:    []LoginMethodPublicInfo{},
	}

	if h.idpRepo == nil {
		c.JSON(http.StatusOK, fallback)
		return
	}

	tenantID := h.resolveLoginMethodsTenant(c)
	fallback.TenantID = tenantID.String()

	realmID := getRealmIDFromContext(c)
	providers, err := h.idpRepo.GetEnabledLoginProviders(c.Request.Context(), tenantID, realmID)
	if err != nil {
		c.JSON(http.StatusOK, fallback)
		return
	}

	resp := h.categorizeLoginProviders(tenantID, providers)
	c.JSON(http.StatusOK, resp)
}

// resolveLoginMethodsTenant resolves the tenant ID for the login methods endpoint
// using the priority: middleware context > X-Tenant-Slug header > default.
func (h *AuthHandler) resolveLoginMethodsTenant(c *gin.Context) uuid.UUID {
	tenantID := middleware.GetTenantID(c)
	if tenantID != uuid.Nil {
		return tenantID
	}
	if slug := c.GetHeader("X-Tenant-Slug"); slug != "" && h.tenantLookup != nil {
		if tenant, err := h.tenantLookup.GetBySlug(c.Request.Context(), slug); err == nil && tenant != nil {
			return tenant.ID
		}
	}
	return models.WellKnownTenantDefaultID
}

// categorizeLoginProviders sorts providers into social, SAML, and LDAP buckets.
func (h *AuthHandler) categorizeLoginProviders(tenantID uuid.UUID, providers []*models.IdentityProvider) LoginMethodsResponse {
	socialTypes := map[string]bool{
		"google": true, "microsoft": true, "github": true,
		"oauth": true, "oidc": true, "apple": true,
	}
	resp := LoginMethodsResponse{
		TenantID:         tenantID.String(),
		LocalAuthEnabled: true,
		SocialProviders:  []LoginMethodPublicInfo{},
		SAMLProviders:    []LoginMethodPublicInfo{},
		LDAPProviders:    []LoginMethodPublicInfo{},
	}
	for _, p := range providers {
		info := LoginMethodPublicInfo{
			ID:          p.ID.String(),
			Type:        p.Type,
			Name:        p.Name,
			DisplayName: p.DisplayName,
		}
		switch {
		case socialTypes[p.Type]:
			resp.SocialProviders = append(resp.SocialProviders, info)
		case p.Type == "saml":
			resp.SAMLProviders = append(resp.SAMLProviders, info)
		case p.Type == idpTypeLDAP:
			resp.LDAPProviders = append(resp.LDAPProviders, info)
			if p.LDAPConfig != nil && p.LDAPConfig.DisableLocalAuth {
				resp.LocalAuthEnabled = false
			}
		}
	}
	return resp
}

// Login handles user authentication
// @Summary Login
// @Description Authenticate user with username and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	resolveLoginTenantContext(c, &req)
	resolveLoginRealmContext(c, &req)

	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)

	// DPoP issue-side binding (RFC 9449): validate proof + stash JKT on
	// context so the token generators embed cnf.jkt in the issued token.
	ctx := c.Request.Context()
	if h.dpop != nil {
		var ok bool
		if ctx, ok = h.dpop.BindJKTOnRequest(c); !ok {
			return
		}
	}

	// Stamp the originating client country (Cloudflare CF-IPCountry) onto
	// the request context AFTER any other context derivations so downstream
	// services (buildRiskContext → iam_login_risk_events.location,
	// createSession → iam_sessions.location) can read it via
	// clientctx.CountryFromContext without inflating every signature in
	// the auth chain.
	ctx = clientctx.WithCountry(ctx, middleware.ClientCountryGin(c))

	// Edge-stamped geo enrichment (asn / asn_org / city / region /
	// is_vpn_hint) sourced from the geo-stamp Cloudflare
	// Worker via X-Geo-* request headers. Stamped alongside the
	// country code so createSession can read both from one ctx walk.
	// Zero-value (Worker not deployed / route not under its pattern)
	// is a no-op — see clientctx.WithGeo.
	if g := middleware.ClientGeoGin(c); g != (middleware.IPGeo{}) {
		ctx = clientctx.WithGeo(ctx, clientctx.Geo{
			ASN:        g.ASN,
			ASNOrg:     g.ASNOrg,
			City:       g.City,
			Region:     g.Region,
			RegionCode: g.RegionCode,
			Country:    g.Country,
			Continent:  g.Continent,
			Timezone:   g.Timezone,
			Latitude:   g.Latitude,
			Longitude:  g.Longitude,
			Colo:       g.Colo,
			IsVPNHint:  g.IsVPNHint,
		})
	}

	response, err := h.authService.Login(ctx, &req, ipAddress, userAgent)
	if err != nil {
		if errors.Is(err, services.ErrMFAUnavailable) {
			respondMFAFlowError(c, err)
			return
		}
		if respondIfTenantSuspended(c, err) {
			return
		}
		logger.SecurityAudit.Warn("Security audit: failed login attempt",
			zap.String("event", "auth.login.failed"),
			zap.String("username", req.Username),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		// Discriminated error: surface account-locked as its own typed
		// response so the login UI can render a countdown / "wait
		// until X to retry" card instead of the generic "invalid
		// credentials" toast. Pre-fix the only signal was an opaque
		// 401 — users hammered the form, extending the lockout, and
		// procurement reviewers flagged "no self-service unlock UI"
		// as a P0 gap. The body field names (`error`, `locked_until`,
		// `lock_reason`, `retry_after_seconds`) match the shape that
		// `apps/login` consumes via the LoginApiClient contract.
		var lockedErr *services.AccountLockedError
		if errors.As(err, &lockedErr) {
			body := gin.H{
				"error":             "account_locked",
				"error_description": "Account is temporarily locked due to security policy",
			}
			if lockedErr.LockedUntil != nil {
				body["locked_until"] = lockedErr.LockedUntil.UTC().Format(time.RFC3339)
			}
			if lockedErr.LockReason != nil {
				body["lock_reason"] = *lockedErr.LockReason
			}
			if retry := lockedErr.RetryAfterSeconds(); retry > 0 {
				body["retry_after_seconds"] = retry
				// RFC 7231 §7.1.3 — Retry-After tells well-behaved
				// HTTP clients (curl, fetch hooks, monitoring probes)
				// when to retry without needing to parse the body.
				c.Header("Retry-After", fmt.Sprintf("%d", retry))
			}
			// 423 Locked is the RFC 4918 §11.3 semantically-precise
			// code for this state. Some tooling that whitelists
			// 401/403 may not handle 423 — clients SHOULD dispatch on
			// the `error` body field, not the HTTP code.
			c.JSON(http.StatusLocked, body)
			return
		}
		// SECURITY / UX tradeoff (2026-09-18 incident follow-up): this body
		// is deliberately IDENTICAL for every login-credential failure —
		// wrong password, unknown username, AND "no local password set"
		// (services/auth_credentials_service.go's authenticateLocal,
		// which logs that distinct reason server-side only, see its doc
		// comment). A response that varied by reason — e.g. a distinct
		// "this account has no password" message — would let an attacker
		// enumerate which usernames exist and are missing a local
		// credential, which is exactly the kind of account-existence
		// oracle constant-time password verification above already
		// exists to prevent. Instead the actionable hint ("use Forgot
		// password") is folded into the SAME generic message so it helps
		// the "no local password set" case (a real, if rare, account
		// state — see the CompleteSignup doc comments for how a signup
		// could reach it) without adding a new discriminator: a user with
		// a merely-wrong password gets equally correct, equally
		// actionable advice, and an attacker probing arbitrary usernames
		// learns nothing they couldn't learn before. Password reset
		// (PasswordResetService.ResetPassword) does not require an
		// existing password_hash, so this path genuinely unblocks the
		// affected accounts rather than sending them into a second dead
		// end.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password. If this is a new account, use \"Forgot password\" to set one."})
		return
	}

	if isTenantIsolationViolation(req.TenantSlug, response) {
		logger.SecurityAudit.Warn("Security audit: tenant isolation violation at login",
			zap.String("event", "auth.login.tenant_violation"),
			zap.String("username", req.Username),
			zap.String("ip", ipAddress),
			zap.String("claimed_tenant", req.TenantSlug),
			zap.String("actual_tenant", response.User.TenantSlug),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if response.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if response.ExpiresIn > 0 {
			accessTTL = time.Duration(response.ExpiresIn) * time.Second
		}
		setAuthCookies(c, response.AccessToken, accessTTL)
		h.establishIdpSession(c, response.User, h.sessionIDFromAccessToken(response.AccessToken), response.IsRememberMeSession)
	}

	if response.User != nil {
		logger.SecurityAudit.Info("Security audit: successful login",
			zap.String("event", "auth.login.success"),
			zap.String("username", response.User.Username),
			zap.String("user_id", response.User.ID.String()),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.Time("timestamp", time.Now().UTC()),
		)
	}

	c.JSON(http.StatusOK, response)
}

// resolveLoginTenantContext fills in tenant information on the login request
// from headers or middleware when it is absent from the request body.
func resolveLoginTenantContext(c *gin.Context, req *models.LoginRequest) {
	if req.TenantSlug == "" {
		if slug := c.GetHeader("X-Tenant-Slug"); slug != "" {
			req.TenantSlug = slug
		}
	}
	if req.TenantID == "" && req.TenantSlug == "" {
		if tid := middleware.GetTenantID(c); tid != uuid.Nil {
			req.TenantID = tid.String()
		}
	}
}

// resolveLoginRealmContext fills in realm information on the login request from headers
// or middleware, following the priority: body > X-Realm-ID > X-Realm-Slug > middleware.
func resolveLoginRealmContext(c *gin.Context, req *models.LoginRequest) {
	if req.RealmID != "" {
		return
	}
	if realmIDStr := c.GetHeader("X-Realm-ID"); realmIDStr != "" {
		req.RealmID = realmIDStr
		return
	}
	if realmSlug := c.GetHeader("X-Realm-Slug"); realmSlug != "" {
		req.RealmID = "slug:" + realmSlug
		return
	}
	if realmID := middleware.GetCurrentRealmID(c); realmID != nil {
		req.RealmID = realmID.String()
	}
}

// isTenantIsolationViolation returns true when the claimed tenant slug does not
// match the tenant recorded on the authenticated user.
func isTenantIsolationViolation(claimedSlug string, response *models.LoginResponse) bool {
	if claimedSlug == "" || response.User == nil {
		return false
	}
	userTenant := response.User.TenantSlug
	return userTenant != "" && userTenant != claimedSlug
}

// CompleteMFALogin completes MFA verification using a session ID (no password re-send)
// @Summary Complete MFA Login
// @Description Verifies MFA code using session ID and returns tokens (password-free)
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.MFACompleteRequest true "MFA completion request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/complete [post]
func (h *AuthHandler) CompleteMFALogin(c *gin.Context) {
	var req models.MFACompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)

	// DPoP issue-side binding (RFC 9449) on the MFA completion path —
	// this is where tokens are actually minted for MFA-gated logins.
	ctx := c.Request.Context()
	if h.dpop != nil {
		var ok bool
		if ctx, ok = h.dpop.BindJKTOnRequest(c); !ok {
			return
		}
	}

	response, err := h.authService.CompleteMFALogin(ctx, &req, ipAddress, userAgent)
	if err != nil {
		if respondIfTenantSuspended(c, err) {
			return
		}
		// Security audit: MFA verification failure
		logger.SecurityAudit.Warn("Security audit: MFA verification failed",
			zap.String("event", "auth.mfa.failed"),
			zap.String("session_id", req.SessionID),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		respondMFAFlowError(c, err)
		return
	}

	// Set HttpOnly cookie for access token
	if response.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if response.ExpiresIn > 0 {
			accessTTL = time.Duration(response.ExpiresIn) * time.Second
		}
		setAuthCookies(c, response.AccessToken, accessTTL)
		// A retry reissues cookies, not a new MFA proof. Keep the original
		// authentication timestamp rather than extending the fresh-auth window.
		proofTime := int64(0)
		if h.tokenService != nil {
			if claims, err := h.tokenService.ValidateAccessTokenWithContext(ctx, response.AccessToken); err == nil && claims != nil {
				proofTime = claims.AuthTime
			}
		}
		h.establishIdpSession(c, response.User, h.sessionIDFromAccessToken(response.AccessToken), response.IsRememberMeSession, proofTime)
	}

	// Security audit: MFA verification success
	if response.User != nil {
		logger.SecurityAudit.Info("Security audit: MFA verification succeeded",
			zap.String("event", "auth.mfa.success"),
			zap.String("username", response.User.Username),
			zap.String("user_id", response.User.ID.String()),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.Time("timestamp", time.Now().UTC()),
		)
	}

	// Authentication material travels in HttpOnly cookies. Do not serialize
	// UserResponse (including thousands of permissions/avatar data) again.
	writeMFACompletionResponse(c, response)
}

// MFAEnrollmentInit handles the first leg of the registration-interrupt
// enrollment flow. The unauthenticated enrollment UI (id.example.com login
// app) calls this endpoint with the enrollment_token returned by the
// preceding /api/v1/auth/login response and the chosen method (totp or
// email). For TOTP it returns the QR code + manual-entry secret; for email
// it triggers a one-time code delivery to the user's on-file mailbox. Idempotent
// within the 10-minute enrollment-token TTL — the user may re-pick a method.
//
// Auth model: gated by the enrollment_token alone (ip + ua-hash bound). No
// Bearer token, no session cookie, no CSRF token — the enrollment_token
// itself is the unguessable single-use credential. Rate-limited identically
// to /api/v1/auth/login (anti-brute-force on the token).
//
// @Summary Initialise MFA enrollment (registration-interrupt)
// @Description Returns TOTP setup material or sends an email code for the chosen method
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.MFAEnrollmentInitRequest true "Enrollment init request"
// @Success 200 {object} models.MFAEnrollmentInitResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/enrollment/init [post]
func (h *AuthHandler) MFAEnrollmentInit(c *gin.Context) {
	if h.mfaEnrollmentSvc == nil {
		metrics.MFAEnrollmentFailed.WithLabelValues("init", "unknown", "service_unavailable").Inc()
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "MFA enrollment service unavailable"})
		return
	}
	var req models.MFAEnrollmentInitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		metrics.MFAEnrollmentFailed.WithLabelValues("init", "unknown", "bad_request").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)
	ctx := c.Request.Context()

	sess, err := h.mfaEnrollmentSvc.LookupSession(ctx, req.EnrollmentToken, ipAddress, userAgent)
	if err != nil {
		metrics.MFAEnrollmentFailed.WithLabelValues("init", req.Method, "expired_or_invalid_token").Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Enrollment token expired or invalid"})
		return
	}

	switch req.Method {
	case "totp":
		setup, terr := h.mfaEnrollmentSvc.InitTOTP(ctx, sess)
		if terr != nil {
			logger.SecurityAudit.Warn("Security audit: MFA enrollment init failed",
				zap.String("event", "auth.mfa.enrollment_init_failed"),
				zap.String("user_id", sess.UserID),
				zap.String("method", "totp"),
				zap.String("ip", ipAddress),
				zap.String("reason", terr.Error()),
				zap.Time("timestamp", time.Now().UTC()),
			)
			metrics.MFAEnrollmentFailed.WithLabelValues("init", "totp", "internal_error").Inc()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialise TOTP enrollment"})
			return
		}
		metrics.MFAEnrollmentMethodPicked.WithLabelValues("totp").Inc()
		c.JSON(http.StatusOK, models.MFAEnrollmentInitResponse{
			Method:      "totp",
			Secret:      setup.Secret,
			QRCode:      setup.QRCode,
			ManualEntry: setup.ManualEntry,
			ExpiresIn:   600,
		})
	case "email":
		if err := h.mfaEnrollmentSvc.InitEmail(ctx, sess); err != nil {
			logger.SecurityAudit.Warn("Security audit: MFA enrollment init failed",
				zap.String("event", "auth.mfa.enrollment_init_failed"),
				zap.String("user_id", sess.UserID),
				zap.String("method", "email"),
				zap.String("ip", ipAddress),
				zap.String("reason", err.Error()),
				zap.Time("timestamp", time.Now().UTC()),
			)
			metrics.MFAEnrollmentFailed.WithLabelValues("init", "email", "internal_error").Inc()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send enrollment email code"})
			return
		}
		metrics.MFAEnrollmentMethodPicked.WithLabelValues("email").Inc()
		c.JSON(http.StatusOK, models.MFAEnrollmentInitResponse{
			Method:    "email",
			Message:   "A verification code has been sent to your registered email address.",
			ExpiresIn: 600,
		})
	default:
		metrics.MFAEnrollmentFailed.WithLabelValues("init", req.Method, "unsupported_method").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported enrollment method"})
	}
}

// MFAEnrollmentVerify completes the registration-interrupt enrollment.
// Validates the user-entered code via MFAEnrollmentService (which flips the
// user's MFA flags), then mints a normal session + access/refresh tokens via
// AuthService.IssueSessionAfterEnrollment so the BFF can plumb cookies +
// redirect_url uniformly with /auth/mfa/complete. On success the original
// /oauth/authorize continuation that triggered the login can resume — the
// browser will silent-SSO the now-authenticated session through to the RP.
//
// Auth model: gated by the enrollment_token alone (ip + ua-hash bound +
// single-use on success). Same rate-limit envelope as /auth/login.
//
// AMR on the issued session: ["pwd","otp"] for TOTP enrollment or
// ["pwd","mfa"] for email enrollment — matches CompleteMFALogin so RP-side
// AMR consumption stays consistent. The enrollment-completion event is
// captured separately (auth.mfa.enrollment_completed) for SIEM/audit.
//
// @Summary Complete MFA enrollment + issue session (registration-interrupt)
// @Description Verifies the code, binds the authenticator, and returns a normal LoginResponse with backup codes
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.MFAEnrollmentVerifyRequest true "Enrollment verify request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/enrollment/verify [post]
func (h *AuthHandler) MFAEnrollmentVerify(c *gin.Context) {
	if h.mfaEnrollmentSvc == nil {
		metrics.MFAEnrollmentFailed.WithLabelValues("verify", "unknown", "service_unavailable").Inc()
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "MFA enrollment service unavailable"})
		return
	}
	var req models.MFAEnrollmentVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		metrics.MFAEnrollmentFailed.WithLabelValues("verify", "unknown", "bad_request").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)

	// DPoP issue-side binding — same model as CompleteMFALogin since this is
	// also a token-issuance endpoint. No-op when DPoP isn't enabled.
	ctx := c.Request.Context()
	if h.dpop != nil {
		var ok bool
		if ctx, ok = h.dpop.BindJKTOnRequest(c); !ok {
			return
		}
	}

	verifyStart := time.Now()

	sess, err := h.mfaEnrollmentSvc.LookupSession(ctx, req.EnrollmentToken, ipAddress, userAgent)
	if err != nil {
		metrics.MFAEnrollmentFailed.WithLabelValues("verify", req.Method, "expired_or_invalid_token").Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Enrollment token expired or invalid"})
		return
	}

	var (
		backupCodes []string
		amr         []string
		verifyErr   error
	)
	switch req.Method {
	case "totp":
		backupCodes, verifyErr = h.mfaEnrollmentSvc.VerifyTOTP(ctx, sess, req.EnrollmentToken, req.Code)
		amr = []string{"pwd", "otp"}
	case "email":
		backupCodes, verifyErr = h.mfaEnrollmentSvc.VerifyEmail(ctx, sess, req.EnrollmentToken, req.Code)
		amr = []string{"pwd", "mfa"}
	default:
		metrics.MFAEnrollmentFailed.WithLabelValues("verify", req.Method, "unsupported_method").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported enrollment method"})
		return
	}

	if verifyErr != nil {
		logger.SecurityAudit.Warn("Security audit: MFA enrollment verification failed",
			zap.String("event", "auth.mfa.enrollment_verify_failed"),
			zap.String("user_id", sess.UserID),
			zap.String("method", req.Method),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.String("reason", verifyErr.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		metrics.MFAEnrollmentFailed.WithLabelValues("verify", req.Method, "invalid_code").Inc()
		metrics.MFAEnrollmentDuration.WithLabelValues(req.Method, "failed").Observe(time.Since(verifyStart).Seconds())
		c.JSON(http.StatusBadRequest, gin.H{"error": verifyErr.Error()})
		return
	}

	response, err := h.authService.IssueSessionAfterEnrollment(ctx, sess, amr, req.RememberMe, req.DeviceID, ipAddress, userAgent)
	if err != nil {
		logger.SecurityAudit.Error("Security audit: MFA enrollment session issuance failed",
			zap.String("event", "auth.mfa.enrollment_session_failed"),
			zap.String("user_id", sess.UserID),
			zap.String("ip", ipAddress),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		metrics.MFAEnrollmentFailed.WithLabelValues("verify", req.Method, "session_issuance_failed").Inc()
		metrics.MFAEnrollmentDuration.WithLabelValues(req.Method, "failed").Observe(time.Since(verifyStart).Seconds())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue session after enrollment"})
		return
	}

	// Successful enrollment.
	metrics.MFAEnrollmentCompleted.WithLabelValues(req.Method).Inc()
	metrics.MFAEnrollmentDuration.WithLabelValues(req.Method, "completed").Observe(time.Since(verifyStart).Seconds())

	if response.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if response.ExpiresIn > 0 {
			accessTTL = time.Duration(response.ExpiresIn) * time.Second
		}
		setAuthCookies(c, response.AccessToken, accessTTL)
		h.establishIdpSession(c, response.User, h.sessionIDFromAccessToken(response.AccessToken), response.IsRememberMeSession)
	}

	if response.User != nil {
		logger.SecurityAudit.Info("Security audit: MFA enrollment session issued",
			zap.String("event", "auth.mfa.enrollment_session_issued"),
			zap.String("username", response.User.Username),
			zap.String("user_id", response.User.ID.String()),
			zap.String("method", req.Method),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.Time("timestamp", time.Now().UTC()),
		)
	}

	// Backup codes are surfaced ONCE in the response so the user can stash
	// them — they're hashed at rest (mfa_service.go:546) so we cannot show
	// them again. UI must display + offer download here.
	c.JSON(http.StatusOK, gin.H{
		"login":        response,
		"backup_codes": backupCodes,
	})
}

// MFAEnrollmentSkip completes the "Remind me later" path on the
// registration-interrupt enrollment flow. Only callable when the
// realm's mfa_grace_period_days > 0 AND mfa_enrollment_max_skips > 0
// — otherwise the service-side budget check rejects with 401. On
// success, consumes the enrollment_token, increments the user's
// skip_count, and issues a normal LoginResponse (cookies + access
// token + redirect-uniform shape — same as MFAEnrollmentVerify so the
// BFF doesn't need a separate code path).
//
// Trade-off (audit-visible): the issued session records AMR ["pwd"]
// only — the user is explicitly deferring MFA during the grace window.
// SIEM should pivot on auth.mfa.enrollment_skipped events to track
// accumulated skips per user/tenant.
//
// CSRF: same skip-list as /init/verify (pre-auth route, no IdP session
// yet; enrollment_token's ip+ua binding is the canonical
// anti-CSRF replacement — OWASP-approved pattern, see
// operational notes).
//
// @Summary Skip MFA enrollment ("Remind me later") during grace period
// @Description Defers enrollment within the realm's configured grace window; issues a normal session at AMR=["pwd"]
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.MFAEnrollmentSkipRequest true "Enrollment skip request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/v1/auth/mfa/enrollment/skip [post]
func (h *AuthHandler) MFAEnrollmentSkip(c *gin.Context) {
	if h.mfaEnrollmentSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "MFA enrollment service unavailable"})
		return
	}
	var req models.MFAEnrollmentSkipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)
	ctx := c.Request.Context()

	// DPoP issue-side binding — same as MFAEnrollmentVerify since this
	// is also a token-issuance endpoint.
	if h.dpop != nil {
		var ok bool
		if ctx, ok = h.dpop.BindJKTOnRequest(c); !ok {
			return
		}
	}

	sess, err := h.mfaEnrollmentSvc.LookupSession(ctx, req.EnrollmentToken, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Enrollment token expired or invalid"})
		return
	}

	resp, err := h.authService.SkipMFAEnrollment(ctx, sess, req.EnrollmentToken, ipAddress, userAgent, req.RememberMe, req.DeviceID)
	if err != nil {
		// Audit log fires inside the service. Map the error to 401 so
		// the frontend re-renders the hard-block UI without leaking
		// which sub-gate fired (deadline vs budget vs realm-policy
		// disabled). That's intentional — defense-in-depth against an
		// attacker probing the skip budget.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Skip not permitted"})
		return
	}

	if resp.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if resp.ExpiresIn > 0 {
			accessTTL = time.Duration(resp.ExpiresIn) * time.Second
		}
		setAuthCookies(c, resp.AccessToken, accessTTL)
		h.establishIdpSession(c, resp.User, h.sessionIDFromAccessToken(resp.AccessToken), resp.IsRememberMeSession)
	}

	c.JSON(http.StatusOK, resp)
}

// MFAEnrollmentWebAuthnBeginRequest is the body for
// POST /api/v1/auth/mfa/enrollment/webauthn/begin. Sent during the
// admin-passkey-required interrupt flow to start a FIDO2 registration
// ceremony from an enrollment_token (ip+ua-bound, 10-min TTL).
type MFAEnrollmentWebAuthnBeginRequest struct {
	EnrollmentToken string `json:"enrollment_token" binding:"required,min=1,max=255"`
	FriendlyName    string `json:"friendly_name" binding:"required,min=1,max=255"`
}

// MFAEnrollmentWebAuthnBegin starts a FIDO2 registration ceremony for an
// enrollment session whose user has been interrupted because they lack a
// passkey on a tenant where require_passkey_for_admin is enabled.
//
// Returns the W3C-shaped credential creation challenge plus a wa_session_id
// the client echoes back on /finish. This is identical to
// /webauthn/register/begin except the auth gate is the enrollment_token
// (not a logged-in session) — the enrollment_token's ip+ua binding makes
// it safe to expose pre-login.
//
// @Summary Begin WebAuthn enrollment from a registration-interrupt
// @Description Returns a passkey-registration challenge for an admin-required-passkey enrollment session
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body MFAEnrollmentWebAuthnBeginRequest true "Enrollment + friendly name"
// @Success 200 {object} services.RegistrationChallenge
// @Failure 401 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /api/v1/auth/mfa/enrollment/webauthn/begin [post]
func (h *AuthHandler) MFAEnrollmentWebAuthnBegin(c *gin.Context) {
	if h.mfaEnrollmentSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "MFA enrollment service unavailable"})
		return
	}
	var req MFAEnrollmentWebAuthnBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)
	ctx := c.Request.Context()

	sess, err := h.mfaEnrollmentSvc.LookupSession(ctx, req.EnrollmentToken, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Enrollment token expired or invalid"})
		return
	}
	challenge, err := h.mfaEnrollmentSvc.InitWebAuthn(ctx, sess, req.FriendlyName)
	if err != nil {
		logger.SecurityAudit.Warn("Security audit: WebAuthn enrollment init failed",
			zap.String("event", "auth.mfa.enrollment_init_failed"),
			zap.String("user_id", sess.UserID),
			zap.String("method", "webauthn"),
			zap.String("ip", ipAddress),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start passkey enrollment"})
		return
	}
	c.JSON(http.StatusOK, challenge)
}

// MFAEnrollmentWebAuthnFinish completes a passkey registration ceremony
// for an enrollment session and issues a normal LoginResponse.
//
// The body MUST be the verbatim W3C credential creation response from
// navigator.credentials.create() / @simplewebauthn/browser. Auxiliary
// parameters ride out-of-band:
//
//   - X-Enrollment-Token header: the ip+ua-bound interrupt token (auth)
//   - wa_session_id query: the ceremony correlator from /begin
//   - friendly_name query: the label for the new credential
//
// Auth tokens go in the header (not the URL) to keep them out of access
// logs and Referer chains. The wa_session_id is not authentication state
// — it's a ceremony correlator validated server-side against the stored
// SessionData challenge — so URL placement is fine.
//
// On success returns a LoginResponse with `amr=["hwk","user"]` so the
// downstream /oauth/authorize → /token flow emits `acr=urn:hexxlock:aal3`
// on derived id_tokens.
//
// @Summary Finish WebAuthn enrollment + issue session
// @Description Completes a passkey registration ceremony and mints a normal session
// @Tags Auth
// @Accept json
// @Produce json
// @Param X-Enrollment-Token header string true "Enrollment token from the registration interrupt"
// @Param wa_session_id query string true "WebAuthn ceremony id from /begin"
// @Param friendly_name query string true "Human-readable credential label"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 503 {object} map[string]string
// @Router /api/v1/auth/mfa/enrollment/webauthn/finish [post]
func (h *AuthHandler) MFAEnrollmentWebAuthnFinish(c *gin.Context) {
	if h.mfaEnrollmentSvc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "MFA enrollment service unavailable"})
		return
	}
	enrollmentToken := c.GetHeader("X-Enrollment-Token")
	if enrollmentToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Enrollment-Token header is required"})
		return
	}
	waSessionID := c.Query("wa_session_id")
	if waSessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wa_session_id is required"})
		return
	}
	friendlyName := c.Query("friendly_name")
	if friendlyName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "friendly_name is required"})
		return
	}
	ipAddress := middleware.RealClientIP(c)
	userAgent := c.GetHeader(hdrUserAgent)
	ctx := c.Request.Context()

	sess, err := h.mfaEnrollmentSvc.LookupSession(ctx, enrollmentToken, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Enrollment token expired or invalid"})
		return
	}
	amr, err := h.mfaEnrollmentSvc.VerifyWebAuthn(ctx, sess, enrollmentToken, waSessionID, friendlyName, models.DefaultAttestationPolicy(), c.Request)
	if err != nil {
		logger.SecurityAudit.Warn("Security audit: WebAuthn enrollment verification failed",
			zap.String("event", "auth.mfa.enrollment_verify_failed"),
			zap.String("user_id", sess.UserID),
			zap.String("method", "webauthn"),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Issue a normal session after enrollment. RememberMe / DeviceID don't
	// apply to passkey enrollment — the credential itself is the durable
	// trust anchor, no cookie-based device trust adds assurance.
	response, err := h.authService.IssueSessionAfterEnrollment(ctx, sess, amr, false, "", ipAddress, userAgent)
	if err != nil {
		logger.SecurityAudit.Error("Security audit: WebAuthn enrollment session issuance failed",
			zap.String("event", "auth.mfa.enrollment_session_failed"),
			zap.String("user_id", sess.UserID),
			zap.String("ip", ipAddress),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue session after enrollment"})
		return
	}
	if response.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if response.ExpiresIn > 0 {
			accessTTL = time.Duration(response.ExpiresIn) * time.Second
		}
		setAuthCookies(c, response.AccessToken, accessTTL)
		h.establishIdpSession(c, response.User, h.sessionIDFromAccessToken(response.AccessToken), response.IsRememberMeSession)
	}
	if response.User != nil {
		logger.SecurityAudit.Info("Security audit: WebAuthn enrollment session issued",
			zap.String("event", "auth.mfa.enrollment_session_issued"),
			zap.String("username", response.User.Username),
			zap.String("user_id", response.User.ID.String()),
			zap.String("method", "webauthn"),
			zap.String("ip", ipAddress),
			zap.String("user_agent", userAgent),
			zap.Time("timestamp", time.Now().UTC()),
		)
	}
	c.JSON(http.StatusOK, gin.H{"login": response})
}

// SwitchMFALoginMethod switches the MFA method during login using session ID
// @Summary Switch MFA Method
// @Description Switches the MFA method during login flow (e.g., TOTP to email)
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body models.SelectMFAMethodRequest true "Method switch request"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/mfa/switch-method [post]
func (h *AuthHandler) SwitchMFALoginMethod(c *gin.Context) {
	var req models.SelectMFAMethodRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	response, err := h.authService.SwitchMFALoginMethod(c.Request.Context(), req.SessionID, req.Method)
	if err != nil {
		respondMFAFlowError(c, err)
		return
	}

	c.JSON(http.StatusOK, response)
}

// Refresh handles token refresh
// @Summary Refresh Token
// @Description Refresh access token using refresh token
// @Tags Auth
// @Accept json
// @Produce json
// @Success 410 {object} map[string]string
// @Router /api/v1/auth/refresh [post]
//
// REMOVED in Phase 3 (2026-05-03). The auth-service refresh path was
// the wrong table for OIDC-flow users (see
// operational notes and the
// frontend!24/!25 + falcon-id!120 MR chain that fixed it). All BFF
// refresh now flows through `/oauth/token` `grant_type=refresh_token`
// (RFC 6749 §6, OIDC Core §12.1) against `iam_oauth_tokens`. The
// underlying `iam_refresh_tokens` table is dropped in migration 233.
//
// Returning 410 Gone with `Deprecation` + `Link` headers (RFC 8594
// `Sunset` is omitted because the deprecation is immediate, not
// scheduled) so any straggler client gets a deterministic failure
// pointing at the replacement endpoint instead of a confusing 401 or
// 500.
func (h *AuthHandler) Refresh(c *gin.Context) {
	c.Header("Deprecation", "true")
	c.Header("Link", `</oauth/token>; rel="successor-version"`)
	c.JSON(http.StatusGone, gin.H{
		"error":             "endpoint_removed",
		"error_description": "/api/v1/auth/refresh was removed in Phase 3 (2026-05-03). Use /oauth/token grant_type=refresh_token (RFC 6749 §6).",
	})
}

// DeriveTokenForSession was the per-RP refresh-token-family minter for
// SSO-silent / SSO-redirect handoff between sibling apps. Phase 3
// (mig 233) removed auth-service refresh tokens entirely — every RP
// now mints its own OAuth-token family inline via /oauth/token + the
// BFF's internal OIDC dance, so this endpoint has nothing to derive.
//
// Returning 410 Gone with the same Deprecation + Link header shape as
// /api/v1/auth/refresh so any straggler caller fails deterministically
// pointing at the replacement flow.
//
// @Summary Removed — use the BFF OAuth dance instead
// @Router /api/v1/auth/derive-token [post]
func (h *AuthHandler) DeriveTokenForSession(c *gin.Context) {
	c.Header("Deprecation", "true")
	c.Header("Link", `</oauth/authorize>; rel="successor-version"`)
	c.JSON(http.StatusGone, gin.H{
		"error":             "endpoint_removed",
		"error_description": "/api/v1/auth/derive-token was removed in Phase 3 (2026-05-03). Each relying party now mints its own OAuth token family via /oauth/authorize + /oauth/token (the BFF internal OIDC dance pattern, see frontend/packages/falcon-id-client/src/server/internal-oauth-dance.ts).",
	})
}

// @Tags Auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.LogoutRequest false "Logout options"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		// Clear cookies even if not authenticated (defensive)
		clearAuthCookies(c)
		clearIdpSessionCookie(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Logout body is optional; use defaults if binding fails
		req = models.LogoutRequest{}
	}

	ipAddress := middleware.RealClientIP(c)

	// Always clear cookies — runs BEFORE authService.Logout because that
	// call can fail (e.g. Bearer-token JWTs that omit the `sid` claim
	// land here with user.SessionID=00000000…, making the underlying
	// `EndSession: session not found or already ended` 500). Production
	// 2026-04-28 trace: the BFF revoke for accounts.example.com kept
	// 500ing here, /oauth/authorize then silent-SSO'd via the
	// falcon_idp_session cookie that should have been cleared, and the
	// user landed back on /home — the tail of the "logout button just
	// refreshes the page" loop. Defensively clearing first means even
	// when authService.Logout fails downstream, the SSO cookie + Redis
	// IdP session entry are GONE for this browser/identity.
	// Per-device sign-out by default: pin down THIS device's session. The JWT
	// `sid` claim is canonical; OAuth access tokens omit it, so fall back to
	// the session_id / idp_session_id on the presented token's
	// iam_oauth_tokens row. Read the token before the cookie is cleared.
	logoutSessionID := user.SessionID
	var logoutIdpID uuid.UUID
	if h.tokenService != nil {
		if rawToken := presentedAccessToken(c); rawToken != "" {
			rowSID, rowIdpID := h.tokenService.ResolveOAuthSession(c.Request.Context(), rawToken, user.ID)
			if logoutSessionID == uuid.Nil {
				logoutSessionID = rowSID
			}
			logoutIdpID = rowIdpID
		}
	}

	clearAuthCookies(c)
	clearIdpSessionCookie(c)

	// Try to delete the Redis IdP session by every key we can recover.
	//   1. user.SessionID from the JWT `sid` claim — the canonical key.
	//      OAuth access tokens issued to RPs (e.g. the accounts BFF
	//      calling here with its access_token) deliberately
	//      omit `sid` per OIDC, so user.SessionID will be uuid.Nil for
	//      cross-RP logout calls — that's expected, falls through to
	//      step 3.
	//   2. falcon_idp_session cookie value — present on browser-direct
	//      same-origin calls, missing when SameSite=Strict drops it on
	//      a cross-site BFF round-trip.
	//   3. the idp_session_id on the presented access token's row.
	//   4. user.ID — fan-out delete every live IdP session for this
	//      user, ONLY for an explicit sign-out everywhere (AllDevices).
	//      A per-device sign-out must not end the user's other devices.
	// All paths are succeed-or-no-op and idempotent.
	if h.sessionCache != nil {
		if user.SessionID != uuid.Nil {
			if delErr := h.sessionCache.DeleteIdpSession(c.Request.Context(), user.SessionID); delErr != nil {
				logger.SecurityAudit.Warn("Logout: DeleteIdpSession by sid failed",
					zap.String("session_id", user.SessionID.String()),
					zap.Error(delErr))
			}
		}
		if cookieVal, err := c.Cookie("falcon_idp_session"); err == nil && cookieVal != "" {
			if sid, parseErr := uuid.Parse(cookieVal); parseErr == nil && sid != user.SessionID {
				if delErr := h.sessionCache.DeleteIdpSession(c.Request.Context(), sid); delErr != nil {
					logger.SecurityAudit.Warn("Logout: DeleteIdpSession by cookie failed",
						zap.String("session_id", sid.String()),
						zap.Error(delErr))
				}
			}
		}
		if logoutIdpID != uuid.Nil && logoutIdpID != user.SessionID {
			if delErr := h.sessionCache.DeleteIdpSession(c.Request.Context(), logoutIdpID); delErr != nil {
				logger.SecurityAudit.Warn("Logout: DeleteIdpSession by token idp id failed",
					zap.String("session_id", logoutIdpID.String()),
					zap.Error(delErr))
			}
		}
		if req.AllDevices && user.ID != uuid.Nil {
			if n, delErr := h.sessionCache.DeleteAllIdpSessionsByUser(c.Request.Context(), user.ID); delErr != nil {
				logger.SecurityAudit.Warn("Logout: DeleteAllIdpSessionsByUser failed",
					zap.String("user_id", user.ID.String()),
					zap.Error(delErr))
			} else if n > 0 {
				logger.SecurityAudit.Info("Logout: deleted IdP sessions for user",
					zap.String("user_id", user.ID.String()),
					zap.Int("count", n))
			}
		}
	}

	// Publish session revocation to the Redis blacklist so the still-valid
	// access-token JWT — which can survive the response's Set-Cookie clear
	// directive in the SDK race window between POST /api/v1/auth/logout
	// and a follow-up GET /oauth/authorize — is rejected by
	// enforceBlacklist inside ValidateAccessTokenWithContext. Without this,
	// /oauth/authorize silent-SSOs and lands the user back on /home,
	// reproducing the "Sign Out just refreshes the page" symptom.
	//
	// TTL = defaultAccessTokenTTL: matches the longest plausible lifetime
	// of any JWT issued under this session, so a stale cookie cannot
	// outlive the marker. Re-login is unaffected because login mints a
	// fresh session row (auth_credentials_service.go:222) with a new
	// session_id that is not in the blacklist.
	//
	// Session-scoped on purpose: the user-level primitive
	// (BlacklistUserTokens / IsUserBlacklisted) is a flat existence check
	// with no issued-before-T semantics, so using it here would block any
	// re-login for the entire TTL window.
	//
	// SessionID == uuid.Nil happens for OAuth Bearer-token logout calls
	// where the access token deliberately omits `sid` per OIDC. The
	// production accounts.example.com BFF uses exactly this path: it
	// fetches /api/v1/auth/logout server-side with `Authorization:
	// Bearer <access_token>`, and that token only carries sub.
	// In that branch we fan out the blacklist across every active
	// session row for this user, mirroring DeleteAllIdpSessionsByUser
	// — the user-intent contract is "click Sign Out and every browser
	// session of mine dies." Production logs 2026-04-28 confirm this
	// is the live path: AuthHandler.Logout fired with
	// SessionID=00000000…, the per-session blacklist was skipped, and
	// the surviving `falcon_access_token` JWT cookie silent-SSO'd the
	// next /oauth/authorize back to /home (cookietrace.mjs trace).
	//
	// Per-session and fan-out paths share the same TTL
	// (defaultAccessTokenTTL = 15min), matching the longest plausible
	// JWT lifetime under any session. Re-login is unaffected: a fresh
	// `Session` row with a new ID is minted by
	// auth_credentials_service.go:222.
	if h.tokenBlacklist != nil {
		switch {
		case logoutSessionID != uuid.Nil && !req.AllDevices:
			if blErr := h.tokenBlacklist.BlacklistSession(c.Request.Context(), logoutSessionID, "user_logout", defaultAccessTokenTTL); blErr != nil {
				logger.SecurityAudit.Warn("Logout: BlacklistSession failed",
					zap.String("session_id", logoutSessionID.String()),
					zap.Error(blErr))
			}
		case req.AllDevices && h.sessionRepo != nil && user.ID != uuid.Nil:
			sessions, listErr := h.sessionRepo.GetActiveSessions(c.Request.Context(), user.ID)
			if listErr != nil {
				logger.SecurityAudit.Warn("Logout: GetActiveSessions for fan-out failed",
					zap.String("user_id", user.ID.String()),
					zap.Error(listErr))
				break
			}
			blacklisted := 0
			for _, sess := range sessions {
				if blErr := h.tokenBlacklist.BlacklistSession(c.Request.Context(), sess.ID, "user_logout", defaultAccessTokenTTL); blErr != nil {
					logger.SecurityAudit.Warn("Logout: BlacklistSession (fan-out) failed",
						zap.String("session_id", sess.ID.String()),
						zap.Error(blErr))
					continue
				}
				blacklisted++
			}
			logger.SecurityAudit.Info("Logout: fan-out blacklisted user sessions",
				zap.String("user_id", user.ID.String()),
				zap.Int("count", blacklisted))
		default:
			logger.SecurityAudit.Info("Logout: BlacklistSession skipped (no resolvable session for per-device sign-out)",
				zap.String("user_id", user.ID.String()))
		}
	}

	// The token's idp_session_id may differ from its iam_sessions id; sweep
	// that binding too (per-device only, all-devices revokes everything).
	if !req.AllDevices && h.tokenService != nil && logoutIdpID != uuid.Nil && logoutIdpID != logoutSessionID {
		if revErr := h.tokenService.RevokeOAuthTokensBySession(c.Request.Context(), logoutIdpID, user.ID); revErr != nil {
			logger.SecurityAudit.Warn("Logout: revoke tokens by idp session failed",
				zap.String("session_id", logoutIdpID.String()),
				zap.Error(revErr))
		}
	}

	err := h.authService.Logout(c.Request.Context(), user.ID, logoutSessionID, user.TenantID, req.AllDevices)
	if err != nil {
		// Log the error but don't expose details. Cookies + IdP session
		// are already gone — return 200 so the BFF treats this as a
		// successful logout. The most common failure here is a
		// Bearer-token JWT whose `sid` claim is empty: the refresh-token
		// row was already revoked or never existed under that session
		// ID. The user's intent (log out) has been honoured by the
		// cookie + IdP-session clears above.
		logger.SecurityAudit.Warn("Security audit: logout authService failure (cookies still cleared)",
			zap.String("event", "auth.logout.partial"),
			zap.String("username", user.Username),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.String("reason", err.Error()),
			zap.Time("timestamp", time.Now().UTC()),
		)
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
		return
	}

	// Security audit: successful logout
	logger.SecurityAudit.Info("Security audit: user logged out",
		zap.String("event", "auth.logout.success"),
		zap.String("username", user.Username),
		zap.String("user_id", user.ID.String()),
		zap.String("ip", ipAddress),
		zap.Bool("all_devices", req.AllDevices),
		zap.Time("timestamp", time.Now().UTC()),
	)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// Profile management, session management, password reset, CSRF token, token validation,
// and pagination helpers are in auth_handler_profile.go

// presentedAccessToken returns the bearer token (Authorization header, else
// the falcon_access_token cookie) without aborting the request.
func presentedAccessToken(c *gin.Context) string {
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return parts[1]
		}
		return ""
	}
	if cookie, err := c.Cookie("falcon_access_token"); err == nil {
		return cookie
	}
	return ""
}
