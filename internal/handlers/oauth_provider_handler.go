// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/internal/shared/security"
	"github.com/dogukanturhal/falcon-id/internal/templates"
	"github.com/dogukanturhal/falcon-id/pkg/clientctx"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	redispkg "github.com/dogukanturhal/falcon-id/pkg/redis"
)

const (
	msgOAuthInvalidUserContext = "invalid user context"
	msgOAuthFailedCSRFToken    = "Failed to generate CSRF token"
	msgOAuthInternalError      = "internal error"
	msgOAuthInternalErrorCap   = "An internal error occurred"
	msgOAuthInvalidClientID    = "invalid client ID"
	msgOAuthClientNotFound     = "OAuth client not found"
	hdrOAuthContentType        = "Content-Type"
	contentTypeHTMLCharset     = "text/html; charset=utf-8"
	queryParamState            = "&state="
	grantTypeClientCredentials = "client_credentials"
	grantTypeTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken       = "urn:ietf:params:oauth:token-type:access_token"
	subjectTokenTypeJWT        = "urn:ietf:params:oauth:token-type:jwt"
)

// OAuthProviderHandler handles OAuth2/OIDC provider endpoints
type OAuthProviderHandler struct {
	tokenService *services.TokenService
	service      *services.OAuthProviderService
	authService  *services.AuthService
	logger       *zap.Logger
	tenantLookup TenantLookup
	sessionCache *redispkg.SessionCache
	// fclService renders OIDC Front-Channel Logout 1.0 iframes on
	// /oauth/logout. Optional: when nil the logout page renders without
	// iframes (cookie-only logout, as before FCL was wired).
	fclService    *services.FrontchannelLogoutService
	logoutService interface {
		EndSession(context.Context, string) (*models.OAuthClient, *uuid.UUID, error)
		GetClientByClientID(context.Context, string) (*models.OAuthClient, error)
	}
	// sessionTerminator revokes refresh tokens / ends the session row on a
	// validly hinted RP-initiated logout. Optional: nil = cookie/Redis
	// teardown only.
	sessionTerminator logoutSessionTerminator
}

// logoutSessionTerminator is the explicit-end surface of RP-initiated logout.
type logoutSessionTerminator interface {
	// RevokeSessionTokens revokes the user's tokens (and families) bound to a session id.
	RevokeSessionTokens(ctx context.Context, sessionID, userID uuid.UUID) error
	// LogoutHintSID returns the sid and sub claims of a signature-verified id_token_hint.
	LogoutHintSID(idTokenHint string) (sid, subject uuid.UUID, ok bool)
	// EndLoginSession ends an iam_sessions row (sweeping its tokens).
	EndLoginSession(ctx context.Context, rowID uuid.UUID, reason string) error
	// EndHintedSession ends the session(s) named by a hint's sid when Redis has none.
	EndHintedSession(ctx context.Context, hintSID, subject uuid.UUID) error
}

// oauthLogoutTerminator adapts the OAuth provider and auth services.
type oauthLogoutTerminator struct {
	service     *services.OAuthProviderService
	authService *services.AuthService
}

func (t oauthLogoutTerminator) RevokeSessionTokens(ctx context.Context, id, userID uuid.UUID) error {
	return t.service.RevokeSessionTokens(ctx, id, userID)
}

func (t oauthLogoutTerminator) LogoutHintSID(hint string) (uuid.UUID, uuid.UUID, bool) {
	return t.service.LogoutHintSID(hint)
}

func (t oauthLogoutTerminator) EndHintedSession(ctx context.Context, hintSID, subject uuid.UUID) error {
	return t.service.EndHintedSession(ctx, hintSID, subject)
}

func (t oauthLogoutTerminator) EndLoginSession(ctx context.Context, rowID uuid.UUID, reason string) error {
	if t.authService == nil {
		return nil
	}
	return t.authService.EndSession(ctx, rowID, reason)
}

// NewOAuthProviderHandler creates a new OAuthProviderHandler
func NewOAuthProviderHandler(service *services.OAuthProviderService, authService *services.AuthService, logger *zap.Logger) *OAuthProviderHandler {
	h := &OAuthProviderHandler{
		service:     service,
		authService: authService,
		logger:      logger,
	}
	if service != nil {
		h.logoutService = service
		h.sessionTerminator = oauthLogoutTerminator{service: service, authService: authService}
	}
	return h
}

// SetTenantLookup sets the tenant lookup used to resolve the ?tenant= hint on /oauth/authorize.
func (h *OAuthProviderHandler) SetTenantLookup(lookup TenantLookup) {
	h.tenantLookup = lookup
}

// SetSessionCache wires the Redis session cache used to store IdP-level SSO sessions.
func (h *OAuthProviderHandler) SetSessionCache(cache *redispkg.SessionCache) {
	h.sessionCache = cache
}

// SetTokenService wires the token service used to read the session id from the
// freshly minted access token (all token versions, not just legacy claims).
func (h *OAuthProviderHandler) SetTokenService(ts *services.TokenService) {
	h.tokenService = ts
}

// SetFrontchannelLogout wires the FCL iframe-renderer used by EndSession.
// The handler degrades gracefully when nil — the logout page renders as
// before, just without the iframe cascade. Wired from cmd/handlers.go after
// the underlying service is constructed.
func (h *OAuthProviderHandler) SetFrontchannelLogout(svc *services.FrontchannelLogoutService) {
	h.fclService = svc
}

// ==================== OIDC Discovery Endpoints ====================

// GetOpenIDConfiguration returns the OIDC discovery document
// @Summary Get OpenID Connect discovery document
// @Description Returns the OIDC discovery document with all supported endpoints and capabilities
// @Tags OAuth2/OIDC
// @Produce json
// @Success 200 {object} map[string]interface{} "OIDC discovery document"
// @Router /.well-known/openid-configuration [get]
func (h *OAuthProviderHandler) GetOpenIDConfiguration(c *gin.Context) {
	doc := h.service.GetDiscoveryDocument()
	c.JSON(http.StatusOK, doc)
}

// GetJWKS returns the JSON Web Key Set
// @Summary Get JSON Web Key Set (JWKS)
// @Description Returns the public keys used to verify JWT tokens issued by this server
// @Tags OAuth2/OIDC
// @Produce json
// @Success 200 {object} map[string]interface{} "JWKS document"
// @Router /.well-known/jwks.json [get]
func (h *OAuthProviderHandler) GetJWKS(c *gin.Context) {
	jwks := h.service.GetJWKS()
	c.JSON(http.StatusOK, jwks)
}

// GetJWKSData returns the raw OIDC JWK entries for merging into a unified JWKS endpoint.
func (h *OAuthProviderHandler) GetJWKSData() []models.JWK {
	jwks := h.service.GetJWKS()
	if jwks == nil {
		return nil
	}
	return jwks.Keys
}

// ==================== OAuth2 Endpoints ====================

// PushAuthorization handles the Pushed Authorization Request endpoint (RFC 9126).
// POST /oauth/par
//
// The client MUST authenticate using client credentials (Basic auth or client_secret_post).
// Returns a request_uri that can be passed to /oauth/authorize in place of the full
// authorization request parameters.
func (h *OAuthProviderHandler) PushAuthorization(c *gin.Context) {
	// RFC 9126 §2: the client MUST authenticate at the PAR endpoint.
	tokenReq := &models.OAuthTokenRequest{
		ClientID:     c.PostForm("client_id"),
		ClientSecret: c.PostForm("client_secret"),
	}
	client, err := h.authenticateClient(c, tokenReq)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.OAuthErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Bind the full set of authorization parameters from the form body.
	var params models.OAuthAuthorizeRequest
	if bindErr := c.ShouldBind(&params); bindErr != nil {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: bindErr.Error(),
		})
		return
	}

	// RFC 9126 §2.1: client_id in the request body MUST match the authenticated client.
	if params.ClientID != "" && params.ClientID != client.ClientID {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "client_id mismatch between authentication and request body",
		})
		return
	}
	params.ClientID = client.ClientID

	resp, err := h.service.PushAuthorizationRequest(c.Request.Context(), client, &params)
	if err != nil {
		h.parError(c, err)
		return
	}

	// RFC 9126 §2.2: respond with 201 Created.
	c.JSON(http.StatusCreated, resp)
}

// authorizeWithPAR resolves a PAR request_uri and continues the standard authorization flow.
// Called by Authorize when a request_uri query parameter is present.
func (h *OAuthProviderHandler) authorizeWithPAR(c *gin.Context, requestURI string) {
	clientID := c.Query("client_id")
	if clientID == "" {
		// RFC 9126 §4: client_id MUST be present even when using request_uri.
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "client_id is required when using request_uri",
		})
		return
	}

	req, err := h.service.ResolvePARRequest(c.Request.Context(), clientID, requestURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Continue the standard authorize flow using the resolved request parameters.
	// viaPAR=true so continueAuthorize knows to skip the per-client
	// require_pushed_authorization_requests rejection (this branch IS PAR).
	h.continueAuthorize(c, req, true)
}

// Authorize handles the OAuth2 authorization endpoint
// GET /oauth/authorize
func (h *OAuthProviderHandler) Authorize(c *gin.Context) {
	// RFC 9126 §4: when request_uri is present, resolve the PAR entry and continue.
	if requestURI := c.Query("request_uri"); requestURI != "" {
		h.authorizeWithPAR(c, requestURI)
		return
	}

	var req models.OAuthAuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		// SECURITY: Do NOT redirect to unvalidated redirect_uri — return JSON error instead.
		// The redirect_uri has not been validated against client's registered URIs yet.
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
			State:            req.State,
		})
		return
	}

	// RFC 9101 — JWT-Secured Authorization Request. When `request=<JWS>`
	// is present, validate the signature against the client's
	// registered jwks and merge the JWS claims back into the parsed
	// request. Front-channel-tampering protection: an attacker who
	// modifies query params downstream of the client cannot forge a
	// matching JWS without the private key.
	if jws := c.Query("request"); jws != "" {
		if err := h.applyJARRequestObject(c, &req, jws); err != nil {
			c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
				Error:            "invalid_request_object",
				ErrorDescription: err.Error(),
				State:            req.State,
			})
			return
		}
	}

	h.continueAuthorize(c, &req, false)
}

// applyJARRequestObject implements RFC 9101 §6 — parse the signed
// request object, validate the JWS against the client's registered
// jwks, and merge the resulting claims back into the OAuthAuthorize
// Request. Any duplicate parameter that's also in the query string
// MUST match the JWS (RFC 9101 §6.1); we enforce by overriding from
// the JWS so a tampered query value can't sneak past.
//
// JAR is opt-in per client — clients without registered jwks that
// send `request=<jws>` get a deterministic 400 here rather than
// having the AS silently fall back to the (potentially tampered)
// query parameters.
func (h *OAuthProviderHandler) applyJARRequestObject(c *gin.Context, req *models.OAuthAuthorizeRequest, jws string) error {
	if req.ClientID == "" {
		return fmt.Errorf("client_id query parameter is required even when sending a JAR request object (used to look up the verification key)")
	}
	client, err := h.service.GetClientByClientID(c.Request.Context(), req.ClientID)
	if err != nil || client == nil {
		// Mirror the error-transparency pattern from
		// OAuthProviderService.{ValidateAuthorizeRequest,AuthenticateClient}:
		// only return the canonical "client not found" wire message when
		// the row genuinely does not exist; surface other DB / pool /
		// pgx failures via %w + structured ERROR log so JAR-flow
		// outages don't masquerade as a missing client.
		if err != nil && !errors.Is(err, repositories.ErrOAuthClientNotFound) {
			logger.Error("OAuth client lookup failed in applyJARRequestObject",
				zap.Error(err),
				zap.String("client_id", req.ClientID),
			)
			return fmt.Errorf("invalid_client: %w", err)
		}
		return fmt.Errorf("invalid_client: client not found")
	}
	if client.Jwks == nil || *client.Jwks == "" {
		return fmt.Errorf("client has not registered a jwks; JAR requires per-client signing-key registration (RFC 9101 §4)")
	}
	allowedAlg := client.RequestObjectSigningAlg
	if allowedAlg == "" {
		allowedAlg = "RS256"
	}

	claims, err := services.VerifyJARRequestObject(jws, *client.Jwks, allowedAlg)
	if err != nil {
		return fmt.Errorf("request object signature verification failed: %v", err)
	}

	// Merge JWS claims onto the request struct. The JWS wins on every
	// duplicated parameter per RFC 9101 §6.1; query params for
	// parameters NOT in the JWS are kept as-is. We apply only the
	// fields the AS actually consumes — extra claims (jti, iat, exp,
	// aud, iss) are validated by VerifyJARRequestObject and discarded.
	if v, ok := claims["response_type"].(string); ok && v != "" {
		req.ResponseType = v
	}
	if v, ok := claims["redirect_uri"].(string); ok && v != "" {
		req.RedirectURI = v
	}
	if v, ok := claims["scope"].(string); ok && v != "" {
		req.Scope = v
	}
	if v, ok := claims["state"].(string); ok && v != "" {
		req.State = v
	}
	if v, ok := claims["nonce"].(string); ok && v != "" {
		req.Nonce = v
	}
	if v, ok := claims["code_challenge"].(string); ok && v != "" {
		req.CodeChallenge = v
	}
	if v, ok := claims["code_challenge_method"].(string); ok && v != "" {
		req.CodeChallengeMethod = v
	}
	if v, ok := claims["resource"].(string); ok && v != "" {
		req.Resource = v
	}
	return nil
}

// continueAuthorize performs the authorization flow after the request has been parsed
// and (in the PAR case) looked up from Redis. viaPAR=true means the
// request reached this function via authorizeWithPAR (RFC 9126 §4 path);
// false means the bare ?client_id=...&response_type=code... query path.
// This bit is required to honor the per-client
// require_pushed_authorization_requests metadata flag (RFC 9126 §2.1):
// when the client demands PAR and the request did NOT use PAR, we MUST
// reject. The check fires inside continueAuthorize because the client
// metadata isn't loaded until ValidateAuthorizeRequest runs.
func (h *OAuthProviderHandler) continueAuthorize(c *gin.Context, req *models.OAuthAuthorizeRequest, viaPAR bool) {
	// Resolve ?tenant= hint before anything else so downstream handlers (login page,
	// consent page) can apply tenant-specific branding and IDP routing without an
	// extra round-trip.  The hint is advisory: if the authenticated client belongs
	// to a different tenant we reject the request below.
	var resolvedTenantID uuid.UUID
	if req.Tenant != "" && h.tenantLookup != nil {
		// Accept both UUID and slug so clients can pass either form.
		if tid, err := uuid.Parse(req.Tenant); err == nil {
			resolvedTenantID = tid
		} else {
			tenant, err := h.tenantLookup.GetBySlug(c.Request.Context(), req.Tenant)
			if err != nil || tenant == nil || tenant.Status != "active" {
				c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
					Error:            "invalid_request",
					ErrorDescription: "unknown tenant",
					State:            req.State,
				})
				return
			}
			resolvedTenantID = tenant.ID
		}
		c.Set("tenant_id", resolvedTenantID)
	}

	// Validate request (this validates redirect_uri against client's registered URIs)
	client, err := h.service.ValidateAuthorizeRequest(c.Request.Context(), req)
	if err != nil {
		// SECURITY: Do NOT redirect to unvalidated redirect_uri — return JSON error instead.
		// ValidateAuthorizeRequest may have failed before validating the redirect_uri.
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
			State:            req.State,
		})
		return
	}

	// FAPI 2.0 Baseline / RFC 9126 §2.1: per-client require_pushed_authorization_requests.
	// When the client opted in to PAR-mandate, the only acceptable entry-
	// point is /oauth/par + request_uri. A bare ?client_id=... query is
	// refused to prevent regression of the front-channel-tampering attacks
	// that PAR is designed to mitigate. The redirect_uri has been validated
	// at this point (one line above) so a 302 to the RP with an OAuth error
	// is also safe; we keep returning JSON to match the existing handler
	// posture for client-metadata violations (cleaner debugging on the
	// client side; an RP that demands PAR knows the server-side check exists).
	if !viaPAR && client.RequirePushedAuthorizationRequests {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "this client requires pushed authorization requests (RFC 9126); send the request to /oauth/par first and pass the returned request_uri here",
			State:            req.State,
		})
		return
	}

	// When a tenant hint was resolved, verify the client is registered to that tenant.
	// This prevents a client from one tenant initiating an auth flow scoped to another.
	if resolvedTenantID != uuid.Nil && client.TenantID != resolvedTenantID {
		c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "client does not belong to the specified tenant",
			State:            req.State,
		})
		return
	}

	// Get authenticated user from context
	userID, exists := c.Get("user_id")
	if !exists || req.Prompt == "login" {
		if req.Prompt == "login" {
			if cookie, err := c.Cookie("falcon_idp_session"); err == nil && h.sessionCache != nil {
				if sid, err := uuid.Parse(cookie); err == nil {
					_ = h.sessionCache.EndIdpSession(c.Request.Context(), sid)
				}
			}
			clearAuthCookies(c)
			clearIdpSessionCookie(c)
		}
		// Build the post-login redirect URL.
		//
		// RFC 9126 §2.2 — PAR entries are one-time-use AND short-TTL (≤60s).
		// `ResolvePARRequest` above has ALREADY consumed the entry; reusing
		// the inbound URL (which still carries `request_uri=...`) as the
		// post-login bounce would re-hit `authorizeWithPAR`, fail to resolve
		// the now-deleted entry, and surface as "request_uri not found or
		// expired" — exactly the bug observed live 2026-05-14 after the
		// RFC 9126 rollout (login + MFA together routinely exceed 60s even
		// without the single-use rule). The fix: when we got here via PAR,
		// build the bounce URL from the RESOLVED parameters so the post-
		// login flow continues without touching the PAR store. The bare-
		// query path (viaPAR=false) keeps using the inbound URL — semantics
		// unchanged for that branch.
		var redirectURL string
		if viaPAR {
			redirectURL = buildAuthorizeURLFromRequest(req)
		} else {
			redirectURL = c.Request.URL.String()
		}
		// The forced authentication is being fulfilled by the hosted form.
		// Do not re-apply prompt=login after the form creates a fresh session.
		redirectURL = loginResumeURL(redirectURL)
		safeRedirect := security.ValidateRedirectURL(redirectURL, security.RedirectValidationConfig{
			AllowRelativePaths: true,
			DefaultPath:        "/dashboard",
		})
		c.Redirect(http.StatusFound, "/oauth/login?redirect="+url.QueryEscape(safeRedirect))
		return
	}

	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		userIDStr, ok := userID.(string)
		if !ok {
			h.oauthError(c, "server_error", msgOAuthInvalidUserContext, req.State, req.RedirectURI)
			return
		}
		var err error
		userUUID, err = uuid.Parse(userIDStr)
		if err != nil {
			h.oauthError(c, "server_error", "invalid user ID", req.State, req.RedirectURI)
			return
		}
	}

	// Consent decision: first-party clients (is_first_party=true) skip
	// consent entirely — they're admin-pre-consented at the tenant level
	// and every login flowing through them is implicitly trusted.
	// Matches Microsoft Entra "admin pre-consent for org apps" and
	// Auth0 "First Party + skip consent" patterns. Third-party clients
	// (is_first_party=false) always require an explicit consent record
	// covering the requested scopes.
	//
	// A previous iteration added a "sensitive scopes still require
	// consent even for first-party" override (groups/roles/offline_
	// access/admin:*) modeled on Google's per-scope consent metadata.
	// In practice every platform service requests `groups roles` as
	// part of its standard scope set, so the override fired on every
	// login of every internal app, defeating the silent-SSO design.
	// Reverted: defense-in-depth for sensitive operations is better
	// expressed as a step-up auth requirement (re-auth / MFA) than as
	// a consent prompt that users habituate to clicking through.
	requestedScopes := strings.Split(req.Scope, " ")
	if !client.IsFirstParty {
		consent, err := h.service.GetConsent(c.Request.Context(), userUUID, client.ID)
		if err != nil {
			h.logger.Error("oauth authorize: consent lookup failed", zap.Error(err))
			h.oauthError(c, "server_error", msgOAuthInternalErrorCap, req.State, req.RedirectURI)
			return
		}
		if consent == nil || !h.scopesCovered(consent.Scopes, requestedScopes) {
			// Redirect to consent page with OAuth params
			consentURL := fmt.Sprintf("/oauth/consent?client_id=%s&scope=%s&state=%s&nonce=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=%s&response_type=%s",
				url.QueryEscape(req.ClientID),
				url.QueryEscape(req.Scope),
				url.QueryEscape(req.State),
				url.QueryEscape(req.Nonce),
				url.QueryEscape(req.RedirectURI),
				url.QueryEscape(req.CodeChallenge),
				url.QueryEscape(req.CodeChallengeMethod),
				url.QueryEscape(req.ResponseType),
			)
			c.Redirect(http.StatusFound, consentURL)
			return
		}
	}

	// Snapshot the current session's RFC 8176 authentication-method references
	// onto the request so the resulting authorization code carries `amr` into
	// subsequent id_tokens (migration 211, docs/oidc-claims-groups-amr.md).
	// Middleware sets `session_id` from the access_token cookie (see
	// middleware/auth.go); missing or unparseable values silently degrade to
	// an empty amr list rather than failing the flow.
	if sidVal, ok := c.Get("session_id"); ok && h.authService != nil {
		if sid, ok := sidVal.(uuid.UUID); ok {
			req.AuthMethodsUsed = h.authService.GetSessionAuthMethods(c.Request.Context(), sid)
		}
	}

	// Max-age freshness gate (OIDC Core 1.0 §3.1.2.1 + RFC 9470 §3).
	//
	// When the client requests `max_age=N`, the IdP MUST verify the
	// current session's auth_time is within N seconds of now and
	// re-authenticate the user otherwise. Pre-fix this handler
	// IGNORED max_age entirely (the field wasn't even bound on the
	// request model) and silent-SSO'd against any extant IdP cookie
	// regardless of age — which surfaced as a passkey-delete loop on
	// 2026-05-23: RP step-up gate (RequireFreshAuth(5min)) emitted a
	// 401, frontend bounced to /oauth/authorize?max_age=300, this
	// handler issued a new auth code without prompting, the new
	// access token still carried the original auth_time, the next
	// DELETE returned 401 with the same step-up challenge, infinite
	// loop.
	//
	// Enforcement matches the RFC's resume semantics: redirect to
	// the login UI with the original /oauth/authorize URL preserved
	// as `redirect`, the same way the no-session branch above does.
	// The IdP login form is the user's chance to re-prove who they
	// are; on submit, /api/v1/auth/login establishes a fresh IdP
	// session (NEW AuthTime via SetIdpSession) and bounces back to
	// the saved URL. Re-evaluation here sees fresh auth_time, passes
	// the max_age check, and issues a token with the new auth_time
	// claim that the RP's RequireFreshAuth gate accepts.
	//
	// Why this check fires BEFORE the ACR step-up gate: max_age is a
	// stricter requirement (re-prove identity) than acr=mfa (any MFA
	// factor in the AMR list). If the session passes ACR but fails
	// max_age, the user must still re-authenticate; re-auth bumps
	// AuthTime AND re-emits MFA per the configured policy, so the
	// ACR gate is automatically satisfied on resume. Putting max_age
	// first avoids an awkward "satisfied ACR but failed freshness →
	// bounce through MFA challenge that doesn't actually fix the
	// freshness problem" routing trap.
	if req.MaxAge != nil && *req.MaxAge >= 0 {
		currentUser := middleware.GetCurrentUser(c)
		var sessionAuthTime int64
		if currentUser != nil {
			sessionAuthTime = currentUser.AuthTime
		}
		// AuthTime == 0 means "session has no recorded auth_time"
		// (legacy session minted before AuthTime was populated, or
		// a token-only path that didn't carry the claim). Treat as
		// infinitely stale: any max_age >= 0 forces re-auth.
		//
		// max_age=0 grace window (OIDC Core §3.1.2.1 + Auth0/Okta
		// convention): the literal interpretation "force re-auth"
		// races against the freshly-minted session's microsecond age —
		// the user has just re-authenticated, the JWT is being read
		// nanoseconds later, but time.Since() returns a positive
		// duration that fails `> 0`. Result: infinite redirect loop
		// because every re-auth pass produces a "stale" verdict.
		// Industry convention is to allow a tiny grace window
		// (typically 1-5s) within which the re-auth is considered
		// to satisfy max_age=0. We pick 5s — longer than any
		// realistic redirect+token-issue round-trip, shorter than
		// any meaningful session-fixation attack window.
		maxAge := time.Duration(*req.MaxAge) * time.Second
		if maxAge == 0 {
			maxAge = 5 * time.Second
		}
		stale := sessionAuthTime == 0 ||
			time.Since(time.Unix(sessionAuthTime, 0)) > maxAge
		// An in-place OTP/passkey step-up refreshes the DB session without
		// reissuing the browser's old access-token cookie. Consult that
		// authoritative timestamp before sending the user through MFA again.
		if stale && currentUser != nil && h.authService != nil {
			if sidVal, ok := c.Get("session_id"); ok {
				if sid, ok := sidVal.(uuid.UUID); ok {
					if session, err := h.authService.GetSessionByID(c.Request.Context(), sid); err == nil && session != nil && session.UserID == userUUID && session.AuthenticatedAt != nil {
						stale = time.Since(*session.AuthenticatedAt) > maxAge
					}
				}
			}
		}
		if stale {
			// Build the resume URL from the parsed request (not the
			// raw inbound URL) for the same PAR-vs-bare-query reason
			// continueAuthorize's no-session branch does above: when
			// viaPAR=true the inbound URL carries `request_uri=` for
			// a now-consumed (one-time-use) PAR entry; reusing it
			// would 404 in authorizeWithPAR after login.
			var redirectURL string
			if viaPAR {
				redirectURL = buildAuthorizeURLFromRequest(req)
			} else {
				redirectURL = c.Request.URL.String()
			}
			safeRedirect := security.ValidateRedirectURL(redirectURL, security.RedirectValidationConfig{
				AllowRelativePaths: true,
				DefaultPath:        "/dashboard",
			})

			// Canonical Auth0 / Microsoft Entra step-up UX (2026-05-26).
			// When the user has an existing IdP session AND has at least
			// one MFA factor enrolled, drive freshness via the MFA
			// challenge handler instead of /oauth/login. NIST SP 800-63B-4
			// §5.1 explicitly recognises a single MFA factor verification
			// as a fresh authentication event at AAL2 — no need to make
			// the user re-enter their password on top of an OTP or
			// passkey assertion. /auth/mfa/challenge bumps
			// iam_sessions.authenticated_at on success (mfa_handler.go
			// RefreshAuthenticatedAt) so the resume of this same
			// /oauth/authorize URL passes the max_age gate.
			//
			// Pre-fix this branch always sent the user through
			// /oauth/login regardless — which on mobile surfaced as a
			// confusing "full email+password re-entry after I just want
			// to disable my email MFA" flow. Live trigger 2026-05-25.
			hasFactor := false
			if currentUser != nil && req.Prompt != "login" {
				hf, _ := h.service.UserHasAnyMFAFactor(c.Request.Context(), userUUID)
				hasFactor = hf
			}
			c.Redirect(http.StatusFound, staleAuthRedirect(staleAuthRedirectInput{
				CurrentUserPresent: currentUser != nil,
				Prompt:             req.Prompt,
				HasMFAFactor:       hasFactor,
				SafeRedirect:       safeRedirect,
			}))
			return
		}
	}

	// ACR step-up gate (RFC 9470 + OIDC Core 1.0 §3.1.2.1).
	//
	// When the client requests an ACR that exceeds what the current
	// session asserts, drive a step-up flow rather than silently
	// issuing a token at a lower assurance level. This closes the
	// gap that bricked vault.ops on 2026-05-08: Talon's
	// startAuthWithMFA appends mfa=1 → /auth/start composes
	// acr_values=mfa on the OIDC redirect → pre-fix this handler
	// IGNORED that, issued a token without MFA, then Talon's gate
	// re-fired and looped without ever prompting the user to actually
	// complete MFA.
	//
	// Three branches:
	//   1. Session ALREADY satisfies the requested ACR → continue.
	//   2. Session lacks MFA AND user has zero factors enrolled →
	//      redirect to /auth/mfa/enrollment so the user can register
	//      a factor (TOTP or WebAuthn). Resumes back here on completion.
	//   3. Session lacks MFA AND user HAS factors → redirect to
	//      /auth/mfa/challenge for an interactive step-up. Resumes
	//      back here on completion.
	//
	// The `rd` query param carries the original /oauth/authorize URL
	// so the post-step-up path lands the user back at the same OAuth
	// flow without re-entering ACR-decision logic (silent SSO).
	// Satisfaction check uses RFC-8176-aware HasMFAFactor (not a literal
	// `slices.Contains(amr, "mfa")` lookup) because passkey sessions
	// record `amr=["hwk","user"]` per LoginViaWebAuthn — the "mfa"
	// umbrella is only appended at token-emission time by
	// amrWithUmbrella, NOT at session-write time. Pre-fix the bare
	// string-match meant /oauth/authorize bounced the user to
	// /auth/mfa/challenge IMMEDIATELY AFTER they had successfully
	// authenticated with a passkey — a phantom second-factor prompt
	// that surfaced live 2026-05-25 as "passkey delete still loops to
	// login". With HasMFAFactor the passkey ceremony satisfies the
	// ACR=mfa requirement per RFC 8176 §2 + NIST SP 800-63B-4 §5.1.7.
	if requiresMFA(req.AcrValues) && !services.HasMFAFactor(req.AuthMethodsUsed) {
		// Route based on the SOURCE-OF-TRUTH factor check, not the
		// denormalized users.mfa_enabled flag. mfa_enabled was set on
		// first-factor enrollment and (until 2026-05-12) was never
		// cleared on factor removal — DisableMFA-style flows could leave
		// it `true` with zero factors enrolled, routing the user to
		// /mfa/challenge instead of /mfa/enrollment and producing an
		// unrecoverable loop. HasAnyMFAFactor evaluates iam_users
		// (TOTP/email), iam_webauthn_credentials (active), and
		// iam_push_mfa_devices in a single query, so the routing
		// decision can never drift from the actual factor inventory.
		hasFactor, ferr := h.service.UserHasAnyMFAFactor(c.Request.Context(), userUUID)
		if ferr != nil {
			h.logger.Error("oauth authorize: factor inventory lookup for acr step-up failed", zap.Error(ferr))
			h.oauthError(c, "server_error", msgOAuthInternalErrorCap, req.State, req.RedirectURI)
			return
		}
		stepUpDest := "/auth/mfa/challenge"
		if !hasFactor {
			// User has zero factors: enroll first.
			stepUpDest = "/auth/mfa/enrollment"
		}
		// Preserve the entire /oauth/authorize URL for post-step-up
		// resume. ValidateRedirectURL already ran on req.RedirectURI
		// up-front, but we wrap the FULL request URL (which includes
		// every OAuth param) — that's a same-origin path on the IdP,
		// so no open-redirect surface.
		//
		// Use RequestURI() (path + "?" + RawQuery) explicitly rather
		// than URL.String(). For inbound requests Go's net/http leaves
		// Scheme/Host empty so .String() produces a relative form
		// today, but RequestURI() is the contractually defined
		// "origin-form" of the URI (RFC 7230 §5.3.1) and is what the
		// frontend-login `validateRedirect()` helper expects (must
		// start with `/oauth/authorize`). Future middleware that fills
		// in Request.URL.Host (e.g. a reverse-proxy header processor)
		// would silently flip .String() to an absolute URL, which the
		// frontend's strict path-only validator rejects → user lands
		// on the enrollment "done" screen with no resume, breaking
		// silent SSO. Pinning to RequestURI() is the explicit guard.
		rd := c.Request.URL.RequestURI()
		c.Redirect(http.StatusFound, stepUpDest+"?rd="+url.QueryEscape(rd))
		return
	}

	// Snapshot the falcon_idp_session UUID so the resulting authorization code
	// (and downstream tokens) carry the OIDC Session Management 1.0 §5 `sid`
	// claim. RPs use `sid` to scope OIDC Front-Channel Logout 1.0 cascades to
	// a single browser session instead of fanning out across the subject
	// (migration 220). Missing/unparseable cookie silently degrades to no
	// `sid` claim — spec-compliant since `sid` is OPTIONAL.
	// Only stamp the cookie's session when it provably belongs to the
	// authenticated user (Redis owner == userUUID): the id later keys explicit
	// session ends, so a cookie naming someone else's session must never end
	// up on this user's tokens. Nil UUIDs and unresolvable sessions are
	// ignored (sid is optional).
	if cookieVal, err := c.Cookie("falcon_idp_session"); err == nil && cookieVal != "" && h.sessionCache != nil {
		if idpSessionID, parseErr := uuid.Parse(cookieVal); parseErr == nil && idpSessionID != uuid.Nil {
			if data, lookupErr := h.sessionCache.GetIdpSession(c.Request.Context(), idpSessionID); lookupErr == nil && data != nil && data.UserID == userUUID {
				req.IdpSessionID = &idpSessionID
			}
		}
	}

	// Generate authorization code
	code, err := h.service.CreateAuthorizationCode(c.Request.Context(), client, userUUID, req)
	if err != nil {
		h.logger.Error("oauth authorize: authorization code creation failed", zap.Error(err))
		h.oauthError(c, "server_error", msgOAuthInternalErrorCap, req.State, req.RedirectURI)
		return
	}

	// Validate and redirect with code
	// Ensure redirect_uri matches one of the client's registered redirect URIs
	// The ValidateAuthorizeRequest already validated this, but we double-check.
	//
	// RFC 9207 (FAPI 2.0 Baseline §5.4): emit `iss=<issuer>` alongside
	// `code` and `state` to defend against the IdP mix-up attack. Without
	// `iss` the RP cannot tell whether the auth_code came from the OP it
	// trusts or from a malicious mirror, and a phishing IdP can trick
	// the RP into POSTing the code back to the honest IdP's /oauth/token
	// (where it would be exchanged for tokens that grant the attacker
	// access). The discovery
	// `authorization_response_iss_parameter_supported=true` in
	// internal/services/oauth_provider_service_tokens.go advertises this
	// to spec-aware RP SDKs.
	redirectURL := buildAuthorizeSuccessRedirect(req.RedirectURI, code, req.State, h.service.Issuer())

	// The redirect_uri is already validated by the OAuth service against
	// the client's registered redirect URIs, so it's safe to redirect.
	// HTML-bodied redirect — Safari iOS download-prompt fix.
	writeOAuthHTMLRedirect(c, redirectURL)
}

// buildAuthorizeSuccessRedirect appends code, state and iss to redirectURI.
// Parameters are set through url.Values so state is escaped (no parameter or
// fragment injection through a hostile state) and a query already present on
// the registered redirect_uri is preserved rather than producing a second "?".
func buildAuthorizeSuccessRedirect(redirectURI, code, state, issuer string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// Unparseable even though it was validated against the client's
		// registered URIs: fall back to explicit escaping.
		out := redirectURI + "?code=" + url.QueryEscape(code) + "&iss=" + url.QueryEscape(issuer)
		if state != "" {
			out += queryParamState + url.QueryEscape(state)
		}
		return out
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// Token handles the OAuth2 token endpoint
// @Summary OAuth2 Token Endpoint
// @Description Exchange authorization code, refresh token, or client credentials for access/refresh tokens.
// @Tags OAuth2/OIDC
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant type" Enums(authorization_code, refresh_token, client_credentials)
// @Param code formData string false "Authorization code (for authorization_code grant)"
// @Param redirect_uri formData string false "Redirect URI (must match authorize request)"
// @Param code_verifier formData string false "PKCE code verifier"
// @Param refresh_token formData string false "Refresh token (for refresh_token grant)"
// @Param client_id formData string false "Client ID (if not using Basic auth)"
// @Param client_secret formData string false "Client secret (if not using Basic auth)"
// @Param scope formData string false "Requested scopes (for client_credentials)"
// @Success 200 {object} models.OAuthTokenResponse "Token response"
// @Failure 400 {object} models.OAuthErrorResponse "Invalid request or grant"
// @Failure 401 {object} models.OAuthErrorResponse "Invalid client credentials"
// @Router /oauth/token [post]
func (h *OAuthProviderHandler) Token(c *gin.Context) {
	var req models.OAuthTokenRequest
	if err := c.ShouldBind(&req); err != nil {
		h.tokenError(c, "invalid_request", err.Error())
		return
	}

	// RFC 8707 — Resource Indicators. Validate the optional `resource`
	// parameter as an absolute URI without a fragment per §2; reject
	// (rather than silently drop) so a misconfigured client gets
	// immediate feedback instead of receiving a token with the wrong
	// audience. The validated value travels through the service layer
	// via context (services.WithOAuthResource) and ends up as the
	// access-token `aud` claim. When omitted, `aud` falls back to the
	// caller's client_id (legacy default).
	if req.Resource != "" {
		if err := validateRFC8707Resource(req.Resource); err != nil {
			h.tokenError(c, "invalid_target", err.Error())
			return
		}
	}

	// Authenticate client
	client, err := h.authenticateClient(c, &req)
	if err != nil {
		h.tokenError(c, "invalid_client", err.Error())
		return
	}

	// RFC 9449: extract the DPoP key thumbprint set by OptionalDPoP middleware.
	// An empty string means no DPoP proof was presented; plain Bearer is issued.
	dpopJKT, _ := c.Get("dpop_jkt")
	dpopJKTStr, _ := dpopJKT.(string)

	// Build a single derived context carrying:
	//   - the RFC 8707 resource (drives the `aud` claim),
	//   - the RFC 9449 DPoP JKT (drives the `cnf.jkt` claim +
	//     sender-constrain enforcement),
	//   - the gateway-resolved client IP (stamped on the issued
	//     OAuthToken row + compared on refresh to drive CAEP
	//     CAEIPChanged signals per OpenID CAEP §5.3).
	// All With* helpers short-circuit on empty input so a request
	// without resource / DPoP / IP keeps pre-fix behavior.
	tokenCtx := services.WithOAuthResource(c.Request.Context(), req.Resource)
	tokenCtx = services.WithDPoPJKT(tokenCtx, dpopJKTStr)
	tokenCtx = services.WithRequestIP(tokenCtx, GetClientIP(c))
	// Stash the request UA + edge-stamped country/geo onto ctx so the
	// refresh-rotation flow can detect session-row drift (e.g. user
	// signed in on macOS Chrome → cookies persist → user switches to
	// Linux Chrome → refresh rotation arrives with a different OS
	// class than the linked iam_sessions row). The service compares
	// these against the linked session in
	// OAuthProviderService.detectSessionDrift and cuts a fresh row
	// when drift is detected (canonical Auth0/Okta pattern). Same
	// short-circuit semantics as WithRequestIP — empty values are no-
	// ops, preserving pre-drift-detection behaviour for grants that
	// don't run through the refresh path (authorization_code, etc.).
	tokenCtx = services.WithRequestUserAgent(tokenCtx, c.GetHeader(hdrUserAgent))
	tokenCtx = clientctx.WithCountry(tokenCtx, middleware.ClientCountry(c.Request))
	if g := middleware.ClientGeo(c.Request); g != (middleware.IPGeo{}) {
		tokenCtx = clientctx.WithGeo(tokenCtx, clientctx.Geo{
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

	var response *models.OAuthTokenResponse

	switch req.GrantType {
	case "authorization_code":
		response, err = h.service.ExchangeAuthorizationCode(
			tokenCtx,
			client,
			req.Code,
			req.RedirectURI,
			req.CodeVerifier,
			dpopJKTStr,
		)
	case "refresh_token":
		response, err = h.service.RefreshTokens(
			tokenCtx,
			client,
			req.RefreshToken,
			dpopJKTStr,
		)
	case grantTypeClientCredentials:
		scopes := strings.Split(req.Scope, " ")
		response, err = h.service.ClientCredentialsGrant(
			tokenCtx,
			client,
			scopes,
			dpopJKTStr,
		)
	case grantTypeTokenExchange:
		// Operator token exchange (platform-admin console): audience
		// hexxlock-ops is a logical name, not an RFC 8707 URI, so this
		// branch must run before the generic audience handling below.
		if req.Audience == services.OperatorTokenAudience && req.TargetTenantID == "" {
			response, err = h.service.OperatorTokenExchange(
				tokenCtx,
				client,
				req.SubjectToken,
				req.SubjectTokenType,
				req.RequestedTokenType,
			)
			if err == nil && response != nil {
				response.IssuedTokenType = tokenTypeAccessToken
			}
			break
		}
		// RFC 8693 — Token Exchange. The `audience` form field is
		// the §2.1 alternative to RFC 8707 `resource`; when present
		// without an explicit `resource` we promote it into the
		// service-layer ctx via WithOAuthResource so generateTokens
		// stamps it as `aud` exactly the same way RFC 8707 does. When
		// both are sent the resource path wins (already in tokenCtx).
		exchangeCtx := tokenCtx
		if req.Resource == "" && req.Audience != "" {
			if vErr := validateRFC8707Resource(req.Audience); vErr != nil {
				h.tokenError(c, "invalid_target", vErr.Error())
				return
			}
			exchangeCtx = services.WithOAuthResource(exchangeCtx, req.Audience)
		}
		// Linkerd-derived SPIFFE identity binding for the IAP→BFF bridge
		// (RFC 7800-style cnf.spiffe claim). The Linkerd sidecar stamps
		// `l5d-client-id` on every inbound HTTP request with the caller's
		// SPIFFE URI after the inter-pod mTLS handshake. We stash it on
		// the exchange context; generateTokens reads it back and emits
		// `cnf.spiffe` on the issued token. Receivers cross-check the
		// claim against their OWN inbound `l5d-client-id` to detect token
		// replay across workloads in the mesh.
		//
		// Scoped to the token-exchange grant: other grants don't
		// necessarily traverse Linkerd (e.g. user-facing /auth/login
		// posting from a browser through the gateway), so attaching a
		// SPIFFE binding there would either be wrong or block legitimate
		// non-mesh callers.
		if l5dID := c.GetHeader("l5d-client-id"); l5dID != "" {
			exchangeCtx = services.WithSpiffeID(exchangeCtx, l5dID)
		}
		var scopes []string
		if req.Scope != "" {
			scopes = strings.Split(req.Scope, " ")
		}
		if req.TargetTenantID != "" {
			// Tenant token exchange: same grant, different trust model
			// (active membership in the target tenant). Never issues a
			// refresh token.
			response, err = h.service.TenantTokenExchange(
				exchangeCtx,
				client,
				req.SubjectToken,
				req.SubjectTokenType,
				req.RequestedTokenType,
				req.TargetTenantID,
				scopes,
			)
		} else {
			response, err = h.service.TokenExchangeGrant(
				exchangeCtx,
				client,
				req.SubjectToken,
				req.SubjectTokenType,
				req.RequestedTokenType,
				scopes,
			)
		}
		if err == nil && response != nil {
			// RFC 8693 §2.2.1 mandates `issued_token_type` on a
			// successful exchange. Set unconditionally for the
			// exchange path — every other grant gets the omitempty
			// default ("").
			response.IssuedTokenType = tokenTypeAccessToken
			// Refresh-token semantics depend on the subject_token_type:
			//
			//   - :access_token (legacy internal narrowing path) — no
			//     refresh issued. The exchange is a narrowing of an
			//     existing session, not a fresh login event; emitting
			//     a refresh token here would let callers
			//     indefinitely re-narrow past the original session's
			//     idle/absolute timeouts.
			//
			//   - :jwt (external IdP bridge — Talon → BFF) — refresh
			//     IS issued because for the BFF this exchange IS the
			//     fresh login event. Without a refresh token the BFF
			//     would have to round-trip back through Talon every
			//     time its access token expires (15min), which would
			//     mean re-doing the OIDC dance behind the user every
			//     quarter-hour. Industry pattern: Microsoft Entra OBO,
			//     Keycloak 26.2 standard token exchange, Auth0, Duende
			//     BFF, Curity Token Handler all issue refresh tokens
			//     on this path.
			if req.SubjectTokenType != subjectTokenTypeJWT {
				response.RefreshToken = ""
			}
		}
	default:
		h.tokenError(c, "unsupported_grant_type", "grant_type not supported")
		return
	}

	if err != nil {
		// RFC 9449 §7.1 — invalid_dpop_proof is the canonical error
		// for "this scope demanded a DPoP-bound token and you didn't
		// send a proof". Map the sentinel before the generic switch
		// so SDKs that recognise the error code can drive the
		// retry-with-proof flow.
		if errors.Is(err, services.ErrDPoPRequired) {
			h.tokenError(c, "invalid_dpop_proof", err.Error())
			return
		}
		if errors.Is(err, services.ErrTenantExchangeRateLimited) {
			c.JSON(http.StatusTooManyRequests, models.OAuthErrorResponse{
				Error:            "slow_down",
				ErrorDescription: "too many tenant token exchanges; retry later",
			})
			return
		}
		// Suspended tenant (R1-GAPS row 27): stable `tenant_suspended` code, 403.
		if respondIfTenantSuspended(c, err) {
			return
		}
		errStr := err.Error()
		switch {
		case strings.HasPrefix(errStr, "invalid_grant:"):
			h.tokenError(c, "invalid_grant", strings.TrimPrefix(errStr, "invalid_grant: "))
		case strings.HasPrefix(errStr, "unauthorized_client:"):
			h.tokenError(c, "unauthorized_client", strings.TrimPrefix(errStr, "unauthorized_client: "))
		case strings.HasPrefix(errStr, "invalid_request:"):
			h.tokenError(c, "invalid_request", strings.TrimPrefix(errStr, "invalid_request: "))
		case strings.HasPrefix(errStr, "invalid_scope:"):
			h.tokenError(c, "invalid_scope", strings.TrimPrefix(errStr, "invalid_scope: "))
		case strings.HasPrefix(errStr, "insufficient_user_authentication:"):
			// RFC 9470: the subject token's authentication is too weak for the
			// requested tenant; the client re-authenticates with MFA.
			h.tokenError(c, "insufficient_user_authentication", strings.TrimPrefix(errStr, "insufficient_user_authentication: "))
		case strings.HasPrefix(errStr, "invalid_target:"):
			h.tokenError(c, "invalid_target", strings.TrimPrefix(errStr, "invalid_target: "))
		case strings.HasPrefix(errStr, "access_denied:"):
			h.tokenError(c, "access_denied", strings.TrimPrefix(errStr, "access_denied: "))
		default:
			// server_error-prefixed and every unclassified error: internal
			// detail (DB errors, signer failures) stays in the log, never in
			// the response.
			h.logger.Error("oauth token request failed", zap.String("grant_type", req.GrantType), zap.Error(err))
			h.tokenError(c, "server_error", "internal error")
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

// UserInfo returns the authenticated user's info
// @Summary OpenID Connect UserInfo Endpoint
// @Description Returns claims about the authenticated user based on the access token scopes.
// @Tags OAuth2/OIDC
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "User claims"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Router /oauth/userinfo [get]
func (h *OAuthProviderHandler) UserInfo(c *gin.Context) {
	// RequireAuth middleware validated the bearer token and populated
	// CurrentUserKey + "user_id". It does NOT set a full *models.User
	// (only the claim-derived CurrentUser view), so look up user_id from
	// the context and let the service fetch the full record from the
	// repository. Reading a non-existent "user" key was the historical
	// cause of /oauth/userinfo always returning 401 `unauthorized`,
	// which in turn broke Pomerium OIDC sign-in at the authenticate
	// callback's userinfo step.
	userID := middleware.GetCurrentUserID(c)
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	scopesI, _ := c.Get("scopes")
	scopes, _ := scopesI.([]string)
	if scopes == nil {
		scopes = []string{"openid", "profile", "email"}
	}

	response, err := h.service.GetUserInfoByID(c.Request.Context(), *userID, scopes)
	if err != nil {
		h.logger.Warn("UserInfo lookup failed", zap.Stringer("user_id", *userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInvalidUserContext})
		return
	}
	c.JSON(http.StatusOK, response)
}

// Revoke handles token revocation (RFC 7009)
// @Summary Revoke Token
// @Description Revokes an access or refresh token. Always returns 200 per RFC 7009.
// @Tags OAuth2/OIDC
// @Accept application/x-www-form-urlencoded
// @Param token formData string true "Token to revoke"
// @Param token_type_hint formData string false "Token type hint" Enums(access_token, refresh_token)
// @Param client_id formData string false "Client ID"
// @Param client_secret formData string false "Client secret"
// @Success 200 "Token revoked"
// @Failure 401 {object} models.ErrorResponse "Invalid client"
// @Router /oauth/revoke [post]
func (h *OAuthProviderHandler) Revoke(c *gin.Context) {
	var req models.OAuthRevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Authenticate client
	tokenReq := &models.OAuthTokenRequest{}
	tokenReq.ClientID = c.PostForm("client_id")
	tokenReq.ClientSecret = c.PostForm("client_secret")

	client, err := h.authenticateClient(c, tokenReq)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	// Revoke token (always return 200 even if token doesn't exist)
	_ = h.service.RevokeToken(c.Request.Context(), client, req.Token, req.TokenTypeHint)
	c.Status(http.StatusOK)
}

// Introspect handles token introspection (RFC 7662).
//
// Conformance contract — see services/oauth_provider_service_tokens.go
// (IntrospectToken) for the per-token logic. The handler enforces the
// transport-level requirements:
//
//   - 400 invalid_request when `token` is missing.
//   - 401 invalid_client when the caller fails client_secret_basic /
//     client_secret_post authentication.
//   - 401 invalid_client for **public clients** (per Keycloak's confidential-
//     only policy and the discovery field
//     introspection_endpoint_auth_methods_supported, which advertises only
//     client_secret_*). Public-client introspection is the canonical
//     token-fingerprinting vector and is rejected at the boundary.
//   - 200 with `{active: …}` for every authenticated request (including
//     unknown / revoked / expired / cross-client tokens) — RFC 7662 §2.2
//     forbids leaking token state via status code.
//
// @Summary Introspect Token
// @Description Validates a token per RFC 7662. Confidential clients only.
// @Tags OAuth2/OIDC
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param token formData string true "Token to introspect"
// @Param token_type_hint formData string false "Token type hint" Enums(access_token, refresh_token)
// @Param client_id formData string false "Client ID"
// @Param client_secret formData string false "Client secret"
// @Success 200 {object} models.OAuthIntrospectResponse "Token metadata"
// @Failure 401 {object} models.ErrorResponse "Invalid client / public client rejected"
// @Router /oauth/introspect [post]
func (h *OAuthProviderHandler) Introspect(c *gin.Context) {
	var req models.OAuthIntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	tokenReq := &models.OAuthTokenRequest{}
	tokenReq.ClientID = c.PostForm("client_id")
	tokenReq.ClientSecret = c.PostForm("client_secret")

	client, err := h.authenticateClient(c, tokenReq)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": err.Error()})
		return
	}

	// Reject public clients per RFC 7662 §2.1 + Keycloak/Curity baseline.
	// authenticateClient lets public clients through with no secret, so we
	// gate explicitly here rather than mutate the auth helper (which is
	// also used by /oauth/token, where public clients are first-class).
	if client.IsPublic {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "introspection requires a confidential client",
		})
		return
	}

	resp := h.service.IntrospectToken(c.Request.Context(), req.Token, req.TokenTypeHint, client)
	c.JSON(http.StatusOK, resp)
}

// ==================== OAuth Login & Consent Pages ====================

const csrfCookieName = "falcon_oauth_csrf"

// generateCSRFToken generates a random CSRF token, sets it as a short-lived cookie, and returns it.
func generateCSRFToken(c *gin.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	token := hex.EncodeToString(b)

	domain := getCookieDomain(c)
	secure := isSecureEnvironment()
	sameSite := http.SameSiteStrictMode
	if !secure {
		sameSite = http.SameSiteNoneMode
	}
	c.SetSameSite(sameSite)
	c.SetCookie(csrfCookieName, token, 600, "/oauth/", domain, secure, true) // 10 min
	return token, nil
}

// validateCSRFToken validates the CSRF token from form against the cookie.
// Uses constant-time comparison to prevent timing side-channel attacks.
func validateCSRFToken(c *gin.Context, formToken string) bool {
	cookie, err := c.Cookie(csrfCookieName)
	if err != nil || cookie == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(formToken)) == 1
}

// scopeDescription returns a human-readable description for an OIDC scope.
func scopeDescription(scope string) string {
	descriptions := map[string]string{
		"openid":         "Verify your identity",
		"profile":        "Access your name and profile info",
		"email":          "Access your email address",
		"offline_access": "Stay signed in on your behalf",
		"address":        "Access your address",
		"phone":          "Access your phone number",
	}
	if d, ok := descriptions[scope]; ok {
		return d
	}
	return "Access: " + scope
}

// ScopeInfo holds a scope name and description for template rendering.
type ScopeInfo struct {
	Name        string
	Description string
}

// writeOAuthHTMLRedirect issues a 302 with an HTML body and explicit
// `Content-Type: text/html; charset=utf-8`.
//
// Why we don't use a bare `c.Redirect`: gin's c.Redirect (and stdlib
// http.Redirect for POST) writes a zero-length body with no Content-Type.
// Combined with the global APISecurityHeaders middleware adding
// `X-Content-Type-Options: nosniff`, Safari iOS refuses to treat the 302
// as an HTML navigation when the redirect chain crosses origins
// (id.example.com → auth-pomerium.internal.example.com → per-route upstream).
// Instead it prompts the user to DOWNLOAD the target URL as a file.
//
// Writing the same minimal body stdlib uses for GET requests, with an
// explicit text/html Content-Type, makes every browser treat the response
// as an HTML navigation. See 4a1e5d4 for the original fix on POST
// /oauth/login — this helper applies the same pattern uniformly across
// every cross-origin OAuth redirect site (Authorize success, post-logout
// redirect, error redirect to RP).
func writeOAuthHTMLRedirect(c *gin.Context, redirectURL string) {
	body := `<html><head><title>Found</title></head><body><a href="` +
		template.HTMLEscapeString(redirectURL) + `">Found</a>.</body></html>`
	c.Header(hdrOAuthContentType, contentTypeHTMLCharset)
	c.Redirect(http.StatusFound, redirectURL)
	_, _ = c.Writer.WriteString(body)
}

// buildAuthorizeURLFromRequest serialises a parsed OAuthAuthorizeRequest
// back into a relative /oauth/authorize URL carrying every front-channel
// parameter. Used to construct post-login bounce URLs for requests that
// arrived via RFC 9126 PAR: the inbound `request_uri` has already been
// consumed (single-use) by ResolvePARRequest, so we MUST NOT echo it
// back — re-resolving the deleted entry would surface as
// "request_uri not found or expired" after the login flow completes.
//
// Output mirrors the parameter set the OAuth2 spec accepts on the
// canonical inline-params path. Optional fields are omitted when empty
// to keep the URL short and prevent ambiguous parsing (e.g. an empty
// `nonce=` would be rejected by clients that require it).
func buildAuthorizeURLFromRequest(req *models.OAuthAuthorizeRequest) string {
	q := url.Values{}
	q.Set("response_type", req.ResponseType)
	q.Set("client_id", req.ClientID)
	q.Set("redirect_uri", req.RedirectURI)
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	if req.Nonce != "" {
		q.Set("nonce", req.Nonce)
	}
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "" {
		q.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	if req.AcrValues != "" {
		q.Set("acr_values", req.AcrValues)
	}
	if req.MaxAge != nil {
		q.Set("max_age", strconv.Itoa(*req.MaxAge))
	}
	if req.Prompt != "" {
		q.Set("prompt", req.Prompt)
	}
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	if req.LoginContext != "" {
		q.Set("login_context", req.LoginContext)
	}
	if req.Display != "" {
		q.Set("display", req.Display)
	}
	if req.Tenant != "" {
		q.Set("tenant", req.Tenant)
	}
	if req.Resource != "" {
		q.Set("resource", req.Resource)
	}
	if req.AuthorizationDetails != "" {
		q.Set("authorization_details", req.AuthorizationDetails)
	}
	return "/oauth/authorize?" + q.Encode()
}

// LoginPage renders the login form for the OAuth flow
// GET /oauth/login
func (h *OAuthProviderHandler) LoginPage(c *gin.Context) {
	redirect := c.Query("redirect")

	// Validate redirect is a relative URL whose path is exactly /oauth/authorize
	// (shared with the signup continuation; a bare prefix match let
	// "/oauth/authorize-x" and dot-segment paths through).
	if _, err := services.ParseAuthorizeContinuation(redirect); err != nil {
		redirect = ""
	}

	// Tier-1 universal login: when OAUTH_LOGIN_REDIRECT_URL is set, hand the
	// browser off to the dedicated login UI app (apps/login on id.example.com)
	// instead of rendering the in-process Go template. The target sees the
	// authorize-continuation URL on `?redirect=` and navigates the browser
	// back there once the falcon_idp_session cookie is set by /api/v1/auth/login.
	//
	// Empty / unset preserves the legacy template flow — safe default until
	// apps/login is deployed and routed at the configured path.
	if loginAppURL := strings.TrimSpace(os.Getenv("OAUTH_LOGIN_REDIRECT_URL")); loginAppURL != "" {
		target := loginAppURL
		if redirect != "" {
			sep := "?"
			if strings.Contains(loginAppURL, "?") {
				sep = "&"
			}
			target = loginAppURL + sep + "redirect=" + url.QueryEscape(redirect)

			// Surface login_hint / login_context from the original
			// /oauth/authorize request as first-class query params on the
			// apps/login URL, in addition to leaving them inside the
			// embedded `redirect`. apps/login's /login page already
			// supports pre-filling via `?email=` (useLoginFlow's
			// initialEmail) — login_hint (OIDC Core 1.0 §3.1.2.1) is the
			// standard carrier for that value, so we translate it here
			// rather than teaching every RP-side caller a bespoke param
			// name. login_context is our own presentation-only extension
			// (see OAuthAuthorizeRequest.LoginContext) forwarded verbatim
			// for the login app to pick copy with — never used for any
			// authorization decision.
			if u, err := url.Parse(redirect); err == nil {
				if hint := u.Query().Get("login_hint"); hint != "" {
					target += "&email=" + url.QueryEscape(hint) + "&login_hint=" + url.QueryEscape(hint)
				}
				if lc := u.Query().Get("login_context"); lc != "" {
					target += "&login_context=" + url.QueryEscape(lc)
				}
			}
		}
		// HTML-bodied redirect — Safari iOS download-prompt fix.
		writeOAuthHTMLRedirect(c, target)
		return
	}

	// Extract tenant_id from redirect URL query params, the ?tenant= hint, or header.
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" && redirect != "" {
		if u, err := url.Parse(redirect); err == nil {
			tenantID = u.Query().Get("tenant_id")
			// Fall back to the ?tenant= slug/UUID hint carried in the original authorize URL.
			if tenantID == "" {
				tenantID = u.Query().Get("tenant")
			}
		}
	}

	csrfToken, err := generateCSRFToken(c)
	if err != nil {
		h.logger.Error(msgOAuthFailedCSRFToken, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalError})
		return
	}

	tmpl, err := template.ParseFS(templates.FS, "login.html", "acmeapp-mark.html")
	if err != nil {
		h.logger.Error("Failed to parse login template", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalError})
		return
	}

	c.Header(hdrOAuthContentType, contentTypeHTMLCharset)
	c.Status(http.StatusOK)
	loginHint := loginHintFrom(c.Query("login_hint"), redirect)
	if err := tmpl.Execute(c.Writer, map[string]string{
		"Brand":            hostedBrand(redirect),
		"Redirect":         redirect,
		"TenantID":         tenantID,
		"Error":            c.Query("error"),
		"CSRFToken":        csrfToken,
		"LoginHint":        loginHint,
		"ChangeAccountURL": changeAccountURL(redirect),
	}); err != nil {
		h.logger.Error("Failed to execute login template", zap.Error(err))
	}
}

// LoginSubmit handles the login form submission
// POST /oauth/login
func (h *OAuthProviderHandler) LoginSubmit(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")
	tenantID := c.PostForm("tenant_id")
	csrfToken := c.PostForm("csrf_token")

	// Validate CSRF
	if !validateCSRFToken(c, csrfToken) {
		h.renderLoginError(c, redirect, tenantID, "Invalid or expired form. Please try again.")
		return
	}

	// Validate redirect to prevent open redirect
	if redirect == "" || !strings.HasPrefix(redirect, "/oauth/authorize") {
		h.renderLoginError(c, "", tenantID, "Invalid redirect URL.")
		return
	}

	ipAddress := GetClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	loginReq := &models.LoginRequest{
		Username: username,
		Password: password,
		TenantID: tenantID,
	}

	// Also try X-Tenant-ID header if not in form
	if loginReq.TenantID == "" {
		tid := middleware.GetTenantID(c)
		if tid != uuid.Nil {
			loginReq.TenantID = tid.String()
		}
	}

	response, err := h.authService.Login(c.Request.Context(), loginReq, ipAddress, userAgent)
	if err != nil {
		// Username deliberately not logged: it is attacker-controlled input and
		// PII, and a mistyped password would otherwise leak it into logs.
		h.logger.Warn("OAuth login failed", zap.String("ip", ipAddress), zap.Error(err))
		h.renderLoginError(c, redirect, tenantID, "Invalid email or password.")
		return
	}

	// If MFA is required, show error directing user to complete MFA via main app
	if response.RequiresMFA {
		h.renderLoginError(c, redirect, tenantID, "Multi-factor authentication is required. Please sign in through the main application first.")
		return
	}

	// Set auth cookie for the browser session
	if response.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if response.ExpiresIn > 0 {
			accessTTL = time.Duration(response.ExpiresIn) * time.Second
		}
		setAuthCookies(c, response.AccessToken, accessTTL)
	}

	// Establish a long-lived IdP SSO session so the user is not prompted to log in
	// again when a different OIDC client initiates an /oauth/authorize flow within
	// the same browser session.  The cookie value is an opaque UUID; the actual
	// identity is stored in Redis and never exposed to JavaScript (HttpOnly).
	if h.sessionCache != nil && response.User != nil {
		idpSessionID := uuid.New()
		// Surface the iam_user_sessions.id (carried as session_id in the
		// freshly-minted access token) so resolveIdpSessionCookie can
		// thread the canonical row id through to MFA step-up writes.
		// See pkg/redis/session_cache.go IdpSessionData.SessionID for
		// the full rationale.
		var sessRowID uuid.UUID
		if h.tokenService != nil {
			if tc, tErr := h.tokenService.ValidateAccessToken(response.AccessToken); tErr == nil && tc != nil {
				sessRowID = tc.SessionID
			}
		}
		if claims, vErr := h.service.ValidateAccessToken(response.AccessToken); sessRowID == uuid.Nil && vErr == nil {
			if sidRaw, ok := claims["session_id"].(string); ok {
				if parsed, pErr := uuid.Parse(sidRaw); pErr == nil {
					sessRowID = parsed
				}
			}
		}
		if err := h.sessionCache.SetIdpSession(c.Request.Context(), idpSessionID, &redispkg.IdpSessionData{
			UserID:    response.User.ID,
			TenantID:  response.User.TenantID,
			Username:  response.User.Username,
			Email:     response.User.Email,
			AuthTime:  time.Now().Unix(),
			SessionID: sessRowID,
		}); err != nil {
			// Non-fatal: the primary access token cookie is already set.
			// SSO will degrade to re-prompting on next authorize rather than failing.
			h.logger.Warn("failed to store IdP session in Redis", zap.Error(err))
		} else {
			// Attributes live in middleware.SetIdpSessionCookie (shared with
			// establishIdpSession and the sliding re-issue).
			middleware.SetIdpSessionCookie(c, idpSessionID.String(), 7*24*time.Hour)
		}
	}

	// Redirect back to the authorize endpoint.
	//
	// HTML-bodied redirect — Safari iOS download-prompt fix; see
	// writeOAuthHTMLRedirect for the rationale.
	writeOAuthHTMLRedirect(c, redirect)
}

// maxLoginHintLen mirrors the binding on OAuthAuthorizeRequest.LoginHint.
const maxLoginHintLen = 254

// loginHintFrom returns the OIDC login_hint (OIDC Core 1.0 §3.1.2.1) to echo
// on the hosted login page: the explicit /oauth/login param, else the one
// carried by the (already validated) authorize continuation. It is only ever
// echoed back verbatim (HTML-escaped by the template) and never used to look
// anything up, so it cannot be used to probe account existence. Control
// characters and over-long values are dropped.
func loginHintFrom(explicit, redirect string) string {
	hint := explicit
	if hint == "" {
		if u, err := url.Parse(redirect); err == nil {
			hint = u.Query().Get("login_hint")
		}
	}
	hint = strings.TrimSpace(hint)
	if hint == "" || len(hint) > maxLoginHintLen {
		return ""
	}
	for _, r := range hint {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return hint
}

// changeAccountURL is the "Use a different account" target: the same login
// page with login_hint removed from the authorize continuation.
func changeAccountURL(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil || redirect == "" {
		return "/oauth/login"
	}
	q := u.Query()
	q.Del("login_hint")
	u.RawQuery = q.Encode()
	return "/oauth/login?redirect=" + url.QueryEscape(u.String())
}

// renderLoginError re-renders the login page with an error message.
func (h *OAuthProviderHandler) renderLoginError(c *gin.Context, redirect, tenantID, errMsg string) {
	csrfToken, err := generateCSRFToken(c)
	if err != nil {
		h.logger.Error(msgOAuthFailedCSRFToken, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalError})
		return
	}

	tmpl, err := template.ParseFS(templates.FS, "login.html", "acmeapp-mark.html")
	if err != nil {
		h.logger.Error("Failed to parse login template", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalError})
		return
	}

	c.Header(hdrOAuthContentType, contentTypeHTMLCharset)
	c.Status(http.StatusOK)
	if err := tmpl.Execute(c.Writer, map[string]string{
		"Brand":     hostedBrand(redirect),
		"Redirect":  redirect,
		"TenantID":  tenantID,
		"Error":     errMsg,
		"CSRFToken": csrfToken,
	}); err != nil {
		h.logger.Error("Failed to execute login error template", zap.Error(err))
	}
}

// ConsentPage renders the consent screen for third-party apps
// GET /oauth/consent
func (h *OAuthProviderHandler) ConsentPage(c *gin.Context) {
	// Mirror /oauth/authorize: if the user isn't authenticated yet,
	// bounce to /oauth/login with the consent URL as the return path.
	// This handler is mounted with OptionalAuth so the SSO session
	// cookie is accepted; only when neither cookie resolves a user
	// do we redirect to login. The consent endpoint can be reached
	// directly via /oauth/authorize's sensitive-scope override even
	// before a falcon_access_token cookie has been minted.
	if _, exists := c.Get("user_id"); !exists {
		safeRedirect := security.ValidateRedirectURL(c.Request.URL.String(), security.RedirectValidationConfig{
			AllowRelativePaths: true,
			DefaultPath:        "/dashboard",
		})
		c.Redirect(http.StatusFound, "/oauth/login?redirect="+url.QueryEscape(safeRedirect))
		return
	}

	clientID := c.Query("client_id")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	redirectURI := c.Query("redirect_uri")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	responseType := c.Query("response_type")

	client, err := h.service.GetClientByClientID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client"})
		return
	}

	// Build scope info list
	requestedScopes := strings.Split(scope, " ")
	var scopeInfos []ScopeInfo
	for _, s := range requestedScopes {
		if s != "" {
			scopeInfos = append(scopeInfos, ScopeInfo{
				Name:        s,
				Description: scopeDescription(s),
			})
		}
	}

	// RFC 7591 §2 — render the registered branding metadata so the
	// end-user can identify the relying party. Any field the client
	// didn't register stays empty and the template suppresses its row.
	derefOrEmpty := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	clientLogo := derefOrEmpty(client.LogoURL)
	clientURI := derefOrEmpty(client.ClientURI)
	tosURL := derefOrEmpty(client.TosURL)
	policyURL := derefOrEmpty(client.PolicyURL)
	contactEmail := derefOrEmpty(client.ContactEmail)

	csrfToken, err := generateCSRFToken(c)
	if err != nil {
		h.logger.Error(msgOAuthFailedCSRFToken, zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalError})
		return
	}

	tmpl, err := template.ParseFS(templates.FS, "consent.html")
	if err != nil {
		h.logger.Error("Failed to parse consent template", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalError})
		return
	}

	data := map[string]interface{}{
		"ClientID":            clientID,
		"ClientName":          client.Name,
		"ClientLogo":          clientLogo,
		"ClientURI":           clientURI,
		"TosURL":              tosURL,
		"PolicyURL":           policyURL,
		"ContactEmail":        contactEmail,
		"Scopes":              scopeInfos,
		"Scope":               scope,
		"State":               state,
		"Nonce":               nonce,
		"RedirectURI":         redirectURI,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"ResponseType":        responseType,
		"CSRFToken":           csrfToken,
	}

	c.Header(hdrOAuthContentType, contentTypeHTMLCharset)
	c.Status(http.StatusOK)
	if err := tmpl.Execute(c.Writer, data); err != nil {
		h.logger.Error("Failed to execute consent template", zap.Error(err))
	}
}

// EndSession handles OIDC RP-Initiated Logout
// @Summary OIDC RP-Initiated Logout
// @Description Ends the user session and optionally redirects to a post-logout URI per OIDC RP-Initiated Logout spec.
// @Tags OAuth2/OIDC
// @Param id_token_hint query string false "ID token for session identification"
// @Param post_logout_redirect_uri query string false "URI to redirect after logout"
// @Param state query string false "State parameter"
// @Param client_id query string false "Client ID"
// @Success 302 "Redirect to post-logout URI"
// @Success 200 "Logged out page"
// @Router /oauth/logout [get]
func (h *OAuthProviderHandler) EndSession(c *gin.Context) {
	idTokenHint := c.Query("id_token_hint")
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	state := c.Query("state")
	clientIDParam := c.Query("client_id")
	client, validHint := h.resolveEndSessionClient(c, idTokenHint, clientIDParam)

	// Order matters:
	//   1. Read the falcon_idp_session cookie BEFORE clearing it
	//      (clearAuthCookies + clearIdpSessionCookie below).
	//   2. Invalidate the corresponding Redis sessionCache entry so
	//      a stolen/replayed cookie can't resurrect the session.
	//   3. Clear cookies on the response. With BOTH cleared
	//      (falcon_access_token + falcon_idp_session) the next
	//      /oauth/authorize cannot auto-consent — the user MUST
	//      re-authenticate.
	//
	// Pre-fix bug (talon!6 surfaced this): EndSession was clearing only
	// the access/refresh tokens via clearAuthCookies. The
	// falcon_idp_session cookie persisted; any subsequent /oauth/
	// authorize from the same browser silently re-issued an auth_code
	// because the SSO middleware (internal/middleware/auth.go
	// LookupSession) found a valid session in Redis. End users saw
	// "logout doesn't work" — they'd click logout, return to the same
	// app, and be silently re-authenticated.
	//
	// Front-Channel Logout: we ALSO need to capture the IdP session's
	// (sid, tenantID) BEFORE the Redis entry is deleted so we can emit
	// per-RP iframes scoped to this session. The iframe URL carries
	// `iss` + `sid` ONLY (FCL §3) — never any session secret.
	revokedIdpSessions := map[uuid.UUID]bool{}
	var (
		idpSid     string
		idpTenant  uuid.UUID
		hasIdpData bool
	)
	if cookieVal, err := c.Cookie("falcon_idp_session"); err == nil && cookieVal != "" {
		if sessionID, parseErr := uuid.Parse(cookieVal); parseErr == nil && h.sessionCache != nil {
			if data, lookupErr := h.sessionCache.GetIdpSession(c.Request.Context(), sessionID); lookupErr == nil && data != nil {
				idpSid = sessionID.String()
				idpTenant = data.TenantID
				hasIdpData = true
				// A VALID id_token_hint makes this an authenticated, explicit
				// RP-initiated logout: end the iam_sessions row (which sweeps
				// the tokens bound to it and their families) and the tokens
				// bound to the opaque idp id. Without a valid hint this URL
				// is a bare GET anyone can make a victim's browser load
				// (logout CSRF), so it only tears down the browser's own
				// cookie + Redis entry, as before. Best effort: the teardown
				// below must still run.
				if validHint {
					h.endLoginSession(c, sessionID, data.SessionID, data.UserID)
					revokedIdpSessions[sessionID] = true
				}
			}
			if delErr := h.sessionCache.EndIdpSession(c.Request.Context(), sessionID); delErr != nil {
				h.logger.Warn("EndSession: DeleteIdpSession failed",
					zap.String("session_id", sessionID.String()),
					zap.Error(delErr))
				// Don't fail the logout — cookie clear below is still
				// effective for the current browser; the Redis entry
				// will TTL-expire in 7d worst-case.
			}
		}
	}

	// Valid hint but no (or a different) Redis entry: the hint itself names
	// the session, so revoke the tokens bound to its sid claim.
	if validHint {
		if hintSID, subject, ok := h.logoutHintSID(idTokenHint); ok && !revokedIdpSessions[hintSID] && h.sessionTerminator != nil {
			if err := h.sessionTerminator.EndHintedSession(c.Request.Context(), hintSID, subject); err != nil {
				h.logger.Warn("EndSession: end hinted session failed",
					zap.String("session_id", hintSID.String()), zap.Error(err))
			}
		}
	}

	clearAuthCookies(c)
	clearIdpSessionCookie(c)

	// A verified RP hint permits immediate logout, without a rendered
	// interstitial. Cookie clears are valid on HTTP redirects; server-side
	// invalidation above and prompt=login at the RP prevent SSO bounce-back.
	if validHint && client != nil && client.ClientID == "acmeapp-bff" && h.redirectAfterValidLogout(c, client, postLogoutRedirectURI, state) {
		return
	}
	if renderAcmeAppLogoutFallback(c, client, postLogoutRedirectURI) {
		return
	}

	// FCL iframe set — built only when we have an IdP session to scope to.
	// Without (sid, tenantID) we can't safely target session-required RPs,
	// so we skip the iframe render entirely rather than emit ambiguous URLs.
	var fclIFrames []services.FrontchannelLogoutIFrame
	if hasIdpData && h.fclService != nil {
		fclIFrames = h.fclService.BuildIFrames(c.Request.Context(), idpTenant, idpSid)
	}

	if h.tryPostLogoutRedirect(c, client, postLogoutRedirectURI, state, fclIFrames) {
		return
	}

	// No valid redirect — show a logged-out page (with FCL iframes when present)
	c.Header(hdrOAuthContentType, contentTypeHTMLCharset)
	c.Status(http.StatusOK)
	_, _ = c.Writer.WriteString(buildLoggedOutPage(fclIFrames))
}

// resolveEndSessionClient looks up the OAuthClient from the id_token_hint or client_id parameter.
// Returns nil when neither yields a valid client (non-fatal — cookies are still cleared).
func (h *OAuthProviderHandler) resolveEndSessionClient(c *gin.Context, idTokenHint, clientIDParam string) (*models.OAuthClient, bool) {
	if h.logoutService == nil {
		return nil, false
	}
	if idTokenHint != "" {
		client, subject, err := h.logoutService.EndSession(c.Request.Context(), idTokenHint)
		if err != nil {
			h.logger.Warn("EndSession: invalid id_token_hint", zap.Error(err))
		} else if client != nil && subject != nil && (clientIDParam == "" || clientIDParam == client.ClientID) {
			if cookie, err := c.Cookie("falcon_idp_session"); err == nil && h.sessionCache != nil {
				if sid, err := uuid.Parse(cookie); err == nil {
					if data, err := h.sessionCache.GetIdpSession(c.Request.Context(), sid); err != nil || (data != nil && data.UserID != *subject) {
						return client, false
					}
				}
			}
			return client, true
		}
	}
	if clientIDParam != "" {
		client, err := h.logoutService.GetClientByClientID(c.Request.Context(), clientIDParam)
		if err != nil {
			h.logger.Warn("EndSession: invalid client_id param", zap.Error(err))
		} else {
			return client, false
		}
	}
	return nil, false
}

// endLoginSession is the explicit-end action of a validly hinted RP-initiated
// logout. It revokes the tokens bound to the opaque idp session id and, when the
// iam_sessions row is known, ends that row with reason "logout" (which sweeps
// its tokens and rotation families in the same statement). Failures are logged,
// never fatal to the logout response.
func (h *OAuthProviderHandler) endLoginSession(c *gin.Context, idpSessionID, rowID, userID uuid.UUID) {
	if h.sessionTerminator == nil {
		return
	}
	ctx := c.Request.Context()
	if err := h.sessionTerminator.RevokeSessionTokens(ctx, idpSessionID, userID); err != nil {
		h.logger.Warn("EndSession: revoke session tokens failed",
			zap.String("session_id", idpSessionID.String()), zap.Error(err))
	}
	if rowID != uuid.Nil {
		if err := h.sessionTerminator.EndLoginSession(ctx, rowID, "logout"); err != nil {
			h.logger.Warn("EndSession: end session row failed",
				zap.String("session_id", rowID.String()), zap.Error(err))
		}
	}
}

// logoutHintSID returns the `sid` claim of a signature-verified id_token_hint.
func (h *OAuthProviderHandler) logoutHintSID(idTokenHint string) (uuid.UUID, uuid.UUID, bool) {
	if h.sessionTerminator == nil {
		return uuid.Nil, uuid.Nil, false
	}
	return h.sessionTerminator.LogoutHintSID(idTokenHint)
}

// redirectAfterValidLogout never trusts an unregistered URI and appends state
// with URL parsing (registered URIs may already have a query string).
func (h *OAuthProviderHandler) redirectAfterValidLogout(c *gin.Context, client *models.OAuthClient, target, state string) bool {
	if client == nil || target == "" {
		return false
	}
	for _, registered := range client.PostLogoutRedirectURIs {
		if registered != target {
			continue
		}
		u, err := url.Parse(target)
		if err != nil {
			return false
		}
		if state != "" {
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
		}
		c.Header("Cache-Control", "no-store")
		c.Redirect(http.StatusFound, u.String())
		return true
	}
	return false
}

// tryPostLogoutRedirect redirects to postLogoutRedirectURI if it is registered for the client.
// Returns true when the redirect was performed, false otherwise.
//
// IMPORTANT — same-origin meta-refresh, NOT a 302.
//
// EndSession's clearAuthCookies + clearIdpSessionCookie write
// Set-Cookie headers expiring the IdP cookies. When we returned a
// 302 here, Chromium followed the redirect cross-site to the RP's
// post_logout_redirect_uri and — observed in production 2026-04-28
// via the Playwright reproducer at
// talon/e2e/playwright/cookietrace.mjs — DID NOT apply the
// Set-Cookie clears across the cross-site navigation. The IdP
// cookies stayed alive on id.example.com, the RP's /login page
// auto-fired /api/auth/oidc-start, the still-valid falcon_idp_session
// silently re-authenticated, and the user landed back on /home.
// Symptom: "logout button just refreshes the page".
//
// A SAME-ORIGIN HTML response (200 from id.example.com) lets the
// browser commit the Set-Cookie clears against the *active*
// origin's cookie jar with no redirect-chain ambiguity. We then
// use a `<meta http-equiv="refresh" content="0;url=…">` tag to
// drive the cross-site navigation only AFTER the browser has
// finished processing the response — the meta-refresh fires at
// HTML-parse time, by which point the cookies are gone.
//
// `<noscript>` fallback link covers the very rare case where a
// browser disables both meta-refresh and JS; that user just clicks
// the link manually. Search-engine indexing is suppressed via
// `<meta name="robots">` so this transient page never lands in a
// crawl.
func (h *OAuthProviderHandler) tryPostLogoutRedirect(c *gin.Context, client *models.OAuthClient, postLogoutRedirectURI, state string, fclIFrames []services.FrontchannelLogoutIFrame) bool {
	if postLogoutRedirectURI == "" || client == nil {
		return false
	}
	for _, uri := range client.PostLogoutRedirectURIs {
		if uri == postLogoutRedirectURI {
			redirectURL := postLogoutRedirectURI
			if state != "" {
				redirectURL += "?state=" + url.QueryEscape(state)
			}
			esc := template.HTMLEscapeString(redirectURL)
			// JSON-encode the URL for the JS string literal — even though
			// HTMLEscape already neutralises HTML metacharacters, we still
			// need to defend against `</script>` mid-URL and quote
			// injection. JSON is the simplest safe encoding for a JS
			// string literal context.
			jsURL, _ := json.Marshal(redirectURL)
			// FCL §3 — render one <iframe> per RP BEFORE the cross-site
			// redirect fires. The iframes load in parallel; the JS
			// timeout below waits long enough for them to clear their
			// RP sessions before the navigation tears the iframes down.
			fclHTML, redirectDelayMS := renderFCLIFrames(fclIFrames)
			body := `<!DOCTYPE html><html><head><meta charset="UTF-8">` +
				`<meta name="robots" content="noindex, nofollow">` +
				`<title>Signing out…</title>` +
				`<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;` +
				`display:flex;align-items:center;justify-content:center;min-height:100vh;` +
				`background:#f5f5f7;color:#1d1d1f;}.card{background:#fff;border-radius:12px;` +
				`box-shadow:0 2px 16px rgba(0,0,0,0.08);padding:40px;text-align:center;max-width:400px;}` +
				`.logo{font-size:28px;font-weight:700;color:#0071e3;margin-bottom:12px;}` +
				`p{color:#6e6e73;font-size:15px;}a{color:#0071e3;}` +
				// Hide FCL iframes — they only need to load network
				// requests, not be visible. display:none is sufficient;
				// browsers still honour the load.
				`.fcl{display:none;}</style></head>` +
				`<body><div class="card"><div class="logo">Hexxlock</div>` +
				`<p>Signing you out…</p>` +
				`<noscript><meta http-equiv="refresh" content="0;url=` + esc + `">` +
				`<p>If you are not redirected, ` +
				`<a href="` + esc + `">click here</a>.</p></noscript>` +
				fclHTML +
				`<script>` +
				// Cookie-clear race protection (250ms minimum) PLUS
				// FCL settle window. The previous version used
				// `<meta http-equiv="refresh" content="0;…">` which
				// Chromium fires on HTML-parse start — that races the
				// cookie-jar write and was observed in production
				// (Playwright trace 2026-04-28) to leave
				// falcon_idp_session alive across the redirect, which
				// then silently re-authenticated the user. setTimeout
				// runs after the parser finishes, by which point cookie
				// processing has committed AND the FCL iframes have
				// had a chance to clear their RP sessions.
				`setTimeout(function(){window.location.replace(` + string(jsURL) + `);},` + strconv.Itoa(redirectDelayMS) + `);` +
				`</script>` +
				`</div></body></html>`
			c.Header(hdrOAuthContentType, contentTypeHTMLCharset)
			c.Status(http.StatusOK)
			_, _ = c.Writer.WriteString(body)
			return true
		}
	}
	return false
}

// fclMinRedirectDelayMS is the cookie-clear race-protection window
// (Chromium needs >= ~250ms after HTML parse to finalise Set-Cookie
// before a cross-site navigation). Used when there are no FCL iframes
// to wait on.
const fclMinRedirectDelayMS = 250

// fclIFrameSettleMS is added to the redirect delay per iframe so they
// have time to load and clear their RP sessions before the cross-site
// navigation discards the iframe DOM. Capped at fclMaxRedirectDelayMS
// to keep total logout latency tolerable.
const fclIFrameSettleMS = 750

// fclMaxRedirectDelayMS caps the total redirect delay so a misconfigured
// RP iframe URL doesn't stall the user's logout indefinitely.
const fclMaxRedirectDelayMS = 3000

// renderFCLIFrames returns the HTML fragment for the iframes plus the
// total delay (in milliseconds) the redirect script should wait before
// navigating. When iframes is empty the fragment is empty and only the
// minimum cookie-clear window applies.
//
// SECURITY: each Src is HTML-escaped via html/template before embedding.
// The Src has been pre-validated by FrontchannelLogoutService.BuildIFrames
// (HTTPS-only, query rebuilt to iss + sid only) — the escape here is
// defense-in-depth.
func renderFCLIFrames(iframes []services.FrontchannelLogoutIFrame) (string, int) {
	if len(iframes) == 0 {
		return "", fclMinRedirectDelayMS
	}
	var b strings.Builder
	for _, f := range iframes {
		// referrerpolicy=no-referrer prevents the iframe URL (which
		// contains sid) from being leaked via the Referer header to
		// other resources the iframe might load. The RP's own iframe
		// handler sees sid as a query param either way.
		// loading=eager forces the iframe to fire immediately rather
		// than lazy-load (which would defeat the cascade entirely
		// when the iframe is hidden via display:none).
		// HTML-escape the comment too so a hostile client_id in the
		// DB can't break out of the comment context.
		b.WriteString(`<!-- fcl: `)
		b.WriteString(template.HTMLEscapeString(f.ClientID))
		b.WriteString(` --><iframe class="fcl" loading="eager" referrerpolicy="no-referrer" src="`)
		b.WriteString(template.HTMLEscapeString(f.Src))
		b.WriteString(`"></iframe>`)
	}
	delay := fclMinRedirectDelayMS + fclIFrameSettleMS*len(iframes)
	if delay > fclMaxRedirectDelayMS {
		delay = fclMaxRedirectDelayMS
	}
	return b.String(), delay
}

// buildLoggedOutPage renders the no-redirect logout landing page,
// optionally with FCL iframes embedded (hidden via display:none) so the
// browser still drives the iframe cascade even when no RP supplied a
// post_logout_redirect_uri.
func buildLoggedOutPage(iframes []services.FrontchannelLogoutIFrame) string {
	fclHTML, delay := renderFCLIFrames(iframes)
	// After the front-channel-logout iframe cascade settles, bounce to the
	// centralized login UI (/oauth/login) instead of dead-ending on a
	// terminal "signed out" card — a logged-out operator almost always
	// wants to sign back in, and a static dead-end is poor UX. A registered
	// post_logout_redirect_uri still short-circuits this via
	// tryPostLogoutRedirect BEFORE we ever reach here, so this only changes
	// the previously-terminal fallback path. /oauth/login is a fixed
	// same-origin literal (no injection surface). <noscript> meta-refresh +
	// a visible link cover JS-disabled clients; the JS setTimeout waits out
	// the FCL settle window so RP sessions clear before we navigate away.
	return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Signed out — Hexxlock</title>` +
		`<noscript><meta http-equiv="refresh" content="0;url=/oauth/login"></noscript>` +
		`<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;` +
		`display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f5f7;color:#1d1d1f;}` +
		`.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,0.08);padding:40px;text-align:center;max-width:400px;}` +
		`.logo{font-size:28px;font-weight:700;color:#0071e3;margin-bottom:16px;}` +
		`p{color:#6e6e73;font-size:15px;margin:0 0 20px;}` +
		`.spinner{width:28px;height:28px;margin:0 auto;border:3px solid #e5e5ea;` +
		`border-top-color:#0071e3;border-radius:50%;animation:spin .8s linear infinite;}` +
		`@keyframes spin{to{transform:rotate(360deg);}}` +
		`a{display:inline-block;margin-top:20px;color:#0071e3;text-decoration:none;font-size:14px;}` +
		`.fcl{display:none;}</style></head>` +
		`<body><div class="card"><div class="logo">Hexxlock</div>` +
		`<p>You've been signed out. Taking you to sign in…</p>` +
		`<div class="spinner"></div>` +
		`<a href="/oauth/login">Continue to sign in</a></div>` +
		fclHTML +
		`<script>setTimeout(function(){window.location.replace("/oauth/login");},` + strconv.Itoa(delay) + `);</script>` +
		`</body></html>`
}

// consentParams holds the resolved parameters for ApproveConsent.
type consentParams struct {
	approved            string
	clientID            string
	redirectURI         string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	responseType        string
}

// ApproveConsent handles the consent approval from the consent form
// POST /oauth/consent
func (h *OAuthProviderHandler) ApproveConsent(c *gin.Context) {
	// SECURITY: Validate CSRF token to prevent cross-site consent approval attacks
	csrfToken := c.PostForm("csrf_token")
	if !validateCSRFToken(c, csrfToken) {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid_request", "error_description": "Invalid or expired form. Please try again."})
		return
	}

	params, ok := resolveConsentParams(c)
	if !ok {
		return // response already written
	}

	userUUID, ok := resolveConsentUserID(c)
	if !ok {
		return // response already written
	}

	client, err := h.service.GetClientByClientID(c.Request.Context(), params.clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client"})
		return
	}

	if params.approved != queryBoolTrue {
		handleConsentDenied(c, client, params.redirectURI, params.state)
		return
	}

	// Grant consent
	scopes := strings.Split(params.scope, " ")
	if err := h.service.GrantConsent(c.Request.Context(), userUUID, client.ID, scopes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	// Redirect back to /oauth/authorize to complete the code grant
	authorizeURL := fmt.Sprintf("/oauth/authorize?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=%s",
		url.QueryEscape(params.responseType),
		url.QueryEscape(params.clientID),
		url.QueryEscape(params.redirectURI),
		url.QueryEscape(params.scope),
		url.QueryEscape(params.state),
		url.QueryEscape(params.nonce),
		url.QueryEscape(params.codeChallenge),
		url.QueryEscape(params.codeChallengeMethod),
	)
	c.Redirect(http.StatusFound, authorizeURL)
}

// resolveConsentParams reads consent parameters from the POST form, falling back to JSON body.
// Returns (params, true) on success; writes a 400 response and returns (_, false) on failure.
func resolveConsentParams(c *gin.Context) (consentParams, bool) {
	p := consentParams{
		approved:            c.PostForm("approved"),
		clientID:            c.PostForm("client_id"),
		redirectURI:         c.PostForm("redirect_uri"),
		scope:               c.PostForm("scope"),
		state:               c.PostForm("state"),
		nonce:               c.PostForm("nonce"),
		codeChallenge:       c.PostForm("code_challenge"),
		codeChallengeMethod: c.PostForm("code_challenge_method"),
		responseType:        c.PostForm("response_type"),
	}
	if p.clientID != "" {
		return p, true
	}
	// Fall back to JSON body
	var req models.ConsentResponse
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return consentParams{}, false
	}
	p.clientID = c.Query("client_id")
	if req.Approved {
		p.approved = queryBoolTrue
	}
	p.state = req.State
	p.scope = strings.Join(req.Scopes, " ")
	return p, true
}

// resolveConsentUserID extracts the user UUID from the Gin context.
// Returns (uuid, true) on success; writes an error response and returns (uuid.Nil, false) on failure.
func resolveConsentUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}
	if uid, ok := userID.(uuid.UUID); ok {
		return uid, true
	}
	uidStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInvalidUserContext})
		return uuid.Nil, false
	}
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user ID"})
		return uuid.Nil, false
	}
	return uid, true
}

// handleConsentDenied responds to a denied consent request.
// It redirects to the registered redirect_uri with an access_denied error, or returns JSON.
func handleConsentDenied(c *gin.Context, client *models.OAuthClient, redirectURI, state string) {
	if redirectURI == "" {
		c.JSON(http.StatusOK, gin.H{
			"error":             "access_denied",
			"error_description": "User denied consent",
			"state":             state,
		})
		return
	}
	// Validate the redirect URI before using it (prevents open-redirect exfiltration).
	for _, registeredURI := range client.RedirectURIs {
		if registeredURI == redirectURI {
			denyURL := redirectURI + "?error=access_denied&error_description=User+denied+consent"
			if state != "" {
				denyURL += queryParamState + url.QueryEscape(state)
			}
			c.Redirect(http.StatusFound, denyURL)
			return
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error":             "invalid_request",
		"error_description": "redirect_uri does not match any registered redirect URI for this client",
	})
}

// ==================== Admin Client Management ====================

// ListClients lists all OAuth clients for the tenant
// @Summary List OAuth Clients
// @Description Returns paginated list of OAuth clients for the current tenant.
// @Tags OAuth2 Admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Items per page" default(20)
// @Success 200 {object} models.OAuthClientListResponse "List of clients"
// @Failure 400 {object} models.ErrorResponse "Bad request"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/admin/oauth-clients [get]
func (h *OAuthProviderHandler) ListClients(c *gin.Context) {
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	clients, total, err := h.service.ListClients(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list OAuth clients", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	// Convert to response
	var responses []models.OAuthClientResponse
	for _, client := range clients {
		responses = append(responses, *client.ToResponse())
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, models.OAuthClientListResponse{
		Clients:    responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// GetClient retrieves an OAuth client by ID
// @Summary Get OAuth Client
// @Description Returns an OAuth client by ID. Only returns clients belonging to the caller's tenant.
// @Tags OAuth2 Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client UUID"
// @Success 200 {object} models.OAuthClientResponse "Client details"
// @Failure 400 {object} models.ErrorResponse "Invalid ID"
// @Failure 404 {object} models.ErrorResponse "Not found"
// @Router /api/v1/admin/oauth-clients/{id} [get]
func (h *OAuthProviderHandler) GetClient(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	client, err := h.service.GetClient(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	c.JSON(http.StatusOK, client.ToResponse())
}

// GetClientByClientIDLookup retrieves an OAuth client by its client_id
// string (not UUID). Exposed only on the internal route group so the
// platform's ServiceClient provisioner can resolve a UUID for an
// existing row before calling PUT /:id, completing the "POST → 409 →
// GET-by-client-id → PUT" upsert flow without a workaround DELETE.
//
// The browser admin surface deliberately does NOT expose this — it
// already lists+filters via the LIST endpoint and works in UUID terms.
//
// @Summary Resolve OAuth client by client_id
// @Description Returns the OAuth client whose `client_id` string matches the path
// parameter. Tenant-scoped. 404 when not found or owned by another tenant.
// @Tags OAuth2 Admin (internal)
// @Produce json
// @Security BearerAuth
// @Param client_id path string true "Client ID string (e.g. svc-accounts)"
// @Success 200 {object} models.OAuthClientResponse "Client (no secret)"
// @Failure 404 {object} models.ErrorResponse "Not found"
// @Router /api/v1/internal/oauth-clients/by-client-id/{client_id} [get]
func (h *OAuthProviderHandler) GetClientByClientIDLookup(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	client, err := h.service.GetClientByClientID(c.Request.Context(), clientID)
	if err != nil || client == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	tenantID := middleware.GetTenantID(c)
	if client.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	c.JSON(http.StatusOK, client.ToResponse())
}

// CreateClient creates a new OAuth client
// @Summary Create OAuth Client
// @Description Creates a new OAuth client for the current tenant. Returns client secret only once.
// @Tags OAuth2 Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateOAuthClientRequest true "Client configuration"
// @Success 201 {object} models.OAuthClientResponse "Created client with secret"
// @Failure 400 {object} models.ErrorResponse "Validation error"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/admin/oauth-clients [post]
func (h *OAuthProviderHandler) CreateClient(c *gin.Context) {
	var req models.CreateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Grant-type-aware fields (redirect_uris, response_types) — see
	// CreateOAuthClientRequest.Validate header for rationale. Static
	// `binding:"required,min=1"` would block client_credentials-only
	// clients which have no callback.
	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Trust gate: is_first_party=true means "skip the OIDC consent
	// screen for any user of this client", which is a platform-level
	// trust statement, NOT a tenant-level one. Allowing a tenant admin
	// (browser admin route) to set it would let a compromised admin
	// promote a third-party app past consent, defeating the consent
	// model. Only the privileged /api/v1/internal/oauth-clients route
	// (mounted with middleware.TrustedRegistration()) sets the context
	// flag. See middleware/trusted_registration.go for the threat
	// model and the Okta TRUSTED-vs-REQUIRED parallel.
	if req.IsFirstParty && !c.GetBool(middleware.CtxKeyTrustedRegistration) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "trusted_registration_required",
			"error_description": "is_first_party=true can only be set via the privileged /api/v1/internal/oauth-clients route; the browser admin surface forces is_first_party=false",
		})
		return
	}

	if !c.GetBool(middleware.CtxKeyTrustedRegistration) {
		if err := services.ValidateTenantClientScopes(req.Scopes); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_scope", "error_description": err.Error()})
			return
		}
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID not found"})
		return
	}

	userID := h.getUserIDFromContext(c)

	client, secret, err := h.service.CreateClient(c.Request.Context(), tenantID, &req, userID)
	if err != nil {
		// 409 on caller-supplied client_id collision so the platform's
		// ServiceClient provisioner can distinguish "name is taken,
		// rotate the secret instead of re-creating" from a generic
		// 500. Error_description carries the requested id verbatim
		// for operator triage.
		if errors.Is(err, services.ErrClientIDConflict) {
			c.JSON(http.StatusConflict, gin.H{
				"error":             "client_id_conflict",
				"error_description": err.Error(),
			})
			return
		}
		if errors.Is(err, services.ErrTenantNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "tenant_not_found"})
			return
		}
		// Client-input validation failures: RFC 7591 §3.2.2 400.
		if respondClientValidationError(c, err) {
			return
		}
		h.logger.Error("Failed to create OAuth client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	response := client.ToResponseWithSecret(secret)
	c.JSON(http.StatusCreated, response)
}

// respondClientValidationError writes a 400 {"error","error_description"}
// (RFC 7591 §3.2.2) when err is a client-input validation error from the
// service and reports whether it did.
func respondClientValidationError(c *gin.Context, err error) bool {
	code, desc, ok := services.ClientValidationDescription(err)
	if !ok {
		return false
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": code, "error_description": desc})
	return true
}

// UpdateClient updates an OAuth client
// @Summary Update OAuth Client
// @Description Updates an existing OAuth client. Only updates clients belonging to the caller's tenant.
// @Tags OAuth2 Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client UUID"
// @Param request body models.UpdateOAuthClientRequest true "Updated configuration"
// @Success 200 {object} models.OAuthClientResponse "Updated client"
// @Failure 400 {object} models.ErrorResponse "Validation error"
// @Failure 404 {object} models.ErrorResponse "Not found"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/admin/oauth-clients/{id} [put]
func (h *OAuthProviderHandler) UpdateClient(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	// Verify client belongs to caller's tenant
	existing, err := h.service.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	var req models.UpdateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Trust gate (Update side): a client whose is_first_party=true was
	// previously set via the privileged route can NOT be flipped back
	// or forth from the tenant-admin surface, and a tenant-admin update
	// can NOT promote a previously-untrusted client to first-party.
	// Both directions go through this gate so the trust attribute is
	// only mutable from /api/v1/internal/oauth-clients/*. See
	// CreateClient + middleware/trusted_registration.go for rationale.
	if req.IsFirstParty != nil && !c.GetBool(middleware.CtxKeyTrustedRegistration) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "trusted_registration_required",
			"error_description": "is_first_party can only be mutated via the privileged /api/v1/internal/oauth-clients route; the browser admin surface treats is_first_party as read-only",
		})
		return
	}

	if !c.GetBool(middleware.CtxKeyTrustedRegistration) {
		if err := services.ValidateTenantClientScopes(req.Scopes); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_scope", "error_description": err.Error()})
			return
		}
	}

	userID := h.getUserIDFromContext(c)

	client, err := h.service.UpdateClient(c.Request.Context(), id, &req, userID)
	if err != nil {
		if errors.Is(err, services.ErrTenantNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "tenant_not_found"})
			return
		}
		if respondClientValidationError(c, err) {
			return
		}
		h.logger.Error("Failed to update OAuth client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	c.JSON(http.StatusOK, client.ToResponse())
}

// DeleteClient deletes an OAuth client
// @Summary Delete OAuth Client
// @Description Permanently deletes an OAuth client. Only deletes clients belonging to the caller's tenant.
// @Tags OAuth2 Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client UUID"
// @Success 200 {object} models.MessageResponse "Deletion confirmation"
// @Failure 400 {object} models.ErrorResponse "Invalid ID"
// @Failure 404 {object} models.ErrorResponse "Not found"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/admin/oauth-clients/{id} [delete]
func (h *OAuthProviderHandler) DeleteClient(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	// Verify client belongs to caller's tenant
	existing, err := h.service.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	if err := h.service.DeleteClient(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to delete OAuth client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OAuth client deleted successfully"})
}

// RegenerateSecret regenerates the client secret
// @Summary Regenerate Client Secret
// @Description Generates a new client secret. The old secret is immediately invalidated.
// @Tags OAuth2 Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client UUID"
// @Success 200 {object} map[string]string "New client secret (shown only once)"
// @Failure 400 {object} models.ErrorResponse "Invalid ID"
// @Failure 404 {object} models.ErrorResponse "Not found"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/admin/oauth-clients/{id}/regenerate-secret [post]
func (h *OAuthProviderHandler) RegenerateSecret(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	// Verify client belongs to caller's tenant
	existing, err := h.service.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	secret, err := h.service.RegenerateClientSecret(c.Request.Context(), id)
	if err != nil {
		h.logger.Error("Failed to regenerate client secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"client_secret": secret,
		"message":       "Client secret regenerated successfully. Store this securely, it won't be shown again.",
	})
}

// RevokeClientTokens revokes all tokens for a client
// @Summary Revoke All Client Tokens
// @Description Immediately invalidates all access and refresh tokens issued to a client.
// @Tags OAuth2 Admin
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client UUID"
// @Success 200 {object} models.MessageResponse "Confirmation"
// @Failure 400 {object} models.ErrorResponse "Invalid ID"
// @Failure 404 {object} models.ErrorResponse "Not found"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/admin/oauth-clients/{id}/revoke-tokens [post]
func (h *OAuthProviderHandler) RevokeClientTokens(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	// Verify client belongs to caller's tenant
	existing, err := h.service.GetClient(c.Request.Context(), id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}
	tenantID := middleware.GetTenantID(c)
	if existing.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": msgOAuthClientNotFound})
		return
	}

	if err := h.service.RevokeAllClientTokens(c.Request.Context(), id); err != nil {
		h.logger.Error("Failed to revoke client tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All tokens revoked successfully"})
}

// ==================== User Consent Management ====================

// GetMyConsents returns the authenticated user's consents
// @Summary List My Consents
// @Description Returns all OAuth consents granted by the authenticated user.
// @Tags OAuth2/OIDC
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "User consents"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/auth/consents [get]
func (h *OAuthProviderHandler) GetMyConsents(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Enriched projection — joins iam_oauth_clients (name, logo,
	// is_first_party→category) and iam_oauth_tokens (last_used_at) at
	// the repo layer so the user-facing "Connected Apps" page can
	// render real client metadata without N+1 follow-up fetches.
	consents, err := h.service.GetUserConsentsEnriched(c.Request.Context(), *userID)
	if err != nil {
		h.logger.Error("Failed to get user consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	c.JSON(http.StatusOK, gin.H{"consents": consents})
}

// RevokeMyConsent revokes the user's consent for a specific client
// @Summary Revoke My Consent
// @Description Revokes the authenticated user's consent for a specific OAuth client.
// @Tags OAuth2/OIDC
// @Produce json
// @Security BearerAuth
// @Param client_id path string true "OAuth Client UUID"
// @Success 200 {object} models.MessageResponse "Consent revoked"
// @Failure 400 {object} models.ErrorResponse "Invalid client ID"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 500 {object} models.ErrorResponse "Internal error"
// @Router /api/v1/auth/consents/{client_id} [delete]
func (h *OAuthProviderHandler) RevokeMyConsent(c *gin.Context) {
	userID := h.getUserIDFromContext(c)
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	clientIDStr := c.Param("client_id")
	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgOAuthInvalidClientID})
		return
	}

	if err := h.service.RevokeConsent(c.Request.Context(), *userID, clientID); err != nil {
		h.logger.Error("Failed to revoke consent", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": msgOAuthInternalErrorCap})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Consent revoked successfully"})
}

// ==================== Helper Functions ====================

func (h *OAuthProviderHandler) authenticateClient(c *gin.Context, req *models.OAuthTokenRequest) (*models.OAuthClient, error) {
	clientID := req.ClientID
	clientSecret := req.ClientSecret

	// Try Basic auth first
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				clientID = parts[0]
				clientSecret = parts[1]
			}
		}
	}

	// RFC 8705 §2.1 — Mutual TLS PKI-mode client authentication. When
	// the client has TLSClientAuthSubjectDN registered AND the proxy
	// forwarded a client certificate via X-Forwarded-Client-Cert, we
	// validate the cert's Subject DN against the registered value
	// INSTEAD of the client_secret check. This is the "the proxy
	// already validated the chain, we just verify the binding" model
	// every major IdP uses. Skips entirely for clients without a
	// registered DN — they continue to authenticate via
	// client_secret_basic / client_secret_post as before.
	if certHdr := c.GetHeader("X-Forwarded-Client-Cert"); certHdr != "" {
		// Pre-fetch the client so we can decide on the auth method.
		// If lookup fails we fall through to the secret-based path so
		// the canonical "invalid_client" error is emitted from a
		// single place (the service).
		preClient, lookupErr := h.service.GetClientByClientID(c.Request.Context(), clientID)
		if lookupErr == nil && preClient != nil &&
			preClient.TLSClientAuthSubjectDN != nil &&
			*preClient.TLSClientAuthSubjectDN != "" {
			cert, err := services.ParseClientCertFromHeader(certHdr)
			if err != nil {
				return nil, fmt.Errorf("invalid_client: %w", err)
			}
			if err := services.VerifyTLSClientAuth(preClient, cert); err != nil {
				return nil, fmt.Errorf("invalid_client: %w", err)
			}
			if !preClient.IsActive {
				return nil, fmt.Errorf("invalid_client: client is not active")
			}
			return preClient, nil
		}
	}

	return h.service.AuthenticateClient(c.Request.Context(), clientID, clientSecret)
}

func (h *OAuthProviderHandler) oauthError(c *gin.Context, errorCode, description, state, redirectURI string) { //nolint:unparam // errorCode is always "server_error" now but kept for flexibility
	if redirectURI != "" {
		// The redirect_uri should already be validated by ValidateAuthorizeRequest
		// against the client's registered redirect URIs, but we add a safety check
		// SECURITY: URL-encode all query parameters to prevent parameter injection
		redirectURL := redirectURI + "?error=" + url.QueryEscape(errorCode)
		if description != "" {
			redirectURL += "&error_description=" + url.QueryEscape(description)
		}
		if state != "" {
			redirectURL += queryParamState + url.QueryEscape(state)
		}
		// HTML-bodied redirect — Safari iOS download-prompt fix.
		writeOAuthHTMLRedirect(c, redirectURL)
		return
	}

	c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
		State:            state,
	})
}

func (h *OAuthProviderHandler) tokenError(c *gin.Context, errorCode, description string) {
	c.JSON(http.StatusBadRequest, models.OAuthErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// validateRFC8707Resource validates a `resource` parameter per RFC 8707
// §2: it MUST be an absolute URI per RFC 3986 with no fragment, and
// the platform restricts the scheme to https/http (http allowed for
// in-cluster service URLs; the cluster network policy is the second
// line of defense). Other schemes — file://, javascript:, custom
// app schemes — are rejected outright since they have no place as
// access-token audience values.
//
// Returns a `target_disabled`/`invalid_target` error_description per
// RFC 8707 §2.2.
func validateRFC8707Resource(resource string) error {
	u, err := url.Parse(resource)
	if err != nil {
		return fmt.Errorf("invalid_target: resource must be an absolute URI per RFC 3986: %v", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("invalid_target: resource must be an absolute URI (got %q)", resource)
	}
	if u.Fragment != "" || strings.Contains(resource, "#") {
		return fmt.Errorf("invalid_target: resource MUST NOT contain a URI fragment (RFC 8707 §2)")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("invalid_target: resource scheme %q is not permitted (only http/https)", u.Scheme)
	}
	return nil
}

func (h *OAuthProviderHandler) scopesCovered(grantedScopes, requestedScopes []string) bool {
	granted := make(map[string]bool)
	for _, s := range grantedScopes {
		granted[s] = true
	}

	for _, s := range requestedScopes {
		if s != "" && !granted[s] {
			return false
		}
	}
	return true
}

// parError maps a PAR service error to the appropriate HTTP response per RFC 9126 §2.3.
func (h *OAuthProviderHandler) parError(c *gin.Context, err error) {
	errStr := err.Error()
	var code string
	var desc string
	var status int

	switch {
	case strings.HasPrefix(errStr, "invalid_client:"):
		code, desc, status = "invalid_client", strings.TrimPrefix(errStr, "invalid_client: "), http.StatusUnauthorized
	case strings.HasPrefix(errStr, "invalid_request:"):
		code, desc, status = "invalid_request", strings.TrimPrefix(errStr, "invalid_request: "), http.StatusBadRequest
	case strings.HasPrefix(errStr, "unsupported_response_type:"):
		code, desc, status = "unsupported_response_type", strings.TrimPrefix(errStr, "unsupported_response_type: "), http.StatusBadRequest
	case strings.HasPrefix(errStr, "invalid_scope:"):
		code, desc, status = "invalid_scope", strings.TrimPrefix(errStr, "invalid_scope: "), http.StatusBadRequest
	case strings.HasPrefix(errStr, "server_error:"):
		h.logger.Error("PAR server error", zap.Error(err))
		code, desc, status = "server_error", msgOAuthInternalErrorCap, http.StatusInternalServerError
	default:
		h.logger.Error("PAR unexpected error", zap.Error(err))
		code, desc, status = "server_error", msgOAuthInternalErrorCap, http.StatusInternalServerError
	}

	c.JSON(status, models.OAuthErrorResponse{
		Error:            code,
		ErrorDescription: desc,
	})
}

func (h *OAuthProviderHandler) getUserIDFromContext(c *gin.Context) *uuid.UUID {
	userID, exists := c.Get("user_id")
	if !exists {
		return nil
	}

	switch v := userID.(type) {
	case uuid.UUID:
		return &v
	case string:
		parsed, err := uuid.Parse(v)
		if err != nil {
			return nil
		}
		return &parsed
	case *uuid.UUID:
		return v
	default:
		return nil
	}
}

// requiresMFA reports whether the requested OIDC `acr_values` query
// parameter demands the session assert MFA. Per OIDC Core 1.0 §3.1.2.1
// acr_values is space-separated and the IdP MUST satisfy at least
// one of the listed values.
//
// Recognised tokens (HexxLock-defined ACR vocabulary, plus the legacy
// `mfa` keyword that Talon's startAuthWithMFA + oauth2-proxy + Authentik
// all pass):
//
//	mfa                       — generic MFA assertion required.
//	urn:hexxlock:aal2         — NIST 800-63 AAL2 (any second factor).
//	urn:hexxlock:aal3         — NIST 800-63 AAL3 (phishing-resistant
//	                            WebAuthn UV ceremony).
//
// Empty / unknown values return false (no step-up demanded).
//
// AAL3 implies AAL2 implies MFA — for the purpose of "should the
// gate fire?" all three are treated equivalent. The /oauth/token
// path is where the issued token's `acr` claim must be set to the
// HIGHEST level the user actually achieved (handled in
// emitSubjectClaims via acrFromAuthMethods).
func requiresMFA(acrValues string) bool {
	if acrValues == "" {
		return false
	}
	for _, v := range strings.Fields(acrValues) {
		switch v {
		case "mfa",
			"urn:hexxlock:aal2",
			"urn:hexxlock:aal3":
			return true
		}
	}
	return false
}
