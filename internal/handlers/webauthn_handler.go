// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const (
	msgWebAuthnSessionIDRequired = "wa_session_id is required"
	msgWebAuthnTenantIDRequired  = "valid tenant_id is required"
	msgWebAuthnUserIDRequired    = "valid user_id is required"
)

// WebAuthnHandler exposes the FIDO2 / WebAuthn passkey HTTP endpoints.
//
// The /register/* endpoints require an authenticated session — the user is
// already known. The /login/* endpoints are pre-auth: tenant_id and (for
// the standard flow) user_id arrive in the request body. The /conditional/*
// endpoints are usernameless — only tenant_id is needed up front.
// The /step-up/* endpoints (added 2026-05-11 for tier-1 RFC 9470 step-up
// support) require an authenticated session AND a verified passkey
// assertion — used to elevate session AMR without issuing a new session.
// The /witness/* endpoints (added 2026-06-09 for ZTNA Path B device
// enrollment) require an authenticated session AND a verified passkey
// assertion, then mint a compact JWS the jess controller can verify.
type WebAuthnHandler struct {
	service     *services.WebAuthnService
	authService *services.AuthService
	sessionRepo passkeyStepUpSessionRepository
	stepUpRepo  passkeyStepUpRecorder
	// authHandler is injected (via SetAuthHandler) so the WebAuthn
	// login-completion paths (FinishAuthentication +
	// CompleteConditionalLogin) can write the same falcon_access_token
	// + falcon_idp_session cookies the password-login path writes.
	// Without this, the LoginResponse JSON is returned but no browser
	// cookies are set → the OAuth flow that initiated the login sees
	// no session on its redirect-back → bounces to /oauth/login →
	// infinite loop. Live repro 2026-05-25 (this commit).
	authHandler *AuthHandler
	// mfaService is injected (via SetMFAService) so FinishRegistration
	// can auto-generate backup codes when a passkey is the user's
	// first MFA factor (Phase B, 2026-05-26). Nil-safe — when unset
	// the registration still completes; the user just has zero
	// recovery codes (matches pre-Phase-B behaviour).
	mfaService *services.MFAService
	// tokenService is injected (via SetTokenService) so
	// FinishWitnessEnroll can mint the compact enrollment witness JWS
	// using the existing RS256 issuer key. Nil → /witness/finish
	// returns 503 (same pattern as sessionRepo → step-up).
	tokenService *services.TokenService
	// witnessService is the narrow WebAuthn ceremony interface used
	// by the /witness/* endpoints. In production it is always nil and
	// the handler falls back to h.service; in unit tests a stub is
	// injected here so tests can exercise the handler without the full
	// service dependency graph.
	witnessService witnessWebAuthnService
	// witnessState holds the begin-time {device_uuid, ek_hash, state} binding
	// the finish step trusts instead of the request. Nil -> witness 503.
	witnessState witnessStateService
	// witnessInfo reports which methods the witness page may offer (optional).
	witnessInfo witnessStatusProvider
	// csrfMiddleware is injected (via SetCSRFMiddleware) so the
	// ZTNA Path B witness enrollment page can mint a per-session CSRF
	// token to embed in its bootstrap payload. Optional — when unset
	// the page renders with an empty token and the first POST to
	// /witness/begin returns 403 csrf_validation_failed, which the page
	// surfaces as a retryable error.
	csrfMiddleware CSRFMiddleware
	logger         *zap.Logger
}

// NewWebAuthnHandler wires the service + auth service + logger. The auth
// service is what converts a verified WebAuthn ceremony into a full session
// + token envelope (LoginResponse) — without it, the login endpoints would
// only certify "credential X authenticated successfully" with no way for
// the caller to act on that.
func NewWebAuthnHandler(service *services.WebAuthnService, authService *services.AuthService, logger *zap.Logger) *WebAuthnHandler {
	return &WebAuthnHandler{
		service:     service,
		authService: authService,
		logger:      logger,
	}
}

// SetSessionRepo injects the SessionRepository so /step-up/* endpoints
// can atomically elevate the current session's AMR after a successful
// passkey assertion. Optional; when unset the step-up handlers return
// 503 service-unavailable. Mirrors MFAHandler.SetSessionRepo.
func (h *WebAuthnHandler) SetSessionRepo(repo *repositories.SessionRepository) {
	if repo == nil {
		h.sessionRepo = nil
		return
	}
	h.sessionRepo = repo
}
func (h *WebAuthnHandler) SetStepUpRepo(repo *repositories.StepUpVerificationRepository) {
	if repo == nil {
		h.stepUpRepo = nil
		return
	}
	h.stepUpRepo = repo
}

// SetAuthHandler injects the AuthHandler so login-completion paths can
// reuse AuthHandler.SetLoginResponseCookies — single source of truth
// for the falcon_access_token + falcon_idp_session cookie pair. Optional
// at startup; when unset the WebAuthn login endpoints still return a
// LoginResponse JSON envelope but the caller cannot establish a browser
// session (use case: pure-API consumers that consume the JWT directly).
// In the standard browser-flow registration the binding MUST be wired or
// every WebAuthn login surfaces as an infinite redirect loop downstream.
func (h *WebAuthnHandler) SetAuthHandler(ah *AuthHandler) {
	h.authHandler = ah
}

// SetMFAService injects the MFAService so FinishRegistration can
// auto-generate backup codes on first MFA factor enrollment. Nil-safe
// — when unset registration still succeeds, the user just gets no
// recovery codes (matches pre-Phase-B behaviour).
func (h *WebAuthnHandler) SetMFAService(svc *services.MFAService) {
	h.mfaService = svc
}

// currentUserToWebAuthnSubject synthesises a narrow webauthn-only identity
// from the gin-context CurrentUser. No DB hit required.
//
// IMPORTANT: returns a `*services.WebAuthnSubject` (NOT `*models.User`) so
// the Go type system rejects any future attempt to flow this synthetic
// identity into `userRepo.Update(ctx, ...)` — that would wipe the user's
// row via the write-all-columns SQL. See services.WebAuthnSubject doc for
// the regression that motivated the narrowing.
func currentUserToWebAuthnSubject(cu *models.CurrentUser) *services.WebAuthnSubject {
	return &services.WebAuthnSubject{
		ID:       cu.ID,
		TenantID: cu.TenantID,
		Username: cu.Username,
		Email:    cu.Email,
	}
}

// ------------------------ Registration ------------------------

// BeginRegistration POST /api/v1/auth/webauthn/register/begin
func (h *WebAuthnHandler) BeginRegistration(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return
	}
	var req models.RegisterWebAuthnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	challenge, err := h.service.BeginRegistration(c.Request.Context(), currentUserToWebAuthnSubject(user), req.FriendlyName)
	if err != nil {
		h.logger.Error("WebAuthn BeginRegistration failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start registration"})
		return
	}
	c.JSON(http.StatusOK, challenge)
}

// FinishRegistration POST /api/v1/auth/webauthn/register/finish
//
// The browser POSTs the standard W3C-shaped credential creation response
// (the JSON produced by @simplewebauthn/browser's startRegistration() or by
// PublicKeyCredential.toJSON()). The wa_session_id is read from the query
// string so the body remains the verbatim W3C payload.
func (h *WebAuthnHandler) FinishRegistration(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return
	}
	sessionID := c.Query("wa_session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnSessionIDRequired})
		return
	}
	friendlyName := c.Query("friendly_name")

	cred, err := h.service.FinishRegistration(
		c.Request.Context(),
		currentUserToWebAuthnSubject(user),
		sessionID,
		friendlyName,
		models.DefaultAttestationPolicy(),
		c.Request,
	)
	if err != nil {
		h.logger.Warn("WebAuthn FinishRegistration failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Auto-generate backup codes on first MFA factor enrollment.
	// Idempotent — passes through when user already has codes from a
	// prior TOTP / email enrollment. Surfaced ONCE in the response so
	// the user can save them; non-fatal on failure (passkey is
	// already registered, codes can be generated later).
	response := cred.ToResponse()
	if h.mfaService != nil {
		codes, generated, ensureErr := h.mfaService.EnsureBackupCodesGenerated(c.Request.Context(), user.ID)
		if ensureErr != nil {
			h.logger.Warn("Failed to ensure backup codes after passkey registration",
				zap.String("user_id", user.ID.String()),
				zap.Error(ensureErr),
			)
		} else if generated && len(codes) > 0 {
			// Wrap the credential response in a JSON object that
			// also carries the freshly-minted codes. Frontend MUST
			// surface these to the user in a "save these now" modal.
			c.JSON(http.StatusCreated, gin.H{
				"credential":             response,
				"backup_codes":           codes,
				"backup_codes_generated": true,
			})
			return
		}
	}
	c.JSON(http.StatusCreated, response)
}

// ------------------------ Standard authentication ------------------------

// BeginAuthentication POST /api/v1/auth/webauthn/login/begin
func (h *WebAuthnHandler) BeginAuthentication(c *gin.Context) {
	userID, tenantID, ok := h.resolveUnauthenticatedIDs(c)
	if !ok {
		return
	}
	challenge, err := h.service.BeginAuthentication(c.Request.Context(), userID, tenantID)
	if err != nil {
		h.logger.Warn("WebAuthn BeginAuthentication failed",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, challenge)
}

// FinishAuthentication POST /api/v1/auth/webauthn/login/finish
//
// Verifies the assertion, then mints a full LoginResponse via AuthService.
// The session row records `amr=["hwk","user"]` so the OAuth /authorize →
// /token flow downstream emits `acr=urn:hexxlock:aal3` on derived id_tokens.
// Optional `client_id` query param scopes the response to a specific OAuth
// client (mirrors /api/v1/auth/login).
func (h *WebAuthnHandler) FinishAuthentication(c *gin.Context) {
	userID, tenantID, ok := h.resolveUnauthenticatedIDs(c)
	if !ok {
		return
	}
	sessionID := c.Query("wa_session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnSessionIDRequired})
		return
	}
	_, user, err := h.service.FinishAuthentication(c.Request.Context(), userID, tenantID, sessionID, c.Request)
	if err != nil {
		h.logger.Warn("WebAuthn FinishAuthentication failed",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.authService.LoginViaWebAuthn(c.Request.Context(), user, GetClientIP(c), c.Request.UserAgent(), c.Query("client_id"), webAuthnRememberMe(c))
	if err != nil {
		h.logger.Error("WebAuthn LoginViaWebAuthn failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue session"})
		return
	}
	// Browser-flow cookies. Without these the LoginResponse JSON is
	// returned but the user's browser has no session — every subsequent
	// /oauth/authorize on the same flow sees no auth and bounces to
	// /oauth/login. Single source of truth: AuthHandler's same helper.
	if h.authHandler != nil {
		h.authHandler.SetLoginResponseCookies(c, resp)
	}
	c.JSON(http.StatusOK, resp)
}

// ------------------------ Conditional / discoverable ------------------------

// BeginConditionalLogin POST /api/v1/auth/webauthn/conditional/begin
//
// Returns a discoverable-credential challenge. The browser presents it via
// navigator.credentials.get({mediation:'conditional'}) which surfaces the
// passkey autofill UI without a deliberate user gesture.
func (h *WebAuthnHandler) BeginConditionalLogin(c *gin.Context) {
	tenantID, ok := h.resolveTenantID(c)
	if !ok {
		return
	}
	challenge, err := h.service.BeginConditionalLogin(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Warn("WebAuthn BeginConditionalLogin failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, challenge)
}

// CompleteConditionalLogin POST /api/v1/auth/webauthn/conditional/complete
//
// Same envelope as FinishAuthentication — a full LoginResponse — but the
// user is resolved from the credential's userHandle rather than from a
// pre-supplied user_id. This is the passwordless / autofill path, so the
// session's amr still records `["hwk","user"]` and the AAL3 ladder applies.
func (h *WebAuthnHandler) CompleteConditionalLogin(c *gin.Context) {
	tenantID, ok := h.resolveTenantID(c)
	if !ok {
		return
	}
	sessionID := c.Query("wa_session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnSessionIDRequired})
		return
	}
	_, user, err := h.service.FinishConditionalLogin(c.Request.Context(), tenantID, sessionID, c.Request)
	if err != nil {
		h.logger.Warn("WebAuthn FinishConditionalLogin failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}
	resp, err := h.authService.LoginViaWebAuthn(c.Request.Context(), user, GetClientIP(c), c.Request.UserAgent(), c.Query("client_id"), webAuthnRememberMe(c))
	if err != nil {
		h.logger.Error("WebAuthn LoginViaWebAuthn (conditional) failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue session"})
		return
	}
	// Browser-flow cookies — see FinishAuthentication for rationale.
	// Discoverable-credential ceremonies arrive via apps/login during a
	// max_age recovery loop; without the cookie write the next
	// /oauth/authorize re-bounces and the user is trapped on /oauth/login.
	if h.authHandler != nil {
		h.authHandler.SetLoginResponseCookies(c, resp)
	}
	c.JSON(http.StatusOK, resp)
}

// ------------------------ Step-up authentication ------------------------
//
// Session-authenticated WebAuthn assertion for RFC 9470 step-up. Distinct
// from /login/{begin,finish} (pre-auth, mints a NEW session) — these
// /step-up/{begin,finish} endpoints REUSE the existing session and only
// elevate its AMR. Used by the /auth/mfa/challenge frontend page when the
// user has at least one passkey enrolled.
//
// Why a dedicated endpoint instead of reusing /login/finish:
//   /login/finish calls authService.LoginViaWebAuthn which creates a NEW
//   session via createSessionWithInvalidation — orthogonal to step-up
//   semantics where the user is re-proving control of a passkey on an
//   ALREADY-active session and we just want to upgrade its AMR. Issuing
//   a fresh session would invalidate other in-flight tabs and lose
//   trusted-device/IP-correlation tracking on the original session.

// BeginStepUp POST /api/v1/auth/webauthn/step-up/begin
//
// Returns a WebAuthn assertion challenge scoped to the current user's
// registered credentials. Frontend feeds the challenge to
// navigator.credentials.get() and POSTs the result to /step-up/finish.
func (h *WebAuthnHandler) BeginStepUp(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	challenge, err := h.service.BeginAuthentication(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		h.logger.Warn("WebAuthn BeginStepUp failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, challenge)
}

// FinishStepUp POST /api/v1/auth/webauthn/step-up/finish
//
// Verifies the assertion against the user's stored credentials, then
// elevates the current session's AMR to include "mfa" + "hwk" so the
// next /oauth/authorize evaluation against `acr_values=mfa` passes.
// Does NOT mint a new session or new tokens — that's
// authService.LoginViaWebAuthn's job in the /login/finish path.
//
// Query params:
//   - wa_session_id: opaque server-side ceremony id returned by /begin
func (h *WebAuthnHandler) FinishStepUp(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	if h.sessionRepo == nil || h.stepUpRepo == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "step-up not configured"})
		return
	}
	sessionID := c.Query("wa_session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnSessionIDRequired})
		return
	}
	action := c.Query("action")
	if len(action) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action too long"})
		return
	}
	_, _, err := h.service.FinishAuthentication(c.Request.Context(), user.ID, user.TenantID, sessionID, c.Request)
	if err != nil {
		h.logger.Warn("WebAuthn FinishStepUp failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Elevate AMR on the CURRENT session — pull session_id from gin
	// context (set by auth middleware from the access-token cookie).
	// Record BOTH "mfa" (for the OAuth acr=mfa gate) and "hwk" (RFC 8176
	// hardware key) so SIEM can distinguish step-up factor types and
	// the resulting OIDC id_tokens carry the higher-assurance amr set.
	sidVal, ok := c.Get("session_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session not found"})
		return
	}
	sid, ok := sidVal.(uuid.UUID)
	if !ok || sid == uuid.Nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid session context"})
		return
	}
	if err := recordPasskeyStepUp(c.Request.Context(), h.sessionRepo, h.stepUpRepo, sid, user.ID); err != nil {
		respondMFAFlowError(c, err)
		return
	}
	// Optional ?action=<name>: also satisfy the per-action StepUpMiddleware gate
	// (e.g. admin_user_mutation) with this passkey assertion.
	if action != "" {
		if err := h.stepUpRepo.RecordVerification(c.Request.Context(), sid, user.ID, action, "webauthn", 5*time.Minute); err != nil {
			respondMFAFlowError(c, err)
			return
		}
	}
	if h.authHandler != nil && !refreshStepUpIdpSession(c, h.authHandler.sessionCache) {
		return
	}

	h.logger.Info("WebAuthn step-up succeeded",
		zap.String("user_id", user.ID.String()),
		zap.String("session_id", sid.String()),
		zap.String("action", action),
	)
	c.JSON(http.StatusOK, gin.H{
		"verified": true,
		"amr":      []string{"mfa", "hwk"},
	})
}

// ------------------------ Credential management ------------------------

// ListCredentials GET /api/v1/auth/webauthn/credentials
func (h *WebAuthnHandler) ListCredentials(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return
	}
	creds, err := h.service.ListCredentials(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		h.logger.Error("WebAuthn ListCredentials failed",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list credentials"})
		return
	}
	resp := make([]*models.WebAuthnCredentialResponse, len(creds))
	for i := range creds {
		resp[i] = creds[i].ToResponse()
	}
	c.JSON(http.StatusOK, gin.H{"credentials": resp})
}

// DeleteCredential DELETE /api/v1/auth/webauthn/credentials/:id
func (h *WebAuthnHandler) DeleteCredential(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return
	}
	credID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
		return
	}
	if err := h.service.DeleteCredential(c.Request.Context(), credID, user.ID, user.TenantID); err != nil {
		h.logger.Warn("WebAuthn DeleteCredential failed",
			zap.String("credential_id", credID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "credential deleted"})
}

// AdminRevokeCredential POST /api/v1/admin/webauthn/credentials/:id/revoke
//
// Tenant admin revocation. The acting admin's user ID is recorded as
// revoked_by for the audit trail; tenant scoping is enforced by RLS.
func (h *WebAuthnHandler) AdminRevokeCredential(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		return
	}
	credID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
		return
	}
	if err := h.service.AdminRevokeCredential(c.Request.Context(), credID, user.ID, user.TenantID); err != nil {
		h.logger.Error("WebAuthn AdminRevokeCredential failed",
			zap.String("credential_id", credID.String()),
			zap.String("admin_id", user.ID.String()),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke credential"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "credential revoked"})
}

// ------------------------ Helpers ------------------------

// resolveUnauthenticatedIDs parses user_id and tenant_id for endpoints that
// run before the user has a session. Accepts JSON body first, then query
// parameters. Writes a 400 + returns false on any parse failure.
func (h *WebAuthnHandler) resolveUnauthenticatedIDs(c *gin.Context) (userID, tenantID uuid.UUID, ok bool) {
	var body struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	_ = c.ShouldBindJSON(&body) // best-effort; query params are an acceptable fallback
	userIDStr := body.UserID
	if userIDStr == "" {
		userIDStr = c.Query("user_id")
	}
	tenantIDStr := body.TenantID
	if tenantIDStr == "" {
		tenantIDStr = c.Query("tenant_id")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnUserIDRequired})
		return uuid.Nil, uuid.Nil, false
	}
	tenantID, err = uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnTenantIDRequired})
		return uuid.Nil, uuid.Nil, false
	}
	return userID, tenantID, true
}

// resolveTenantID parses tenant_id for the conditional/discoverable flow
// where user_id is unknown until the authenticator response arrives.
func (h *WebAuthnHandler) resolveTenantID(c *gin.Context) (uuid.UUID, bool) {
	tenantIDStr := c.Query("tenant_id")
	if tenantIDStr == "" {
		var body struct {
			TenantID string `json:"tenant_id"`
		}
		_ = c.ShouldBindJSON(&body)
		tenantIDStr = body.TenantID
	}
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": msgWebAuthnTenantIDRequired})
		return uuid.Nil, false
	}
	return tenantID, true
}

// webAuthnRememberMe reads the "remember me" choice for passkey logins. The
// request body is the raw WebAuthn assertion (consumed by go-webauthn), so
// the flag travels as a query parameter, like the MFA-WebAuthn path.
func webAuthnRememberMe(c *gin.Context) bool {
	return c.Query("remember_me") == "true"
}
