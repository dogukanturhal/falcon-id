// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// webauthn_witness_page_handler.go — server-rendered browser UI for the
// ZTNA Path B device-enrollment witness flow (ADR 0043 §3.c.0).
//
// The matching POST endpoints (/api/v1/auth/webauthn/witness/{begin,finish})
// are in webauthn_witness_handler.go; this file only owns the
// /auth/webauthn/witness/enroll GET page that the Tauri enrollment wizard
// deep-links to. The page:
//
//   1. Validates the inbound query parameters (device_uuid uuidv4,
//      ek_pubkey_hash sha256-hex, callback_url tightly-allowlisted
//      127.0.0.1:<port>/witness-callback, state ≤64 chars).
//   2. Requires an authenticated session — anonymous visitors get a 302 to
//      the OAuth login page with the original URL preserved as ?redirect=.
//   3. Requires platform_admin membership — non-admins see a 403 page
//      explaining why they cannot witness.
//   4. Renders witness_enroll.html, which then drives navigator.credentials
//      .get() against the witness endpoints and POSTs the resulting JWS
//      to the loopback callback target.
//
// Hardening:
//   - callback_url is parsed AND regex-matched (`^http://127\.0\.0\.1:[1-9]
//     [0-9]{0,4}/witness-callback$`). The literal IPv4 (not "localhost")
//     defeats name-resolution attacks; the hard-coded path defeats
//     arbitrary-localhost-endpoint abuse; the port-range guard rejects
//     port 0.
//   - The response carries a witness-specific CSP that lets the bootstrap
//     <script> island parse and lets the page POST to its own origin AND
//     to 127.0.0.1:* (the loopback callback) — but NOTHING ELSE.
//   - The page MUST NOT set cookies or write localStorage. The bootstrap
//     payload is server-rendered in a <script type="application/json">
//     island so the runtime never concatenates user input into JS source.
//
// The validator + handler split keeps callback_url validation unit-testable
// without spinning up the full handler harness.

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/templates"
)

// WitnessEnrollPagePath is the canonical URL path the Tauri enrollment
// wizard deep-links to. Exported so the route registration in cmd/routes.go
// and the wizard can share a single source of truth.
const WitnessEnrollPagePath = "/auth/webauthn/witness/enroll"

// WitnessCallbackPath is the only path component accepted on the
// callback_url query parameter. Hard-coded to defeat the page POSTing
// to an arbitrary localhost endpoint.
const WitnessCallbackPath = "/witness-callback"

// WitnessCSP is the Content-Security-Policy header attached to the
// witness enrollment page response. Same-origin for scripts and styles
// (with 'unsafe-inline' because the page inlines a small bootstrap
// script + style block by design — no remote CDN), and connect-src
// scoped to self + 127.0.0.1:* (the loopback callback) + the public
// id.hexxlock.com host so the WebAuthn ceremony's same-origin fetch
// is honoured in environments that proxy id.hexxlock.com through a
// different upstream than the document origin.
const WitnessCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:* https://id.hexxlock.com; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// witnessSHA256HexRE matches a lower-case-or-mixed-case 64-char hex string.
// Used to validate the ek_pubkey_hash query parameter, which the operator
// is meant to read off the device's enrollment screen before signing.
var witnessSHA256HexRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// witnessCallbackURLRE is the strict callback-URL allowlist:
//   - http:// only (the loopback target is plaintext by definition; the
//     payload is a short-lived JWS which carries its own signature)
//   - 127.0.0.1 literal (NOT "localhost" — `localhost` can resolve to IPv6
//     ::1 on some stacks, or be hijacked via /etc/hosts on a hostile box)
//   - port 1..65535 (rejects port 0 + port-component overflows)
//   - hard-coded /witness-callback path so the page cannot be coerced into
//     POSTing the JWS to an attacker-controlled localhost endpoint that
//     would otherwise also match the loopback host
//
// Live: matched as a single regex below for the unit-test surface. The
// "port up to 5 digits" bound is the canonical IPv4 TCP port range
// (0..65535); 65535 is 5 digits, so `[1-9][0-9]{0,4}` rejects 0 + leading
// zeroes + 6+ digit ports. Any port > 65535 will fail Parse downstream
// even though it matches the regex (e.g. 99999) — the Parse path is the
// belt-and-suspenders cross-check below.
var witnessCallbackURLRE = regexp.MustCompile(`^http://127\.0\.0\.1:[1-9][0-9]{0,4}/witness-callback$`)

// ValidateWitnessCallbackURL returns nil if raw is a well-formed loopback
// callback URL the witness page is permitted to POST to. Otherwise it
// returns a descriptive error so the handler can surface a precise 400
// to the caller (and so the unit tests can assert on the failure mode).
//
// Validation layers:
//  1. Regex match (cheap, kills obviously-bad input).
//  2. url.Parse round-trip (rejects URLs that pass the regex but parse
//     differently — e.g. a 6-digit port that overflows uint16).
//  3. host MUST equal 127.0.0.1 (defense-in-depth in case the regex
//     loses its anchor in a future edit).
//  4. path MUST equal /witness-callback.
//  5. port MUST be 1..65535.
//
// Why not allow https + a public host? Because the only place this page
// is supposed to POST to is the Tauri wizard's loopback listener — there
// is no legitimate enrollment flow where the callback is on the public
// internet, and allowing it would turn this page into a witness-JWS
// exfiltration primitive.
func ValidateWitnessCallbackURL(raw string) error {
	if raw == "" {
		return errWitnessCallbackEmpty
	}
	if !witnessCallbackURLRE.MatchString(raw) {
		return errWitnessCallbackPattern
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errWitnessCallbackParse
	}
	if u.Scheme != "http" {
		return errWitnessCallbackScheme
	}
	if u.Hostname() != "127.0.0.1" {
		return errWitnessCallbackHost
	}
	if u.Path != WitnessCallbackPath {
		return errWitnessCallbackPath
	}
	port := u.Port()
	if port == "" {
		return errWitnessCallbackPort
	}
	// Belt-and-suspenders numeric range check: regex already bounds the
	// string form to 1..99999, this catches the 65536..99999 gap.
	var p int
	for _, r := range port {
		if r < '0' || r > '9' {
			return errWitnessCallbackPort
		}
		p = p*10 + int(r-'0')
		if p > 65535 {
			return errWitnessCallbackPort
		}
	}
	if p < 1 {
		return errWitnessCallbackPort
	}
	return nil
}

// Sentinel errors for ValidateWitnessCallbackURL. Carry just enough
// detail that the unit tests can assert via errors.Is and the handler
// can render an operator-readable string without leaking layout.
var (
	errWitnessCallbackEmpty   = &witnessCallbackErr{msg: "callback_url is required"}
	errWitnessCallbackPattern = &witnessCallbackErr{msg: "callback_url must match http://127.0.0.1:<port>/witness-callback"}
	errWitnessCallbackParse   = &witnessCallbackErr{msg: "callback_url is malformed"}
	errWitnessCallbackScheme  = &witnessCallbackErr{msg: "callback_url scheme must be http"}
	errWitnessCallbackHost    = &witnessCallbackErr{msg: "callback_url host must be 127.0.0.1 (use the IPv4 literal, not localhost)"}
	errWitnessCallbackPath    = &witnessCallbackErr{msg: "callback_url path must be /witness-callback"}
	errWitnessCallbackPort    = &witnessCallbackErr{msg: "callback_url port must be 1..65535"}
)

type witnessCallbackErr struct{ msg string }

func (e *witnessCallbackErr) Error() string { return e.msg }

// witnessPageBootstrap is the JSON-serialised payload that the page's
// inline <script type="application/json"> island carries. Field names
// match what the page-side JS expects.
type witnessPageBootstrap struct {
	DeviceUUID   string `json:"deviceUUID"`
	EKPubkeyHash string `json:"ekPubkeyHash"`
	CallbackURL  string `json:"callbackUrl"`
	State        string `json:"state"`
	OperatorSub  string `json:"operatorSub"`
	CSRFToken    string `json:"csrfToken"`
}

// witnessEnrollPageData is the html/template render context.
type witnessEnrollPageData struct {
	OperatorEmail string
	OperatorSub   string
	DeviceUUID    string
	EKPubkeyHash  string
	CallbackURL   string
	State         string
	// BootstrapJSON is pre-marshaled JSON injected into a
	// <script type="application/json"> island and read back client-side via
	// JSON.parse(textContent).
	//
	// It MUST be template.JS, NOT string. With a plain string, html/template
	// treats the <script> body as a JS value and serialises it as a *quoted,
	// backslash-escaped JS string literal* — i.e. it emits
	//   "{\"deviceUUID\":\"...\"}"
	// instead of the raw object. JSON.parse then yields a STRING, not an
	// object, so data.deviceUUID is undefined and POST /witness/begin sends an
	// empty body → 400 "DeviceUUID required" (live repro 2026-06-16). Marking
	// it template.JS emits the JSON verbatim. This is XSS-safe because
	// json.Marshal HTML-escapes <, >, & (< etc.) by default, so no value
	// can break out of the <script> island, and every embedded value is
	// already validated (uuid / sha256-hex / strict callback regex).
	BootstrapJSON template.JS
}

// RenderWitnessEnrollPage serves GET /auth/webauthn/witness/enroll.
//
// Mounting expectation: the route is registered with OptionalAuth (so this
// handler can choose between a 302 to /oauth/login on miss vs. rendering
// the page on hit). The route is NOT registered under the authProtected
// group, because that group's RequireAuth middleware writes a 401 JSON
// envelope — wrong for a browser-loaded GET.
func (h *WebAuthnHandler) RenderWitnessEnrollPage(c *gin.Context) {
	deviceUUID := c.Query("device_uuid")
	ekHash := c.Query("ek_pubkey_hash")
	callbackURL := c.Query("callback_url")
	state := c.Query("state")

	// Parameter validation BEFORE auth so a misconfigured Tauri build
	// surfaces a clear error message instead of bouncing the operator
	// through login first and then failing.
	if _, parseErr := uuid.Parse(deviceUUID); parseErr != nil {
		h.writeWitnessPageError(c, http.StatusBadRequest, "Invalid device_uuid",
			"The device_uuid query parameter must be a valid UUID (v4).")
		return
	}
	if !witnessSHA256HexRE.MatchString(ekHash) {
		h.writeWitnessPageError(c, http.StatusBadRequest, "Invalid ek_pubkey_hash",
			"The ek_pubkey_hash query parameter must be a 64-character SHA-256 hex string.")
		return
	}
	if err := ValidateWitnessCallbackURL(callbackURL); err != nil {
		h.writeWitnessPageError(c, http.StatusBadRequest, "Invalid callback_url", err.Error())
		return
	}
	if len(state) > 64 {
		h.writeWitnessPageError(c, http.StatusBadRequest, "Invalid state",
			"The state query parameter must be ≤ 64 characters.")
		return
	}

	// Auth check: OptionalAuth has already populated CurrentUser if a
	// session cookie was present. Anonymous → 302 to the OAuth login
	// page with the original URL preserved as ?redirect= so the post-
	// login flow lands the operator back here.
	user := middleware.GetCurrentUser(c)
	if user == nil {
		original := c.Request.URL.RequestURI()
		c.Redirect(http.StatusFound, "/oauth/login?redirect="+url.QueryEscape(original))
		return
	}

	// platform_admin check. RequirePlatformAdmin would write JSON; we
	// inline the same dual-gate check here so we can render an HTML
	// 403 page.
	if !user.IsPlatformAdmin || user.TenantID.String() != models.HexxlockInternalTenantID {
		h.logger.Warn("Witness enroll page access denied (not platform admin)",
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", user.TenantID.String()),
		)
		h.writeWitnessPageError(c, http.StatusForbidden, "Platform admin required",
			"Only HexxLock platform admins may witness device enrollment. "+
				"Sign in with a platform-admin account and try again.")
		return
	}

	// CSRF token for the page's subsequent POSTs to /witness/{begin,finish}.
	// The CSRF middleware's session-bound synchronizer-token path needs a
	// Redis-persisted token; we lazily generate one here so the page can
	// embed it in its bootstrap payload + send it via X-CSRF-Token. If
	// csrfMiddleware is not wired we fall back to a "" token; the API will
	// then 403 the begin call, which surfaces as a retryable error in the
	// page — strictly fail-closed.
	csrfToken := h.generateWitnessCSRFToken(c, user.SessionID)

	bootstrap := witnessPageBootstrap{
		DeviceUUID:   deviceUUID,
		EKPubkeyHash: ekHash,
		CallbackURL:  callbackURL,
		State:        state,
		OperatorSub:  user.ID.String(),
		CSRFToken:    csrfToken,
	}
	bsJSON, err := json.Marshal(bootstrap)
	if err != nil {
		h.logger.Error("Failed to marshal witness page bootstrap", zap.Error(err))
		h.writeWitnessPageError(c, http.StatusInternalServerError, "Internal error",
			"Failed to prepare the enrollment page. Please reload.")
		return
	}

	tmpl, err := template.ParseFS(templates.FS, "witness_enroll.html")
	if err != nil {
		h.logger.Error("Failed to parse witness_enroll template", zap.Error(err))
		h.writeWitnessPageError(c, http.StatusInternalServerError, "Internal error",
			"Failed to render the enrollment page. Please reload.")
		return
	}

	operatorEmail := user.Email
	if operatorEmail == "" {
		operatorEmail = user.Username
	}

	// CSP + no-cache. The page renders sensitive operator metadata and
	// kicks off a WebAuthn ceremony — neither belongs in a shared cache.
	c.Header("Content-Security-Policy", WitnessCSP)
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := tmpl.Execute(c.Writer, witnessEnrollPageData{
		OperatorEmail: operatorEmail,
		OperatorSub:   user.ID.String(),
		DeviceUUID:    deviceUUID,
		EKPubkeyHash:  ekHash,
		CallbackURL:   callbackURL,
		State:         state,
		BootstrapJSON: template.JS(bsJSON),
	}); err != nil {
		h.logger.Error("Failed to execute witness_enroll template", zap.Error(err))
	}
}

// generateWitnessCSRFToken returns a CSRF token bound to sessionID via
// the regular CSRFMiddleware path. Fail-soft on missing wiring: the page
// still renders and the first POST returns 403 csrf_validation_failed,
// which the page surfaces as a retryable error.
func (h *WebAuthnHandler) generateWitnessCSRFToken(c *gin.Context, sessionID uuid.UUID) string {
	if h.csrfMiddleware == nil || sessionID == uuid.Nil {
		return ""
	}
	tok, err := h.csrfMiddleware.GenerateTokenForSession(c, sessionID)
	if err != nil {
		h.logger.Warn("Failed to generate witness CSRF token (non-fatal)", zap.Error(err))
		return ""
	}
	// Also set the hexxlock_csrf double-submit cookie to the SAME token we
	// embed in the page bootstrap. The witness ceremony's /witness/begin and
	// /witness/finish POSTs send this token as X-CSRF-Token; the cookie gives
	// validateToken a stable double-submit proof that survives the per-session
	// synchronizer slot being overwritten between this render and the POST
	// (concurrent renders/retries, or a different auth path resolving a
	// different session_id). Mirrors auth_handler_profile's
	// GenerateTokenForSession+WriteCookie pairing.
	h.csrfMiddleware.WriteCookie(c, tok)
	return tok
}

// SetCSRFMiddleware wires the CSRF middleware so RenderWitnessEnrollPage
// can mint a per-session token to embed in the page bootstrap. Optional;
// when unset the page renders with an empty csrf_token and the first
// /witness/begin POST 403s, which is then surfaced to the operator as a
// retry-able error rather than a silent failure.
//
// Reuses the existing handlers.CSRFMiddleware interface so the wiring
// in cmd/handlers.go can pass the same concrete *middleware.CSRFMiddleware
// already wired into AuthHandler.
func (h *WebAuthnHandler) SetCSRFMiddleware(m CSRFMiddleware) {
	h.csrfMiddleware = m
}

// writeWitnessPageError renders an HTML error card styled identically to
// internal/templates/login.html — same body background, card shell, logo
// header, subtitle, and .error banner. An operator hitting a 400 / 403 /
// 500 from this handler sees the SAME brand presentation as they did on
// the /oauth/login page they came from (#159 follow-up). The triangle-
// icon one-off treatment is gone.
//
// Avoids html/template parsing for top-level inputs because the inputs
// (status, title, detail) are all server-controlled string constants — no
// user input is interpolated. We still route through a tiny templated
// render so {{.Title}} / {{.Detail}} get html/template auto-escape and a
// future refactor cannot accidentally inject user input here.
func (h *WebAuthnHandler) writeWitnessPageError(c *gin.Context, status int, title, detail string) {
	c.Header("Content-Security-Policy", WitnessCSP)
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	// SECURITY: title + detail are caller-supplied constants in every
	// invocation site above. We still HTML-escape via html/template's
	// auto-escape by routing through a tiny templated render to avoid
	// any future refactor accidentally injecting user input here.
	tmpl, err := template.New("witness-err").Parse(witnessErrorTemplate)
	if err != nil {
		_, _ = c.Writer.WriteString("Falcon ID witness enrollment error")
		return
	}
	_ = tmpl.Execute(c.Writer, map[string]any{
		"Title":  title,
		"Detail": detail,
	})
}

// witnessErrorTemplate is the HTML shell for 400/403/500 error surfaces.
//
// Visual primitives are lifted verbatim from internal/templates/login.html
// — same body background, card shell, logo, subtitle, and .error banner —
// so an operator who just authenticated at /oauth/login sees the SAME
// brand presentation here. The previous one-off "red warning triangle"
// treatment is GONE: brand-consistent error rendering means the same
// `.error` banner the login page uses for a wrong-password error.
//
// No JS, no fetches, no user input interpolation beyond the
// {{.Title}}/{{.Detail}} fields which html/template auto-escapes.
const witnessErrorTemplate = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Falcon ID — {{.Title}}</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif; background: linear-gradient(to bottom right, #f8fafc, #ffffff, #eef2ff); display: flex; align-items: center; justify-content: center; min-height: 100vh; color: #020817; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(2,8,23,0.06), 0 8px 10px -6px rgba(2,8,23,0.05); padding: 40px; width: 100%; max-width: 400px; }
.logo { display: flex; flex-direction: column; align-items: center; gap: 12px; margin-bottom: 20px; }
.logo-mark { display: flex; align-items: center; justify-content: center; width: 56px; height: 56px; border-radius: 16px; background: #2563eb; color: #ffffff; box-shadow: 0 10px 15px -3px rgba(37,99,235,0.25); }
.logo-word { font-size: 24px; font-weight: 700; letter-spacing: -0.02em; color: #020817; }
.subtitle { text-align: center; margin-bottom: 28px; color: #64748b; font-size: 15px; }
.error { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; padding: 10px 14px; border-radius: 8px; font-size: 14px; margin-bottom: 16px; }
.error strong { display: block; margin-bottom: 4px; font-weight: 600; }
</style></head><body>
<div class="card">
<div class="logo"><span class="logo-mark"><svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg></span><span class="logo-word">Falcon ID</span></div>
<div class="subtitle">Device enrollment witness</div>
<div class="error"><strong>{{.Title}}</strong>{{.Detail}}</div>
</div>
</body></html>`
