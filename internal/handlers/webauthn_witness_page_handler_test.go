// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// webauthn_witness_page_handler_test.go covers:
//   - the ValidateWitnessCallbackURL allowlist (unit-level fuzz of the
//     regex + parse-cross-check + port-range guard)
//   - the RenderWitnessEnrollPage handler decision tree:
//       * anonymous       → 302 to /oauth/login with ?redirect=<original URI>
//       * non-admin       → 403 HTML page (NOT JSON)
//       * valid admin     → 200 HTML containing the device_uuid value
//       * bad params      → 400 HTML page with a precise reason
//
// The handler exercises the SAME html/template render path the production
// code uses (no test-time template-shim), so a future edit that breaks
// the template file or its parse-FS embedding lights up here.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ── ValidateWitnessCallbackURL ────────────────────────────────────────────────

func TestValidateWitnessCallbackURL_AcceptsCanonical(t *testing.T) {
	good := []string{
		"http://127.0.0.1:1/witness-callback",
		"http://127.0.0.1:80/witness-callback",
		"http://127.0.0.1:1024/witness-callback",
		"http://127.0.0.1:53217/witness-callback",
		"http://127.0.0.1:65535/witness-callback",
	}
	for _, u := range good {
		t.Run(u, func(t *testing.T) {
			if err := ValidateWitnessCallbackURL(u); err != nil {
				t.Fatalf("expected %q to pass, got %v", u, err)
			}
		})
	}
}

func TestValidateWitnessCallbackURL_RejectsBad(t *testing.T) {
	// (input, expected sentinel) — every rejection path must surface a
	// SPECIFIC error so the handler can render a precise 400 explanation.
	bad := []struct {
		raw  string
		want error
	}{
		{"", errWitnessCallbackEmpty},
		// host != 127.0.0.1 — name-resolution attacks
		{"http://localhost:53217/witness-callback", errWitnessCallbackPattern},
		{"http://127.0.0.2:53217/witness-callback", errWitnessCallbackPattern},
		{"http://[::1]:53217/witness-callback", errWitnessCallbackPattern},
		// public host — JWS exfiltration primitive risk
		{"http://1.2.3.4:53217/witness-callback", errWitnessCallbackPattern},
		// scheme guard
		{"https://127.0.0.1:53217/witness-callback", errWitnessCallbackPattern},
		{"ftp://127.0.0.1:53217/witness-callback", errWitnessCallbackPattern},
		// path guard — must be exactly /witness-callback
		{"http://127.0.0.1:53217/other-path", errWitnessCallbackPattern},
		{"http://127.0.0.1:53217/witness-callback/extra", errWitnessCallbackPattern},
		{"http://127.0.0.1:53217/witness-callbac", errWitnessCallbackPattern},
		{"http://127.0.0.1:53217/", errWitnessCallbackPattern},
		// port guards
		{"http://127.0.0.1/witness-callback", errWitnessCallbackPattern},   // no port
		{"http://127.0.0.1:0/witness-callback", errWitnessCallbackPattern}, // port 0
		{"http://127.0.0.1:abc/witness-callback", errWitnessCallbackPattern},
		// port > 65535 — regex caps at 5 digits / 99999, the numeric
		// guard catches the 65536..99999 gap and returns the port sentinel
		{"http://127.0.0.1:65536/witness-callback", errWitnessCallbackPort},
		{"http://127.0.0.1:99999/witness-callback", errWitnessCallbackPort},
		// port >= 6 digits — regex rejects outright
		{"http://127.0.0.1:100000/witness-callback", errWitnessCallbackPattern},
		// leading-zero port — regex rejects
		{"http://127.0.0.1:01234/witness-callback", errWitnessCallbackPattern},
		// query / fragment injection — regex is anchored end-of-string
		{"http://127.0.0.1:53217/witness-callback?evil=1", errWitnessCallbackPattern},
		{"http://127.0.0.1:53217/witness-callback#frag", errWitnessCallbackPattern},
		// userinfo abuse
		{"http://attacker@127.0.0.1:53217/witness-callback", errWitnessCallbackPattern},
		// space-stuffing / newline injection
		{"http://127.0.0.1:53217/witness-callback ", errWitnessCallbackPattern},
		{"http://127.0.0.1:53217/witness-callback\n", errWitnessCallbackPattern},
	}
	for _, tc := range bad {
		t.Run(tc.raw, func(t *testing.T) {
			err := ValidateWitnessCallbackURL(tc.raw)
			if err == nil {
				t.Fatalf("expected %q to fail, got nil", tc.raw)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("input=%q got %v (%T), want %v", tc.raw, err, err, tc.want)
			}
		})
	}
}

// ── RenderWitnessEnrollPage ───────────────────────────────────────────────────

const (
	witnessPagePath        = "/auth/webauthn/witness/enroll"
	witnessPageDeviceUUID  = "33333333-3333-3333-3333-333333333333"
	witnessPageEKHash      = "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"
	witnessPageCallbackURL = "http://127.0.0.1:53217/witness-callback"
)

// witnessPageEngine wires the page route plus an inject middleware that
// optionally populates CurrentUser into the gin context — matching the
// real OptionalAuth behaviour without spinning up the full auth stack.
func witnessPageEngine(h *WebAuthnHandler, user *models.CurrentUser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if user != nil {
		r.Use(func(c *gin.Context) {
			c.Set(middleware.CurrentUserKey, user)
			c.Next()
		})
	}
	r.GET(witnessPagePath, h.RenderWitnessEnrollPage)
	return r
}

func newWitnessPageHandler() *WebAuthnHandler {
	return &WebAuthnHandler{logger: zap.NewNop()}
}

func newPlatformAdminUser(t *testing.T) *models.CurrentUser {
	t.Helper()
	tid, err := uuid.Parse(models.HexxlockInternalTenantID)
	if err != nil {
		t.Fatalf("parse HexxlockInternalTenantID: %v", err)
	}
	return &models.CurrentUser{
		ID:              uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		TenantID:        tid,
		Username:        "platformadmin",
		Email:           "ops@example.com",
		IsPlatformAdmin: true,
		SessionID:       uuid.MustParse("22222222-2222-2222-2222-222222222222"),
	}
}

func newRegularTenantUser() *models.CurrentUser {
	return &models.CurrentUser{
		ID:              uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		TenantID:        uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		Username:        "regularuser",
		Email:           "user@example.com",
		IsPlatformAdmin: false,
	}
}

func buildPageURL(deviceUUID, ekHash, callbackURL, state string) string {
	q := "device_uuid=" + deviceUUID +
		"&ek_pubkey_hash=" + ekHash +
		"&callback_url=" + callbackURL
	if state != "" {
		q += "&state=" + state
	}
	return witnessPagePath + "?" + q
}

func TestRenderWitnessEnrollPage_AnonymousRedirectsToLogin(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, nil) // no user injected
	target := buildPageURL(witnessPageDeviceUUID, witnessPageEKHash,
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", "")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 for anonymous visitor, got %d body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/oauth/login?redirect=") {
		t.Fatalf("expected redirect to /oauth/login, got %q", loc)
	}
	// The redirect must carry the original page URI so post-login lands
	// the operator right back here.
	if !strings.Contains(loc, "device_uuid%3D"+witnessPageDeviceUUID) {
		t.Fatalf("expected device_uuid to be preserved in redirect target, got %q", loc)
	}
}

func TestRenderWitnessEnrollPage_NonAdminGets403HTML(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, newRegularTenantUser())
	target := buildPageURL(witnessPageDeviceUUID, witnessPageEKHash,
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", "")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html 403 page (not JSON), got Content-Type=%q", ct)
	}
	if !strings.Contains(w.Body.String(), "Platform admin required") {
		t.Fatalf("403 page must explain the role requirement, got %q", w.Body.String())
	}
}

func TestRenderWitnessEnrollPage_ValidAdminRenders200(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, newPlatformAdminUser(t))
	target := buildPageURL(witnessPageDeviceUUID, witnessPageEKHash,
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", "wizard-corr-1")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, witnessPageDeviceUUID) {
		t.Fatalf("rendered page must contain device_uuid value, got %q", body[:min(len(body), 400)])
	}
	if !strings.Contains(body, witnessPageEKHash) {
		t.Fatalf("rendered page must contain ek_pubkey_hash value")
	}
	if !strings.Contains(body, "http://127.0.0.1:53217/witness-callback") {
		t.Fatalf("rendered page must contain callback_url value")
	}
	if !strings.Contains(body, "ops@example.com") {
		t.Fatalf("rendered page must contain operator email")
	}
	// Regression (2026-06-16): the bootstrap island MUST be a raw JSON object,
	// not html/template's quoted+escaped JS-string form
	// ("{\"deviceUUID\":...}"). The escaped form makes client-side
	// JSON.parse(textContent) return a STRING, so data.deviceUUID is undefined
	// and POST /witness/begin sends an empty body → 400 "DeviceUUID required".
	// Presence of the unescaped object proves BootstrapJSON is emitted as
	// template.JS, not a plain string.
	if !strings.Contains(body, `{"deviceUUID":"`+witnessPageDeviceUUID+`"`) {
		t.Fatalf("bootstrap island must be a raw JSON object (template.JS); got body excerpt %q", body[:min(len(body), 600)])
	}
	if strings.Contains(body, `"{\"deviceUUID\"`) {
		t.Fatalf("bootstrap island is html/template-escaped as a JS string literal — JSON.parse would yield a string, breaking /witness/begin")
	}
	// CSP must be attached.
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" || !strings.Contains(csp, "connect-src 'self' http://127.0.0.1:*") {
		t.Fatalf("CSP header must allow connect-src to loopback callback; got %q", csp)
	}
	// MUST NOT set cookies on this page — spec requires in-memory-only state.
	if cookies := w.Result().Cookies(); len(cookies) > 0 {
		t.Fatalf("witness enroll page must not set cookies; got %d cookies", len(cookies))
	}
}

func TestRenderWitnessEnrollPage_BadDeviceUUID(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, newPlatformAdminUser(t))
	target := buildPageURL("not-a-uuid", witnessPageEKHash,
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", "")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid device_uuid, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid device_uuid") {
		t.Fatalf("400 page must explain device_uuid issue, got %q", w.Body.String())
	}
}

func TestRenderWitnessEnrollPage_BadEKHash(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, newPlatformAdminUser(t))
	target := buildPageURL(witnessPageDeviceUUID, "shorthash",
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", "")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ek_pubkey_hash, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid ek_pubkey_hash") {
		t.Fatalf("400 page must explain ek_pubkey_hash issue, got %q", w.Body.String())
	}
}

func TestRenderWitnessEnrollPage_BadCallbackURL(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, newPlatformAdminUser(t))
	target := buildPageURL(witnessPageDeviceUUID, witnessPageEKHash,
		"http%3A%2F%2Flocalhost%3A53217%2Fwitness-callback", "")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid callback_url (localhost not 127.0.0.1), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid callback_url") {
		t.Fatalf("400 page must explain callback_url issue, got %q", w.Body.String())
	}
}

func TestRenderWitnessEnrollPage_StateTooLong(t *testing.T) {
	h := newWitnessPageHandler()
	r := witnessPageEngine(h, newPlatformAdminUser(t))
	tooLong := strings.Repeat("x", 65)
	target := buildPageURL(witnessPageDeviceUUID, witnessPageEKHash,
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", tooLong)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for over-length state, got %d", w.Code)
	}
}

func TestRenderWitnessEnrollPage_PlatformAdminFlagWithoutInternalTenantBlocked(t *testing.T) {
	// Defense in depth: even if IsPlatformAdmin=true, the user must
	// belong to the exampletenant tenant. A tenant-admin claim that
	// mis-set IsPlatformAdmin would otherwise sneak through.
	h := newWitnessPageHandler()
	tid := uuid.MustParse("66666666-6666-6666-6666-666666666666") // NOT the internal tenant
	r := witnessPageEngine(h, &models.CurrentUser{
		ID:              uuid.MustParse("77777777-7777-7777-7777-777777777777"),
		TenantID:        tid,
		Username:        "rogue",
		Email:           "rogue@example.com",
		IsPlatformAdmin: true,
	})
	target := buildPageURL(witnessPageDeviceUUID, witnessPageEKHash,
		"http%3A%2F%2F127.0.0.1%3A53217%2Fwitness-callback", "")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for IsPlatformAdmin=true but wrong tenant, got %d", w.Code)
	}
}
