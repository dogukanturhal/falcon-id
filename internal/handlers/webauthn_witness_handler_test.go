// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// webauthn_witness_handler_test.go covers the ZTNA Path B witness endpoints:
//   - POST /api/v1/auth/webauthn/witness/begin
//   - POST /api/v1/auth/webauthn/witness/finish?wa_session_id=<id>
//
// including the P0 hardening: platform-admin only, begin persists
// {device_uuid, ek_pubkey_hash, state} and finish trusts only that.
//
// Testing approach: white-box (package handlers) so we can inject the
// witnessWebAuthnService stub via the unexported witnessService field without
// exporting test-only constructors. Token signing uses NewJWTKeyProvider with
// an ephemeral RSA key (the standard test pattern in pkg/crypto/jwt_keys_test.go)
// so the full signing path executes. sessionRepo is left nil in all tests;
// the AMR-elevation path is best-effort and the handler nil-guards it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	pkgcrypto "github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ── stub witnessWebAuthnService ───────────────────────────────────────────────

type witnessWebAuthnStub struct {
	beginErr   error
	finishErr  error
	finishBody []byte // raw request body observed by FinishAuthentication
}

func (s *witnessWebAuthnStub) BeginAuthentication(_ context.Context, _, _ uuid.UUID) (*services.AuthenticationChallenge, error) {
	if s.beginErr != nil {
		return nil, s.beginErr
	}
	return &services.AuthenticationChallenge{SessionID: "stub-session"}, nil
}

func (s *witnessWebAuthnStub) FinishAuthentication(_ context.Context, _, _ uuid.UUID, _ string, r *http.Request) (*models.WebAuthnCredential, *models.User, error) {
	// Capture the body the ceremony parser would see, so a test can prove the
	// handler restored it after reading device_uuid (real ceremony does
	// protocol.ParseCredentialRequestResponse(r), which reads r.Body).
	if r != nil && r.Body != nil {
		s.finishBody, _ = io.ReadAll(r.Body)
	}
	return nil, nil, s.finishErr
}

// ── helpers ───────────────────────────────────────────────────────────────────

const (
	witnessTestIssuer     = "https://id.example.com"
	witnessTestUserIDStr  = "11111111-1111-1111-1111-111111111111"
	witnessTestSessionID  = "22222222-2222-2222-2222-222222222222"
	witnessTestDeviceUUID = "33333333-3333-3333-3333-333333333333"
	witnessTestEKHash     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// fakeWitnessState is an in-memory witnessStateService.
type fakeWitnessState struct {
	m map[string]services.WitnessBinding
}

func newFakeWitnessState() *fakeWitnessState {
	return &fakeWitnessState{m: map[string]services.WitnessBinding{}}
}

func (f *fakeWitnessState) SavePasskeyBinding(_ context.Context, id string, b services.WitnessBinding) error {
	f.m[id] = b
	return nil
}

func (f *fakeWitnessState) TakePasskeyBinding(_ context.Context, id string, userID uuid.UUID) (*services.WitnessBinding, error) {
	b, ok := f.m[id]
	delete(f.m, id)
	if !ok || b.UserID != userID {
		return nil, &services.WitnessError{Status: http.StatusGone, Code: services.WitnessErrExpired, Message: "expired"}
	}
	return &b, nil
}

// newWitnessTokenService builds a TokenService backed by an ephemeral RSA key.
// Unsets JWT_PRIVATE_KEY env so the provider generates a fresh key each call.
func newWitnessTokenService(t *testing.T) *services.TokenService {
	t.Helper()
	t.Setenv("JWT_PRIVATE_KEY", "")
	t.Setenv("JWT_PRIVATE_KEY_FILE", "")
	t.Setenv("JWT_PUBLIC_KEY", "")
	t.Setenv("JWT_PUBLIC_KEY_FILE", "")
	kp, err := pkgcrypto.NewJWTKeyProvider(nil, "test-kid-witness")
	if err != nil {
		t.Fatalf("NewJWTKeyProvider: %v", err)
	}
	cfg := &config.Config{
		JWTIssuer:           witnessTestIssuer,
		JWTSigningAlgorithm: "RS256",
	}
	svc := services.NewTokenService(cfg, nil, nil)
	svc.SetJWTKeyProvider(kp)
	return svc
}

// newWitnessHandler builds a WebAuthnHandler with an injected ceremony stub,
// an in-memory binding store and optionally a token service.
func newWitnessHandler(t *testing.T, waStub *witnessWebAuthnStub, tokenSvc *services.TokenService) *WebAuthnHandler {
	t.Helper()
	return &WebAuthnHandler{
		witnessService: waStub,
		witnessState:   newFakeWitnessState(),
		tokenService:   tokenSvc,
		logger:         zap.NewNop(),
	}
}

// witnessTestEngine wires the two witness routes under a gin engine that injects
// a platform-admin CurrentUser and session_id into every request context.
func witnessTestEngine(h *WebAuthnHandler, userID, sessionID uuid.UUID) *gin.Engine {
	return witnessTestEngineAs(h, userID, sessionID, true)
}

func witnessTestEngineAs(h *WebAuthnHandler, userID, sessionID uuid.UUID, admin bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	injectUser := func(c *gin.Context) {
		tenant := uuid.MustParse("44444444-4444-4444-4444-444444444444")
		if admin {
			tenant = uuid.MustParse(models.HexxlockInternalTenantID)
		}
		c.Set(middleware.CurrentUserKey, &models.CurrentUser{
			ID:              userID,
			TenantID:        tenant,
			Username:        "testoperator",
			Email:           "ops@example.com",
			IsPlatformAdmin: admin,
		})
		c.Set("session_id", sessionID)
		c.Next()
	}
	g := r.Group("/api/v1/auth/webauthn")
	g.Use(injectUser)
	g.POST("/witness/begin", h.BeginWitnessEnroll)
	g.POST("/witness/finish", h.FinishWitnessEnroll)
	return r
}

// witnessPost POSTs a JSON-marshalled body and returns the recorder.
func witnessPost(t *testing.T, r *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func witnessBeginBody() map[string]string {
	return map[string]string{
		"device_uuid":    witnessTestDeviceUUID,
		"ek_pubkey_hash": witnessTestEKHash,
		"state":          "st4te",
	}
}

// witnessBegun runs a begin so a binding exists under the stub's "stub-session".
func witnessBegun(t *testing.T, r *gin.Engine) {
	t.Helper()
	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", witnessBeginBody())
	if w.Code != http.StatusOK {
		t.Fatalf("begin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

const witnessFinishPath = "/api/v1/auth/webauthn/witness/finish?wa_session_id=stub-session"

// ── begin tests ───────────────────────────────────────────────────────────────

func TestBeginWitnessEnroll_HappyPathPersistsBinding(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	uid := uuid.MustParse(witnessTestUserIDStr)
	r := witnessTestEngine(h, uid, uuid.MustParse(witnessTestSessionID))

	witnessBegun(t, r)
	b := h.witnessState.(*fakeWitnessState).m["stub-session"]
	if b.UserID != uid || b.DeviceUUID != witnessTestDeviceUUID || b.EKPubkeyHash != witnessTestEKHash || b.State != "st4te" {
		t.Fatalf("binding not persisted as sent: %+v", b)
	}
}

func TestBeginWitnessEnroll_BadInput(t *testing.T) {
	for name, body := range map[string]map[string]string{
		"missing device_uuid": {"ek_pubkey_hash": witnessTestEKHash},
		"missing ek hash":     {"device_uuid": witnessTestDeviceUUID},
		"non-uuid device":     {"device_uuid": "not-a-uuid", "ek_pubkey_hash": witnessTestEKHash},
		"short ek hash":       {"device_uuid": witnessTestDeviceUUID, "ek_pubkey_hash": "deadbeef"},
		"uppercase ek hash":   {"device_uuid": witnessTestDeviceUUID, "ek_pubkey_hash": strings.ToUpper(witnessTestEKHash)},
		"oversize state":      {"device_uuid": witnessTestDeviceUUID, "ek_pubkey_hash": witnessTestEKHash, "state": strings.Repeat("a", 65)},
	} {
		t.Run(name, func(t *testing.T) {
			h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
			r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
			w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBeginWitnessEnroll_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r.POST("/witness/begin", h.BeginWitnessEnroll) // no injectUser middleware
	w := witnessPost(t, r, "/witness/begin", witnessBeginBody())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated caller, got %d", w.Code)
	}
}

func TestBeginWitnessEnroll_NonPlatformAdminForbidden(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r := witnessTestEngineAs(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID), false)
	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", witnessBeginBody())
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}
	if len(h.witnessState.(*fakeWitnessState).m) != 0 {
		t.Fatal("a binding was persisted for a non-admin")
	}
}

func TestBeginWitnessEnroll_BeginAuthFails(t *testing.T) {
	stub := &witnessWebAuthnStub{beginErr: errors.New("ceremony store unavailable")}
	h := newWitnessHandler(t, stub, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", witnessBeginBody())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when BeginAuthentication fails, got %d", w.Code)
	}
}

func TestBeginWitnessEnroll_StateStoreMissingFailsClosed(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	h.witnessState = nil
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", witnessBeginBody())
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

// ── finish tests ──────────────────────────────────────────────────────────────

// TestFinishWitnessEnroll_AssertionBodyReachesCeremony: the finish body is the
// W3C assertion; FinishAuthentication must see it intact.
func TestFinishWitnessEnroll_AssertionBodyReachesCeremony(t *testing.T) {
	stub := &witnessWebAuthnStub{}
	h := newWitnessHandler(t, stub, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	witnessBegun(t, r)

	w := witnessPost(t, r, witnessFinishPath, map[string]any{
		"id":       "cred-id-xyz",
		"type":     "public-key",
		"response": map[string]string{"signature": "sig-bytes"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(string(stub.finishBody), `"id":"cred-id-xyz"`) {
		t.Fatalf("ceremony body missing the W3C assertion payload; got %q", string(stub.finishBody))
	}
}

func TestFinishWitnessEnroll_HappyPathUsesStoredBinding(t *testing.T) {
	tokenSvc := newWitnessTokenService(t)
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, tokenSvc)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	witnessBegun(t, r)

	// The request tries to smuggle a DIFFERENT device_uuid / ek hash: ignored.
	w := witnessPost(t, r, witnessFinishPath, map[string]string{
		"device_uuid":    "99999999-9999-9999-9999-999999999999",
		"ek_pubkey_hash": strings.Repeat("f", 64),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp witnessFinishResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.SignedJWS == "" || resp.IssuedAt == "" || resp.ExpiresAt == "" {
		t.Fatalf("incomplete response: %+v", resp)
	}
	if resp.AdminSub != witnessTestUserIDStr {
		t.Errorf("admin_sub = %q, want %q", resp.AdminSub, witnessTestUserIDStr)
	}
	if resp.State != "st4te" {
		t.Errorf("state = %q, want the stored value", resp.State)
	}

	tok, _, err := jwt.NewParser().ParseUnverified(resp.SignedJWS, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if kid, _ := tok.Header["kid"].(string); kid == "" {
		t.Error("JWS header carries no kid")
	}
	claims := tok.Claims.(jwt.MapClaims)
	checkStr := func(key, want string) {
		t.Helper()
		if got, _ := claims[key].(string); got != want {
			t.Errorf("JWS[%q] = %q, want %q", key, got, want)
		}
	}
	checkStr("iss", witnessTestIssuer)
	checkStr("sub", witnessTestUserIDStr)
	checkStr("device_uuid", witnessTestDeviceUUID)
	checkStr("ek_pubkey_hash", witnessTestEKHash)
	checkStr("witness_method", "passkey")
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Error("jti missing")
	}
	if amr, _ := claims["amr"].([]interface{}); len(amr) != 1 || fmt.Sprint(amr[0]) != "hwk" {
		t.Errorf("amr = %v, want [hwk]", claims["amr"])
	}
	switch v := claims["aud"].(type) {
	case string:
		if v != "https://jess.internal.example.com/device-attest" {
			t.Errorf("aud = %q", v)
		}
	case []interface{}:
		if len(v) == 0 || fmt.Sprint(v[0]) != "https://jess.internal.example.com/device-attest" {
			t.Errorf("aud = %v", v)
		}
	default:
		t.Errorf("unexpected aud type %T", claims["aud"])
	}
	expF, _ := claims["exp"].(float64)
	if delta := time.Until(time.Unix(int64(expF), 0)); delta < 9*time.Minute || delta > 11*time.Minute {
		t.Errorf("exp delta = %s, want ~10m", delta.Round(time.Second))
	}
}

func TestFinishWitnessEnroll_WithoutBeginIsRefused(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	w := witnessPost(t, r, witnessFinishPath, map[string]string{"device_uuid": witnessTestDeviceUUID})
	if w.Code != http.StatusGone {
		t.Fatalf("expected 410 without a begun session, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWitnessEnroll_BindingIsSingleUse(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	witnessBegun(t, r)
	if w := witnessPost(t, r, witnessFinishPath, map[string]string{}); w.Code != http.StatusOK {
		t.Fatalf("first finish: %d %s", w.Code, w.Body.String())
	}
	if w := witnessPost(t, r, witnessFinishPath, map[string]string{}); w.Code != http.StatusGone {
		t.Fatalf("replayed finish: expected 410, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_OtherUsersSessionRefused(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r1 := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	witnessBegun(t, r1)
	r2 := witnessTestEngine(h, uuid.MustParse("55555555-5555-5555-5555-555555555555"), uuid.MustParse(witnessTestSessionID))
	if w := witnessPost(t, r2, witnessFinishPath, map[string]string{}); w.Code != http.StatusGone {
		t.Fatalf("expected 410 for another user's wa_session_id, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_NonPlatformAdminForbidden(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r := witnessTestEngineAs(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID), false)
	if w := witnessPost(t, r, witnessFinishPath, map[string]string{}); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_MissingWASessionID(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish", map[string]string{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing wa_session_id, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_AssertionFails(t *testing.T) {
	stub := &witnessWebAuthnStub{finishErr: errors.New("signature mismatch")}
	h := newWitnessHandler(t, stub, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	witnessBegun(t, r)
	if w := witnessPost(t, r, witnessFinishPath, map[string]string{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when assertion fails, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_TokenServiceNotWired(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	if w := witnessPost(t, r, witnessFinishPath, map[string]string{}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when TokenService not wired, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_NoSigningKey(t *testing.T) {
	cfg := &config.Config{JWTIssuer: witnessTestIssuer, JWTSigningAlgorithm: "RS256"}
	tokenSvc := services.NewTokenService(cfg, nil, nil) // no key provider -> ErrNoSigningKey
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, tokenSvc)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))
	witnessBegun(t, r)
	if w := witnessPost(t, r, witnessFinishPath, map[string]string{}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no signing key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWitnessEnroll_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r.POST("/witness/finish", h.FinishWitnessEnroll) // no injectUser middleware
	if w := witnessPost(t, r, "/witness/finish?wa_session_id=abc", map[string]string{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated caller, got %d", w.Code)
	}
}
