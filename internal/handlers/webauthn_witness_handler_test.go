// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// webauthn_witness_handler_test.go covers the ZTNA Path B witness endpoints:
//   - POST /api/v1/auth/webauthn/witness/begin
//   - POST /api/v1/auth/webauthn/witness/finish?wa_session_id=<id>
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
	witnessTestIssuer     = "https://id.hexxlock.com"
	witnessTestUserIDStr  = "11111111-1111-1111-1111-111111111111"
	witnessTestSessionID  = "22222222-2222-2222-2222-222222222222"
	witnessTestDeviceUUID = "33333333-3333-3333-3333-333333333333"
)

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

// newWitnessHandler builds a WebAuthnHandler with an injected ceremony stub
// and optionally a token service.
func newWitnessHandler(t *testing.T, waStub *witnessWebAuthnStub, tokenSvc *services.TokenService) *WebAuthnHandler {
	t.Helper()
	return &WebAuthnHandler{
		witnessService: waStub,
		tokenService:   tokenSvc,
		logger:         zap.NewNop(),
	}
}

// witnessTestEngine wires the two witness routes under a gin engine that injects
// a CurrentUser and session_id into every request context.
func witnessTestEngine(h *WebAuthnHandler, userID, sessionID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	injectUser := func(c *gin.Context) {
		c.Set(middleware.CurrentUserKey, &models.CurrentUser{
			ID:       userID,
			TenantID: uuid.MustParse("44444444-4444-4444-4444-444444444444"),
			Username: "testoperator",
			Email:    "ops@example.com",
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

// ── begin tests ───────────────────────────────────────────────────────────────

func TestBeginWitnessEnroll_HappyPath(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", map[string]string{
		"device_uuid":    witnessTestDeviceUUID,
		"ek_pubkey_hash": "deadbeef0123456789ab",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBeginWitnessEnroll_MissingDeviceUUID(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", map[string]string{
		"ek_pubkey_hash": "deadbeef",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing device_uuid, got %d", w.Code)
	}
}

func TestBeginWitnessEnroll_MissingEKHash(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing ek_pubkey_hash, got %d", w.Code)
	}
}

func TestBeginWitnessEnroll_InvalidDeviceUUID(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", map[string]string{
		"device_uuid":    "not-a-uuid",
		"ek_pubkey_hash": "deadbeef",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-UUID device_uuid, got %d", w.Code)
	}
}

func TestBeginWitnessEnroll_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil)
	r.POST("/witness/begin", h.BeginWitnessEnroll) // no injectUser middleware
	w := witnessPost(t, r, "/witness/begin", map[string]string{
		"device_uuid":    witnessTestDeviceUUID,
		"ek_pubkey_hash": "deadbeef",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated caller, got %d", w.Code)
	}
}

func TestBeginWitnessEnroll_BeginAuthFails(t *testing.T) {
	stub := &witnessWebAuthnStub{beginErr: errors.New("ceremony store unavailable")}
	h := newWitnessHandler(t, stub, nil)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/begin", map[string]string{
		"device_uuid":    witnessTestDeviceUUID,
		"ek_pubkey_hash": "deadbeef",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when BeginAuthentication fails, got %d", w.Code)
	}
}

// ── finish tests ──────────────────────────────────────────────────────────────

// TestFinishWitnessEnroll_AssertionBodyReachesCeremony locks the body-restore
// fix. The finish body carries BOTH device_uuid (read by the handler) AND the
// W3C assertion (re-read by FinishAuthentication). If the handler consumes the
// stream while reading device_uuid, the ceremony parser sees an empty body and
// every finish 401s. We assert the stub's FinishAuthentication observed the full
// body.
func TestFinishWitnessEnroll_AssertionBodyReachesCeremony(t *testing.T) {
	stub := &witnessWebAuthnStub{}
	h := newWitnessHandler(t, stub, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=abc", map[string]any{
		"device_uuid": witnessTestDeviceUUID,
		"id":          "cred-id-xyz",
		"type":        "public-key",
		"response":    map[string]string{"signature": "sig-bytes"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(stub.finishBody) == 0 {
		t.Fatal("FinishAuthentication received an EMPTY body — handler consumed it before the ceremony (body-restore regression)")
	}
	if !strings.Contains(string(stub.finishBody), `"id":"cred-id-xyz"`) {
		t.Fatalf("ceremony body missing the W3C assertion payload; got %q", string(stub.finishBody))
	}
}

func TestFinishWitnessEnroll_HappyPath(t *testing.T) {
	tokenSvc := newWitnessTokenService(t)
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, tokenSvc)
	userID := uuid.MustParse(witnessTestUserIDStr)
	sessID := uuid.MustParse(witnessTestSessionID)
	r := witnessTestEngine(h, userID, sessID)

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=abc", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp witnessFinishResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.SignedJWS == "" {
		t.Fatal("signed_jws is empty")
	}
	if resp.AdminSub != witnessTestUserIDStr {
		t.Errorf("admin_sub = %q, want %q", resp.AdminSub, witnessTestUserIDStr)
	}
	if resp.IssuedAt == "" {
		t.Error("issued_at is empty")
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at is empty")
	}

	// Parse the JWS and check claims. We skip signature verification here —
	// correctness is guaranteed by jwt.SignedString in signToken which errors
	// on invalid keys, and the real RSA path is exercised by signToken itself.
	tok, _, err := jwt.NewParser().ParseUnverified(resp.SignedJWS, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)

	checkStr := func(key, want string) {
		t.Helper()
		got, _ := claims[key].(string)
		if got != want {
			t.Errorf("JWS[%q] = %q, want %q", key, got, want)
		}
	}
	checkStr("iss", witnessTestIssuer)
	checkStr("sub", witnessTestUserIDStr)
	checkStr("device_uuid", witnessTestDeviceUUID)

	// aud may be string or []interface{}.
	switch v := claims["aud"].(type) {
	case string:
		if v != "https://internal.example.com/device-attest" {
			t.Errorf("aud = %q", v)
		}
	case []interface{}:
		if len(v) == 0 || fmt.Sprint(v[0]) != "https://internal.example.com/device-attest" {
			t.Errorf("aud = %v", v)
		}
	default:
		t.Errorf("unexpected aud type %T", claims["aud"])
	}

	// exp must be ~10 minutes in the future (witnessFreshnessWindow = 10m).
	expF, _ := claims["exp"].(float64)
	expTime := time.Unix(int64(expF), 0)
	delta := time.Until(expTime)
	if delta < 9*time.Minute || delta > 11*time.Minute {
		t.Errorf("exp delta = %s, want ~10m", delta.Round(time.Second))
	}
}

func TestFinishWitnessEnroll_MissingWASessionID(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	// No ?wa_session_id query param.
	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing wa_session_id, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_MissingDeviceUUID(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=abc", map[string]string{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing device_uuid, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWitnessEnroll_AssertionFails(t *testing.T) {
	stub := &witnessWebAuthnStub{finishErr: errors.New("signature mismatch")}
	h := newWitnessHandler(t, stub, newWitnessTokenService(t))
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=abc", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when assertion fails, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_TokenServiceNotWired(t *testing.T) {
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, nil) // nil tokenService
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=abc", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when TokenService not wired, got %d", w.Code)
	}
}

func TestFinishWitnessEnroll_NoSigningKey(t *testing.T) {
	// TokenService with NO key provider wired → useRS256() = false → ErrNoSigningKey → 503.
	cfg := &config.Config{JWTIssuer: witnessTestIssuer, JWTSigningAlgorithm: "RS256"}
	tokenSvc := services.NewTokenService(cfg, nil, nil)
	// Deliberately skip SetJWTKeyProvider / SetKeyManager.

	h := newWitnessHandler(t, &witnessWebAuthnStub{}, tokenSvc)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=abc", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no signing key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinishWitnessEnroll_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := newWitnessHandler(t, &witnessWebAuthnStub{}, newWitnessTokenService(t))
	r.POST("/witness/finish", h.FinishWitnessEnroll) // no injectUser middleware
	w := witnessPost(t, r, "/witness/finish?wa_session_id=abc", map[string]string{
		"device_uuid": witnessTestDeviceUUID,
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated caller, got %d", w.Code)
	}
}

// TestFinishWitnessEnroll_WaSessionIDReuse simulates wa_session_id replay.
// The second call fails because FinishAuthentication consumes the challenge
// on first use. We model this by programming the stub to fail on the second call.
func TestFinishWitnessEnroll_WaSessionIDReuse(t *testing.T) {
	stub := &witnessWebAuthnStub{}
	tokenSvc := newWitnessTokenService(t)
	h := newWitnessHandler(t, stub, tokenSvc)
	r := witnessTestEngine(h, uuid.MustParse(witnessTestUserIDStr), uuid.MustParse(witnessTestSessionID))

	for i, tc := range []struct {
		setFinishErr bool
		wantCode     int
	}{
		{false, http.StatusOK},
		{true, http.StatusUnauthorized},
	} {
		if tc.setFinishErr {
			stub.finishErr = errors.New("challenge not found: already consumed")
		}
		w := witnessPost(t, r, "/api/v1/auth/webauthn/witness/finish?wa_session_id=reused-id", map[string]string{
			"device_uuid": witnessTestDeviceUUID,
		})
		if w.Code != tc.wantCode {
			t.Errorf("call %d: expected %d, got %d: %s", i+1, tc.wantCode, w.Code, w.Body.String())
		}
	}
}
