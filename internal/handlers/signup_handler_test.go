// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// Mock service
// ---------------------------------------------------------------------------

type mockSignupService struct{ mock.Mock }

func (m *mockSignupService) SignupPasswordPolicy() services.SignupPasswordPolicy {
	return services.SignupPasswordPolicy{Version: 1, LengthUnit: "unicode_code_points", MinLength: 12, BreachCheck: "disabled"}
}

func (m *mockSignupService) InitiateSignup(ctx context.Context, input *models.CreateSignupRequestInput, ipAddress, userAgent string) (*models.SignupRequest, error) {
	args := m.Called(ctx, input, ipAddress, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SignupRequest), args.Error(1)
}

func (m *mockSignupService) CheckUsernameAvailable(ctx context.Context, username string) (bool, string, error) {
	args := m.Called(ctx, username)
	return args.Bool(0), args.String(1), args.Error(2)
}

func (m *mockSignupService) CheckSlugAvailable(ctx context.Context, slug string) (bool, error) {
	args := m.Called(ctx, slug)
	return args.Bool(0), args.Error(1)
}

func (m *mockSignupService) SuggestSlug(ctx context.Context, name string) (string, bool) {
	args := m.Called(ctx, name)
	return args.String(0), args.Bool(1)
}

func (m *mockSignupService) VerifyEmail(ctx context.Context, input *models.VerifySignupEmailInput) (*models.SignupRequest, error) {
	args := m.Called(ctx, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SignupRequest), args.Error(1)
}

func (m *mockSignupService) CompleteSignup(ctx context.Context, input *models.CompleteSignupInput, ipAddress, userAgent string) (*services.CompleteSignupResult, error) {
	args := m.Called(ctx, input, ipAddress, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*services.CompleteSignupResult), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestRouter registers all signup routes and returns the engine.
func newTestRouter(svc SignupServiceInterface) *gin.Engine {
	r := gin.New()
	h := NewSignupHandler(svc, zap.NewNop())

	auth := r.Group("/api/v1/auth")
	auth.POST("/signup", h.InitiateSignup)
	auth.POST("/signup/verify-email", h.VerifySignupEmail)
	auth.POST("/signup/complete", h.CompleteSignup)
	auth.GET("/signup/suggest-slug", h.SuggestSlug)

	return r
}

// signupJSONBody serialises v to a *bytes.Reader suitable for httptest requests.
func signupJSONBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// signupDoRequest performs an HTTP request against the given router and returns the recorder.
func signupDoRequest(t *testing.T, router *gin.Engine, method, path string, body *bytes.Reader) *httptest.ResponseRecorder { //nolint:unparam // method is always POST currently but kept for flexibility
	t.Helper()
	w := httptest.NewRecorder()
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(context.Background(), method, path, body)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(context.Background(), method, path, nil)
	}
	require.NoError(t, err)
	router.ServeHTTP(w, req)
	return w
}

// signupDecodeJSON parses the response body into a map.
func signupDecodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&m))
	return m
}

func fakeSignupRequest(email string) *models.SignupRequest {
	now := time.Now()
	return &models.SignupRequest{
		ID:                uuid.New(),
		Email:             email,
		AccountType:       "personal",
		VerificationToken: "tok-abc",
		Verified:          false,
		ExpiresAt:         now.Add(24 * time.Hour),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func fakeVerifiedRequest(email string) *models.SignupRequest {
	req := fakeSignupRequest(email)
	req.Verified = true
	now := time.Now()
	req.VerifiedAt = &now
	return req
}

func fakeHandlerUser(tenantID uuid.UUID, email string) *models.User {
	return &models.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Email:     email,
		Username:  "jane",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// InitiateSignup handler
// ---------------------------------------------------------------------------

func TestSignupHandler_InitiateSignup_Valid_Returns201(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	signupReq := fakeSignupRequest("jane@example.com")
	svc.On("InitiateSignup", mock.Anything, mock.MatchedBy(func(i *models.CreateSignupRequestInput) bool {
		return i.Email == "jane@example.com" && i.AccountType == "personal"
	}), mock.Anything, mock.Anything).Return(signupReq, nil)

	firstName := "Jane"
	body := signupJSONBody(t, map[string]interface{}{
		"email":        "jane@example.com",
		"first_name":   firstName,
		"account_type": "personal",
	})

	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusCreated, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "Verification email sent. Please check your inbox.", resp["message"])
	assert.Equal(t, signupReq.ID.String(), resp["signup_id"])
	assert.Equal(t, "jane@example.com", resp["email"])

	svc.AssertExpectations(t)
}

func TestSignupHandler_InitiateSignup_InvalidJSON_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	// Missing required fields — only an email, no account_type.
	body := bytes.NewReader([]byte(`{"email":"bad@example.com"}`))
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "invalid request", resp["error"])
	svc.AssertNotCalled(t, "InitiateSignup")
}

func TestSignupHandler_InitiateSignup_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	body := bytes.NewReader([]byte(`not-json`))
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupHandler_InitiateSignup_ExistingUser_Returns409(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	svc.On("InitiateSignup", mock.Anything, mock.AnythingOfType("*models.CreateSignupRequestInput"),
		mock.Anything, mock.Anything).Return(nil, errors.New("an account with this email already exists"))

	body := signupJSONBody(t, map[string]interface{}{
		"email":        "existing@example.com",
		"account_type": "personal",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusConflict, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Contains(t, resp["error"], "already exists")
}

func TestSignupHandler_InitiateSignup_BusinessAccount_Returns201(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	companyName := "Acme"
	signupReq := fakeSignupRequest("ceo@acme.com")
	signupReq.AccountType = "business"
	signupReq.CompanyName = &companyName

	svc.On("InitiateSignup", mock.Anything, mock.AnythingOfType("*models.CreateSignupRequestInput"),
		mock.Anything, mock.Anything).Return(signupReq, nil)

	body := signupJSONBody(t, map[string]interface{}{
		"email":        "ceo@acme.com",
		"account_type": "business",
		"company_name": "Acme",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// ---------------------------------------------------------------------------
// VerifySignupEmail handler
// ---------------------------------------------------------------------------

func TestSignupHandler_VerifySignupEmail_Valid_Returns200(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	verified := fakeVerifiedRequest("jane@example.com")
	svc.On("VerifyEmail", mock.Anything, tokenInput("valid-token-xyz")).Return(verified, nil)

	body := signupJSONBody(t, map[string]string{"token": "valid-token-xyz"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", body)

	assert.Equal(t, http.StatusOK, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "Email verified successfully.", resp["message"])
	assert.Equal(t, verified.ID.String(), resp["signup_id"])
	assert.Equal(t, true, resp["verified"])

	svc.AssertExpectations(t)
}

func TestSignupHandler_VerifySignupEmail_MissingToken_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	body := signupJSONBody(t, map[string]string{}) // token field absent
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	svc.AssertNotCalled(t, "VerifyEmail")
}

func TestSignupHandler_VerifySignupEmail_InvalidToken_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	svc.On("VerifyEmail", mock.Anything, tokenInput("bad-token")).
		Return(nil, errors.New("invalid or expired verification token"))

	body := signupJSONBody(t, map[string]string{"token": "bad-token"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Contains(t, resp["error"], "invalid or expired")
}

func TestSignupHandler_VerifySignupEmail_ExpiredToken_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	svc.On("VerifyEmail", mock.Anything, tokenInput("expired-token")).
		Return(nil, errors.New("verification token has expired"))

	body := signupJSONBody(t, map[string]string{"token": "expired-token"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Contains(t, resp["error"], "expired")
}

// ---------------------------------------------------------------------------
// CompleteSignup handler
// ---------------------------------------------------------------------------

func TestSignupHandler_CompleteSignup_Valid_Returns201(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	signupID := uuid.New()
	tenantID := uuid.New()
	user := fakeHandlerUser(tenantID, "jane@example.com")

	svc.On("CompleteSignup", mock.Anything, mock.MatchedBy(func(i *models.CompleteSignupInput) bool {
		return i.SignupRequestID == signupID && i.Password == "SecurePass1!"
	}), mock.Anything, mock.Anything).Return(&services.CompleteSignupResult{User: user}, nil)

	body := signupJSONBody(t, map[string]interface{}{
		"signup_request_id": signupID.String(),
		"password":          "SecurePass1!",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusCreated, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "Account created successfully. You can now sign in.", resp["message"])
	assert.Equal(t, user.ID.String(), resp["user_id"])
	assert.Equal(t, "jane@example.com", resp["email"])

	svc.AssertExpectations(t)
}

func TestSignupHandler_CompleteSignup_MissingSignupRequestID_Returns400(t *testing.T) {
	// Renamed + reshaped 2026-05-22 (ENT-4 Phase 1). Password is now
	// optional (passwordless / social-only signup); the only still-
	// required input field is signup_request_id. Tests that the
	// binding tag's `required` on the UUID still fires.
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	body := signupJSONBody(t, map[string]interface{}{
		"password": "validPass1!",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "invalid request", resp["error"])
	svc.AssertNotCalled(t, "CompleteSignup")
}

func TestSignupHandler_CompleteSignup_MissingPassword_Returns422(t *testing.T) {
	// Reverted 2026-09-13 (t-<pwfix>): the ENT-4 Phase 1 premise that an
	// empty password here means "social-only signup" was wrong — this
	// endpoint carries no federation signal and is the sole completion
	// path for the self-service email/password flow (see the doc comment
	// on models.CompleteSignupInput). An empty password used to complete
	// with 201 and password_hash = NULL, permanently locking the user
	// out. It must now fail loudly at signup completion instead.
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	body := signupJSONBody(t, map[string]interface{}{
		"signup_request_id": uuid.New().String(),
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Equal(t, "password_policy_violation", signupDecodeJSON(t, w)["code"])
	svc.AssertNotCalled(t, "CompleteSignup")
}

func TestSignupHandler_CompleteSignup_MalformedBody_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	body := bytes.NewReader([]byte(`not valid json`))
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupHandler_CompleteSignup_NotVerified_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	signupID := uuid.New()
	svc.On("CompleteSignup", mock.Anything, mock.AnythingOfType("*models.CompleteSignupInput"), mock.Anything, mock.Anything).
		Return(nil, &services.SignupStateError{Code: "signup_email_unverified"})

	body := signupJSONBody(t, map[string]interface{}{
		"signup_request_id": signupID.String(),
		"password":          "Pass1234!",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "signup_email_unverified", resp["code"])
}

func TestSignupHandler_CompleteSignup_AlreadyCompleted_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	signupID := uuid.New()
	svc.On("CompleteSignup", mock.Anything, mock.AnythingOfType("*models.CompleteSignupInput"), mock.Anything, mock.Anything).
		Return(nil, &services.SignupStateError{Code: "signup_already_completed"})

	body := signupJSONBody(t, map[string]interface{}{
		"signup_request_id": signupID.String(),
		"password":          "Pass1234!",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := signupDecodeJSON(t, w)
	assert.Equal(t, "signup_already_completed", resp["code"])
}

func TestSignupHandler_CompleteSignup_ServiceError_Returns503(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	signupID := uuid.New()
	svc.On("CompleteSignup", mock.Anything, mock.AnythingOfType("*models.CompleteSignupInput"), mock.Anything, mock.Anything).
		Return(nil, errors.New("database unavailable"))

	body := signupJSONBody(t, map[string]interface{}{
		"signup_request_id": signupID.String(),
		"password":          "Pass1234!",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "signup_provisioning_failed", signupDecodeJSON(t, w)["code"])
}

func TestSignupHandler_InitiateSignup_InvalidContinuation_Returns400(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)
	svc.On("InitiateSignup", mock.Anything, mock.MatchedBy(func(i *models.CreateSignupRequestInput) bool {
		return i.Continuation == "https://evil.example/oauth/authorize"
	}), mock.Anything, mock.Anything).Return(nil, &services.SignupStateError{Code: "invalid_continuation"})

	body := signupJSONBody(t, map[string]interface{}{
		"username": "jane", "account_type": "personal", "continuation": "https://evil.example/oauth/authorize",
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_continuation", signupDecodeJSON(t, w)["code"])
}

func TestSignupHandler_InitiateSignup_OversizedContinuation_Returns400(t *testing.T) {
	t.Parallel()

	router := newTestRouter(&mockSignupService{})
	body := signupJSONBody(t, map[string]interface{}{
		"username": "jane", "account_type": "personal", "continuation": "/oauth/authorize?x=" + string(make([]byte, 5000)),
	})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignupHandler_CompleteSignup_ReturnsRedirectURL(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)
	signupID := uuid.New()
	user := fakeHandlerUser(uuid.New(), "jane@example.com")
	continuation := "/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"

	svc.On("CompleteSignup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&services.CompleteSignupResult{User: user, RedirectURL: continuation}, nil)

	body := signupJSONBody(t, map[string]interface{}{"signup_request_id": signupID.String(), "password": "SecurePass1!"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, continuation, signupDecodeJSON(t, w)["redirect_url"])
}

func TestSignupHandler_CompleteSignup_OmitsRedirectURLWhenNone(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)
	user := fakeHandlerUser(uuid.New(), "jane@example.com")
	svc.On("CompleteSignup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&services.CompleteSignupResult{User: user}, nil)

	body := signupJSONBody(t, map[string]interface{}{"signup_request_id": uuid.New().String(), "password": "SecurePass1!"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/complete", body)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotContains(t, signupDecodeJSON(t, w), "redirect_url")
}

func TestSignupHandler_VerifySignupEmail_ReturnsCompletionSecretNoStore(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)
	req := fakeSignupRequest("jane@example.com")
	req.CompletionSecret = "s3cret"
	svc.On("VerifyEmail", mock.Anything, tokenInput("tok-abc")).Return(req, nil)

	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", signupJSONBody(t, map[string]string{"token": "tok-abc"}))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s3cret", signupDecodeJSON(t, w)["completion_secret"])
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestSignupHandler_InitiateSignup_NeverReturnsCompletionSecret(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)
	req := fakeSignupRequest("jane@example.com")
	req.CompletionSecret = "must-not-leak"
	svc.On("InitiateSignup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(req, nil)

	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", signupJSONBody(t, map[string]interface{}{"username": "jane", "account_type": "personal"}))

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotContains(t, w.Body.String(), "must-not-leak")
}

// tokenInput matches a legacy token-only verify request.
func tokenInput(token string) interface{} {
	return mock.MatchedBy(func(in *models.VerifySignupEmailInput) bool { return in != nil && in.Token == token })
}

func TestSignupHandler_VerifySignupEmail_Code_PassesIdentifierAndReturns200(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)

	verified := fakeVerifiedRequest("jane@example.com")
	svc.On("VerifyEmail", mock.Anything, mock.MatchedBy(func(in *models.VerifySignupEmailInput) bool {
		return in.SignupID == "abc" && in.Code == "482 913" && in.Token == ""
	})).Return(verified, nil)

	body := signupJSONBody(t, map[string]string{"signup_id": "abc", "code": "482 913"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", body)

	assert.Equal(t, http.StatusOK, w.Code)
	svc.AssertExpectations(t)
}

func TestSignupHandler_VerifySignupEmail_CodeErrors_ExposeStableCode(t *testing.T) {
	t.Parallel()

	for _, code := range []string{"verification_code_invalid", "verification_code_expired", "verification_attempts_exceeded"} {
		svc := &mockSignupService{}
		router := newTestRouter(svc)
		svc.On("VerifyEmail", mock.Anything, mock.Anything).Return(nil, &services.SignupStateError{Code: code})

		body := signupJSONBody(t, map[string]string{"email": "jane@example.com", "code": "123456"})
		w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup/verify-email", body)

		assert.Equal(t, http.StatusBadRequest, w.Code, code)
		assert.Equal(t, code, signupDecodeJSON(t, w)["code"])
	}
}

func TestSignupHandler_InitiateSignup_ResendThrottled_Returns429(t *testing.T) {
	t.Parallel()

	svc := &mockSignupService{}
	router := newTestRouter(svc)
	svc.On("InitiateSignup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, &services.SignupStateError{Code: "resend_throttled"})

	body := signupJSONBody(t, map[string]string{"account_type": "personal", "username": "jane"})
	w := signupDoRequest(t, router, http.MethodPost, "/api/v1/auth/signup", body)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "resend_throttled", signupDecodeJSON(t, w)["code"])
}

func TestSignupHandler_SuggestSlug_Returns200(t *testing.T) {
	svc := new(mockSignupService)
	svc.On("SuggestSlug", mock.Anything, "Kaya İnşaat").Return("kaya-insaat", true)

	w := signupDoRequest(t, newTestRouter(svc), http.MethodGet, "/api/v1/auth/signup/suggest-slug?name="+url.QueryEscape("Kaya İnşaat"), nil)
	require.Equal(t, http.StatusOK, w.Code)
	body := signupDecodeJSON(t, w)
	assert.Equal(t, "kaya-insaat", body["slug"])
	assert.Equal(t, true, body["available"])
	svc.AssertExpectations(t)
}

func TestSignupHandler_SuggestSlug_UnavailableStaysOK(t *testing.T) {
	svc := new(mockSignupService)
	svc.On("SuggestSlug", mock.Anything, "").Return("", false)

	w := signupDoRequest(t, newTestRouter(svc), http.MethodGet, "/api/v1/auth/signup/suggest-slug", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, false, signupDecodeJSON(t, w)["available"])
}

func TestSignupHandler_CompleteSignup_SlugUnavailable_Returns409(t *testing.T) {
	svc := new(mockSignupService)
	svc.On("CompleteSignup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, &services.SignupStateError{Code: "slug_unavailable"})

	w := signupDoRequest(t, newTestRouter(svc), http.MethodPost, "/api/v1/auth/signup/complete",
		signupJSONBody(t, map[string]any{"signup_request_id": uuid.New().String(), "password": "SecurePass1!", "company_name": "Acme", "slug": "taken"}))
	require.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "slug_unavailable", signupDecodeJSON(t, w)["code"])
}
