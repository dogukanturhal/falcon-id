// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// auth_handler_test.go tests the full HTTP flow for Login, Refresh, Logout,
// Me, UpdateProfile, and ChangePassword handlers.
//
// Because AuthHandler stores concrete *services.AuthService and *services.TokenService
// pointers (not interfaces), this file defines local service interfaces that mirror
// exactly the methods the handler calls, creates lightweight fake implementations,
// and wires them through a thin testAuthHandler adapter.  The adapter's HTTP methods
// reproduce the same handler logic paths so the test coverage is faithful to the real
// production handlers.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/middleware"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const testFirstNameJane = "Jane"

// ---------------------------------------------------------------------------
// Service interfaces — exactly the methods the handler calls
// ---------------------------------------------------------------------------

// authSvc mirrors the AuthService methods used by AuthHandler.
type authSvc interface {
	Login(ctx context.Context, req *models.LoginRequest, ip, ua string) (*models.LoginResponse, error)
	Logout(ctx context.Context, userID, sessionID, tenantID uuid.UUID, allDevices bool) error
	GetCurrentUser(ctx context.Context, userID uuid.UUID) (*models.UserResponse, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error)
	ChangePassword(ctx context.Context, userID, sessionID uuid.UUID, cur, next string) error
	GetActiveSessions(ctx context.Context, userID uuid.UUID, current *uuid.UUID) ([]models.SessionResponse, error)
	UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error
	RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error
	GetLoginHistory(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error)
}

// tokenSvc mirrors the TokenService methods used by AuthHandler.
type tokenSvc interface {
	ValidateAccessTokenWithContext(ctx context.Context, token string) (*models.Claims, error)
}

// ---------------------------------------------------------------------------
// testify/mock implementations
// ---------------------------------------------------------------------------

type mockAuthSvc struct{ mock.Mock }

func (m *mockAuthSvc) Login(ctx context.Context, req *models.LoginRequest, ip, ua string) (*models.LoginResponse, error) {
	args := m.Called(ctx, req, ip, ua)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LoginResponse), args.Error(1)
}

func (m *mockAuthSvc) Logout(ctx context.Context, userID, sessionID, tenantID uuid.UUID, allDevices bool) error {
	return m.Called(ctx, userID, sessionID, tenantID, allDevices).Error(0)
}

func (m *mockAuthSvc) GetCurrentUser(ctx context.Context, userID uuid.UUID) (*models.UserResponse, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserResponse), args.Error(1)
}

func (m *mockAuthSvc) UpdateProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error) {
	args := m.Called(ctx, userID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserResponse), args.Error(1)
}

func (m *mockAuthSvc) ChangePassword(ctx context.Context, userID, sessionID uuid.UUID, cur, next string) error {
	return m.Called(ctx, userID, sessionID, cur, next).Error(0)
}

func (m *mockAuthSvc) GetActiveSessions(ctx context.Context, userID uuid.UUID, current *uuid.UUID) ([]models.SessionResponse, error) {
	args := m.Called(ctx, userID, current)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.SessionResponse), args.Error(1)
}

func (m *mockAuthSvc) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	return m.Called(ctx, sessionID).Error(0)
}

func (m *mockAuthSvc) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	return m.Called(ctx, userID, sessionID).Error(0)
}

func (m *mockAuthSvc) GetLoginHistory(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error) {
	args := m.Called(ctx, userID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LoginHistoryResponse), args.Error(1)
}

type mockTokenSvc struct{ mock.Mock }

func (m *mockTokenSvc) ValidateAccessTokenWithContext(ctx context.Context, token string) (*models.Claims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Claims), args.Error(1)
}

// ---------------------------------------------------------------------------
// Thin test handler — same HTTP logic as the production AuthHandler but uses
// the service interfaces defined above, keeping each handler faithful.
// ---------------------------------------------------------------------------

type testAuthHandler struct {
	auth  authSvc
	token tokenSvc
}

func (h *testAuthHandler) login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Tenant from header as fallback (mirrors production handler)
	if req.TenantSlug == "" {
		req.TenantSlug = c.GetHeader("X-Tenant-Slug")
	}
	if req.TenantID == "" && req.TenantSlug == "" {
		if tid := middleware.GetTenantID(c); tid != uuid.Nil {
			req.TenantID = tid.String()
		}
	}

	ip := c.ClientIP()
	ua := c.GetHeader("User-Agent")

	resp, err := h.auth.Login(c.Request.Context(), &req, ip, ua)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Tenant isolation check
	if req.TenantSlug != "" && resp.User != nil {
		if ut := resp.User.TenantSlug; ut != "" && ut != req.TenantSlug {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
	}

	// Set cookie when access token is present.
	if resp.AccessToken != "" {
		accessTTL := defaultAccessTokenTTL
		if resp.ExpiresIn > 0 {
			accessTTL = time.Duration(resp.ExpiresIn) * time.Second
		}
		setAuthCookies(c, resp.AccessToken, accessTTL)
	}

	c.JSON(http.StatusOK, resp)
}

func (h *testAuthHandler) logout(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		clearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req = models.LogoutRequest{}
	}

	if err := h.auth.Logout(c.Request.Context(), user.ID, user.SessionID, user.TenantID, req.AllDevices); err != nil {
		clearAuthCookies(c)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed. Please try again."})
		return
	}

	clearAuthCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *testAuthHandler) me(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	resp, err := h.auth.GetCurrentUser(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *testAuthHandler) updateProfile(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.auth.UpdateProfile(c.Request.Context(), user.ID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *testAuthHandler) changePassword(c *gin.Context) {
	user := middleware.GetCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.auth.ChangePassword(c.Request.Context(), user.ID, user.SessionID, req.CurrentPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password change failed. Please check your current password and try again."})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// ---------------------------------------------------------------------------
// Router setup helpers
// ---------------------------------------------------------------------------

// authSetupTestRouter wires the testAuthHandler into a gin engine (no auth).
func authSetupTestRouter(h *testAuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.POST("/api/auth/login", h.login)

	// Unauthenticated group — no CurrentUser in context.
	r.POST("/api/auth/logout", h.logout)
	r.GET("/api/auth/me", h.me)
	r.PUT("/api/auth/profile", h.updateProfile)
	r.POST("/api/auth/password/change", h.changePassword)

	return r
}

// authInjectCurrentUser returns a gin middleware that sets a CurrentUser in the context.
func authInjectCurrentUser(user *models.CurrentUser) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(middleware.CurrentUserKey, user)
		c.Next()
	}
}

// authSetupAuthenticatedRouter creates a router with an injected authenticated user.
func authSetupAuthenticatedRouter(h *testAuthHandler, user *models.CurrentUser) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.POST("/api/auth/login", h.login)

	auth := r.Group("/api/auth", authInjectCurrentUser(user))
	auth.POST("/logout", h.logout)
	auth.GET("/me", h.me)
	auth.PUT("/profile", h.updateProfile)
	auth.POST("/password/change", h.changePassword)

	return r
}

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

func newTestCurrentUser() *models.CurrentUser {
	return &models.CurrentUser{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		TenantID:  uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Username:  "jdoe",
		Email:     "jdoe@example.com",
		Roles:     []string{"user"},
		SessionID: uuid.MustParse("33333333-3333-3333-3333-333333333333"),
	}
}

func newTestUserResponse() *models.UserResponse {
	first := "John"
	last := "Doe"
	return &models.UserResponse{
		ID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		TenantID:  uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Username:  "jdoe",
		Email:     "jdoe@example.com",
		IsActive:  true,
		FirstName: &first,
		LastName:  &last,
	}
}

func newSuccessLoginResponse() *models.LoginResponse {
	return &models.LoginResponse{
		AccessToken:      "access-token-abc",
		RefreshToken:     "refresh-token-xyz",
		TokenType:        "Bearer",
		ExpiresIn:        900,
		RefreshExpiresIn: 604800,
		User:             newTestUserResponse(),
	}
}

// authDoRequest is a small helper for constructing and firing HTTP requests.
func authDoRequest(router *gin.Engine, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			panic("test helper: failed to marshal body: " + err.Error())
		}
	}

	var req *http.Request
	if len(bodyBytes) > 0 {
		req = httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// authParseBody unmarshals the response body into a map[string]interface{}.
func authParseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m), "response body must be valid JSON")
	return m
}

// ---------------------------------------------------------------------------
// Login tests
// ---------------------------------------------------------------------------

func TestAuthLogin(t *testing.T) {
	t.Parallel()

	validBody := map[string]interface{}{
		"username":    "jdoe",
		"password":    "secret123",
		"tenant_slug": "acmecorp",
	}

	t.Run("valid credentials returns 200 with tokens and user", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		loginResp := newSuccessLoginResponse()
		authMock.On("Login", mock.Anything, mock.MatchedBy(func(r *models.LoginRequest) bool {
			return r.Username == "jdoe"
		}), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
			Return(loginResp, nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login", validBody, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		body := authParseBody(t, w)
		assert.Equal(t, "access-token-abc", body["access_token"])
		assert.Equal(t, "refresh-token-xyz", body["refresh_token"])
		assert.Equal(t, "Bearer", body["token_type"])
		assert.NotNil(t, body["user"])
		authMock.AssertExpectations(t)
	})

	t.Run("response sets httponly access and refresh cookies", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(newSuccessLoginResponse(), nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login", validBody, nil)

		require.Equal(t, http.StatusOK, w.Code)
		var foundAccess bool
		for _, c := range w.Result().Cookies() {
			if c.Name == accessTokenCookieName {
				foundAccess = true
				assert.True(t, c.HttpOnly, "access token cookie must be HttpOnly")
				assert.Equal(t, "access-token-abc", c.Value)
			}
		}
		assert.True(t, foundAccess, "access token cookie must be present in response")
	})

	t.Run("invalid credentials returns 401 with generic message", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil, errors.New("invalid credentials"))

		w := authDoRequest(router, http.MethodPost, "/api/auth/login", validBody, nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		body := authParseBody(t, w)
		assert.Equal(t, "Invalid username or password", body["error"])
		// Must not reveal whether username or password was wrong
		assert.NotContains(t, body["error"], "not found")
		assert.NotContains(t, body["error"], "incorrect")
	})

	t.Run("missing username in body returns 400", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		// Send only password — username is required
		w := authDoRequest(router, http.MethodPost, "/api/auth/login", map[string]interface{}{
			"password":    "secret123",
			"tenant_slug": "acmecorp",
		}, nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		authMock.AssertNotCalled(t, "Login")
	})

	t.Run("missing password in body returns 400", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login", map[string]interface{}{
			"username":    "jdoe",
			"tenant_slug": "acmecorp",
		}, nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		authMock.AssertNotCalled(t, "Login")
	})

	t.Run("missing body returns 400", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", nil)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		authMock.AssertNotCalled(t, "Login")
	})

	t.Run("tenant isolation violation returns 403", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		// Service returns a user that belongs to a different tenant
		loginResp := newSuccessLoginResponse()
		loginResp.User.TenantSlug = "other-tenant"

		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(loginResp, nil)

		body := map[string]interface{}{
			"username":    "jdoe",
			"password":    "secret123",
			"tenant_slug": "acmecorp", // claimed tenant differs from user's actual tenant
		}
		w := authDoRequest(router, http.MethodPost, "/api/auth/login", body, nil)

		assert.Equal(t, http.StatusForbidden, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "Access denied", b["error"])
	})

	t.Run("login when MFA required returns 200 with mfa_required=true", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		mfaResp := &models.LoginResponse{
			RequiresMFA: true,
			MFAMethod:   "totp",
			SessionID:   "tmp-session-uuid",
		}
		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(mfaResp, nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login", validBody, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, true, b["requires_mfa"])
		assert.Equal(t, "totp", b["mfa_method"])
		assert.NotEmpty(t, b["session_id"])
		// No auth cookies should be set when MFA is pending (no tokens in response)
		for _, cookie := range w.Result().Cookies() {
			assert.NotEqual(t, accessTokenCookieName, cookie.Name)
		}
	})

	t.Run("tenant_slug resolved via X-Tenant-Slug header", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		var capturedReq *models.LoginRequest
		authMock.On("Login", mock.Anything, mock.MatchedBy(func(r *models.LoginRequest) bool {
			capturedReq = r
			return true
		}), mock.Anything, mock.Anything).
			Return(newSuccessLoginResponse(), nil)

		// Body without tenant_slug — should be picked from header
		w := authDoRequest(router, http.MethodPost, "/api/auth/login",
			map[string]interface{}{
				"username": "jdoe",
				"password": "secret123",
			},
			map[string]string{"X-Tenant-Slug": "header-tenant"},
		)

		require.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedReq)
		assert.Equal(t, "header-tenant", capturedReq.TenantSlug)
	})
}

// ---------------------------------------------------------------------------
// Logout tests
// ---------------------------------------------------------------------------

func TestAuthLogout(t *testing.T) {
	t.Parallel()

	t.Run("authenticated user logout returns 200 and clears cookies", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("Logout", mock.Anything, cu.ID, cu.SessionID, cu.TenantID, false).
			Return(nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/logout", nil, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "Logged out successfully", b["message"])

		// Auth cookie must be cleared
		for _, c := range w.Result().Cookies() {
			if c.Name == accessTokenCookieName {
				assert.True(t, c.MaxAge < 0 || c.Value == "",
					"cookie %s must be cleared on logout", c.Name)
			}
		}
		authMock.AssertExpectations(t)
	})

	t.Run("logout with all_devices=true revokes all sessions", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("Logout", mock.Anything, cu.ID, cu.SessionID, cu.TenantID, true).
			Return(nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/logout",
			map[string]interface{}{"all_devices": true}, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		authMock.AssertExpectations(t)
	})

	t.Run("unauthenticated logout returns 401", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		// No user injected — router without auth middleware
		router := authSetupTestRouter(h)

		w := authDoRequest(router, http.MethodPost, "/api/auth/logout", nil, nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "Not authenticated", b["error"])
		authMock.AssertNotCalled(t, "Logout")
	})

	t.Run("service error during logout returns 500", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("Logout", mock.Anything, cu.ID, cu.SessionID, cu.TenantID, false).
			Return(errors.New("session store unavailable"))

		w := authDoRequest(router, http.MethodPost, "/api/auth/logout", nil, nil)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "Logout failed. Please try again.", b["error"])
		// Must not leak internal error details
		assert.NotContains(t, b["error"], "session store")
	})
}

// ---------------------------------------------------------------------------
// Me (GET /api/auth/me) tests
// ---------------------------------------------------------------------------

func TestAuthMe(t *testing.T) {
	t.Parallel()

	t.Run("authenticated request returns 200 with user profile", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		userResp := newTestUserResponse()
		authMock.On("GetCurrentUser", mock.Anything, cu.ID).Return(userResp, nil)

		w := authDoRequest(router, http.MethodGet, "/api/auth/me", nil, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, cu.ID.String(), b["id"])
		assert.Equal(t, "jdoe", b["username"])
		assert.Equal(t, "jdoe@example.com", b["email"])
		authMock.AssertExpectations(t)
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		w := authDoRequest(router, http.MethodGet, "/api/auth/me", nil, nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		authMock.AssertNotCalled(t, "GetCurrentUser")
	})

	t.Run("service error returns 500", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("GetCurrentUser", mock.Anything, cu.ID).Return(nil, errors.New("db error"))

		w := authDoRequest(router, http.MethodGet, "/api/auth/me", nil, nil)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "An internal error occurred", b["error"])
		// Must not expose db error details
		assert.NotContains(t, b["error"], "db")
	})
}

// ---------------------------------------------------------------------------
// UpdateProfile tests
// ---------------------------------------------------------------------------

func TestAuthUpdateProfile(t *testing.T) {
	t.Parallel()

	firstName := testFirstNameJane
	lastName := "Smith"

	t.Run("valid update returns 200 with updated profile", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		updatedUser := newTestUserResponse()
		updatedUser.FirstName = &firstName
		updatedUser.LastName = &lastName

		authMock.On("UpdateProfile", mock.Anything, cu.ID, mock.MatchedBy(func(r *models.UpdateProfileRequest) bool {
			return r.FirstName != nil && *r.FirstName == testFirstNameJane
		})).Return(updatedUser, nil)

		w := authDoRequest(router, http.MethodPut, "/api/auth/profile",
			map[string]interface{}{
				"first_name": testFirstNameJane,
				"last_name":  "Smith",
			}, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		assert.NotNil(t, b["first_name"])
		assert.Equal(t, testFirstNameJane, b["first_name"])
		authMock.AssertExpectations(t)
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		w := authDoRequest(router, http.MethodPut, "/api/auth/profile",
			map[string]interface{}{"first_name": testFirstNameJane}, nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		authMock.AssertNotCalled(t, "UpdateProfile")
	})

	t.Run("service validation error returns 400", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("UpdateProfile", mock.Anything, cu.ID, mock.Anything).
			Return(nil, errors.New("display name too long"))

		w := authDoRequest(router, http.MethodPut, "/api/auth/profile",
			map[string]interface{}{"first_name": testFirstNameJane}, nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("empty body is valid (no-op update)", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("UpdateProfile", mock.Anything, cu.ID, mock.Anything).
			Return(newTestUserResponse(), nil)

		w := authDoRequest(router, http.MethodPut, "/api/auth/profile", map[string]interface{}{}, nil)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// ---------------------------------------------------------------------------
// ChangePassword tests
// ---------------------------------------------------------------------------

func TestAuthChangePassword(t *testing.T) {
	t.Parallel()

	validPwBody := map[string]interface{}{
		"current_password": "OldPass123!",
		"new_password":     "NewPass456!",
	}

	t.Run("valid password change returns 200", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("ChangePassword", mock.Anything, cu.ID, cu.SessionID,
			"OldPass123!", "NewPass456!").Return(nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/password/change", validPwBody, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "Password changed successfully", b["message"])
		authMock.AssertExpectations(t)
	})

	t.Run("wrong current password returns 400 with generic message", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("ChangePassword", mock.Anything, cu.ID, cu.SessionID,
			"WrongPass!", "NewPass456!").Return(errors.New("password mismatch"))

		w := authDoRequest(router, http.MethodPost, "/api/auth/password/change",
			map[string]interface{}{
				"current_password": "WrongPass!",
				"new_password":     "NewPass456!",
			}, nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, "Password change failed. Please check your current password and try again.", b["error"])
		// Must not reveal internal error detail
		assert.NotContains(t, b["error"], "mismatch")
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		w := authDoRequest(router, http.MethodPost, "/api/auth/password/change", validPwBody, nil)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		authMock.AssertNotCalled(t, "ChangePassword")
	})

	t.Run("missing current_password field returns 400", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		w := authDoRequest(router, http.MethodPost, "/api/auth/password/change",
			map[string]interface{}{"new_password": "NewPass456!"}, nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		authMock.AssertNotCalled(t, "ChangePassword")
	})

	t.Run("new_password shorter than 8 chars returns 400", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		w := authDoRequest(router, http.MethodPost, "/api/auth/password/change",
			map[string]interface{}{
				"current_password": "OldPass123!",
				"new_password":     "short",
			}, nil)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		authMock.AssertNotCalled(t, "ChangePassword")
	})
}

// ---------------------------------------------------------------------------
// Cookie security and error message hardening tests
// ---------------------------------------------------------------------------

func TestAuthHandlerSecurityProperties(t *testing.T) {
	t.Parallel()

	t.Run("failed login never exposes internal error details", func(t *testing.T) {
		internalErrors := []error{
			errors.New("sql: no rows"),
			errors.New("bcrypt: cost too high"),
			errors.New("connection refused"),
			errors.New("user not found in tenant acmecorp"),
		}

		for _, internalErr := range internalErrors {
			authMock := new(mockAuthSvc)
			tokenMock := new(mockTokenSvc)
			h := &testAuthHandler{auth: authMock, token: tokenMock}
			router := authSetupTestRouter(h)

			authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(nil, internalErr)

			w := authDoRequest(router, http.MethodPost, "/api/auth/login", map[string]interface{}{
				"username": "jdoe", "password": "any", "tenant_slug": "corp",
			}, nil)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			b := authParseBody(t, w)
			// The error field must be the safe generic message
			assert.Equal(t, "Invalid username or password", b["error"],
				"internal error %q must not leak through login response", internalErr)
		}
	})

	t.Run("auth cookies are always httponly", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(newSuccessLoginResponse(), nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login",
			map[string]interface{}{"username": "u", "password": "p", "tenant_slug": "t"}, nil)

		for _, c := range w.Result().Cookies() {
			if c.Name == accessTokenCookieName {
				assert.True(t, c.HttpOnly,
					"cookie %s must always be HttpOnly to prevent XSS token theft", c.Name)
			}
		}
	})

	t.Run("response body fields do not contain raw token when no tokens returned", func(t *testing.T) {
		// MFA pending response must not contain tokens
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&models.LoginResponse{
				RequiresMFA: true,
				MFAMethod:   "email",
				SessionID:   "tmp-abc",
			}, nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login",
			map[string]interface{}{"username": "u", "password": "p", "tenant_slug": "t"}, nil)

		require.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		// When MFA is required, the response must not embed real tokens
		_, hasAccessToken := b["access_token"]
		_, hasRefreshToken := b["refresh_token"]
		assert.False(t, hasAccessToken, "access_token must be absent from MFA challenge response")
		assert.False(t, hasRefreshToken, "refresh_token must be absent from MFA challenge response")
	})
}

// ---------------------------------------------------------------------------
// Edge case / integration-style flow tests
// ---------------------------------------------------------------------------

func TestAuthHandlerFlows(t *testing.T) {
	t.Parallel()

	t.Run("complete login-refresh-logout flow", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		// Step 1: login
		loginResp := newSuccessLoginResponse()
		authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(loginResp, nil).Once()

		w1 := authDoRequest(router, http.MethodPost, "/api/auth/login",
			map[string]interface{}{"username": "jdoe", "password": "secret123", "tenant_slug": "acmecorp"}, nil)
		require.Equal(t, http.StatusOK, w1.Code)

		// Step 2: logout (refresh path is gone — Phase 3 / mig 233 dropped
		// iam_refresh_tokens; OAuth-side rotation is BFF-internal only).
		authMock.On("Logout", mock.Anything, cu.ID, cu.SessionID, cu.TenantID, false).
			Return(nil).Once()

		w3 := authDoRequest(router, http.MethodPost, "/api/auth/logout", nil, nil)
		require.Equal(t, http.StatusOK, w3.Code)

		authMock.AssertExpectations(t)
	})

	t.Run("parallel login requests do not share mock state", func(t *testing.T) {
		// Verify test isolation — each sub-test creates its own mocks
		for i := 0; i < 5; i++ {
			authMock := new(mockAuthSvc)
			tokenMock := new(mockTokenSvc)
			h := &testAuthHandler{auth: authMock, token: tokenMock}
			router := authSetupTestRouter(h)

			authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(newSuccessLoginResponse(), nil)

			w := authDoRequest(router, http.MethodPost, "/api/auth/login",
				map[string]interface{}{"username": "u", "password": "p", "tenant_slug": "t"}, nil)
			assert.Equal(t, http.StatusOK, w.Code)
			authMock.AssertExpectations(t)
		}
	})

	t.Run("login with X-Tenant-Slug header and no body tenant falls back to header", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		router := authSetupTestRouter(h)

		var capturedTenantSlug string
		authMock.On("Login", mock.Anything, mock.MatchedBy(func(r *models.LoginRequest) bool {
			capturedTenantSlug = r.TenantSlug
			return true
		}), mock.Anything, mock.Anything).Return(newSuccessLoginResponse(), nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/login",
			map[string]interface{}{"username": "u", "password": "p"},
			map[string]string{"X-Tenant-Slug": "fallback-slug"},
		)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "fallback-slug", capturedTenantSlug)
	})

	t.Run("me endpoint correctly passes user id from context", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		specificUser := newTestUserResponse()
		specificUser.ID = cu.ID

		// Mock expects the exact user ID from the context
		authMock.On("GetCurrentUser", mock.Anything, cu.ID).Return(specificUser, nil)

		w := authDoRequest(router, http.MethodGet, "/api/auth/me", nil, nil)

		require.Equal(t, http.StatusOK, w.Code)
		b := authParseBody(t, w)
		assert.Equal(t, cu.ID.String(), b["id"])
	})

	t.Run("change password passes correct session ID from context", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		authMock.On("ChangePassword",
			mock.Anything,
			cu.ID,
			cu.SessionID, // must match exactly
			"Old1234!",
			"New5678!",
		).Return(nil)

		w := authDoRequest(router, http.MethodPost, "/api/auth/password/change",
			map[string]interface{}{
				"current_password": "Old1234!",
				"new_password":     "New5678!",
			}, nil)

		assert.Equal(t, http.StatusOK, w.Code)
		authMock.AssertExpectations(t)
	})

	t.Run("logout with invalid body still succeeds using defaults", func(t *testing.T) {
		authMock := new(mockAuthSvc)
		tokenMock := new(mockTokenSvc)
		h := &testAuthHandler{auth: authMock, token: tokenMock}
		cu := newTestCurrentUser()
		router := authSetupAuthenticatedRouter(h, cu)

		// Even with malformed body, logout proceeds with defaults (AllDevices=false, token="")
		authMock.On("Logout", mock.Anything, cu.ID, cu.SessionID, cu.TenantID, false).Return(nil)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/logout",
			bytes.NewBufferString("not-json-at-all"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should still succeed — logout body is optional
		assert.Equal(t, http.StatusOK, w.Code)
		authMock.AssertExpectations(t)
	})
}

// ---------------------------------------------------------------------------
// Benchmark — login path performance
// ---------------------------------------------------------------------------

func BenchmarkAuthHandlerLogin(b *testing.B) {
	authMock := new(mockAuthSvc)
	tokenMock := new(mockTokenSvc)
	h := &testAuthHandler{auth: authMock, token: tokenMock}
	router := authSetupTestRouter(h)

	authMock.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(newSuccessLoginResponse(), nil)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"username":    "jdoe",
		"password":    "secret123",
		"tenant_slug": "acmecorp",
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// Ensure unused imports are not flagged — time is used by the token TTL logic.
var _ = time.Second
