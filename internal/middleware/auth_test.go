// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// authTestConfig returns a config suitable for auth middleware tests.
func authTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:              "test-secret-key-for-jwt-signing-at-least-32-chars",
		JWTIssuer:              "hexxlock-test",
		AccessTokenExpiry:      15 * time.Minute,
		JWTHMACFallbackEnabled: true, // allow HS256 tokens in tests
	}
}

// newAuthTestTokenService builds a real TokenService backed by no-op mock repos.
// No Redis is attached, so token blacklist checks are skipped.
func newAuthTestTokenService(cfg *config.Config) *services.TokenService {
	mockTokenRepo := new(MockAuthTokenRepository)
	mockUserRepo := new(MockAuthUserRepository)
	return services.NewTokenService(cfg, mockTokenRepo, mockUserRepo)
}

// buildValidToken generates a signed JWT matching what ValidateAccessTokenWithContext expects.
func buildValidToken(t *testing.T, cfg *config.Config, userID, tenantID, sessionID uuid.UUID, roles, permissions []string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":               cfg.JWTIssuer,
		"aud":               "hexxlock-services",
		"sub":               userID.String(),
		"user_id":           userID.String(),
		"tenant_id":         tenantID.String(),
		"username":          "testuser",
		"email":             "test@example.com",
		"roles":             roles,
		"permissions":       permissions,
		"session_id":        sessionID.String(),
		"realm_id":          uuid.New().String(),
		"realm_slug":        "default",
		"realm_type":        "shared",
		"is_platform_admin": false,
		"v":                 0,
		"iat":               now.Unix(),
		"exp":               now.Add(15 * time.Minute).Unix(),
		"nbf":               now.Unix(),
		"jti":               uuid.New().String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)
	return signed
}

// buildExpiredToken generates a JWT that is already expired.
func buildExpiredToken(t *testing.T, cfg *config.Config, userID, tenantID, sessionID uuid.UUID) string {
	t.Helper()
	past := time.Now().Add(-2 * time.Hour)
	claims := jwt.MapClaims{
		"iss":        cfg.JWTIssuer,
		"aud":        "hexxlock-services",
		"sub":        userID.String(),
		"user_id":    userID.String(),
		"tenant_id":  tenantID.String(),
		"username":   "testuser",
		"email":      "test@example.com",
		"session_id": sessionID.String(),
		"realm_id":   uuid.New().String(),
		"v":          0,
		"iat":        past.Add(-15 * time.Minute).Unix(),
		"exp":        past.Unix(), // already expired
		"nbf":        past.Add(-15 * time.Minute).Unix(),
		"jti":        uuid.New().String(),
	}
	// Use jwt.NewWithClaims but bypass standard expiry validation when signing
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)
	return signed
}

// --- Minimal mock repositories needed to construct TokenService ---

type MockAuthTokenRepository struct{}

func (m *MockAuthTokenRepository) CleanupExpiredPasswordResets(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *MockAuthTokenRepository) CreatePasswordReset(_ context.Context, _ *models.PasswordReset) error {
	return nil
}

func (m *MockAuthTokenRepository) GetPasswordReset(_ context.Context, _ string) (*models.PasswordReset, error) {
	return nil, nil
}

func (m *MockAuthTokenRepository) InvalidateUserPasswordResets(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (m *MockAuthTokenRepository) MarkPasswordResetUsed(_ context.Context, _ uuid.UUID) error {
	return nil
}

type MockAuthUserRepository struct{}

func (m *MockAuthUserRepository) GetByID(_ context.Context, _ uuid.UUID) (*models.User, error) {
	return nil, nil
}

func (m *MockAuthUserRepository) GetUserRoles(_ context.Context, _ uuid.UUID) ([]models.Role, error) {
	return nil, nil
}

func (m *MockAuthUserRepository) GetUserPermissions(_ context.Context, _ uuid.UUID) ([]models.Permission, error) {
	return nil, nil
}
func (m *MockAuthUserRepository) Update(_ context.Context, _ *models.User) error { return nil }

// --- Test helpers ---

// newAuthRouter builds a fresh gin.Engine with RequireAuth applied.
func newAuthRouter(m *AuthMiddleware) *gin.Engine {
	router := gin.New()
	router.GET("/protected", m.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	router.POST("/protected", m.RequireAuth(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

// ==================== RequireAuth tests ====================

func TestRequireAuth_ValidBearerToken_SetsCurrentUserAndCallsNext(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	var capturedUser *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/protected", m.RequireAuth(), func(c *gin.Context) {
		capturedUser = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	token := buildValidToken(t, cfg, userID, tenantID, sessionID, []string{"admin"}, []string{"read:users"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser, "current_user should be set in context")
	assert.Equal(t, userID, capturedUser.ID)
	assert.Equal(t, tenantID, capturedUser.TenantID)
	assert.Equal(t, sessionID, capturedUser.SessionID)
	assert.Equal(t, "testuser", capturedUser.Username)
	assert.Equal(t, "test@example.com", capturedUser.Email)
}

func TestRequireAuth_MissingAuthorizationHeader_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_MalformedBearerHeader_MissingToken_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer") // missing actual token
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_WrongScheme_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // Basic auth, not Bearer
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_InvalidToken_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer this.is.not.a.valid.jwt")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_TokenSignedWithWrongKey_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	// Sign with a different key than what the service expects
	differentKeyCfg := *cfg
	differentKeyCfg.JWTSecret = "completely-different-secret-key-which-is-at-least-32"
	token := buildValidToken(t, &differentKeyCfg, uuid.New(), uuid.New(), uuid.New(), nil, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_ExpiredToken_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	token := buildExpiredToken(t, cfg, uuid.New(), uuid.New(), uuid.New())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_ValidTokenInCookie_SetsCurrentUser(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	var capturedUser *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/protected", m.RequireAuth(), func(c *gin.Context) {
		capturedUser = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	token := buildValidToken(t, cfg, userID, tenantID, sessionID, []string{"user"}, []string{"read:profile"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_access_token", Value: token})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, userID, capturedUser.ID)
	assert.Equal(t, tenantID, capturedUser.TenantID)
}

func TestRequireAuth_BothHeaderAndCookie_HeaderTakesPrecedence(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userIDHeader := uuid.New()
	userIDCookie := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	var capturedUser *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/protected", m.RequireAuth(), func(c *gin.Context) {
		capturedUser = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	headerToken := buildValidToken(t, cfg, userIDHeader, tenantID, sessionID, nil, nil)
	cookieToken := buildValidToken(t, cfg, userIDCookie, tenantID, sessionID, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+headerToken)
	req.AddCookie(&http.Cookie{Name: "falcon_access_token", Value: cookieToken})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	// The header token should have been used (userIDHeader, not userIDCookie)
	assert.Equal(t, userIDHeader, capturedUser.ID)
}

func TestRequireAuth_ValidToken_SetsAllContextKeys(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	var gotUserID, gotTenantID, gotSessionID interface{}
	var gotCurrentUser, gotCurrentSession interface{}
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/protected", m.RequireAuth(), func(c *gin.Context) {
		gotUserID, _ = c.Get("user_id")
		gotTenantID, _ = c.Get("tenant_id")
		gotSessionID, _ = c.Get("session_id")
		gotCurrentUser, _ = c.Get(CurrentUserKey)
		gotCurrentSession, _ = c.Get(CurrentSessionKey)
		c.Status(http.StatusOK)
	})

	token := buildValidToken(t, cfg, userID, tenantID, sessionID, []string{"user"}, []string{"read:profile"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, userID, gotUserID)
	assert.Equal(t, tenantID, gotTenantID)
	assert.Equal(t, sessionID, gotSessionID)
	assert.NotNil(t, gotCurrentUser)
	assert.NotNil(t, gotCurrentSession)
}

func TestRequireAuth_ImpersonationToken_SetsImpersonatorContext(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()
	impersonatorID := uuid.New()
	impersonationSessionID := uuid.New()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                      cfg.JWTIssuer,
		"aud":                      "hexxlock-services",
		"sub":                      userID.String(),
		"user_id":                  userID.String(),
		"tenant_id":                tenantID.String(),
		"username":                 "testuser",
		"email":                    "test@example.com",
		"session_id":               sessionID.String(),
		"realm_id":                 uuid.New().String(),
		"is_platform_admin":        false,
		"v":                        0,
		"iat":                      now.Unix(),
		"exp":                      now.Add(15 * time.Minute).Unix(),
		"nbf":                      now.Unix(),
		"jti":                      uuid.New().String(),
		"impersonator_id":          impersonatorID.String(),
		"impersonation_session_id": impersonationSessionID.String(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)

	var gotImpersonatorID, gotImpersonationSessionID interface{}
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/protected", m.RequireAuth(), func(c *gin.Context) {
		gotImpersonatorID, _ = c.Get(ImpersonatorIDKey)
		gotImpersonationSessionID, _ = c.Get(ImpersonationSessionIDKey)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, impersonatorID, gotImpersonatorID)
	assert.Equal(t, impersonationSessionID, gotImpersonationSessionID)
}

func TestRequireAuth_CookieWithInvalidToken_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_access_token", Value: "not-a-valid-jwt"})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_EmptyCookieAndNoHeader_Returns401(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)
	router := newAuthRouter(m)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "falcon_access_token", Value: ""})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ==================== GetCurrentUser helpers ====================

func TestGetCurrentUser_WhenSet_ReturnsUser(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	expected := &models.CurrentUser{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Username: "alice",
	}
	c.Set(CurrentUserKey, expected)

	got := GetCurrentUser(c)
	require.NotNil(t, got)
	assert.Equal(t, expected.ID, got.ID)
}

func TestGetCurrentUser_WhenNotSet_ReturnsNil(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	got := GetCurrentUser(c)
	assert.Nil(t, got)
}

func TestGetCurrentUserID_WhenSet_ReturnsID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	userID := uuid.New()
	c.Set(CurrentUserKey, &models.CurrentUser{ID: userID, TenantID: uuid.New()})

	got := GetCurrentUserID(c)
	require.NotNil(t, got)
	assert.Equal(t, userID, *got)
}

func TestGetCurrentTenantID_WhenSet_ReturnsTenantID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	tenantID := uuid.New()
	c.Set(CurrentUserKey, &models.CurrentUser{ID: uuid.New(), TenantID: tenantID})

	got := GetCurrentTenantID(c)
	require.NotNil(t, got)
	assert.Equal(t, tenantID, *got)
}

func TestGetCurrentSessionID_WhenSet_ReturnsSessionID(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	sessionID := uuid.New()
	c.Set(CurrentSessionKey, sessionID)

	got := GetCurrentSessionID(c)
	require.NotNil(t, got)
	assert.Equal(t, sessionID, *got)
}

// ==================== Mock Authorization Engine ====================

// mockAuthzEngine implements services.AuthorizationEngine for middleware tests.
// checkPermFn controls which permissions are granted; defaults to deny-all.
type mockAuthzEngine struct {
	checkPermFn func(req services.PermissionRequest) bool
}

func (e *mockAuthzEngine) CheckPermission(_ context.Context, req services.PermissionRequest) (*services.PermissionResult, error) {
	allowed := false
	if e.checkPermFn != nil {
		allowed = e.checkPermFn(req)
	}
	reason := "permission denied by SpiceDB"
	if allowed {
		reason = "granted via SpiceDB"
	}
	return &services.PermissionResult{Allowed: allowed, Source: "spicedb", Reason: reason}, nil
}

func (e *mockAuthzEngine) CheckResourcePermission(_ context.Context, _ services.ResourcePermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false, Source: "spicedb", Reason: "denied"}, nil
}

func (e *mockAuthzEngine) CheckContextualPermission(_ context.Context, _ services.ContextualPermissionRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: false, Source: "opa", Reason: "denied"}, nil
}

func (e *mockAuthzEngine) BatchCheckPermissions(_ context.Context, _ uuid.UUID, _ uuid.UUID, perms []string) (map[string]bool, error) {
	results := make(map[string]bool, len(perms))
	for _, p := range perms {
		if e.checkPermFn != nil {
			results[p] = e.checkPermFn(services.PermissionRequest{Permission: p})
		}
	}
	return results, nil
}

func (e *mockAuthzEngine) CheckProductAccess(_ context.Context, _ services.ProductAccessRequest) (*services.PermissionResult, error) {
	return &services.PermissionResult{Allowed: true, Source: "spicedb", Reason: "granted via SpiceDB"}, nil
}

// grantPermsEngine returns a mockAuthzEngine that grants the specified permissions.
func grantPermsEngine(perms ...string) *mockAuthzEngine {
	permSet := make(map[string]bool, len(perms))
	for _, p := range perms {
		permSet[p] = true
	}
	return &mockAuthzEngine{
		checkPermFn: func(req services.PermissionRequest) bool {
			return permSet[req.Permission]
		},
	}
}

// grantAllEngine returns a mockAuthzEngine that grants all permissions.
func grantAllEngine() *mockAuthzEngine {
	return &mockAuthzEngine{
		checkPermFn: func(_ services.PermissionRequest) bool { return true },
	}
}

// ==================== RequirePermission tests ====================

func TestRequirePermission_SpiceDB_UserHasPermission_Passes(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	m.SetAuthorizationEngine(grantPermsEngine("read:users", "write:users"))

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		})
	}, m.RequirePermission("read:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequirePermission_SpiceDB_UserLacksPermission_Returns403(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	m.SetAuthorizationEngine(grantPermsEngine("read:profile"))

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		})
	}, m.RequirePermission("delete:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePermission_NoUserInContext_Returns401(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	m.SetAuthorizationEngine(grantAllEngine())

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", m.RequirePermission("read:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePermission_NoAuthzEngine_FailClosed(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	// authzEngine not set — should fail-closed

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Permissions: []string{"read:users"}, // JWT claims don't matter
		})
	}, m.RequirePermission("read:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "must fail-closed when authzEngine is nil")
}

func TestRequirePermission_SpiceDB_AnyPermissionMatch_Passes(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	m.SetAuthorizationEngine(grantPermsEngine("write:users"))

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		})
	}, m.RequirePermission("read:users", "write:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "should pass if any of the permissions is granted")
}

// ==================== RequireRole tests ====================

func TestRequireRole_AuthMiddleware_UserHasRole_Passes(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Roles:    []string{"admin", "user"},
		})
	}, m.RequireRole("admin"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_AuthMiddleware_UserLacksRole_Returns403(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Roles:    []string{"user"},
		})
	}, m.RequireRole("admin"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_AnyRoleMatches_Passes(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
			Roles:    []string{"editor"},
		})
	}, m.RequireRole("admin", "editor", "moderator"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ==================== RequireAllPermissions tests ====================

func TestRequireAllPermissions_SpiceDB_UserHasAll_Passes(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	m.SetAuthorizationEngine(grantPermsEngine("read:users", "write:users", "delete:users"))

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		})
	}, m.RequireAllPermissions("read:users", "write:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAllPermissions_SpiceDB_UserMissesOne_Returns403(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	m.SetAuthorizationEngine(grantPermsEngine("read:users")) // missing write:users

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: uuid.New(),
		})
	}, m.RequireAllPermissions("read:users", "write:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireAllPermissions_NoAuthzEngine_FailClosed(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(nil, cfg)
	// No authzEngine set — must fail-closed

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/test", func(c *gin.Context) {
		c.Set(CurrentUserKey, &models.CurrentUser{
			ID:          uuid.New(),
			TenantID:    uuid.New(),
			Permissions: []string{"read:users", "write:users"}, // JWT claims should be ignored
		})
	}, m.RequireAllPermissions("read:users", "write:users"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "must fail-closed when authzEngine is nil")
}

// ==================== OptionalAuth tests ====================

func TestOptionalAuth_ValidToken_SetsCurrentUser(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	var capturedUser *models.CurrentUser
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/public", m.OptionalAuth(), func(c *gin.Context) {
		capturedUser = GetCurrentUser(c)
		c.Status(http.StatusOK)
	})

	token := buildValidToken(t, cfg, userID, tenantID, sessionID, nil, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedUser)
	assert.Equal(t, userID, capturedUser.ID)
}

func TestOptionalAuth_NoToken_StillCallsNext(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	reached := false
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/public", m.OptionalAuth(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/public", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached, "next handler should be called even without a token")
	// current_user must not be set
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	assert.Nil(t, GetCurrentUser(c2))
}

func TestOptionalAuth_InvalidToken_StillCallsNext(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	reached := false
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/public", m.OptionalAuth(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Bearer garbage.token.here")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached)
}

func TestOptionalAuth_MalformedScheme_StillCallsNext(t *testing.T) {
	cfg := authTestConfig()
	svc := newAuthTestTokenService(cfg)
	m := NewAuthMiddleware(svc, cfg)

	reached := false
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.GET("/public", m.OptionalAuth(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/public", nil)
	req.Header.Set("Authorization", "Token somethinghere") // not Bearer
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, reached)
}

// A tenant API key token (type=api_key) is signed by the same provider key but
// is not meant for falcon-id; RequireAuth must answer 401.
func TestRequireAuth_APIKeyToken_Returns401(t *testing.T) {
	cfg := authTestConfig()
	m := NewAuthMiddleware(newAuthTestTokenService(cfg), cfg)
	router := newAuthRouter(m)

	keyID := uuid.New()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": cfg.JWTIssuer, "aud": jwt.ClaimStrings{"business-api"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti": uuid.NewString(), "sub": keyID.String(), "tenant_id": uuid.NewString(),
		"type": services.APIKeyTokenType, "api_key_id": keyID.String(), "scope": "erp.read",
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(cfg.JWTSecret))
	require.NoError(t, err)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
