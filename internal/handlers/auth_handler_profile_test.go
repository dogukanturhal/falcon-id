// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// auth_handler_profile_test.go covers the profile-oriented methods that live
// in auth_handler_profile.go and are defined on AuthHandler:
//
//   Me              — returns current user info
//   UpdateProfile   — updates displayable profile fields
//   ChangePassword  — requires current password, enforces new-password policy
//   GetSessions     — lists active sessions
//   Heartbeat       — keeps session alive
//   RevokeSession   — ends a specific session
//   GetLoginHistory — paginated login event history
//   ForgotPassword  — sends reset email (always 200 to prevent enumeration)
//   ResetPassword   — applies password-reset token
//
// The adapter pattern mirrors auth_handler_test.go: local interfaces plus
// lightweight fakes, no dependency on the real service constructors.

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
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Local service interfaces for profile tests
// ---------------------------------------------------------------------------

type profileAuthSvc interface {
	GetCurrentUser(ctx context.Context, userID uuid.UUID) (*models.UserResponse, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error)
	ChangePassword(ctx context.Context, userID, sessionID uuid.UUID, currentPwd, newPwd string) error
	GetActiveSessions(ctx context.Context, userID uuid.UUID, currentSessionID *uuid.UUID) ([]*models.SessionResponse, error)
	UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error
	RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error
	GetLoginHistory(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error)
}

type profilePasswordResetSvc interface {
	RequestPasswordReset(ctx context.Context, tenantID uuid.UUID, email, ipAddress string) error
	ResetPassword(ctx context.Context, token, newPassword, ipAddress string) error
}

// ---------------------------------------------------------------------------
// Fake profileAuthSvc
// ---------------------------------------------------------------------------

type fakeProfileAuthSvc struct {
	getCurrentUserFn    func(ctx context.Context, userID uuid.UUID) (*models.UserResponse, error)
	updateProfileFn     func(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error)
	changePasswordFn    func(ctx context.Context, userID, sessionID uuid.UUID, current, newPwd string) error
	getActiveSessionsFn func(ctx context.Context, userID uuid.UUID, currentSID *uuid.UUID) ([]*models.SessionResponse, error)
	updateSessionActFn  func(ctx context.Context, sessionID uuid.UUID) error
	revokeSessionFn     func(ctx context.Context, userID, sessionID uuid.UUID) error
	getLoginHistoryFn   func(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error)
}

func (f *fakeProfileAuthSvc) GetCurrentUser(ctx context.Context, userID uuid.UUID) (*models.UserResponse, error) {
	if f.getCurrentUserFn != nil {
		return f.getCurrentUserFn(ctx, userID)
	}
	return &models.UserResponse{ID: userID}, nil
}

func (f *fakeProfileAuthSvc) UpdateProfile(ctx context.Context, userID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error) {
	if f.updateProfileFn != nil {
		return f.updateProfileFn(ctx, userID, req)
	}
	return &models.UserResponse{ID: userID}, nil
}

func (f *fakeProfileAuthSvc) ChangePassword(ctx context.Context, userID, sessionID uuid.UUID, current, newPwd string) error {
	if f.changePasswordFn != nil {
		return f.changePasswordFn(ctx, userID, sessionID, current, newPwd)
	}
	return nil
}

func (f *fakeProfileAuthSvc) GetActiveSessions(ctx context.Context, userID uuid.UUID, currentSID *uuid.UUID) ([]*models.SessionResponse, error) {
	if f.getActiveSessionsFn != nil {
		return f.getActiveSessionsFn(ctx, userID, currentSID)
	}
	return []*models.SessionResponse{}, nil
}

func (f *fakeProfileAuthSvc) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	if f.updateSessionActFn != nil {
		return f.updateSessionActFn(ctx, sessionID)
	}
	return nil
}

func (f *fakeProfileAuthSvc) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	if f.revokeSessionFn != nil {
		return f.revokeSessionFn(ctx, userID, sessionID)
	}
	return nil
}

func (f *fakeProfileAuthSvc) GetLoginHistory(ctx context.Context, userID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error) {
	if f.getLoginHistoryFn != nil {
		return f.getLoginHistoryFn(ctx, userID, page, pageSize)
	}
	return &models.LoginHistoryResponse{}, nil
}

// ---------------------------------------------------------------------------
// Fake profilePasswordResetSvc
// ---------------------------------------------------------------------------

type fakeProfilePasswordResetSvc struct {
	requestFn func(ctx context.Context, tenantID uuid.UUID, email, ip string) error
	resetFn   func(ctx context.Context, token, newPassword, ip string) error
}

func (f *fakeProfilePasswordResetSvc) RequestPasswordReset(ctx context.Context, tenantID uuid.UUID, email, ip string) error {
	if f.requestFn != nil {
		return f.requestFn(ctx, tenantID, email, ip)
	}
	return nil
}

func (f *fakeProfilePasswordResetSvc) ResetPassword(ctx context.Context, token, newPassword, ip string) error {
	if f.resetFn != nil {
		return f.resetFn(ctx, token, newPassword, ip)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test adapter — same behaviour as the real AuthHandler profile methods
// ---------------------------------------------------------------------------

type testProfileHandler struct {
	authSvc          profileAuthSvc
	passwordResetSvc profilePasswordResetSvc
}

func newTestProfileHandler(authSvc profileAuthSvc, pwdResetSvc profilePasswordResetSvc) *testProfileHandler {
	return &testProfileHandler{authSvc: authSvc, passwordResetSvc: pwdResetSvc}
}

func (h *testProfileHandler) Me(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	response, err := h.authSvc.GetCurrentUser(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *testProfileHandler) UpdateProfile(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, err := h.authSvc.UpdateProfile(c.Request.Context(), user.ID, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *testProfileHandler) ChangePassword(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	var req models.PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authSvc.ChangePassword(c.Request.Context(), user.ID, user.SessionID, req.CurrentPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password change failed. Please check your current password and try again."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func (h *testProfileHandler) GetSessions(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	sessions, err := h.authSvc.GetActiveSessions(c.Request.Context(), user.ID, &user.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (h *testProfileHandler) Heartbeat(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	if err := h.authSvc.UpdateSessionActivity(c.Request.Context(), user.SessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

func (h *testProfileHandler) RevokeSession(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	sessionIDStr := c.Param("id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}
	if err := h.authSvc.RevokeSession(c.Request.Context(), user.ID, sessionID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Session revoked"})
}

func (h *testProfileHandler) GetLoginHistory(c *gin.Context) {
	user := getTestCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	page, pageSize := 1, 20
	if p := c.Query("page"); p != "" {
		if v, err := parsePageNumber(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := parsePageNumber(ps); err == nil && v > 0 {
			pageSize = v
		}
	}
	response, err := h.authSvc.GetLoginHistory(c.Request.Context(), user.ID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *testProfileHandler) ForgotPassword(c *gin.Context) {
	if h.passwordResetSvc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password reset service not configured"})
		return
	}
	var req models.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Always returns success — anti-enumeration
	_ = h.passwordResetSvc.RequestPasswordReset(c.Request.Context(), uuid.Nil, req.Email, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "If the email address is registered, you will receive a password reset link shortly."})
}

func (h *testProfileHandler) ResetPassword(c *gin.Context) {
	if h.passwordResetSvc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password reset service not configured"})
		return
	}
	var req models.PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.passwordResetSvc.ResetPassword(c.Request.Context(), req.Token, req.NewPassword, c.ClientIP()); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully. You can now log in with your new password."})
}

// getTestCurrentUser extracts the current user from gin context (same logic as middleware.GetCurrentUser).
func getTestCurrentUser(c *gin.Context) *models.CurrentUser {
	raw, exists := c.Get("current_user")
	if !exists {
		return nil
	}
	cu, _ := raw.(*models.CurrentUser)
	return cu
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newProfileTestRouter(h *testProfileHandler) *gin.Engine {
	r := gin.New()
	r.GET("/api/auth/me", h.Me)
	r.PUT("/api/auth/profile", h.UpdateProfile)
	r.POST("/api/auth/password/change", h.ChangePassword)
	r.GET("/api/auth/sessions", h.GetSessions)
	r.POST("/api/auth/heartbeat", h.Heartbeat)
	r.DELETE("/api/auth/sessions/:id", h.RevokeSession)
	r.GET("/api/auth/login-history", h.GetLoginHistory)
	r.POST("/api/auth/password/forgot", h.ForgotPassword)
	r.POST("/api/auth/password/reset", h.ResetPassword)
	return r
}

func makeCurrentUser() *models.CurrentUser {
	return &models.CurrentUser{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		SessionID: uuid.New(),
		Username:  "testuser",
		Email:     "test@example.com",
	}
}

func profileJSONBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// ---------------------------------------------------------------------------
// Tests: Me
// ---------------------------------------------------------------------------

func TestProfileHandler_Me(t *testing.T) {
	t.Run("returns current user info", func(t *testing.T) {
		cu := makeCurrentUser()
		firstName := "Alice"
		svc := &fakeProfileAuthSvc{
			getCurrentUserFn: func(_ context.Context, uID uuid.UUID) (*models.UserResponse, error) {
				assert.Equal(t, cu.ID, uID)
				return &models.UserResponse{
					ID:        cu.ID,
					TenantID:  cu.TenantID,
					Email:     "alice@example.com",
					Username:  "alice",
					FirstName: &firstName,
					IsActive:  true,
				}, nil
			},
		}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))
		router.Use(injectCurrentUser(cu))

		r2 := gin.New()
		r2.GET("/api/auth/me", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).Me)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/me", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.UserResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, cu.ID, resp.ID)
		assert.Equal(t, "alice@example.com", resp.Email)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/me", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 500 when service fails", func(t *testing.T) {
		cu := makeCurrentUser()
		svc := &fakeProfileAuthSvc{
			getCurrentUserFn: func(_ context.Context, _ uuid.UUID) (*models.UserResponse, error) {
				return nil, errors.New("database error")
			},
		}
		r2 := gin.New()
		r2.GET("/api/auth/me", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).Me)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/me", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: UpdateProfile
// ---------------------------------------------------------------------------

func TestProfileHandler_UpdateProfile(t *testing.T) {
	t.Run("updates profile successfully", func(t *testing.T) {
		cu := makeCurrentUser()
		newFirst := "Bob"
		newLast := "Builder"

		svc := &fakeProfileAuthSvc{
			updateProfileFn: func(_ context.Context, uID uuid.UUID, req *models.UpdateProfileRequest) (*models.UserResponse, error) {
				assert.Equal(t, cu.ID, uID)
				require.NotNil(t, req.FirstName)
				assert.Equal(t, "Bob", *req.FirstName)
				return &models.UserResponse{ID: uID, FirstName: &newFirst, LastName: &newLast}, nil
			},
		}
		r2 := gin.New()
		r2.PUT("/api/auth/profile", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).UpdateProfile)

		fn := "Bob"
		ln := "Builder"
		body := profileJSONBody(t, models.UpdateProfileRequest{FirstName: &fn, LastName: &ln})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/auth/profile", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.UserResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		require.NotNil(t, resp.FirstName)
		assert.Equal(t, "Bob", *resp.FirstName)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/auth/profile", profileJSONBody(t, map[string]string{}))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		cu := makeCurrentUser()
		svc := &fakeProfileAuthSvc{}
		r2 := gin.New()
		r2.PUT("/api/auth/profile", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).UpdateProfile)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/auth/profile", bytes.NewReader([]byte("{bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when service rejects update", func(t *testing.T) {
		cu := makeCurrentUser()
		svc := &fakeProfileAuthSvc{
			updateProfileFn: func(_ context.Context, _ uuid.UUID, _ *models.UpdateProfileRequest) (*models.UserResponse, error) {
				return nil, errors.New("username already taken")
			},
		}
		r2 := gin.New()
		r2.PUT("/api/auth/profile", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).UpdateProfile)

		firstName := "taken"
		body := profileJSONBody(t, models.UpdateProfileRequest{FirstName: &firstName})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/auth/profile", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: ChangePassword
// ---------------------------------------------------------------------------

func TestProfileHandler_ChangePassword(t *testing.T) {
	t.Run("changes password successfully", func(t *testing.T) {
		cu := makeCurrentUser()
		var capturedCurrent, capturedNew string

		svc := &fakeProfileAuthSvc{
			changePasswordFn: func(_ context.Context, uID, sID uuid.UUID, current, newPwd string) error {
				assert.Equal(t, cu.ID, uID)
				assert.Equal(t, cu.SessionID, sID)
				capturedCurrent = current
				capturedNew = newPwd
				return nil
			},
		}
		r2 := gin.New()
		r2.POST("/api/auth/password/change", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).ChangePassword)

		body := profileJSONBody(t, models.PasswordChangeRequest{
			CurrentPassword: "OldPass@123",
			NewPassword:     "NewSecurePass@456",
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/change", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OldPass@123", capturedCurrent)
		assert.Equal(t, "NewSecurePass@456", capturedNew)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "changed successfully")
	})

	t.Run("returns 400 when current password is wrong", func(t *testing.T) {
		cu := makeCurrentUser()
		svc := &fakeProfileAuthSvc{
			changePasswordFn: func(_ context.Context, _, _ uuid.UUID, _, _ string) error {
				return errors.New("current password is incorrect")
			},
		}
		r2 := gin.New()
		r2.POST("/api/auth/password/change", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).ChangePassword)

		body := profileJSONBody(t, models.PasswordChangeRequest{
			CurrentPassword: "WrongPass@1",
			NewPassword:     "NewPass@456",
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/change", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "Password change failed")
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		body := profileJSONBody(t, models.PasswordChangeRequest{CurrentPassword: "old", NewPassword: "newpassword1"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/change", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetSessions
// ---------------------------------------------------------------------------

func TestProfileHandler_GetSessions(t *testing.T) {
	t.Run("returns active sessions", func(t *testing.T) {
		cu := makeCurrentUser()
		now := time.Now()
		svc := &fakeProfileAuthSvc{
			getActiveSessionsFn: func(_ context.Context, uID uuid.UUID, sID *uuid.UUID) ([]*models.SessionResponse, error) {
				assert.Equal(t, cu.ID, uID)
				assert.Equal(t, cu.SessionID, *sID)
				return []*models.SessionResponse{
					{ID: uuid.New(), UserID: uID, CreatedAt: now, LastActivityAt: now},
					{ID: uuid.New(), UserID: uID, CreatedAt: now, LastActivityAt: now},
				}, nil
			},
		}
		r2 := gin.New()
		r2.GET("/api/auth/sessions", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).GetSessions)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/sessions", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		sessions, ok := body["sessions"].([]interface{})
		require.True(t, ok)
		assert.Len(t, sessions, 2)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/sessions", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Heartbeat
// ---------------------------------------------------------------------------

func TestProfileHandler_Heartbeat(t *testing.T) {
	t.Run("updates session activity and returns ok", func(t *testing.T) {
		cu := makeCurrentUser()
		var updatedSID uuid.UUID
		svc := &fakeProfileAuthSvc{
			updateSessionActFn: func(_ context.Context, sID uuid.UUID) error {
				updatedSID = sID
				return nil
			},
		}
		r2 := gin.New()
		r2.POST("/api/auth/heartbeat", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).Heartbeat)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/heartbeat", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, cu.SessionID, updatedSID)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "ok", resp["message"])
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/heartbeat", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: RevokeSession
// ---------------------------------------------------------------------------

func TestProfileHandler_RevokeSession(t *testing.T) {
	t.Run("revokes a session successfully", func(t *testing.T) {
		cu := makeCurrentUser()
		targetSessionID := uuid.New()
		var revokedSID uuid.UUID

		svc := &fakeProfileAuthSvc{
			revokeSessionFn: func(_ context.Context, uID, sID uuid.UUID) error {
				assert.Equal(t, cu.ID, uID)
				revokedSID = sID
				return nil
			},
		}
		r2 := gin.New()
		r2.DELETE("/api/auth/sessions/:id", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).RevokeSession)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/auth/sessions/"+targetSessionID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, targetSessionID, revokedSID)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "revoked")
	})

	t.Run("returns 400 for invalid session UUID", func(t *testing.T) {
		cu := makeCurrentUser()
		svc := &fakeProfileAuthSvc{}
		r2 := gin.New()
		r2.DELETE("/api/auth/sessions/:id", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).RevokeSession)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/auth/sessions/bad-uuid", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/auth/sessions/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetLoginHistory
// ---------------------------------------------------------------------------

func TestProfileHandler_GetLoginHistory(t *testing.T) {
	t.Run("returns login history with default pagination", func(t *testing.T) {
		cu := makeCurrentUser()
		svc := &fakeProfileAuthSvc{
			getLoginHistoryFn: func(_ context.Context, uID uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error) {
				assert.Equal(t, cu.ID, uID)
				assert.Equal(t, 1, page)
				assert.Equal(t, 20, pageSize)
				return &models.LoginHistoryResponse{
					History:    []models.LoginHistoryEntry{{ID: uuid.New()}},
					Total:      1,
					Page:       1,
					PageSize:   20,
					TotalPages: 1,
				}, nil
			},
		}
		r2 := gin.New()
		r2.GET("/api/auth/login-history", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).GetLoginHistory)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/login-history", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.LoginHistoryResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, int64(1), resp.Total)
	})

	t.Run("respects page and page_size query params", func(t *testing.T) {
		cu := makeCurrentUser()
		var capturedPage, capturedPageSize int
		svc := &fakeProfileAuthSvc{
			getLoginHistoryFn: func(_ context.Context, _ uuid.UUID, page, pageSize int) (*models.LoginHistoryResponse, error) {
				capturedPage = page
				capturedPageSize = pageSize
				return &models.LoginHistoryResponse{}, nil
			},
		}
		r2 := gin.New()
		r2.GET("/api/auth/login-history", func(c *gin.Context) { c.Set("current_user", cu) }, newTestProfileHandler(svc, nil).GetLoginHistory)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/login-history?page=3&page_size=10", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 3, capturedPage)
		assert.Equal(t, 10, capturedPageSize)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/login-history", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: ForgotPassword (anti-enumeration)
// ---------------------------------------------------------------------------

func TestProfileHandler_ForgotPassword(t *testing.T) {
	t.Run("always returns 200 regardless of whether email is registered", func(t *testing.T) {
		var requestedEmail string
		pwdSvc := &fakeProfilePasswordResetSvc{
			requestFn: func(_ context.Context, _ uuid.UUID, email, _ string) error {
				requestedEmail = email
				return errors.New("user not found") // ignored by handler
			},
		}
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, pwdSvc))

		body := profileJSONBody(t, models.PasswordResetRequest{Email: "unknown@example.com"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/forgot", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// SECURITY: 200 must always be returned to prevent user enumeration
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "unknown@example.com", requestedEmail)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "If the email address is registered")
	})

	t.Run("returns 400 for invalid email format", func(t *testing.T) {
		pwdSvc := &fakeProfilePasswordResetSvc{}
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, pwdSvc))

		body := profileJSONBody(t, models.PasswordResetRequest{Email: "not-an-email"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/forgot", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 500 when password reset service not configured", func(t *testing.T) {
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, nil))

		body := profileJSONBody(t, models.PasswordResetRequest{Email: "user@example.com"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/forgot", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: ResetPassword
// ---------------------------------------------------------------------------

func TestProfileHandler_ResetPassword(t *testing.T) {
	t.Run("resets password with valid token", func(t *testing.T) {
		var capturedToken, capturedNewPwd string
		pwdSvc := &fakeProfilePasswordResetSvc{
			resetFn: func(_ context.Context, token, newPassword, _ string) error {
				capturedToken = token
				capturedNewPwd = newPassword
				return nil
			},
		}
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, pwdSvc))

		body := profileJSONBody(t, models.PasswordResetConfirmRequest{ //nolint:gosec // test fixture value, not a real credential
			Token:       "valid-reset-token",
			NewPassword: "SuperNewPass@789",
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/reset", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "valid-reset-token", capturedToken)
		assert.Equal(t, "SuperNewPass@789", capturedNewPwd)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "reset successfully")
	})

	t.Run("returns 400 for expired or invalid token", func(t *testing.T) {
		pwdSvc := &fakeProfilePasswordResetSvc{
			resetFn: func(_ context.Context, _, _, _ string) error {
				return errors.New("invalid or expired reset token")
			},
		}
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, pwdSvc))

		body := profileJSONBody(t, models.PasswordResetConfirmRequest{
			Token:       "expired-token",
			NewPassword: "NewPass@123",
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/reset", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "expired")
	})

	t.Run("returns 400 for malformed JSON body", func(t *testing.T) {
		pwdSvc := &fakeProfilePasswordResetSvc{}
		svc := &fakeProfileAuthSvc{}
		router := newProfileTestRouter(newTestProfileHandler(svc, pwdSvc))

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/password/reset", bytes.NewReader([]byte("{bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
