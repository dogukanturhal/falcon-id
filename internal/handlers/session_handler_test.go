// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// session_handler_test.go tests the session-related endpoints that are
// surfaced through AuthHandler (user-facing) and AdminHandler (admin-facing).
// Because AuthHandler wires a concrete *services.AuthService and AdminHandler
// wires a concrete *repositories.SessionRepository, we test these handlers
// via lightweight shims that replicate the handler logic but accept fakes.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// sessionAuthServiceFake – subset of AuthService methods used by session handlers
// ---------------------------------------------------------------------------

type sessionAuthServiceFake struct {
	// GetActiveSessions
	activeSessions []models.SessionResponse
	getSessionsErr error

	// RevokeSession
	revokeSessionErr error

	// UpdateSessionActivity
	updateActivityErr error
}

func (f *sessionAuthServiceFake) GetActiveSessions(_ context.Context, _ uuid.UUID, _ *uuid.UUID) ([]models.SessionResponse, error) {
	return f.activeSessions, f.getSessionsErr
}

func (f *sessionAuthServiceFake) RevokeSession(_ context.Context, _, _ uuid.UUID) error {
	return f.revokeSessionErr
}

func (f *sessionAuthServiceFake) UpdateSessionActivity(_ context.Context, _ uuid.UUID) error {
	return f.updateActivityErr
}

// ---------------------------------------------------------------------------
// sessionHandlerShim – mirrors the user-facing session portions of AuthHandler
// ---------------------------------------------------------------------------

type sessionHandlerShim struct {
	svc *sessionAuthServiceFake
}

func newSessionTestRouter(svc *sessionAuthServiceFake, withUser bool, userID, sessionID uuid.UUID) *gin.Engine {
	router := gin.New()
	injectUser := func(c *gin.Context) {
		if withUser {
			c.Set("current_user", &models.CurrentUser{
				ID:        userID,
				TenantID:  uuid.New(),
				Email:     "test@example.com",
				SessionID: sessionID,
			})
		}
		c.Next()
	}
	h := &sessionHandlerShim{svc: svc}
	router.Use(injectUser)
	router.GET("/sessions", h.GetSessions)
	router.DELETE("/sessions/:id", h.RevokeSession)
	router.POST("/heartbeat", h.Heartbeat)
	return router
}

func sessionCurrentUser(c *gin.Context) *models.CurrentUser {
	val, exists := c.Get("current_user")
	if !exists {
		return nil
	}
	u, ok := val.(*models.CurrentUser)
	if !ok {
		return nil
	}
	return u
}

func (h *sessionHandlerShim) GetSessions(c *gin.Context) {
	user := sessionCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	sessions, err := h.svc.GetActiveSessions(c.Request.Context(), user.ID, &user.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (h *sessionHandlerShim) RevokeSession(c *gin.Context) {
	user := sessionCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	sessionIDStr := c.Param("id")
	sessionID, err := parseUUID(sessionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}
	if err := h.svc.RevokeSession(c.Request.Context(), user.ID, sessionID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Session revoked"})
}

func (h *sessionHandlerShim) Heartbeat(c *gin.Context) {
	user := sessionCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	if err := h.svc.UpdateSessionActivity(c.Request.Context(), user.SessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

// ---------------------------------------------------------------------------
// HTTP helpers for session tests
// ---------------------------------------------------------------------------

func performSessionRequest(router *gin.Engine, method, path, body string) *httptest.ResponseRecorder { //nolint:unparam // body is always "" now but kept for flexibility
	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, path, nil)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func decodeSessionBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func buildSessionResponse(sessionID, userID uuid.UUID, isCurrent bool) models.SessionResponse {
	now := time.Now()
	ua := "Mozilla/5.0 Test Browser"
	ip := "127.0.0.1"
	exp := now.Add(24 * time.Hour)
	return models.SessionResponse{
		ID:        sessionID,
		UserID:    userID,
		UserAgent: &ua,
		IPAddress: &ip,
		CreatedAt: now,
		ExpiresAt: exp,
		IsCurrent: isCurrent,
	}
}

// ---------------------------------------------------------------------------
// Tests: GetSessions (GET /sessions)
// ---------------------------------------------------------------------------

func TestSessionHandler_GetSessions(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	t.Run("returns list of active sessions", func(t *testing.T) {
		sess1 := buildSessionResponse(sessionID, userID, true)
		sess2 := buildSessionResponse(uuid.New(), userID, false)
		svc := &sessionAuthServiceFake{
			activeSessions: []models.SessionResponse{sess1, sess2},
		}
		router := newSessionTestRouter(svc, true, userID, sessionID)
		w := performSessionRequest(router, http.MethodGet, "/sessions", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		sessions, ok := body["sessions"].([]interface{})
		require.True(t, ok, "sessions should be an array")
		assert.Len(t, sessions, 2)
	})

	t.Run("returns empty list when no sessions", func(t *testing.T) {
		svc := &sessionAuthServiceFake{activeSessions: []models.SessionResponse{}}
		router := newSessionTestRouter(svc, true, userID, sessionID)
		w := performSessionRequest(router, http.MethodGet, "/sessions", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		sessions, ok := body["sessions"].([]interface{})
		require.True(t, ok)
		assert.Empty(t, sessions)
	})

	t.Run("current session is marked as current", func(t *testing.T) {
		currentSess := buildSessionResponse(sessionID, userID, true)
		otherSess := buildSessionResponse(uuid.New(), userID, false)
		svc := &sessionAuthServiceFake{
			activeSessions: []models.SessionResponse{currentSess, otherSess},
		}
		router := newSessionTestRouter(svc, true, userID, sessionID)
		w := performSessionRequest(router, http.MethodGet, "/sessions", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		sessions := body["sessions"].([]interface{})
		require.Len(t, sessions, 2)

		// Find the current session and verify is_current flag
		found := false
		for _, s := range sessions {
			sess := s.(map[string]interface{})
			if sess["is_current"] == true {
				found = true
				break
			}
		}
		assert.True(t, found, "expected one session to be marked as current")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newSessionTestRouter(&sessionAuthServiceFake{}, false, userID, sessionID)
		w := performSessionRequest(router, http.MethodGet, "/sessions", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &sessionAuthServiceFake{getSessionsErr: errors.New("db error")}
		router := newSessionTestRouter(svc, true, userID, sessionID)
		w := performSessionRequest(router, http.MethodGet, "/sessions", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: RevokeSession / DELETE /sessions/:id (end specific session)
// ---------------------------------------------------------------------------

func TestSessionHandler_RevokeSession(t *testing.T) {
	userID := uuid.New()
	currentSessionID := uuid.New()
	targetSessionID := uuid.New()

	t.Run("revokes target session successfully", func(t *testing.T) {
		router := newSessionTestRouter(&sessionAuthServiceFake{}, true, userID, currentSessionID)
		path := "/sessions/" + targetSessionID.String()
		w := performSessionRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		assert.Equal(t, "Session revoked", body["message"])
	})

	t.Run("invalid session ID returns 400", func(t *testing.T) {
		router := newSessionTestRouter(&sessionAuthServiceFake{}, true, userID, currentSessionID)
		w := performSessionRequest(router, http.MethodDelete, "/sessions/not-a-uuid", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 400", func(t *testing.T) {
		svc := &sessionAuthServiceFake{revokeSessionErr: errors.New("session not found")}
		router := newSessionTestRouter(svc, true, userID, currentSessionID)
		path := "/sessions/" + targetSessionID.String()
		w := performSessionRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		body := decodeSessionBody(t, w)
		assert.Contains(t, body["error"], "session not found")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newSessionTestRouter(&sessionAuthServiceFake{}, false, userID, currentSessionID)
		path := "/sessions/" + targetSessionID.String()
		w := performSessionRequest(router, http.MethodDelete, path, "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Heartbeat (POST /heartbeat) – keep-alive for current session
// ---------------------------------------------------------------------------

func TestSessionHandler_Heartbeat(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	t.Run("heartbeat updates session activity", func(t *testing.T) {
		router := newSessionTestRouter(&sessionAuthServiceFake{}, true, userID, sessionID)
		w := performSessionRequest(router, http.MethodPost, "/heartbeat", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		assert.Equal(t, "ok", body["message"])
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		router := newSessionTestRouter(&sessionAuthServiceFake{}, false, userID, sessionID)
		w := performSessionRequest(router, http.MethodPost, "/heartbeat", "")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &sessionAuthServiceFake{updateActivityErr: errors.New("session expired")}
		router := newSessionTestRouter(svc, true, userID, sessionID)
		w := performSessionRequest(router, http.MethodPost, "/heartbeat", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: AdminHandler session management
// ---------------------------------------------------------------------------

// adminSessionServiceFake provides the session-repo subset used by admin
// session-related handler logic tested here.
type adminSessionServiceFake struct {
	// GetActiveSessions (by user)
	userSessions    []models.Session
	userSessionsErr error

	// GetAllActiveSessionsForTenant
	tenantSessions    []models.Session
	tenantSessionsErr error

	// GetByID
	sessionByID    *models.Session
	sessionByIDErr error

	// EndSession
	endSessionErr error

	// EndAllUserSessions
	endAllErr error
}

// adminSessionHandlerShim mirrors the admin session handler methods.
type adminSessionHandlerShim struct {
	svc *adminSessionServiceFake
}

func newAdminSessionTestRouter(svc *adminSessionServiceFake, tenantID uuid.UUID) *gin.Engine {
	router := gin.New()
	injectAdminUser := func(c *gin.Context) {
		c.Set("current_user", &models.CurrentUser{
			ID:       uuid.New(),
			TenantID: tenantID,
			Email:    "admin@example.com",
			Roles:    []string{"admin"},
		})
		c.Next()
	}
	h := &adminSessionHandlerShim{svc: svc}
	router.Use(injectAdminUser)
	router.GET("/admin/sessions", h.ListAllSessions)
	router.DELETE("/admin/sessions/:id", h.RevokeSession)
	router.DELETE("/admin/users/:id/sessions", h.RevokeUserSessions)
	return router
}

func (h *adminSessionHandlerShim) ListAllSessions(c *gin.Context) {
	user := sessionCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	sessions, err := h.svc.GetAllActiveSessionsForTenant(c.Request.Context(), user.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve sessions"})
		return
	}
	responses := make([]models.SessionResponse, len(sessions))
	for i, s := range sessions {
		responses[i] = *s.ToResponse(nil)
	}
	c.JSON(http.StatusOK, gin.H{"sessions": responses, "total": int64(len(responses))})
}

func (h *adminSessionHandlerShim) RevokeSession(c *gin.Context) {
	user := sessionCurrentUser(c)
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
	session, err := h.svc.GetByID(c.Request.Context(), sessionID)
	if err != nil || session == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}
	if err := h.svc.EndSession(c.Request.Context(), sessionID, "revoked by admin"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Session revoked successfully"})
}

func (h *adminSessionHandlerShim) RevokeUserSessions(c *gin.Context) {
	user := sessionCurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	userIDStr := c.Param("id")
	targetUserID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	if err := h.svc.EndAllUserSessions(c.Request.Context(), targetUserID, "revoked by admin"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke sessions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "All user sessions revoked successfully"})
}

// Methods on adminSessionServiceFake:
func (f *adminSessionServiceFake) GetAllActiveSessionsForTenant(_ context.Context, _ uuid.UUID) ([]models.Session, error) {
	return f.tenantSessions, f.tenantSessionsErr
}

func (f *adminSessionServiceFake) GetActiveSessions(_ context.Context, _ uuid.UUID) ([]models.Session, error) {
	return f.userSessions, f.userSessionsErr
}

func (f *adminSessionServiceFake) GetByID(_ context.Context, _ uuid.UUID) (*models.Session, error) {
	return f.sessionByID, f.sessionByIDErr
}

func (f *adminSessionServiceFake) EndSession(_ context.Context, _ uuid.UUID, _ string) error {
	return f.endSessionErr
}

func (f *adminSessionServiceFake) EndAllUserSessions(_ context.Context, _ uuid.UUID, _ string) error {
	return f.endAllErr
}

// ---------------------------------------------------------------------------
// Tests: Admin - ListAllSessions (GET /admin/sessions)
// ---------------------------------------------------------------------------

func TestSessionHandler_Admin_ListAllSessions(t *testing.T) {
	tenantID := uuid.New()

	t.Run("returns all active sessions for tenant", func(t *testing.T) {
		ua := "Mozilla/5.0"
		ip := "10.0.0.1"
		exp := time.Now().Add(time.Hour)
		svc := &adminSessionServiceFake{
			tenantSessions: []models.Session{
				{ID: uuid.New(), UserID: uuid.New(), UserAgent: &ua, IPAddress: &ip, ExpiresAt: exp},
				{ID: uuid.New(), UserID: uuid.New(), UserAgent: &ua, IPAddress: &ip, ExpiresAt: exp},
			},
		}
		router := newAdminSessionTestRouter(svc, tenantID)
		w := performSessionRequest(router, http.MethodGet, "/admin/sessions", "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		sessions, ok := body["sessions"].([]interface{})
		require.True(t, ok)
		assert.Len(t, sessions, 2)
		assert.Equal(t, float64(2), body["total"])
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &adminSessionServiceFake{tenantSessionsErr: errors.New("db error")}
		router := newAdminSessionTestRouter(svc, tenantID)
		w := performSessionRequest(router, http.MethodGet, "/admin/sessions", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Admin - RevokeSession (DELETE /admin/sessions/:id)
// ---------------------------------------------------------------------------

func TestSessionHandler_Admin_RevokeSession(t *testing.T) {
	tenantID := uuid.New()

	t.Run("revokes session successfully", func(t *testing.T) {
		sessionID := uuid.New()
		ua := "Mozilla/5.0"
		ip := "10.0.0.1"
		exp := time.Now().Add(time.Hour)
		svc := &adminSessionServiceFake{
			sessionByID: &models.Session{
				ID:        sessionID,
				UserID:    uuid.New(),
				UserAgent: &ua,
				IPAddress: &ip,
				ExpiresAt: exp,
			},
		}
		router := newAdminSessionTestRouter(svc, tenantID)
		path := "/admin/sessions/" + sessionID.String()
		w := performSessionRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		assert.Equal(t, "Session revoked successfully", body["message"])
	})

	t.Run("invalid session ID returns 400", func(t *testing.T) {
		router := newAdminSessionTestRouter(&adminSessionServiceFake{}, tenantID)
		w := performSessionRequest(router, http.MethodDelete, "/admin/sessions/bad-uuid", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("session not found returns 404", func(t *testing.T) {
		svc := &adminSessionServiceFake{sessionByID: nil}
		router := newAdminSessionTestRouter(svc, tenantID)
		path := "/admin/sessions/" + uuid.New().String()
		w := performSessionRequest(router, http.MethodDelete, path, "")
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: Admin - RevokeUserSessions (DELETE /admin/users/:id/sessions)
// ---------------------------------------------------------------------------

func TestSessionHandler_Admin_RevokeUserSessions(t *testing.T) {
	tenantID := uuid.New()

	t.Run("ends all user sessions successfully", func(t *testing.T) {
		router := newAdminSessionTestRouter(&adminSessionServiceFake{}, tenantID)
		path := "/admin/users/" + uuid.New().String() + "/sessions"
		w := performSessionRequest(router, http.MethodDelete, path, "")

		assert.Equal(t, http.StatusOK, w.Code)
		body := decodeSessionBody(t, w)
		assert.Equal(t, "All user sessions revoked successfully", body["message"])
	})

	t.Run("invalid user ID returns 400", func(t *testing.T) {
		router := newAdminSessionTestRouter(&adminSessionServiceFake{}, tenantID)
		w := performSessionRequest(router, http.MethodDelete, "/admin/users/not-a-uuid/sessions", "")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error returns 500", func(t *testing.T) {
		svc := &adminSessionServiceFake{endAllErr: errors.New("db error")}
		router := newAdminSessionTestRouter(svc, tenantID)
		path := "/admin/users/" + uuid.New().String() + "/sessions"
		w := performSessionRequest(router, http.MethodDelete, path, "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
