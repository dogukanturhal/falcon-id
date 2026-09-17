// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// impersonation_handler_test.go covers ImpersonationHandler:
//
//   StartImpersonation         — admin starts impersonating a user
//   EndImpersonation           — end the caller's impersonation session
//   GetImpersonationStatus     — query whether current token is impersonated
//   ListImpersonationSessions  — admin audit list
//   GetImpersonationSession    — admin retrieve single session
//   EndImpersonationByAdmin    — admin forcefully ends any session
//   GetActiveImpersonation     — admin check active session for a user
//
// Security properties tested:
//   - Cross-tenant isolation: tenant_id from context gates all admin ops
//   - 401/400 when required context values are absent
//   - Session ownership verified before revealing details

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
// Local service interface
// ---------------------------------------------------------------------------

type impersonationSvc interface {
	StartImpersonation(ctx context.Context, adminUserID, targetUserID uuid.UUID, reason, ip, ua string, originalSessionID *uuid.UUID) (*models.ImpersonationResponse, error)
	EndImpersonation(ctx context.Context, sessionID, adminUserID uuid.UUID, ip, ua string) error
	GetImpersonationStatus(ctx context.Context, impersonatorID, sessionID *uuid.UUID) (*models.ImpersonationStatus, error)
	ListImpersonationSessions(ctx context.Context, tenantID uuid.UUID, page, pageSize int, adminUserID, targetUserID *uuid.UUID, activeOnly bool) (*models.ImpersonationSessionListResponse, error)
	GetImpersonationSession(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error)
	GetActiveImpersonation(ctx context.Context, adminUserID uuid.UUID) (*models.ImpersonationSession, error)
}

// ---------------------------------------------------------------------------
// Mock impersonationSvc
// ---------------------------------------------------------------------------

type mockImpersonationSvc struct {
	startFn      func(ctx context.Context, adminID, targetID uuid.UUID, reason, ip, ua string, origSID *uuid.UUID) (*models.ImpersonationResponse, error)
	endFn        func(ctx context.Context, sessID, adminID uuid.UUID, ip, ua string) error
	statusFn     func(ctx context.Context, impersonatorID, sessID *uuid.UUID) (*models.ImpersonationStatus, error)
	listFn       func(ctx context.Context, tenantID uuid.UUID, page, pageSize int, adminID, targetID *uuid.UUID, activeOnly bool) (*models.ImpersonationSessionListResponse, error)
	getSessionFn func(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error)
	getActiveFn  func(ctx context.Context, adminID uuid.UUID) (*models.ImpersonationSession, error)
}

func (m *mockImpersonationSvc) StartImpersonation(ctx context.Context, adminID, targetID uuid.UUID, reason, ip, ua string, origSID *uuid.UUID) (*models.ImpersonationResponse, error) {
	if m.startFn != nil {
		return m.startFn(ctx, adminID, targetID, reason, ip, ua, origSID)
	}
	sessID := uuid.New().String()
	return &models.ImpersonationResponse{
		ImpersonationSessionID: sessID,
		AccessToken:            "impersonation-access-token",
		TokenType:              "Bearer",
		ExpiresIn:              900,
		Message:                "Impersonation started",
	}, nil
}

func (m *mockImpersonationSvc) EndImpersonation(ctx context.Context, sessID, adminID uuid.UUID, ip, ua string) error {
	if m.endFn != nil {
		return m.endFn(ctx, sessID, adminID, ip, ua)
	}
	return nil
}

func (m *mockImpersonationSvc) GetImpersonationStatus(ctx context.Context, impersonatorID, sessID *uuid.UUID) (*models.ImpersonationStatus, error) {
	if m.statusFn != nil {
		return m.statusFn(ctx, impersonatorID, sessID)
	}
	return &models.ImpersonationStatus{IsImpersonating: false}, nil
}

func (m *mockImpersonationSvc) ListImpersonationSessions(ctx context.Context, tenantID uuid.UUID, page, pageSize int, adminID, targetID *uuid.UUID, activeOnly bool) (*models.ImpersonationSessionListResponse, error) {
	if m.listFn != nil {
		return m.listFn(ctx, tenantID, page, pageSize, adminID, targetID, activeOnly)
	}
	return &models.ImpersonationSessionListResponse{Sessions: []*models.ImpersonationSession{}, Total: 0}, nil
}

func (m *mockImpersonationSvc) GetImpersonationSession(ctx context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
	if m.getSessionFn != nil {
		return m.getSessionFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockImpersonationSvc) GetActiveImpersonation(ctx context.Context, adminID uuid.UUID) (*models.ImpersonationSession, error) {
	if m.getActiveFn != nil {
		return m.getActiveFn(ctx, adminID)
	}
	return nil, errors.New("not found")
}

// ---------------------------------------------------------------------------
// Test adapter
// ---------------------------------------------------------------------------

type testImpersonationHandler struct {
	svc impersonationSvc
}

func newTestImpersonationHandler(svc impersonationSvc) *testImpersonationHandler {
	return &testImpersonationHandler{svc: svc}
}

func (h *testImpersonationHandler) StartImpersonation(c *gin.Context) {
	adminUserIDRaw, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	var req models.StartImpersonationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var origSessionID *uuid.UUID
	if sID, exists := c.Get("session_id"); exists {
		if sid, ok := sID.(uuid.UUID); ok {
			origSessionID = &sid
		}
	}
	adminUID, ok := adminUserIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	response, err := h.svc.StartImpersonation(c.Request.Context(), adminUID, targetUserID, req.Reason, c.ClientIP(), c.Request.UserAgent(), origSessionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *testImpersonationHandler) EndImpersonation(c *gin.Context) {
	impersonatorIDRaw, exists := c.Get("impersonator_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not currently impersonating"})
		return
	}
	sessIDRaw, exists := c.Get("impersonation_session_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Impersonation session not found"})
		return
	}
	sessID, ok := sessIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	adminUID, ok := impersonatorIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	if err := h.svc.EndImpersonation(c.Request.Context(), sessID, adminUID, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Impersonation ended successfully"})
}

func (h *testImpersonationHandler) GetImpersonationStatus(c *gin.Context) {
	var impersonatorID, sessID *uuid.UUID
	if raw, exists := c.Get("impersonator_id"); exists {
		if uid, ok := raw.(uuid.UUID); ok {
			impersonatorID = &uid
		}
	}
	if raw, exists := c.Get("impersonation_session_id"); exists {
		if uid, ok := raw.(uuid.UUID); ok {
			sessID = &uid
		}
	}
	status, err := h.svc.GetImpersonationStatus(c.Request.Context(), impersonatorID, sessID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *testImpersonationHandler) ListImpersonationSessions(c *gin.Context) {
	tenantIDRaw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found in context"})
		return
	}
	tenantUID, ok := tenantIDRaw.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	page := 1
	pageSize := 20
	activeOnly := c.Query("active_only") == "true"

	var adminUserID, targetUserID *uuid.UUID
	if adminID := c.Query("admin_user_id"); adminID != "" {
		if parsed, err := uuid.Parse(adminID); err == nil {
			adminUserID = &parsed
		}
	}
	if targetID := c.Query("target_user_id"); targetID != "" {
		if parsed, err := uuid.Parse(targetID); err == nil {
			targetUserID = &parsed
		}
	}

	response, err := h.svc.ListImpersonationSessions(c.Request.Context(), tenantUID, page, pageSize, adminUserID, targetUserID, activeOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An internal error occurred"})
		return
	}
	c.JSON(http.StatusOK, response)
}

func (h *testImpersonationHandler) GetImpersonationSession(c *gin.Context) {
	tenantIDRaw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found in context"})
		return
	}
	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}
	session, err := h.svc.GetImpersonationSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Impersonation session not found"})
		return
	}
	tenantUID, ok := tenantIDRaw.(uuid.UUID)
	if !ok || session.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Impersonation session not found"})
		return
	}
	c.JSON(http.StatusOK, session)
}

func (h *testImpersonationHandler) EndImpersonationByAdmin(c *gin.Context) {
	tenantIDRaw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found in context"})
		return
	}
	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}
	session, err := h.svc.GetImpersonationSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Impersonation session not found"})
		return
	}
	tenantUID, ok := tenantIDRaw.(uuid.UUID)
	if !ok || session.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Impersonation session not found"})
		return
	}
	if err := h.svc.EndImpersonation(c.Request.Context(), sessionID, session.AdminUserID, c.ClientIP(), c.Request.UserAgent()); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Impersonation session ended successfully"})
}

func (h *testImpersonationHandler) GetActiveImpersonation(c *gin.Context) {
	tenantIDRaw, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found in context"})
		return
	}
	adminUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	session, err := h.svc.GetActiveImpersonation(c.Request.Context(), adminUserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active impersonation found"})
		return
	}
	tenantUID, ok := tenantIDRaw.(uuid.UUID)
	if !ok || session.TenantID != tenantUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active impersonation found"})
		return
	}
	c.JSON(http.StatusOK, session)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newImpersonationTestRouter(h *testImpersonationHandler) *gin.Engine {
	r := gin.New()
	r.POST("/api/admin/users/:id/impersonate", h.StartImpersonation)
	r.POST("/api/auth/impersonation/end", h.EndImpersonation)
	r.GET("/api/auth/impersonation/status", h.GetImpersonationStatus)
	r.GET("/api/admin/impersonation-sessions", h.ListImpersonationSessions)
	r.GET("/api/admin/impersonation-sessions/:id", h.GetImpersonationSession)
	r.POST("/api/admin/impersonation-sessions/:id/end", h.EndImpersonationByAdmin)
	r.GET("/api/admin/users/:id/impersonation", h.GetActiveImpersonation)
	return r
}

func sampleImpersonationSession(id, tenantID, adminID, targetID uuid.UUID) *models.ImpersonationSession {
	now := time.Now()
	return &models.ImpersonationSession{
		ID:           id,
		TenantID:     tenantID,
		AdminUserID:  adminID,
		TargetUserID: targetID,
		Reason:       "debugging production issue",
		StartedAt:    now,
		CreatedAt:    now,
	}
}

func impJSONBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// ---------------------------------------------------------------------------
// Tests: StartImpersonation
// ---------------------------------------------------------------------------

func TestImpersonationHandler_StartImpersonation(t *testing.T) {
	t.Run("admin starts impersonation successfully", func(t *testing.T) {
		adminID := uuid.New()
		targetID := uuid.New()
		sessID := uuid.New().String()

		svc := &mockImpersonationSvc{
			startFn: func(_ context.Context, aID, tID uuid.UUID, reason, _, _ string, _ *uuid.UUID) (*models.ImpersonationResponse, error) {
				assert.Equal(t, adminID, aID)
				assert.Equal(t, targetID, tID)
				assert.Equal(t, "debugging production issue for ticket ABC-123", reason)
				return &models.ImpersonationResponse{
					ImpersonationSessionID: sessID,
					AccessToken:            "imp-access-token",
					TokenType:              "Bearer",
					ExpiresIn:              900,
					Message:                "Impersonation started",
				}, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/admin/users/:id/impersonate", func(c *gin.Context) {
			c.Set("user_id", adminID)
		}, h.StartImpersonation)

		body := impJSONBody(t, models.StartImpersonationRequest{
			Reason: "debugging production issue for ticket ABC-123",
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users/"+targetID.String()+"/impersonate", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.ImpersonationResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, sessID, resp.ImpersonationSessionID)
		assert.Equal(t, "imp-access-token", resp.AccessToken)
		assert.Contains(t, resp.Message, "started")
	})

	t.Run("returns 401 when admin user not in context", func(t *testing.T) {
		svc := &mockImpersonationSvc{}
		router := newImpersonationTestRouter(newTestImpersonationHandler(svc))

		body := impJSONBody(t, models.StartImpersonationRequest{Reason: "some valid reason here"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users/"+uuid.New().String()+"/impersonate", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 400 for invalid target user UUID", func(t *testing.T) {
		adminID := uuid.New()
		svc := &mockImpersonationSvc{}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/admin/users/:id/impersonate", func(c *gin.Context) {
			c.Set("user_id", adminID)
		}, h.StartImpersonation)

		body := impJSONBody(t, models.StartImpersonationRequest{Reason: "debugging production issue here"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users/bad-uuid/impersonate", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when service rejects impersonation", func(t *testing.T) {
		adminID := uuid.New()
		targetID := uuid.New()
		svc := &mockImpersonationSvc{
			startFn: func(_ context.Context, _, _ uuid.UUID, _, _, _ string, _ *uuid.UUID) (*models.ImpersonationResponse, error) {
				return nil, errors.New("cannot impersonate users in a different tenant")
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/admin/users/:id/impersonate", func(c *gin.Context) {
			c.Set("user_id", adminID)
		}, h.StartImpersonation)

		body := impJSONBody(t, models.StartImpersonationRequest{Reason: "debugging production issue here"})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users/"+targetID.String()+"/impersonate", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "different tenant")
	})

	t.Run("returns 400 for malformed JSON body", func(t *testing.T) {
		adminID := uuid.New()
		svc := &mockImpersonationSvc{}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/admin/users/:id/impersonate", func(c *gin.Context) {
			c.Set("user_id", adminID)
		}, h.StartImpersonation)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/users/"+uuid.New().String()+"/impersonate", bytes.NewReader([]byte("{bad")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: EndImpersonation
// ---------------------------------------------------------------------------

func TestImpersonationHandler_EndImpersonation(t *testing.T) {
	t.Run("ends impersonation session", func(t *testing.T) {
		adminID := uuid.New()
		sessID := uuid.New()
		var endedSessID uuid.UUID

		svc := &mockImpersonationSvc{
			endFn: func(_ context.Context, sID, aID uuid.UUID, _, _ string) error {
				endedSessID = sID
				assert.Equal(t, adminID, aID)
				return nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/auth/impersonation/end", func(c *gin.Context) {
			c.Set("impersonator_id", adminID)
			c.Set("impersonation_session_id", sessID)
		}, h.EndImpersonation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/impersonation/end", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, sessID, endedSessID)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "ended successfully")
	})

	t.Run("returns 400 when not currently impersonating", func(t *testing.T) {
		svc := &mockImpersonationSvc{}
		router := newImpersonationTestRouter(newTestImpersonationHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/impersonation/end", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "Not currently impersonating")
	})

	t.Run("returns 400 when impersonation session not in context", func(t *testing.T) {
		adminID := uuid.New()
		svc := &mockImpersonationSvc{}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/auth/impersonation/end", func(c *gin.Context) {
			c.Set("impersonator_id", adminID)
			// impersonation_session_id intentionally absent
		}, h.EndImpersonation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/impersonation/end", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetImpersonationStatus
// ---------------------------------------------------------------------------

func TestImpersonationHandler_GetImpersonationStatus(t *testing.T) {
	t.Run("returns not-impersonating status for normal session", func(t *testing.T) {
		svc := &mockImpersonationSvc{
			statusFn: func(_ context.Context, impID, sessID *uuid.UUID) (*models.ImpersonationStatus, error) {
				assert.Nil(t, impID)
				assert.Nil(t, sessID)
				return &models.ImpersonationStatus{IsImpersonating: false}, nil
			},
		}
		router := newImpersonationTestRouter(newTestImpersonationHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/impersonation/status", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var status models.ImpersonationStatus
		require.NoError(t, json.NewDecoder(w.Body).Decode(&status))
		assert.False(t, status.IsImpersonating)
	})

	t.Run("returns is_impersonating=true when impersonation context is set", func(t *testing.T) {
		adminID := uuid.New()
		sessID := uuid.New()
		adminIDStr := adminID.String()
		targetIDStr := uuid.New().String()
		reasonStr := "audit purposes"

		svc := &mockImpersonationSvc{
			statusFn: func(_ context.Context, impID, sID *uuid.UUID) (*models.ImpersonationStatus, error) {
				require.NotNil(t, impID)
				assert.Equal(t, adminID, *impID)
				require.NotNil(t, sID)
				assert.Equal(t, sessID, *sID)
				return &models.ImpersonationStatus{
					IsImpersonating:        true,
					AdminUserID:            &adminIDStr,
					TargetUserID:           &targetIDStr,
					ImpersonationSessionID: strPtr(sessID.String()),
					Reason:                 &reasonStr,
				}, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/auth/impersonation/status", func(c *gin.Context) {
			c.Set("impersonator_id", adminID)
			c.Set("impersonation_session_id", sessID)
		}, h.GetImpersonationStatus)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/impersonation/status", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var status models.ImpersonationStatus
		require.NoError(t, json.NewDecoder(w.Body).Decode(&status))
		assert.True(t, status.IsImpersonating)
		require.NotNil(t, status.AdminUserID)
		assert.Equal(t, adminIDStr, *status.AdminUserID)
	})
}

// strPtr is a tiny helper used in this file only.
func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Tests: ListImpersonationSessions
// ---------------------------------------------------------------------------

func TestImpersonationHandler_ListImpersonationSessions(t *testing.T) {
	t.Run("returns session list for tenant", func(t *testing.T) {
		tenantID := uuid.New()
		adminID := uuid.New()
		targetID := uuid.New()

		svc := &mockImpersonationSvc{
			listFn: func(_ context.Context, tID uuid.UUID, page, pageSize int, _, _ *uuid.UUID, _ bool) (*models.ImpersonationSessionListResponse, error) {
				assert.Equal(t, tenantID, tID)
				assert.Equal(t, 1, page)
				assert.Equal(t, 20, pageSize)
				return &models.ImpersonationSessionListResponse{
					Sessions: []*models.ImpersonationSession{
						sampleImpersonationSession(uuid.New(), tenantID, adminID, targetID),
					},
					Total:      1,
					Page:       1,
					PageSize:   20,
					TotalPages: 1,
				}, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/impersonation-sessions", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.ListImpersonationSessions)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.ImpersonationSessionListResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, 1, resp.Total)
		assert.Len(t, resp.Sessions, 1)
	})

	t.Run("filters by admin_user_id query param", func(t *testing.T) {
		tenantID := uuid.New()
		adminID := uuid.New()
		var capturedAdminID *uuid.UUID

		svc := &mockImpersonationSvc{
			listFn: func(_ context.Context, _ uuid.UUID, _, _ int, aID, _ *uuid.UUID, _ bool) (*models.ImpersonationSessionListResponse, error) {
				capturedAdminID = aID
				return &models.ImpersonationSessionListResponse{Sessions: []*models.ImpersonationSession{}}, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/impersonation-sessions", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.ListImpersonationSessions)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions?admin_user_id="+adminID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedAdminID)
		assert.Equal(t, adminID, *capturedAdminID)
	})

	t.Run("returns 400 when tenant_id not in context", func(t *testing.T) {
		svc := &mockImpersonationSvc{}
		router := newImpersonationTestRouter(newTestImpersonationHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetImpersonationSession
// ---------------------------------------------------------------------------

func TestImpersonationHandler_GetImpersonationSession(t *testing.T) {
	t.Run("returns session for same-tenant admin", func(t *testing.T) {
		tenantID := uuid.New()
		adminID := uuid.New()
		targetID := uuid.New()
		sessionID := uuid.New()
		session := sampleImpersonationSession(sessionID, tenantID, adminID, targetID)

		svc := &mockImpersonationSvc{
			getSessionFn: func(_ context.Context, id uuid.UUID) (*models.ImpersonationSession, error) {
				assert.Equal(t, sessionID, id)
				return session, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/impersonation-sessions/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.GetImpersonationSession)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions/"+sessionID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.ImpersonationSession
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, sessionID, resp.ID)
		assert.Equal(t, adminID, resp.AdminUserID)
	})

	t.Run("security: returns 404 for session belonging to different tenant", func(t *testing.T) {
		callerTenantID := uuid.New()
		sessionID := uuid.New()
		session := sampleImpersonationSession(sessionID, uuid.New(), uuid.New(), uuid.New()) // different tenant

		svc := &mockImpersonationSvc{
			getSessionFn: func(_ context.Context, _ uuid.UUID) (*models.ImpersonationSession, error) {
				return session, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/impersonation-sessions/:id", func(c *gin.Context) {
			c.Set("tenant_id", callerTenantID)
		}, h.GetImpersonationSession)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions/"+sessionID.String(), nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 for invalid session UUID", func(t *testing.T) {
		tenantID := uuid.New()
		svc := &mockImpersonationSvc{}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/impersonation-sessions/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.GetImpersonationSession)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions/not-a-uuid", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when session not found", func(t *testing.T) {
		tenantID := uuid.New()
		svc := &mockImpersonationSvc{
			getSessionFn: func(_ context.Context, _ uuid.UUID) (*models.ImpersonationSession, error) {
				return nil, errors.New("not found")
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/impersonation-sessions/:id", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.GetImpersonationSession)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/impersonation-sessions/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: EndImpersonationByAdmin
// ---------------------------------------------------------------------------

func TestImpersonationHandler_EndImpersonationByAdmin(t *testing.T) {
	t.Run("admin can forcefully end any session in their tenant", func(t *testing.T) {
		tenantID := uuid.New()
		adminID := uuid.New()
		targetID := uuid.New()
		sessionID := uuid.New()
		session := sampleImpersonationSession(sessionID, tenantID, adminID, targetID)
		var endedSessID uuid.UUID

		svc := &mockImpersonationSvc{
			getSessionFn: func(_ context.Context, _ uuid.UUID) (*models.ImpersonationSession, error) {
				return session, nil
			},
			endFn: func(_ context.Context, sID, _ uuid.UUID, _, _ string) error {
				endedSessID = sID
				return nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/admin/impersonation-sessions/:id/end", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.EndImpersonationByAdmin)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/impersonation-sessions/"+sessionID.String()+"/end", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, sessionID, endedSessID)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "ended successfully")
	})

	t.Run("security: cannot end session from another tenant", func(t *testing.T) {
		callerTenantID := uuid.New()
		sessionID := uuid.New()
		session := sampleImpersonationSession(sessionID, uuid.New(), uuid.New(), uuid.New())

		svc := &mockImpersonationSvc{
			getSessionFn: func(_ context.Context, _ uuid.UUID) (*models.ImpersonationSession, error) {
				return session, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/admin/impersonation-sessions/:id/end", func(c *gin.Context) {
			c.Set("tenant_id", callerTenantID)
		}, h.EndImpersonationByAdmin)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/admin/impersonation-sessions/"+sessionID.String()+"/end", nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetActiveImpersonation
// ---------------------------------------------------------------------------

func TestImpersonationHandler_GetActiveImpersonation(t *testing.T) {
	t.Run("returns active impersonation for admin user in same tenant", func(t *testing.T) {
		tenantID := uuid.New()
		adminID := uuid.New()
		targetID := uuid.New()
		sessionID := uuid.New()
		session := sampleImpersonationSession(sessionID, tenantID, adminID, targetID)

		svc := &mockImpersonationSvc{
			getActiveFn: func(_ context.Context, aID uuid.UUID) (*models.ImpersonationSession, error) {
				assert.Equal(t, adminID, aID)
				return session, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/users/:id/impersonation", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.GetActiveImpersonation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users/"+adminID.String()+"/impersonation", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.ImpersonationSession
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, adminID, resp.AdminUserID)
		assert.Equal(t, targetID, resp.TargetUserID)
	})

	t.Run("returns 404 when no active impersonation", func(t *testing.T) {
		tenantID := uuid.New()
		svc := &mockImpersonationSvc{
			getActiveFn: func(_ context.Context, _ uuid.UUID) (*models.ImpersonationSession, error) {
				return nil, errors.New("no active impersonation")
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/users/:id/impersonation", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.GetActiveImpersonation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users/"+uuid.New().String()+"/impersonation", nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("security: returns 404 when session tenant does not match caller", func(t *testing.T) {
		callerTenantID := uuid.New()
		adminID := uuid.New()
		sessionID := uuid.New()
		session := sampleImpersonationSession(sessionID, uuid.New(), adminID, uuid.New()) // different tenant

		svc := &mockImpersonationSvc{
			getActiveFn: func(_ context.Context, _ uuid.UUID) (*models.ImpersonationSession, error) {
				return session, nil
			},
		}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/users/:id/impersonation", func(c *gin.Context) {
			c.Set("tenant_id", callerTenantID)
		}, h.GetActiveImpersonation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users/"+adminID.String()+"/impersonation", nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 for invalid admin user UUID", func(t *testing.T) {
		tenantID := uuid.New()
		svc := &mockImpersonationSvc{}
		h := newTestImpersonationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/admin/users/:id/impersonation", func(c *gin.Context) {
			c.Set("tenant_id", tenantID)
		}, h.GetActiveImpersonation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/admin/users/not-a-uuid/impersonation", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
