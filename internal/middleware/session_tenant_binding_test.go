// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"encoding/json"
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

// ------------------------------------------------------------------
// Helpers -- lightweight fakes for the middleware's dependencies
// ------------------------------------------------------------------

// fakeSessionRepo is a minimal in-memory stub that satisfies the methods
// called by SessionTenantBindingMiddleware.
type fakeSessionRepo struct {
	sessions map[uuid.UUID]*models.Session
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{
		sessions: make(map[uuid.UUID]*models.Session),
	}
}

func (f *fakeSessionRepo) addSession(s *models.Session) {
	f.sessions[s.ID] = s
}

// ------------------------------------------------------------------
// Test setup helpers
// ------------------------------------------------------------------

func setupTestRouter(_ *SessionTenantBindingMiddleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

// setCurrentUser places a models.CurrentUser into the gin context,
// simulating what RequireAuth does.
func setCurrentUser(c *gin.Context, user *models.CurrentUser) {
	c.Set(CurrentUserKey, user)
	c.Set(CurrentSessionKey, user.SessionID)
	c.Set("user_id", user.ID)
	c.Set("tenant_id", user.TenantID)
	c.Set("session_id", user.SessionID)
}

// setRequestTenant places a tenant ID into the gin context,
// simulating what ExtractTenant does.
func setRequestTenant(c *gin.Context, tenantID uuid.UUID) {
	c.Set(TenantIDKey, tenantID)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

func TestSessionTenantBinding_MatchingTenant_Passes(t *testing.T) {
	tenantID := uuid.New()
	sessionID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	repo := newFakeSessionRepo()
	repo.addSession(&models.Session{
		ID:              sessionID,
		UserID:          userID,
		IsActive:        true,
		CreatedAt:       now,
		AuthenticatedAt: &now,
		ExpiresAt:       now.Add(time.Hour),
	})

	// We cannot inject fakeSessionRepo into the real middleware because
	// it expects *repositories.SessionRepository. Instead we test the
	// middleware logic by passing nil for sessionRepo (skipping DB checks)
	// and focusing on the tenant affinity claim validation which is pure
	// in-memory.
	mw := NewSessionTenantBindingMiddleware(nil, nil)

	router := setupTestRouter(mw)
	router.Use(func(c *gin.Context) {
		setCurrentUser(c, &models.CurrentUser{
			ID:        userID,
			TenantID:  tenantID,
			SessionID: sessionID,
		})
		setRequestTenant(c, tenantID)
		c.Next()
	})
	router.Use(mw.SessionTenantBinding())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSessionTenantBinding_CrossTenant_Blocked(t *testing.T) {
	jwtTenantID := uuid.New()
	requestTenantID := uuid.New()
	sessionID := uuid.New()
	userID := uuid.New()

	mw := NewSessionTenantBindingMiddleware(nil, nil)

	router := setupTestRouter(mw)
	router.Use(func(c *gin.Context) {
		setCurrentUser(c, &models.CurrentUser{
			ID:        userID,
			TenantID:  jwtTenantID,
			SessionID: sessionID,
		})
		setRequestTenant(c, requestTenantID)
		c.Next()
	})
	router.Use(mw.SessionTenantBinding())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "Session tenant mismatch", body["error"])
}

func TestSessionTenantBinding_NoRequestTenant_Passes(t *testing.T) {
	// When no request tenant context is set (e.g., public endpoints),
	// the middleware should not block.
	tenantID := uuid.New()
	sessionID := uuid.New()
	userID := uuid.New()

	mw := NewSessionTenantBindingMiddleware(nil, nil)

	router := setupTestRouter(mw)
	router.Use(func(c *gin.Context) {
		setCurrentUser(c, &models.CurrentUser{
			ID:        userID,
			TenantID:  tenantID,
			SessionID: sessionID,
		})
		// Intentionally do NOT set request tenant
		c.Next()
	})
	router.Use(mw.SessionTenantBinding())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSessionTenantBinding_NoUser_Passes(t *testing.T) {
	// When no user is authenticated (e.g., unauthenticated endpoint),
	// the middleware should just call Next().
	mw := NewSessionTenantBindingMiddleware(nil, nil)

	router := setupTestRouter(mw)
	router.Use(mw.SessionTenantBinding())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSessionTenantBinding_NilTenantIDs_Passes(t *testing.T) {
	// When both JWT tenant and request tenant are Nil (zero value),
	// the middleware should not block.
	sessionID := uuid.New()
	userID := uuid.New()

	mw := NewSessionTenantBindingMiddleware(nil, nil)

	router := setupTestRouter(mw)
	router.Use(func(c *gin.Context) {
		setCurrentUser(c, &models.CurrentUser{
			ID:        userID,
			TenantID:  uuid.Nil,
			SessionID: sessionID,
		})
		setRequestTenant(c, uuid.Nil)
		c.Next()
	})
	router.Use(mw.SessionTenantBinding())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ------------------------------------------------------------------
// Table-driven tests for tenant affinity edge cases
// ------------------------------------------------------------------

func TestSessionTenantBinding_TenantAffinity_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		jwtTenantID     uuid.UUID
		requestTenantID uuid.UUID
		expectBlocked   bool
	}{
		{
			name:            "same tenant - allowed",
			jwtTenantID:     uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			requestTenantID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			expectBlocked:   false,
		},
		{
			name:            "different tenant - blocked",
			jwtTenantID:     uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			requestTenantID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
			expectBlocked:   true,
		},
		{
			name:            "jwt tenant nil, request tenant set - allowed (no jwt tenant to compare)",
			jwtTenantID:     uuid.Nil,
			requestTenantID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			expectBlocked:   false,
		},
		{
			name:            "jwt tenant set, request tenant nil - allowed (no request tenant to compare)",
			jwtTenantID:     uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			requestTenantID: uuid.Nil,
			expectBlocked:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewSessionTenantBindingMiddleware(nil, nil)

			router := setupTestRouter(mw)
			router.Use(func(c *gin.Context) {
				setCurrentUser(c, &models.CurrentUser{
					ID:        uuid.New(),
					TenantID:  tt.jwtTenantID,
					SessionID: uuid.New(),
				})
				if tt.requestTenantID != uuid.Nil {
					setRequestTenant(c, tt.requestTenantID)
				}
				c.Next()
			})
			router.Use(mw.SessionTenantBinding())
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "/test", nil)
			router.ServeHTTP(w, req)

			if tt.expectBlocked {
				assert.Equal(t, http.StatusForbidden, w.Code, "expected request to be blocked")
			} else {
				assert.Equal(t, http.StatusOK, w.Code, "expected request to pass")
			}
		})
	}
}

// ------------------------------------------------------------------
// Model-level tests for session fixation protection fields
// ------------------------------------------------------------------

func TestSession_FixationProtectionFields(t *testing.T) {
	now := time.Now()
	prevID := uuid.New()

	session := &models.Session{
		ID:                 uuid.New(),
		UserID:             uuid.New(),
		CreatedAt:          now,
		AuthenticatedAt:    &now,
		PreviousSessionID:  &prevID,
		SessionRegenerated: true,
	}

	assert.NotNil(t, session.AuthenticatedAt)
	assert.Equal(t, now.Unix(), session.AuthenticatedAt.Unix())
	assert.NotNil(t, session.PreviousSessionID)
	assert.Equal(t, prevID, *session.PreviousSessionID)
	assert.True(t, session.SessionRegenerated)
}

func TestSession_NewSessionHasNilPreviousID(t *testing.T) {
	session := &models.Session{
		ID:     uuid.New(),
		UserID: uuid.New(),
	}

	assert.Nil(t, session.PreviousSessionID)
	assert.False(t, session.SessionRegenerated)
	assert.Nil(t, session.AuthenticatedAt)
}

// ------------------------------------------------------------------
// Constant validation tests
// ------------------------------------------------------------------

func TestMaxAuthenticatedAtSkew(t *testing.T) {
	// Verify the constant is set to a reasonable value
	assert.Equal(t, 5*time.Minute, maxAuthenticatedAtSkew)
	assert.True(t, maxAuthenticatedAtSkew > 0, "maxAuthenticatedAtSkew must be positive")
	assert.True(t, maxAuthenticatedAtSkew <= 10*time.Minute, "maxAuthenticatedAtSkew should not be too large")
}
