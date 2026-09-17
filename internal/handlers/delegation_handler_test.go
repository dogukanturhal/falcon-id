// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// delegation_handler_test.go covers DelegationHandler:
//
//   CreateDelegation   — grant act-on-behalf permissions to another user
//   ListMyDelegations  — list delegations involving the current user
//   GetDelegation      — retrieve a single delegation by ID
//   RevokeDelegation   — cancel a delegation
//
// The handler stores a concrete *services.DelegationService pointer so we
// use the same adapter pattern: local interface + fake + testDelegationHandler.

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
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Local service interface
// ---------------------------------------------------------------------------

type delegationSvc interface {
	CreateDelegation(ctx context.Context, delegatorID, tenantID uuid.UUID, req *models.CreateDelegationRequest) (*models.Delegation, error)
	GetDelegation(ctx context.Context, id, callerID, tenantID uuid.UUID) (*models.DelegationResponse, error)
	ListMyDelegations(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.DelegationResponse, error)
	RevokeDelegation(ctx context.Context, id, callerID, tenantID uuid.UUID) error
}

// ---------------------------------------------------------------------------
// Mock delegationSvc
// ---------------------------------------------------------------------------

type mockDelegationSvc struct {
	createFn func(ctx context.Context, delegatorID, tenantID uuid.UUID, req *models.CreateDelegationRequest) (*models.Delegation, error)
	getFn    func(ctx context.Context, id, callerID, tenantID uuid.UUID) (*models.DelegationResponse, error)
	listMyFn func(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.DelegationResponse, error)
	revokeFn func(ctx context.Context, id, callerID, tenantID uuid.UUID) error
}

func (m *mockDelegationSvc) CreateDelegation(ctx context.Context, delegatorID, tenantID uuid.UUID, req *models.CreateDelegationRequest) (*models.Delegation, error) {
	if m.createFn != nil {
		return m.createFn(ctx, delegatorID, tenantID, req)
	}
	return &models.Delegation{ID: uuid.New(), TenantID: tenantID, DelegatorID: delegatorID, DelegateeID: req.DelegateeID}, nil
}

func (m *mockDelegationSvc) GetDelegation(ctx context.Context, id, callerID, tenantID uuid.UUID) (*models.DelegationResponse, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id, callerID, tenantID)
	}
	return nil, errors.New("not found")
}

func (m *mockDelegationSvc) ListMyDelegations(ctx context.Context, userID uuid.UUID, includeRevoked bool) ([]*models.DelegationResponse, error) {
	if m.listMyFn != nil {
		return m.listMyFn(ctx, userID, includeRevoked)
	}
	return []*models.DelegationResponse{}, nil
}

func (m *mockDelegationSvc) RevokeDelegation(ctx context.Context, id, callerID, tenantID uuid.UUID) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, id, callerID, tenantID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test adapter — mirrors DelegationHandler without concrete services
// ---------------------------------------------------------------------------

type testDelegationHandler struct {
	svc    delegationSvc
	logger *zap.Logger
}

func newTestDelegationHandler(svc delegationSvc) *testDelegationHandler {
	return &testDelegationHandler{svc: svc, logger: zap.NewNop()}
}

func (h *testDelegationHandler) getUser(c *gin.Context) *models.CurrentUser {
	raw, exists := c.Get("current_user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil
	}
	cu, ok := raw.(*models.CurrentUser)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user context"})
		return nil
	}
	return cu
}

func (h *testDelegationHandler) CreateDelegation(c *gin.Context) {
	cu := h.getUser(c)
	if cu == nil {
		return
	}
	var req models.CreateDelegationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	delegation, err := h.svc.CreateDelegation(c.Request.Context(), cu.ID, cu.TenantID, &req)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	response, err := h.svc.GetDelegation(c.Request.Context(), delegation.ID, cu.ID, cu.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load delegation"})
		return
	}
	c.JSON(http.StatusCreated, response)
}

func (h *testDelegationHandler) ListMyDelegations(c *gin.Context) {
	cu := h.getUser(c)
	if cu == nil {
		return
	}
	includeRevoked := c.Query("include_revoked") == queryBoolTrue
	delegations, err := h.svc.ListMyDelegations(c.Request.Context(), cu.ID, includeRevoked)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list delegations"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"delegations": delegations})
}

func (h *testDelegationHandler) GetDelegation(c *gin.Context) {
	cu := h.getUser(c)
	if cu == nil {
		return
	}
	delegationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid delegation ID"})
		return
	}
	delegation, err := h.svc.GetDelegation(c.Request.Context(), delegationID, cu.ID, cu.TenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "delegation not found"})
		return
	}
	c.JSON(http.StatusOK, delegation)
}

func (h *testDelegationHandler) RevokeDelegation(c *gin.Context) {
	cu := h.getUser(c)
	if cu == nil {
		return
	}
	delegationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid delegation ID"})
		return
	}
	if err := h.svc.RevokeDelegation(c.Request.Context(), delegationID, cu.ID, cu.TenantID); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "delegation revoked successfully"})
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newDelegationTestRouter(h *testDelegationHandler) *gin.Engine {
	r := gin.New()
	r.POST("/api/delegations", h.CreateDelegation)
	r.GET("/api/delegations", h.ListMyDelegations)
	r.GET("/api/delegations/:id", h.GetDelegation)
	r.DELETE("/api/delegations/:id", h.RevokeDelegation)
	return r
}

func sampleDelegationResponse(delegationID, tenantID, delegatorID, delegateeID uuid.UUID) *models.DelegationResponse {
	return &models.DelegationResponse{
		ID:            delegationID.String(),
		TenantID:      tenantID.String(),
		DelegatorID:   delegatorID.String(),
		DelegatorName: "Alice",
		DelegateeID:   delegateeID.String(),
		DelegateeName: "Bob",
		Permissions:   []string{"reports:read"},
		ExpiresAt:     time.Now().Add(time.Hour),
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func delegJSONBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// ---------------------------------------------------------------------------
// Tests: CreateDelegation
// ---------------------------------------------------------------------------

func TestDelegationHandler_CreateDelegation(t *testing.T) {
	t.Run("creates delegation and returns 201", func(t *testing.T) {
		tenantID := uuid.New()
		delegatorID := uuid.New()
		delegateeID := uuid.New()
		delegationID := uuid.New()
		cu := &models.CurrentUser{ID: delegatorID, TenantID: tenantID}

		svc := &mockDelegationSvc{
			createFn: func(_ context.Context, dID, tID uuid.UUID, req *models.CreateDelegationRequest) (*models.Delegation, error) {
				assert.Equal(t, delegatorID, dID)
				assert.Equal(t, tenantID, tID)
				assert.Equal(t, delegateeID, req.DelegateeID)
				assert.Contains(t, req.Permissions, "reports:read")
				return &models.Delegation{
					ID:          delegationID,
					TenantID:    tenantID,
					DelegatorID: delegatorID,
					DelegateeID: delegateeID,
				}, nil
			},
			getFn: func(_ context.Context, id, _, _ uuid.UUID) (*models.DelegationResponse, error) {
				return sampleDelegationResponse(id, tenantID, delegatorID, delegateeID), nil
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/delegations", func(c *gin.Context) { c.Set("current_user", cu) }, h.CreateDelegation)

		body := delegJSONBody(t, models.CreateDelegationRequest{
			DelegateeID: delegateeID,
			Permissions: []string{"reports:read"},
			Duration:    3600, // 1 hour in seconds
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/delegations", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp models.DelegationResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "active", resp.Status)
		assert.Equal(t, delegatorID.String(), resp.DelegatorID)
		assert.Equal(t, delegateeID.String(), resp.DelegateeID)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &mockDelegationSvc{}
		router := newDelegationTestRouter(newTestDelegationHandler(svc))

		body := delegJSONBody(t, models.CreateDelegationRequest{
			DelegateeID: uuid.New(),
			Permissions: []string{"reports:read"},
			Duration:    3600,
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/delegations", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 400 for malformed JSON", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/delegations", func(c *gin.Context) { c.Set("current_user", cu) }, h.CreateDelegation)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/delegations", bytes.NewReader([]byte("{bad}")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 403 when service rejects delegation", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{
			createFn: func(_ context.Context, _, _ uuid.UUID, _ *models.CreateDelegationRequest) (*models.Delegation, error) {
				return nil, errors.New("cannot delegate permissions you don't have")
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.POST("/api/delegations", func(c *gin.Context) { c.Set("current_user", cu) }, h.CreateDelegation)

		body := delegJSONBody(t, models.CreateDelegationRequest{
			DelegateeID: uuid.New(),
			Permissions: []string{"admin:all"},
			Duration:    3600,
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/delegations", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r2.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "cannot delegate")
	})
}

// ---------------------------------------------------------------------------
// Tests: ListMyDelegations
// ---------------------------------------------------------------------------

func TestDelegationHandler_ListMyDelegations(t *testing.T) {
	t.Run("returns delegations for current user", func(t *testing.T) {
		tenantID := uuid.New()
		userID := uuid.New()
		cu := &models.CurrentUser{ID: userID, TenantID: tenantID}

		svc := &mockDelegationSvc{
			listMyFn: func(_ context.Context, uID uuid.UUID, includeRevoked bool) ([]*models.DelegationResponse, error) {
				assert.Equal(t, userID, uID)
				assert.False(t, includeRevoked)
				return []*models.DelegationResponse{
					sampleDelegationResponse(uuid.New(), tenantID, userID, uuid.New()),
					sampleDelegationResponse(uuid.New(), tenantID, uuid.New(), userID),
				}, nil
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/delegations", func(c *gin.Context) { c.Set("current_user", cu) }, h.ListMyDelegations)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
		delegations, ok := body["delegations"].([]interface{})
		require.True(t, ok)
		assert.Len(t, delegations, 2)
	})

	t.Run("passes include_revoked=true when query param set", func(t *testing.T) {
		tenantID := uuid.New()
		userID := uuid.New()
		cu := &models.CurrentUser{ID: userID, TenantID: tenantID}
		var capturedIncludeRevoked bool

		svc := &mockDelegationSvc{
			listMyFn: func(_ context.Context, _ uuid.UUID, includeRevoked bool) ([]*models.DelegationResponse, error) {
				capturedIncludeRevoked = includeRevoked
				return []*models.DelegationResponse{}, nil
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/delegations", func(c *gin.Context) { c.Set("current_user", cu) }, h.ListMyDelegations)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations?include_revoked=true", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, capturedIncludeRevoked)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &mockDelegationSvc{}
		router := newDelegationTestRouter(newTestDelegationHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 500 on service error", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{
			listMyFn: func(_ context.Context, _ uuid.UUID, _ bool) ([]*models.DelegationResponse, error) {
				return nil, errors.New("database error")
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/delegations", func(c *gin.Context) { c.Set("current_user", cu) }, h.ListMyDelegations)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: GetDelegation
// ---------------------------------------------------------------------------

func TestDelegationHandler_GetDelegation(t *testing.T) {
	t.Run("returns delegation for authorised user", func(t *testing.T) {
		tenantID := uuid.New()
		userID := uuid.New()
		delegateeID := uuid.New()
		delegationID := uuid.New()
		cu := &models.CurrentUser{ID: userID, TenantID: tenantID}

		svc := &mockDelegationSvc{
			getFn: func(_ context.Context, id, callerID, tID uuid.UUID) (*models.DelegationResponse, error) {
				assert.Equal(t, delegationID, id)
				assert.Equal(t, userID, callerID)
				assert.Equal(t, tenantID, tID)
				return sampleDelegationResponse(id, tID, userID, delegateeID), nil
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/delegations/:id", func(c *gin.Context) { c.Set("current_user", cu) }, h.GetDelegation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations/"+delegationID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp models.DelegationResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, delegationID.String(), resp.ID)
		assert.Equal(t, "active", resp.Status)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/delegations/:id", func(c *gin.Context) { c.Set("current_user", cu) }, h.GetDelegation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations/not-a-uuid", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when delegation not found", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{
			getFn: func(_ context.Context, _, _, _ uuid.UUID) (*models.DelegationResponse, error) {
				return nil, errors.New("delegation not found")
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.GET("/api/delegations/:id", func(c *gin.Context) { c.Set("current_user", cu) }, h.GetDelegation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &mockDelegationSvc{}
		router := newDelegationTestRouter(newTestDelegationHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/delegations/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ---------------------------------------------------------------------------
// Tests: RevokeDelegation
// ---------------------------------------------------------------------------

func TestDelegationHandler_RevokeDelegation(t *testing.T) {
	t.Run("revokes delegation successfully", func(t *testing.T) {
		tenantID := uuid.New()
		userID := uuid.New()
		delegationID := uuid.New()
		cu := &models.CurrentUser{ID: userID, TenantID: tenantID}
		var capturedID uuid.UUID

		svc := &mockDelegationSvc{
			revokeFn: func(_ context.Context, id, callerID, tID uuid.UUID) error {
				capturedID = id
				assert.Equal(t, userID, callerID)
				assert.Equal(t, tenantID, tID)
				return nil
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.DELETE("/api/delegations/:id", func(c *gin.Context) { c.Set("current_user", cu) }, h.RevokeDelegation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/delegations/"+delegationID.String(), nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, delegationID, capturedID)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["message"], "revoked successfully")
	})

	t.Run("returns 403 when caller is not the delegator", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{
			revokeFn: func(_ context.Context, _, _, _ uuid.UUID) error {
				return errors.New("only the delegator can revoke this delegation")
			},
		}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.DELETE("/api/delegations/:id", func(c *gin.Context) { c.Set("current_user", cu) }, h.RevokeDelegation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/delegations/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusForbidden, w.Code)
		var resp map[string]string
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Contains(t, resp["error"], "delegator")
	})

	t.Run("returns 400 for invalid delegation UUID", func(t *testing.T) {
		tenantID := uuid.New()
		cu := &models.CurrentUser{ID: uuid.New(), TenantID: tenantID}
		svc := &mockDelegationSvc{}
		h := newTestDelegationHandler(svc)

		r2 := gin.New()
		r2.DELETE("/api/delegations/:id", func(c *gin.Context) { c.Set("current_user", cu) }, h.RevokeDelegation)

		w := httptest.NewRecorder()
		r2.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/delegations/bad-uuid", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		svc := &mockDelegationSvc{}
		router := newDelegationTestRouter(newTestDelegationHandler(svc))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/delegations/"+uuid.New().String(), nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
