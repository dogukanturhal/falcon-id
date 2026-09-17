// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

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
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

// ─────────────────────────────────────────────────────────────
// Mock repo for APIKeyService (satisfies apiKeyServiceRepo)
// ─────────────────────────────────────────────────────────────

type mockAPIKeyRepo struct {
	createFn         func(ctx context.Context, key *models.APIKey) error
	getByIDFn        func(ctx context.Context, id uuid.UUID) (*models.APIKey, error)
	getByTenantIDFn  func(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error)
	getByUserIDFn    func(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error)
	updateFn         func(ctx context.Context, key *models.APIKey) error
	revokeFn         func(ctx context.Context, id uuid.UUID) error
	deleteFn         func(ctx context.Context, id uuid.UUID) error
	getByPrefixFn    func(ctx context.Context, prefix string) (*models.APIKey, error)
	updateLastUsedFn func(ctx context.Context, id uuid.UUID, ip string) error
	logUsageFn       func(ctx context.Context, usage *models.APIKeyUsage) error
	getUsageStatsFn  func(ctx context.Context, keyID uuid.UUID) (*models.APIKeyUsageStats, error)
}

func (m *mockAPIKeyRepo) Create(ctx context.Context, key *models.APIKey) error {
	if m.createFn != nil {
		return m.createFn(ctx, key)
	}
	return nil
}

func (m *mockAPIKeyRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockAPIKeyRepo) GetByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*models.APIKey, error) {
	if m.getByTenantIDFn != nil {
		return m.getByTenantIDFn(ctx, tenantID)
	}
	return []*models.APIKey{}, nil
}

func (m *mockAPIKeyRepo) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	if m.getByUserIDFn != nil {
		return m.getByUserIDFn(ctx, userID)
	}
	return []*models.APIKey{}, nil
}

func (m *mockAPIKeyRepo) Update(ctx context.Context, key *models.APIKey) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, key)
	}
	return nil
}

func (m *mockAPIKeyRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, id)
	}
	return nil
}

func (m *mockAPIKeyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockAPIKeyRepo) GetByPrefix(ctx context.Context, prefix string) (*models.APIKey, error) {
	if m.getByPrefixFn != nil {
		return m.getByPrefixFn(ctx, prefix)
	}
	return nil, errors.New("not found")
}

func (m *mockAPIKeyRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	if m.updateLastUsedFn != nil {
		return m.updateLastUsedFn(ctx, id, ip)
	}
	return nil
}

func (m *mockAPIKeyRepo) LogUsage(ctx context.Context, usage *models.APIKeyUsage) error {
	if m.logUsageFn != nil {
		return m.logUsageFn(ctx, usage)
	}
	return nil
}

func (m *mockAPIKeyRepo) GetUsageStats(ctx context.Context, keyID uuid.UUID) (*models.APIKeyUsageStats, error) {
	if m.getUsageStatsFn != nil {
		return m.getUsageStatsFn(ctx, keyID)
	}
	return nil, errors.New("not found")
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func newAPIKeyHandlerWithMock(repo *mockAPIKeyRepo) *APIKeyHandler {
	svc := services.NewAPIKeyService(repo)
	return NewAPIKeyHandler(svc, zap.NewNop())
}

func newTestAPIKey(id, tenantID, userID uuid.UUID, name string) *models.APIKey {
	return &models.APIKey{
		ID:          id,
		TenantID:    tenantID,
		UserID:      userID,
		Name:        name,
		KeyPrefix:   "testpfx",
		KeyHash:     "hashed-key-value",
		Environment: "production",
		IsActive:    true,
		CreatedAt:   time.Now(),
	}
}

// injectCurrentUser creates a gin middleware that injects the given CurrentUser.
func injectCurrentUser(user *models.CurrentUser) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("current_user", user)
		c.Next()
	}
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

func TestAPIKeyHandler_ListAPIKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("returns empty list when no keys exist", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			getByTenantIDFn: func(_ context.Context, tID uuid.UUID) ([]*models.APIKey, error) {
				assert.Equal(t, tenantID, tID)
				return []*models.APIKey{}, nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys", h.ListAPIKeys)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp []*models.APIKeyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Empty(t, resp)
	})

	t.Run("returns list of API keys for tenant", func(t *testing.T) {
		keyID1 := uuid.New()
		keyID2 := uuid.New()

		repo := &mockAPIKeyRepo{
			getByTenantIDFn: func(_ context.Context, _ uuid.UUID) ([]*models.APIKey, error) {
				return []*models.APIKey{
					newTestAPIKey(keyID1, tenantID, userID, "Key One"),
					newTestAPIKey(keyID2, tenantID, userID, "Key Two"),
				}, nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys", h.ListAPIKeys)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp []*models.APIKeyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp, 2)
		assert.Equal(t, "Key One", resp[0].Name)
		assert.Equal(t, "Key Two", resp[1].Name)
	})

	t.Run("returns 401 when user not authenticated", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.GET("/api-keys", h.ListAPIKeys)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 500 on repo error", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			getByTenantIDFn: func(_ context.Context, _ uuid.UUID) ([]*models.APIKey, error) {
				return nil, errors.New("database error")
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys", h.ListAPIKeys)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestAPIKeyHandler_GetAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()
	key := newTestAPIKey(keyID, tenantID, userID, "My Key")

	t.Run("returns key by ID", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.APIKey, error) {
				if id == keyID {
					return key, nil
				}
				return nil, errors.New("not found")
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys/:id", h.GetAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys/"+keyID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.APIKeyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, keyID, resp.ID)
		assert.Equal(t, "My Key", resp.Name)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys/:id", h.GetAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys/not-a-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 for key belonging to different tenant", func(t *testing.T) {
		otherTenantKey := newTestAPIKey(keyID, uuid.New(), userID, "Other Tenant Key")

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return otherTenantKey, nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys/:id", h.GetAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys/"+keyID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 404 when key not found", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return nil, nil // nil, nil means "not found" per handler logic
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys/:id", h.GetAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys/"+keyID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestAPIKeyHandler_CreateAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("creates API key and returns it once with full key value", func(t *testing.T) {
		var createdKey *models.APIKey

		repo := &mockAPIKeyRepo{
			createFn: func(_ context.Context, key *models.APIKey) error {
				key.ID = uuid.New()
				key.CreatedAt = time.Now()
				createdKey = key
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys", h.CreateAPIKey)

		body := `{"name":"CI/CD Key","scopes":["read:users","write:users"]}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp models.APIKeyCreatedResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		// The full key value is only exposed at creation time
		assert.NotEmpty(t, resp.Key, "key value must be present at creation")
		assert.True(t, len(resp.Key) > 10, "key should be a substantial string")
		assert.Equal(t, "CI/CD Key", resp.Name)
		assert.Equal(t, tenantID, resp.TenantID)

		// Verify the key hash is NOT exposed (KeyHash field is json:"-")
		rawBody := w.Body.Bytes()
		assert.NotContains(t, string(rawBody), "key_hash")

		require.NotNil(t, createdKey)
		assert.Equal(t, tenantID, createdKey.TenantID)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.POST("/api-keys", h.CreateAPIKey)

		body := `{"name":"Test Key"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys", h.CreateAPIKey)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys", strings.NewReader(`{invalid`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 on repo create error", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			createFn: func(_ context.Context, _ *models.APIKey) error {
				return errors.New("db error")
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys", h.CreateAPIKey)

		body := `{"name":"Bad Key"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAPIKeyHandler_UpdateAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()

	t.Run("updates API key successfully", func(t *testing.T) {
		existingKey := newTestAPIKey(keyID, tenantID, userID, "Old Name")

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return existingKey, nil
			},
			updateFn: func(_ context.Context, _ *models.APIKey) error {
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.PUT("/api-keys/:id", h.UpdateAPIKey)

		newName := "New Name"
		body, _ := json.Marshal(models.UpdateAPIKeyRequest{Name: &newName})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api-keys/"+keyID.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.APIKeyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "New Name", resp.Name)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.PUT("/api-keys/:id", h.UpdateAPIKey)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api-keys/bad-id", strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAPIKeyHandler_RevokeAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()

	t.Run("revokes API key successfully", func(t *testing.T) {
		existingKey := newTestAPIKey(keyID, tenantID, userID, "Key to Revoke")
		var revokedID uuid.UUID

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return existingKey, nil
			},
			revokeFn: func(_ context.Context, id uuid.UUID) error {
				revokedID = id
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys/:id/revoke", h.RevokeAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys/"+keyID.String()+"/revoke", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, keyID, revokedID)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Contains(t, body["message"], "revoked")
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys/:id/revoke", h.RevokeAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys/bad-uuid/revoke", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.POST("/api-keys/:id/revoke", h.RevokeAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys/"+keyID.String()+"/revoke", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAPIKeyHandler_DeleteAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()

	t.Run("deletes API key (returns 204)", func(t *testing.T) {
		existingKey := newTestAPIKey(keyID, tenantID, userID, "Key to Delete")
		var deletedID uuid.UUID

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return existingKey, nil
			},
			deleteFn: func(_ context.Context, id uuid.UUID) error {
				deletedID = id
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.DELETE("/api-keys/:id", h.DeleteAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api-keys/"+keyID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, keyID, deletedID)
		assert.Empty(t, w.Body.String())
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.DELETE("/api-keys/:id", h.DeleteAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api-keys/not-valid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAPIKeyHandler_RegenerateAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()

	t.Run("regenerates API key and returns new key value", func(t *testing.T) {
		existingKey := newTestAPIKey(keyID, tenantID, userID, "Old Key")
		existingKey.Scopes = []string{"read:users"}
		existingKey.Environment = "production"

		callCount := 0

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				callCount++
				if callCount == 1 {
					// First call: GetByID for the old key
					return existingKey, nil
				}
				// Second call: GetByID inside Create service (for new key after create)
				newKey := newTestAPIKey(uuid.New(), tenantID, userID, "Old Key (regenerated)")
				return newKey, nil
			},
			createFn: func(_ context.Context, key *models.APIKey) error {
				key.ID = uuid.New()
				key.CreatedAt = time.Now()
				return nil
			},
			revokeFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys/:id/regenerate", h.RegenerateAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys/"+keyID.String()+"/regenerate", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp models.APIKeyCreatedResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Key, "regenerated key must include the new key value")
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/api-keys/:id/regenerate", h.RegenerateAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys/bad/regenerate", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 401 when not authenticated", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.POST("/api-keys/:id/regenerate", h.RegenerateAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api-keys/"+keyID.String()+"/regenerate", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAPIKeyHandler_GetAPIKeyUsageStats(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()

	t.Run("returns usage stats for owned API key", func(t *testing.T) {
		existingKey := newTestAPIKey(keyID, tenantID, userID, "Stats Key")
		stats := &models.APIKeyUsageStats{
			TotalRequests:     1000,
			Last24Hours:       50,
			Last7Days:         300,
			AvgResponseTimeMs: 45.5,
			ErrorRate:         0.02,
			TopEndpoints: []models.EndpointUsage{
				{Endpoint: "/api/users", RequestCount: 400},
			},
		}

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return existingKey, nil
			},
			getUsageStatsFn: func(_ context.Context, _ uuid.UUID) (*models.APIKeyUsageStats, error) {
				return stats, nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/api-keys/:id/stats", h.GetAPIKeyUsageStats)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api-keys/"+keyID.String()+"/stats", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.APIKeyUsageStats
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1000), resp.TotalRequests)
		assert.Equal(t, int64(50), resp.Last24Hours)
	})
}

func TestAPIKeyHandler_ListMyAPIKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("returns API keys for current user", func(t *testing.T) {
		keyID := uuid.New()
		repo := &mockAPIKeyRepo{
			getByUserIDFn: func(_ context.Context, uID uuid.UUID) ([]*models.APIKey, error) {
				assert.Equal(t, userID, uID)
				return []*models.APIKey{
					newTestAPIKey(keyID, tenantID, userID, "User Personal Key"),
				}, nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.GET("/auth/api-keys", h.ListMyAPIKeys)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/api-keys", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp []*models.APIKeyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "User Personal Key", resp[0].Name)
	})
}

func TestAPIKeyHandler_CreateMyAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("creates API key for current user", func(t *testing.T) {
		repo := &mockAPIKeyRepo{
			createFn: func(_ context.Context, key *models.APIKey) error {
				key.ID = uuid.New()
				key.CreatedAt = time.Now()
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/auth/api-keys", h.CreateMyAPIKey)

		body := `{"name":"My Personal Key"}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/api-keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp models.APIKeyCreatedResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Key)
		assert.Equal(t, "My Personal Key", resp.Name)
	})
}

func TestAPIKeyHandler_RevokeMyAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()
	keyID := uuid.New()

	t.Run("revokes user's own API key", func(t *testing.T) {
		key := newTestAPIKey(keyID, tenantID, userID, "Personal Key")

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return key, nil
			},
			revokeFn: func(_ context.Context, _ uuid.UUID) error {
				return nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/auth/api-keys/:id/revoke", h.RevokeMyAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/api-keys/"+keyID.String()+"/revoke", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns 404 when key belongs to different user", func(t *testing.T) {
		otherUserKey := newTestAPIKey(keyID, tenantID, uuid.New(), "Other User's Key")

		repo := &mockAPIKeyRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.APIKey, error) {
				return otherUserKey, nil
			},
		}

		h := newAPIKeyHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/auth/api-keys/:id/revoke", h.RevokeMyAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/api-keys/"+keyID.String()+"/revoke", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newAPIKeyHandlerWithMock(&mockAPIKeyRepo{})
		router := gin.New()
		router.Use(injectCurrentUser(&models.CurrentUser{ID: userID, TenantID: tenantID}))
		router.POST("/auth/api-keys/:id/revoke", h.RevokeMyAPIKey)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/api-keys/bad-uuid/revoke", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
