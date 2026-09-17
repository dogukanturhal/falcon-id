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

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
)

const testWebhookEventBody = `{"event_type":"user.created"}`

// ─────────────────────────────────────────────────────────────
// Mock repo for WebhookService (satisfies webhookServiceWebhookRepo)
// ─────────────────────────────────────────────────────────────

type mockWebhookRepo struct {
	getPendingDeliveriesFn   func(ctx context.Context, limit int) ([]*models.WebhookDelivery, error)
	markDeliveryProcessingFn func(ctx context.Context, id uuid.UUID) error
	updateDeliveryFn         func(ctx context.Context, delivery *models.WebhookDelivery) error
	createFn                 func(ctx context.Context, webhook *models.Webhook) error
	getByIDFn                func(ctx context.Context, id uuid.UUID) (*models.Webhook, error)
	updateFn                 func(ctx context.Context, webhook *models.Webhook) error
	deleteFn                 func(ctx context.Context, id, tenantID uuid.UUID) error
	listFn                   func(ctx context.Context, tenantID uuid.UUID, page, pageSize int, activeOnly bool) ([]*models.Webhook, int, error)
	getActiveByEventFn       func(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*models.Webhook, error)
	createDeliveryFn         func(ctx context.Context, delivery *models.WebhookDelivery) error
	listDeliveriesFn         func(ctx context.Context, webhookID uuid.UUID, page, pageSize int, status *string) ([]*models.WebhookDelivery, int, error)
	getDeliveryByIDFn        func(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error)
	getDeliveryStatsFn       func(ctx context.Context, webhookID uuid.UUID) (map[string]int, error)
}

func (m *mockWebhookRepo) GetPendingDeliveries(ctx context.Context, limit int) ([]*models.WebhookDelivery, error) {
	if m.getPendingDeliveriesFn != nil {
		return m.getPendingDeliveriesFn(ctx, limit)
	}
	return []*models.WebhookDelivery{}, nil
}

func (m *mockWebhookRepo) MarkDeliveryProcessing(ctx context.Context, id uuid.UUID) error {
	if m.markDeliveryProcessingFn != nil {
		return m.markDeliveryProcessingFn(ctx, id)
	}
	return nil
}

func (m *mockWebhookRepo) UpdateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error {
	if m.updateDeliveryFn != nil {
		return m.updateDeliveryFn(ctx, delivery)
	}
	return nil
}

func (m *mockWebhookRepo) Create(ctx context.Context, webhook *models.Webhook) error {
	if m.createFn != nil {
		return m.createFn(ctx, webhook)
	}
	return nil
}

func (m *mockWebhookRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Webhook, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockWebhookRepo) Update(ctx context.Context, webhook *models.Webhook) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, webhook)
	}
	return nil
}

func (m *mockWebhookRepo) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id, tenantID)
	}
	return nil
}

func (m *mockWebhookRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, activeOnly bool) ([]*models.Webhook, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, tenantID, page, pageSize, activeOnly)
	}
	return []*models.Webhook{}, 0, nil
}

func (m *mockWebhookRepo) GetActiveByEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*models.Webhook, error) {
	if m.getActiveByEventFn != nil {
		return m.getActiveByEventFn(ctx, tenantID, eventType)
	}
	return []*models.Webhook{}, nil
}

func (m *mockWebhookRepo) CreateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error {
	if m.createDeliveryFn != nil {
		return m.createDeliveryFn(ctx, delivery)
	}
	return nil
}

func (m *mockWebhookRepo) ListDeliveries(ctx context.Context, webhookID uuid.UUID, page, pageSize int, status *string) ([]*models.WebhookDelivery, int, error) {
	if m.listDeliveriesFn != nil {
		return m.listDeliveriesFn(ctx, webhookID, page, pageSize, status)
	}
	return []*models.WebhookDelivery{}, 0, nil
}

func (m *mockWebhookRepo) GetDeliveryByID(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error) {
	if m.getDeliveryByIDFn != nil {
		return m.getDeliveryByIDFn(ctx, id)
	}
	return nil, errors.New("not found")
}

func (m *mockWebhookRepo) GetDeliveryStats(ctx context.Context, webhookID uuid.UUID) (map[string]int, error) {
	if m.getDeliveryStatsFn != nil {
		return m.getDeliveryStatsFn(ctx, webhookID)
	}
	return map[string]int{}, nil
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func newWebhookHandlerWithMock(repo *mockWebhookRepo) *WebhookHandler {
	svc := services.NewWebhookService(repo)
	return NewWebhookHandler(svc)
}

func newTestWebhook(id, tenantID uuid.UUID, name string) *models.Webhook {
	return &models.Webhook{ //nolint:gosec // test fixture value, not a real credential
		ID:             id,
		TenantID:       tenantID,
		Name:           name,
		URL:            "https://example.com/webhook",
		SecretHash:     "a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
		Events:         []string{"user.created"},
		IsActive:       true,
		RetryCount:     3,
		TimeoutSeconds: 30,
		Headers:        map[string]string{},
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

// injectTenantContext injects a tenant_id into gin context.
func injectTenantContext(tenantID uuid.UUID) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	}
}

// injectTenantAndUser injects both tenant_id and user_id into gin context.
func injectTenantAndUser(tenantID, userID uuid.UUID) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Set("user_id", userID)
		c.Next()
	}
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

func TestWebhookHandler_CreateWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	userID := uuid.New()

	t.Run("creates webhook successfully and returns response", func(t *testing.T) {
		webhookID := uuid.New()

		repo := &mockWebhookRepo{
			createFn: func(_ context.Context, webhook *models.Webhook) error {
				webhook.ID = webhookID
				return nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantAndUser(tenantID, userID))
		router.POST("/webhooks", h.CreateWebhook)

		body := `{
			"name":"Deploy Notification",
			"url":"https://hooks.example.com/deploy",
			"secret":"supersecretvalue12345",
			"events":["user.created","user.updated"]
		}`

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp models.WebhookCreatedResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Deploy Notification", resp.Name)
		assert.Equal(t, "https://hooks.example.com/deploy", resp.URL)
		// Secret is returned only at creation
		assert.Equal(t, "supersecretvalue12345", resp.Secret)
		assert.Equal(t, tenantID, resp.TenantID)
	})

	t.Run("returns 400 when tenant_id not in context", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.POST("/webhooks", h.CreateWebhook)

		body := `{"name":"Test","url":"https://example.com","secret":"secret12345678","events":["user.created"]}` // gitleaks:allow — test fixture, not a real credential
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON body", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks", h.CreateWebhook)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks", strings.NewReader(`{invalid}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when secret is too short (less than 16 chars)", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks", h.CreateWebhook)

		// Secret is only 8 chars - below 16 minimum
		body := `{"name":"Test","url":"https://example.com","secret":"short","events":["user.created"]}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid event type", func(t *testing.T) {
		repo := &mockWebhookRepo{}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks", h.CreateWebhook)

		body := `{"name":"Test","url":"https://example.com","secret":"validsecret12345","events":["invalid.event.type.here"]}` // gitleaks:allow — test fixture, not a real credential
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebhookHandler_GetWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	webhookID := uuid.New()
	webhook := newTestWebhook(webhookID, tenantID, "My Webhook")

	t.Run("returns webhook by ID", func(t *testing.T) {
		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*models.Webhook, error) {
				if id == webhookID {
					return webhook, nil
				}
				return nil, errors.New("not found")
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id", h.GetWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/"+webhookID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.WebhookResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, webhookID, resp.ID)
		assert.Equal(t, "My Webhook", resp.Name)
		assert.Equal(t, "https://example.com/webhook", resp.URL)
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id", h.GetWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/bad-id", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 when webhook not found", func(t *testing.T) {
		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return nil, errors.New("not found")
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id", h.GetWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/"+webhookID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 404 for webhook belonging to different tenant", func(t *testing.T) {
		differentTenantWebhook := newTestWebhook(webhookID, uuid.New(), "Other Tenant Webhook")

		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return differentTenantWebhook, nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id", h.GetWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/"+webhookID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestWebhookHandler_UpdateWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	webhookID := uuid.New()
	webhook := newTestWebhook(webhookID, tenantID, "Original Webhook")

	t.Run("updates webhook successfully", func(t *testing.T) {
		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return webhook, nil
			},
			updateFn: func(_ context.Context, _ *models.Webhook) error {
				return nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/webhooks/:id", h.UpdateWebhook)

		newName := "Updated Webhook"
		body, _ := json.Marshal(models.UpdateWebhookRequest{Name: &newName}) //nolint:gosec // test struct with secret field, not real credentials
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/webhooks/"+webhookID.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.WebhookResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Updated Webhook", resp.Name)
	})

	t.Run("returns 400 when new secret is too short", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return webhook, nil
			},
		})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/webhooks/:id", h.UpdateWebhook)

		tooShort := "abc"
		body, _ := json.Marshal(models.UpdateWebhookRequest{Secret: &tooShort}) //nolint:gosec // test struct with secret field, not real credentials
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/webhooks/"+webhookID.String(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid webhook UUID", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.PUT("/webhooks/:id", h.UpdateWebhook)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/webhooks/bad-id", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebhookHandler_DeleteWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	webhookID := uuid.New()

	t.Run("deletes webhook successfully", func(t *testing.T) {
		var deletedID, deletedTenantID uuid.UUID

		repo := &mockWebhookRepo{
			deleteFn: func(_ context.Context, id, tID uuid.UUID) error {
				deletedID = id
				deletedTenantID = tID
				return nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/webhooks/:id", h.DeleteWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/webhooks/"+webhookID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, webhookID, deletedID)
		assert.Equal(t, tenantID, deletedTenantID)

		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		assert.Contains(t, body["message"], "deleted")
	})

	t.Run("returns 400 for invalid UUID", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/webhooks/:id", h.DeleteWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/webhooks/bad-uuid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when delete fails", func(t *testing.T) {
		repo := &mockWebhookRepo{
			deleteFn: func(_ context.Context, _, _ uuid.UUID) error {
				return errors.New("webhook not found or access denied")
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.DELETE("/webhooks/:id", h.DeleteWebhook)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/webhooks/"+webhookID.String(), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebhookHandler_ListWebhooks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()

	t.Run("returns paginated list of webhooks", func(t *testing.T) {
		wh1 := newTestWebhook(uuid.New(), tenantID, "Webhook One")
		wh2 := newTestWebhook(uuid.New(), tenantID, "Webhook Two")

		repo := &mockWebhookRepo{
			listFn: func(_ context.Context, tID uuid.UUID, _, _ int, _ bool) ([]*models.Webhook, int, error) {
				assert.Equal(t, tenantID, tID)
				return []*models.Webhook{wh1, wh2}, 2, nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks", h.ListWebhooks)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks?page=1&page_size=10", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.WebhookListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Webhooks, 2)
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, 1, resp.Page)
	})

	t.Run("applies active_only filter", func(t *testing.T) {
		var capturedActiveOnly bool

		repo := &mockWebhookRepo{
			listFn: func(_ context.Context, _ uuid.UUID, _, _ int, activeOnly bool) ([]*models.Webhook, int, error) {
				capturedActiveOnly = activeOnly
				return []*models.Webhook{}, 0, nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks", h.ListWebhooks)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks?active_only=true", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, capturedActiveOnly)
	})

	t.Run("returns 400 when tenant_id not in context", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.GET("/webhooks", h.ListWebhooks)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 500 on repo error", func(t *testing.T) {
		repo := &mockWebhookRepo{
			listFn: func(_ context.Context, _ uuid.UUID, _, _ int, _ bool) ([]*models.Webhook, int, error) {
				return nil, 0, errors.New("database error")
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks", h.ListWebhooks)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestWebhookHandler_TestWebhook(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	webhookID := uuid.New()

	// TestWebhook makes an actual HTTP request to the webhook URL.
	// We can only test the validation paths here (missing tenant, bad UUID, bad body)
	// and the service-level error path without a real HTTP server.

	t.Run("returns 400 for invalid webhook UUID", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks/:id/test", h.TestWebhook)

		body := testWebhookEventBody
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks/bad-uuid/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when tenant_id not in context", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.POST("/webhooks/:id/test", h.TestWebhook)

		body := testWebhookEventBody
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks/"+webhookID.String()+"/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON body", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks/:id/test", h.TestWebhook)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks/"+webhookID.String()+"/test", strings.NewReader(`{invalid}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 when webhook not found", func(t *testing.T) {
		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return nil, errors.New("not found")
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks/:id/test", h.TestWebhook)

		body := testWebhookEventBody
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks/"+webhookID.String()+"/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for missing event_type field", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.POST("/webhooks/:id/test", h.TestWebhook)

		body := `{}`
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/webhooks/"+webhookID.String()+"/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebhookHandler_GetEventTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newWebhookHandlerWithMock(&mockWebhookRepo{})
	router := gin.New()
	router.GET("/webhooks/event-types", h.GetEventTypes)

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/event-types", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)

	eventTypes, ok := body["event_types"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, eventTypes)

	grouped, ok := body["grouped"].(map[string]interface{})
	require.True(t, ok)
	// Should have category groups like "user", "role", "session", etc.
	assert.Contains(t, grouped, "user")
	assert.Contains(t, grouped, "role")
	assert.Contains(t, grouped, "session")
}

func TestWebhookHandler_ListDeliveries(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	webhookID := uuid.New()

	t.Run("returns deliveries for a webhook", func(t *testing.T) {
		deliveryID := uuid.New()
		webhook := newTestWebhook(webhookID, tenantID, "My Webhook")
		delivery := &models.WebhookDelivery{
			ID:        deliveryID,
			WebhookID: webhookID,
			EventType: "user.created",
			Status:    models.WebhookDeliveryStatusSuccess,
			CreatedAt: time.Now(),
		}

		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return webhook, nil
			},
			listDeliveriesFn: func(_ context.Context, _ uuid.UUID, _, _ int, _ *string) ([]*models.WebhookDelivery, int, error) {
				return []*models.WebhookDelivery{delivery}, 1, nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id/deliveries", h.ListDeliveries)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/"+webhookID.String()+"/deliveries", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp models.WebhookDeliveryListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Len(t, resp.Deliveries, 1)
		assert.Equal(t, 1, resp.Total)
	})

	t.Run("returns 400 for invalid webhook UUID", func(t *testing.T) {
		h := newWebhookHandlerWithMock(&mockWebhookRepo{})
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id/deliveries", h.ListDeliveries)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/bad-uuid/deliveries", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestWebhookHandler_GetDeliveryStats(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tenantID := uuid.New()
	webhookID := uuid.New()

	t.Run("returns delivery stats for a webhook", func(t *testing.T) {
		webhook := newTestWebhook(webhookID, tenantID, "Stats Webhook")
		stats := map[string]int{
			"total":   100,
			"success": 95,
			"failed":  5,
		}

		repo := &mockWebhookRepo{
			getByIDFn: func(_ context.Context, _ uuid.UUID) (*models.Webhook, error) {
				return webhook, nil
			},
			getDeliveryStatsFn: func(_ context.Context, _ uuid.UUID) (map[string]int, error) {
				return stats, nil
			},
		}

		h := newWebhookHandlerWithMock(repo)
		router := gin.New()
		router.Use(injectTenantContext(tenantID))
		router.GET("/webhooks/:id/stats", h.GetDeliveryStats)

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/webhooks/"+webhookID.String()+"/stats", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var body map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err)
		assert.Contains(t, body, "stats")
	})
}

func TestSplitEventType(t *testing.T) {
	tests := []struct {
		input    string
		wantLen  int
		wantPart string
	}{
		{"user.created", 2, "user"},
		{"role.assigned", 2, "role"},
		{"noDot", 1, "noDot"},
		{"a.b.c", 2, "a.b"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parts := splitEventType(tt.input)
			assert.Len(t, parts, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantPart, parts[0])
			}
		})
	}
}
