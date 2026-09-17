// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---------------------------------------------------------------------------
// Mock for webhookServiceWebhookRepo
// ---------------------------------------------------------------------------

type mockWebhookRepo struct {
	mock.Mock
}

func (m *mockWebhookRepo) GetPendingDeliveries(ctx context.Context, limit int) ([]*models.WebhookDelivery, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.WebhookDelivery), args.Error(1)
}

func (m *mockWebhookRepo) MarkDeliveryProcessing(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockWebhookRepo) UpdateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error {
	args := m.Called(ctx, delivery)
	return args.Error(0)
}

func (m *mockWebhookRepo) Create(ctx context.Context, webhook *models.Webhook) error {
	args := m.Called(ctx, webhook)
	return args.Error(0)
}

func (m *mockWebhookRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Webhook, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Webhook), args.Error(1)
}

func (m *mockWebhookRepo) Update(ctx context.Context, webhook *models.Webhook) error {
	args := m.Called(ctx, webhook)
	return args.Error(0)
}

func (m *mockWebhookRepo) Delete(ctx context.Context, id, tenantID uuid.UUID) error {
	args := m.Called(ctx, id, tenantID)
	return args.Error(0)
}

func (m *mockWebhookRepo) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, activeOnly bool) ([]*models.Webhook, int, error) {
	args := m.Called(ctx, tenantID, page, pageSize, activeOnly)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.Webhook), args.Int(1), args.Error(2)
}

func (m *mockWebhookRepo) GetActiveByEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*models.Webhook, error) {
	args := m.Called(ctx, tenantID, eventType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Webhook), args.Error(1)
}

func (m *mockWebhookRepo) CreateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error {
	args := m.Called(ctx, delivery)
	return args.Error(0)
}

func (m *mockWebhookRepo) ListDeliveries(ctx context.Context, webhookID uuid.UUID, page, pageSize int, status *string) ([]*models.WebhookDelivery, int, error) {
	args := m.Called(ctx, webhookID, page, pageSize, status)
	if args.Get(0) == nil {
		return nil, args.Int(1), args.Error(2)
	}
	return args.Get(0).([]*models.WebhookDelivery), args.Int(1), args.Error(2)
}

func (m *mockWebhookRepo) GetDeliveryByID(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.WebhookDelivery), args.Error(1)
}

func (m *mockWebhookRepo) GetDeliveryStats(ctx context.Context, webhookID uuid.UUID) (map[string]int, error) {
	args := m.Called(ctx, webhookID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int), args.Error(1)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newWebhookService(repo *mockWebhookRepo) *WebhookService {
	return NewWebhookService(repo)
}

func validWebhookRequest() *models.CreateWebhookRequest {
	return &models.CreateWebhookRequest{
		Name:   "Test Webhook",
		URL:    "https://example.com/hooks",
		Secret: "supersecretvalue-at-least-16chars",
		Events: []string{string(models.WebhookEventUserCreated)},
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateWebhook
// ---------------------------------------------------------------------------

func TestWebhook_Create_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	creatorID := uuid.New()
	req := validWebhookRequest()

	repo.On("Create", ctx, mock.AnythingOfType("*models.Webhook")).Return(nil)

	resp, err := svc.CreateWebhook(ctx, tenantID, req, &creatorID)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "Test Webhook", resp.Name)
	assert.Equal(t, req.URL, resp.URL)
	// Secret is returned only on creation
	assert.Equal(t, req.Secret, resp.Secret)
	assert.Equal(t, tenantID, resp.TenantID)
	repo.AssertExpectations(t)
}

func TestWebhook_Create_DefaultActiveStatus(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	req := validWebhookRequest()

	repo.On("Create", ctx, mock.AnythingOfType("*models.Webhook")).Return(nil)

	resp, err := svc.CreateWebhook(ctx, uuid.New(), req, nil)

	require.NoError(t, err)
	// Default active status is true when not specified
	assert.True(t, resp.IsActive)
}

func TestWebhook_Create_WithInactiveFlag(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	inactive := false
	req := validWebhookRequest()
	req.IsActive = &inactive

	repo.On("Create", ctx, mock.AnythingOfType("*models.Webhook")).Return(nil)

	resp, err := svc.CreateWebhook(ctx, uuid.New(), req, nil)

	require.NoError(t, err)
	assert.False(t, resp.IsActive)
}

func TestWebhook_Create_InvalidEvent_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	req := validWebhookRequest()
	req.Events = []string{"invalid.event.type"}

	resp, err := svc.CreateWebhook(ctx, uuid.New(), req, nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid event type")
}

func TestWebhook_Create_RepoError(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	req := validWebhookRequest()
	repo.On("Create", ctx, mock.AnythingOfType("*models.Webhook")).
		Return(errors.New("db error"))

	resp, err := svc.CreateWebhook(ctx, uuid.New(), req, nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

// ---------------------------------------------------------------------------
// Tests: UpdateWebhook
// ---------------------------------------------------------------------------

func TestWebhook_Update_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	whID := uuid.New()
	existing := &models.Webhook{
		ID:       whID,
		TenantID: tenantID,
		Name:     "Old Name",
		URL:      "https://old.example.com",
		IsActive: true,
	}

	newName := "New Name"
	req := &models.UpdateWebhookRequest{Name: &newName}

	repo.On("GetByID", ctx, whID).Return(existing, nil)
	repo.On("Update", ctx, mock.AnythingOfType("*models.Webhook")).Return(nil)

	resp, err := svc.UpdateWebhook(ctx, whID, tenantID, req)

	require.NoError(t, err)
	assert.Equal(t, "New Name", resp.Name)
	repo.AssertExpectations(t)
}

func TestWebhook_Update_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	whID := uuid.New()
	existing := &models.Webhook{ID: whID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, whID).Return(existing, nil)

	_, err := svc.UpdateWebhook(ctx, whID, uuid.New(), &models.UpdateWebhookRequest{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: DeleteWebhook
// ---------------------------------------------------------------------------

func TestWebhook_Delete_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	whID := uuid.New()

	repo.On("Delete", ctx, whID, tenantID).Return(nil)

	err := svc.DeleteWebhook(ctx, whID, tenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestWebhook_Delete_NotFound_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	whID := uuid.New()
	tenantID := uuid.New()

	repo.On("Delete", ctx, whID, tenantID).
		Return(errors.New("webhook not found"))

	err := svc.DeleteWebhook(ctx, whID, tenantID)

	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: ListWebhooks
// ---------------------------------------------------------------------------

func TestWebhook_List_ByTenant(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	webhooks := []*models.Webhook{
		{ID: uuid.New(), TenantID: tenantID, Name: "WH 1"},
		{ID: uuid.New(), TenantID: tenantID, Name: "WH 2"},
	}
	repo.On("List", ctx, tenantID, 1, 20, false).Return(webhooks, 2, nil)

	result, err := svc.ListWebhooks(ctx, tenantID, 1, 20, false)

	require.NoError(t, err)
	assert.Len(t, result.Webhooks, 2)
	assert.Equal(t, 2, result.Total)
	assert.Equal(t, 1, result.TotalPages)
	repo.AssertExpectations(t)
}

func TestWebhook_List_Paginated(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	repo.On("List", ctx, tenantID, 1, 5, false).Return([]*models.Webhook{}, 15, nil)

	result, err := svc.ListWebhooks(ctx, tenantID, 1, 5, false)

	require.NoError(t, err)
	assert.Equal(t, 15, result.Total)
	assert.Equal(t, 3, result.TotalPages) // ceil(15/5)
}

// ---------------------------------------------------------------------------
// Tests: TriggerEvent
// ---------------------------------------------------------------------------

func TestWebhook_TriggerEvent_NoSubscribers(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	event := &models.WebhookEvent{
		ID:        uuid.New().String(),
		Type:      models.WebhookEventUserCreated,
		Timestamp: time.Now(),
		TenantID:  tenantID,
		Data:      map[string]interface{}{"user_id": "test"},
	}

	// No webhooks subscribed to this event
	repo.On("GetActiveByEvent", ctx, tenantID, string(models.WebhookEventUserCreated)).
		Return([]*models.Webhook{}, nil)
	// Wildcard lookup (user.*)
	repo.On("GetActiveByEvent", ctx, tenantID, "user.*").
		Return([]*models.Webhook{}, nil)

	err := svc.TriggerEvent(ctx, event)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestWebhook_TriggerEvent_WithSubscriber_CreatesDelivery(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	wh := &models.Webhook{
		ID:         uuid.New(),
		TenantID:   tenantID,
		URL:        "https://example.com/hook",
		IsActive:   true,
		RetryCount: 3,
		SecretHash: "hash",
	}
	event := &models.WebhookEvent{
		ID:        uuid.New().String(),
		Type:      models.WebhookEventUserCreated,
		Timestamp: time.Now(),
		TenantID:  tenantID,
		Data:      map[string]interface{}{},
	}

	repo.On("GetActiveByEvent", ctx, tenantID, string(models.WebhookEventUserCreated)).
		Return([]*models.Webhook{wh}, nil)
	repo.On("GetActiveByEvent", ctx, tenantID, "user.*").
		Return([]*models.Webhook{}, nil)
	repo.On("CreateDelivery", ctx, mock.AnythingOfType("*models.WebhookDelivery")).Return(nil)

	err := svc.TriggerEvent(ctx, event)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: GetWebhook
// ---------------------------------------------------------------------------

func TestWebhook_Get_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	whID := uuid.New()
	existing := &models.Webhook{ID: whID, TenantID: tenantID, Name: "My Hook"}

	repo.On("GetByID", ctx, whID).Return(existing, nil)

	resp, err := svc.GetWebhook(ctx, whID, tenantID)

	require.NoError(t, err)
	assert.Equal(t, "My Hook", resp.Name)
	repo.AssertExpectations(t)
}

func TestWebhook_Get_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	whID := uuid.New()
	existing := &models.Webhook{ID: whID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, whID).Return(existing, nil)

	_, err := svc.GetWebhook(ctx, whID, uuid.New())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: GetDeliveryStats
// ---------------------------------------------------------------------------

func TestWebhook_GetDeliveryStats_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	whID := uuid.New()
	existing := &models.Webhook{ID: whID, TenantID: tenantID}
	stats := map[string]int{"success": 10, "failed": 2}

	repo.On("GetByID", ctx, whID).Return(existing, nil)
	repo.On("GetDeliveryStats", ctx, whID).Return(stats, nil)

	result, err := svc.GetDeliveryStats(ctx, whID, tenantID)

	require.NoError(t, err)
	assert.Equal(t, 10, result["success"])
	assert.Equal(t, 2, result["failed"])
	repo.AssertExpectations(t)
}

func TestWebhook_GetDeliveryStats_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	whID := uuid.New()
	existing := &models.Webhook{ID: whID, TenantID: uuid.New()}

	repo.On("GetByID", ctx, whID).Return(existing, nil)

	_, err := svc.GetDeliveryStats(ctx, whID, uuid.New())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: ListDeliveries
// ---------------------------------------------------------------------------

func TestWebhook_ListDeliveries_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	whID := uuid.New()
	existing := &models.Webhook{ID: whID, TenantID: tenantID}
	deliveries := []*models.WebhookDelivery{
		{ID: uuid.New(), WebhookID: whID, Status: models.WebhookDeliveryStatusSuccess},
	}

	repo.On("GetByID", ctx, whID).Return(existing, nil)
	repo.On("ListDeliveries", ctx, whID, 1, 20, (*string)(nil)).Return(deliveries, 1, nil)

	result, err := svc.ListDeliveries(ctx, whID, tenantID, 1, 20, nil)

	require.NoError(t, err)
	assert.Len(t, result.Deliveries, 1)
	assert.Equal(t, 1, result.Total)
	repo.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Tests: RetryDelivery
// ---------------------------------------------------------------------------

func TestWebhook_RetryDelivery_Success(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	tenantID := uuid.New()
	whID := uuid.New()
	deliveryID := uuid.New()

	wh := &models.Webhook{ID: whID, TenantID: tenantID}
	delivery := &models.WebhookDelivery{
		ID:        deliveryID,
		WebhookID: whID,
		Status:    models.WebhookDeliveryStatusFailed,
		Attempts:  3,
	}

	repo.On("GetDeliveryByID", ctx, deliveryID).Return(delivery, nil)
	repo.On("GetByID", ctx, whID).Return(wh, nil)
	repo.On("UpdateDelivery", ctx, mock.AnythingOfType("*models.WebhookDelivery")).Return(nil)

	err := svc.RetryDelivery(ctx, deliveryID, tenantID)

	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestWebhook_RetryDelivery_WrongTenant_Error(t *testing.T) {
	ctx := context.Background()
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	deliveryID := uuid.New()
	whID := uuid.New()
	delivery := &models.WebhookDelivery{ID: deliveryID, WebhookID: whID}
	wh := &models.Webhook{ID: whID, TenantID: uuid.New()}

	repo.On("GetDeliveryByID", ctx, deliveryID).Return(delivery, nil)
	repo.On("GetByID", ctx, whID).Return(wh, nil)

	err := svc.RetryDelivery(ctx, deliveryID, uuid.New())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Tests: generateSignature (internal, tested via observable side-effects)
// ---------------------------------------------------------------------------

func TestWebhook_GenerateSignature_Deterministic(t *testing.T) {
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	payload := []byte(`{"test":true}`)
	secretHash := "mysecretkey"

	sig1 := svc.generateSignature(payload, secretHash)
	sig2 := svc.generateSignature(payload, secretHash)

	assert.Equal(t, sig1, sig2, "signature must be deterministic for same payload and key")
	assert.True(t, len(sig1) > 0)
	assert.Equal(t, "sha256=", sig1[:7])
}

func TestWebhook_GenerateSignature_DifferentPayload(t *testing.T) {
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	sig1 := svc.generateSignature([]byte("payload1"), "secret")
	sig2 := svc.generateSignature([]byte("payload2"), "secret")

	assert.NotEqual(t, sig1, sig2)
}

// ---------------------------------------------------------------------------
// Tests: GetEventTypes
// ---------------------------------------------------------------------------

func TestWebhook_GetEventTypes(t *testing.T) {
	repo := new(mockWebhookRepo)
	svc := newWebhookService(repo)

	types := svc.GetEventTypes()

	assert.NotEmpty(t, types)
	// Spot-check a known event type is present
	found := false
	for _, et := range types {
		if et == models.WebhookEventUserCreated {
			found = true
			break
		}
	}
	assert.True(t, found, "user.created must be in event types")
}
