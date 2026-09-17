// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/shared/httpclient"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// webhookServiceWebhookRepo defines the webhook repository methods needed by WebhookService.
type webhookServiceWebhookRepo interface {
	GetPendingDeliveries(ctx context.Context, limit int) ([]*models.WebhookDelivery, error)
	MarkDeliveryProcessing(ctx context.Context, id uuid.UUID) error
	UpdateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error
	Create(ctx context.Context, webhook *models.Webhook) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Webhook, error)
	Update(ctx context.Context, webhook *models.Webhook) error
	Delete(ctx context.Context, id, tenantID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, activeOnly bool) ([]*models.Webhook, int, error)
	GetActiveByEvent(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*models.Webhook, error)
	CreateDelivery(ctx context.Context, delivery *models.WebhookDelivery) error
	ListDeliveries(ctx context.Context, webhookID uuid.UUID, page, pageSize int, status *string) ([]*models.WebhookDelivery, int, error)
	GetDeliveryByID(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error)
	GetDeliveryStats(ctx context.Context, webhookID uuid.UUID) (map[string]int, error)
}

// WebhookService handles webhook business logic
type WebhookService struct {
	webhookRepo webhookServiceWebhookRepo
	httpClient  *httpclient.ServiceClient
	eventChan   chan *webhookDeliveryTask
	workerCount int
	wg          sync.WaitGroup
	stopChan    chan struct{}
	stopOnce    sync.Once
	isRunning   bool
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
}

type webhookDeliveryTask struct {
	delivery *models.WebhookDelivery
	webhook  *models.Webhook
}

// NewWebhookService creates a new WebhookService
func NewWebhookService(webhookRepo webhookServiceWebhookRepo) *WebhookService {
	logger := zap.NewNop()
	client := httpclient.NewServiceClient(
		"iam",
		"", // No base URL - webhooks have dynamic URLs
		logger,
		httpclient.WithTimeout(30*time.Second),
		httpclient.WithMaxRetries(3),
	)
	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // context cancellation is handled via done channel
	return &WebhookService{
		webhookRepo: webhookRepo,
		httpClient:  client,
		eventChan:   make(chan *webhookDeliveryTask, 1000),
		workerCount: 5,
		stopChan:    make(chan struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start starts the webhook delivery workers
func (s *WebhookService) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return
	}

	s.isRunning = true
	for i := 0; i < s.workerCount; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	// Start retry worker
	s.wg.Add(1)
	go s.retryWorker()

	logger.Info("Webhook service started", zap.Int("worker_count", s.workerCount))
}

// Stop stops the webhook delivery workers
func (s *WebhookService) Stop() {
	s.mu.Lock()
	if !s.isRunning {
		s.mu.Unlock()
		return
	}

	s.stopOnce.Do(func() { close(s.stopChan) })
	s.isRunning = false
	s.mu.Unlock()

	// Wait for workers to drain remaining tasks before cancelling context
	s.wg.Wait()
	s.cancel()
	logger.Info("Webhook service stopped")
}

// worker processes webhook deliveries from the channel
func (s *WebhookService) worker(_ int) {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			// Drain remaining buffered tasks before exiting
			for {
				select {
				case task := <-s.eventChan:
					s.processDelivery(task)
				default:
					return
				}
			}
		case task := <-s.eventChan:
			s.processDelivery(task)
		}
	}
}

// retryWorker periodically checks for pending deliveries to retry
func (s *WebhookService) retryWorker() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.processPendingDeliveries()
		}
	}
}

// processPendingDeliveries processes pending deliveries from the database
func (s *WebhookService) processPendingDeliveries() {
	ctx := s.ctx

	deliveries, err := s.webhookRepo.GetPendingDeliveries(ctx, 100)
	if err != nil {
		logger.Error("Error getting pending deliveries", zap.Error(err))
		return
	}

	for _, delivery := range deliveries {
		// Mark as processing
		if err := s.webhookRepo.MarkDeliveryProcessing(ctx, delivery.ID); err != nil {
			continue
		}

		// Queue for processing
		select {
		case s.eventChan <- &webhookDeliveryTask{delivery: delivery, webhook: delivery.Webhook}:
		default:
			// Channel full, mark back as pending
			delivery.Status = models.WebhookDeliveryStatusPending
			_ = s.webhookRepo.UpdateDelivery(ctx, delivery)
		}
	}
}

// processDelivery processes a single webhook delivery
func (s *WebhookService) processDelivery(task *webhookDeliveryTask) {
	ctx := s.ctx
	delivery := task.delivery
	webhook := task.webhook

	delivery.Attempts++
	now := time.Now()
	delivery.LastAttemptAt = &now

	// Create HTTP request
	payloadBytes, err := json.Marshal(delivery.Payload)
	if err != nil {
		s.handleDeliveryError(ctx, delivery, fmt.Sprintf("Failed to marshal payload: %v", err))
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		s.handleDeliveryError(ctx, delivery, fmt.Sprintf("Failed to create request: %v", err))
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HexxLock-Webhook/1.0")
	req.Header.Set("X-Hexxlock-Event", delivery.EventType)
	req.Header.Set("X-Hexxlock-Delivery", delivery.ID.String())
	if delivery.EventID != nil {
		req.Header.Set("X-Hexxlock-Event-ID", *delivery.EventID)
	}

	// Add HMAC signature
	signature := s.generateSignature(payloadBytes, webhook.SecretHash)
	req.Header.Set("X-Hexxlock-Signature", signature)

	// Add custom headers
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	// Execute request using the raw HTTP client
	// Note: Timeout is already configured in the ServiceClient, but webhook-specific
	// timeouts would require creating a new client per webhook. For now, we use the
	// default 30s timeout configured during initialization.
	start := time.Now()
	resp, err := s.httpClient.HTTPClient.Do(req)
	duration := int(time.Since(start).Milliseconds())
	delivery.DurationMs = &duration

	if err != nil {
		s.handleDeliveryError(ctx, delivery, fmt.Sprintf("Request failed: %v", err))
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read response
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240)) // Limit to 10KB
	bodyStr := string(bodyBytes)
	delivery.ResponseStatus = &resp.StatusCode
	delivery.ResponseBody = &bodyStr

	// Capture response headers
	responseHeaders := make(map[string]string)
	for key := range resp.Header {
		responseHeaders[key] = resp.Header.Get(key)
	}
	delivery.ResponseHeaders = responseHeaders

	// Check if successful (2xx status)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		delivery.Status = models.WebhookDeliveryStatusSuccess
		completedAt := time.Now()
		delivery.CompletedAt = &completedAt
	} else {
		errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, bodyStr)
		if len(errMsg) > 500 {
			errMsg = errMsg[:500]
		}
		s.handleDeliveryError(ctx, delivery, errMsg)
		return
	}

	// Update delivery record
	if err := s.webhookRepo.UpdateDelivery(ctx, delivery); err != nil {
		logger.Error("Error updating successful delivery", zap.Error(err))
	}
}

// handleDeliveryError handles a failed delivery attempt
func (s *WebhookService) handleDeliveryError(ctx context.Context, delivery *models.WebhookDelivery, errMsg string) {
	delivery.ErrorMessage = &errMsg

	if delivery.Attempts >= delivery.MaxAttempts {
		// Max attempts reached, mark as failed
		delivery.Status = models.WebhookDeliveryStatusFailed
		completedAt := time.Now()
		delivery.CompletedAt = &completedAt
	} else {
		// Schedule retry with exponential backoff
		delivery.Status = models.WebhookDeliveryStatusPending
		backoff := time.Duration(1<<uint(delivery.Attempts-1)) * time.Minute //nolint:gosec // 1, 2, 4, 8... minutes; value is bounded by retry count config
		if backoff > 30*time.Minute {
			backoff = 30 * time.Minute
		}
		nextRetry := time.Now().Add(backoff)
		delivery.NextRetryAt = &nextRetry
	}

	if err := s.webhookRepo.UpdateDelivery(ctx, delivery); err != nil {
		logger.Error("Error updating failed delivery", zap.Error(err))
	}
}

// generateSignature generates HMAC-SHA256 signature for webhook payload
func (s *WebhookService) generateSignature(payload []byte, secretHash string) string {
	// Use the secret hash directly as the key (the stored value)
	h := hmac.New(sha256.New, []byte(secretHash))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// CreateWebhook creates a new webhook
func (s *WebhookService) CreateWebhook(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.CreateWebhookRequest,
	createdBy *uuid.UUID,
) (*models.WebhookCreatedResponse, error) {
	// Validate events
	validEvents := models.AllWebhookEventTypes()
	validEventMap := make(map[string]bool)
	for _, e := range validEvents {
		validEventMap[string(e)] = true
	}

	for _, event := range req.Events {
		if !validEventMap[event] && !strings.HasSuffix(event, ".*") {
			return nil, fmt.Errorf("invalid event type: %s", event)
		}
	}

	// Hash the secret for storage (we'll use bcrypt but also store for HMAC)
	// For HMAC we need the original secret, so we'll store a simple hash
	secretHash := sha256.Sum256([]byte(req.Secret))
	secretHashStr := hex.EncodeToString(secretHash[:])

	now := time.Now()
	webhook := &models.Webhook{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Name:           req.Name,
		Description:    req.Description,
		URL:            req.URL,
		SecretHash:     secretHashStr,
		Events:         req.Events,
		Headers:        req.Headers,
		IsActive:       true,
		RetryCount:     3,
		TimeoutSeconds: 30,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      createdBy,
	}

	if req.IsActive != nil {
		webhook.IsActive = *req.IsActive
	}
	if req.RetryCount != nil && *req.RetryCount >= 0 && *req.RetryCount <= 10 {
		webhook.RetryCount = *req.RetryCount
	}
	if req.TimeoutSeconds != nil && *req.TimeoutSeconds >= 5 && *req.TimeoutSeconds <= 60 {
		webhook.TimeoutSeconds = *req.TimeoutSeconds
	}
	if req.Headers == nil {
		webhook.Headers = make(map[string]string)
	}

	if err := s.webhookRepo.Create(ctx, webhook); err != nil {
		return nil, fmt.Errorf("failed to create webhook: %w", err)
	}

	response := webhook.ToResponse()
	return &models.WebhookCreatedResponse{
		WebhookResponse: *response,
		Secret:          req.Secret, // Return original secret only on creation
	}, nil
}

// GetWebhook gets a webhook by ID
func (s *WebhookService) GetWebhook(ctx context.Context, id, tenantID uuid.UUID) (*models.WebhookResponse, error) {
	webhook, err := s.webhookRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("GetWebhook: %w", err)
	}

	if webhook.TenantID != tenantID {
		return nil, fmt.Errorf("webhook not found")
	}

	return webhook.ToResponse(), nil
}

// UpdateWebhook updates a webhook
func (s *WebhookService) UpdateWebhook(
	ctx context.Context,
	id, tenantID uuid.UUID,
	req *models.UpdateWebhookRequest,
) (*models.WebhookResponse, error) {
	webhook, err := s.webhookRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("UpdateWebhook: %w", err)
	}

	if webhook.TenantID != tenantID {
		return nil, fmt.Errorf("webhook not found")
	}

	if req.Name != nil {
		webhook.Name = *req.Name
	}
	if req.Description != nil {
		webhook.Description = req.Description
	}
	if req.URL != nil {
		webhook.URL = *req.URL
	}
	if req.Secret != nil && len(*req.Secret) >= 16 {
		secretHash := sha256.Sum256([]byte(*req.Secret))
		webhook.SecretHash = hex.EncodeToString(secretHash[:])
	}
	if req.Events != nil {
		webhook.Events = req.Events
	}
	if req.Headers != nil {
		webhook.Headers = req.Headers
	}
	if req.IsActive != nil {
		webhook.IsActive = *req.IsActive
	}
	if req.RetryCount != nil && *req.RetryCount >= 0 && *req.RetryCount <= 10 {
		webhook.RetryCount = *req.RetryCount
	}
	if req.TimeoutSeconds != nil && *req.TimeoutSeconds >= 5 && *req.TimeoutSeconds <= 60 {
		webhook.TimeoutSeconds = *req.TimeoutSeconds
	}

	if err := s.webhookRepo.Update(ctx, webhook); err != nil {
		return nil, fmt.Errorf("failed to update webhook: %w", err)
	}

	return webhook.ToResponse(), nil
}

// DeleteWebhook deletes a webhook
func (s *WebhookService) DeleteWebhook(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.webhookRepo.Delete(ctx, id, tenantID)
}

// ListWebhooks lists webhooks for a tenant
func (s *WebhookService) ListWebhooks(ctx context.Context, tenantID uuid.UUID, page, pageSize int, activeOnly bool) (*models.WebhookListResponse, error) {
	webhooks, total, err := s.webhookRepo.List(ctx, tenantID, page, pageSize, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("ListWebhooks: %w", err)
	}

	responses := make([]*models.WebhookResponse, len(webhooks))
	for i, webhook := range webhooks {
		responses[i] = webhook.ToResponse()
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.WebhookListResponse{
		Webhooks:   responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// TestWebhook sends a test event to a webhook
func (s *WebhookService) TestWebhook(ctx context.Context, id, tenantID uuid.UUID, eventType string) (*models.WebhookTestResponse, error) {
	webhook, err := s.webhookRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("TestWebhook: %w", err)
	}

	if webhook.TenantID != tenantID {
		return nil, fmt.Errorf("webhook not found")
	}

	// Create test payload
	payload := map[string]interface{}{
		"id":        uuid.New().String(),
		"type":      eventType,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"tenant_id": tenantID.String(),
		"test":      true,
		"data": map[string]interface{}{
			"message": "This is a test webhook delivery from HexxLock IAM",
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal test payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create request: %v", err)
		return &models.WebhookTestResponse{
			Success:      false,
			ErrorMessage: &errMsg,
		}, nil
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HexxLock-Webhook/1.0")
	req.Header.Set("X-Hexxlock-Event", eventType)
	req.Header.Set("X-Hexxlock-Delivery", uuid.New().String())
	req.Header.Set("X-Hexxlock-Test", "true")

	// Add HMAC signature
	signature := s.generateSignature(payloadBytes, webhook.SecretHash)
	req.Header.Set("X-Hexxlock-Signature", signature)

	// Add custom headers
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	// Execute request using the resilient HTTP client
	start := time.Now()
	resp, err := s.httpClient.HTTPClient.Do(req)
	duration := int(time.Since(start).Milliseconds())

	if err != nil {
		errMsg := fmt.Sprintf("Request failed: %v", err)
		return &models.WebhookTestResponse{
			Success:      false,
			DurationMs:   duration,
			ErrorMessage: &errMsg,
		}, nil
	}
	defer resp.Body.Close() //nolint:errcheck

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
	bodyStr := string(bodyBytes)

	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	result := &models.WebhookTestResponse{
		Success:      success,
		StatusCode:   resp.StatusCode,
		ResponseBody: bodyStr,
		DurationMs:   duration,
	}

	if !success {
		errMsg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		result.ErrorMessage = &errMsg
	}

	return result, nil
}

// TriggerEvent triggers a webhook event for all subscribed webhooks
func (s *WebhookService) TriggerEvent(ctx context.Context, event *models.WebhookEvent) error {
	// Get all webhooks subscribed to this event
	webhooks, err := s.webhookRepo.GetActiveByEvent(ctx, event.TenantID, string(event.Type))
	if err != nil {
		return fmt.Errorf("failed to get webhooks: %w", err)
	}

	// Also check for wildcard subscriptions (e.g., "user.*")
	parts := strings.Split(string(event.Type), ".")
	if len(parts) == 2 {
		wildcardEvent := parts[0] + ".*"
		wildcardWebhooks, err := s.webhookRepo.GetActiveByEvent(ctx, event.TenantID, wildcardEvent)
		if err == nil {
			webhooks = append(webhooks, wildcardWebhooks...)
		}
	}

	// Create delivery records and queue for processing
	for _, webhook := range webhooks {
		payload := map[string]interface{}{
			"id":        event.ID,
			"type":      string(event.Type),
			"timestamp": event.Timestamp.UTC().Format(time.RFC3339),
			"tenant_id": event.TenantID.String(),
			"data":      event.Data,
		}

		if event.Actor != nil {
			payload["actor"] = event.Actor
		}

		delivery := &models.WebhookDelivery{
			ID:          uuid.New(),
			WebhookID:   webhook.ID,
			EventType:   string(event.Type),
			EventID:     &event.ID,
			Payload:     payload,
			Status:      models.WebhookDeliveryStatusPending,
			Attempts:    0,
			MaxAttempts: webhook.RetryCount,
			CreatedAt:   time.Now(),
		}

		if err := s.webhookRepo.CreateDelivery(ctx, delivery); err != nil {
			logger.Error("Error creating delivery for webhook", zap.String("webhook_id", webhook.ID.String()), zap.Error(err))
			continue
		}

		// Queue for immediate processing
		delivery.Webhook = webhook
		select {
		case s.eventChan <- &webhookDeliveryTask{delivery: delivery, webhook: webhook}:
		default:
			// Channel full, will be picked up by retry worker
		}
	}

	return nil
}

// ListDeliveries lists deliveries for a webhook
func (s *WebhookService) ListDeliveries(ctx context.Context, webhookID, tenantID uuid.UUID, page, pageSize int, status *string) (*models.WebhookDeliveryListResponse, error) {
	// Verify webhook belongs to tenant
	webhook, err := s.webhookRepo.GetByID(ctx, webhookID)
	if err != nil {
		return nil, fmt.Errorf("ListDeliveries: %w", err)
	}
	if webhook.TenantID != tenantID {
		return nil, fmt.Errorf("webhook not found")
	}

	deliveries, total, err := s.webhookRepo.ListDeliveries(ctx, webhookID, page, pageSize, status)
	if err != nil {
		return nil, fmt.Errorf("ListDeliveries: %w", err)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &models.WebhookDeliveryListResponse{
		Deliveries: deliveries,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetDelivery gets a delivery by ID
func (s *WebhookService) GetDelivery(ctx context.Context, id uuid.UUID) (*models.WebhookDelivery, error) {
	return s.webhookRepo.GetDeliveryByID(ctx, id)
}

// RetryDelivery retries a failed delivery
func (s *WebhookService) RetryDelivery(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	delivery, err := s.webhookRepo.GetDeliveryByID(ctx, id)
	if err != nil {
		return fmt.Errorf("RetryDelivery: %w", err)
	}

	// Verify the webhook belongs to the tenant
	webhook, err := s.webhookRepo.GetByID(ctx, delivery.WebhookID)
	if err != nil {
		return fmt.Errorf("RetryDelivery: %w", err)
	}
	if webhook.TenantID != tenantID {
		return fmt.Errorf("delivery not found")
	}

	// Reset delivery for retry
	delivery.Status = models.WebhookDeliveryStatusPending
	delivery.NextRetryAt = nil
	delivery.Attempts = 0
	delivery.ErrorMessage = nil
	delivery.CompletedAt = nil

	if err := s.webhookRepo.UpdateDelivery(ctx, delivery); err != nil {
		return fmt.Errorf("failed to update delivery: %w", err)
	}

	// Queue for immediate processing
	delivery.Webhook = webhook
	select {
	case s.eventChan <- &webhookDeliveryTask{delivery: delivery, webhook: webhook}:
	default:
		// Will be picked up by retry worker
	}

	return nil
}

// GetEventTypes returns all available webhook event types
func (s *WebhookService) GetEventTypes() []models.WebhookEventType {
	return models.AllWebhookEventTypes()
}

// GetDeliveryStats gets delivery statistics for a webhook
func (s *WebhookService) GetDeliveryStats(ctx context.Context, webhookID, tenantID uuid.UUID) (map[string]int, error) {
	// Verify webhook belongs to tenant
	webhook, err := s.webhookRepo.GetByID(ctx, webhookID)
	if err != nil {
		return nil, fmt.Errorf("GetDeliveryStats: %w", err)
	}
	if webhook.TenantID != tenantID {
		return nil, fmt.Errorf("webhook not found")
	}

	return s.webhookRepo.GetDeliveryStats(ctx, webhookID)
}
