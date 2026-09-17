// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// maxResponseBodySize limits webhook response reads to 64KB
const (
	maxResponseBodySize = 64 * 1024
	webhookMethodPOST   = "POST"
	webhookMethodGET    = "GET"
)

// ---- In-memory circuit breaker (per-webhook) ----

// webhookCircuitBreakerState tracks the state of a per-webhook circuit breaker
type webhookCircuitBreakerState int

const (
	cbStateClosed webhookCircuitBreakerState = iota
	cbStateOpen
	cbStateHalfOpen
)

// webhookCircuitBreaker is a simple in-memory circuit breaker
type webhookCircuitBreaker struct {
	mu              sync.Mutex
	state           webhookCircuitBreakerState
	failureCount    int
	threshold       int
	timeoutDuration time.Duration
	lastFailure     time.Time
}

func newWebhookCircuitBreaker(threshold int, timeoutSec int) *webhookCircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &webhookCircuitBreaker{
		state:           cbStateClosed,
		threshold:       threshold,
		timeoutDuration: time.Duration(timeoutSec) * time.Second,
	}
}

func (cb *webhookCircuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case cbStateClosed:
		return true
	case cbStateOpen:
		if time.Since(cb.lastFailure) >= cb.timeoutDuration {
			cb.state = cbStateHalfOpen
			return true
		}
		return false
	case cbStateHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *webhookCircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case cbStateClosed:
		cb.failureCount = 0
	case cbStateHalfOpen:
		cb.state = cbStateClosed
		cb.failureCount = 0
	}
}

func (cb *webhookCircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailure = time.Now()

	switch cb.state {
	case cbStateClosed:
		cb.failureCount++
		if cb.failureCount >= cb.threshold {
			cb.state = cbStateOpen
		}
	case cbStateHalfOpen:
		cb.state = cbStateOpen
		cb.failureCount = cb.threshold
	}
}

func (cb *webhookCircuitBreaker) getState() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbStateClosed:
		return "closed"
	case cbStateOpen:
		return "open"
	case cbStateHalfOpen:
		return "half-open"
	default:
		return routingDeviceUnknown
	}
}

// ---- RoutingWebhookService ----

// RoutingWebhookService handles dynamic routing webhook business logic
type RoutingWebhookService struct {
	repo              *repositories.RoutingWebhookRepository
	encryptionService *crypto.EncryptionService

	// Per-webhook circuit breakers, keyed by webhook UUID string
	circuitBreakers sync.Map
}

// NewRoutingWebhookService creates a new RoutingWebhookService
func NewRoutingWebhookService(repo *repositories.RoutingWebhookRepository) *RoutingWebhookService {
	return &RoutingWebhookService{
		repo: repo,
	}
}

// SetEncryptionService sets the encryption service for encrypting auth secrets
func (s *RoutingWebhookService) SetEncryptionService(enc *crypto.EncryptionService) {
	s.encryptionService = enc
}

// getCircuitBreaker gets or creates a circuit breaker for a webhook
func (s *RoutingWebhookService) getCircuitBreaker(webhook *models.RoutingWebhook) *webhookCircuitBreaker {
	key := webhook.ID.String()
	if v, ok := s.circuitBreakers.Load(key); ok {
		return v.(*webhookCircuitBreaker)
	}
	cb := newWebhookCircuitBreaker(webhook.CBThreshold, webhook.CBTimeoutSec)
	actual, _ := s.circuitBreakers.LoadOrStore(key, cb)
	return actual.(*webhookCircuitBreaker)
}

// ---- CRUD operations ----

// CreateWebhook creates a new routing webhook
func (s *RoutingWebhookService) CreateWebhook(ctx context.Context, tenantID uuid.UUID, req *models.CreateRoutingWebhookRequest, createdBy *uuid.UUID) (*models.RoutingWebhook, error) {
	if err := validateWebhookURL(ctx, req.URL); err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}
	method, authType, fallbackAction, err := validateCreateWebhookRequest(req)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	webhook := &models.RoutingWebhook{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Name:               req.Name,
		Description:        req.Description,
		URL:                req.URL,
		Method:             method,
		AuthType:           authType,
		AuthUsername:       req.AuthUsername,
		TimeoutMs:          3000,
		RetryCount:         1,
		CBEnabled:          true,
		CBThreshold:        5,
		CBTimeoutSec:       30,
		FallbackAction:     fallbackAction,
		FallbackProviderID: req.FallbackProviderID,
		IsEnabled:          true,
		Priority:           100,
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedBy:          createdBy,
	}
	applyWebhookOptionalFields(webhook, req.TimeoutMs, req.RetryCount, req.CBEnabled, req.CBThreshold, req.CBTimeoutSec, req.IsEnabled, req.Priority)

	if req.AuthSecret != nil && *req.AuthSecret != "" {
		encrypted, err := s.encryptSecret(*req.AuthSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt auth_secret: %w", err)
		}
		webhook.AuthSecret = &encrypted
	}

	if err := s.repo.Create(ctx, webhook); err != nil {
		return nil, fmt.Errorf("failed to create routing webhook: %w", err)
	}
	webhook.AuthSecret = nil
	return webhook, nil
}

// validateCreateWebhookRequest validates and returns derived fields from a create request.
func validateCreateWebhookRequest(req *models.CreateRoutingWebhookRequest) (method string, authType models.RoutingWebhookAuthType, fallbackAction string, err error) {
	method = webhookMethodPOST
	if req.Method != "" {
		method = strings.ToUpper(req.Method)
	}
	if method != webhookMethodPOST && method != webhookMethodGET {
		return "", "", "", fmt.Errorf("invalid method: must be POST or GET")
	}

	authType = models.RoutingWebhookAuthBearer
	if req.AuthType != "" {
		authType = models.RoutingWebhookAuthType(req.AuthType)
	}
	if !isValidWebhookAuthType(authType) {
		return "", "", "", fmt.Errorf("invalid auth_type: must be none, bearer, basic, or hmac")
	}
	if authType != models.RoutingWebhookAuthNone && (req.AuthSecret == nil || *req.AuthSecret == "") {
		return "", "", "", fmt.Errorf("auth_secret is required for auth_type %s", authType)
	}
	if authType == models.RoutingWebhookAuthBasic && (req.AuthUsername == nil || *req.AuthUsername == "") {
		return "", "", "", fmt.Errorf("auth_username is required for basic auth")
	}

	fallbackAction = "allow"
	if req.FallbackAction != "" {
		fallbackAction = req.FallbackAction
	}
	if err := validateFallbackAction(fallbackAction, req.FallbackProviderID); err != nil {
		return "", "", "", err
	}
	return method, authType, fallbackAction, nil
}

func isValidWebhookAuthType(at models.RoutingWebhookAuthType) bool {
	return at == models.RoutingWebhookAuthNone ||
		at == models.RoutingWebhookAuthBearer ||
		at == models.RoutingWebhookAuthBasic ||
		at == models.RoutingWebhookAuthHMAC
}

func validateFallbackAction(fallbackAction string, fallbackProviderID *uuid.UUID) error {
	validFallback := map[string]bool{"allow": true, "deny": true, "redirect": true, "step_up_mfa": true}
	if !validFallback[fallbackAction] {
		return fmt.Errorf("invalid fallback_action: must be allow, deny, redirect, or step_up_mfa")
	}
	if fallbackAction == "redirect" && fallbackProviderID == nil {
		return fmt.Errorf("fallback_provider_id is required when fallback_action is redirect")
	}
	return nil
}

func applyWebhookOptionalFields(webhook *models.RoutingWebhook, timeoutMs, retryCount *int, cbEnabled *bool, cbThreshold, cbTimeoutSec *int, isEnabled *bool, priority *int) {
	if timeoutMs != nil && *timeoutMs >= 100 && *timeoutMs <= 30000 {
		webhook.TimeoutMs = *timeoutMs
	}
	if retryCount != nil && *retryCount >= 0 && *retryCount <= 3 {
		webhook.RetryCount = *retryCount
	}
	if cbEnabled != nil {
		webhook.CBEnabled = *cbEnabled
	}
	if cbThreshold != nil && *cbThreshold >= 1 {
		webhook.CBThreshold = *cbThreshold
	}
	if cbTimeoutSec != nil && *cbTimeoutSec >= 1 {
		webhook.CBTimeoutSec = *cbTimeoutSec
	}
	if isEnabled != nil {
		webhook.IsEnabled = *isEnabled
	}
	if priority != nil {
		webhook.Priority = *priority
	}
}

// GetWebhook retrieves a routing webhook by ID (tenant-scoped)
func (s *RoutingWebhookService) GetWebhook(ctx context.Context, id, tenantID uuid.UUID) (*models.RoutingWebhook, error) {
	webhook, err := s.repo.GetByIDAndTenant(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	// Clear secret from response
	webhook.AuthSecret = nil
	return webhook, nil
}

// UpdateWebhook updates a routing webhook
func (s *RoutingWebhookService) UpdateWebhook(ctx context.Context, id, tenantID uuid.UUID, req *models.UpdateRoutingWebhookRequest) (*models.RoutingWebhook, error) {
	webhook, err := s.repo.GetByIDAndTenant(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.applyUpdateWebhookRequest(ctx, webhook, req); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, webhook); err != nil {
		return nil, fmt.Errorf("failed to update routing webhook: %w", err)
	}
	webhook.AuthSecret = nil
	return webhook, nil
}

// applyUpdateWebhookRequest applies the update request fields to the webhook.
func (s *RoutingWebhookService) applyUpdateWebhookRequest(ctx context.Context, webhook *models.RoutingWebhook, req *models.UpdateRoutingWebhookRequest) error {
	if req.Name != nil {
		webhook.Name = *req.Name
	}
	if req.Description != nil {
		webhook.Description = req.Description
	}
	if req.URL != nil {
		if err := validateWebhookURL(ctx, *req.URL); err != nil {
			return fmt.Errorf("invalid webhook URL: %w", err)
		}
		webhook.URL = *req.URL
	}
	if req.Method != nil {
		method := strings.ToUpper(*req.Method)
		if method != webhookMethodPOST && method != webhookMethodGET {
			return fmt.Errorf("invalid method: must be POST or GET")
		}
		webhook.Method = method
	}
	if req.AuthType != nil {
		at := models.RoutingWebhookAuthType(*req.AuthType)
		if !isValidWebhookAuthType(at) {
			return fmt.Errorf("invalid auth_type")
		}
		webhook.AuthType = at
	}
	if req.AuthUsername != nil {
		webhook.AuthUsername = req.AuthUsername
	}
	if req.AuthSecret != nil && *req.AuthSecret != "" {
		encrypted, err := s.encryptSecret(*req.AuthSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt auth_secret: %w", err)
		}
		webhook.AuthSecret = &encrypted
	}
	applyWebhookOptionalFields(webhook, req.TimeoutMs, req.RetryCount, req.CBEnabled, req.CBThreshold, req.CBTimeoutSec, req.IsEnabled, req.Priority)
	if req.FallbackAction != nil {
		if err := validateFallbackAction(*req.FallbackAction, webhook.FallbackProviderID); err != nil {
			return fmt.Errorf("invalid fallback_action")
		}
		webhook.FallbackAction = *req.FallbackAction
	}
	if req.FallbackProviderID != nil {
		webhook.FallbackProviderID = req.FallbackProviderID
	}
	return nil
}

// DeleteWebhook deletes a routing webhook
func (s *RoutingWebhookService) DeleteWebhook(ctx context.Context, id, tenantID uuid.UUID) error {
	if err := s.repo.Delete(ctx, id, tenantID); err != nil {
		return err
	}
	// Clean up circuit breaker
	s.circuitBreakers.Delete(id.String())
	return nil
}

// ListWebhooks lists routing webhooks for a tenant
func (s *RoutingWebhookService) ListWebhooks(ctx context.Context, tenantID uuid.UUID, page, pageSize int) (*models.RoutingWebhookListResponse, error) {
	webhooks, total, err := s.repo.List(ctx, tenantID, page, pageSize)
	if err != nil {
		return nil, err
	}

	// Clear secrets from all webhooks
	for _, w := range webhooks {
		w.AuthSecret = nil
	}

	totalPages := (total + pageSize - 1) / pageSize
	return &models.RoutingWebhookListResponse{
		Webhooks:   webhooks,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ListLogs lists execution logs for a webhook
func (s *RoutingWebhookService) ListLogs(ctx context.Context, webhookID, tenantID uuid.UUID, page, pageSize int) (*models.RoutingWebhookLogListResponse, error) {
	// Verify the webhook belongs to the tenant
	_, err := s.repo.GetByIDAndTenant(ctx, webhookID, tenantID)
	if err != nil {
		return nil, err
	}

	logs, total, err := s.repo.ListLogs(ctx, webhookID, page, pageSize)
	if err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	return &models.RoutingWebhookLogListResponse{
		Logs:       logs,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ---- Webhook evaluation (called during HRD) ----

// RoutingEvaluationContext provides context for the routing decision
type RoutingEvaluationContext struct {
	TenantID      uuid.UUID
	Email         string
	EmailDomain   string
	DeviceType    string
	NetworkZone   string
	ApplicationID string
	ClientIP      string
	UserAgent     string
	RiskLevel     string
	Custom        map[string]interface{}
}

// RoutingEvaluationResult represents the result of webhook-based routing
type RoutingEvaluationResult struct {
	Action     models.RoutingWebhookAction `json:"action"`
	ProviderID *uuid.UUID                  `json:"provider_id,omitempty"`
	Reason     string                      `json:"reason,omitempty"`
	Metadata   map[string]interface{}      `json:"metadata,omitempty"`
	WebhookID  uuid.UUID                   `json:"webhook_id"`
}

// EvaluateWebhooks calls enabled webhooks for a tenant in priority order (first-match-wins)
func (s *RoutingWebhookService) EvaluateWebhooks(ctx context.Context, evalCtx *RoutingEvaluationContext) (*RoutingEvaluationResult, error) {
	webhooks, err := s.repo.GetEnabled(ctx, evalCtx.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled webhooks: %w", err)
	}

	if len(webhooks) == 0 {
		return nil, nil // no webhooks configured
	}

	for _, webhook := range webhooks {
		result, err := s.evaluateSingleWebhook(ctx, webhook, evalCtx)
		if err != nil {
			logger.Warn("Routing webhook evaluation failed, trying next",
				zap.String("webhook_id", webhook.ID.String()),
				zap.String("webhook_name", webhook.Name),
				zap.Error(err),
			)
			continue
		}

		if result == nil {
			// Webhook returned "pass" -- continue to next
			continue
		}

		return result, nil
	}

	// All webhooks failed or passed
	return nil, nil
}

// evaluateSingleWebhook evaluates a single webhook (with circuit breaker, retry, fallback)
func (s *RoutingWebhookService) evaluateSingleWebhook(ctx context.Context, webhook *models.RoutingWebhook, evalCtx *RoutingEvaluationContext) (*RoutingEvaluationResult, error) {
	// Check circuit breaker
	if webhook.CBEnabled {
		cb := s.getCircuitBreaker(webhook)
		if !cb.allow() {
			logger.Debug("Circuit breaker open for routing webhook",
				zap.String("webhook_id", webhook.ID.String()),
				zap.String("state", cb.getState()),
			)
			return s.applyFallback(ctx, webhook, "circuit breaker open")
		}
	}

	// Build request payload
	reqPayload := s.buildRequestPayload(evalCtx)

	// Execute webhook with retries
	var lastErr error
	for attempt := 0; attempt <= webhook.RetryCount; attempt++ {
		resp, duration, err := s.callWebhook(ctx, webhook, reqPayload)

		if err == nil && resp != nil {
			return s.handleWebhookSuccess(webhook, reqPayload, resp, duration)
		}

		lastErr = err

		// Record failure in circuit breaker
		if webhook.CBEnabled {
			s.getCircuitBreaker(webhook).recordFailure()
		}

		// Don't retry on context cancellation
		if ctx.Err() != nil {
			break
		}

		// Brief backoff before retry
		if attempt < webhook.RetryCount {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
		}
	}

	// All attempts failed -- log and apply fallback
	errMsg := "unknown error"
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	go s.logWebhookCall(webhook, reqPayload, nil, 0, &errMsg, true) //nolint:gosec // goroutine must outlive request context

	return s.applyFallback(ctx, webhook, errMsg)
}

// callWebhook executes a single HTTP request to the webhook endpoint
func (s *RoutingWebhookService) callWebhook(ctx context.Context, webhook *models.RoutingWebhook, reqPayload *models.RoutingWebhookRequest) (*models.RoutingWebhookResponse, int, error) {
	// Serialize request body
	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(webhook.TimeoutMs)*time.Millisecond)
	defer cancel()

	var httpReq *http.Request
	if webhook.Method == webhookMethodGET {
		httpReq, err = http.NewRequestWithContext(timeoutCtx, webhookMethodGET, webhook.URL, nil)
	} else {
		httpReq, err = http.NewRequestWithContext(timeoutCtx, webhookMethodPOST, webhook.URL, bytes.NewReader(bodyBytes))
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set common headers
	httpReq.Header.Set("User-Agent", "HexxLock-RoutingWebhook/1.0")
	httpReq.Header.Set("X-Webhook-Request-ID", reqPayload.RequestID)

	// Add authentication
	if err := s.addAuthHeaders(httpReq, webhook, bodyBytes); err != nil {
		return nil, 0, fmt.Errorf("failed to add auth headers: %w", err)
	}

	// Execute the request
	client := &http.Client{
		Timeout: time.Duration(webhook.TimeoutMs) * time.Millisecond,
		// Prevent following redirects to external URLs
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	durationMs := int(time.Since(start).Milliseconds())

	if err != nil {
		return nil, durationMs, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read response body (limited to 64KB)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, durationMs, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, durationMs, fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, truncateString(string(respBody), 500))
	}

	// Parse response
	var webhookResp models.RoutingWebhookResponse
	if err := json.Unmarshal(respBody, &webhookResp); err != nil {
		return nil, durationMs, fmt.Errorf("failed to parse webhook response: %w", err)
	}

	// Validate action
	if !models.IsValidRoutingWebhookAction(string(webhookResp.Action)) {
		return nil, durationMs, fmt.Errorf("invalid action in webhook response: %s", webhookResp.Action)
	}

	return &webhookResp, durationMs, nil
}

// addAuthHeaders adds authentication headers based on webhook config
func (s *RoutingWebhookService) addAuthHeaders(req *http.Request, webhook *models.RoutingWebhook, bodyBytes []byte) error {
	if webhook.AuthType == models.RoutingWebhookAuthNone {
		return nil
	}

	// Decrypt the stored secret
	secret, err := s.decryptSecret(webhook.AuthSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt auth secret: %w", err)
	}

	switch webhook.AuthType {
	case models.RoutingWebhookAuthBearer:
		req.Header.Set("Authorization", "Bearer "+secret)

	case models.RoutingWebhookAuthBasic:
		username := ""
		if webhook.AuthUsername != nil {
			username = *webhook.AuthUsername
		}
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + secret))
		req.Header.Set("Authorization", "Basic "+auth)

	case models.RoutingWebhookAuthHMAC:
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(bodyBytes)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Webhook-Signature", "sha256="+signature)
	}

	return nil
}

// buildRequestPayload creates the webhook request payload from evaluation context
func (s *RoutingWebhookService) buildRequestPayload(evalCtx *RoutingEvaluationContext) *models.RoutingWebhookRequest {
	return &models.RoutingWebhookRequest{
		TenantID:      evalCtx.TenantID.String(),
		Email:         evalCtx.Email,
		EmailDomain:   evalCtx.EmailDomain,
		DeviceType:    evalCtx.DeviceType,
		NetworkZone:   evalCtx.NetworkZone,
		ApplicationID: evalCtx.ApplicationID,
		ClientIP:      evalCtx.ClientIP,
		UserAgent:     evalCtx.UserAgent,
		RiskLevel:     evalCtx.RiskLevel,
		Custom:        evalCtx.Custom,
		RequestID:     uuid.New().String(),
		Timestamp:     time.Now().UTC(),
	}
}

// applyFallback returns the fallback action for a webhook
func (s *RoutingWebhookService) applyFallback(_ context.Context, webhook *models.RoutingWebhook, reason string) (*RoutingEvaluationResult, error) {
	action := models.RoutingWebhookAction(webhook.FallbackAction)

	result := &RoutingEvaluationResult{
		Action:     action,
		Reason:     fmt.Sprintf("fallback: %s", reason),
		ProviderID: webhook.FallbackProviderID,
		WebhookID:  webhook.ID,
	}

	logger.Info("Routing webhook using fallback",
		zap.String("webhook_id", webhook.ID.String()),
		zap.String("fallback_action", webhook.FallbackAction),
		zap.String("reason", reason),
	)

	return result, nil
}

// logWebhookCall asynchronously logs a webhook execution
func (s *RoutingWebhookService) logWebhookCall(webhook *models.RoutingWebhook, reqPayload *models.RoutingWebhookRequest, resp *models.RoutingWebhookResponse, durationMs int, errMsg *string, usedFallback bool) {
	if s.repo == nil {
		return // no repository available (e.g., in tests)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reqBodyBytes, _ := json.Marshal(reqPayload)
	// Truncate request body for storage
	if len(reqBodyBytes) > maxResponseBodySize {
		reqBodyBytes = reqBodyBytes[:maxResponseBodySize]
	}

	logEntry := &models.RoutingWebhookLog{
		ID:           uuid.New(),
		TenantID:     webhook.TenantID,
		WebhookID:    webhook.ID,
		RequestURL:   webhook.URL,
		RequestBody:  reqBodyBytes,
		UsedFallback: usedFallback,
		CreatedAt:    time.Now(),
	}

	if durationMs > 0 {
		logEntry.ResponseMs = &durationMs
	}

	if errMsg != nil {
		truncated := truncateString(*errMsg, 2000)
		logEntry.ErrorMessage = &truncated
	}

	populateLogEntryResult(logEntry, webhook, resp, usedFallback)

	if err := s.repo.CreateLog(ctx, logEntry); err != nil {
		logger.Error("Failed to create routing webhook log",
			zap.String("webhook_id", webhook.ID.String()),
			zap.Error(err),
		)
	}
}

// TestWebhook sends a test request to a webhook and returns the result
func (s *RoutingWebhookService) TestWebhook(ctx context.Context, id, tenantID uuid.UUID, testReq *models.RoutingWebhookTestRequest) (*models.RoutingWebhookTestResponse, error) {
	webhook, err := s.repo.GetByIDAndTenant(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}

	evalCtx := &RoutingEvaluationContext{
		TenantID:      tenantID,
		Email:         testReq.Email,
		EmailDomain:   testReq.EmailDomain,
		DeviceType:    testReq.DeviceType,
		NetworkZone:   testReq.NetworkZone,
		ApplicationID: testReq.ApplicationID,
		ClientIP:      testReq.ClientIP,
		UserAgent:     testReq.UserAgent,
		RiskLevel:     testReq.RiskLevel,
		Custom:        testReq.Custom,
	}

	reqPayload := s.buildRequestPayload(evalCtx)
	resp, durationMs, err := s.callWebhook(ctx, webhook, reqPayload)
	if err != nil {
		errMsg := err.Error()
		return &models.RoutingWebhookTestResponse{ //nolint:nilerr // intentional: webhook call errors are returned in the response body, not as Go errors
			Success:      false,
			DurationMs:   durationMs,
			ErrorMessage: &errMsg,
		}, nil
	}

	return &models.RoutingWebhookTestResponse{
		Success:      true,
		StatusCode:   200,
		ResponseBody: resp,
		DurationMs:   durationMs,
	}, nil
}

// ---- Encryption helpers ----

func (s *RoutingWebhookService) encryptSecret(plaintext string) (string, error) {
	if s.encryptionService == nil {
		// No encryption available -- store as-is (development mode)
		return plaintext, nil
	}
	return s.encryptionService.Encrypt(plaintext)
}

func (s *RoutingWebhookService) decryptSecret(ciphertext *string) (string, error) {
	if ciphertext == nil || *ciphertext == "" {
		return "", nil
	}
	if s.encryptionService == nil {
		return *ciphertext, nil
	}
	return s.encryptionService.Decrypt(*ciphertext)
}

// ---- SSRF protection ----

// validateWebhookURL validates a webhook URL to prevent SSRF attacks
func validateWebhookURL(ctx context.Context, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTPS and HTTP
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("URL must use http or https scheme")
	}

	// Extract hostname
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL must have a hostname")
	}

	// Reject localhost variants
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "ip6-localhost" || lower == "ip6-loopback" {
		return fmt.Errorf("localhost URLs are not allowed")
	}

	// Check for private IP ranges
	ip := net.ParseIP(hostname)
	if ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("private IP addresses are not allowed")
		}
	}

	// Try DNS resolution to catch hostnames that resolve to private IPs
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err == nil {
		for _, addr := range addrs {
			if isPrivateIP(addr.IP) {
				return fmt.Errorf("hostname resolves to a private IP address")
			}
		}
	}

	return nil
}

// isPrivateIP checks if an IP is in a private/reserved range
func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")}, // link-local
		{net.ParseIP("0.0.0.0"), net.ParseIP("0.255.255.255")},
	}

	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6 loopback
		if ip.Equal(net.IPv6loopback) {
			return true
		}
		// IPv6 link-local
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		return false
	}

	for _, r := range privateRanges {
		start := r.start.To4()
		end := r.end.To4()
		if start == nil || end == nil {
			continue
		}
		if bytes.Compare(ip4, start) >= 0 && bytes.Compare(ip4, end) <= 0 {
			return true
		}
	}

	return false
}

// truncateString truncates a string to maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// populateLogEntryResult fills the action, response body, and provider ID fields of a log entry.
func populateLogEntryResult(logEntry *models.RoutingWebhookLog, webhook *models.RoutingWebhook, resp *models.RoutingWebhookResponse, usedFallback bool) {
	if resp != nil {
		action := string(resp.Action)
		logEntry.ActionTaken = &action
		respBodyBytes, _ := json.Marshal(resp)
		if len(respBodyBytes) > maxResponseBodySize {
			respBodyBytes = respBodyBytes[:maxResponseBodySize]
		}
		logEntry.ResponseBody = respBodyBytes
		if resp.ProviderID != nil {
			if provID, err := uuid.Parse(*resp.ProviderID); err == nil {
				logEntry.ProviderID = &provID
			}
		}
		return
	}
	if usedFallback {
		action := webhook.FallbackAction
		logEntry.ActionTaken = &action
		logEntry.ProviderID = webhook.FallbackProviderID
	}
}

// handleWebhookSuccess processes a successful webhook response: records the circuit-breaker
// success, logs the call asynchronously, and builds the evaluation result.
func (s *RoutingWebhookService) handleWebhookSuccess(webhook *models.RoutingWebhook, reqPayload *models.RoutingWebhookRequest, resp *models.RoutingWebhookResponse, durationMs int) (*RoutingEvaluationResult, error) {
	if webhook.CBEnabled {
		s.getCircuitBreaker(webhook).recordSuccess()
	}
	go s.logWebhookCall(webhook, reqPayload, resp, durationMs, nil, false) //nolint:gosec // goroutine must outlive request context

	if resp.Action == models.RoutingWebhookActionPass {
		return nil, nil
	}

	result := &RoutingEvaluationResult{
		Action:    resp.Action,
		Reason:    resp.Reason,
		Metadata:  resp.Metadata,
		WebhookID: webhook.ID,
	}
	if resp.ProviderID != nil {
		if provID, parseErr := uuid.Parse(*resp.ProviderID); parseErr == nil {
			result.ProviderID = &provID
		}
	}
	return result, nil
}
