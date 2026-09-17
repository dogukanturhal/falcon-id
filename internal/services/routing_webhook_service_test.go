// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ---- SSRF validation tests ----

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid HTTPS URL",
			url:     "https://api.example.com/webhook",
			wantErr: false,
		},
		{
			name:    "valid HTTP URL",
			url:     "http://api.example.com/webhook",
			wantErr: false,
		},
		{
			name:    "reject localhost",
			url:     "http://localhost:8080/webhook",
			wantErr: true,
			errMsg:  "localhost",
		},
		{
			name:    "reject localhost uppercase",
			url:     "http://LOCALHOST:8080/webhook",
			wantErr: true,
			errMsg:  "localhost",
		},
		{
			name:    "reject 127.0.0.1",
			url:     "http://127.0.0.1/webhook",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject 10.x.x.x",
			url:     "http://10.0.0.1/webhook",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject 172.16.x.x",
			url:     "http://172.16.0.1/webhook",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject 192.168.x.x",
			url:     "http://192.168.1.1/webhook",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject 0.0.0.0",
			url:     "http://0.0.0.0/webhook",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject FTP scheme",
			url:     "ftp://example.com/webhook",
			wantErr: true,
			errMsg:  "http or https",
		},
		{
			name:    "reject empty hostname",
			url:     "http:///webhook",
			wantErr: true,
			errMsg:  "hostname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(context.Background(), tt.url)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errMsg))
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---- Circuit breaker tests ----

func TestWebhookCircuitBreaker_ClosedToOpen(t *testing.T) {
	cb := newWebhookCircuitBreaker(3, 1)

	// Closed state: should allow requests
	assert.True(t, cb.allow())
	assert.Equal(t, "closed", cb.getState())

	// Record failures below threshold
	cb.recordFailure()
	cb.recordFailure()
	assert.True(t, cb.allow())
	assert.Equal(t, "closed", cb.getState())

	// Third failure triggers open
	cb.recordFailure()
	assert.False(t, cb.allow())
	assert.Equal(t, "open", cb.getState())
}

func TestWebhookCircuitBreaker_OpenToHalfOpen(t *testing.T) {
	cb := newWebhookCircuitBreaker(1, 1) // threshold=1, timeout=1s

	// Trip the breaker
	cb.recordFailure()
	assert.False(t, cb.allow())
	assert.Equal(t, "open", cb.getState())

	// Wait for timeout to expire
	time.Sleep(1100 * time.Millisecond)

	// Should transition to half-open
	assert.True(t, cb.allow())
	assert.Equal(t, "half-open", cb.getState())
}

func TestWebhookCircuitBreaker_HalfOpenToClosedOnSuccess(t *testing.T) {
	cb := newWebhookCircuitBreaker(1, 1)

	// Trip to open
	cb.recordFailure()
	assert.Equal(t, "open", cb.getState())

	// Wait and transition to half-open
	time.Sleep(1100 * time.Millisecond)
	cb.allow() // triggers transition
	assert.Equal(t, "half-open", cb.getState())

	// Success in half-open resets to closed
	cb.recordSuccess()
	assert.Equal(t, "closed", cb.getState())
	assert.True(t, cb.allow())
}

func TestWebhookCircuitBreaker_HalfOpenToOpenOnFailure(t *testing.T) {
	cb := newWebhookCircuitBreaker(1, 1)

	// Trip to open
	cb.recordFailure()
	assert.Equal(t, "open", cb.getState())

	// Wait and transition to half-open
	time.Sleep(1100 * time.Millisecond)
	cb.allow()
	assert.Equal(t, "half-open", cb.getState())

	// Failure in half-open goes back to open
	cb.recordFailure()
	assert.Equal(t, "open", cb.getState())
}

func TestWebhookCircuitBreaker_SuccessResetsClosed(t *testing.T) {
	cb := newWebhookCircuitBreaker(5, 30)

	// Accumulate some failures
	cb.recordFailure()
	cb.recordFailure()
	cb.recordFailure()

	// Success resets failure count
	cb.recordSuccess()
	assert.Equal(t, "closed", cb.getState())

	// Need full threshold again to trip
	cb.recordFailure()
	cb.recordFailure()
	cb.recordFailure()
	cb.recordFailure()
	assert.Equal(t, "closed", cb.getState())

	cb.recordFailure()
	assert.Equal(t, "open", cb.getState())
}

// ---- Webhook call tests with httptest ----

func TestCallWebhook_SuccessfulRedirect(t *testing.T) {
	providerID := uuid.New().String()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "HexxLock-RoutingWebhook/1.0", r.Header.Get("User-Agent"))
		assert.NotEmpty(t, r.Header.Get("X-Webhook-Request-ID"))

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqPayload models.RoutingWebhookRequest
		require.NoError(t, json.Unmarshal(body, &reqPayload))
		assert.Equal(t, "example.com", reqPayload.EmailDomain)

		// Return redirect action
		resp := models.RoutingWebhookResponse{
			Action:     models.RoutingWebhookActionRedirect,
			ProviderID: &providerID,
			Reason:     "corporate domain detected",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		TenantID:    uuid.New().String(),
		EmailDomain: "example.com",
		RequestID:   uuid.New().String(),
		Timestamp:   time.Now(),
	}

	resp, durationMs, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.GreaterOrEqual(t, durationMs, 0)
	assert.Equal(t, models.RoutingWebhookActionRedirect, resp.Action)
	assert.Equal(t, &providerID, resp.ProviderID)
	assert.Equal(t, "corporate domain detected", resp.Reason)
}

func TestCallWebhook_PassAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := models.RoutingWebhookResponse{
			Action: models.RoutingWebhookActionPass,
			Reason: "not applicable for this domain",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	resp, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.NoError(t, err)
	assert.Equal(t, models.RoutingWebhookActionPass, resp.Action)
}

func TestCallWebhook_DenyAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := models.RoutingWebhookResponse{
			Action: models.RoutingWebhookActionDeny,
			Reason: "user terminated in HR system",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	resp, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.NoError(t, err)
	assert.Equal(t, models.RoutingWebhookActionDeny, resp.Action)
}

func TestCallWebhook_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Simulate slow response
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 200, // 200ms timeout
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	_, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook request failed")
}

func TestCallWebhook_HTTP500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	_, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestCallWebhook_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	_, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestCallWebhook_InvalidAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"action": "invalid_action"})
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "POST",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	_, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid action")
}

// ---- HMAC authentication test ----

func TestCallWebhook_HMACAuthentication(t *testing.T) {
	hmacSecret := "my-super-secret-hmac-key-12345"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		// Verify HMAC signature
		sigHeader := r.Header.Get("X-Webhook-Signature")
		require.NotEmpty(t, sigHeader, "signature header missing")
		assert.True(t, strings.HasPrefix(sigHeader, "sha256="))

		// Compute expected signature
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write(body)
		expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		assert.Equal(t, expectedSig, sigHeader)

		resp := models.RoutingWebhookResponse{
			Action: models.RoutingWebhookActionAllow,
			Reason: "hmac verified",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)
	// No encryption service -- secret stored plaintext in test

	webhook := &models.RoutingWebhook{
		ID:         uuid.New(),
		URL:        server.URL,
		Method:     "POST",
		AuthType:   models.RoutingWebhookAuthHMAC,
		AuthSecret: &hmacSecret,
		TimeoutMs:  5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		TenantID:    uuid.New().String(),
		EmailDomain: "corp.example.com",
		RequestID:   uuid.New().String(),
		Timestamp:   time.Now(),
	}

	resp, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.NoError(t, err)
	assert.Equal(t, models.RoutingWebhookActionAllow, resp.Action)
}

// ---- Bearer authentication test ----

func TestCallWebhook_BearerAuthentication(t *testing.T) {
	bearerToken := "test-bearer-token-xyz"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer "+bearerToken, authHeader)

		resp := models.RoutingWebhookResponse{
			Action: models.RoutingWebhookActionAllow,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:         uuid.New(),
		URL:        server.URL,
		Method:     "POST",
		AuthType:   models.RoutingWebhookAuthBearer,
		AuthSecret: &bearerToken,
		TimeoutMs:  5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	resp, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.NoError(t, err)
	assert.Equal(t, models.RoutingWebhookActionAllow, resp.Action)
}

// ---- Fallback behavior test ----

func TestApplyFallback(t *testing.T) {
	tests := []struct {
		name           string
		fallbackAction string
		providerID     *uuid.UUID
		expectedAction models.RoutingWebhookAction
	}{
		{
			name:           "allow fallback",
			fallbackAction: "allow",
			expectedAction: models.RoutingWebhookActionAllow,
		},
		{
			name:           "deny fallback",
			fallbackAction: "deny",
			expectedAction: models.RoutingWebhookActionDeny,
		},
		{
			name:           "redirect fallback",
			fallbackAction: "redirect",
			providerID:     ptrUUID(uuid.New()),
			expectedAction: models.RoutingWebhookActionRedirect,
		},
		{
			name:           "step_up_mfa fallback",
			fallbackAction: "step_up_mfa",
			expectedAction: models.RoutingWebhookActionStepUpMFA,
		},
	}

	svc := NewRoutingWebhookService(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := &models.RoutingWebhook{
				ID:                 uuid.New(),
				TenantID:           uuid.New(),
				FallbackAction:     tt.fallbackAction,
				FallbackProviderID: tt.providerID,
			}

			result, err := svc.applyFallback(context.Background(), webhook, "test reason")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAction, result.Action)
			assert.Contains(t, result.Reason, "fallback")
			if tt.providerID != nil {
				assert.Equal(t, tt.providerID, result.ProviderID)
			}
		})
	}
}

// ---- First-match-wins with multiple webhooks (via evaluateSingleWebhook) ----

func TestEvaluateSingleWebhook_WithCircuitBreaker(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		resp := models.RoutingWebhookResponse{
			Action: models.RoutingWebhookActionAllow,
			Reason: "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:             uuid.New(),
		TenantID:       uuid.New(),
		URL:            server.URL,
		Method:         "POST",
		AuthType:       models.RoutingWebhookAuthNone,
		TimeoutMs:      5000,
		RetryCount:     0,
		CBEnabled:      true,
		CBThreshold:    2,
		CBTimeoutSec:   30,
		FallbackAction: "deny",
	}

	evalCtx := &RoutingEvaluationContext{
		TenantID:    webhook.TenantID,
		EmailDomain: "test.com",
	}

	// First call succeeds
	result, err := svc.evaluateSingleWebhook(context.Background(), webhook, evalCtx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, models.RoutingWebhookActionAllow, result.Action)
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
}

func TestEvaluateSingleWebhook_CircuitBreakerOpen_UsesFallback(t *testing.T) {
	svc := NewRoutingWebhookService(nil)

	webhookID := uuid.New()
	webhook := &models.RoutingWebhook{
		ID:             webhookID,
		TenantID:       uuid.New(),
		URL:            "http://unreachable.invalid/webhook",
		Method:         "POST",
		AuthType:       models.RoutingWebhookAuthNone,
		TimeoutMs:      100,
		RetryCount:     0,
		CBEnabled:      true,
		CBThreshold:    1,
		CBTimeoutSec:   60,
		FallbackAction: "deny",
	}

	evalCtx := &RoutingEvaluationContext{
		TenantID:    webhook.TenantID,
		EmailDomain: "test.com",
	}

	// Manually open the circuit breaker
	cb := svc.getCircuitBreaker(webhook)
	cb.recordFailure() // trips the breaker (threshold=1)
	assert.Equal(t, "open", cb.getState())

	// Now evaluate -- should use fallback since circuit is open
	result, err := svc.evaluateSingleWebhook(context.Background(), webhook, evalCtx)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, models.RoutingWebhookActionDeny, result.Action)
	assert.Contains(t, result.Reason, "fallback")
}

// ---- GET method test ----

func TestCallWebhook_GETMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		// GET requests should not have a body
		body, _ := io.ReadAll(r.Body)
		assert.Empty(t, body)

		resp := models.RoutingWebhookResponse{
			Action: models.RoutingWebhookActionAllow,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	svc := NewRoutingWebhookService(nil)

	webhook := &models.RoutingWebhook{
		ID:        uuid.New(),
		URL:       server.URL,
		Method:    "GET",
		AuthType:  models.RoutingWebhookAuthNone,
		TimeoutMs: 5000,
	}

	reqPayload := &models.RoutingWebhookRequest{
		RequestID: uuid.New().String(),
		Timestamp: time.Now(),
	}

	resp, _, err := svc.callWebhook(context.Background(), webhook, reqPayload)
	require.NoError(t, err)
	assert.Equal(t, models.RoutingWebhookActionAllow, resp.Action)
}

// ---- Helper functions ----

func ptrUUID(id uuid.UUID) *uuid.UUID {
	return &id
}

// ---- Model validation tests ----

func TestIsValidRoutingWebhookAction(t *testing.T) {
	tests := []struct {
		action string
		valid  bool
	}{
		{"redirect", true},
		{"allow", true},
		{"deny", true},
		{"step_up_mfa", true},
		{"pass", true},
		{"invalid", false},
		{"", false},
		{"REDIRECT", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			assert.Equal(t, tt.valid, models.IsValidRoutingWebhookAction(tt.action))
		})
	}
}

// ---- isPrivateIP tests ----

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		private bool
	}{
		{"public IP", "8.8.8.8", false},
		{"loopback", "127.0.0.1", true},
		{"loopback range", "127.5.5.5", true},
		{"10.x private", "10.0.0.1", true},
		{"10.x private high", "10.255.255.255", true},
		{"172.16 private", "172.16.0.1", true},
		{"172.31 private", "172.31.255.255", true},
		{"172.32 public", "172.32.0.1", false},
		{"192.168 private", "192.168.0.1", true},
		{"192.167 public", "192.167.0.1", false},
		{"link-local", "169.254.1.1", true},
		{"0.0.0.0", "0.0.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse IP: %s", tt.ip)
			assert.Equal(t, tt.private, isPrivateIP(ip))
		})
	}
}

// ---- truncateString test ----

func TestTruncateString(t *testing.T) {
	assert.Equal(t, "hello", truncateString("hello", 10))
	assert.Equal(t, "hello", truncateString("hello", 5))
	assert.Equal(t, "hel", truncateString("hello", 3))
	assert.Equal(t, "", truncateString("", 5))
}
