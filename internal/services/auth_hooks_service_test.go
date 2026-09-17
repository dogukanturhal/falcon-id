// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/dogukanturhal/platform-shared/hooks"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const testTenantID = "tenant-hooks-test-001"

// allowServer returns an httptest.Server that responds with allow=true and
// optional enrichment data. Close() it after use.
func allowServer(t *testing.T, enrich map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"allow":  true,
			"enrich": enrich,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// denyServer returns an httptest.Server that responds with allow=false and a
// denial message.
func denyServer(t *testing.T, message string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"allow":   false,
			"message": message,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// countingServer returns a server that counts requests and responds with allow=true.
func countingServer(counter *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		counter.Add(1)
		resp := map[string]interface{}{"allow": true, "enrich": map[string]interface{}{}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// slowServer returns a server that delays its response to trigger a timeout.
func slowServer(delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		resp := map[string]interface{}{"allow": true, "enrich": map[string]interface{}{}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// errorServer returns a server that always responds with HTTP 500.
func errorServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
}

// newTestAuthHooksService creates an AuthHooksService with a real HookEngine
// using a test-specific HTTP client (no TLS, direct connection to test servers).
func newTestAuthHooksService(t *testing.T, tenantID string, hookCfgs []hooks.HookConfig) *AuthHooksService { //nolint:unparam // tenantID is always testTenantID currently but kept for flexibility
	t.Helper()
	log := zaptest.NewLogger(t)
	engine := hooks.NewHookEngineWithClient(zap.NewNop(), &http.Client{Timeout: 5 * time.Second})
	if len(hookCfgs) > 0 {
		engine.RegisterHooks(tenantID, hookCfgs)
	}
	return NewAuthHooksService(engine, log)
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreLogin_Allow
// ---------------------------------------------------------------------------

func TestAuthHooks_PreLogin_Allow(t *testing.T) {
	srv := allowServer(t, map[string]interface{}{"custom_claim": "value123"})
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-pre-login-allow",
			TenantID:  testTenantID,
			Name:      "Allow Pre-Login",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})

	data := map[string]interface{}{"username": "alice", "ip": "1.2.3.4"}
	allow, enrich, err := svc.ExecutePreLogin(context.Background(), testTenantID, data)

	require.NoError(t, err)
	assert.True(t, allow, "hook returned allow=true")
	assert.Equal(t, "value123", enrich["custom_claim"], "enrichment data should be propagated")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreLogin_Deny
// ---------------------------------------------------------------------------

func TestAuthHooks_PreLogin_Deny(t *testing.T) {
	srv := denyServer(t, "account suspended")
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-pre-login-deny",
			TenantID:  testTenantID,
			Name:      "Deny Pre-Login",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})

	allow, enrich, err := svc.ExecutePreLogin(context.Background(), testTenantID, map[string]interface{}{})

	assert.False(t, allow, "hook returned allow=false → should deny")
	assert.Nil(t, enrich, "no enrichment on denial")
	require.Error(t, err, "denial should produce an error")
	assert.Contains(t, err.Error(), "account suspended", "error should contain denial message")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreLogin_NoHooks_Allow
// ---------------------------------------------------------------------------

func TestAuthHooks_PreLogin_NoHooks_Allow(t *testing.T) {
	// No hooks registered for the tenant — should default to allow=true.
	svc := newTestAuthHooksService(t, testTenantID, nil)

	allow, enrich, err := svc.ExecutePreLogin(context.Background(), testTenantID, map[string]interface{}{})

	require.NoError(t, err)
	assert.True(t, allow, "no hooks = implicit allow")
	assert.Nil(t, enrich)
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PostLogin_FireAndForget
// ---------------------------------------------------------------------------

func TestAuthHooks_PostLogin_FireAndForget(t *testing.T) {
	// Ensure the async hook fires exactly once and the call returns immediately.
	var counter atomic.Int64
	srv := countingServer(&counter)
	defer srv.Close()

	log := zaptest.NewLogger(t)
	engine := hooks.NewHookEngineWithClient(zap.NewNop(), &http.Client{Timeout: 5 * time.Second})
	engine.RegisterHooks(testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-post-login-async",
			TenantID:  testTenantID,
			Name:      "Post-Login Async",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPostLogin,
			Enabled:   true,
			Async:     true, // fire-and-forget
			Priority:  0,
			TimeoutMs: 3000,
		},
	})
	svc := NewAuthHooksService(engine, log)

	start := time.Now()
	svc.ExecutePostLogin(context.Background(), testTenantID, map[string]interface{}{"user_id": "u1"})
	elapsed := time.Since(start)

	// The call must return well under 50 ms — it must not wait for the HTTP call.
	assert.Less(t, elapsed, 50*time.Millisecond, "ExecutePostLogin must return immediately")

	// Wait for the goroutine to deliver.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if counter.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.Equal(t, int64(1), counter.Load(), "async hook should have fired exactly once")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreTokenIssue_EnrichClaims
// ---------------------------------------------------------------------------

func TestAuthHooks_PreTokenIssue_EnrichClaims(t *testing.T) {
	enrich := map[string]interface{}{
		"custom_role": "billing-admin",
		"mfa_level":   2,
	}
	srv := allowServer(t, enrich)
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-pre-token-enrich",
			TenantID:  testTenantID,
			Name:      "Enrich Token Claims",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreTokenIssue,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})

	result, err := svc.ExecutePreTokenIssue(context.Background(), testTenantID, map[string]interface{}{})

	require.NoError(t, err)
	require.NotNil(t, result, "enrichment data should be returned")
	assert.Equal(t, "billing-admin", result["custom_role"])
	// JSON numbers decode as float64
	assert.Equal(t, float64(2), result["mfa_level"])
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreTokenIssue_NoHooks
// ---------------------------------------------------------------------------

func TestAuthHooks_PreTokenIssue_NoHooks(t *testing.T) {
	svc := newTestAuthHooksService(t, testTenantID, nil)

	result, err := svc.ExecutePreTokenIssue(context.Background(), testTenantID, map[string]interface{}{})

	require.NoError(t, err)
	assert.Nil(t, result, "no hooks = no enrichment")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreLogin_Timeout_FailOpen
// ---------------------------------------------------------------------------

func TestAuthHooks_PreLogin_Timeout_FailOpen(t *testing.T) {
	// Server takes 500 ms; hook timeout is 100 ms → should time out and fail open.
	srv := slowServer(500 * time.Millisecond)
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-pre-login-slow",
			TenantID:  testTenantID,
			Name:      "Slow Pre-Login",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 100, // 100 ms timeout — will expire before server responds
		},
	})

	allow, _, err := svc.ExecutePreLogin(context.Background(), testTenantID, map[string]interface{}{})

	require.NoError(t, err, "timeout should fail open, not return error to caller")
	assert.True(t, allow, "timeout must fail open (allow=true)")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreLogin_HookError_FailOpen
// ---------------------------------------------------------------------------

func TestAuthHooks_PreLogin_HookError_FailOpen(t *testing.T) {
	// Server always returns HTTP 500.
	srv := errorServer()
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-pre-login-error",
			TenantID:  testTenantID,
			Name:      "Error Pre-Login",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})

	allow, _, err := svc.ExecutePreLogin(context.Background(), testTenantID, map[string]interface{}{})

	require.NoError(t, err, "hook HTTP error should fail open, not propagate")
	assert.True(t, allow, "HTTP error must fail open (allow=true)")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreTokenIssue_MergesEnrichData
// ---------------------------------------------------------------------------

func TestAuthHooks_PreTokenIssue_MergesEnrichData(t *testing.T) {
	// Two hooks: each returns different enrichment keys. Both should appear in the result.
	enrich1 := map[string]interface{}{"claim_a": "value_a", "shared_key": "hook1"}
	enrich2 := map[string]interface{}{"claim_b": "value_b", "shared_key": "hook2"}

	srv1 := allowServer(t, enrich1)
	defer srv1.Close()
	srv2 := allowServer(t, enrich2)
	defer srv2.Close()

	const tid = "tenant-merge-test"
	log := zaptest.NewLogger(t)
	engine := hooks.NewHookEngineWithClient(zap.NewNop(), &http.Client{Timeout: 5 * time.Second})
	engine.RegisterHooks(tid, []hooks.HookConfig{
		{
			ID:        "hook-enrich-1",
			TenantID:  tid,
			Name:      "Enrich Hook 1",
			URL:       srv1.URL,
			Trigger:   hooks.TriggerPreTokenIssue,
			Enabled:   true,
			Async:     false,
			Priority:  1, // runs first
			TimeoutMs: 2000,
		},
		{
			ID:        "hook-enrich-2",
			TenantID:  tid,
			Name:      "Enrich Hook 2",
			URL:       srv2.URL,
			Trigger:   hooks.TriggerPreTokenIssue,
			Enabled:   true,
			Async:     false,
			Priority:  2, // runs second
			TimeoutMs: 2000,
		},
	})

	svc := NewAuthHooksService(engine, log)
	result, err := svc.ExecutePreTokenIssue(context.Background(), tid, map[string]interface{}{})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "value_a", result["claim_a"], "claim_a from hook 1")
	assert.Equal(t, "value_b", result["claim_b"], "claim_b from hook 2")
	// Later hook (priority 2) wins on conflict.
	assert.Equal(t, "hook2", result["shared_key"], "later hook overrides earlier on key conflict")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_ExecutePreLogin_WithRequestID
// ---------------------------------------------------------------------------

func TestAuthHooks_ExecutePreLogin_WithRequestID(t *testing.T) {
	// Verify that the request ID stored in the context is forwarded in the
	// webhook payload's request_id field.
	var capturedPayload hooks.HookPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&capturedPayload); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := map[string]interface{}{"allow": true, "enrich": map[string]interface{}{}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	const reqID = "req-trace-abc-123"
	const tid = "tenant-reqid-test"

	log := zaptest.NewLogger(t)
	engine := hooks.NewHookEngineWithClient(zap.NewNop(), &http.Client{Timeout: 5 * time.Second})
	engine.RegisterHooks(tid, []hooks.HookConfig{
		{
			ID:        "hook-reqid",
			TenantID:  tid,
			Name:      "RequestID Hook",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})
	svc := NewAuthHooksService(engine, log)

	// Embed request ID in context using the shared package's helper.
	ctx := hooks.ContextWithRequestID(context.Background(), reqID)
	allow, _, err := svc.ExecutePreLogin(ctx, tid, map[string]interface{}{"username": "bob"})

	require.NoError(t, err)
	assert.True(t, allow)
	assert.Equal(t, reqID, capturedPayload.RequestID, "request ID should be forwarded to webhook")
	assert.Equal(t, hooks.TriggerPreLogin, capturedPayload.Trigger)
	assert.Equal(t, tid, capturedPayload.TenantID)
}

// ---------------------------------------------------------------------------
// TestAuthHooks_NilEngine_DefaultsToAllow
// ---------------------------------------------------------------------------

func TestAuthHooks_NilEngine_DefaultsToAllow(t *testing.T) {
	// When the engine is nil, all operations should degrade gracefully (allow).
	svc := &AuthHooksService{engine: nil, logger: zap.NewNop()}

	t.Run("PreLogin", func(t *testing.T) {
		allow, enrich, err := svc.ExecutePreLogin(context.Background(), testTenantID, nil)
		assert.True(t, allow)
		assert.Nil(t, enrich)
		assert.NoError(t, err)
	})

	t.Run("PostLogin", func(t *testing.T) {
		// Must not panic.
		assert.NotPanics(t, func() {
			svc.ExecutePostLogin(context.Background(), testTenantID, nil)
		})
	})

	t.Run("PreTokenIssue", func(t *testing.T) {
		result, err := svc.ExecutePreTokenIssue(context.Background(), testTenantID, nil)
		assert.Nil(t, result)
		assert.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// TestAuthHooks_DisabledHook_IsSkipped
// ---------------------------------------------------------------------------

func TestAuthHooks_DisabledHook_IsSkipped(t *testing.T) {
	// A hook registered as Enabled=false must not be called.
	var counter atomic.Int64
	srv := countingServer(&counter)
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-disabled",
			TenantID:  testTenantID,
			Name:      "Disabled Hook",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   false, // disabled — must not fire
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})

	allow, _, err := svc.ExecutePreLogin(context.Background(), testTenantID, map[string]interface{}{})

	require.NoError(t, err)
	assert.True(t, allow, "no enabled hooks = allow")
	assert.Equal(t, int64(0), counter.Load(), "disabled hook must not receive any HTTP calls")
}

// ---------------------------------------------------------------------------
// TestAuthHooks_PreLogin_DenyEmptyMessage
// ---------------------------------------------------------------------------

func TestAuthHooks_PreLogin_DenyEmptyMessage(t *testing.T) {
	// When a hook denies with an empty message, a default message should be used.
	srv := denyServer(t, "") // empty message
	defer srv.Close()

	svc := newTestAuthHooksService(t, testTenantID, []hooks.HookConfig{
		{
			ID:        "hook-deny-empty-msg",
			TenantID:  testTenantID,
			Name:      "Deny Empty Message",
			URL:       srv.URL,
			Trigger:   hooks.TriggerPreLogin,
			Enabled:   true,
			Async:     false,
			Priority:  0,
			TimeoutMs: 2000,
		},
	})

	allow, _, err := svc.ExecutePreLogin(context.Background(), testTenantID, map[string]interface{}{})

	assert.False(t, allow)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied", "fallback message should mention denial")
}
