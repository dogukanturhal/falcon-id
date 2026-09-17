// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestZTOrchestrator constructs a ZeroTrustOrchestrator using the current API.
func newTestZTOrchestrator(enabled bool) *ZeroTrustOrchestrator {
	cfg := ZeroTrustOrchestratorConfig{
		Enabled:                enabled,
		RiskThresholdDeny:      0.9,
		RiskThresholdChallenge: 0.6,
	}
	return NewZeroTrustOrchestrator(nil, nil, cfg, zap.NewNop())
}

// ---------------------------------------------------------------------------
// DefaultZeroTrustOrchestratorConfig tests
// ---------------------------------------------------------------------------

func TestDefaultZeroTrustOrchestratorConfig(t *testing.T) {
	cfg := DefaultZeroTrustOrchestratorConfig()

	assert.False(t, cfg.Enabled, "should be opt-in (disabled by default)")
	assert.Equal(t, 0.9, cfg.RiskThresholdDeny)
	assert.Equal(t, 0.6, cfg.RiskThresholdChallenge)
}

// ---------------------------------------------------------------------------
// Evaluate tests
// ---------------------------------------------------------------------------

func TestZeroTrustOrchestrator_Evaluate_DisabledAlwaysAllow(t *testing.T) {
	o := newTestZTOrchestrator(false)
	ctx := context.Background()

	signals := ContinuousAuthSignals{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		SessionID: "sess-abc",
		IPAddress: "1.2.3.4",
		UserAgent: "Chrome/120",
		Resource:  "/api/resource",
		Action:    "read",
	}

	decision := o.Evaluate(ctx, signals)
	assert.Equal(t, ContinuousAuthAllow, decision)
}

func TestZeroTrustOrchestrator_Evaluate_EnabledNilDepsAllows(t *testing.T) {
	// When enabled but all deps are nil, the current stub always returns allow.
	cfg := ZeroTrustOrchestratorConfig{
		Enabled:                true,
		RiskThresholdDeny:      0.9,
		RiskThresholdChallenge: 0.6,
	}
	o := NewZeroTrustOrchestrator(nil, nil, cfg, zap.NewNop())
	ctx := context.Background()

	signals := ContinuousAuthSignals{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		SessionID: "sess-enabled",
		IPAddress: "10.0.0.1",
	}

	decision := o.Evaluate(ctx, signals)
	// Stub implementation always returns Allow regardless of signals.
	assert.Equal(t, ContinuousAuthAllow, decision)
}

// ---------------------------------------------------------------------------
// EvaluateRequest tests
// ---------------------------------------------------------------------------

func TestZeroTrustOrchestrator_EvaluateRequest_ReturnsAllow(t *testing.T) {
	o := newTestZTOrchestrator(false)
	ctx := context.Background()

	result, err := o.EvaluateRequest(ctx, "any-session", "1.2.3.4", "Mozilla")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "allow", result.Action)
}

func TestZeroTrustOrchestrator_EvaluateRequest_Enabled_ReturnsAllow(t *testing.T) {
	o := newTestZTOrchestrator(true)
	ctx := context.Background()

	result, err := o.EvaluateRequest(ctx, "sess-xyz", "10.0.0.1", "Firefox/121")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "allow", result.Action)
}

// ---------------------------------------------------------------------------
// RecordRequestContext tests
// ---------------------------------------------------------------------------

func TestZeroTrustOrchestrator_RecordRequestContext_NoPanic(t *testing.T) {
	o := newTestZTOrchestrator(false)
	ctx := context.Background()

	// Should not panic even with nil redis.
	assert.NotPanics(t, func() {
		o.RecordRequestContext(ctx, "sess-record", "1.2.3.4", "TestAgent/1.0")
	})
}

// ---------------------------------------------------------------------------
// ContinuousAuthDecision constants
// ---------------------------------------------------------------------------

func TestContinuousAuthDecisionConstants(t *testing.T) {
	assert.Equal(t, ContinuousAuthDecision("allow"), ContinuousAuthAllow)
	assert.Equal(t, ContinuousAuthDecision("challenge"), ContinuousAuthChallenge)
	assert.Equal(t, ContinuousAuthDecision("deny"), ContinuousAuthDeny)
}

// ---------------------------------------------------------------------------
// HTTPMiddlewareFunc tests
// ---------------------------------------------------------------------------

func TestZeroTrustOrchestrator_HTTPMiddlewareFunc_NotNil(t *testing.T) {
	o := newTestZTOrchestrator(false)

	mw := o.HTTPMiddlewareFunc(nil)
	// When disabled, the middleware function is returned but never calls next
	// (next is nil here — just verify it doesn't panic on construction).
	assert.NotNil(t, mw)
}
