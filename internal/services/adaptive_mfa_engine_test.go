// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// newAdaptiveMFATestEngine creates an AdaptiveMFAEngine without Redis for unit tests.
func newAdaptiveMFATestEngine() *AdaptiveMFAEngine {
	return NewAdaptiveMFAEngine(nil, zap.NewNop())
}

// ---------------------------------------------------------------------------
// AdaptiveMFAEngine.Evaluate
// ---------------------------------------------------------------------------

func TestAdaptiveMFAEngine_Evaluate_LowRisk_Skip(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "1.2.3.4",
		UserAgent: "Mozilla/5.0",
		RiskScore: 0.1, // below 0.3 threshold
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionSkip, decision)
}

func TestAdaptiveMFAEngine_Evaluate_MediumRisk_Required(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "1.2.3.4",
		RiskScore: 0.5, // between 0.3 and 0.7
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionRequired, decision)
}

func TestAdaptiveMFAEngine_Evaluate_HighRisk_Escalate(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "5.5.5.5",
		RiskScore: 0.9, // >= 0.7 threshold
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionEscalate, decision)
}

func TestAdaptiveMFAEngine_Evaluate_BoundaryLow_Skip(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	// Exactly at 0.3 boundary — should be Required (0.3 <= score < 0.7).
	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "1.2.3.4",
		RiskScore: 0.3,
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionRequired, decision)
}

func TestAdaptiveMFAEngine_Evaluate_BoundaryHigh_Escalate(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	// Exactly at 0.7 boundary — should be Escalate (score >= 0.7).
	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "10.0.0.1",
		RiskScore: 0.7,
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionEscalate, decision)
}

func TestAdaptiveMFAEngine_Evaluate_ZeroRisk_Skip(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "192.168.1.1",
		RiskScore: 0.0,
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionSkip, decision)
}

func TestAdaptiveMFAEngine_Evaluate_MaxRisk_Escalate(t *testing.T) {
	t.Parallel()
	engine := newAdaptiveMFATestEngine()
	ctx := context.Background()

	amCtx := AdaptiveMFAContext{
		UserID:    uuid.New(),
		TenantID:  uuid.New(),
		IPAddress: "185.220.101.1",
		RiskScore: 1.0,
	}

	decision := engine.Evaluate(ctx, amCtx)
	assert.Equal(t, MFADecisionEscalate, decision)
}

// ---------------------------------------------------------------------------
// MFADecision constants
// ---------------------------------------------------------------------------

func TestMFADecisionConstants(t *testing.T) {
	assert.Equal(t, MFADecision("required"), MFADecisionRequired)
	assert.Equal(t, MFADecision("skip"), MFADecisionSkip)
	assert.Equal(t, MFADecision("escalate"), MFADecisionEscalate)
}

// ---------------------------------------------------------------------------
// NewAdaptiveMFAEngine — nil Redis is safe
// ---------------------------------------------------------------------------

func TestNewAdaptiveMFAEngine_NilRedis_NoPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		e := NewAdaptiveMFAEngine(nil, zap.NewNop())
		assert.NotNil(t, e)
	})
}
