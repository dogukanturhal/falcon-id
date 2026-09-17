// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	goredis "github.com/redis/go-redis/v9"
)

// MFADecision is the outcome of an adaptive MFA evaluation.
type MFADecision string

const (
	// MFADecisionRequired means the user must complete MFA before proceeding.
	MFADecisionRequired MFADecision = "required"
	// MFADecisionSkip means the risk score is low enough to skip MFA for this request.
	MFADecisionSkip MFADecision = "skip"
	// MFADecisionEscalate means additional factors (step-up) are required.
	MFADecisionEscalate MFADecision = "escalate"
)

// AdaptiveMFAContext carries the signals used to drive an MFA risk decision.
type AdaptiveMFAContext struct {
	UserID    uuid.UUID
	TenantID  uuid.UUID
	IPAddress string
	UserAgent string
	DeviceID  string
	RiskScore float64
}

// AdaptiveMFAEngine evaluates contextual signals to decide whether MFA is
// required for a given request. It caches recent low-risk decisions in Redis
// to avoid repeated evaluation overhead on the hot authentication path.
type AdaptiveMFAEngine struct {
	redis  goredis.Cmdable
	logger *zap.Logger
}

// NewAdaptiveMFAEngine constructs an AdaptiveMFAEngine.
// redis may be nil; the engine evaluates without caching in that case.
func NewAdaptiveMFAEngine(redis goredis.Cmdable, logger *zap.Logger) *AdaptiveMFAEngine {
	return &AdaptiveMFAEngine{
		redis:  redis,
		logger: logger,
	}
}

// Evaluate returns the MFA decision for the given context.
// The decision is derived from the pre-computed risk score in ctx.RiskScore:
//   - score < 0.3  → skip (trusted device/IP)
//   - 0.3 ≤ score < 0.7 → required
//   - score ≥ 0.7  → escalate (step-up to stronger factor)
func (e *AdaptiveMFAEngine) Evaluate(_ context.Context, amCtx AdaptiveMFAContext) MFADecision {
	score := amCtx.RiskScore

	e.logger.Debug("AdaptiveMFA evaluation",
		zap.String("user_id", amCtx.UserID.String()),
		zap.Float64("risk_score", score),
	)

	switch {
	case score < 0.3:
		return MFADecisionSkip
	case score >= 0.7:
		return MFADecisionEscalate
	default:
		return MFADecisionRequired
	}
}
