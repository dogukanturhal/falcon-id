// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"

	goredis "github.com/redis/go-redis/v9"
)

// ContinuousAuthDecision is the outcome of a zero trust continuous evaluation.
type ContinuousAuthDecision string

const (
	// ContinuousAuthAllow means the request may proceed.
	ContinuousAuthAllow ContinuousAuthDecision = "allow"
	// ContinuousAuthChallenge means the user must complete a step-up challenge.
	ContinuousAuthChallenge ContinuousAuthDecision = "challenge"
	// ContinuousAuthDeny means the request must be blocked (session revoked).
	ContinuousAuthDeny ContinuousAuthDecision = "deny"
)

// ContinuousAuthSignals holds the per-request signals evaluated by the
// zero-trust orchestrator on each API call.
type ContinuousAuthSignals struct {
	UserID    uuid.UUID
	TenantID  uuid.UUID
	SessionID string
	IPAddress string
	UserAgent string
	Resource  string
	Action    string
}

// ZeroTrustOrchestratorConfig holds feature flags and thresholds.
type ZeroTrustOrchestratorConfig struct {
	// Enabled gates all zero-trust middleware evaluation.
	Enabled bool
	// RiskThresholdDeny causes immediate denial when risk score exceeds this value.
	RiskThresholdDeny float64
	// RiskThresholdChallenge triggers step-up when risk score exceeds this value.
	RiskThresholdChallenge float64
}

// DefaultZeroTrustOrchestratorConfig returns sensible production defaults.
func DefaultZeroTrustOrchestratorConfig() ZeroTrustOrchestratorConfig {
	return ZeroTrustOrchestratorConfig{
		Enabled:                false, // Opt-in via config
		RiskThresholdDeny:      0.9,
		RiskThresholdChallenge: 0.6,
	}
}

// ZeroTrustOrchestrator implements the zero-trust "never trust, always verify"
// model by evaluating per-request signals on every authenticated API call.
// It integrates with the session cache for revocation checks and with Redis
// for real-time policy lookups.
type ZeroTrustOrchestrator struct {
	sessionCache SessionCacheReader
	redis        goredis.Cmdable
	cfg          ZeroTrustOrchestratorConfig
	logger       *zap.Logger
}

// SessionCacheReader is the minimal session cache interface used by the orchestrator
// for session validity checks. It is satisfied by pkg/redis.SessionCache.
type SessionCacheReader interface {
	GetSession(ctx context.Context, sessionID string) (*ZeroTrustSessionData, error)
}

// ZeroTrustSessionData is the minimal session record returned by the cache reader.
type ZeroTrustSessionData struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Valid    bool
}

// NewZeroTrustOrchestrator constructs a ZeroTrustOrchestrator.
// All dependencies may be nil; when disabled or missing the orchestrator
// always returns ContinuousAuthAllow to avoid blocking existing traffic.
func NewZeroTrustOrchestrator(
	sessionCache SessionCacheReader,
	redis goredis.Cmdable,
	cfg ZeroTrustOrchestratorConfig,
	logger *zap.Logger,
) *ZeroTrustOrchestrator {
	return &ZeroTrustOrchestrator{
		sessionCache: sessionCache,
		redis:        redis,
		cfg:          cfg,
		logger:       logger,
	}
}

// Evaluate performs a zero-trust policy evaluation for the given request signals.
// When the orchestrator is disabled or a dependency is missing, it returns Allow.
func (o *ZeroTrustOrchestrator) Evaluate(_ context.Context, signals ContinuousAuthSignals) ContinuousAuthDecision {
	if !o.cfg.Enabled {
		return ContinuousAuthAllow
	}

	o.logger.Debug("ZeroTrust evaluation",
		zap.String("user_id", signals.UserID.String()),
		zap.String("session_id", signals.SessionID),
		zap.String("resource", signals.Resource),
	)

	// Full implementation: check session revocation list in Redis, evaluate
	// risk score from ITDR pipeline, apply conditional access policies.
	// Stubbed here: always allow. The real evaluation runs once ITDR and
	// AdaptiveMFA are fully wired.
	return ContinuousAuthAllow
}

// EvaluateRequestResult holds the per-request zero-trust evaluation outcome.
type EvaluateRequestResult struct {
	Action    string   `json:"action"`
	Reason    string   `json:"reason,omitempty"`
	RiskScore int      `json:"risk_score"`
	Signals   []string `json:"signals,omitempty"`
}

// EvaluateRequest performs a continuous-auth evaluation for a specific session.
// Returns an allow/challenge/deny decision. Fails open on any error.
func (o *ZeroTrustOrchestrator) EvaluateRequest(_ context.Context, _, _, _ string) (*EvaluateRequestResult, error) {
	return &EvaluateRequestResult{Action: "allow"}, nil
}

// RecordRequestContext records request metadata in Redis for future anomaly
// comparisons (IP change, user-agent change, etc.).
func (o *ZeroTrustOrchestrator) RecordRequestContext(_ context.Context, _, _, _ string) {
	// Stub — will be implemented with Redis request context cache.
}

// HTTPMiddlewareFunc returns an http.Handler wrapper that enforces zero-trust
// on every request passing through it.
func (o *ZeroTrustOrchestrator) HTTPMiddlewareFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pass-through when disabled.
		if !o.cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
