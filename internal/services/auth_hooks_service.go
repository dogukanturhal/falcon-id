// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/hooks"
)

// AuthHooksService integrates the shared HookEngine into Falcon-ID's auth flow.
//
// It wraps the engine's generic Execute method with auth-specific convenience
// methods that enforce Falcon-ID's hook execution semantics:
//
//   - ExecutePreLogin  — synchronous, fail-open on error/timeout, can deny
//   - ExecutePostLogin — asynchronous fire-and-forget, never blocks the caller
//   - ExecutePreTokenIssue — synchronous, returns enrichment data for JWT claims
//
// All three methods are safe for concurrent use.
type AuthHooksService struct {
	engine *hooks.HookEngine
	logger *zap.Logger
}

// NewAuthHooksService creates an AuthHooksService backed by the given HookEngine.
// Both engine and logger must be non-nil for production use; passing nil values
// degrades gracefully (engine is skipped, logger panics are guarded).
func NewAuthHooksService(engine *hooks.HookEngine, logger *zap.Logger) *AuthHooksService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AuthHooksService{
		engine: engine,
		logger: logger,
	}
}

// ExecutePreLogin runs all pre-login hooks for the given tenant.
//
// Returns (allow, enrichData, error):
//   - allow=false means at least one hook denied the login. The hook's denial
//     message is returned as the error.
//   - enrichData carries additional key/value pairs returned by hooks (may be nil).
//   - error is non-nil only when the engine itself fails (not when a hook denies).
//
// The method is fail-open: if the engine or a hook returns an unexpected error,
// the login is allowed and the error is logged but not propagated. This matches
// Auth0 Actions and Okta Event Hooks behaviour where availability of hooks must
// not gate the core auth flow.
func (s *AuthHooksService) ExecutePreLogin(ctx context.Context, tenantID string, data map[string]interface{}) (bool, map[string]interface{}, error) {
	if s.engine == nil {
		return true, nil, nil
	}

	resp, err := s.engine.Execute(ctx, hooks.TriggerPreLogin, tenantID, data)
	if err != nil {
		// Fail-open: log and allow.
		s.logger.Warn("auth_hooks: pre-login hook engine error, failing open",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		return true, nil, nil
	}

	if !resp.Allow {
		// A hook explicitly denied — propagate as an error so the auth handler
		// can return a proper 401 with the denial message.
		msg := resp.Message
		if msg == "" {
			msg = "login denied by pre-login hook"
		}
		s.logger.Info("auth_hooks: pre-login denied by hook",
			zap.String("tenant_id", tenantID),
			zap.String("message", msg),
		)
		return false, nil, fmt.Errorf("%s", msg)
	}

	var enrich map[string]interface{}
	if len(resp.Enrich) > 0 {
		enrich = resp.Enrich
	}

	s.logger.Debug("auth_hooks: pre-login hooks executed",
		zap.String("tenant_id", tenantID),
		zap.Int("enrich_keys", len(enrich)),
	)

	return true, enrich, nil
}

// ExecutePostLogin fires all post-login hooks for the given tenant asynchronously.
//
// The method returns immediately; hook delivery happens in a background goroutine.
// Any errors from hooks are logged but never surface to the caller. This matches
// the "best-effort audit / notification" pattern used by Auth0 post-login actions.
//
// Because delivery is asynchronous, post-login hooks cannot deny or enrich —
// they are suitable for audit logging, SIEM forwarding, and analytics.
func (s *AuthHooksService) ExecutePostLogin(_ context.Context, tenantID string, data map[string]interface{}) {
	if s.engine == nil {
		return
	}

	// Capture logger and engine for the goroutine (avoids capturing the receiver
	// pointer directly which could be GC'd if the caller is very short-lived).
	log := s.logger
	engine := s.engine

	go func() { //nolint:gosec // goroutine must outlive request context
		// Use a fresh background context so cancellation of the original request
		// does not abort post-login delivery.
		bgCtx := context.Background()

		_, err := engine.Execute(bgCtx, hooks.TriggerPostLogin, tenantID, data)
		if err != nil {
			log.Warn("auth_hooks: post-login hook engine error (async, ignored)",
				zap.String("tenant_id", tenantID),
				zap.Error(err),
			)
		}
	}()
}

// ExecutePreTokenIssue runs all pre-token-issue hooks for the given tenant and
// returns a merged enrichment map that callers add as additional JWT claims.
//
// Returns (enrichData, error):
//   - enrichData is the merged map from all hooks' Enrich fields. It is safe to
//     pass nil/empty maps directly to JWT claim builders.
//   - error is non-nil only when a hook denies token issuance (rare — most hooks
//     use this trigger to add claims, not to deny).
//
// On engine error the method returns (nil, nil), failing open so that token
// issuance can continue without enrichment rather than blocking the user.
func (s *AuthHooksService) ExecutePreTokenIssue(ctx context.Context, tenantID string, data map[string]interface{}) (map[string]interface{}, error) {
	if s.engine == nil {
		return nil, nil
	}

	resp, err := s.engine.Execute(ctx, hooks.TriggerPreTokenIssue, tenantID, data)
	if err != nil {
		s.logger.Warn("auth_hooks: pre-token-issue hook engine error, failing open",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		return nil, nil
	}

	if !resp.Allow {
		msg := resp.Message
		if msg == "" {
			msg = "token issuance denied by pre-token-issue hook"
		}
		s.logger.Info("auth_hooks: token issuance denied by hook",
			zap.String("tenant_id", tenantID),
			zap.String("message", msg),
		)
		return nil, fmt.Errorf("%s", msg)
	}

	var enrich map[string]interface{}
	if len(resp.Enrich) > 0 {
		enrich = resp.Enrich
	}

	s.logger.Debug("auth_hooks: pre-token-issue hooks executed",
		zap.String("tenant_id", tenantID),
		zap.Int("enrich_keys", len(enrich)),
	)

	return enrich, nil
}
