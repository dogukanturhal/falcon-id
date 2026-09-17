// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// SSFEventEmitter is the abstraction the post-signup hook (and any
// future emit-site) uses to publish a Shared Signals Framework event
// downstream. Distinct from SSFService (which is stream-CRUD) — this
// interface is the WRITE side that didn't exist on master pre-2026-05-22.
//
// Today's implementation (NoOpSSFEmitter) logs but doesn't deliver.
// Real implementations land later (ENT-7 Phase 2): an outbox-pattern
// emitter that writes to iam_ssf_event_outbox + a delivery worker
// that drains to subscriber URLs per RFC 8417 / OpenID SSF spec.
//
// Why a stub now: the consumer-signup hook + future "MFA enabled",
// "password changed", "session-revoked" hooks need a single emit
// surface to converge on. Wiring the interface now means future MRs
// that implement real delivery don't need to refactor every call
// site — they just swap the NoOp impl for the real one in
// cmd/services.go.
type SSFEventEmitter interface {
	// EmitAccountCreated fires when a new user account is created.
	// Matches the SSF/CAEP "account-credential-change-required" /
	// "session-revoked" / "account-purged" event class but is
	// specifically the "account-credential-change.account-created"
	// signal. Per RFC 8417 §4, events MUST carry a deterministic
	// JTI, a stream-scoped issuer, and a sub claim identifying the
	// principal. Real implementation will fill those in; NoOp just
	// logs.
	EmitAccountCreated(ctx context.Context, evt AccountCreatedEvent) error
}

// AccountCreatedEvent carries the minimum SSF-compliant payload for
// a new-account signal. Fields map to the OpenID SSF + RISC event
// schemas (https://openid.net/specs/openid-sse-framework-1_0.html).
type AccountCreatedEvent struct {
	// UserID — the canonical iam_users.id of the freshly-created
	// account. Becomes the `sub` claim in the emitted event.
	UserID uuid.UUID
	// TenantID — the tenant the user landed in. Becomes part of
	// the `aud` / `iss` shape so subscribers can filter by tenant.
	TenantID uuid.UUID
	// AccountType — "personal" / "business" / "consumer". Lets
	// subscribers route consumer-signups separately from business.
	AccountType string
	// Email — the user's email at creation time. Used by SIEM
	// correlation; NOT included in the event body unless the
	// subscriber has a `with_pii=true` stream config (default
	// false). Real impl scrubs by default.
	Email string
}

// NoOpSSFEmitter logs but doesn't deliver. The default until the
// outbox + delivery worker land (ENT-7 Phase 2). Logs are still
// useful for forensics — every account-created event lands in
// the SOC's pod-log pipeline even without real SSF delivery.
type NoOpSSFEmitter struct{}

// NewNoOpSSFEmitter constructs the no-op emitter.
func NewNoOpSSFEmitter() *NoOpSSFEmitter { return &NoOpSSFEmitter{} }

// EmitAccountCreated logs the event. Real delivery is deferred.
func (NoOpSSFEmitter) EmitAccountCreated(_ context.Context, evt AccountCreatedEvent) error {
	logger.Info("SSF: account-created (no-op emitter — delivery deferred to ENT-7 Phase 2)",
		zap.String("user_id", evt.UserID.String()),
		zap.String("tenant_id", evt.TenantID.String()),
		zap.String("account_type", evt.AccountType),
	)
	return nil
}
