// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// CAEEventType represents the type of continuous access evaluation event.
// Events are consumed by a subscriber that re-evaluates active sessions in
// real time without waiting for the next token refresh.
type CAEEventType string

const (
	// CAEPasswordChanged signals that the user's password was changed and all
	// sessions that pre-date the change should be invalidated.
	CAEPasswordChanged CAEEventType = "password_changed"
	// CAEAccountLocked signals that the account has been administratively locked
	// or automatically locked due to too many failed attempts.
	CAEAccountLocked CAEEventType = "account_locked"
	// CAEMFARevoked signals that a MFA method was removed from the user's account,
	// potentially reducing their assurance level.
	CAEMFARevoked CAEEventType = "mfa_revoked"
	// CAERoleRevoked signals that a role assignment was removed, potentially
	// reducing the permissions available to active sessions.
	CAERoleRevoked CAEEventType = "role_revoked"
	// CAEIPChanged signals that the user's IP address has changed in a way that
	// violates a conditional access policy.
	CAEIPChanged CAEEventType = "ip_changed"
	// CAESessionRevoked signals that a specific session has been explicitly
	// revoked by an administrator or the user themselves.
	CAESessionRevoked CAEEventType = "session_revoked"
	// CAECredentialCompromised signals that a specific authenticator credential
	// has been auto-revoked due to clone evidence (W3C WebAuthn §6.1.3 sign-
	// count regression). Subscribers should revoke any active session whose
	// authentication context references this credential.
	CAECredentialCompromised CAEEventType = "credential_compromised"
	// CAERefreshTokenReuse signals that a rotated (already-revoked) refresh
	// token was replayed — the RFC 9700 §4.14 theft signal. The IdP has
	// already revoked the entire token family; subscribing relying parties
	// MUST terminate every session descended from the compromised grant
	// (the `family_id` / `session_id` metadata identifies which). This maps
	// to the OpenID CAEP "token-claims-change" / RISC "session-revoked"
	// event class and is emitted automatically by OAuthProviderService on
	// reuse detection — never call it from policy code.
	CAERefreshTokenReuse CAEEventType = "refresh_token_reuse"
)

// CAEEvent represents a security event that triggers immediate session re-evaluation.
// The Metadata map carries event-specific attributes (e.g., "role_id", "session_id").
type CAEEvent struct {
	Type      CAEEventType      `json:"type"`
	UserID    uuid.UUID         `json:"user_id"`
	TenantID  uuid.UUID         `json:"tenant_id"`
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// CAEPublisher defines the interface for publishing CAE events to a message bus.
// The Redis implementation satisfies this interface via PUBLISH.
type CAEPublisher interface {
	Publish(ctx context.Context, channel string, message []byte) error
}

// caeRedisStore is a narrow interface covering the Redis sorted-set and
// pub/sub operations required by CAEService for history storage and
// tenant-scoped publishing. Using an interface instead of a concrete type
// makes the service straightforward to test with miniredis.
type caeRedisStore interface {
	// Publish sends a message to a Redis pub/sub channel.
	Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd
	// ZAdd adds members to a sorted set.
	ZAdd(ctx context.Context, key string, members ...redis.Z) *redis.IntCmd
	// ZRangeByScore returns members of a sorted set within a score range.
	ZRangeByScore(ctx context.Context, key string, opt *redis.ZRangeBy) *redis.StringSliceCmd
	// Expire sets a TTL on a key.
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}

// CAEService manages continuous access evaluation events.
//
// Publishing strategy — two channels per event:
//   - Legacy broadcast: "hexxlock:cae:events" for backward-compatible listeners.
//   - Tenant-scoped:    "caep:events:{tenant_id}" for the CAERedisSubscriber
//     that fans events out to registered SSE clients.
//
// History storage:
// Each published event is also appended to a per-tenant Redis sorted set
// ("caep:history:{tenant_id}") with the event's Unix nanosecond timestamp as
// the score. This enables the SSE handler to replay missed events after a
// client reconnects using Last-Event-ID.
type CAEService struct {
	// publisher satisfies the legacy CAEPublisher interface used by callers
	// that construct CAEService without a full Redis client.
	publisher CAEPublisher

	// redisStore is optional. When non-nil, events are also published to the
	// tenant-scoped channel and persisted in the history sorted set.
	redisStore caeRedisStore

	// channel is the legacy broadcast pub/sub channel.
	channel string

	// tenantChannelPrefix is the prefix for per-tenant pub/sub channels.
	// Full channel name: "<tenantChannelPrefix>:<tenant_id>"
	tenantChannelPrefix string

	// historyKeyPrefix is the prefix for per-tenant history sorted sets.
	// Full key name: "<historyKeyPrefix>:<tenant_id>"
	historyKeyPrefix string

	// historyTTL is how long to retain events in the history sorted set.
	// Defaults to 24 hours; sufficient for the reconnect catch-up window.
	historyTTL time.Duration

	logger *zap.Logger
}

// NewCAEService constructs a CAEService with only the legacy publisher wired.
// This signature is backward-compatible with existing callers.
//
// Call SetRedisStore to additionally enable tenant-scoped SSE delivery and
// event history for reconnection catch-up.
func NewCAEService(publisher CAEPublisher, logger *zap.Logger) *CAEService {
	return &CAEService{
		publisher:           publisher,
		channel:             "hexxlock:cae:events",
		tenantChannelPrefix: "caep:events",
		historyKeyPrefix:    "caep:history",
		historyTTL:          24 * time.Hour,
		logger:              logger,
	}
}

// SetRedisStore wires a Redis client for tenant-scoped pub/sub and history
// storage. Call this after NewCAEService when the full SSE delivery pipeline
// is required (typically in cmd/services.go).
func (s *CAEService) SetRedisStore(store caeRedisStore) {
	s.redisStore = store
}

// tenantChannel returns the Redis pub/sub channel name for a tenant.
func (s *CAEService) tenantChannel(tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", s.tenantChannelPrefix, tenantID.String())
}

// historyKey returns the Redis sorted-set key for a tenant's event history.
func (s *CAEService) historyKey(tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:%s", s.historyKeyPrefix, tenantID.String())
}

// PublishEvent serialises a CAEEvent to JSON and broadcasts it on:
//  1. The legacy "hexxlock:cae:events" channel (via s.publisher).
//  2. The tenant-scoped "caep:events:{tenant_id}" channel (when redisStore is set).
//
// The event is also appended to the per-tenant history sorted set so that
// reconnecting SSE clients can replay events they missed.
//
// The Timestamp field is always overwritten with the current UTC time
// immediately before publishing to ensure monotonicity.
func (s *CAEService) PublishEvent(ctx context.Context, event CAEEvent) error {
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("CAEService.PublishEvent: failed to marshal event: %w", err)
	}

	// 1. Legacy broadcast channel — maintains backward compatibility.
	if err := s.publisher.Publish(ctx, s.channel, data); err != nil {
		s.logger.Error("CAEService: failed to publish to legacy channel",
			zap.String("type", string(event.Type)),
			zap.String("user_id", event.UserID.String()),
			zap.String("tenant_id", event.TenantID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("CAEService.PublishEvent: %w", err)
	}

	if s.redisStore != nil {
		// 2. Tenant-scoped pub/sub channel for the SSE subscriber.
		if err := s.redisStore.Publish(ctx, s.tenantChannel(event.TenantID), data).Err(); err != nil {
			// Non-fatal: SSE delivery is best-effort. Log the error but do not
			// fail the caller — the security event was already on the legacy
			// channel and any downstream session enforcement will still occur.
			s.logger.Error("CAEService: failed to publish to tenant channel",
				zap.String("tenant_id", event.TenantID.String()),
				zap.Error(err),
			)
		}

		// 3. Persist in history sorted set for reconnect catch-up.
		score := float64(event.Timestamp.UnixNano())
		addCmd := s.redisStore.ZAdd(ctx, s.historyKey(event.TenantID), redis.Z{
			Score:  score,
			Member: string(data),
		})
		if addCmd.Err() != nil {
			s.logger.Warn("CAEService: failed to append event to history",
				zap.String("tenant_id", event.TenantID.String()),
				zap.Error(addCmd.Err()),
			)
		} else {
			// Refresh the sorted set TTL on every write so the window slides
			// with usage rather than expiring from the first event's timestamp.
			_ = s.redisStore.Expire(ctx, s.historyKey(event.TenantID), s.historyTTL)
		}
	}

	s.logger.Info("CAE event published",
		zap.String("type", string(event.Type)),
		zap.String("user_id", event.UserID.String()),
		zap.String("tenant_id", event.TenantID.String()),
	)

	return nil
}

// GetRecentEvents fetches all events for tenantID whose Timestamp is strictly
// after since. This is used by the SSE handler to replay missed events when a
// client reconnects with a Last-Event-ID header.
//
// Returns an empty slice (not an error) when there are no matching events or
// when no Redis history store is configured.
func (s *CAEService) GetRecentEvents(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]CAEEvent, error) {
	if s.redisStore == nil {
		return nil, nil
	}

	// Scores are Unix nanoseconds; add 1 to make the range exclusive of `since`.
	minScore := strconv.FormatInt(since.UnixNano()+1, 10)

	results, err := s.redisStore.ZRangeByScore(ctx, s.historyKey(tenantID), &redis.ZRangeBy{
		Min: minScore,
		Max: "+inf",
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("CAEService.GetRecentEvents: %w", err)
	}

	events := make([]CAEEvent, 0, len(results))
	for _, raw := range results {
		var ev CAEEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			s.logger.Warn("CAEService.GetRecentEvents: skipping malformed event",
				zap.String("tenant_id", tenantID.String()),
				zap.Error(err),
			)
			continue
		}
		events = append(events, ev)
	}

	return events, nil
}

// OnPasswordChanged publishes a CAEPasswordChanged event. Call this immediately
// after persisting a password change so that downstream subscribers can revoke
// sessions that were issued under the previous credential.
func (s *CAEService) OnPasswordChanged(ctx context.Context, userID, tenantID uuid.UUID) error {
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAEPasswordChanged,
		UserID:   userID,
		TenantID: tenantID,
	})
}

// OnAccountLocked publishes a CAEAccountLocked event, signalling that all active
// sessions for this user should be terminated immediately.
func (s *CAEService) OnAccountLocked(ctx context.Context, userID, tenantID uuid.UUID) error {
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAEAccountLocked,
		UserID:   userID,
		TenantID: tenantID,
	})
}

// OnMFARevoked publishes a CAEMFARevoked event. Subscribers should re-evaluate
// whether the user's remaining MFA methods still satisfy the current policy.
func (s *CAEService) OnMFARevoked(ctx context.Context, userID, tenantID uuid.UUID) error {
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAEMFARevoked,
		UserID:   userID,
		TenantID: tenantID,
	})
}

// OnRoleRevoked publishes a CAERoleRevoked event with the affected role ID in the
// Metadata map. Subscribers can use the role ID to check whether any live session
// token references the removed role and must be downgraded or revoked.
func (s *CAEService) OnRoleRevoked(ctx context.Context, userID, tenantID uuid.UUID, roleID uuid.UUID) error {
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAERoleRevoked,
		UserID:   userID,
		TenantID: tenantID,
		Metadata: map[string]string{
			"role_id": roleID.String(),
		},
	})
}

// OnCredentialCompromised publishes a CAECredentialCompromised event with the
// affected credential's ID in the Metadata map. Subscribers should immediately
// revoke any active session whose amr/acr context references this credential
// (i.e. any passkey-authenticated session for this user). Emitted automatically
// by WebAuthnService when sign-count regression is detected — never call this
// directly from policy code.
func (s *CAEService) OnCredentialCompromised(ctx context.Context, userID, tenantID, credentialID uuid.UUID) error {
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAECredentialCompromised,
		UserID:   userID,
		TenantID: tenantID,
		Metadata: map[string]string{
			"credential_id": credentialID.String(),
		},
	})
}

// OnIPChanged publishes a CAEIPChanged event when the request IP on a
// refresh-token grant (or other recurring session signal) differs from the
// IP captured at original token issuance. Per OpenID CAEP §5.3 this is a
// signal, not enforcement — receivers (Talon IAP, SIEM) decide whether
// the change violates a conditional-access policy and revoke the session
// downstream. The metadata carries both IPs verbatim plus an optional
// session_id when the caller can resolve one (e.g. from token.IdpSessionID).
func (s *CAEService) OnIPChanged(ctx context.Context, userID, tenantID uuid.UUID, oldIP, newIP string, sessionID *uuid.UUID) error {
	md := map[string]string{
		"old_ip": oldIP,
		"new_ip": newIP,
	}
	if sessionID != nil {
		md["session_id"] = sessionID.String()
	}
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAEIPChanged,
		UserID:   userID,
		TenantID: tenantID,
		Metadata: md,
	})
}

// OnRefreshTokenReuse publishes a CAERefreshTokenReuse event after the OAuth
// provider has detected a replayed (already-revoked) refresh token and revoked
// the entire token family per RFC 9700 §4.14. This is the token-theft signal:
// subscribing relying parties (Talon IAP, SIEM, and any RP with an active
// session descended from the compromised grant) MUST terminate those sessions
// immediately rather than waiting for their next token refresh. The metadata
// carries the revoked family_id and, when resolvable, the idp session_id so
// receivers can scope the revocation precisely. Best-effort — the family has
// already been revoked in the token store before this fires, so a publish
// failure never leaves the compromised tokens live; it only delays downstream
// session teardown to the next introspection/refresh.
func (s *CAEService) OnRefreshTokenReuse(ctx context.Context, userID, tenantID, familyID uuid.UUID, sessionID *uuid.UUID) error {
	md := map[string]string{
		"family_id": familyID.String(),
		"reason":    "refresh_token_reuse_detected",
	}
	if sessionID != nil {
		md["session_id"] = sessionID.String()
	}
	return s.PublishEvent(ctx, CAEEvent{
		Type:     CAERefreshTokenReuse,
		UserID:   userID,
		TenantID: tenantID,
		Metadata: md,
	})
}
