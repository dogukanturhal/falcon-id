// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// UnavailableError indicates Redis is unavailable and operations cannot be verified
// SECURITY: This error type is used to enforce fail-closed behavior
type UnavailableError struct {
	Operation string
	Err       error
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("redis unavailable for %s: %v", e.Operation, e.Err)
}

func (e *UnavailableError) Unwrap() error {
	return e.Err
}

// IsRedisUnavailableError checks if an error is a UnavailableError
func IsRedisUnavailableError(err error) bool {
	var redisErr *UnavailableError
	return errors.As(err, &redisErr)
}

// SessionCache handles session caching in Redis
type SessionCache struct {
	client *Client
	prefix string
	ttl    time.Duration

	// roleVersionHook, when set, is invoked with the new version after every
	// successful IncrementRoleVersion. It lets the DDIL offline-authz layer
	// (P3.2) learn a revocation-epoch bump immediately, so cached offline
	// decisions under an older epoch are voided even while SpiceDB is
	// unreachable. Optional; set once during wiring.
	roleVersionHook func(tenantID uuid.UUID, version int64)
}

// SetRoleVersionHook registers a callback fired after each role-version bump so
// the per-tenant revocation epoch can be propagated to the DDIL offline-authz
// layer. Pass nil to clear. Set once during wiring (not concurrency-guarded).
func (s *SessionCache) SetRoleVersionHook(hook func(tenantID uuid.UUID, version int64)) {
	s.roleVersionHook = hook
}

// Client returns the underlying Redis client for direct key-value operations
func (s *SessionCache) Client() *Client {
	return s.client
}

// CachedSession represents a cached user session (legacy format).
//
// Deprecated: Use SessionData from models package for new implementations.
type CachedSession struct {
	SessionID   uuid.UUID `json:"session_id"`
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	DeviceInfo  string    `json:"device_info,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ProductSubscriptionClaim represents an active product subscription stored in session data.
// Mirrors models.ProductSubscriptionClaim to avoid circular imports between redis and models packages.
type ProductSubscriptionClaim struct {
	ProductID   uuid.UUID `json:"pid"`
	ProductSlug string    `json:"slug"`
	PlanID      *string   `json:"plan,omitempty"`
	// State mirrors models.ProductSubscriptionClaim.State — "" (active),
	// "provisioning", or "failed".
	State string `json:"state,omitempty"`
}

// SessionData represents the full user context stored in Redis for minimal JWT tokens
// This is the preferred format for new implementations
// Redis Key Format: hexxlock:session:{sessionID}
type SessionData struct {
	// User identification
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`

	// Authorization context
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"` // Full permissions list

	// Product subscriptions — active product subscriptions for the tenant.
	// Cached alongside permissions so token refresh can re-populate JWT claims
	// without an extra DB round-trip.
	ProductSubscriptions []ProductSubscriptionClaim `json:"product_subscriptions,omitempty"`

	// Realm context for multi-realm architecture
	RealmID   uuid.UUID `json:"realm_id"`
	RealmSlug string    `json:"realm_slug,omitempty"`
	RealmType string    `json:"realm_type,omitempty"`

	// RoleVersion is used for cache invalidation
	RoleVersion int64 `json:"role_version"`

	// Session metadata
	DeviceInfo string `json:"device_info,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	CreatedAt  int64  `json:"created_at"` // Unix timestamp

	// Impersonation context (optional)
	ImpersonatorID         *uuid.UUID `json:"impersonator_id,omitempty"`
	ImpersonationSessionID *uuid.UUID `json:"impersonation_session_id,omitempty"`

	// Platform admin flag - computed server-side based on tenant membership
	IsPlatformAdmin bool `json:"is_platform_admin,omitempty"`

	// ClientID preserves the app audience scope across token refreshes
	ClientID string `json:"client_id,omitempty"`
}

// IsImpersonated returns true if this session represents an impersonated user
func (s *SessionData) IsImpersonated() bool {
	return s.ImpersonatorID != nil
}

// NewSessionCache creates a new session cache
func NewSessionCache(client *Client, prefix string, ttl time.Duration) *SessionCache {
	return &SessionCache{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

func (s *SessionCache) sessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s:session:%s", s.prefix, sessionID.String())
}

func (s *SessionCache) userSessionsKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s:user:%s:sessions", s.prefix, userID.String())
}

// realmSessionKey returns the realm-scoped session key (new format).
// Having realm_id in the key prevents cross-realm key collisions and
// enables per-realm cache invalidation without scanning all sessions.
func (s *SessionCache) realmSessionKey(realmID, sessionID uuid.UUID) string {
	return fmt.Sprintf("%s:realm:%s:session:%s", s.prefix, realmID.String(), sessionID.String())
}

// realmUserSessionsKey returns the realm-scoped user sessions set key (new format).
// Sessions within a realm are tracked separately from sessions in other realms,
// so realm-scoped bulk invalidation does not touch unrelated realms.
func (s *SessionCache) realmUserSessionsKey(realmID, userID uuid.UUID) string {
	return fmt.Sprintf("%s:realm:%s:user:%s:sessions", s.prefix, realmID.String(), userID.String())
}

// Set stores a session in the cache
func (s *SessionCache) Set(ctx context.Context, session *CachedSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	pipe := s.client.Redis().Pipeline()

	// Store the session
	pipe.Set(ctx, s.sessionKey(session.SessionID), data, s.ttl)

	// Add to user's session set
	pipe.SAdd(ctx, s.userSessionsKey(session.UserID), session.SessionID.String())
	pipe.Expire(ctx, s.userSessionsKey(session.UserID), s.ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("Set: Exec failed: %w", err)
	}
	return nil
}

// Get retrieves a session from the cache.
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior.
// Uses sliding TTL to extend key expiration on every successful read.
func (s *SessionCache) Get(ctx context.Context, sessionID uuid.UUID) (*CachedSession, error) {
	key := s.sessionKey(sessionID)
	data, err := s.client.Redis().Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		// SECURITY: Fail-closed - if Redis is unavailable, return a specific error
		// that will be handled by the authentication middleware to deny access
		return nil, &UnavailableError{
			Operation: "session retrieval",
			Err:       err,
		}
	}

	var session CachedSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Sliding TTL: extend expiration on every successful read (fire-and-forget).
	_ = s.client.Redis().Expire(ctx, key, s.ttl)

	return &session, nil
}

// Delete removes a session from the cache
func (s *SessionCache) Delete(ctx context.Context, sessionID uuid.UUID) error {
	// First get the session to find the user ID
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("Delete: Get failed: %w", err)
	}

	pipe := s.client.Redis().Pipeline()

	// Delete the session
	pipe.Del(ctx, s.sessionKey(sessionID))

	// Remove from user's session set if we have the session
	if session != nil {
		pipe.SRem(ctx, s.userSessionsKey(session.UserID), sessionID.String())
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("Delete: Exec failed: %w", err)
	}
	return nil
}

// DeleteUserSessions removes all sessions for a user
func (s *SessionCache) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	// Get all session IDs for the user
	sessionIDs, err := s.client.Redis().SMembers(ctx, s.userSessionsKey(userID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("DeleteUserSessions: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil
	}

	// Build keys to delete
	keys := make([]string, 0, len(sessionIDs)+1)
	for _, sid := range sessionIDs {
		if uid, err := uuid.Parse(sid); err == nil {
			keys = append(keys, s.sessionKey(uid))
		}
	}
	keys = append(keys, s.userSessionsKey(userID))

	return s.client.Redis().Del(ctx, keys...).Err()
}

// Exists checks if a session exists in the cache
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior
func (s *SessionCache) Exists(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	result, err := s.client.Redis().Exists(ctx, s.sessionKey(sessionID)).Result()
	if err != nil {
		// SECURITY: Fail-closed - cannot verify session existence
		return false, &UnavailableError{
			Operation: "session existence check",
			Err:       err,
		}
	}
	return result > 0, nil
}

// Refresh extends the TTL of a session
func (s *SessionCache) Refresh(ctx context.Context, sessionID uuid.UUID) error {
	session, err := s.Get(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("Refresh: Get failed: %w", err)
	}
	if session == nil {
		return nil
	}

	pipe := s.client.Redis().Pipeline()
	pipe.Expire(ctx, s.sessionKey(sessionID), s.ttl)
	pipe.Expire(ctx, s.userSessionsKey(session.UserID), s.ttl)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("Refresh: Exec failed: %w", err)
	}
	return nil
}

// GetUserSessionCount returns the number of active sessions for a user
func (s *SessionCache) GetUserSessionCount(ctx context.Context, userID uuid.UUID) (int64, error) {
	return s.client.Redis().SCard(ctx, s.userSessionsKey(userID)).Result()
}

// SetSessionData stores full session data in Redis for minimal JWT tokens.
// This is the preferred method for storing session context with minimal tokens.
//
// Dual-write strategy: the session is written to both the legacy flat key and
// the new realm-scoped key so that old readers continue to work while new code
// migrates to realm-aware lookups.  Old flat keys expire naturally via TTL —
// no explicit migration step is required.
func (s *SessionCache) SetSessionData(ctx context.Context, sessionID uuid.UUID, data *SessionData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	pipe := s.client.Redis().Pipeline()

	// Legacy flat key — keeps existing readers working during the migration window.
	pipe.Set(ctx, s.sessionKey(sessionID), jsonData, s.ttl)
	pipe.SAdd(ctx, s.userSessionsKey(data.UserID), sessionID.String())
	pipe.Expire(ctx, s.userSessionsKey(data.UserID), s.ttl)

	// Realm-scoped key — written whenever a non-zero RealmID is available.
	// This enables future per-realm cache invalidation and prevents cross-realm
	// key collisions once all readers are migrated to realm-aware lookups.
	if data.RealmID != (uuid.UUID{}) {
		pipe.Set(ctx, s.realmSessionKey(data.RealmID, sessionID), jsonData, s.ttl)
		pipe.SAdd(ctx, s.realmUserSessionsKey(data.RealmID, data.UserID), sessionID.String())
		pipe.Expire(ctx, s.realmUserSessionsKey(data.RealmID, data.UserID), s.ttl)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("SetSessionData: Exec failed: %w", err)
	}
	return nil
}

// GetSessionData retrieves full session data from Redis for minimal JWT tokens.
// Returns nil if the session is not found.
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior.
// PERFORMANCE: Uses sliding TTL -- every successful read extends the key's expiration,
// ensuring active sessions never evict from cache prematurely. This does NOT extend the
// session's security boundary (which is enforced by PostgreSQL expires_at and blacklist checks).
func (s *SessionCache) GetSessionData(ctx context.Context, sessionID uuid.UUID) (*SessionData, error) {
	key := s.sessionKey(sessionID)
	data, err := s.client.Redis().Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		// SECURITY: Fail-closed - if Redis is unavailable, we cannot verify the session
		// Return specific error to trigger service unavailable response
		return nil, &UnavailableError{
			Operation: "session data retrieval",
			Err:       err,
		}
	}

	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Sliding TTL: extend expiration on every successful read.
	// This is fire-and-forget -- a failure here does not affect the current request
	// and the next read will retry the extension.
	_ = s.client.Redis().Expire(ctx, key, s.ttl)

	return &sessionData, nil
}

// ExpireSessionData sets a short TTL on a session key instead of deleting it immediately.
// This provides a grace period for in-flight requests that still reference the old session ID
// (e.g., during session rotation on token refresh). The key will auto-expire after the grace period.
func (s *SessionCache) ExpireSessionData(ctx context.Context, sessionID uuid.UUID, gracePeriod time.Duration) error {
	key := s.sessionKey(sessionID)
	return s.client.Redis().Expire(ctx, key, gracePeriod).Err()
}

// DeleteSessionData removes session data from Redis.
// This is used when logging out or when a session is revoked.
//
// Both the legacy flat key and the realm-scoped key (if one was written) are
// deleted atomically so no stale entries remain in either key-space.
func (s *SessionCache) DeleteSessionData(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID) error {
	// Fetch the stored data first so we can derive the realm-scoped keys.
	// The read is best-effort: if the key is already gone we still attempt the
	// delete pipeline so that set-membership entries are also cleaned up.
	existing, _ := s.GetSessionData(ctx, sessionID)

	pipe := s.client.Redis().Pipeline()

	// Always remove the legacy flat key and the flat user-sessions set.
	pipe.Del(ctx, s.sessionKey(sessionID))
	pipe.SRem(ctx, s.userSessionsKey(userID), sessionID.String())

	// Also remove the realm-scoped keys when the realm is known.
	if existing != nil && existing.RealmID != (uuid.UUID{}) {
		pipe.Del(ctx, s.realmSessionKey(existing.RealmID, sessionID))
		pipe.SRem(ctx, s.realmUserSessionsKey(existing.RealmID, userID), sessionID.String())
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("DeleteSessionData: Exec failed: %w", err)
	}
	return nil
}

// InvalidateUserSessionsByRoleVersion invalidates all sessions for a user with an old role version
// This is used when user roles/permissions are updated to force re-authentication
func (s *SessionCache) InvalidateUserSessionsByRoleVersion(ctx context.Context, userID uuid.UUID, minRoleVersion int64) error {
	// Get all session IDs for the user
	sessionIDs, err := s.client.Redis().SMembers(ctx, s.userSessionsKey(userID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("InvalidateUserSessionsByRoleVersion: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil
	}

	// Check each session and delete if role version is outdated
	for _, sidStr := range sessionIDs {
		sid, err := uuid.Parse(sidStr)
		if err != nil {
			continue
		}

		sessionData, err := s.GetSessionData(ctx, sid)
		if err != nil || sessionData == nil {
			continue
		}

		// If session has outdated role version, delete it
		if sessionData.RoleVersion < minRoleVersion {
			if err := s.DeleteSessionData(ctx, sid, userID); err != nil {
				// Log error but continue with other sessions
				continue
			}
		}
	}

	return nil
}

// IdpSessionData is the minimal identity record stored for the IdP-level SSO cookie.
// It lives under a separate key namespace so it outlives the short-lived access token
// and survives across multiple OIDC client sessions (same-IdP SSO).
//
// Username/Email are cached so the IdP-cookie auth path (resolveIdpSessionCookie
// in internal/middleware/auth.go) can populate CurrentUser without a per-request
// DB hit — audit logs and any handler reading CurrentUser.Username/Email then
// see the right values regardless of whether the request was authenticated by
// access token or by cookie.
//
// AuthTime is the Unix timestamp of the original authentication event
// (RFC 9470 §3 / OIDC Core §2 `auth_time`). It powers RequireFreshAuth gates
// for the cookie-auth path the same way the JWT auth_time claim does for the
// token-auth path: sensitive endpoints (password change, MFA disable, session
// revoke) refuse stale sessions.
type IdpSessionData struct {
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Username string    `json:"username,omitempty"`
	Email    string    `json:"email,omitempty"`
	AuthTime int64     `json:"auth_time,omitempty"`
	// SessionID is the iam_user_sessions.id row created at login time
	// — the same UUID the access token carries in its session_id claim
	// (RFC 7519 jti-equivalent for our domain). It is NOT the same as
	// the falcon_idp_session cookie value (which is the Redis key of
	// THIS very record). Carrying it here lets the cookie-only auth
	// path (resolveIdpSessionCookie) populate the gin context's
	// "session_id" with the canonical iam_user_sessions.id so any
	// downstream code keyed on that row — notably
	// MFAHandler.elevateCurrentSessionAMR which calls
	// sessionRepo.AppendAuthMethod(ctx, sessionID, "mfa") to update
	// auth_methods_used on the session row — finds the right row to
	// update. Before this field landed, cookie-auth callers silently
	// passed the IdP cookie UUID (Redis key) to AppendAuthMethod,
	// which matched no iam_user_sessions row, the UPDATE affected 0
	// rows, and the OAuth step-up gate looped forever because AMR
	// never gained "mfa". Live repro 2026-05-12 (this commit).
	SessionID uuid.UUID `json:"session_id,omitempty"`
}

func (s *SessionCache) idpSessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s:idp_session:%s", s.prefix, sessionID.String())
}

const idpSessionTTL = 7 * 24 * time.Hour

// SetIdpSession stores an IdP-level SSO session entry with a 7-day TTL.
func (s *SessionCache) SetIdpSession(ctx context.Context, sessionID uuid.UUID, data *IdpSessionData) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("SetIdpSession: marshal: %w", err)
	}
	return s.client.Redis().Set(ctx, s.idpSessionKey(sessionID), payload, idpSessionTTL).Err()
}

// GetIdpSession retrieves an IdP-level SSO session.
// Returns nil (no error) when the key does not exist.
// Returns UnavailableError when Redis is unreachable so callers can degrade gracefully.
func (s *SessionCache) GetIdpSession(ctx context.Context, sessionID uuid.UUID) (*IdpSessionData, error) {
	data, err := s.client.Redis().Get(ctx, s.idpSessionKey(sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, &UnavailableError{Operation: "idp session retrieval", Err: err}
	}
	var out IdpSessionData
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("GetIdpSession: unmarshal: %w", err)
	}
	// Sliding TTL — extends on every read so active SSO sessions don't expire mid-use.
	_ = s.client.Redis().Expire(ctx, s.idpSessionKey(sessionID), idpSessionTTL)
	return &out, nil
}

// DeleteIdpSession removes an IdP-level SSO session (called on logout).
func (s *SessionCache) DeleteIdpSession(ctx context.Context, sessionID uuid.UUID) error {
	return s.client.Redis().Del(ctx, s.idpSessionKey(sessionID)).Err()
}

// GetIdpSessionAuthTime is the narrow lookup the OAuth provider
// service uses to stamp the RFC 9470 §6.1 / OIDC Core §2 `auth_time`
// claim on /oauth/token-minted access tokens. Returns (authTime, true,
// nil) when the session is found, (0, false, nil) when not found,
// and (_, _, err) when Redis is unreachable.
//
// Decoupled from GetIdpSession above so callers that only need the
// AuthTime field don't pay the cost of full IdpSessionData unmarshal
// and don't extend the sliding TTL — the OAuth mint path is a write-
// side hot path that shouldn't be affecting SSO session lifetime as
// a side effect.
func (s *SessionCache) GetIdpSessionAuthTime(ctx context.Context, sessionID uuid.UUID) (int64, bool, error) {
	data, err := s.client.Redis().Get(ctx, s.idpSessionKey(sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, false, nil
		}
		return 0, false, &UnavailableError{Operation: "idp session AuthTime retrieval", Err: err}
	}
	var out IdpSessionData
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, false, fmt.Errorf("GetIdpSessionAuthTime: unmarshal: %w", err)
	}
	return out.AuthTime, true, nil
}

// DeleteAllIdpSessionsByUser removes every IdP SSO session entry whose
// IdpSessionData.UserID matches userID. Used by /api/v1/auth/logout
// when the caller authenticated via a Bearer access token that does
// not carry a session_id / sid claim (the OAuth access tokens issued
// to RPs like accounts.hexxlock.com only carry sub/aud/scope, not the
// IdP session ID — that's intentional per OIDC, but it means the
// RP-initiated logout has no per-session identifier to scope the
// cleanup to). Falls back to "log out everywhere" semantics for that
// caller, which matches user intent (clicking "Sign out" on one app
// should not leave silent-SSO live for the next visit).
//
// Implementation uses SCAN+GET+DEL. Scope is the IdP-session keyspace
// only — `{prefix}:idp_session:*` — so it doesn't touch refresh-token
// rotation state, OAuth tokens, etc. With a 7-day TTL on entries the
// hot keyspace is small, so the scan is bounded; we still bound the
// scan with COUNT to avoid blocking Redis on a runaway prefix.
//
// Returns the count of sessions deleted (zero is success — user had
// no live IdP sessions, e.g. already logged out elsewhere).
func (s *SessionCache) DeleteAllIdpSessionsByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	pattern := fmt.Sprintf("%s:idp_session:*", s.prefix)
	var cursor uint64
	deleted := 0
	for {
		keys, next, err := s.client.Redis().Scan(ctx, cursor, pattern, 256).Result()
		if err != nil {
			return deleted, &UnavailableError{Operation: "idp session scan", Err: err}
		}
		for _, k := range keys {
			data, err := s.client.Redis().Get(ctx, k).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue // expired between SCAN and GET — fine
				}
				// Don't fail the whole logout on a single stale key.
				continue
			}
			var entry IdpSessionData
			if err := json.Unmarshal(data, &entry); err != nil {
				continue // unreadable entry — leave it, TTL will harvest
			}
			if entry.UserID != userID {
				continue
			}
			if delErr := s.client.Redis().Del(ctx, k).Err(); delErr == nil {
				deleted++
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return deleted, nil
}

// PermissionInvalidationChannel is the Redis pub/sub channel for permission changes
const PermissionInvalidationChannel = "hexxlock:permission:invalidate"

// PermissionInvalidationMessage represents a permission change event
type PermissionInvalidationMessage struct {
	Type      string    `json:"type"` // "role_revoked", "permission_changed", "session_killed"
	TenantID  uuid.UUID `json:"tenant_id"`
	UserID    uuid.UUID `json:"user_id"`
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason"`
}

// PublishPermissionInvalidation publishes a permission invalidation event
// Accepts interface{} to satisfy the services.SessionCache interface
func (s *SessionCache) PublishPermissionInvalidation(ctx context.Context, msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal invalidation message: %w", err)
	}

	return s.client.Redis().Publish(ctx, PermissionInvalidationChannel, data).Err()
}

// roleVersionKey returns the Redis key for tenant role version
func (s *SessionCache) roleVersionKey(tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:tenant:%s:role_version", s.prefix, tenantID.String())
}

// GetRoleVersion gets the current role version for a tenant
func (s *SessionCache) GetRoleVersion(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	result, err := s.client.Redis().Get(ctx, s.roleVersionKey(tenantID)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil // No version set yet
	}
	if err != nil {
		return 0, fmt.Errorf("GetRoleVersion: %w", err)
	}
	return result, nil
}

// IncrementRoleVersion increments and returns the new role version for a tenant
func (s *SessionCache) IncrementRoleVersion(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	version, err := s.client.Redis().Incr(ctx, s.roleVersionKey(tenantID)).Result()
	if err != nil {
		return version, err
	}
	// DDIL P3.2: propagate the new revocation epoch to any registered
	// offline-authz layer so cached offline decisions carrying an older epoch
	// are voided immediately, without waiting for the next online re-stamp.
	if s.roleVersionHook != nil {
		s.roleVersionHook(tenantID, version)
	}
	return version, nil
}
