// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// TokenBlacklist handles JWT token blacklisting in Redis
type TokenBlacklist struct {
	client *Client
	prefix string
}

// NewTokenBlacklist creates a new token blacklist
func NewTokenBlacklist(client *Client, prefix string) *TokenBlacklist {
	return &TokenBlacklist{
		client: client,
		prefix: prefix,
	}
}

func (t *TokenBlacklist) tokenKey(jti string) string {
	return fmt.Sprintf("%s:blacklist:token:%s", t.prefix, jti)
}

// realmTokenKey returns the realm-scoped blacklist key for a JWT token.
// Scoping the key by realm allows per-realm blacklist operations and prevents
// a token JTI collision in one realm from affecting another realm's blacklist.
func (t *TokenBlacklist) realmTokenKey(realmID uuid.UUID, jti string) string {
	return fmt.Sprintf("%s:realm:%s:blacklist:token:%s", t.prefix, realmID.String(), jti)
}

func (t *TokenBlacklist) userTokensKey(userID uuid.UUID) string {
	return fmt.Sprintf("%s:blacklist:user:%s", t.prefix, userID.String())
}

// realmUserTokensKey returns the realm-scoped set key that tracks all blacklisted
// token JTIs for a user within a realm.  This enables efficient per-realm bulk
// revocation without scanning keys from unrelated realms.
func (t *TokenBlacklist) realmUserTokensKey(realmID, userID uuid.UUID) string {
	return fmt.Sprintf("%s:realm:%s:blacklist:user:%s", t.prefix, realmID.String(), userID.String())
}

// Blacklist adds a token to the blacklist
// The token will be automatically removed after the TTL expires
func (t *TokenBlacklist) Blacklist(ctx context.Context, jti string, reason string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	return t.client.Redis().Set(ctx, t.tokenKey(jti), reason, ttl).Err()
}

// BlacklistWithUserID blacklists a token and associates it with a user ID for bulk revocation
func (t *TokenBlacklist) BlacklistWithUserID(ctx context.Context, jti string, userID uuid.UUID, reason string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	pipe := t.client.Redis().Pipeline()
	pipe.Set(ctx, t.tokenKey(jti), reason, ttl)
	pipe.SAdd(ctx, t.userTokensKey(userID), jti)
	pipe.Expire(ctx, t.userTokensKey(userID), ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("BlacklistWithUserID: Exec failed: %w", err)
	}
	return nil
}

// IsBlacklisted checks if a token is blacklisted
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior
// If Redis is unavailable, we cannot verify if a token is blacklisted, so we must deny access
func (t *TokenBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	result, err := t.client.Redis().Exists(ctx, t.tokenKey(jti)).Result()
	if err != nil {
		// SECURITY: Fail-closed - if we cannot verify blacklist status, deny access
		return false, &UnavailableError{
			Operation: "token blacklist check",
			Err:       err,
		}
	}
	return result > 0, nil
}

// GetBlacklistReason returns the reason a token was blacklisted
func (t *TokenBlacklist) GetBlacklistReason(ctx context.Context, jti string) (string, error) {
	reason, err := t.client.Redis().Get(ctx, t.tokenKey(jti)).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("GetBlacklistReason: %w", err)
	}
	return reason, nil
}

// Remove removes a token from the blacklist (use with caution)
func (t *TokenBlacklist) Remove(ctx context.Context, jti string) error {
	return t.client.Redis().Del(ctx, t.tokenKey(jti)).Err()
}

// BlacklistUserTokens blacklists all tokens for a user
// This is useful when a user's password is changed or account is compromised
func (t *TokenBlacklist) BlacklistUserTokens(ctx context.Context, userID uuid.UUID, reason string, ttl time.Duration) error {
	// We use a special key to indicate all tokens for a user should be considered blacklisted
	// This is checked in addition to individual token blacklisting
	key := fmt.Sprintf("%s:blacklist:user_all:%s", t.prefix, userID.String())
	return t.client.Redis().Set(ctx, key, reason, ttl).Err()
}

// IsUserBlacklisted checks if all tokens for a user are blacklisted
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior
func (t *TokenBlacklist) IsUserBlacklisted(ctx context.Context, userID uuid.UUID) (bool, error) {
	key := fmt.Sprintf("%s:blacklist:user_all:%s", t.prefix, userID.String())
	result, err := t.client.Redis().Exists(ctx, key).Result()
	if err != nil {
		// SECURITY: Fail-closed - if we cannot verify user blacklist, deny access
		return false, &UnavailableError{
			Operation: "user blacklist check",
			Err:       err,
		}
	}
	return result > 0, nil
}

// CheckToken checks if a token or its user is blacklisted
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior
func (t *TokenBlacklist) CheckToken(ctx context.Context, jti string, userID uuid.UUID) (blacklisted bool, reason string, err error) {
	// Check user-level blacklist first
	userBlacklisted, err := t.IsUserBlacklisted(ctx, userID)
	if err != nil {
		// SECURITY: Fail-closed - propagate UnavailableError
		return false, "", fmt.Errorf("CheckToken: IsUserBlacklisted failed: %w", err)
	}
	if userBlacklisted {
		return true, "user_tokens_revoked", nil
	}

	// Check individual token blacklist
	isBlacklisted, err := t.IsBlacklisted(ctx, jti)
	if err != nil {
		// SECURITY: Fail-closed - propagate UnavailableError
		return false, "", fmt.Errorf("CheckToken: IsBlacklisted failed: %w", err)
	}
	if isBlacklisted {
		reason, _ = t.GetBlacklistReason(ctx, jti)
		return true, reason, nil
	}

	return false, "", nil
}

// sessionKey returns the Redis key for a session blacklist entry
func (t *TokenBlacklist) sessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s:blacklist:session:%s", t.prefix, sessionID.String())
}

// BlacklistSession adds a session to the blacklist
// This will cause all tokens with this session ID to be rejected
func (t *TokenBlacklist) BlacklistSession(ctx context.Context, sessionID uuid.UUID, reason string, ttl time.Duration) error {
	if ttl <= 0 {
		// Use a default TTL of 24 hours if not specified
		ttl = 24 * time.Hour
	}
	return t.client.Redis().Set(ctx, t.sessionKey(sessionID), reason, ttl).Err()
}

// IsSessionBlacklisted checks if a session is blacklisted
// SECURITY: Returns UnavailableError if Redis is down to enforce fail-closed behavior
func (t *TokenBlacklist) IsSessionBlacklisted(ctx context.Context, sessionID uuid.UUID) (bool, string, error) {
	reason, err := t.client.Redis().Get(ctx, t.sessionKey(sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, "", nil
	}
	if err != nil {
		// SECURITY: Fail-closed - if we cannot verify session blacklist, deny access
		return false, "", &UnavailableError{
			Operation: "session blacklist check",
			Err:       err,
		}
	}
	return true, reason, nil
}
