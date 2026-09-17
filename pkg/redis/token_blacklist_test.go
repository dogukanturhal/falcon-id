// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const testUserTokensRevoked = "user_tokens_revoked" //nolint:gosec // test fixture value, not a real credential

func setupTestTokenBlacklist(t *testing.T) (*TokenBlacklist, *miniredis.Miniredis, *Client) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create miniredis: %v", err)
	}

	cfg := &Config{
		URL:          "redis://" + mr.Addr(),
		MaxRetries:   3,
		MinIdleConns: 1,
		DialTimeout:  5 * time.Second,
	}

	logger := zap.NewNop()
	client, err := NewClient(cfg, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("Failed to create client: %v", err)
	}

	blacklist := NewTokenBlacklist(client, "test")

	return blacklist, mr, client
}

func TestNewTokenBlacklist(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	if blacklist == nil {
		t.Fatal("NewTokenBlacklist() returned nil")
	}

	if blacklist.client == nil {
		t.Fatal("TokenBlacklist client is nil")
	}

	if blacklist.prefix != "test" {
		t.Errorf("TokenBlacklist prefix = %q, want %q", blacklist.prefix, "test")
	}
}

func TestTokenBlacklist_Blacklist(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	tests := []struct {
		name      string
		jti       string
		reason    string
		expiresAt time.Time
		wantErr   bool
	}{
		{
			name:      "Blacklist valid token",
			jti:       "token-123",
			reason:    "user_logout",
			expiresAt: time.Now().Add(1 * time.Hour),
			wantErr:   false,
		},
		{
			name:      "Blacklist with different reason",
			jti:       "token-456",
			reason:    "security_breach",
			expiresAt: time.Now().Add(2 * time.Hour),
			wantErr:   false,
		},
		{
			name:      "Blacklist expired token",
			jti:       "token-789",
			reason:    "expired",
			expiresAt: time.Now().Add(-1 * time.Hour), // Already expired
			wantErr:   false,                          // Should not error, just skip
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := blacklist.Blacklist(ctx, tt.jti, tt.reason, tt.expiresAt)
			if (err != nil) != tt.wantErr {
				t.Errorf("Blacklist() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify blacklist state based on token expiry
			assertBlacklistState(ctx, t, blacklist, tt.jti, tt.reason, tt.expiresAt)
		})
	}
}

func TestTokenBlacklist_IsBlacklisted(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Non-blacklisted token", func(t *testing.T) {
		jti := "non-blacklisted-token"
		isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
		if err != nil {
			t.Fatalf("IsBlacklisted() error = %v", err)
		}
		if isBlacklisted {
			t.Error("Token should not be blacklisted")
		}
	})

	t.Run("Blacklisted token", func(t *testing.T) {
		jti := "blacklisted-token"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := blacklist.Blacklist(ctx, jti, "test", expiresAt)
		if err != nil {
			t.Fatalf("Blacklist() error = %v", err)
		}

		isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
		if err != nil {
			t.Fatalf("IsBlacklisted() error = %v", err)
		}
		if !isBlacklisted {
			t.Error("Token should be blacklisted")
		}
	})
}

func TestTokenBlacklist_GetBlacklistReason(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Get reason for blacklisted token", func(t *testing.T) {
		jti := "token-with-reason"
		expectedReason := "password_changed"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := blacklist.Blacklist(ctx, jti, expectedReason, expiresAt)
		if err != nil {
			t.Fatalf("Blacklist() error = %v", err)
		}

		reason, err := blacklist.GetBlacklistReason(ctx, jti)
		if err != nil {
			t.Fatalf("GetBlacklistReason() error = %v", err)
		}

		if reason != expectedReason {
			t.Errorf("Reason = %q, want %q", reason, expectedReason)
		}
	})

	t.Run("Get reason for non-blacklisted token", func(t *testing.T) {
		jti := "non-existent-token"

		reason, err := blacklist.GetBlacklistReason(ctx, jti)
		if err != nil {
			t.Fatalf("GetBlacklistReason() error = %v", err)
		}

		if reason != "" {
			t.Errorf("Reason = %q, want empty string", reason)
		}
	})
}

func TestTokenBlacklist_Remove(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	jti := "token-to-remove"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Blacklist the token
	err := blacklist.Blacklist(ctx, jti, "test", expiresAt)
	if err != nil {
		t.Fatalf("Blacklist() error = %v", err)
	}

	// Verify it's blacklisted
	isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted before removal")
	}

	// Remove from blacklist
	err = blacklist.Remove(ctx, jti)
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	// Verify it's no longer blacklisted
	isBlacklisted, err = blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if isBlacklisted {
		t.Error("Token should not be blacklisted after removal")
	}
}

func TestTokenBlacklist_BlacklistWithUserID(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	jti := "user-token-123"
	userID := uuid.New()
	reason := "user_logout"
	expiresAt := time.Now().Add(1 * time.Hour)

	err := blacklist.BlacklistWithUserID(ctx, jti, userID, reason, expiresAt)
	if err != nil {
		t.Fatalf("BlacklistWithUserID() error = %v", err)
	}

	// Verify token is blacklisted
	isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted")
	}

	// Verify reason
	gotReason, err := blacklist.GetBlacklistReason(ctx, jti)
	if err != nil {
		t.Fatalf("GetBlacklistReason() error = %v", err)
	}
	if gotReason != reason {
		t.Errorf("Reason = %q, want %q", gotReason, reason)
	}
}

func TestTokenBlacklist_BlacklistUserTokens(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	userID := uuid.New()
	reason := "account_compromised"
	ttl := 2 * time.Hour

	err := blacklist.BlacklistUserTokens(ctx, userID, reason, ttl)
	if err != nil {
		t.Fatalf("BlacklistUserTokens() error = %v", err)
	}

	// Verify user is blacklisted
	isBlacklisted, err := blacklist.IsUserBlacklisted(ctx, userID)
	if err != nil {
		t.Fatalf("IsUserBlacklisted() error = %v", err)
	}
	if !isBlacklisted {
		t.Error("User should be blacklisted")
	}
}

func TestTokenBlacklist_IsUserBlacklisted(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Non-blacklisted user", func(t *testing.T) {
		userID := uuid.New()

		isBlacklisted, err := blacklist.IsUserBlacklisted(ctx, userID)
		if err != nil {
			t.Fatalf("IsUserBlacklisted() error = %v", err)
		}
		if isBlacklisted {
			t.Error("User should not be blacklisted")
		}
	})

	t.Run("Blacklisted user", func(t *testing.T) {
		userID := uuid.New()
		ttl := 1 * time.Hour

		err := blacklist.BlacklistUserTokens(ctx, userID, "test", ttl)
		if err != nil {
			t.Fatalf("BlacklistUserTokens() error = %v", err)
		}

		isBlacklisted, err := blacklist.IsUserBlacklisted(ctx, userID)
		if err != nil {
			t.Fatalf("IsUserBlacklisted() error = %v", err)
		}
		if !isBlacklisted {
			t.Error("User should be blacklisted")
		}
	})
}

func TestTokenBlacklist_CheckToken(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	t.Run("Valid token and user", func(t *testing.T) {
		jti := "valid-token"
		userID := uuid.New()

		isBlacklisted, reason, err := blacklist.CheckToken(ctx, jti, userID)
		if err != nil {
			t.Fatalf("CheckToken() error = %v", err)
		}
		if isBlacklisted {
			t.Error("Token should not be blacklisted")
		}
		if reason != "" {
			t.Errorf("Reason should be empty, got %q", reason)
		}
	})

	t.Run("Blacklisted token", func(t *testing.T) {
		jti := "blacklisted-token"
		userID := uuid.New()
		expectedReason := "token_revoked"
		expiresAt := time.Now().Add(1 * time.Hour)

		err := blacklist.Blacklist(ctx, jti, expectedReason, expiresAt)
		if err != nil {
			t.Fatalf("Blacklist() error = %v", err)
		}

		isBlacklisted, reason, err := blacklist.CheckToken(ctx, jti, userID)
		if err != nil {
			t.Fatalf("CheckToken() error = %v", err)
		}
		if !isBlacklisted {
			t.Error("Token should be blacklisted")
		}
		if reason != expectedReason {
			t.Errorf("Reason = %q, want %q", reason, expectedReason)
		}
	})

	t.Run("User blacklisted", func(t *testing.T) {
		jti := "user-blacklist-token"
		userID := uuid.New()
		ttl := 1 * time.Hour

		err := blacklist.BlacklistUserTokens(ctx, userID, "password_changed", ttl)
		if err != nil {
			t.Fatalf("BlacklistUserTokens() error = %v", err)
		}

		isBlacklisted, reason, err := blacklist.CheckToken(ctx, jti, userID)
		if err != nil {
			t.Fatalf("CheckToken() error = %v", err)
		}
		if !isBlacklisted {
			t.Error("Token should be blacklisted due to user blacklist")
		}
		if reason != testUserTokensRevoked {
			t.Errorf("Reason = %q, want %q", reason, testUserTokensRevoked)
		}
	})

	t.Run("Both token and user blacklisted", func(t *testing.T) {
		jti := "both-blacklisted"
		userID := uuid.New()
		expiresAt := time.Now().Add(1 * time.Hour)

		// Blacklist user first
		err := blacklist.BlacklistUserTokens(ctx, userID, "user_reason", 1*time.Hour)
		if err != nil {
			t.Fatalf("BlacklistUserTokens() error = %v", err)
		}

		// Blacklist token
		err = blacklist.Blacklist(ctx, jti, "token_reason", expiresAt)
		if err != nil {
			t.Fatalf("Blacklist() error = %v", err)
		}

		isBlacklisted, reason, err := blacklist.CheckToken(ctx, jti, userID)
		if err != nil {
			t.Fatalf("CheckToken() error = %v", err)
		}
		if !isBlacklisted {
			t.Error("Token should be blacklisted")
		}
		// User-level blacklist is checked first
		if reason != testUserTokensRevoked {
			t.Errorf("Reason = %q, want %q", reason, testUserTokensRevoked)
		}
	})
}

func TestTokenBlacklist_MultipleTokens(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	expiresAt := time.Now().Add(1 * time.Hour)

	tokens := []struct {
		jti    string
		reason string
	}{
		{"token-1", "reason-1"},
		{"token-2", "reason-2"},
		{"token-3", "reason-3"},
	}

	// Blacklist multiple tokens
	for _, token := range tokens {
		err := blacklist.Blacklist(ctx, token.jti, token.reason, expiresAt)
		if err != nil {
			t.Fatalf("Blacklist() error = %v", err)
		}
	}

	// Verify all are blacklisted with correct reasons
	for _, token := range tokens {
		isBlacklisted, err := blacklist.IsBlacklisted(ctx, token.jti)
		if err != nil {
			t.Fatalf("IsBlacklisted() error = %v", err)
		}
		if !isBlacklisted {
			t.Errorf("Token %s should be blacklisted", token.jti)
		}

		reason, err := blacklist.GetBlacklistReason(ctx, token.jti)
		if err != nil {
			t.Fatalf("GetBlacklistReason() error = %v", err)
		}
		if reason != token.reason {
			t.Errorf("Token %s reason = %q, want %q", token.jti, reason, token.reason)
		}
	}
}

func TestTokenBlacklist_TTL(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	jti := "token-with-ttl"
	shortExpiry := time.Now().Add(100 * time.Millisecond)

	// Blacklist with short TTL
	err := blacklist.Blacklist(ctx, jti, "test", shortExpiry)
	if err != nil {
		t.Fatalf("Blacklist() error = %v", err)
	}

	// Should be blacklisted immediately
	isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted initially")
	}

	// Fast forward time in miniredis
	mr.FastForward(200 * time.Millisecond)

	// Should no longer be blacklisted (expired)
	isBlacklisted, err = blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if isBlacklisted {
		t.Error("Token should not be blacklisted after TTL expires")
	}
}

func TestTokenBlacklist_KeyFormat(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	jti := "test-token-123"
	userID := uuid.New()

	// Test tokenKey format
	tokenKey := blacklist.tokenKey(jti)
	expectedTokenKey := "test:blacklist:token:test-token-123"
	if tokenKey != expectedTokenKey {
		t.Errorf("tokenKey() = %q, want %q", tokenKey, expectedTokenKey)
	}

	// Test userTokensKey format
	userKey := blacklist.userTokensKey(userID)
	expectedUserKey := "test:blacklist:user:" + userID.String()
	if userKey != expectedUserKey {
		t.Errorf("userTokensKey() = %q, want %q", userKey, expectedUserKey)
	}
}

func TestTokenBlacklist_EmptyReason(t *testing.T) {
	blacklist, mr, client := setupTestTokenBlacklist(t)
	defer mr.Close()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()
	jti := "token-empty-reason"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Blacklist with empty reason
	err := blacklist.Blacklist(ctx, jti, "", expiresAt)
	if err != nil {
		t.Fatalf("Blacklist() error = %v", err)
	}

	// Should still be blacklisted
	isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted even with empty reason")
	}

	// Reason should be empty string
	reason, err := blacklist.GetBlacklistReason(ctx, jti)
	if err != nil {
		t.Fatalf("GetBlacklistReason() error = %v", err)
	}
	if reason != "" {
		t.Errorf("Reason = %q, want empty string", reason)
	}
}

// assertBlacklistState verifies IsBlacklisted and GetBlacklistReason based on whether the token has expired.
func assertBlacklistState(ctx context.Context, t *testing.T, blacklist *TokenBlacklist, jti, wantReason string, expiresAt time.Time) {
	t.Helper()
	isBlacklisted, err := blacklist.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted() error = %v", err)
	}
	if !expiresAt.After(time.Now()) {
		if isBlacklisted {
			t.Error("Expired token should not be blacklisted")
		}
		return
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted")
	}
	reason, err := blacklist.GetBlacklistReason(ctx, jti)
	if err != nil {
		t.Fatalf("GetBlacklistReason() error = %v", err)
	}
	if reason != wantReason {
		t.Errorf("Reason = %q, want %q", reason, wantReason)
	}
}
