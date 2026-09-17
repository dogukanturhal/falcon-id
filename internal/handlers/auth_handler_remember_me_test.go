// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// TestAuthHandler_IdpSessionCookieMaxAge verifies the cookie Max-Age
// bifurcation. Pairs with TestAuthService_SessionTTLForLogin in
// internal/services — they MUST resolve to the same horizon so the
// falcon_idp_session cookie and iam_sessions.expires_at row expire in
// lock-step.
func TestAuthHandler_IdpSessionCookieMaxAge(t *testing.T) {
	t.Parallel()

	t.Run("rememberMe=true with config returns SessionTTLRememberMe", func(t *testing.T) {
		h := &AuthHandler{
			config: &config.Config{
				SessionTTLDefault:    8 * time.Hour,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		got := h.idpSessionCookieMaxAge(true)
		assert.Equal(t, 30*24*time.Hour, got)
	})

	t.Run("rememberMe=false with config returns SessionTTLDefault", func(t *testing.T) {
		h := &AuthHandler{
			config: &config.Config{
				SessionTTLDefault:    8 * time.Hour,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		got := h.idpSessionCookieMaxAge(false)
		assert.Equal(t, 8*time.Hour, got)
	})

	t.Run("nil config falls back to legacy hardcoded defaults", func(t *testing.T) {
		// Handler tests that pre-date the remember-me feature don't
		// inject a config — the legacy 7d / 30d constants apply so
		// those tests keep passing without modification.
		h := &AuthHandler{}
		assert.Equal(t, idpSessionDefaultMaxAge, h.idpSessionCookieMaxAge(false))
		assert.Equal(t, 30*24*time.Hour, h.idpSessionCookieMaxAge(true))
	})

	t.Run("rememberMe=true with zero SessionTTLRememberMe falls back to 30d", func(t *testing.T) {
		// Defensive: matches sessionTTLForLogin's behaviour for the
		// "operator zeroed out the remember-me TTL" case.
		h := &AuthHandler{
			config: &config.Config{
				SessionTTLDefault:    8 * time.Hour,
				SessionTTLRememberMe: 0,
			},
		}
		got := h.idpSessionCookieMaxAge(true)
		assert.Equal(t, 30*24*time.Hour, got)
	})

	t.Run("rememberMe=false with zero SessionTTLDefault falls back to 7d", func(t *testing.T) {
		h := &AuthHandler{
			config: &config.Config{
				SessionTTLDefault:    0,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		got := h.idpSessionCookieMaxAge(false)
		assert.Equal(t, idpSessionDefaultMaxAge, got)
	})
}
