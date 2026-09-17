// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// TestAuthService_SessionTTLForLogin verifies the TTL bifurcation
// driven by AuthService.sessionTTLForLogin. This is the single
// decision point that drives both iam_sessions.expires_at (via
// AuthService.createSession) and falcon_idp_session cookie Max-Age
// (via AuthHandler.idpSessionCookieMaxAge), so getting it right here
// is load-bearing for the entire remember-me feature.
func TestAuthService_SessionTTLForLogin(t *testing.T) {
	t.Parallel()

	t.Run("rememberMe=true returns SessionTTLRememberMe", func(t *testing.T) {
		s := &AuthService{
			config: &config.Config{
				SessionExpiry:        24 * time.Hour,
				SessionTTLDefault:    24 * time.Hour,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		got := s.sessionTTLForLogin(true)
		assert.Equal(t, 30*24*time.Hour, got)
	})

	t.Run("rememberMe=false returns SessionTTLDefault", func(t *testing.T) {
		s := &AuthService{
			config: &config.Config{
				SessionExpiry:        24 * time.Hour,
				SessionTTLDefault:    8 * time.Hour,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		got := s.sessionTTLForLogin(false)
		assert.Equal(t, 8*time.Hour, got)
	})

	t.Run("rememberMe=true with zero SessionTTLRememberMe falls back to SessionTTLDefault", func(t *testing.T) {
		// Defensive: when an operator zeroes out SESSION_TTL_REMEMBER_ME
		// to effectively disable the feature, the short TTL is still used —
		// no panic, no negative duration, no silently extending to
		// SessionExpiry.
		s := &AuthService{
			config: &config.Config{
				SessionExpiry:        24 * time.Hour,
				SessionTTLDefault:    8 * time.Hour,
				SessionTTLRememberMe: 0,
			},
		}
		got := s.sessionTTLForLogin(true)
		assert.Equal(t, 8*time.Hour, got)
	})

	t.Run("zero SessionTTLDefault falls back to SessionExpiry (preserves pre-feature behaviour)", func(t *testing.T) {
		// Operators upgrading without setting SESSION_TTL_DEFAULT keep
		// the existing SESSION_EXPIRY-driven TTL. This is the case
		// Load() aliases by copying SessionExpiry into
		// SessionTTLDefault, but the in-process fallback inside
		// sessionTTLForLogin must also hold — defensive against test
		// harnesses or partial config wiring.
		s := &AuthService{
			config: &config.Config{
				SessionExpiry:        24 * time.Hour,
				SessionTTLDefault:    0,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		got := s.sessionTTLForLogin(false)
		assert.Equal(t, 24*time.Hour, got)
	})

	t.Run("absent rememberMe (zero-value bool) matches false branch", func(t *testing.T) {
		// req.RememberMe is a Go bool, so an omitted JSON field
		// deserialises as false. This explicit test guarantees the
		// "user didn't tick the box" path uses the short TTL — the
		// load-bearing safety property of the feature.
		s := &AuthService{
			config: &config.Config{
				SessionExpiry:        24 * time.Hour,
				SessionTTLDefault:    8 * time.Hour,
				SessionTTLRememberMe: 30 * 24 * time.Hour,
			},
		}
		var rememberMe bool // zero value, simulating absent JSON field
		got := s.sessionTTLForLogin(rememberMe)
		assert.Equal(t, 8*time.Hour, got, "absent remember_me MUST resolve to short TTL")
	})
}
