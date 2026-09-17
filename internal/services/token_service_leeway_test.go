// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// DDIL P3.3 — access-token clock-skew leeway boundary tests.
//
// A disconnected/drifting node whose clock runs ahead of the issuer must still
// accept a token that has only just expired (within the configured leeway), and
// must reject one expired beyond it. These tests pin both sides of that
// boundary and confirm an explicit zero leeway restores strict validation.

func leewayTestService(secret string, leeway time.Duration) *TokenService {
	return &TokenService{config: &config.Config{
		JWTSecret:              secret,
		JWTIssuer:              "leeway-test-issuer",
		JWTHMACFallbackEnabled: true,
		JWTClockSkewLeeway:     leeway,
	}}
}

// hs256TokenExpiringAt mints a minimal legacy (v0) HS256 token that expires at
// exp. No session cache / blacklist is required for the legacy claim path.
func hs256TokenExpiringAt(t *testing.T, secret string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "00000000-0000-0000-0000-000000000001",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": exp.Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestValidateAccessToken_ClockSkewLeewayBoundary(t *testing.T) {
	const secret = "leeway-test-secret-32-bytes-minimum!"
	const leeway = 60 * time.Second

	svc := leewayTestService(secret, leeway)
	now := time.Now()

	t.Run("expired within leeway is accepted", func(t *testing.T) {
		// Expired 30s ago; 60s leeway must still accept it.
		tok := hs256TokenExpiringAt(t, secret, now.Add(-30*time.Second))
		if _, err := svc.ValidateAccessToken(tok); err != nil {
			t.Fatalf("expected token within leeway to be accepted, got: %v", err)
		}
	})

	t.Run("expired beyond leeway is rejected", func(t *testing.T) {
		// Expired 90s ago; beyond the 60s leeway → must be rejected.
		tok := hs256TokenExpiringAt(t, secret, now.Add(-90*time.Second))
		if _, err := svc.ValidateAccessToken(tok); err == nil {
			t.Fatal("expected token expired beyond leeway to be rejected, got nil error")
		}
	})
}

func TestValidateAccessToken_ZeroLeewayIsStrict(t *testing.T) {
	const secret = "leeway-test-secret-32-bytes-minimum!"
	svc := leewayTestService(secret, 0) // explicit strict

	// Expired 30s ago; with zero leeway even a small overrun is rejected.
	tok := hs256TokenExpiringAt(t, secret, time.Now().Add(-30*time.Second))
	if _, err := svc.ValidateAccessToken(tok); err == nil {
		t.Fatal("expected strict (zero-leeway) validation to reject an expired token")
	}
}

func TestJWTClockSkewLeeway_DefaultWhenNoConfig(t *testing.T) {
	// A service with no config falls back to the documented default, never 0.
	svc := &TokenService{}
	if got := svc.jwtClockSkewLeeway(); got != defaultJWTClockSkewLeeway {
		t.Fatalf("nil-config leeway = %v, want default %v", got, defaultJWTClockSkewLeeway)
	}

	// A negative configured value is clamped to zero (never tightens the window).
	neg := &TokenService{config: &config.Config{JWTClockSkewLeeway: -5 * time.Second}}
	if got := neg.jwtClockSkewLeeway(); got != 0 {
		t.Fatalf("negative leeway = %v, want 0", got)
	}
}
