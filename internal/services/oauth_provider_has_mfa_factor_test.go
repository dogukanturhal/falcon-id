// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import "testing"

// TestHasMFAFactor — locks the RFC 8176 §2 IANA-registry-aware
// multi-factor check that drives both the service-side claims emit
// path (via the lowercase alias) AND the handler-side
// /oauth/authorize ACR-satisfaction gate (via the exported name).
//
// The exported HasMFAFactor is load-bearing for WebAuthn step-up:
// passkey sessions write amr=["hwk","user"] at session-write time,
// the "mfa" umbrella is only appended at TOKEN-emission time by
// amrWithUmbrella. Pre-fix the /oauth/authorize gate called
// `slices.Contains(amr, "mfa")` directly — false for passkeys —
// which double-bounced the user through /auth/mfa/challenge AFTER
// they had already authenticated with a passkey.
//
// Lock the contract so a future "just rename it" refactor can't
// silently downgrade WebAuthn AAL3 sessions to "no MFA satisfied"
// without these tests screaming first.
func TestHasMFAFactor(t *testing.T) {
	tests := []struct {
		name string
		amr  []string
		want bool
	}{
		// Canonical passkey AMR — the post-LoginViaWebAuthn shape.
		// MUST recognise as MFA: hwk is RFC 8176 §2 hardware-key.
		{"passkey (hwk+user)", []string{"hwk", "user"}, true},

		// Software-key authenticator (e.g. browser-stored passkey
		// before Sync Fabric) — RFC 8176 §2 swk.
		{"software key (swk)", []string{"swk", "user"}, true},

		// Password + TOTP — canonical 2FA.
		{"password + TOTP", []string{"pwd", "otp"}, true},

		// Password + SMS — degraded MFA, still satisfies RFC 8176.
		{"password + SMS", []string{"pwd", "sms"}, true},

		// MFA umbrella explicitly present (token-rewrite path).
		{"mfa umbrella alone", []string{"mfa"}, true},
		{"mfa umbrella with hwk", []string{"hwk", "user", "mfa"}, true},

		// Biometric — RFC 8176 §2 face / fpt / iris.
		{"biometric (face)", []string{"face", "user"}, true},
		{"biometric (fpt)", []string{"fpt"}, true},

		// Password ALONE — single-factor, MUST NOT satisfy.
		{"password only", []string{"pwd"}, false},

		// Empty AMR.
		{"empty", []string{}, false},
		{"nil", nil, false},

		// Unknown values shouldn't match.
		{"unknown", []string{"unknown"}, false},
		{"unknown + user (interaction-only)", []string{"user"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasMFAFactor(tc.amr); got != tc.want {
				t.Errorf("HasMFAFactor(%v) = %v, want %v", tc.amr, got, tc.want)
			}
			// Lowercase alias must agree — same body, different
			// callers; regression guard against a future split that
			// allows them to drift.
			if got := hasMFAFactor(tc.amr); got != tc.want {
				t.Errorf("hasMFAFactor(%v) = %v, want %v (must match HasMFAFactor)", tc.amr, got, tc.want)
			}
		})
	}
}
