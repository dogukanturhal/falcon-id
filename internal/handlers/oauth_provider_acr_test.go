// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import "testing"

// TestRequiresMFA — locks down the OIDC `acr_values` query-param
// recognition logic that drives /oauth/authorize's step-up gate.
//
// Per OIDC Core 1.0 §3.1.2.1, acr_values is space-separated; the
// IdP must satisfy at least one. Talon's startAuthWithMFA emits the
// bare `mfa` token; future MRs (Talon route refactor + RFC 9470
// challenge bridge) may also emit `urn:hexxlock:aal2` /
// `urn:hexxlock:aal3`. All three must trigger the step-up.
func TestRequiresMFA(t *testing.T) {
	tests := []struct {
		acrValues string
		want      bool
	}{
		// HexxLock vocabulary (canonical).
		{"mfa", true},
		{"urn:hexxlock:aal2", true},
		{"urn:hexxlock:aal3", true},

		// Multi-value space-separated. Per spec, satisfy any one =>
		// satisfy whole.
		{"urn:hexxlock:aal2 urn:hexxlock:aal3", true},
		{"urn:hexxlock:aal3 mfa", true},
		{"urn:hexxlock:aal1 mfa", true}, // mfa wins over aal1

		// AAL1 alone = password-only. Should NOT trigger MFA gate.
		{"urn:hexxlock:aal1", false},

		// Empty / unknown values.
		{"", false},
		{"unknown:value", false},
		{"loa:1", false},

		// Whitespace robustness — strings.Fields collapses runs of
		// whitespace.
		{"  mfa  ", true},
		{"\turn:hexxlock:aal2\n", true},
	}
	for _, tc := range tests {
		t.Run(tc.acrValues, func(t *testing.T) {
			got := requiresMFA(tc.acrValues)
			if got != tc.want {
				t.Errorf("requiresMFA(%q)=%v, want %v", tc.acrValues, got, tc.want)
			}
		})
	}
}
