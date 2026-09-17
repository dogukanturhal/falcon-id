// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/url"
	"testing"
)

// TestStaleAuthRedirect locks the routing decision the /oauth/authorize
// max_age gate makes when the session's auth_time has aged out.
//
// Bug this guards against: prior to 2026-05-26 this branch ALWAYS sent
// the user through /oauth/login (full email+password re-entry) even
// when they had a live IdP session + MFA factor enrolled. Live trigger
// 2026-05-25T18:55 on mobile: user clicked Disable Email MFA, was
// asked to enter password + email-OTP from scratch, bailed before
// finishing — perceived as "why am I doing a full sign-in when I just
// want to disable MFA?". The canonical Auth0 / Microsoft Entra UX is
// to drive freshness via a single MFA factor verification (per NIST
// SP 800-63B-4 §5.1 — a fresh MFA verification IS a fresh
// authentication event at AAL2).
func TestStaleAuthRedirect(t *testing.T) {
	const safe = "/oauth/authorize?client_id=svc-accounts&max_age=300"

	tcs := []struct {
		name           string
		in             staleAuthRedirectInput
		wantStartsWith string
		wantContainsRD bool
	}{
		{
			name: "session+factor+no prompt=login → MFA challenge (the canonical step-up)",
			in: staleAuthRedirectInput{
				CurrentUserPresent: true,
				Prompt:             "",
				HasMFAFactor:       true,
				SafeRedirect:       safe,
			},
			wantStartsWith: "/auth/mfa/challenge?rd=",
			wantContainsRD: true,
		},
		{
			name: "session+factor+prompt=none → MFA challenge (prompt=none is not prompt=login)",
			in: staleAuthRedirectInput{
				CurrentUserPresent: true,
				Prompt:             "none",
				HasMFAFactor:       true,
				SafeRedirect:       safe,
			},
			wantStartsWith: "/auth/mfa/challenge?rd=",
			wantContainsRD: true,
		},
		{
			name: "session+factor+prompt=login → /oauth/login (RP explicitly wants full re-auth)",
			in: staleAuthRedirectInput{
				CurrentUserPresent: true,
				Prompt:             "login",
				HasMFAFactor:       true,
				SafeRedirect:       safe,
			},
			wantStartsWith: "/oauth/login?redirect=",
			wantContainsRD: true,
		},
		{
			name: "session+NO factor → /oauth/login (nothing to challenge with)",
			in: staleAuthRedirectInput{
				CurrentUserPresent: true,
				Prompt:             "",
				HasMFAFactor:       false,
				SafeRedirect:       safe,
			},
			wantStartsWith: "/oauth/login?redirect=",
			wantContainsRD: true,
		},
		{
			name: "NO session+factor → /oauth/login (anonymous user)",
			in: staleAuthRedirectInput{
				CurrentUserPresent: false,
				Prompt:             "",
				HasMFAFactor:       true,
				SafeRedirect:       safe,
			},
			wantStartsWith: "/oauth/login?redirect=",
			wantContainsRD: true,
		},
		{
			name: "NO session+NO factor → /oauth/login",
			in: staleAuthRedirectInput{
				CurrentUserPresent: false,
				Prompt:             "",
				HasMFAFactor:       false,
				SafeRedirect:       safe,
			},
			wantStartsWith: "/oauth/login?redirect=",
			wantContainsRD: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := staleAuthRedirect(tc.in)
			if got[:len(tc.wantStartsWith)] != tc.wantStartsWith {
				t.Fatalf("redirect URL = %q, want prefix %q", got, tc.wantStartsWith)
			}
			if tc.wantContainsRD {
				wantEncoded := url.QueryEscape(safe)
				if !contains(got, wantEncoded) {
					t.Errorf("redirect URL = %q, want encoded safe redirect %q to be present", got, wantEncoded)
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
