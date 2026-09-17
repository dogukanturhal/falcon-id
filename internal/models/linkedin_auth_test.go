// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMutated = "mutated"

// TestLinkedInOIDCConstants verifies that all LinkedIn OIDC endpoint constants
// are non-empty and use the expected URL prefixes.
func TestLinkedInOIDCConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string // expected URL prefix
	}{
		{
			name:  "AuthURL",
			value: LinkedInOIDCAuthURL,
			want:  "https://www.linkedin.com/oauth/v2/",
		},
		{
			name:  "TokenURL",
			value: LinkedInOIDCTokenURL,
			want:  "https://www.linkedin.com/oauth/v2/",
		},
		{
			name:  "UserInfoURL",
			value: LinkedInOIDCUserInfoURL,
			want:  "https://api.linkedin.com/",
		},
		{
			name:  "DiscoveryURL",
			value: LinkedInOIDCDiscoveryURL,
			want:  "https://www.linkedin.com/",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.NotEmpty(t, tc.value, "constant %s must not be empty", tc.name)
			assert.Contains(t, tc.value, tc.want,
				"constant %s must start with %s", tc.name, tc.want)
		})
	}
}

// TestLinkedInScopesForUseCase verifies that the helper returns the correct
// scope slice for every supported LinkedIn use case.
func TestLinkedInScopesForUseCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		useCase        string
		wantContains   []string
		wantNotContain []string
	}{
		{
			useCase:        "",
			wantContains:   []string{"openid", "profile", "email"},
			wantNotContain: []string{"r_liteprofile", "r_ads"},
		},
		{
			useCase:        "login",
			wantContains:   []string{"openid", "profile", "email"},
			wantNotContain: []string{"r_liteprofile"},
		},
		{
			useCase:      "lead_sync",
			wantContains: []string{"r_ads_leadgen_automation"},
		},
		{
			useCase:        "advertising",
			wantContains:   []string{"r_ads", "rw_ads", "r_ads_reporting"},
			wantNotContain: []string{"openid", "r_liteprofile"},
		},
		{
			useCase:        "content_marketing",
			wantContains:   []string{"r_organization_social", "w_organization_social", "rw_organization_admin"},
			wantNotContain: []string{"r_liteprofile"},
		},
		{
			useCase:        "community",
			wantContains:   []string{"w_member_social", "r_organization_social", "w_organization_social"},
			wantNotContain: []string{"r_liteprofile"},
		},
		{
			useCase:        "events",
			wantContains:   []string{"r_events", "w_organization_events"},
			wantNotContain: []string{"r_liteprofile"},
		},
		{
			// Unknown use cases fall back to login scopes.
			useCase:        "unknown_use_case",
			wantContains:   []string{"openid", "profile", "email"},
			wantNotContain: []string{"r_liteprofile"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.useCase, func(t *testing.T) {
			t.Parallel()

			scopes := LinkedInScopesForUseCase(tc.useCase)
			require.NotEmpty(t, scopes, "scopes must not be empty for use case %q", tc.useCase)

			for _, want := range tc.wantContains {
				assert.Contains(t, scopes, want,
					"use case %q: expected scope %q to be present", tc.useCase, want)
			}
			for _, notWant := range tc.wantNotContain {
				assert.NotContains(t, scopes, notWant,
					"use case %q: deprecated scope %q must not be present", tc.useCase, notWant)
			}
		})
	}
}

// TestLinkedInScopesForUseCase_ReturnsCopy verifies that mutating the returned
// slice does not affect subsequent calls (i.e., the helper returns a copy).
func TestLinkedInScopesForUseCase_ReturnsCopy(t *testing.T) {
	t.Parallel()

	first := LinkedInScopesForUseCase("login")
	require.NotEmpty(t, first)

	// Mutate the returned slice.
	original := first[0]
	first[0] = testMutated

	second := LinkedInScopesForUseCase("login")
	require.NotEmpty(t, second)
	assert.Equal(t, original, second[0],
		"mutating the returned slice must not affect subsequent calls")
}
