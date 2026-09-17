// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// LinkedIn OIDC endpoints.
//
// LinkedIn supports the OpenID Connect protocol for identity federation. These
// constants correspond to the endpoints published in LinkedIn's OIDC discovery
// document at LinkedInOIDCDiscoveryURL.
//
// Reference: https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
const (
	// LinkedInOIDCAuthURL is the authorization endpoint for the LinkedIn OIDC flow.
	LinkedInOIDCAuthURL = "https://www.linkedin.com/oauth/v2/authorization"

	// LinkedInOIDCTokenURL is the token endpoint for exchanging authorization
	// codes and refreshing access tokens in the LinkedIn OIDC flow.
	LinkedInOIDCTokenURL = "https://www.linkedin.com/oauth/v2/accessToken" //nolint:gosec // not a credential, this is an OAuth field name constant

	// LinkedInOIDCUserInfoURL is the UserInfo endpoint that returns standard
	// OIDC claims (sub, name, given_name, family_name, email, picture) when
	// the openid, profile, and email scopes have been granted.
	LinkedInOIDCUserInfoURL = "https://api.linkedin.com/v2/userinfo"

	// LinkedInOIDCDiscoveryURL is LinkedIn's OpenID Connect discovery document,
	// which advertises all supported endpoints and signing algorithms.
	LinkedInOIDCDiscoveryURL = "https://www.linkedin.com/oauth/v2/.well-known/openid-configuration"
)

// LinkedIn OAuth2 scope sets.
//
// LinkedIn's API partitions permissions into distinct scope sets. Callers should
// select the set that corresponds to their integration use case. Scope sets must
// not be mixed across different app types — LinkedIn enforces this at the
// application level in its developer portal.
const (
	// LinkedInScopeLogin is the minimal OIDC scope set for "Sign In with
	// LinkedIn" identity federation. This replaces the deprecated
	// r_liteprofile scope that was removed in the 2024 LinkedIn API update.
	LinkedInScopeLogin = "openid profile email"

	// LinkedInScopeLeadSync is the scope set required to read lead gen form
	// submissions from LinkedIn Ads.
	LinkedInScopeLeadSync = "r_ads_leadgen_automation"

	// LinkedInScopeAdvertising is the scope set required to manage and report
	// on LinkedIn advertising campaigns.
	LinkedInScopeAdvertising = "r_ads rw_ads r_ads_reporting"

	// LinkedInScopeContentMarketing is the scope set for publishing and
	// managing organic content on behalf of organizations.
	LinkedInScopeContentMarketing = "r_organization_social w_organization_social rw_organization_admin"

	// LinkedInScopeCommunityManagement is the scope set for managing community
	// interactions and member-level social actions.
	LinkedInScopeCommunityManagement = "w_member_social r_organization_social w_organization_social"

	// LinkedInScopeEvents is the scope set for reading and managing LinkedIn
	// events on behalf of organizations.
	LinkedInScopeEvents = "r_events w_organization_events"
)

// LinkedInScopesForUseCase returns the OAuth2 scope slice for the given
// LinkedIn integration use case string. The returned slice is ready to pass
// directly to oauth2.Config.Scopes.
//
// Recognised use-case values:
//
//	"login"               — OIDC sign-in (default)
//	"lead_sync"           — Lead Gen form automation
//	"advertising"         — Ads management and reporting
//	"content_marketing"   — Organic organization content
//	"community"           — Community / member social
//	"events"              — Organization event management
//
// An unrecognised use case falls back to the login scope set.
func LinkedInScopesForUseCase(useCase string) []string {
	switch useCase {
	case "lead_sync":
		return splitScopes(LinkedInScopeLeadSync)
	case "advertising":
		return splitScopes(LinkedInScopeAdvertising)
	case "content_marketing":
		return splitScopes(LinkedInScopeContentMarketing)
	case "community":
		return splitScopes(LinkedInScopeCommunityManagement)
	case "events":
		return splitScopes(LinkedInScopeEvents)
	default:
		// "login" and any unrecognised value → OIDC login scopes.
		return splitScopes(LinkedInScopeLogin)
	}
}

// splitScopes converts a space-separated scope string into a string slice.
// This avoids importing strings in the models package just for this helper.
func splitScopes(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
