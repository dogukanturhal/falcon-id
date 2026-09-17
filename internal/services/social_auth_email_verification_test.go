// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"testing"
	"time"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// providerAssertsVerifiedEmail was extracted from findOrCreateUser during the
// t-052 security fix. It previously lived inline BELOW an early return and so
// governed only account provisioning, never account linking.
func TestProviderAssertsVerifiedEmail(t *testing.T) {
	s := &SocialAuthService{}

	cases := []struct {
		name         string
		providerType string
		userInfo     map[string]interface{}
		want         bool
	}{
		{"google trusted without claim", "google", map[string]interface{}{}, true},
		{"microsoft trusted without claim", "microsoft", map[string]interface{}{}, true},
		{"linkedin trusted without claim", "linkedin", map[string]interface{}{}, true},

		{"github honours bool true", "github", map[string]interface{}{"email_verified": true}, true},
		{"github honours bool false", "github", map[string]interface{}{"email_verified": false}, false},
		{"github honours string true", "github", map[string]interface{}{"email_verified": "true"}, true},
		{"github honours string false", "github", map[string]interface{}{"email_verified": "false"}, false},

		// The takeover-relevant defaults: a provider asserting nothing is NOT
		// treated as verified.
		{"github absent claim is unverified", "github", map[string]interface{}{}, false},
		{"generic oauth absent claim is unverified", "oauth", map[string]interface{}{}, false},
		{"oidc absent claim is unverified", "oidc", map[string]interface{}{}, false},
		{"unexpected claim type is unverified", "oidc", map[string]interface{}{"email_verified": 1}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.providerAssertsVerifiedEmail(&models.IdentityProvider{Type: tc.providerType}, tc.userInfo)
			if got != tc.want {
				t.Fatalf("provider %q userInfo %v: got %v, want %v", tc.providerType, tc.userInfo, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MFA session store presence (t-060)
// ---------------------------------------------------------------------------

// The SSO MFA fail-open at social_auth_service.go turned on a premise that two
// readers got wrong in opposite directions: whether a SocialAuthService built
// without SetRedisClient has a nil redisClient.
//
// It does. cmd/services.go wireTokenServiceRedis early-returns when
// infra.RedisClient is nil (which initRedisComponents deliberately produces,
// logging "continuing without Redis features", if Redis is unreachable at
// boot), so SetRedisClient is never called and the field keeps its zero value.
//
// That makes the "MFA required but no session store" branch genuinely
// reachable in a running binary rather than theoretical. These tests pin that
// premise so it cannot be quietly re-argued.
func TestSSOMFAStore_UnwiredServiceHasNilStore(t *testing.T) {
	s := &SocialAuthService{}
	if s.redisClient != nil {
		t.Fatal("a service built without SetRedisClient must have a nil MFA session store; " +
			"the fail-closed branch depends on this being reachable")
	}
}

type stubSSORedis struct{}

func (stubSSORedis) Set(_ context.Context, _ string, _ interface{}, _ time.Duration) error {
	return nil
}

func TestSSOMFAStore_SetRedisClientMakesStorePresent(t *testing.T) {
	s := &SocialAuthService{}
	s.SetRedisClient(stubSSORedis{})
	if s.redisClient == nil {
		t.Fatal("SetRedisClient must make the MFA session store present")
	}
}
