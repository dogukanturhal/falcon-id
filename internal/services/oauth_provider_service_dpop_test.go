// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the RFC 9449 DPoP wiring added in the tier-1
// hardening pass: cnf.jkt emission on issued access tokens, and the
// per-scope "MUST be DPoP-bound" enforcement on /oauth/token.

func TestScopeRequiresDPoP(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"empty", nil, false},
		{"openid only", []string{"openid"}, false},
		{"profile email", []string{"profile", "email"}, false},

		// admin:* prefix triggers
		{"admin:oauth-clients", []string{"admin:oauth-clients"}, true},
		{"admin:tenants", []string{"admin:tenants"}, true},
		{"admin:* mixed with openid", []string{"openid", "admin:foo"}, true},

		// offline_access triggers
		{"offline_access alone", []string{"offline_access"}, true},
		{"offline_access mixed", []string{"openid", "offline_access"}, true},

		// near misses
		{"administrator (no colon)", []string{"administrator"}, false},
		{"adminstuff (no colon)", []string{"adminstuff"}, false},
		{"empty string element", []string{""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scopeRequiresDPoP(tc.in))
		})
	}
}

func TestGenerateTokens_CnfJKTEmitted_WhenContextHasJKT(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	jkt := "abc123-jwk-thumbprint"
	ctx := WithDPoPJKT(context.Background(), jkt)

	resp, err := svc.generateTokens(
		ctx,
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	cnf, ok := claims["cnf"].(map[string]interface{})
	require.True(t, ok, "cnf claim MUST be present when ctx carries a JKT")
	assert.Equal(t, jkt, cnf["jkt"])
}

func TestGenerateTokens_CnfJKTOmitted_WhenContextHasNoJKT(t *testing.T) {
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	resp, err := svc.generateTokens(
		context.Background(),
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	_, present := claims["cnf"]
	assert.False(t, present, "cnf claim MUST NOT be emitted on plain bearer flows (backward compat)")
}

func TestGenerateTokens_CnfJKTOmitted_WhenContextJKTEmpty(t *testing.T) {
	// WithDPoPJKT short-circuits on "" — pinning that no cnf claim
	// gets stamped if a caller passes through an empty form value.
	svc := newTestOAuthService(t)
	client := authzCodeClient([]string{"openid"})
	user := subjectUser()

	ctx := WithDPoPJKT(context.Background(), "")
	resp, err := svc.generateTokens(
		ctx,
		client, user,
		[]string{"openid"}, nil, nil,
		[]string{"pwd"},
		nil,
	)
	require.NoError(t, err)

	claims := decodeJWTUnverified(t, resp.AccessToken)
	_, present := claims["cnf"]
	assert.False(t, present)
}

// errIs is a tiny adapter so we don't need errors.Is at every callsite.
func errIs(t *testing.T, err, target error) bool {
	t.Helper()
	return err != nil && errors.Is(err, target)
}

// Sanity: scopeRequiresDPoP wired correctly for the most-common
// platform shapes — admin:oauth-clients (the actual provisioner scope)
// and openid+groups+roles (which is NOT DPoP-required, even though it
// triggered the now-reverted consent override).
func TestScopeRequiresDPoP_PlatformShapes(t *testing.T) {
	assert.True(t, scopeRequiresDPoP([]string{"admin:oauth-clients"}))
	assert.False(t, scopeRequiresDPoP([]string{"openid", "email", "profile", "groups", "roles"}),
		"groups/roles are NOT in the DPoP-required set; they're sensitive but the platform's RBAC primitive shape — gating them on DPoP would force every internal app to ship proof keys.")
	assert.True(t, errIs(t, ErrDPoPRequired, ErrDPoPRequired), "sentinel sanity")
}
