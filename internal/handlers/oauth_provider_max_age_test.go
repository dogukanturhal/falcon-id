// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// TestBuildAuthorizeURLFromRequest_MaxAge locks in that the resume URL
// built when /oauth/authorize bounces a user to /oauth/login (for either
// the no-session branch or the new max_age freshness branch) preserves
// the `max_age` query parameter.
//
// If max_age were dropped here, the post-login resume would re-enter
// /oauth/authorize WITHOUT the gate, silent-SSO would issue a token
// with the freshly-bumped auth_time, but the RP's RFC 9470 freshAuth
// gate would still get an old auth_time on subsequent calls because
// the resume side wouldn't have re-enforced freshness — meaning the
// gate is only as strong as the round-trip. Lock the contract.
func TestBuildAuthorizeURLFromRequest_MaxAge(t *testing.T) {
	maxAge := 300
	req := &models.OAuthAuthorizeRequest{
		ResponseType: "code",
		ClientID:     "svc-accounts",
		RedirectURI:  "https://accounts.hexxlock.com/api/auth/oidc-callback",
		Scope:        "openid email profile",
		State:        "test-state",
		AcrValues:    "mfa",
		MaxAge:       &maxAge,
	}

	got := buildAuthorizeURLFromRequest(req)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("buildAuthorizeURLFromRequest produced unparseable URL %q: %v", got, err)
	}
	if u.Path != "/oauth/authorize" {
		t.Errorf("path = %q, want /oauth/authorize", u.Path)
	}

	q := u.Query()
	if q.Get("max_age") != strconv.Itoa(maxAge) {
		t.Errorf("max_age query = %q, want %q", q.Get("max_age"), strconv.Itoa(maxAge))
	}
	if q.Get("acr_values") != "mfa" {
		t.Errorf("acr_values query = %q, want mfa", q.Get("acr_values"))
	}
}

// TestBuildAuthorizeURLFromRequest_MaxAgeOmittedWhenNil locks the
// other side: when the client did not request max_age, the resume
// URL MUST NOT inject one. Doing so would tighten freshness in
// places the RP didn't ask for it (e.g. a /oauth/authorize that
// originally had no max_age would silently start enforcing one
// after the first redirect) and breaks "don't re-interpret the
// client's request" contract.
func TestBuildAuthorizeURLFromRequest_MaxAgeOmittedWhenNil(t *testing.T) {
	req := &models.OAuthAuthorizeRequest{
		ResponseType: "code",
		ClientID:     "svc-accounts",
		RedirectURI:  "https://accounts.hexxlock.com/api/auth/oidc-callback",
		Scope:        "openid",
		MaxAge:       nil,
	}
	got := buildAuthorizeURLFromRequest(req)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("unparseable URL %q: %v", got, err)
	}
	if _, present := u.Query()["max_age"]; present {
		t.Errorf("max_age must be absent when req.MaxAge is nil, got URL %q", got)
	}
}

// TestBuildAuthorizeURLFromRequest_MaxAgeZeroPropagated locks the
// edge case where the RP requests max_age=0 (RFC 9470: "always
// re-authenticate"). The pointer is non-nil, value is 0, must
// serialise as max_age=0 (not be omitted as zero-value).
func TestBuildAuthorizeURLFromRequest_MaxAgeZeroPropagated(t *testing.T) {
	zero := 0
	req := &models.OAuthAuthorizeRequest{
		ResponseType: "code",
		ClientID:     "svc-accounts",
		RedirectURI:  "https://accounts.hexxlock.com/api/auth/oidc-callback",
		Scope:        "openid",
		MaxAge:       &zero,
	}
	got := buildAuthorizeURLFromRequest(req)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("unparseable URL %q: %v", got, err)
	}
	if q := u.Query().Get("max_age"); q != "0" {
		t.Errorf("max_age = %q, want \"0\" (zero-value carries semantic meaning per RFC 9470)", q)
	}
}
