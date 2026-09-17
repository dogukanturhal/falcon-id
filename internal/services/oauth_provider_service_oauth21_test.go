// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"strings"
	"testing"
)

// TestValidateOAuth21GrantsAndResponses_AcceptsConformantValues verifies
// the OAuth 2.1 / BCP-225 hardening allows the grant_types and
// response_types we actually implement.
func TestValidateOAuth21GrantsAndResponses_AcceptsConformantValues(t *testing.T) {
	t.Parallel()
	s := &OAuthProviderService{}
	cases := []struct {
		name  string
		grant []string
		resp  []string
	}{
		{name: "code only", grant: []string{"authorization_code"}, resp: []string{"code"}},
		{name: "all three OAuth 2.1 conformant grants", grant: []string{"authorization_code", "refresh_token", "client_credentials"}, resp: []string{"code"}},
		{name: "empty (no client-asserted preference)", grant: nil, resp: nil},
		{name: "client_credentials grant with no response_types (client_credentials does not use /authorize)", grant: []string{"client_credentials"}, resp: nil},
		{name: "refresh_token alone", grant: []string{"refresh_token"}, resp: []string{"code"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.validateOAuth21GrantsAndResponses(tc.grant, tc.resp); err != nil {
				t.Fatalf("expected nil error for conformant input, got %v", err)
			}
		})
	}
}

// TestValidateOAuth21GrantsAndResponses_RejectsImplicit covers every
// composite response_type that contains the implicit-flow `token` or
// `id_token` part. OAuth 2.1 BCP-225 / draft-ietf-oauth-v2-1 §10.2
// removes implicit-flow tokens-in-URL-fragment across the board.
func TestValidateOAuth21GrantsAndResponses_RejectsImplicit(t *testing.T) {
	t.Parallel()
	s := &OAuthProviderService{}
	rejects := []string{
		"token",                 // pure implicit
		"id_token",              // pure implicit
		"id_token token",        // implicit composite
		"code id_token",         // hybrid (still includes id_token)
		"code token",            // hybrid (still includes token)
		"code id_token token",   // hybrid (both)
	}
	for _, rt := range rejects {
		t.Run(rt, func(t *testing.T) {
			err := s.validateOAuth21GrantsAndResponses(nil, []string{rt})
			if err == nil {
				t.Fatalf("expected rejection of response_type %q, got nil", rt)
			}
			if !strings.Contains(err.Error(), "invalid_client_metadata") {
				t.Fatalf("expected RFC 7591 invalid_client_metadata error code, got: %v", err)
			}
		})
	}
}

// TestValidateOAuth21GrantsAndResponses_RejectsROPC — Resource Owner
// Password Credentials grant (RFC 6749 §4.3) is removed in OAuth 2.1.
func TestValidateOAuth21GrantsAndResponses_RejectsROPC(t *testing.T) {
	t.Parallel()
	s := &OAuthProviderService{}
	err := s.validateOAuth21GrantsAndResponses([]string{"password"}, nil)
	if err == nil {
		t.Fatal("expected rejection of grant_type=password (ROPC), got nil")
	}
	if !strings.Contains(err.Error(), "invalid_client_metadata") {
		t.Fatalf("expected RFC 7591 invalid_client_metadata error code, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Resource Owner Password Credentials") {
		t.Fatalf("error message should reference ROPC for operator clarity, got: %v", err)
	}
}

// TestValidateOAuth21GrantsAndResponses_RejectsImplicitGrant — separate
// from the implicit response_type tests because the implicit "grant"
// (RFC 6749 §4.2) is what shows up in the grant_types column when an
// admin tool inadvertently mirrors the response_type into grant_types.
func TestValidateOAuth21GrantsAndResponses_RejectsImplicitGrant(t *testing.T) {
	t.Parallel()
	s := &OAuthProviderService{}
	err := s.validateOAuth21GrantsAndResponses([]string{"implicit"}, nil)
	if err == nil {
		t.Fatal("expected rejection of grant_type=implicit, got nil")
	}
	if !strings.Contains(err.Error(), "invalid_client_metadata") {
		t.Fatalf("expected RFC 7591 invalid_client_metadata error code, got: %v", err)
	}
}

// TestValidateOAuth21GrantsAndResponses_MixedRejectStillRejects — a
// client that asks for one good and one bad value must be rejected.
// Otherwise an attacker can request `[authorization_code, password]`
// and still get the password handler if any future codepath dispatches
// on the first element.
func TestValidateOAuth21GrantsAndResponses_MixedRejectStillRejects(t *testing.T) {
	t.Parallel()
	s := &OAuthProviderService{}
	err := s.validateOAuth21GrantsAndResponses(
		[]string{"authorization_code", "password"},
		[]string{"code", "id_token"},
	)
	if err == nil {
		t.Fatal("expected rejection on mixed conformant + non-conformant input, got nil")
	}
}
