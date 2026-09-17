// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// identity_provider_login_ready_test.go pins which providers may be offered as
// a login option.
//
// The failure being guarded: an enabled-but-uncredentialed row used to render a
// button, and clicking it sent the user to the IdP with client_id= empty, so the
// error appeared on the IdP's property rather than ours.

import "testing"

func strptr(s string) *string { return &s }

func TestLoginConfigurationError(t *testing.T) {
	cases := []struct {
		name    string
		p       IdentityProvider
		wantErr bool
	}{
		{
			// POSITIVE CONTROL. A rule that rejects everything passes every
			// negative case below while removing all social login.
			name:    "credentialed oidc provider is offerable",
			p:       IdentityProvider{Type: "oidc", Name: "google", ClientID: strptr("cid"), AuthorizationURL: strptr("https://idp/auth")},
			wantErr: false,
		},
		{
			name:    "oidc with no client_id is refused",
			p:       IdentityProvider{Type: "oidc", Name: "google", AuthorizationURL: strptr("https://idp/auth")},
			wantErr: true,
		},
		{
			name:    "oidc with empty client_id is refused",
			p:       IdentityProvider{Type: "oidc", Name: "google", ClientID: strptr(""), AuthorizationURL: strptr("https://idp/auth")},
			wantErr: true,
		},
		{
			name:    "oidc with no authorization_url is refused",
			p:       IdentityProvider{Type: "oidc", Name: "google", ClientID: strptr("cid")},
			wantErr: true,
		},
		{
			// LDAP and SAML keep credentials in their own config blocks. An
			// OAuth credential rule must not sweep them up.
			name:    "ldap needs no client_id",
			p:       IdentityProvider{Type: "ldap", Name: "corp-ad"},
			wantErr: false,
		},
		{
			name:    "saml needs no client_id",
			p:       IdentityProvider{Type: "saml", Name: "corp-saml"},
			wantErr: false,
		},
		{
			// Polarity check: an unrecognised type must be REQUIRED to prove it
			// is configured, not silently exempted by an enumeration nobody
			// updated when the type was added.
			name:    "unknown provider type must still be credentialed",
			p:       IdentityProvider{Type: "some-new-oauth-provider", Name: "new"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.LoginConfigurationError()
			if tc.wantErr && err == nil {
				t.Fatalf("expected %q to be refused, but it was offerable", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected %q to be offerable, got refusal: %v", tc.name, err)
			}
			if tc.p.IsLoginReady() == tc.wantErr {
				t.Fatal("IsLoginReady disagrees with LoginConfigurationError")
			}
		})
	}
}
