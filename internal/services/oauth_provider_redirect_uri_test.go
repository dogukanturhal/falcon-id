// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"strings"
	"testing"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

func TestValidateRedirectURI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		tenantType models.TenantType
		uri        string
		wantErr    bool
		errSubstr  string
	}{
		// Production-tier accepts: https with any non-loopback host.
		{name: "prod_https_apex_ok", tenantType: models.TenantTypeCustomer, uri: "https://app.example.com/auth/callback"},
		{name: "prod_https_subdomain_ok", tenantType: models.TenantTypeCustomer, uri: "https://accounts.example.com/api/auth/oidc-callback"},
		{name: "prod_https_with_port_ok", tenantType: models.TenantTypeInternal, uri: "https://app.example.com:8443/auth/callback"},
		{name: "prod_https_with_query_ok", tenantType: models.TenantTypePartner, uri: "https://app.example.com/auth/callback?app=widget"},

		// Production-tier rejects: http scheme on any host.
		{name: "prod_http_apex_rejects", tenantType: models.TenantTypeCustomer, uri: "http://app.example.com/auth/callback", wantErr: true, errSubstr: "https"},
		// http://localhost on prod: http-scheme check fires first (more
		// specific diagnostic than "loopback"). Either reason is correct;
		// the test pins the actual message.
		{name: "prod_http_localhost_rejects", tenantType: models.TenantTypeInternal, uri: "http://localhost:3002/auth/callback", wantErr: true, errSubstr: "https"},
		{name: "prod_http_127_rejects", tenantType: models.TenantTypeTrial, uri: "http://127.0.0.1:3002/auth/callback", wantErr: true, errSubstr: "https"},
		{name: "prod_https_localhost_rejects", tenantType: models.TenantTypeCustomer, uri: "https://localhost:3002/auth/callback", wantErr: true, errSubstr: "loopback"},
		{name: "prod_https_ipv6_loopback_rejects", tenantType: models.TenantTypeCustomer, uri: "https://[::1]:3002/auth/callback", wantErr: true, errSubstr: "loopback"},
		{name: "prod_localhost_subdomain_rejects", tenantType: models.TenantTypeCustomer, uri: "https://api.localhost/auth/callback", wantErr: true, errSubstr: "loopback"},

		// Sandbox-tier accepts: https anywhere, http on loopback only.
		{name: "sandbox_https_anywhere_ok", tenantType: models.TenantTypeDemo, uri: "https://dev.example.com/auth/callback"},
		{name: "sandbox_http_localhost_ok", tenantType: models.TenantTypeDemo, uri: "http://localhost:3002/auth/callback"},
		{name: "sandbox_http_127_ok", tenantType: models.TenantTypeDemo, uri: "http://127.0.0.1:3002/auth/callback"},
		{name: "sandbox_http_ipv6_loopback_ok", tenantType: models.TenantTypeDemo, uri: "http://[::1]:3002/auth/callback"},
		{name: "sandbox_http_localhost_subdomain_ok", tenantType: models.TenantTypeDemo, uri: "http://app.localhost:3002/auth/callback"},
		{name: "sandbox_https_localhost_ok", tenantType: models.TenantTypeDemo, uri: "https://localhost:3002/auth/callback"},

		// Sandbox-tier rejects: http on non-loopback (still no plaintext to the internet).
		{name: "sandbox_http_apex_rejects", tenantType: models.TenantTypeDemo, uri: "http://example.com/auth/callback", wantErr: true, errSubstr: "loopback"},

		// Universal rejects (all tenant types).
		{name: "empty_rejects_prod", tenantType: models.TenantTypeCustomer, uri: "", wantErr: true, errSubstr: "must not be empty"},
		{name: "empty_rejects_sandbox", tenantType: models.TenantTypeDemo, uri: "", wantErr: true, errSubstr: "must not be empty"},
		{name: "fragment_rejects_prod", tenantType: models.TenantTypeCustomer, uri: "https://app.example.com/auth/callback#fragment", wantErr: true, errSubstr: "fragment"},
		{name: "fragment_rejects_sandbox", tenantType: models.TenantTypeDemo, uri: "http://localhost:3002/auth/callback#x", wantErr: true, errSubstr: "fragment"},
		{name: "wildcard_path_rejects", tenantType: models.TenantTypeCustomer, uri: "https://app.example.com/auth/*", wantErr: true, errSubstr: "wildcard"},
		{name: "wildcard_host_rejects", tenantType: models.TenantTypeDemo, uri: "https://*.example.com/auth/callback", wantErr: true, errSubstr: "wildcard"},
		{name: "ftp_scheme_rejects", tenantType: models.TenantTypeCustomer, uri: "ftp://example.com/cb", wantErr: true, errSubstr: "scheme"},
		{name: "custom_scheme_rejects", tenantType: models.TenantTypeDemo, uri: "myapp://callback", wantErr: true, errSubstr: "scheme"},
		{name: "javascript_scheme_rejects", tenantType: models.TenantTypeCustomer, uri: "javascript:alert(1)", wantErr: true, errSubstr: "scheme"},
		{name: "no_host_rejects", tenantType: models.TenantTypeCustomer, uri: "https:///cb", wantErr: true, errSubstr: "host"},
		{name: "too_long_rejects", tenantType: models.TenantTypeCustomer, uri: "https://app.example.com/" + strings.Repeat("a", 1025), wantErr: true, errSubstr: "exceeds"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedirectURI(tc.tenantType, tc.uri, false, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRedirectURI(%q, %q) = nil, want error containing %q", tc.tenantType, tc.uri, tc.errSubstr)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("validateRedirectURI(%q, %q) error = %q, want substring %q", tc.tenantType, tc.uri, err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRedirectURI(%q, %q) = %v, want nil", tc.tenantType, tc.uri, err)
			}
		})
	}
}

func TestValidateRedirectURIs_ListSemantics(t *testing.T) {
	t.Parallel()

	t.Run("empty_list_ok", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURIs(models.TenantTypeCustomer, nil, false, nil); err != nil {
			t.Fatalf("validateRedirectURIs(nil) = %v, want nil", err)
		}
	})

	t.Run("all_valid_ok", func(t *testing.T) {
		t.Parallel()
		uris := []string{
			"https://app.example.com/auth/callback",
			"https://app.example.com/api/auth/oidc-callback",
		}
		if err := validateRedirectURIs(models.TenantTypeCustomer, uris, false, nil); err != nil {
			t.Fatalf("validateRedirectURIs(valid prod set) = %v, want nil", err)
		}
	})

	t.Run("first_invalid_returned", func(t *testing.T) {
		t.Parallel()
		uris := []string{
			"http://example.com/cb",
			"https://app.example.com/cb",
		}
		err := validateRedirectURIs(models.TenantTypeCustomer, uris, false, nil)
		if err == nil {
			t.Fatalf("validateRedirectURIs(mixed) = nil, want error on first http entry")
		}
	})

	t.Run("sandbox_mixed_valid_ok", func(t *testing.T) {
		t.Parallel()
		uris := []string{
			"http://localhost:3002/auth/callback",
			"http://localhost:3002/api/auth/oidc-callback",
		}
		if err := validateRedirectURIs(models.TenantTypeDemo, uris, false, nil); err != nil {
			t.Fatalf("validateRedirectURIs(sandbox localhost set) = %v, want nil", err)
		}
	})
}

// TestValidateRedirectURI_NativeApp verifies the RFC 8252 §7.3 carve-out:
// public + first-party + PKCE clients MAY register loopback redirect URIs
// on production tenants. Non-native clients on the same tenant still reject.
func TestValidateRedirectURI_NativeApp(t *testing.T) {
	t.Parallel()
	prodTenant := models.TenantTypeCustomer

	t.Run("native_loopback_127_0_0_1_ok", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURI(prodTenant, "http://127.0.0.1/oidc-callback", true, nil); err != nil {
			t.Fatalf("native loopback rejected: %v", err)
		}
	})
	t.Run("native_loopback_localhost_ok", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURI(prodTenant, "http://localhost/oidc-callback", true, nil); err != nil {
			t.Fatalf("native loopback rejected: %v", err)
		}
	})
	t.Run("native_loopback_ipv6_ok", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURI(prodTenant, "http://[::1]/oidc-callback", true, nil); err != nil {
			t.Fatalf("native loopback rejected: %v", err)
		}
	})
	t.Run("native_loopback_with_port_ok", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURI(prodTenant, "http://127.0.0.1:45829/oidc-callback", true, nil); err != nil {
			t.Fatalf("native loopback with port rejected: %v", err)
		}
	})
	t.Run("non_native_loopback_still_rejected", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURI(prodTenant, "http://127.0.0.1/oidc-callback", false, nil); err == nil {
			t.Fatal("non-native loopback should be rejected on prod tenant")
		}
	})
	t.Run("native_https_remote_still_ok", func(t *testing.T) {
		t.Parallel()
		if err := validateRedirectURI(prodTenant, "https://accounts.example.com/cb", true, nil); err != nil {
			t.Fatalf("native https remote rejected: %v", err)
		}
	})
}

// TestMatchRedirectURI covers the RFC 8252 §7.3 port-fuzzy match used
// at /oauth/authorize. Loopback URIs match across ports; non-loopback
// URIs must be exact-string equal.
func TestMatchRedirectURI(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		registered []string
		requested  string
		want       bool
	}{
		{
			name:       "exact non-loopback hit",
			registered: []string{"https://accounts.example.com/cb"},
			requested:  "https://accounts.example.com/cb",
			want:       true,
		},
		{
			name:       "non-loopback wrong path",
			registered: []string{"https://accounts.example.com/cb"},
			requested:  "https://accounts.example.com/other",
			want:       false,
		},
		{
			name:       "non-loopback port mismatch is rejected",
			registered: []string{"https://accounts.example.com/cb"},
			requested:  "https://accounts.example.com:8443/cb",
			want:       false,
		},
		{
			name:       "loopback 127.0.0.1 port fuzz",
			registered: []string{"http://127.0.0.1/oidc-callback"},
			requested:  "http://127.0.0.1:45829/oidc-callback",
			want:       true,
		},
		{
			name:       "loopback localhost port fuzz",
			registered: []string{"http://localhost/oidc-callback"},
			requested:  "http://localhost:31337/oidc-callback",
			want:       true,
		},
		{
			name:       "loopback ::1 port fuzz",
			registered: []string{"http://[::1]/oidc-callback"},
			requested:  "http://[::1]:8080/oidc-callback",
			want:       true,
		},
		{
			name:       "loopback path mismatch still rejects",
			registered: []string{"http://127.0.0.1/oidc-callback"},
			requested:  "http://127.0.0.1:45829/other",
			want:       false,
		},
		{
			name:       "loopback scheme mismatch rejects",
			registered: []string{"http://127.0.0.1/cb"},
			requested:  "https://127.0.0.1/cb",
			want:       false,
		},
		{
			name:       "loopback query mismatch rejects",
			registered: []string{"http://127.0.0.1/cb"},
			requested:  "http://127.0.0.1:45829/cb?attacker=1",
			want:       false,
		},
		{
			name:       "registered with port, request with different port — still loopback fuzz",
			registered: []string{"http://127.0.0.1:8080/cb"},
			requested:  "http://127.0.0.1:9090/cb",
			want:       true,
		},
		{
			name: "multi-registered — first non-loopback exact, second loopback",
			registered: []string{
				"https://accounts.example.com/cb",
				"http://127.0.0.1/cb",
			},
			requested: "http://127.0.0.1:45829/cb",
			want:      true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := matchRedirectURI(tc.registered, tc.requested)
			if got != tc.want {
				t.Fatalf("matchRedirectURI(%v, %q) = %v, want %v",
					tc.registered, tc.requested, got, tc.want)
			}
		})
	}
}

func TestValidateRedirectURI_PrivateUseScheme(t *testing.T) {
	allow := []string{"example.com"}
	cases := []struct {
		name   string
		uri    string
		native bool
		allow  []string
		ok     bool
	}{
		{"single slash", "com.example.app:/oauth/callback", true, allow, true},
		{"with host", "com.example.app://auth/oauth/callback", true, allow, true},
		{"subdomain of allowed", "com.example.beta.app:/cb", true, allow, true},
		{"javascript", "javascript:alert(1)", true, allow, false},
		{"no dot", "myapp:/x", true, allow, false},
		{"foreign domain", "com.evil.app:/x", true, allow, false},
		{"non-native client", "com.example.app:/oauth/callback", false, allow, false},
		{"fragment", "com.example.app:/x#f", true, allow, false},
		{"port", "com.example.app://host:80/x", true, allow, false},
		{"userinfo", "com.example.app://u@host/x", true, allow, false},
		{"wildcard", "com.example.app:/x*", true, allow, false},
		{"uppercase scheme", "COM.acmeapp.app:/x", true, allow, false},
		{"allowlist empty", "com.example.app:/oauth/callback", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRedirectURI(models.TenantTypeCustomer, tc.uri, tc.native, tc.allow)
			if tc.ok && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("want error for %q", tc.uri)
			}
		})
	}
}

func TestValidatePostLogoutRedirectURIs_Scheme(t *testing.T) {
	allow := []string{"example.com"}
	if err := validatePostLogoutRedirectURIs([]string{"https://example.com/x", "com.example.app:/oauth/logout"}, true, allow); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if err := validatePostLogoutRedirectURIs([]string{"com.evil.app:/x"}, true, allow); err == nil {
		t.Fatal("foreign scheme accepted")
	}
	if err := validatePostLogoutRedirectURIs([]string{"com.example.app:/x"}, false, allow); err == nil {
		t.Fatal("non-native accepted")
	}
	if err := validatePostLogoutRedirectURIs([]string{"com.example.app:/x"}, true, nil); err == nil {
		t.Fatal("empty allowlist accepted")
	}
}
