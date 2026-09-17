// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "testing"

func TestIsReservedSlug(t *testing.T) {
	cases := []struct {
		slug string
		want bool
	}{
		// Brand
		{"hexxlock", true},
		{"HexxLock", true}, // case-insensitive
		{" hexxlock ", true},
		{"hexx", true},
		{"falcon-id", true},
		// Operator namespace
		{"admin", true},
		{"api", true},
		{"www", true},
		{"login", true},
		{"oauth", true},
		{"platform", true},
		{"sso", true},
		// Technical
		{"default", true},
		{"shared", true},
		{"localhost", true},
		// Customer-allowed
		{"acme-corp", false},
		{"my-cool-saas", false},
		{"customer1", false},
		{"123-test-co", false},
	}
	for _, tc := range cases {
		t.Run(tc.slug, func(t *testing.T) {
			if got := IsReservedSlug(tc.slug); got != tc.want {
				t.Errorf("IsReservedSlug(%q) = %v, want %v", tc.slug, got, tc.want)
			}
		})
	}
}

func TestIsValidSlug(t *testing.T) {
	cases := []struct {
		slug string
		want bool
	}{
		{"acme", true},
		{"acme-corp", true},
		{"foo123", true},
		{"a1b2c3-x", true},
		{"abc", true},     // 3-char minimum
		{"ab", false},     // too short
		{"-abc", false},   // leading hyphen
		{"abc-", false},   // trailing hyphen
		{"a--b", false},   // consecutive hyphen (xn-- punycode collision)
		{"ABC", false},    // uppercase
		{"abc_def", false}, // underscore not allowed
		{"abc.def", false}, // dot not allowed
		{"abç", false},    // non-ASCII (IDN homograph guard)
		{"a.b.c", false},
		{"", false},
		// 64 chars (over 63 RFC 1035 cap)
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		// 63 chars exactly — boundary
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
	}
	for _, tc := range cases {
		t.Run(tc.slug, func(t *testing.T) {
			if got := IsValidSlug(tc.slug); got != tc.want {
				t.Errorf("IsValidSlug(%q) = %v, want %v", tc.slug, got, tc.want)
			}
		})
	}
}
