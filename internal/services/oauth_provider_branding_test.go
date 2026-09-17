// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBrandingURIs_AcceptsHTTPS(t *testing.T) {
	logo := "https://cdn.example.com/logo.png"
	homepage := "https://example.com"
	tos := "https://example.com/terms"
	policy := "https://example.com/privacy"

	require.NoError(t, validateBrandingURIs(&logo, &homepage, &tos, &policy))
}

func TestValidateBrandingURIs_AcceptsAllNil(t *testing.T) {
	// Caller may not be touching any branding fields. nil pointer is "no
	// change" — must not error.
	require.NoError(t, validateBrandingURIs(nil, nil, nil, nil))
}

func TestValidateBrandingURIs_AcceptsEmptyStringPointer(t *testing.T) {
	// Caller wants to clear a previously-registered URI. Empty string
	// short-circuits validation; the model layer drops the field.
	empty := ""
	require.NoError(t, validateBrandingURIs(&empty, &empty, &empty, &empty))
}

func TestValidateBrandingURIs_RejectsHTTP(t *testing.T) {
	cases := map[string]*string{
		"logo_url":   brandingPtr("http://example.com/logo.png"),
		"client_uri": brandingPtr("http://example.com"),
		"tos_url":    brandingPtr("http://example.com/terms"),
		"policy_url": brandingPtr("http://example.com/privacy"),
	}
	for field, val := range cases {
		t.Run(field, func(t *testing.T) {
			var l, c, p, q *string
			switch field {
			case "logo_url":
				l = val
			case "client_uri":
				c = val
			case "tos_url":
				p = val
			case "policy_url":
				q = val
			}
			err := validateBrandingURIs(l, c, p, q)
			require.Error(t, err)
			assert.True(t,
				strings.Contains(err.Error(), field) && strings.Contains(err.Error(), "https"),
				"error should name the offending field and require https — got %q", err.Error(),
			)
		})
	}
}

func TestValidateBrandingURIs_RejectsMalformed(t *testing.T) {
	// net/url.Parse is lenient — these inputs return nil err but the
	// host check catches them. Validates the post-parse guard.
	bad := "https:/missing-host"
	err := validateBrandingURIs(nil, &bad, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_uri")
	assert.Contains(t, err.Error(), "host")
}

func TestValidateBrandingURIs_RejectsOverLimit(t *testing.T) {
	long := "https://" + strings.Repeat("a", brandingURIMaxLen) + ".example.com/logo.png"
	err := validateBrandingURIs(&long, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logo_url")
	assert.Contains(t, err.Error(), "1024")
}

func brandingPtr(s string) *string { return &s }
