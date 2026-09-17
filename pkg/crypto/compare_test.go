// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "equal strings",
			a:    "hello",
			b:    "hello",
			want: true,
		},
		{
			name: "equal empty strings",
			a:    "",
			b:    "",
			want: true,
		},
		{
			name: "different strings same length",
			a:    "hello",
			b:    "world",
			want: false,
		},
		{
			name: "different lengths — a shorter",
			a:    "hi",
			b:    "hello",
			want: false,
		},
		{
			name: "different lengths — a longer",
			a:    "hello world",
			b:    "hello",
			want: false,
		},
		{
			name: "one empty one non-empty",
			a:    "",
			b:    "notempty",
			want: false,
		},
		{
			name: "non-empty vs empty",
			a:    "notempty",
			b:    "",
			want: false,
		},
		{
			name: "equal long strings (token-like)",
			a:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			b:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			want: true,
		},
		{
			name: "differ by last character only",
			a:    "abc123X",
			b:    "abc123Y",
			want: false,
		},
		{
			name: "differ by first character only",
			a:    "Xbc123",
			b:    "Ybc123",
			want: false,
		},
		{
			name: "unicode equal",
			a:    "paßwörd",
			b:    "paßwörd",
			want: true,
		},
		{
			name: "unicode different",
			a:    "paßwörd",
			b:    "password",
			want: false,
		},
		{
			name: "special characters equal",
			a:    "!@#$%^&*()",
			b:    "!@#$%^&*()",
			want: true,
		},
		{
			name: "special characters different",
			a:    "!@#$%^&*()",
			b:    "!@#$%^&*(!",
			want: false,
		},
		{
			name: "equal 128-char strings",
			a:    strings.Repeat("a", 128),
			b:    strings.Repeat("a", 128),
			want: true,
		},
		{
			name: "long strings differ by one byte",
			a:    strings.Repeat("a", 127) + "x",
			b:    strings.Repeat("a", 127) + "y",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SecureCompare(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestSecureCompare_Symmetry verifies that SecureCompare(a, b) == SecureCompare(b, a).
func TestSecureCompare_Symmetry(t *testing.T) {
	pairs := [][2]string{
		{"hello", "hello"},
		{"hello", "world"},
		{"abc", "abcd"},
		{"", "x"},
	}
	for _, pair := range pairs {
		a, b := pair[0], pair[1]
		assert.Equal(t, SecureCompare(a, b), SecureCompare(b, a),
			"SecureCompare must be symmetric for (%q, %q)", a, b)
	}
}

// TestSecureCompare_NoEarlyReturn ensures that length-differing strings still
// undergo a constant-time path without panicking.
func TestSecureCompare_NoEarlyReturn(t *testing.T) {
	// These lengths trigger the dummy-compare branch.
	result := SecureCompare("short", "a-much-longer-string-here")
	assert.False(t, result)
}

// TestSecureCompare_TokenComparison exercises the typical production use case:
// comparing an untrusted token hash against a stored hash.
func TestSecureCompare_TokenComparison(t *testing.T) {
	stored := "bGZoWjBZSGp3ZzVOSjhubUpYWXlDNTVLM09mY3R2MnR5ek9jMkRRWFRRcz0="
	provided := "bGZoWjBZSGp3ZzVOSjhubUpYWXlDNTVLM09mY3R2MnR5ek9jMkRRWFRRcz0="
	tampered := "bGZoWjBZSGp3ZzVOSjhubUpYWXlDNTVLM09mY3R2MnR5ek9jMkRRWFRRcz1="

	assert.True(t, SecureCompare(stored, provided), "equal hashes must match")
	assert.False(t, SecureCompare(stored, tampered), "tampered hash must not match")
}
