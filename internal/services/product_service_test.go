// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSlugify exercises the package-private slugify helper that the ProductService
// uses to derive a URL-safe slug from a product name when none is provided.
func TestSlugify(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic lowercasing
		{
			name:     "should lower-case an all-uppercase name",
			input:    "MYPRODUCT",
			expected: "myproduct",
		},
		{
			name:     "should lower-case a mixed-case name",
			input:    "MyProduct",
			expected: "myproduct",
		},

		// Space handling
		{
			name:     "should replace a single space with a hyphen",
			input:    "my product",
			expected: "my-product",
		},
		{
			name:     "should collapse multiple spaces into a single hyphen",
			input:    "my   product",
			expected: "my-product",
		},
		{
			name:     "should trim leading and trailing spaces",
			input:    "  my product  ",
			expected: "my-product",
		},

		// Special character handling
		{
			name:     "should replace an underscore with a hyphen",
			input:    "my_product",
			expected: "my-product",
		},
		{
			name:     "should replace a dot with a hyphen",
			input:    "my.product",
			expected: "my-product",
		},
		{
			name:     "should replace multiple consecutive special chars with one hyphen",
			input:    "my---product",
			expected: "my-product",
		},
		{
			name:     "should replace mixed special chars with one hyphen",
			input:    "my._-product",
			expected: "my-product",
		},

		// Numbers
		{
			name:     "should keep numbers intact",
			input:    "product 2024",
			expected: "product-2024",
		},
		{
			name:     "should handle numeric-only input",
			input:    "12345",
			expected: "12345",
		},

		// Trimming of leading/trailing hyphens
		{
			name:     "should strip leading hyphens caused by leading special chars",
			input:    "!hello",
			expected: "hello",
		},
		{
			name:     "should strip trailing hyphens caused by trailing special chars",
			input:    "hello!",
			expected: "hello",
		},
		{
			name:     "should strip both leading and trailing hyphens",
			input:    "!hello world!",
			expected: "hello-world",
		},

		// Real-world product name examples
		{
			name:     "typical product name",
			input:    "Examplesuite",
			expected: "examplesuite",
		},
		{
			name:     "product name with version",
			input:    "Falcon ID v2",
			expected: "falcon-id-v2",
		},
		{
			name:     "product name with ampersand",
			input:    "Sales & Marketing",
			expected: "sales-marketing",
		},
		{
			name:     "product name with parentheses",
			input:    "CRM (Enterprise)",
			expected: "crm-enterprise",
		},
		{
			name:     "already slug-like name",
			input:    "my-product",
			expected: "my-product",
		},
		{
			name:     "single word lower-case",
			input:    "falcon",
			expected: "falcon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slugify(tt.input)
			assert.Equal(t, tt.expected, got,
				"slugify(%q) = %q, want %q", tt.input, got, tt.expected)
		})
	}
}

// TestSlugifyRegex verifies the underlying regular expression is compiled and
// behaves correctly for the raw character-class replacement.
func TestSlugifyRegex(t *testing.T) {
	t.Run("compiled regex replaces non-alphanumeric runs", func(t *testing.T) {
		// nonAlphanumRE is the package-level compiled regex used by slugify.
		result := nonAlphanumRE.ReplaceAllString("hello world!", "-")
		assert.Equal(t, "hello-world-", result)
	})

	t.Run("compiled regex does not replace alphanumeric characters", func(t *testing.T) {
		result := nonAlphanumRE.ReplaceAllString("abc123", "-")
		assert.Equal(t, "abc123", result)
	})
}

// BenchmarkSlugify measures the performance of the slugify function across a
// representative set of inputs.
func BenchmarkSlugify(b *testing.B) {
	cases := []struct {
		name  string
		input string
	}{
		{"short plain", "falcon"},
		{"short mixed", "Falcon ID"},
		{"long mixed", "Enterprise Resource Planning Suite v3.0 (Professional Edition)"},
		{"special chars", "My Product! @ 2024 #release"},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = slugify(c.input)
			}
		})
	}
}
