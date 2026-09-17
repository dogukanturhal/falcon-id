// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateTenantSlug tests the tenant slug validation function
func TestValidateTenantSlug(t *testing.T) {
	tests := []struct {
		name    string
		slug    string
		wantErr bool
		errMsg  string
	}{
		// Happy path cases
		{
			name:    "should accept valid slug with letters only",
			slug:    "acmecorp",
			wantErr: false,
		},
		{
			name:    "should accept valid slug with letters and numbers",
			slug:    "acme123",
			wantErr: false,
		},
		{
			name:    "should accept valid slug with hyphens",
			slug:    "acme-corp",
			wantErr: false,
		},
		{
			name:    "should accept valid slug with multiple hyphens",
			slug:    "acme-corp-2024",
			wantErr: false,
		},
		{
			name:    "should accept single character slug",
			slug:    "a",
			wantErr: false,
		},
		{
			name:    "should accept maximum length slug (63 chars)",
			slug:    "a123456789012345678901234567890123456789012345678901234567890bc",
			wantErr: false,
		},

		// Error cases - length constraints
		{
			name:    "should reject empty slug",
			slug:    "",
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "should reject slug exceeding 63 characters",
			slug:    "a1234567890123456789012345678901234567890123456789012345678901234",
			wantErr: true,
			errMsg:  "must be at most 63 characters",
		},

		// Error cases - format validation
		{
			name:    "should reject slug with uppercase letters",
			slug:    "AcmeCorp",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "should reject slug starting with hyphen",
			slug:    "-acme",
			wantErr: true,
			errMsg:  "must start and end",
		},
		{
			name:    "should reject slug ending with hyphen",
			slug:    "acme-",
			wantErr: true,
			errMsg:  "must start and end",
		},
		{
			name:    "should reject slug with consecutive hyphens",
			slug:    "acme--corp",
			wantErr: true,
			errMsg:  "consecutive hyphens",
		},
		{
			name:    "should reject slug with special characters",
			slug:    "acme_corp",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "should reject slug with spaces",
			slug:    "acme corp",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "should reject slug with dots",
			slug:    "acme.corp",
			wantErr: true,
			errMsg:  "lowercase",
		},

		// Error cases - SQL injection attempts
		{
			name:    "should reject SQL injection attempt with quotes",
			slug:    "acme'; DROP TABLE users--",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "should reject SQL injection with semicolon",
			slug:    "acme;delete",
			wantErr: true,
			errMsg:  "lowercase",
		},

		// Error cases - path traversal attempts
		{
			name:    "should reject path traversal with ../",
			slug:    "../etc/passwd",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "should reject path traversal with ./",
			slug:    "./admin",
			wantErr: true,
			errMsg:  "lowercase",
		},

		// Error cases - reserved slugs
		{
			name:    "should reject reserved slug: admin",
			slug:    "admin",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: api",
			slug:    "api",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: www",
			slug:    "www",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: localhost",
			slug:    "localhost",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: system",
			slug:    "system",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: root",
			slug:    "root",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: test",
			slug:    "test",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "should reject reserved slug: production",
			slug:    "production",
			wantErr: true,
			errMsg:  "reserved",
		},

		// Edge cases
		{
			name:    "should accept slug with numbers only",
			slug:    "12345",
			wantErr: false,
		},
		{
			name:    "should accept slug starting with number",
			slug:    "123acme",
			wantErr: false,
		},
		{
			name:    "should accept slug ending with number",
			slug:    "acme123",
			wantErr: false,
		},
		{
			name:    "should reject slug with emoji",
			slug:    "acme😀corp",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "should reject slug with unicode characters",
			slug:    "acmé-corp",
			wantErr: true,
			errMsg:  "lowercase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantSlug(tt.slug)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg,
						"error message should contain expected substring")
				}
			} else {
				require.NoError(t, err, "expected no error but got: %v", err)
			}
		})
	}
}

// TestValidateTenantSlugRegexPattern verifies the regex pattern itself
func TestValidateTenantSlugRegexPattern(t *testing.T) {
	tests := []struct {
		name        string
		slug        string
		shouldMatch bool
	}{
		{
			name:        "should match valid alphanumeric",
			slug:        "abc123",
			shouldMatch: true,
		},
		{
			name:        "should match with single hyphen",
			slug:        "abc-123",
			shouldMatch: true,
		},
		{
			name:        "should not match starting with hyphen",
			slug:        "-abc",
			shouldMatch: false,
		},
		{
			name:        "should not match ending with hyphen",
			slug:        "abc-",
			shouldMatch: false,
		},
		{
			name:        "should not match with uppercase",
			slug:        "ABC",
			shouldMatch: false,
		},
		{
			name:        "should match single character",
			slug:        "a",
			shouldMatch: true,
		},
		{
			name:        "should match two characters",
			slug:        "ab",
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := tenantSlugRegex.MatchString(tt.slug)
			assert.Equal(t, tt.shouldMatch, matches,
				"regex match result mismatch for slug: %s", tt.slug)
		})
	}
}

// TestTenantContext verifies the tenantContext structure
func TestTenantContext(t *testing.T) {
	t.Run("should create tenant context", func(t *testing.T) {
		ctx := &tenantContext{
			TenantSlug: "acme-corp",
			RealmSlug:  "main",
			RealmType:  "B2B",
		}

		assert.NotEmpty(t, ctx.TenantSlug)
		assert.NotEmpty(t, ctx.RealmSlug)
		assert.NotEmpty(t, ctx.RealmType)
	})
}

// Benchmark tests for tenant slug validation performance

func BenchmarkValidateTenantSlug(b *testing.B) {
	testCases := []struct {
		name string
		slug string
	}{
		{
			name: "valid short slug",
			slug: "acme",
		},
		{
			name: "valid long slug",
			slug: "acme-corporation-2024-production-deployment",
		},
		{
			name: "invalid with uppercase",
			slug: "AcmeCorp",
		},
		{
			name: "reserved slug",
			slug: "admin",
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = validateTenantSlug(tc.slug)
			}
		})
	}
}

// TestValidateTenantSlugConcurrency verifies thread-safety
func TestValidateTenantSlugConcurrency(t *testing.T) {
	t.Run("should be thread-safe", func(t *testing.T) {
		slugs := []string{
			"acme-corp",
			"example-tenant",
			"test-org",
			"demo-company",
			"my-tenant",
		}

		done := make(chan bool)
		for i := 0; i < 100; i++ {
			go func(idx int) {
				slug := slugs[idx%len(slugs)]
				err := validateTenantSlug(slug)
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		for i := 0; i < 100; i++ {
			<-done
		}
	})
}

// TestSecurityValidation verifies security-focused validation
func TestSecurityValidation(t *testing.T) {
	t.Run("should prevent all common injection attacks", func(t *testing.T) {
		attacks := []string{
			// SQL injection variants
			"'; DROP TABLE users--",
			"' OR '1'='1",
			"admin'--",
			"' UNION SELECT * FROM users--",

			// NoSQL injection variants
			"{$ne: null}",
			"{'$gt': ''}",

			// Path traversal variants
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32",
			"./../../secret",

			// Command injection variants
			"; ls -la",
			"| cat /etc/passwd",
			"& whoami",

			// XSS variants
			"<script>alert('xss')</script>",
			"javascript:alert(1)",
			"onerror=alert(1)",

			// LDAP injection variants
			"*)(uid=*",
			"admin)(|(password=*",
		}

		for _, attack := range attacks {
			t.Run("attack: "+attack, func(t *testing.T) {
				err := validateTenantSlug(attack)
				require.Error(t, err, "should reject injection attack: %s", attack)
			})
		}
	})
}

// TestReservedSlugsComprehensive ensures all reserved slugs are blocked
func TestReservedSlugsComprehensive(t *testing.T) {
	reservedSlugs := []string{
		"admin", "api", "www", "mail", "ftp", "localhost",
		"test", "demo", "staging", "prod", "production",
		"system", "root", "user", "public", "private",
		"internal", "external", "default",
	}

	for _, slug := range reservedSlugs {
		t.Run("reserved: "+slug, func(t *testing.T) {
			err := validateTenantSlug(slug)
			require.Error(t, err, "should reject reserved slug: %s", slug)
			assert.Contains(t, err.Error(), "reserved",
				"error should mention slug is reserved")
		})
	}
}

// TestBoundaryValues tests edge cases at boundaries
func TestBoundaryValues(t *testing.T) {
	tests := []struct {
		name    string
		slug    string
		wantErr bool
	}{
		{
			name:    "exactly 1 character (min valid)",
			slug:    "a",
			wantErr: false,
		},
		{
			name:    "exactly 63 characters (max valid)",
			slug:    "a123456789012345678901234567890123456789012345678901234567890bc",
			wantErr: false,
		},
		{
			name:    "exactly 64 characters (min invalid)",
			slug:    "a1234567890123456789012345678901234567890123456789012345678901234",
			wantErr: true,
		},
		{
			name:    "2 characters",
			slug:    "ab",
			wantErr: false,
		},
		{
			name:    "62 characters",
			slug:    "a12345678901234567890123456789012345678901234567890123456789bc",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantSlug(tt.slug)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRealWorldTenantSlugs tests realistic tenant slug patterns
func TestRealWorldTenantSlugs(t *testing.T) {
	tests := []struct {
		name    string
		slug    string
		wantErr bool
	}{
		{
			name:    "typical company name",
			slug:    "acme-corporation",
			wantErr: false,
		},
		{
			name:    "company with year",
			slug:    "startup-2024",
			wantErr: false,
		},
		{
			name:    "multi-word company",
			slug:    "big-tech-company",
			wantErr: false,
		},
		{
			name:    "company with numbers",
			slug:    "company123",
			wantErr: false,
		},
		{
			name:    "subsidiary or department",
			slug:    "acme-corp-sales",
			wantErr: false,
		},
		{
			name:    "international company",
			slug:    "company-uk",
			wantErr: false,
		},
		{
			name:    "versioned tenant",
			slug:    "tenant-v2",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTenantSlug(tt.slug)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "valid real-world slug should be accepted: %s", tt.slug)
			}
		})
	}
}
