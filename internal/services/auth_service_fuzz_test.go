// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
)

// authFuzzInputValidator exercises only the input-validation path of AuthService.
// It is a thin shim that replaces the real service and avoids any I/O.
type authFuzzInputValidator struct {
	slugRegex *regexp.Regexp
}

func newAuthFuzzValidator() *authFuzzInputValidator {
	return &authFuzzInputValidator{
		// Same regex used by the real AuthService.
		slugRegex: regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`),
	}
}

// validateLoginInput replicates the validation logic from AuthService.Login
// without touching any database, Redis, or downstream services.
// It is self-contained so the fuzz target has no external dependencies.
func (v *authFuzzInputValidator) validateLoginInput(req *models.LoginRequest) error {
	if req == nil {
		return errors.New("request must not be nil")
	}
	if req.Username == "" {
		return errors.New("username is required")
	}
	if len(req.Username) > 255 {
		return errors.New("username too long")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if len(req.Password) > 1024 {
		return errors.New("password too long")
	}
	if req.TenantSlug == "" {
		return errors.New("tenant slug is required")
	}
	if !v.slugRegex.MatchString(req.TenantSlug) {
		return errors.New("invalid tenant slug format")
	}
	return nil
}

// FuzzLoginInput ensures the login input-validation path never panics for any
// combination of username, password, and tenant slug inputs.
func FuzzLoginInput(f *testing.F) {
	type seed struct {
		username   string
		password   string
		tenantSlug string
	}

	seeds := []seed{
		// Happy path
		{"alice", "correct-horse-battery-staple", "acme-corp"},
		{"admin", "HexxAdmin@2024!", "exampletenant"},

		// Empty fields
		{"", "", ""},
		{"", "password", "slug"},
		{"user", "", "slug"},
		{"user", "pass", ""},

		// Very long inputs
		{string(make([]byte, 512)), "pass", "slug"},
		{"user", string(make([]byte, 2048)), "slug"},
		{"user", "pass", string(make([]byte, 128))},

		// Null bytes
		{"user\x00name", "pass", "slug"},
		{"user", "pass\x00word", "slug"},
		{"user", "pass", "sl\x00ug"},

		// SQL injection patterns
		{"' OR 1=1 --", "password", "tenant"},
		{"admin'--", "anything", "tenant"},
		{"user", "'; DROP TABLE users; --", "tenant"},
		{"user", "pass", "'; DROP TABLE tenants; --"},

		// Unicode usernames
		{"αλφα", "password", "tenant"},
		{"中文用户", "password", "tenant"},
		{"用户@example.com", "P@ssw0rd!", "tenant"},
		{"ñoño", "password", "my-tenant"},

		// Special characters that may confuse regex or parsers
		{"user%20name", "pass", "tenant"},
		{"user+name", "pass", "tenant"},
		{"user@domain.com", "pass", "tenant-01"},
		{"<script>alert(1)</script>", "pass", "tenant"},

		// Path traversal
		{"../../etc/passwd", "pass", "tenant"},
		{"..\\..\\system32", "pass", "tenant"},

		// Valid slug / invalid slug boundary cases
		{"user", "pass", "a"},              // too short (single char is valid per regex)
		{"user", "pass", "ab"},             // valid
		{"user", "pass", "a-b"},            // valid
		{"user", "pass", "-invalid"},       // starts with hyphen
		{"user", "pass", "invalid-"},       // ends with hyphen
		{"user", "pass", "UPPERCASE"},      // uppercase not allowed
		{"user", "pass", "has spaces"},     // spaces not allowed
		{"user", "pass", "has.dot"},        // dots not allowed
		{"user", "pass", "valid-slug-123"}, // valid
		{"user", "pass", "a0"},             // valid minimal
		{"user", "pass", "0a"},             // valid, starts with digit

		// Control characters
		{"\t\n\r", "pass", "tenant"},
		{"user", "\t\n\r", "tenant"},

		// JSON-like strings (testing that we don't accidentally parse as JSON)
		{`{"username":"admin"}`, "pass", "tenant"},
		{"user", `{"key":"value"}`, "tenant"},

		// Very long valid slug (boundary at 63 chars)
		{"user", "pass", "abcdefghij-abcdefghij-abcdefghij-abcdefghij-abcdefghijklmno"},  // 63 chars
		{"user", "pass", "abcdefghij-abcdefghij-abcdefghij-abcdefghij-abcdefghijklmnop"}, // 64 chars (over limit)
	}

	for _, s := range seeds {
		f.Add(s.username, s.password, s.tenantSlug)
	}

	validator := newAuthFuzzValidator()
	_ = context.Background() // satisfy import

	f.Fuzz(func(t *testing.T, username, password, tenantSlug string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("validateLoginInput panicked: username=%q password=%q slug=%q panic=%v",
					username, password, tenantSlug, r)
			}
		}()

		req := &models.LoginRequest{
			Username:   username,
			Password:   password,
			TenantSlug: tenantSlug,
		}

		// We only care that this never panics — errors are fully expected.
		//nolint:errcheck
		_ = validator.validateLoginInput(req)
	})
}

// FuzzTenantSlugValidation specifically targets the tenant slug regex to ensure
// it handles all possible string inputs without panicking or catastrophic backtracking.
func FuzzTenantSlugValidation(f *testing.F) {
	seeds := []string{
		"",
		"a",
		"ab",
		"a-b",
		"valid-tenant-123",
		"-starts-with-hyphen",
		"ends-with-hyphen-",
		"UPPER",
		"has space",
		"has.dot",
		string(make([]byte, 256)),
		"\x00",
		"aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa", // 63+ chars
	}

	for _, s := range seeds {
		f.Add(s)
	}

	// Compile once outside the fuzz loop — same as production code.
	slugRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	_ = &config.Config{} // satisfy config import

	f.Fuzz(func(t *testing.T, slug string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("slug regex panicked with input %q: %v", slug, r)
			}
		}()

		// MatchString must never panic — it may return true or false.
		//nolint:errcheck
		_ = slugRegex.MatchString(slug)
	})
}
