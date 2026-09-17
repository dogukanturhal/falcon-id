// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"unicode"
	"unicode/utf8"

	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// SignupPasswordPolicy is the public, non-sensitive contract for local-password
// signup. It is built by the same UserService that persists the credential.
// Global login/reset/admin policy defaults are deliberately not changed here.
type SignupPasswordPolicy struct {
	Version        int    `json:"version"`
	LengthUnit     string `json:"length_unit"`
	MinLength      int    `json:"min_length"`
	MaxLength      int    `json:"max_length"` // 0 means no policy maximum
	RequireUpper   bool   `json:"require_upper"`
	RequireLower   bool   `json:"require_lower"`
	RequireDigit   bool   `json:"require_digit"`
	RequireSpecial bool   `json:"require_special"`
	BreachCheck    string `json:"breach_check"` // disabled or best_effort
}

// SignupPasswordError contains rule identifiers only, never the submitted value.
type SignupPasswordError struct {
	Policy     SignupPasswordPolicy `json:"policy"`
	Violations []string             `json:"violations"`
}

func (*SignupPasswordError) Error() string { return "password does not meet signup policy" }

// Validate evaluates the public contract itself. Count Unicode code points,
// not bytes or UTF-16 units; do not trim, normalize, or truncate credentials.
func (p SignupPasswordPolicy) Validate(password string) error {
	violations := make([]string, 0)
	length := utf8.RuneCountInString(password)
	if length < p.MinLength {
		violations = append(violations, "min_length")
	}
	if p.MaxLength > 0 && length > p.MaxLength {
		violations = append(violations, "max_length")
	}
	var upper, lower, digit, special bool
	for _, c := range password {
		upper = upper || unicode.IsUpper(c)
		lower = lower || unicode.IsLower(c)
		digit = digit || unicode.IsDigit(c)
		special = special || unicode.IsPunct(c) || unicode.IsSymbol(c)
	}
	for _, rule := range []struct {
		code   string
		failed bool
	}{
		{"require_upper", p.RequireUpper && !upper},
		{"require_lower", p.RequireLower && !lower},
		{"require_digit", p.RequireDigit && !digit},
		{"require_special", p.RequireSpecial && !special},
	} {
		if rule.failed {
			violations = append(violations, rule.code)
		}
	}
	if len(violations) != 0 {
		return &SignupPasswordError{Policy: p, Violations: violations}
	}
	return nil
}

// localPasswordPolicy is also used by Create: composition requirements cannot
// diverge between signup preflight and the final credential write. This path
// currently enforces neither common-substring nor username rules (zero values).
func (s *UserService) localPasswordPolicy() *crypto.PasswordPolicy {
	return &crypto.PasswordPolicy{
		MinLength:      s.config.PasswordMinLength,
		RequireUpper:   s.config.PasswordRequireUpper,
		RequireLower:   s.config.PasswordRequireLower,
		RequireDigit:   s.config.PasswordRequireDigit,
		RequireSpecial: s.config.PasswordRequireSpecial,
	}
}

func (s *UserService) SignupPasswordPolicy() SignupPasswordPolicy {
	p := s.localPasswordPolicy()
	breachCheck := "disabled"
	if s.breachChecker != nil {
		breachCheck = "best_effort"
	}
	return SignupPasswordPolicy{
		Version: 1, LengthUnit: "unicode_code_points",
		// Preserve the old signup binding's eight-code-point floor. Applying
		// the configured minimum in code points also satisfies Create's byte
		// minimum; this strengthens Unicode signup without changing login.
		MinLength: max(8, p.MinLength), MaxLength: p.MaxLength,
		RequireUpper: p.RequireUpper, RequireLower: p.RequireLower,
		RequireDigit: p.RequireDigit, RequireSpecial: p.RequireSpecial,
		BreachCheck: breachCheck,
	}
}

func (s *UserService) ValidateSignupPassword(ctx context.Context, password string) error {
	p := s.SignupPasswordPolicy()
	if err := p.Validate(password); err != nil {
		return err
	}
	// Preserve the existing best-effort HIBP policy, including outage behavior.
	if err := assertPasswordNotBreached(ctx, s.breachChecker, password); err != nil {
		return &SignupPasswordError{Policy: p, Violations: []string{"breached"}}
	}
	return nil
}

// SignupStateError identifies a correctable request-state error, independently
// of provisioning/transport failures. It carries no identity or credential data.
type SignupStateError struct{ Code string }

func (e *SignupStateError) Error() string {
	switch e.Code {
	case "signup_request_unavailable":
		return "signup request not found"
	case "signup_email_unverified":
		return "email not yet verified"
	case "signup_already_completed":
		return "signup already completed"
	case "signup_expired":
		return "signup request has expired"
	case "plan_required":
		return "a subscription plan must be selected to complete signup"
	default:
		return e.Code
	}
}
