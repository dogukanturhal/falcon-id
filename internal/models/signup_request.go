// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"time"

	"github.com/google/uuid"
)

// AccountType enumerates the kinds of accounts a user can sign up for.
type AccountType string

const (
	// AccountTypePersonal is an exported identifier.
	AccountTypePersonal AccountType = "personal"
	// AccountTypeBusiness is an exported identifier.
	AccountTypeBusiness AccountType = "business"
)

// SignupRequest represents a pending self-service signup flow.
// It acts as a short-lived record that captures the user's intent to create an
// account, tracks verification state, and is finalised into a real User and
// (optionally) Tenant once the email has been verified and the password set.
type SignupRequest struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	FirstName   *string   `json:"first_name,omitempty" db:"first_name"`
	LastName    *string   `json:"last_name,omitempty" db:"last_name"`
	AccountType string    `json:"account_type" db:"account_type"` // "personal" or "business"
	CompanyName *string   `json:"company_name,omitempty" db:"company_name"`
	CompanySlug *string   `json:"company_slug,omitempty" db:"company_slug"`
	// Continuation is the validated /oauth/authorize URL the signup started
	// from, kept server-side so verify/complete (possibly on another tab or
	// device) can send the person back into the OIDC flow. Never serialised.
	Continuation      *string    `json:"-" db:"continuation"`
	// CompletionSecretHash is the SHA-256 (hex) of the single-use secret that
	// VerifyEmail hands ONLY to the caller who presented the emailed
	// verification token. CompleteSignup requires it, so knowing a signup id
	// (returned to anyone who starts a signup for an address) is not enough to
	// claim the mailbox's account. Cleared on completion.
	CompletionSecretHash *string `json:"-" db:"completion_secret_hash"`
	// CompletionSecret is the plaintext secret, set in memory by VerifyEmail
	// for the response only. Never persisted, never serialised.
	CompletionSecret string `json:"-" db:"-"`
	VerificationToken string     `json:"-" db:"verification_token"` // Never expose
	// VerificationCodeHash is the hex hash of the current 6-digit email code;
	// nil marks a legacy row still verified by VerificationToken. The expiry
	// and attempt counter belong to that code. Never serialised.
	VerificationCodeHash      *string    `json:"-" db:"verification_code_hash"`
	VerificationCodeExpiresAt *time.Time `json:"-" db:"verification_code_expires_at"`
	VerificationAttempts      int        `json:"-" db:"verification_attempts"`
	// VerificationFailedTotal counts wrong guesses over the row's lifetime
	// (resends do not reset it); see signupCodeRowMaxFailures.
	VerificationFailedTotal int `json:"-" db:"verification_failed_total"`
	Verified          bool       `json:"verified" db:"verified"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty" db:"verified_at"`
	Completed         bool       `json:"completed" db:"completed"`
	CompletedAt       *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	TenantID          *uuid.UUID `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID            *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	IPAddress         *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent         *string    `json:"user_agent,omitempty" db:"user_agent"`
	ExpiresAt         time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// IsExpired reports whether the signup request has passed its expiry deadline.
func (s *SignupRequest) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsComplete reports whether the signup flow has been fully completed (email
// verified and account provisioned).
func (s *SignupRequest) IsComplete() bool {
	return s.Verified && s.Completed
}

// CreateSignupRequestInput is the initial payload submitted by a prospective user.
// For business accounts, company_name is required.
// Note: string (not *string) is used for fields with length constraints because
// go-playground/validator cannot apply max/min to pointer types.
type CreateSignupRequestInput struct {
	// Email is supplied directly for BUSINESS accounts (their own work email).
	// For PERSONAL accounts it is left empty — the server derives it from
	// Username + the configured consumer domain (single source of truth).
	Email string `json:"email" binding:"omitempty,email"`
	// Username is supplied for PERSONAL accounts; the server derives the email
	// as <username>@<ConsumerEmailDomain> and validates the format/availability.
	Username    string `json:"username" binding:"omitempty,max=64"`
	FirstName   string `json:"first_name" binding:"omitempty,max=100"`
	LastName    string `json:"last_name" binding:"omitempty,max=100"`
	AccountType string `json:"account_type" binding:"required,oneof=personal business"`
	// CompanyName was previously required_if=AccountType business. Relaxed
	// to omitempty: the AcmeWeb signup page collects only email+password up
	// front (mirroring Brevo's structure) and defers company name to
	// onboarding wizard step 1. provisionTenant falls back to the display
	// name PlaceholderTenantName ("My Company") when this is empty — that placeholder name is
	// deliberate and fine to reuse across tenants. The SLUG is different:
	// it must be unique per tenant, so provisionTenant does NOT fall back
	// to a fixed literal for it. When no CompanySlug is supplied either
	// (the normal case on this signup page), it generates a fresh,
	// human-presentable word-pair slug such as "amber-harbor" per signup
	// (see randomTenantSlug), with a bounded retry loop on collision. See
	// provisionTenant / candidateTenantSlug in
	// internal/services/signup_service.go.
	CompanyName string `json:"company_name" binding:"omitempty,max=255"`
	// Slug is an OPTIONAL explicit subdomain slug for business accounts,
	// claimed up front at signup instead of deferred to the onboarding
	// wizard's later "choose your subdomain" step (OnboardingSlugService).
	// When present it is validated synchronously — format
	// (models.IsValidSlug), reserved-word blocklist
	// (models.IsReservedSlug), and live uniqueness against
	// tenant-management (SignupService.slugChecker) — and, on success,
	// becomes the signup request's CompanySlug, taking priority over the
	// CompanyName-derived slug the comment above describes. Left empty,
	// behavior is UNCHANGED from before this field existed: provisionTenant
	// mints a fresh word-pair candidate such as "amber-harbor" (or
	// "<company-name-slug>-<hex4>" once a base slug has collided once)
	// with no synchronous availability check. binding:"omitempty"
	// only — format/reserved/availability are all checked in
	// SignupService.InitiateSignup so a rejection can return a specific,
	// slug-tenant-enumeration-safe reason (see models.ReservedTenantSlugs).
	Slug string `json:"slug" binding:"omitempty,max=100"`

	// Continuation is OPTIONAL: the relative /oauth/authorize URL of the
	// OIDC request that sent the person to sign up. It is validated
	// server-side (exact path, active client, registered redirect_uri) and
	// returned as CompleteSignup's redirect_url so the flow resumes after
	// verification, even when the verification link opens in another
	// browser or device. Anything that fails validation is rejected, never
	// silently dropped.
	Continuation string `json:"continuation" binding:"omitempty,max=4096"`
}

// VerifySignupEmailInput carries the one-time token sent to the user's email address.
//
// New flow: Code (6 digits; spaces and dashes tolerated) plus SignupID or Email
// (the code is never looked up on its own). Legacy flow: Token only, accepted
// for rows created before the code rollout.
type VerifySignupEmailInput struct {
	SignupID string `json:"signup_id" binding:"omitempty,max=64"`
	Email    string `json:"email" binding:"omitempty,max=320"`
	Code     string `json:"code" binding:"omitempty,max=32"`
	Token    string `json:"token" binding:"omitempty,max=256"`
}

// CompleteSignupInput finalises account creation after email verification.
//
// Password is REQUIRED (reverted 2026-09-13, t-<pwfix> — was made optional
// 2026-05-22 / ENT-4 Phase 1 on the theory that an empty password would
// produce a legitimate social-auth-only account, matching the Microsoft
// Entra MSA pattern). That theory does not match this codebase: this
// endpoint (POST /api/v1/auth/signup/complete, SignupService.CompleteSignup)
// is the sole completion path for the self-service email/password signup
// flow and carries no federation/provider signal at all — SignupRequest has
// no such field, and social/federated accounts are provisioned entirely
// separately by SocialAuthService.resolveUserForFederation (OAuth/OIDC
// callback), which never touches CompleteSignupInput. So in practice every
// account completed through this endpoint IS meant to have a local
// password, and an empty one silently stranded the user with
// password_hash = NULL — indistinguishable at login from a typo (see
// authenticateLocal in auth_credentials_service.go). Genuinely passwordless
// accounts (federated, FederationType set) are created by the other path
// and never reach this validation.
type CompleteSignupInput struct {
	SignupRequestID uuid.UUID `json:"signup_request_id" binding:"required"`
	// CompletionSecret is the one-time secret returned by the verify-email
	// call. A missing or wrong value is answered exactly like an unknown
	// signup_request_id.
	CompletionSecret string `json:"completion_secret"`
	// Policy validation belongs to the service, including missing passwords.
	// No independent binding minimum that can drift from the public contract.
	Password string `json:"password"`
	// PlanCode is the subscription_packages.code the user picked, IF the
	// client collected one — the signup wizard no longer has a
	// plan-selection step (removed 2026-09-18, t-signup-no-plan-step): every
	// self-serve signup starts on the reverse trial and plan choice is
	// surfaced later, at the upgrade/limit-hit moment. Deliberately carried
	// on THIS request rather than persisted on SignupRequest at
	// InitiateSignup time, same as Password. OPTIONAL — briefly REQUIRED
	// 2026-09-17..2026-09-18 (e75eeb7, reverted here) when
	// SignupService.CompleteSignup rejected an empty PlanCode with
	// SignupStateError{Code: "plan_required"}. That was fixing a real gap
	// (empty plan meant no trial subscription row at all — nothing to
	// expire, convert, or dun), but the gap is now closed a layer down
	// instead: subscription-management's TrialService.StartTrial always
	// grants the reverse trial on the operator-configured top self-serve
	// tier (subscription_packages.is_default=true, resolved via
	// packageRepo.FindDefault) regardless of whether PackageCode is empty —
	// see that function's 2026-09-18 reverse-trial-redesign doc comment.
	// PlanCode, when present, only picks the DESTINATION package the trial
	// converts to at day 14; it was never what gated whether a trial
	// started. binding stays "omitempty" (validated in code, not via gin,
	// mirroring Password). Still never independently trusted for billing:
	// subscription-management resolves and validates the actual package
	// server-side — this is a selection hint, not billing state.
	PlanCode string `json:"plan_code" binding:"omitempty,max=64"`
	// CompanyName, Slug and MarketingConsent are collected on the company
	// step, after email verification. They are applied only while the
	// request has not yet provisioned a tenant: on a resumed completion the
	// slug already registered wins and these are ignored. Slug is an
	// optional explicit subdomain; without it one is derived from
	// CompanyName.
	CompanyName      string `json:"company_name" binding:"omitempty,max=255"`
	Slug             string `json:"slug" binding:"omitempty,max=100"`
	MarketingConsent *bool  `json:"marketing_consent"`
}
