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
	ID                uuid.UUID  `json:"id" db:"id"`
	Email             string     `json:"email" db:"email"`
	FirstName         *string    `json:"first_name,omitempty" db:"first_name"`
	LastName          *string    `json:"last_name,omitempty" db:"last_name"`
	AccountType       string     `json:"account_type" db:"account_type"` // "personal" or "business"
	CompanyName       *string    `json:"company_name,omitempty" db:"company_name"`
	CompanySlug       *string    `json:"company_slug,omitempty" db:"company_slug"`
	VerificationToken string     `json:"-" db:"verification_token"` // Never expose
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
	// to omitempty: the Mearax signup page collects only email+password up
	// front (mirroring Brevo's structure) and defers company name to
	// onboarding wizard step 1. provisionTenant falls back to the display
	// name "My Company" when this is empty — that placeholder name is
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
}

// VerifySignupEmailInput carries the one-time token sent to the user's email address.
type VerifySignupEmailInput struct {
	Token string `json:"token" binding:"required"`
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
	// Policy validation belongs to the service, including missing passwords.
	// No independent binding minimum that can drift from the public contract.
	Password string `json:"password"`
	// PlanCode is the subscription_packages.code the user picked during
	// the signup wizard's plan-selection step (e.g. "starter"/
	// "professional"/"scale"). Deliberately carried on THIS request, not
	// persisted on SignupRequest at InitiateSignup time: the plan choice
	// is UI-only state the client already holds across the wizard's
	// steps (same as Password, which is likewise never captured at
	// Initiate), so completing the flow needs no new signup_requests
	// column / Keystone migration. REQUIRED as of 2026-09-17 (t-<planreq>):
	// SignupService.CompleteSignup rejects an empty PlanCode with
	// SignupStateError{Code: "plan_required"} before doing any
	// provisioning work. Previously optional/empty meant the user could
	// skip plan choice entirely — but that left no trial subscription
	// row for the tenant at all, so nothing could expire, convert, or be
	// dunned; closing that commercial gap is the entire point of this
	// field being mandatory now. binding stays "omitempty" (validated in
	// code, not via gin, mirroring how Password has no binding tag
	// either) — see the plan_required check in CompleteSignup. Still
	// never independently trusted for billing: subscription-management
	// resolves and validates the actual package server-side (see
	// TrialService.StartTrial's PackageCode handling in
	// platform-commerce) — this is a selection hint, not billing state.
	PlanCode string `json:"plan_code" binding:"omitempty,max=64"`
}
