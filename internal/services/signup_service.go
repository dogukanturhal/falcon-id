// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// usernameRE constrains the local-part of a personal-account email: lowercase
// letters/digits plus . _ - , never at the ends. Kept in sync with the signup
// wizard's client-side hint (the server is authoritative).
var usernameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

func normalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func validateUsername(u string) error {
	if u == "" {
		return fmt.Errorf("username is required")
	}
	if len(u) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}
	if len(u) > 64 {
		return fmt.Errorf("username must be at most 64 characters")
	}
	if !usernameRE.MatchString(u) {
		return fmt.Errorf("username may use lowercase letters, numbers, and . _ - (not at the start or end)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Interface contracts consumed by SignupService
// ---------------------------------------------------------------------------

// SignupRequestRepo persists and retrieves self-service signup requests.
type SignupRequestRepo interface {
	Create(ctx context.Context, req *models.SignupRequest) error
	GetByToken(ctx context.Context, token string) (*models.SignupRequest, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.SignupRequest, error)
	GetPendingByEmail(ctx context.Context, email string) (*models.SignupRequest, error)
	MarkVerified(ctx context.Context, id uuid.UUID) error
	MarkCompleted(ctx context.Context, id uuid.UUID, tenantID, userID uuid.UUID) error
}

// SignupEmailSender sends transactional email during the signup flow.
type SignupEmailSender interface {
	SendSignupVerificationEmail(ctx context.Context, email, token, name string) error
}

// SignupTenantCreator provisions a new tenant during account completion
// (used for `account_type=business` signups) AND looks up the shared
// consumer tenant (used for `account_type=personal` signups, since
// 2026-05-22 — see provisionTenant for the industry-standard B2C
// rationale).
type SignupTenantCreator interface {
	CreateTenant(ctx context.Context, req *models.CreateTenantRequest) (*models.Tenant, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
}

// SignupUserCreator provisions a new user account during account completion.
type SignupUserCreator interface {
	CreateForSignup(ctx context.Context, req *models.CreateUserRequest, credential *PreparedSignupCredential) (*models.User, error)
	SignupPasswordPolicy() SignupPasswordPolicy
	PrepareSignupCredential(ctx context.Context, password string) (*PreparedSignupCredential, error)
}

// SignupUserLookup checks whether an email address already has an account.
type SignupUserLookup interface {
	GetByEmail(ctx context.Context, email string) (*models.User, error)
}

// TenantSlugAvailabilityChecker reports whether a candidate subdomain slug
// is free, via tenant-management's S2S GET
// /api/v1/internal/tenants/slug-available/:slug (platform:tenants:read).
// Optional dependency: when nil (outbound S2S creds/URL missing — see
// cmd/services.go's buildTenantManagementSlugCheckerHTTPClient), an
// explicitly-supplied CreateSignupRequestInput.Slug is refused rather than
// silently accepted unchecked — see InitiateSignup's slug-claim block for
// why "cannot verify" must never be treated as "available".
type TenantSlugAvailabilityChecker interface {
	IsSlugAvailable(ctx context.Context, slug string) (bool, error)
}

// TenantManagementRegisterRequest carries the fields tenant-management's
// public POST /api/v1/tenants/register endpoint requires.
//
// Email/FirstName/LastName/Password are validated by that endpoint's
// binding tags but then DISCARDED — RegisterTenantRequest's fields never
// reach a user-creation call in tenant-management's handler (verified by
// reading services/tenant-management/internal/handlers/tenant_handler.go
// and models/tenant.go: no code path after ShouldBindJSON references them
// again). Password is therefore a locally-generated, never-reused,
// never-logged, never-persisted-as-a-real-credential throwaway value that
// exists solely to satisfy that endpoint's `required,min=8` validator —
// it is NOT the user's actual falcon-id password, which is set separately
// by provisionUser via s.userCreator.CreateForSignup.
type TenantManagementRegisterRequest struct {
	TenantName string
	TenantSlug string
	Email      string
	FirstName  string
	LastName   string
}

// TenantManagementRegisterResult is the subset of tenant-management's
// tenant response the signup flow needs.
type TenantManagementRegisterResult struct {
	// ID is the tenant-management-minted tenant ID. Threaded into the
	// local iam_tenants row (via CreateTenantRequest.ID) so both systems
	// agree on one tenant identity — see that field's doc comment.
	ID uuid.UUID
}

// TenantManagementRegistrar registers a new business tenant with
// tenant-management — the sole system-of-record for subscription
// plan/quota since ADR-0029 Phase 3 dropped iam_tenants.plan/type — via
// its public, unauthenticated /api/v1/tenants/register endpoint.
//
// Why call this at all, and why make its failure fatal to signup: a
// tenant created ONLY in falcon-id's local iam_tenants (the pre-existing
// behavior) never gets a subscription_plan_id anywhere, because that
// column no longer exists on this side. quota-service only grants quota
// from tenant-management's example.tenant.created event, so such a tenant
// gets ZERO quota — every email/API call rejected with "quota exceeded
// (current: 0, limit: 0)" (t-597). Letting CompleteSignup succeed anyway
// would silently hand every new business signup a broken account.
type TenantManagementRegistrar interface {
	Register(ctx context.Context, req *TenantManagementRegisterRequest) (*TenantManagementRegisterResult, error)
}

// ---------------------------------------------------------------------------
// SignupService
// ---------------------------------------------------------------------------

// PostSignupHook is called after a successful signup to provision default
// resources (app access, subdomain, etc.). Errors from the hook are non-fatal
// and must not prevent signup completion.
type PostSignupHook interface {
	OnSignupComplete(ctx context.Context, tenantID, userID uuid.UUID, accountType string) error
}

// PostSignupSessionIssuer mints a real session for a just-provisioned
// signup user, through the SAME code path as a normal password login
// (see AuthService.IssueSessionForNewUser's doc comment). Like
// PostSignupHook, it is best-effort from CompleteSignup's point of view:
// by the time it's called, provisionTenant/provisionUser have already
// succeeded and the signup request has already been marked completed, so
// a mint failure here is logged and swallowed rather than surfaced as an
// error — surfacing it would turn an already-successful signup into an
// error response the client can't retry (CompleteSignup rejects a
// re-post against a request that's already Completed). A nil
// CompleteSignupResult.Session tells the caller to fall back to the
// pre-existing hosted-login redirect.
type PostSignupSessionIssuer interface {
	IssueSessionForNewUser(ctx context.Context, tenantID uuid.UUID, user *models.User, ipAddress, userAgent string) (*models.LoginResponse, error)
}

// SignupService orchestrates the three-step self-service signup flow:
//  1. InitiateSignup  – create a pending request and send a verification email.
//  2. VerifyEmail     – validate the token and stamp the request as verified.
//  3. CompleteSignup  – provision the tenant and user, then close the request.
type SignupService struct {
	repo            SignupRequestRepo
	emailSender     SignupEmailSender
	tenantCreator   SignupTenantCreator
	tenantRegistrar TenantManagementRegistrar
	userCreator     SignupUserCreator
	userLookup      SignupUserLookup
	postSignupHook  PostSignupHook
	sessionIssuer   PostSignupSessionIssuer
	slugChecker     TenantSlugAvailabilityChecker
	consumerDomain  string
	defaultPlanCode string
}

// consumerEmailDomain returns the configured personal-account email domain,
// falling back to downstream.com if unset.
func (s *SignupService) consumerEmailDomain() string {
	if s.consumerDomain != "" {
		return s.consumerDomain
	}
	return "downstream.com"
}

// defaultPlan returns the subscription plan assigned to tenants provisioned
// through self-service signup, falling back to "starter" if unset. Config is
// the single source of truth (SIGNUP_DEFAULT_PLAN_CODE, see pkg/config) — this
// fallback only guards direct construction (e.g. tests) that skip it.
func (s *SignupService) defaultPlan() string {
	if s.defaultPlanCode != "" {
		return s.defaultPlanCode
	}
	return "starter"
}

// deriveConsumerEmail builds a personal account's email from its username.
func (s *SignupService) deriveConsumerEmail(username string) string {
	return username + "@" + s.consumerEmailDomain()
}

// SetPostSignupHook wires an optional post-signup hook that runs after
// successful user creation. Errors from the hook are logged but non-fatal.
func (s *SignupService) SetPostSignupHook(hook PostSignupHook) {
	s.postSignupHook = hook
}

// SetSlugChecker wires the optional tenant-management slug-availability
// S2S client used by InitiateSignup's up-front slug claim (business
// accounts only) and CheckSlugAvailable. Left unset in tests/partial
// deployments that don't need it — see IsSlugAvailable's nil-checker
// fallback below.
func (s *SignupService) SetSlugChecker(checker TenantSlugAvailabilityChecker) {
	s.slugChecker = checker
}

// SetSessionIssuer wires the session-minting dependency used by
// CompleteSignup. Left unset in tests/partial deployments that don't need
// it — CompleteSignup falls back to returning no session, matching the
// prior behaviour exactly.
func (s *SignupService) SetSessionIssuer(issuer PostSignupSessionIssuer) {
	s.sessionIssuer = issuer
}

// NewSignupService wires together all dependencies for the signup flow.
func NewSignupService(
	repo SignupRequestRepo,
	emailSender SignupEmailSender,
	tenantCreator SignupTenantCreator,
	tenantRegistrar TenantManagementRegistrar,
	userCreator SignupUserCreator,
	userLookup SignupUserLookup,
	consumerDomain string,
	defaultPlanCode string,
) *SignupService {
	return &SignupService{
		repo:            repo,
		emailSender:     emailSender,
		tenantCreator:   tenantCreator,
		tenantRegistrar: tenantRegistrar,
		userCreator:     userCreator,
		userLookup:      userLookup,
		consumerDomain:  consumerDomain,
		defaultPlanCode: defaultPlanCode,
	}
}

// CheckUsernameAvailable validates a personal-account username and reports
// whether the derived email is free. Returns the derived email so the client
// can show exactly what the account will be (server is authoritative for the
// domain). A format error is returned as err so the caller can surface it.
func (s *SignupService) CheckUsernameAvailable(ctx context.Context, username string) (bool, string, error) {
	username = normalizeUsername(username)
	if err := validateUsername(username); err != nil {
		return false, "", err
	}
	email := s.deriveConsumerEmail(username)
	if existing, _ := s.userLookup.GetByEmail(ctx, email); existing != nil {
		return false, email, nil
	}
	if pending, _ := s.repo.GetPendingByEmail(ctx, email); pending != nil && !pending.Verified {
		return false, email, nil
	}
	return true, email, nil
}

// CheckSlugAvailable validates a candidate subdomain slug's format, checks
// it against the reserved-word blocklist, and — when a slugChecker is
// wired — reports live availability against tenant-management. Mirrors
// CheckUsernameAvailable's contract: a format/reserved rejection and a
// "taken" result are BOTH reported as available=false with the same
// generic reason, never distinguished in the response (slug-tenant-
// enumeration mitigation — see models.ReservedTenantSlugs's doc comment).
// When no slugChecker is wired, availability is reported false with an
// explicit "cannot verify" reason rather than silently answering true for
// an unverifiable claim — this method must never assert a slug is free
// when it does not actually know that.
func (s *SignupService) CheckSlugAvailable(ctx context.Context, rawSlug string) (bool, error) {
	slug := normalizeUsername(rawSlug) // same lowercase/trim normalization
	if !models.IsValidSlug(slug) || models.IsReservedSlug(slug) {
		return false, fmt.Errorf("slug unavailable")
	}
	if s.slugChecker == nil {
		return false, fmt.Errorf("slug availability cannot be verified right now")
	}
	available, err := s.slugChecker.IsSlugAvailable(ctx, slug)
	if err != nil {
		return false, fmt.Errorf("slug availability cannot be verified right now")
	}
	if !available {
		return false, fmt.Errorf("slug unavailable")
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// InitiateSignup
// ---------------------------------------------------------------------------

// InitiateSignup creates a pending signup request and dispatches a verification
// email.  If a live (unexpired, uncompleted) request already exists for the
// address and has not yet been verified, the verification email is re-sent and
// the existing record is returned so the caller can surface the same signup_id.
func (s *SignupService) InitiateSignup(
	ctx context.Context,
	input *models.CreateSignupRequestInput,
	ipAddress, userAgent string,
) (*models.SignupRequest, error) {
	// Resolve the email. Personal accounts choose a username and the server
	// derives <username>@<consumerDomain> (authoritative — the client never
	// invents the address); business accounts bring their own work email.
	var email string
	if input.AccountType == string(models.AccountTypePersonal) {
		username := normalizeUsername(input.Username)
		if err := validateUsername(username); err != nil {
			return nil, err
		}
		email = s.deriveConsumerEmail(username)
	} else {
		email = strings.ToLower(strings.TrimSpace(input.Email))
		if email == "" {
			return nil, fmt.Errorf("a work email is required for business accounts")
		}
	}

	// Fail fast: email already registered.
	existing, _ := s.userLookup.GetByEmail(ctx, email)
	if existing != nil {
		return nil, fmt.Errorf("an account with this email already exists")
	}

	// Re-use an existing pending request if we have one.
	pending, _ := s.repo.GetPendingByEmail(ctx, email)
	if pending != nil && !pending.Verified {
		// Best-effort re-send: a delivery failure must not fail the request,
		// but it must not be silent either (2026-08-02 — a six-minute
		// greylist stall on this path went unnoticed for two days).
		if err := s.emailSender.SendSignupVerificationEmail(ctx, email, pending.VerificationToken, input.FirstName); err != nil {
			logger.Error("signup verification re-send failed", zap.String("email", email), zap.Error(err))
		}
		return pending, nil
	}

	// Generate a cryptographically random 64-character hex token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate verification token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Resolve company slug for business accounts. An explicit input.Slug
	// (the up-front "claim your subdomain" signup step) takes priority
	// over the CompanyName-derived fallback and, unlike that fallback, is
	// synchronously validated here — format, reserved-word blocklist, and
	// live tenant-management uniqueness (CheckSlugAvailable) — so the
	// signup fails fast with a specific reason rather than silently
	// minting an unrelated random slug later in provisionTenant.
	var companySlug *string
	if input.AccountType == discoverAccountTypeBusiness {
		if strings.TrimSpace(input.Slug) != "" {
			normalized := normalizeUsername(input.Slug)
			if _, err := s.CheckSlugAvailable(ctx, normalized); err != nil {
				return nil, err
			}
			companySlug = &normalized
		} else if input.CompanyName != "" {
			slug := generateSlug(input.CompanyName)
			companySlug = &slug
		}
	}

	// Convert non-empty string fields to pointers for the DB model.
	var firstName, lastName, companyName *string
	if input.FirstName != "" {
		firstName = &input.FirstName
	}
	if input.LastName != "" {
		lastName = &input.LastName
	}
	if input.CompanyName != "" {
		companyName = &input.CompanyName
	}

	req := &models.SignupRequest{
		ID:                uuid.New(),
		Email:             email,
		FirstName:         firstName,
		LastName:          lastName,
		AccountType:       input.AccountType,
		CompanyName:       companyName,
		CompanySlug:       companySlug,
		VerificationToken: token,
		IPAddress:         &ipAddress,
		UserAgent:         &userAgent,
		ExpiresAt:         time.Now().Add(24 * time.Hour),
	}

	if err := s.repo.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create signup request: %w", err)
	}

	// Email delivery is best-effort: a failure here must not roll back the
	// signup request so the user can request a re-send later. It is logged
	// rather than discarded — see iam_email_send_failures_total for the
	// corresponding metric.
	if err := s.emailSender.SendSignupVerificationEmail(ctx, email, token, input.FirstName); err != nil {
		logger.Error("signup verification send failed", zap.String("email", email), zap.Error(err))
	}

	return req, nil
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

// VerifyEmail validates the one-time token supplied by the user.  The
// operation is idempotent: calling it again on an already-verified request
// simply returns the request without error.
func (s *SignupService) VerifyEmail(ctx context.Context, token string) (*models.SignupRequest, error) {
	req, err := s.repo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired verification token")
	}

	if req.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Idempotent: already verified is not an error.
	if req.Verified {
		return req, nil
	}

	if err := s.repo.MarkVerified(ctx, req.ID); err != nil {
		return nil, fmt.Errorf("mark verified: %w", err)
	}

	req.Verified = true
	now := time.Now()
	req.VerifiedAt = &now
	return req, nil
}

// ---------------------------------------------------------------------------
// CompleteSignup
// ---------------------------------------------------------------------------

// CompleteSignup provisions the tenant (and, for personal accounts, a personal
// tenant) and the user record once the email has been verified.
// CompleteSignupResult carries the provisioned user and, when a session
// issuer is wired, the freshly-minted session for that user. Session is
// nil when no issuer is configured — callers must handle that case (it
// mirrors the pre-existing "no session" behaviour, it is not an error).
type CompleteSignupResult struct {
	User    *models.User
	Session *models.LoginResponse
	// TenantSlug is the slug provisionTenant landed on (company-derived,
	// or the word-pair fallback such as "amber-harbor" — see
	// candidateTenantSlug/randomTenantSlug). Personal
	// signups share the well-known consumer tenant and have no
	// self-service slug, so this is "" for account_type=personal.
	TenantSlug string
}

func (s *SignupService) CompleteSignup(ctx context.Context, input *models.CompleteSignupInput, ipAddress, userAgent string) (*CompleteSignupResult, error) {
	// SECURITY: defense-in-depth, independent of the `binding:"required"`
	// tag on models.CompleteSignupInput.Password — that tag only fires for
	// callers that go through gin's ShouldBindJSON (the HTTP handler).
	// This is the one and only completion path for the self-service
	// email/password signup flow (see the doc comment on
	// CompleteSignupInput for why an empty password here is never a
	// legitimate passwordless/federated account), so refuse loudly here
	// too rather than silently provisioning a user nobody can ever log
	// into. Never log the password value itself — only the condition.
	if input.Password == "" {
		return nil, &SignupPasswordError{Policy: s.SignupPasswordPolicy(), Violations: []string{"required"}}
	}

	req, err := s.repo.GetByID(ctx, input.SignupRequestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &SignupStateError{Code: "signup_request_unavailable"}
		}
		return nil, fmt.Errorf("read signup request: %w", err)
	}
	if req == nil {
		return nil, &SignupStateError{Code: "signup_request_unavailable"}
	}

	if !req.Verified {
		return nil, &SignupStateError{Code: "signup_email_unverified"}
	}

	if req.Completed {
		return nil, &SignupStateError{Code: "signup_already_completed"}
	}

	if req.ExpiresAt.Before(time.Now()) {
		return nil, &SignupStateError{Code: "signup_expired"}
	}

	// Make the single authoritative password decision before tenant work. The
	// prepared credential also prevents a second breach lookup after provision.
	// Deliberately ordered BEFORE the plan-required check below: a caller
	// sending both a weak password and no plan should see the password
	// violation (422, with actionable per-rule feedback), matching the
	// pre-existing precedent that password policy is the first
	// correctable-input error surfaced.
	credential, err := s.userCreator.PrepareSignupCredential(ctx, input.Password)
	if err != nil {
		return nil, err
	}

	// SECURITY/COMMERCIAL: a plan selection is now mandatory to complete
	// signup. Skipping plan choice used to mean no trial subscription row
	// was ever created for the tenant — nothing to expire, convert, or
	// dun — the exact commercial gap this check closes. Checked here
	// (service layer) rather than via a gin `binding:"required"` tag on
	// models.CompleteSignupInput.PlanCode, mirroring how the password
	// check above is validated in code, not by a binding tag.
	if strings.TrimSpace(input.PlanCode) == "" {
		return nil, &SignupStateError{Code: "plan_required"}
	}

	tenantID, tenantSlug, err := s.provisionTenant(ctx, req)
	if err != nil {
		return nil, err
	}

	user, err := s.provisionUser(ctx, req, tenantID, input.Password, credential)
	if err != nil {
		return nil, err
	}

	// Non-fatal: tenant and user already exist, so the failure here would
	// only leave the record in a non-completed state.
	_ = s.repo.MarkCompleted(ctx, req.ID, tenantID, user.ID)

	// Best-effort: run post-signup hook for default app access, subdomain,
	// cardless trial start, etc. When the wired hook also implements
	// PlanAwarePostSignupHook (PostSignupProvisioner in production —
	// see that type's doc comment), prefer OnSignupCompleteWithPlan so
	// step 7 (trial start) uses the plan the user picked at signup
	// instead of always falling back to subscription-management's
	// operator-configured default. Same optional-capability idiom as
	// SyncProductEntitlementProvisioner (falcon-id!360) — additive, not
	// a breaking change to the base PostSignupHook interface.
	if s.postSignupHook != nil {
		if planAware, ok := s.postSignupHook.(PlanAwarePostSignupHook); ok {
			_ = planAware.OnSignupCompleteWithPlan(ctx, tenantID, user.ID, req.AccountType, input.PlanCode)
		} else {
			_ = s.postSignupHook.OnSignupComplete(ctx, tenantID, user.ID, req.AccountType)
		}
	}

	result := &CompleteSignupResult{User: user, TenantSlug: tenantSlug}

	// Session minting is deliberately best-effort, same as the hook above:
	// the account and tenant already exist and MarkCompleted has already
	// run, so a session-issuance failure must not turn a successful
	// signup into an error response the client would retry against an
	// "already completed" request. A nil Session tells the caller (the
	// HTTP handler, then the frontend) to fall back to the pre-existing
	// OIDC hosted-login redirect — exactly the behaviour before this
	// dependency existed — rather than leaving the user stuck.
	if s.sessionIssuer != nil {
		session, sessErr := s.sessionIssuer.IssueSessionForNewUser(ctx, tenantID, user, ipAddress, userAgent)
		if sessErr != nil {
			logger.Error("signup: post-signup session issuance failed; client falls back to hosted login",
				zap.String("signup_request_id", req.ID.String()),
				zap.String("user_id", user.ID.String()),
				zap.Error(sessErr),
			)
		} else {
			result.Session = session
		}
	}

	return result, nil
}

func (s *SignupService) SignupPasswordPolicy() SignupPasswordPolicy {
	return s.userCreator.SignupPasswordPolicy()
}

// provisionTenant creates either a business or personal tenant and returns its ID.
func (s *SignupService) provisionTenant(ctx context.Context, req *models.SignupRequest) (uuid.UUID, string, error) {
	var tenantReq *models.CreateTenantRequest

	if req.AccountType == discoverAccountTypeBusiness {
		tenantName := "My Company"
		if req.CompanyName != nil {
			tenantName = *req.CompanyName
		}

		// Base slug candidate. The Brevo-style signup page collects only
		// email + password, so req.CompanySlug is nil for essentially every
		// self-service signup today — base stays "" and every attempt below
		// mints a fresh word-pair slug such as "amber-harbor". A caller that DOES
		// supply CompanySlug (a future onboarding step, or a non-UI caller)
		// gets that exact slug tried first, with random suffixes appended
		// only if it turns out to collide.
		//
		// IMPORTANT: this must never default to a fixed literal like
		// "company" — that was the bug: every company-less signup minted
		// the SAME slug, so only the first one could ever complete
		// (production incident: the first real self-service signup
		// created iam_tenants/tenants row slug="company", and every
		// subsequent one collided on it).
		baseSlug := ""
		if req.CompanySlug != nil {
			baseSlug = *req.CompanySlug
		}

		firstName := ""
		if req.FirstName != nil {
			firstName = *req.FirstName
		}
		lastName := ""
		if req.LastName != nil {
			lastName = *req.LastName
		}

		// Register with tenant-management FIRST — it is the sole
		// system-of-record for subscription plan/quota (ADR-0029 Phase 3).
		// A hard failure here aborts CompleteSignup entirely: see
		// TenantManagementRegistrar's doc comment for why a signup that
		// only creates the local iam_tenants row must not be allowed to
		// "succeed" into a zero-quota account (t-597).
		//
		// Slug collisions are handled here, not by picking "a good enough"
		// slug once: tenant-management enforces slug uniqueness only at
		// the application level (check-then-insert against tenants.slug
		// via GetBySlug, no DB UNIQUE constraint on that column — verified
		// against the live schema) and its public
		// /tenants/register endpoint collapses every Create() failure —
		// including "slug already exists" — into a generic 500 (see
		// TenantHandler.Register in platform-core). There is no wire
		// signal here to distinguish a collision from a genuine outage,
		// so on ANY failure we mint a brand-new random candidate and
		// retry: harmless when tenant-management is actually down (every
		// attempt fails the same way and the loop gives up below), and
		// self-healing on the one case that matters — a slug already
		// taken. Never reuses or silently overwrites another tenant's
		// slug; a fresh random suffix is generated for every retry.
		const maxTenantSlugAttempts = 5
		var (
			registered *TenantManagementRegisterResult
			tenantSlug string
			regErr     error
		)
		for attempt := 0; attempt < maxTenantSlugAttempts; attempt++ {
			candidate, genErr := candidateTenantSlug(baseSlug, attempt)
			if genErr != nil {
				return uuid.Nil, "", fmt.Errorf("generate tenant slug: %w", genErr)
			}

			registered, regErr = s.tenantRegistrar.Register(ctx, &TenantManagementRegisterRequest{
				TenantName: tenantName,
				TenantSlug: candidate,
				Email:      req.Email,
				FirstName:  firstName,
				LastName:   lastName,
			})
			if regErr == nil {
				tenantSlug = candidate
				break
			}

			logger.Warn("tenant-management registration attempt failed, retrying with a new tenant slug",
				zap.Int("attempt", attempt+1),
				zap.Int("max_attempts", maxTenantSlugAttempts),
				zap.Error(regErr),
			)
		}
		if regErr != nil {
			return uuid.Nil, "", fmt.Errorf("register tenant with tenant-management after %d attempts: %w", maxTenantSlugAttempts, regErr)
		}

		tenantReq = &models.CreateTenantRequest{
			ID:          &registered.ID,
			Name:        tenantName,
			Slug:        tenantSlug,
			DisplayName: tenantName,
			Type:        "customer",
			Plan:        s.defaultPlan(),
		}
	} else {
		// Personal / consumer signup: enroll the user as a MEMBER of the
		// shared `hexxlock-consumer` tenant (models.WellKnownTenantConsumer,
		// bootstrapped by cmd/consumer_tenant_bootstrap.go) instead of
		// minting a fresh per-user "personal-<rand>" tenant.
		//
		// Why shared (industry-standard B2C pattern):
		//   - Microsoft Entra ID holds every personal Microsoft account
		//     in ONE tenant (9188040d-6c67-4c5b-b112-36a304b66dad).
		//     Auth0, Okta CIC, Keycloak, ForgeRock — all use a single
		//     "consumer" realm for self-signups + per-org realms for B2B.
		//   - O(1) iam_tenants rows instead of O(N) tenant explosion
		//     (100K signups → 1 tenant row, not 100K). Same applies to
		//     realm_tenants + keystone schema-bundle application cost.
		//   - Logical isolation (tenant_id + user_id ACL) instead of
		//     physical tenant-per-user — matches the OWASP Multi-Tenant
		//     Cheat Sheet + NIST SP 800-207 (Zero Trust) guidance.
		//
		// The consumer tenant is bootstrapped in
		// main.go::bootstrapConsumerTenant. If the row is missing here
		// (bootstrap failed + nobody noticed), return a distinct error
		// so the operator can pivot fast — NOT a silent fallback to the
		// legacy per-user-tenant provisioning path.
		consumerTenant, err := s.tenantCreator.GetByID(ctx, models.WellKnownTenantConsumer)
		if err != nil {
			return uuid.Nil, "", fmt.Errorf("look up consumer tenant: %w", err)
		}
		if consumerTenant == nil {
			return uuid.Nil, "", fmt.Errorf("consumer tenant %s missing — bootstrap did not run; check pod logs for bootstrapConsumerTenant errors", models.WellKnownTenantConsumer)
		}
		// Shared consumer tenant has no self-service slug of its own.
		return consumerTenant.ID, "", nil
	}

	// KNOWN LIMITATION (disclosed, not solved here): for the business path,
	// tenant-management's row now already exists (registered above). If
	// this local create fails, that row is orphaned — no distributed saga/
	// rollback is implemented to delete it. Accepted trade-off: the
	// alternative (create locally first, then register) reopens the
	// zero-quota window this change exists to close, which is strictly
	// worse. An orphaned tenant-management row is inert (no local user can
	// reach it) and cheap to clean up manually; a zero-quota tenant is a
	// silent production incident.
	tenant, err := s.tenantCreator.CreateTenant(ctx, tenantReq)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("create %s tenant: %w", req.AccountType, err)
	}
	return tenant.ID, tenant.Slug, nil
}

// provisionUser creates the user record for the given tenant.
func (s *SignupService) provisionUser(
	ctx context.Context,
	req *models.SignupRequest,
	tenantID uuid.UUID,
	password string,
	credential *PreparedSignupCredential,
) (*models.User, error) {
	firstName := ""
	if req.FirstName != nil {
		firstName = *req.FirstName
	}
	lastName := ""
	if req.LastName != nil {
		lastName = *req.LastName
	}

	// Derive a username from the email local-part (before the @).
	username := req.Email
	if at := strings.IndexByte(req.Email, '@'); at > 0 {
		username = req.Email[:at]
	}

	userReq := &models.CreateUserRequest{
		TenantID:  tenantID,
		Username:  username,
		Email:     req.Email,
		FirstName: ptr(firstName),
		LastName:  ptr(lastName),
		Password:  password,
	}

	user, err := s.userCreator.CreateForSignup(ctx, userReq, credential)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// generateSlug converts a human-readable name into a URL-safe slug.
// "Acme Corp!" → "acme-corp"
func generateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		case r == ' ':
			return '-'
		default:
			return -1 // drop
		}
	}, slug)

	// Collapse consecutive dashes.
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "company"
	}
	return slug
}

// slugAdjectives and slugNouns generate a memorable, human-presentable
// fallback tenant slug ("amber-harbor" style) in place of the earlier
// opaque hex suffix ("tenant-560282a0e97f") that shipped to production
// (tenant-560282a0e97f, tenant-4dfe2a7399ba, tenant-6878a101c4ba among
// them) — no human would recognize that as "their" address. Word-pair
// naming follows the same well-worn pattern as Docker container names,
// Heroku app names, and Kubernetes generateName suffixes: short, common,
// lowercase-ASCII-only words that read as a real (if disposable)
// identifier rather than noise. Every entry here is verified, in
// signup_service_test.go, to be absent from models.ReservedTenantSlugs
// and to individually satisfy models.IsValidSlug, so a generated pair can
// never collide with the reserved-word check by construction.
var slugAdjectives = []string{
	"amber", "azure", "bold", "brave", "bright", "calm", "clear", "cobalt",
	"coral", "crisp", "cyan", "dawn", "deep", "eager", "early", "fair",
	"fleet", "fresh", "gentle", "golden", "grand", "green", "happy", "hardy",
	"honest", "humble", "indigo", "ivory", "jolly", "keen", "kind", "lively",
	"lucky", "lunar", "maple", "merry", "mint", "misty", "modern", "noble",
	"opal", "pale", "peaceful", "plain", "polar", "prime", "proud", "quiet",
	"rapid", "ready", "royal", "ruby", "sage", "sandy", "scarlet", "sharp",
	"silent", "silver", "simple", "sincere", "smooth", "solar", "solid",
	"steady", "still", "stout", "sturdy", "sunny", "swift", "teal", "tidy",
	"topaz", "true", "urban", "vivid", "warm", "wise", "witty", "zesty",
}

var slugNouns = []string{
	"anchor", "arbor", "arch", "atlas", "aspen", "bay", "beacon", "birch",
	"bloom", "brook", "canyon", "cascade", "cedar", "channel", "cliff",
	"clover", "coast", "compass", "cove", "crane", "creek", "crest",
	"current", "dawn", "delta", "dune", "eagle", "ember", "estuary",
	"fern", "field", "fjord", "forge", "fountain", "garden", "glacier",
	"glade", "glen", "grove", "gulf", "harbor", "haven", "heath", "hollow",
	"horizon", "inlet", "island", "juniper", "lagoon", "lake", "lantern",
	"ledge", "loft", "lookout", "marsh", "meadow", "mesa", "mill", "moor",
	"nook", "oasis", "orchard", "outpost", "peak", "pier", "pine", "plaza",
	"port", "prairie", "quarry", "reef", "ridge", "river", "shore", "signal",
	"slope", "spire", "spring", "strand", "summit", "terrace", "thicket",
	"trail", "valley", "vista", "willow", "woods",
}

// randomSlugWord picks a cryptographically random entry from words.
// crypto/rand, never math/rand: a predictable fallback-slug generator
// would let an attacker infer signup ordering/volume from adjacent
// slugs, exactly the enumeration risk IsReservedSlug's design guards
// against elsewhere in this package.
func randomSlugWord(words []string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
	if err != nil {
		return "", fmt.Errorf("select slug word: %w", err)
	}
	return words[n.Int64()], nil
}

// randomSlugDisambiguator returns a short (2 bytes, 4 hex chars) suffix
// used only once a candidate has already been observed to collide — see
// candidateTenantSlug. Kept short deliberately: it only has to break one
// specific, already-observed collision, not carry the slug's entropy on
// its own the way the retired randomTenantSlugSuffix's 6-byte suffix did.
func randomSlugDisambiguator() (string, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate slug disambiguator: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// randomTenantSlug mints a fresh, human-presentable fallback tenant slug
// with no caller-supplied base: "<adjective>-<noun>" normally, or
// "<adjective>-<noun>-<hex4>" once withDisambiguator is set (attempt > 0
// in candidateTenantSlug, i.e. a previous word pair really did collide
// against a live tenant). The retry loop guards the astronomically
// unlikely case that a curated pair still fails IsValidSlug/IsReservedSlug
// (belt-and-suspenders — the lists are verified clear of reserved words by
// unit test); if every retry somehow still fails, it falls back to the
// old opaque-hex scheme so signup can never be blocked by this generator.
func randomTenantSlug(withDisambiguator bool) (string, error) {
	const maxWordPairAttempts = 8
	for i := 0; i < maxWordPairAttempts; i++ {
		adj, err := randomSlugWord(slugAdjectives)
		if err != nil {
			return "", err
		}
		noun, err := randomSlugWord(slugNouns)
		if err != nil {
			return "", err
		}
		candidate := adj + "-" + noun
		if withDisambiguator {
			suffix, err := randomSlugDisambiguator()
			if err != nil {
				return "", err
			}
			candidate = candidate + "-" + suffix
		}
		if models.IsValidSlug(candidate) && !models.IsReservedSlug(candidate) {
			return candidate, nil
		}
	}
	// Last resort, should be unreachable given the curated word lists:
	// fall back to a fully random, guaranteed-valid opaque slug rather
	// than fail the whole signup over a cosmetic generator.
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate fallback slug: %w", err)
	}
	return "tenant-" + hex.EncodeToString(b), nil
}

// candidateTenantSlug returns the tenant slug to try for the given
// (zero-based) attempt, given an optional caller-supplied base slug.
//
//   - attempt 0 with a non-empty base: try the base as-is (honors an
//     explicit company-derived or user-chosen slug on the first try).
//   - a retry (attempt > 0) with a non-empty base: the base itself just
//     collided, so disambiguate it ("<base>-<hex4>") rather than
//     discarding it — the tenant still gets a name related to what they
//     supplied.
//   - no base at all (the common case: Mearax's signup collects only
//     email+password): mint a word-pair fallback slug. attempt 0 tries a
//     bare pair; any retry means the previous pair collided, so a short
//     disambiguator is appended to guarantee a different candidate.
func candidateTenantSlug(base string, attempt int) (string, error) {
	if attempt == 0 && base != "" {
		return base, nil
	}
	if base != "" {
		suffix, err := randomSlugDisambiguator()
		if err != nil {
			return "", err
		}
		return base + "-" + suffix, nil
	}
	return randomTenantSlug(attempt > 0)
}

// ptr returns a pointer to the given string.
func ptr(s string) *string { return &s }
