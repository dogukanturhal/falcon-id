// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/text/unicode/norm"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
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
	// SetProvisionedTenant records a tenant-management registration that
	// has succeeded but not yet been followed by local provisioning
	// (CompleteSignup is not yet done — see provisionTenant's resume
	// checkpoint). slug is the ACTUAL slug tenant-management accepted,
	// which may differ from the originally-requested one after
	// collision retries.
	SetProvisionedTenant(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, slug string) error
	// SetCompanyDetails stores the company name and slug collected at
	// completion, only while no tenant is provisioned yet (an empty slug
	// stores NULL).
	SetCompanyDetails(ctx context.Context, id uuid.UUID, name, slug string) error
	// SetContinuation replaces the stored OIDC continuation of a pending
	// (not completed) request that a repeated signup reuses.
	SetContinuation(ctx context.Context, id uuid.UUID, continuation string) error
	// SetCompletionSecretHash stores the hash of the single-use completion
	// secret VerifyEmail issues (see CompleteSignup).
	SetCompletionSecretHash(ctx context.Context, id uuid.UUID, hash string) error
	// CountCompletedBusinessSignupsByEmailDomain counts COMPLETED business
	// signups whose email's domain (the part after "@", case-insensitive)
	// equals domain — see InitiateSignup's one-trial-per-work-domain abuse
	// control, below, for why this exists and what it does and does not stop.
	CountCompletedBusinessSignupsByEmailDomain(ctx context.Context, domain string) (int, error)
	// ReserveVerificationResend admits one more code send (cooldown + hourly
	// cap + per-row failed-guess cap, atomically); false means throttled.
	// requireUnverified scopes the send to the unverified branch so a
	// concurrent successful verify wins; the verified-recovery branch passes
	// false.
	ReserveVerificationResend(ctx context.Context, id uuid.UUID, cooldown, window time.Duration, maxPerWindow, maxFailedTotal int, requireUnverified bool) (bool, error)
	// SetVerificationCode installs a new code hash, invalidating the old code
	// and resetting its attempts.
	SetVerificationCode(ctx context.Context, id uuid.UUID, hash string, expiresAt time.Time) error
	// ClaimVerificationAttempt spends one attempt before the comparison.
	ClaimVerificationAttempt(ctx context.Context, id uuid.UUID, maxAttempts, maxFailedTotal int) (hash string, expiresAt time.Time, attempts int, ok bool, err error)
	// ConsumeVerificationCode makes the code single-use, marks verified and
	// refunds the claimed attempt from the per-row failure total.
	ConsumeVerificationCode(ctx context.Context, id uuid.UUID, hash string) (bool, error)
}

// Signup email-code limits.
const (
	signupCodeLength      = 6
	signupCodeTTL         = 15 * time.Minute
	signupCodeMaxAttempts = 5
	// signupCodeRowMaxFailures caps wrong guesses per signup row across all
	// codes: resends reset the per-code counter, not this one.
	signupCodeRowMaxFailures = 15
	signupResendCooldown     = 60 * time.Second
	signupResendWindow       = time.Hour
	signupResendMaxPerHour   = 5
)

var signupCodeRE = regexp.MustCompile(`^[0-9]{6}$`)

// generateSignupCode returns a uniformly random zero-padded 6-digit code.
// rand.Int draws by rejection sampling, so there is no modulo bias.
func generateSignupCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("generate verification code: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

const signupOTPKeyInfo = "falcon-id/signup-otp/v1"

// DeriveSignupOTPKey derives the HMAC key for signup codes from the
// deployment's TOKEN_HASH_SALT via HKDF-SHA256, so a leaked database alone
// cannot brute-force the 10^6 code space offline.
func DeriveSignupOTPKey(tokenHashSalt string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(tokenHashSalt), nil, []byte(signupOTPKeyInfo)), key); err != nil {
		return nil, fmt.Errorf("derive signup otp key: %w", err)
	}
	return key, nil
}

// hashVerificationCode is HMAC-SHA256 over the signup request id and the code,
// so a hash is useless for any other row. Only this hash is stored; never the
// plaintext.
func (s *SignupService) hashVerificationCode(id uuid.UUID, code string) string {
	mac := hmac.New(sha256.New, s.otpKey)
	mac.Write([]byte(id.String() + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

// normalizeSignupCode strips the spaces and dashes users paste with the code.
func normalizeSignupCode(raw string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\u00a0' || r == '\t' {
			return -1
		}
		return r
	}, raw)
}

// issueVerificationCode generates a code and returns it with its hash and expiry.
func (s *SignupService) issueVerificationCode(id uuid.UUID) (code, hash string, expires time.Time, err error) {
	code, err = generateSignupCode()
	if err != nil {
		return "", "", time.Time{}, err
	}
	return code, s.hashVerificationCode(id, code), time.Now().Add(signupCodeTTL), nil
}

// SignupEmailSender sends transactional email during the signup flow.
type SignupEmailSender interface {
	// SendSignupVerificationEmail emails the plaintext 6-digit code.
	SendSignupVerificationEmail(ctx context.Context, email, code, name string) error
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

// SignupPreferencesWriter writes per-product user preferences. It carries the
// marketing consent given at signup (best-effort; see CompleteSignup).
type SignupPreferencesWriter interface {
	PatchProduct(ctx context.Context, userID uuid.UUID, slug string, patch json.RawMessage) (json.RawMessage, error)
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

// SignupContinuationValidator decides whether a submitted OIDC continuation may
// be stored and later echoed back as a redirect (OAuthProviderService satisfies
// it). Optional: without it a submitted continuation is refused, because
// "cannot verify" must never be treated as "valid".
type SignupContinuationValidator interface {
	ValidateAuthorizeContinuation(ctx context.Context, raw string) error
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
	prefsWriter     SignupPreferencesWriter
	continuations   SignupContinuationValidator
	defaultAppURL   string
	consumerDomain  string
	defaultPlanCode string
	otpKey          []byte
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
	// Legacy SIGNUP_DEFAULT_PLAN_CODE controls consumer defaults only. It
	// must not turn a new business signup into Starter/Free/Marketing Scale.
	return SignupTrialPackageCode
}

// deriveConsumerEmail builds a personal account's email from its username.
func (s *SignupService) deriveConsumerEmail(username string) string {
	return username + "@" + s.consumerEmailDomain()
}

// freeEmailProviderDomains holds well-known consumer webmail domains that
// are routinely typed into a "work email" field by real, unrelated small
// businesses/solo founders. See emailDomainTrialAbuseCheck's doc comment
// (InitiateSignup, below) for why these are exempted from the
// one-trial-per-work-domain check rather than fed into it: enforcing
// domain-uniqueness on gmail.com would let the FIRST person who ever
// signs up with a gmail.com address lock every other unrelated gmail.com
// user out of a trial forever, which is not the abuse this control
// targets. Not exhaustive — a determined abuser can still find or stand
// up their own free-mail-alike domain; see the control's own doc comment
// for what this does and does not stop.
var freeEmailProviderDomains = map[string]struct{}{
	"gmail.com":      {},
	"googlemail.com": {},
	"yahoo.com":      {},
	"outlook.com":    {},
	"hotmail.com":    {},
	"live.com":       {},
	"msn.com":        {},
	"icloud.com":     {},
	"me.com":         {},
	"aol.com":        {},
	"protonmail.com": {},
	"proton.me":      {},
	"mail.com":       {},
	"gmx.com":        {},
	"yandex.com":     {},
	"zoho.com":       {},
	"fastmail.com":   {},
	"hey.com":        {},
	"pm.me":          {},
}

// emailDomain returns the lowercased portion after the last "@" in email,
// or "" if email has no "@". Used only for the abuse control below — not
// a general email-parsing helper (no local-part validation, no IDN/
// punycode handling — the addresses reaching here already passed
// InitiateSignup's own upstream format checks).
func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
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

// SetPreferencesWriter wires the optional user-preferences writer used to
// store the marketing consent given at signup. Unset, consent is dropped.
func (s *SignupService) SetPreferencesWriter(w SignupPreferencesWriter) {
	s.prefsWriter = w
}

// SetContinuationValidator wires the validator for the OIDC continuation a
// signup may carry (see SignupContinuationValidator).
func (s *SignupService) SetContinuationValidator(v SignupContinuationValidator) {
	s.continuations = v
}

// SetDefaultAppURL sets where a signup with no (valid) continuation is sent after
// completion (env SIGNUP_DEFAULT_APP_URL). Only an absolute http(s) URL is
// accepted; anything else is ignored with a warning so a misconfiguration can
// never turn into an open or broken redirect.
func (s *SignupService) SetDefaultAppURL(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		logger.Warn("SIGNUP_DEFAULT_APP_URL ignored: not an absolute http(s) URL")
		return
	}
	s.defaultAppURL = raw
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
	otpKey []byte,
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
		otpKey:          otpKey,
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
// address, a new throttled code is emailed and the existing record is returned
// so the caller can surface the same signup_id. That holds for a verified but
// not yet completed request too: it must re-verify the new code, which issues a
// new completion secret and invalidates the old one.
func (s *SignupService) InitiateSignup(
	ctx context.Context,
	input *models.CreateSignupRequestInput,
	ipAddress, userAgent string,
) (*models.SignupRequest, error) {
	// A submitted OIDC continuation is validated up front and refused (never
	// dropped) when it fails: it will be echoed back as a redirect later.
	continuation, err := s.validatedContinuation(ctx, input.Continuation)
	if err != nil {
		return nil, err
	}

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

	// Abuse control (t-signup-no-plan-step, 2026-09-18): one cardless
	// reverse-trial per work-email DOMAIN, for business accounts only.
	//
	// WHY: signup now hands out a full top-tier trial with no card and no
	// plan choice (see this method's opening comment and
	// signup_request.go's PlanCode doc comment) — removing the friction
	// that used to slow down repeat signups. Before this check, nothing
	// stopped the same person/company from re-running signup with
	// alice@acme.com, then bob@acme.com, then carol@acme.com, each one a
	// brand-new 14-day top-tier trial for the same organization. Personal
	// accounts are excluded: every personal signup shares ONE consumer
	// email domain (consumerEmailDomain(), <username>@downstream.com) and
	// never starts a billing trial at all — TrialStarter.StartTrial is
	// only ever called for business accounts (see
	// signup_post_provisioner.go's OnSignupComplete step 7 gate on
	// accountType == business) — so a per-domain rule on the shared
	// consumer domain would be both meaningless (nothing to protect) and
	// wrong (it would lock out unrelated people after the first one).
	//
	// Free consumer webmail domains (gmail.com, outlook.com, ...) are
	// exempt — see freeEmailProviderDomains's doc comment: enforcing
	// domain-uniqueness there would block the SECOND unrelated gmail.com
	// user forever, not the abuser.
	//
	// WHAT THIS DOES NOT STOP (say so, don't bury it):
	//   - A single domain still gets exactly one trial no matter how many
	//     employees sign up — legitimate multi-person signup at the same
	//     company after the first one will also be refused here. That is
	//     the accepted tradeoff for closing the free-trial-farming path;
	//     the second employee can still be invited into the FIRST trial's
	//     tenant instead of starting a new one.
	//   - Someone willing to register their OWN throwaway domain
	//     (acme-trial-2.com, acme-trial-3.com, ...) is not blocked — DNS
	//     registration cost is the only friction, and this control does
	//     not attempt domain-similarity/typosquat detection.
	//   - Someone using a free-webmail domain not on the exemption list,
	//     or a disposable-email service, is not blocked (no card, no
	//     disposable-domain blocklist — out of this change's scope; see
	//     the task's explicit "do not add a credit-card requirement").
	//   - This only counts COMPLETED signups; an abandoned/never-completed
	//     signup at the same domain does not consume the domain's slot.
	if input.AccountType == discoverAccountTypeBusiness {
		if domain := emailDomain(email); domain != "" {
			if _, free := freeEmailProviderDomains[domain]; !free {
				n, err := s.repo.CountCompletedBusinessSignupsByEmailDomain(ctx, domain)
				if err != nil {
					return nil, fmt.Errorf("check domain trial eligibility: %w", err)
				}
				if n > 0 {
					return nil, &SignupStateError{Code: "domain_trial_exists"}
				}
			}
		}
	}

	// Re-use an existing pending request if we have one.
	pending, _ := s.repo.GetPendingByEmail(ctx, email)
	if pending != nil && continuation != nil {
		// A repeated signup for the same pending email reuses its row; it only
		// gains a continuation if it has none (never overwritten).
		if err := s.refreshContinuation(ctx, pending, *continuation); err != nil {
			return nil, err
		}
	}
	if pending != nil && !pending.Completed && !pending.IsExpired() {
		// Resend (unverified) or recovery (verified but never completed): both
		// run the same throttled path (cooldown + hourly cap + per-row guess
		// cap), then a NEW code replaces the old one and resets its attempts.
		// Delivery is best-effort: a failure must not fail the request, but it
		// must not be silent either (2026-08-02 — a six-minute greylist stall
		// on this path went unnoticed for two days).
		//
		// A verified row resumes into CompleteSignup against the SAME request
		// id rather than forking a second row (which used to mint an orphaned
		// tenant-management tenant: production "atlasbadi" 938ba35f, zero
		// users, then "atlasbadi-a1ad" cf097694). Resuming now requires proving
		// the mailbox again: verifying the new code issues a new completion
		// secret and the old one stops working, so merely knowing the email no
		// longer yields a resumable session.
		//
		// requireUnverified (unverified branch only) lets a concurrent
		// successful verify win over a resend.
		ok, err := s.repo.ReserveVerificationResend(ctx, pending.ID, signupResendCooldown, signupResendWindow, signupResendMaxPerHour, signupCodeRowMaxFailures, !pending.Verified)
		if err != nil {
			return nil, fmt.Errorf("reserve verification resend: %w", err)
		}
		if !ok {
			return nil, &SignupStateError{Code: "resend_throttled"}
		}
		code, hash, expires, err := s.issueVerificationCode(pending.ID)
		if err != nil {
			return nil, err
		}
		if err := s.repo.SetVerificationCode(ctx, pending.ID, hash, expires); err != nil {
			return nil, fmt.Errorf("store verification code: %w", err)
		}
		pending.VerificationCodeHash = &hash
		pending.VerificationCodeExpiresAt = &expires
		pending.VerificationAttempts = 0
		firstName := ""
		if pending.FirstName != nil {
			firstName = *pending.FirstName
		}
		if err := s.emailSender.SendSignupVerificationEmail(ctx, email, code, firstName); err != nil {
			logger.Error("signup verification re-send failed", zap.String("email", email), zap.Error(err))
		}
		return pending, nil
	}

	// verification_token is kept populated (legacy column) with an unusable
	// random placeholder that is never emailed; verification is by code.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate verification token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	reqID := uuid.New()
	code, codeHash, codeExpires, err := s.issueVerificationCode(reqID)
	if err != nil {
		return nil, err
	}

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
			if slug := generateSlug(input.CompanyName); slug != "" {
				companySlug = &slug
			}
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
		ID:                        reqID,
		Email:                     email,
		FirstName:                 firstName,
		LastName:                  lastName,
		AccountType:               input.AccountType,
		CompanyName:               companyName,
		CompanySlug:               companySlug,
		Continuation:              continuation,
		VerificationToken:         token,
		VerificationCodeHash:      &codeHash,
		VerificationCodeExpiresAt: &codeExpires,
		IPAddress:                 &ipAddress,
		UserAgent:                 &userAgent,
		ExpiresAt:                 time.Now().Add(24 * time.Hour),
	}

	if err := s.repo.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create signup request: %w", err)
	}
	metrics.SignupFunnelInc(metrics.SignupStageInitiated, companyName != nil)

	// Email delivery is best-effort: a failure here must not roll back the
	// signup request so the user can request a re-send later. It is logged
	// rather than discarded — see iam_email_send_failures_total for the
	// corresponding metric.
	if err := s.emailSender.SendSignupVerificationEmail(ctx, email, code, input.FirstName); err != nil {
		logger.Error("signup verification send failed", zap.String("email", email), zap.Error(err))
	}

	return req, nil
}

// validatedContinuation returns nil for an empty continuation, a pointer to the
// validated one otherwise, or a SignupStateError("invalid_continuation").
func (s *SignupService) validatedContinuation(ctx context.Context, raw string) (*string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if s.continuations == nil {
		return nil, &SignupStateError{Code: "invalid_continuation"}
	}
	if err := s.continuations.ValidateAuthorizeContinuation(ctx, raw); err != nil {
		if errors.Is(err, ErrInvalidAuthorizeContinuation) {
			return nil, &SignupStateError{Code: "invalid_continuation"}
		}
		return nil, fmt.Errorf("validate signup continuation: %w", err)
	}
	return &raw, nil
}

// refreshContinuation stores continuation on a reused pending request that has
// none.
func (s *SignupService) refreshContinuation(ctx context.Context, pending *models.SignupRequest, continuation string) error {
	// An unauthenticated caller must not redirect an existing signup: only a
	// request with no continuation yet accepts one.
	if pending.Continuation != nil {
		return nil
	}
	if err := s.repo.SetContinuation(ctx, pending.ID, continuation); err != nil {
		return fmt.Errorf("update signup continuation: %w", err)
	}
	pending.Continuation = &continuation
	return nil
}

// completionRedirect decides where the browser goes once signup completes: the
// stored OIDC continuation when it still validates (the client may have been
// deactivated since it was stored), otherwise the configured default app URL,
// otherwise "" (the caller then falls back to its own default).
func (s *SignupService) completionRedirect(ctx context.Context, req *models.SignupRequest) string {
	if req.Continuation != nil && *req.Continuation != "" && s.continuations != nil {
		if err := s.continuations.ValidateAuthorizeContinuation(ctx, *req.Continuation); err == nil {
			return *req.Continuation
		}
		logger.Warn("signup: stored continuation no longer valid; using default app URL",
			zap.String("signup_request_id", req.ID.String()))
	}
	return s.defaultAppURL
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

// VerifyEmail validates the emailed 6-digit code (input.Code) for the signup
// identified by input.SignupID or input.Email. The code is never looked up on
// its own. A request that carries only the legacy long token is accepted for
// rows that have no code hash (pre-OTP signups).
//
// Idempotence: the code is single-use, but a fresh completion secret is issued
// to whoever proves the mailbox. Errors are SignupStateError with codes
// verification_code_invalid (also for an expired code, so expiry is not an
// oracle) and verification_attempts_exceeded (per-code or per-row cap).
func (s *SignupService) VerifyEmail(ctx context.Context, input *models.VerifySignupEmailInput) (*models.SignupRequest, error) {
	var req *models.SignupRequest
	var err error
	if strings.TrimSpace(input.Code) == "" && strings.TrimSpace(input.Token) != "" {
		// TODO(2026-12-01): remove the legacy hex-token path once all pre-OTP
		// pending signups (24h lifetime) and old frontend builds are gone.
		req, err = s.verifyLegacyToken(ctx, strings.TrimSpace(input.Token))
	} else {
		req, err = s.verifyCode(ctx, input)
	}
	if err != nil {
		return nil, err
	}
	return s.issueCompletionSecret(ctx, req)
}

func (s *SignupService) verifyLegacyToken(ctx context.Context, token string) (*models.SignupRequest, error) {
	req, err := s.repo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired verification token")
	}
	if req.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("verification token has expired")
	}
	if !req.Verified {
		if err := s.repo.MarkVerified(ctx, req.ID); err != nil {
			return nil, fmt.Errorf("mark verified: %w", err)
		}
		req.Verified = true
		now := time.Now()
		req.VerifiedAt = &now
	}
	return req, nil
}

func (s *SignupService) verifyCode(ctx context.Context, input *models.VerifySignupEmailInput) (*models.SignupRequest, error) {
	invalid := &SignupStateError{Code: "verification_code_invalid"}
	code := normalizeSignupCode(input.Code)
	if !signupCodeRE.MatchString(code) {
		return nil, invalid
	}

	var req *models.SignupRequest
	switch {
	case strings.TrimSpace(input.SignupID) != "":
		id, perr := uuid.Parse(strings.TrimSpace(input.SignupID))
		if perr != nil {
			return nil, invalid
		}
		r, gerr := s.repo.GetByID(ctx, id)
		if gerr != nil {
			return nil, invalid
		}
		req = r
	case strings.TrimSpace(input.Email) != "":
		r, gerr := s.repo.GetPendingByEmail(ctx, strings.ToLower(strings.TrimSpace(input.Email)))
		if gerr != nil {
			return nil, invalid
		}
		req = r
	default:
		return nil, invalid
	}
	if req.Completed || req.ExpiresAt.Before(time.Now()) {
		return nil, invalid
	}

	// Spend the attempt first (atomic), then compare.
	storedHash, _, attempts, ok, err := s.repo.ClaimVerificationAttempt(ctx, req.ID, signupCodeMaxAttempts, signupCodeRowMaxFailures)
	if err != nil {
		return nil, fmt.Errorf("claim verification attempt: %w", err)
	}
	if !ok {
		// The claim also fails for an expired code, which answers invalid.
		if req.VerificationCodeHash != nil && (req.VerificationAttempts >= signupCodeMaxAttempts || req.VerificationFailedTotal >= signupCodeRowMaxFailures) {
			metrics.SignupVerifyFailures.WithLabelValues("attempts_exceeded").Inc()
			return nil, &SignupStateError{Code: "verification_attempts_exceeded"}
		}
		return nil, invalid
	}
	given := s.hashVerificationCode(req.ID, code)
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(given)) != 1 {
		if attempts >= signupCodeMaxAttempts || req.VerificationFailedTotal+1 >= signupCodeRowMaxFailures {
			metrics.SignupVerifyFailures.WithLabelValues("attempts_exceeded").Inc()
			return nil, &SignupStateError{Code: "verification_attempts_exceeded"}
		}
		metrics.SignupVerifyFailures.WithLabelValues("invalid").Inc()
		return nil, invalid
	}
	consumed, err := s.repo.ConsumeVerificationCode(ctx, req.ID, storedHash)
	if err != nil {
		return nil, fmt.Errorf("consume verification code: %w", err)
	}
	if !consumed {
		return nil, invalid
	}
	req.Verified = true
	now := time.Now()
	req.VerifiedAt = &now
	metrics.SignupFunnelInc(metrics.SignupStageVerified, req.CompanyName != nil)
	return req, nil
}

// issueCompletionSecret hands the caller who proved the mailbox a fresh
// single-use completion secret.
func (s *SignupService) issueCompletionSecret(ctx context.Context, req *models.SignupRequest) (*models.SignupRequest, error) {
	secret, err := newCompletionSecret()
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetCompletionSecretHash(ctx, req.ID, hashCompletionSecret(secret)); err != nil {
		return nil, fmt.Errorf("store completion secret: %w", err)
	}
	req.CompletionSecret = secret
	return req, nil
}

// newCompletionSecret returns 256 random bits, hex encoded.
func newCompletionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate completion secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashCompletionSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// completionSecretMatches compares in constant time. A request with no stored
// hash (never verified through VerifyEmail) never matches.
func completionSecretMatches(req *models.SignupRequest, secret string) bool {
	if req.CompletionSecretHash == nil || *req.CompletionSecretHash == "" || secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(*req.CompletionSecretHash), []byte(hashCompletionSecret(secret))) == 1
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
	// RedirectURL is where the client sends the browser next: the validated
	// OIDC continuation stored at signup (relative /oauth/authorize URL), else
	// the configured default app URL, else "".
	RedirectURL string
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

	// Mailbox proof: the signup id is handed to anyone who starts a signup for
	// an address, so completing also needs the secret only the verify-email
	// caller receives. Same answer as an unknown id, checked before any state
	// (verified/completed/expired) is revealed.
	if !completionSecretMatches(req, input.CompletionSecret) {
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
	input.PlanCode, err = signupPlanSelection(input.PlanCode)
	if err != nil {
		return nil, err
	}

	// PlanCode is intentionally OPTIONAL again (reverted 2026-09-18 —
	// t-signup-no-plan-step). It was made mandatory by e75eeb7
	// (2026-09-17) because an empty plan meant no trial subscription row
	// was ever created — nothing to expire, convert, or dun. That gap is
	// now closed a layer down instead of by refusing signup: every
	// self-serve signup provisions the reverse trial on the top self-serve
	// tier regardless of PlanCode (subscription-management's
	// TrialService.StartTrial resolves the trial-entitlement package via
	// packageRepo.FindDefault when PlanCode is empty — see that function's
	// 2026-09-18 reverse-trial-redesign doc comment in
	// platform-commerce/services/subscription-management/internal/services/
	// trial.go). PlanCode, when present, only ever picks the DESTINATION
	// package the trial converts to at day 14 (or is ignored by an
	// upgrade-moment picker later) — it never gated whether a trial started
	// in the first place; that was purely this now-removed check.
	// Step 7 of onSignupComplete below (trial start) logs at Error with a
	// dedicated metric on failure and is repaired by tenant-management's
	// trial-gap reconciler — it is not silently swallowed, so removing
	// this gate does not reopen the original "trial start failure is
	// invisible" half of the incident, only the "plan choice was
	// mandatory" half.
	if err := s.applyCompanyDetails(ctx, req, input); err != nil {
		return nil, err
	}
	withCompany := req.CompanyName != nil

	tenantID, tenantSlug, err := s.provisionTenant(ctx, req)
	if err != nil {
		metrics.SignupFunnelInc(metrics.SignupStageFailed, withCompany)
		return nil, err
	}

	user, err := s.provisionUser(ctx, req, tenantID, input.Password, credential)
	if err != nil {
		metrics.SignupFunnelInc(metrics.SignupStageFailed, withCompany)
		return nil, err
	}
	s.storeMarketingConsent(ctx, user.ID, input.MarketingConsent)

	// Non-fatal: tenant and user already exist, so the failure here would
	// only leave the record in a non-completed state.
	_ = s.repo.MarkCompleted(ctx, req.ID, tenantID, user.ID)
	metrics.SignupFunnelInc(metrics.SignupStageCompleted, withCompany)
	metrics.SignupDuration.Observe(time.Since(req.CreatedAt).Seconds())

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
		var hookErr error
		if planAware, ok := s.postSignupHook.(PlanAwarePostSignupHook); ok {
			hookErr = planAware.OnSignupCompleteWithPlan(ctx, tenantID, user.ID, req.AccountType, input.PlanCode)
		} else {
			hookErr = s.postSignupHook.OnSignupComplete(ctx, tenantID, user.ID, req.AccountType)
		}
		if errors.Is(hookErr, ErrSignupTrialAlreadyConsumed) {
			return nil, &SignupStateError{Code: "TRIAL_ALREADY_CONSUMED"}
		}
	}

	result := &CompleteSignupResult{User: user, TenantSlug: tenantSlug, RedirectURL: s.completionRedirect(ctx, req)}

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

// applyCompanyDetails persists the company name and slug sent with
// CompleteSignup, for business accounts that have not provisioned a tenant
// yet. A resumed completion (req.TenantID set) ignores both: the slug that
// registered wins. An explicit slug is validated like the initiate-time
// claim and refused with the same generic "slug_unavailable"; without one
// the slug is derived from the name (and may be empty, which falls back to
// a word pair in provisionTenant).
func (s *SignupService) applyCompanyDetails(ctx context.Context, req *models.SignupRequest, input *models.CompleteSignupInput) error {
	if req.AccountType != discoverAccountTypeBusiness || req.TenantID != nil {
		return nil
	}
	name := strings.TrimSpace(input.CompanyName)
	if name == "" {
		return nil
	}
	if n := utf8.RuneCountInString(name); n < 2 || n > 120 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return &SignupStateError{Code: "invalid_company_name"}
	}
	var slug string
	if explicit := normalizeUsername(input.Slug); explicit != "" {
		if _, err := s.CheckSlugAvailable(ctx, explicit); err != nil {
			return &SignupStateError{Code: "slug_unavailable"}
		}
		slug = explicit
	} else {
		slug = generateSlug(name)
	}
	if err := s.repo.SetCompanyDetails(ctx, req.ID, name, slug); err != nil {
		return err
	}
	req.CompanyName = &name
	req.CompanySlug = nil
	if slug != "" {
		req.CompanySlug = &slug
	}
	return nil
}

// storeMarketingConsent records the consent given on the company step under
// the key the old onboarding wizard used, so its readers do not change.
// Best-effort: it never fails the signup.
func (s *SignupService) storeMarketingConsent(ctx context.Context, userID uuid.UUID, consent *bool) {
	if consent == nil || s.prefsWriter == nil {
		return
	}
	patch, err := json.Marshal(map[string]any{"onboarding_profile": map[string]any{"marketingConsent": *consent}})
	if err == nil {
		_, err = s.prefsWriter.PatchProduct(ctx, userID, "acmeweb", patch)
	}
	if err != nil {
		logger.Warn("signup: storing marketing consent failed", zap.String("user_id", userID.String()), zap.Error(err))
	}
}

func (s *SignupService) SignupPasswordPolicy() SignupPasswordPolicy {
	return s.userCreator.SignupPasswordPolicy()
}

// provisionTenant creates either a business or personal tenant and returns its ID.
func (s *SignupService) provisionTenant(ctx context.Context, req *models.SignupRequest) (uuid.UUID, string, error) {
	var tenantReq *models.CreateTenantRequest

	if req.AccountType == discoverAccountTypeBusiness {
		tenantName := models.PlaceholderTenantName
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

		// RESUME CHECKPOINT: a prior CompleteSignup attempt against this
		// same request may have already registered a tenant-management
		// tenant (req.TenantID set by SetProvisionedTenant, immediately
		// after a successful Register call below) before failing on the
		// second, local-provisioning phase, or CompleteSignup may simply
		// be getting called twice (client retry after a slow/lost
		// response). Either way, calling s.tenantRegistrar.Register again
		// here would mint a SECOND tenant-management row for the same
		// signup — this is exactly the "atlasbadi" / "atlasbadi-a1ad"
		// production duplicate (938ba35f then cf097694, 24 seconds apart,
		// same person, first row left as a permanent zero-user orphan).
		// So: if a tenant was already registered, resume from there
		// instead of re-registering.
		if req.TenantID != nil {
			if existingLocal, err := s.tenantCreator.GetByID(ctx, *req.TenantID); err != nil {
				return uuid.Nil, "", fmt.Errorf("look up already-provisioned tenant %s: %w", *req.TenantID, err)
			} else if existingLocal != nil {
				// Both phases already completed on a prior attempt —
				// fully idempotent resume, no further provisioning calls.
				return existingLocal.ID, existingLocal.Slug, nil
			}

			// Phase 1 (tenant-management registration) succeeded before;
			// phase 2 (local iam_tenants row) did not. Resume straight
			// into phase 2 using the slug that was actually registered
			// (persisted into req.CompanySlug by SetProvisionedTenant —
			// NOT the original candidate, which may have collided and
			// been replaced by a later attempt).
			resumeSlug := ""
			if req.CompanySlug != nil {
				resumeSlug = *req.CompanySlug
			}
			tenantReq = &models.CreateTenantRequest{
				ID:          req.TenantID,
				Name:        tenantName,
				Slug:        resumeSlug,
				DisplayName: tenantName,
				Type:        "customer",
				Plan:        s.defaultPlan(),
			}
			tenant, err := s.tenantCreator.CreateTenant(ctx, tenantReq)
			if err != nil {
				return uuid.Nil, "", fmt.Errorf("create %s tenant (resumed): %w", req.AccountType, err)
			}
			return tenant.ID, tenant.Slug, nil
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
		// Pre-check base, base-2..base-5 so a name collision lands on a
		// readable slug; the hex4 retries below stay the fallback for races.
		firstSlug, _ := s.firstAvailableSlug(ctx, baseSlug)
		for attempt := 0; attempt < maxTenantSlugAttempts; attempt++ {
			candidate, genErr := candidateTenantSlug(baseSlug, attempt)
			if attempt == 0 && firstSlug != "" {
				candidate, genErr = firstSlug, nil
			}
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

		// Checkpoint immediately: from this point on, a tenant-management
		// row exists for this signup request. Persist it BEFORE the
		// (separate, unsagaed) local CreateTenant call below so that if
		// CreateTenant fails, or the process dies, or the client retries
		// CompleteSignup, the resume branch above finds it and reuses it
		// instead of registering a second tenant. Best-effort: a failure
		// to persist the checkpoint must not undo a successful
		// registration (there is nothing to roll back to), so it is
		// logged, not fatal — this narrows, but does not fully close, the
		// duplicate-tenant window down to "checkpoint write itself fails",
		// versus today's "every retry re-registers."
		if err := s.repo.SetProvisionedTenant(ctx, req.ID, registered.ID, tenantSlug); err != nil {
			logger.Error("signup: failed to checkpoint provisioned tenant; a retry may re-register",
				zap.String("signup_request_id", req.ID.String()),
				zap.String("tenant_id", registered.ID.String()),
				zap.Error(err),
			)
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
		// Completion is reachable only after the verification link was
		// followed, so the mailbox is proven.
		EmailVerified: true,
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

// slugTurkishReplacer maps Turkish letters before lowercasing: ToLower('İ')
// yields "i" plus a combining dot, and 'I' is the dotless capital that must become "i".
var slugTurkishReplacer = strings.NewReplacer(
	"ç", "c", "Ç", "c", "ğ", "g", "Ğ", "g", "ı", "i", "I", "i", "İ", "i",
	"ö", "o", "Ö", "o", "ş", "s", "Ş", "s", "ü", "u", "Ü", "u",
)

// slugLegalTails are trailing words (after transliteration) that name a
// legal form or trade description, not the brand: "A.Ş.", "Ltd. Şti.",
// "San. ve Tic.". Stripped from the end one phrase at a time.
var slugLegalTails = [][]string{
	{"a", "s"}, {"as"}, {"anonim"}, {"sirketi"}, {"limited"}, {"ltd"}, {"sti"},
	{"san"}, {"sanayi"}, {"tic"}, {"ticaret"}, {"ve"},
	{"inc"}, {"llc"}, {"gmbh"},
}

const maxGeneratedSlugLen = 40

// generateSlug derives a tenant subdomain slug from a company name:
// "Çağrı Yazılım A.Ş." becomes "cagri-yazilim". Turkish letters are mapped
// before lowercasing, other accents are stripped (NFD), legal-form suffixes
// are dropped, and the result is cut to 40 characters at a hyphen. It
// returns "" when nothing usable is left (too short, not a valid slug); the
// caller then falls back to a word pair, never a fixed literal. A reserved
// word gets a "-2" suffix.
func generateSlug(name string) string {
	decomposed := norm.NFD.String(strings.ToLower(slugTurkishReplacer.Replace(name)))
	// Drop combining marks first so "e" + U+0301 stays one word.
	decomposed = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, decomposed)
	words := strings.FieldsFunc(decomposed, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	for stripped := true; stripped; {
		stripped = false
		for _, tail := range slugLegalTails {
			if len(words) > len(tail) && slicesEqual(words[len(words)-len(tail):], tail) {
				words = words[:len(words)-len(tail)]
				stripped = true
				break
			}
		}
	}
	slug := strings.Join(words, "-")
	if len(slug) > maxGeneratedSlugLen {
		slug = slug[:maxGeneratedSlugLen+1]
		if i := strings.LastIndexByte(slug, '-'); i > 0 {
			slug = slug[:i]
		} else {
			slug = slug[:maxGeneratedSlugLen]
		}
	}
	slug = strings.Trim(slug, "-")
	if !models.IsValidSlug(slug) {
		return ""
	}
	if models.IsReservedSlug(slug) {
		return slug + "-2"
	}
	return slug
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// slugCandidates lists the readable names to try for base: base, base-2 ..
// base-5, without the reserved or invalid ones. Empty for an empty base.
func slugCandidates(base string) []string {
	if base == "" {
		return nil
	}
	out := make([]string, 0, 5)
	for i := 1; i <= 5; i++ {
		c := base
		if i > 1 {
			c = fmt.Sprintf("%s-%d", base, i)
		}
		if models.IsValidSlug(c) && !models.IsReservedSlug(c) {
			out = append(out, c)
		}
	}
	return out
}

// firstAvailableSlug returns the first slugCandidates(base) entry that
// tenant-management reports free. With no checker, or when every check
// errors or reports taken, it returns "" and false so the caller keeps its
// existing retry behaviour.
func (s *SignupService) firstAvailableSlug(ctx context.Context, base string) (string, bool) {
	if s.slugChecker == nil {
		return "", false
	}
	for _, c := range slugCandidates(base) {
		if ok, err := s.slugChecker.IsSlugAvailable(ctx, c); err == nil && ok {
			return c, true
		}
	}
	return "", false
}

// SuggestSlug backs GET /signup/suggest-slug: the first available slug for a
// company name. When the name yields nothing usable it suggests a word pair.
// available=false means no free candidate could be confirmed (all taken, or
// availability cannot be verified); the slug is then only a hint. Taken,
// reserved and unverifiable are not told apart.
func (s *SignupService) SuggestSlug(ctx context.Context, name string) (string, bool) {
	base := generateSlug(name)
	if base == "" {
		pair, err := randomTenantSlug(false)
		if err != nil {
			return "", false
		}
		base = pair
	}
	if slug, ok := s.firstAvailableSlug(ctx, base); ok {
		return slug, true
	}
	suffix, err := randomSlugDisambiguator()
	if err != nil {
		return base, false
	}
	return base + "-" + suffix, false
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
//   - no base at all (the common case: AcmeWeb's signup collects only
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
