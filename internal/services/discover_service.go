// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// discoverNegativeCacheSize bounds the unknown-email negative cache.
// 1024 entries × ~256B per entry = ~256KB ceiling — trivial for the
// IdP process even at maximum saturation. Sized for the realistic peak
// of credential-stuffing probes per minute (industry threat intel: <500
// distinct emails/min from a single bot fleet); larger sizes provide
// diminishing returns since the TTL retires entries faster than the
// LRU evicts under attack.
const discoverNegativeCacheSize = 1024

// discoverNegativeCacheTTL bounds how long an "email unknown" verdict
// can be served from cache. 60s matches the user-experience window for
// a legitimate sign-up: a user typing an email, getting "we don't know
// you, sign up?", and finishing the sign-up flow takes more than 60s
// in practice, so a freshly-registered email will not be wrongly
// pinned to "unknown" once the user comes back to the login page.
const discoverNegativeCacheTTL = 60 * time.Second

const (
	discoverAccountTypeBusiness = "business"
	discoverIDPTypeSAML         = "saml"

	// DiscoverResponse.AuthMethod values returned by Discover. The login UI
	// branches on these to render the password form, SSO redirect, signup
	// flow, or contact-admin screen. Must stay in sync with the field
	// docstring on models.DiscoverResponse.AuthMethod.
	discoverAuthMethodPassword     = "password"
	discoverAuthMethodSignup       = "signup"
	discoverAuthMethodSSO          = "sso"
	discoverAuthMethodContactAdmin = "contact_admin"
)

// Sentinel errors for the Home Realm Discovery service.
//
// Sentinels let the handler distinguish "user-input is invalid"
// (400 Bad Request) from "I couldn't look up state" (502/503/500),
// and let the metrics counter label by step instead of stringifying
// the underlying error message (label-cardinality blowout).
//
// Pattern follows Ory Hydra / Fosite (errors.Is-comparable sentinels
// at every service boundary) and Dave Cheney's "handle errors once"
// guidance — wrap with %w at each hop, log + branch at the boundary.
var (
	// ErrDiscoverInvalidEmail is returned when the email argument can't
	// be parsed (no @ sign, empty after trim, etc). User-input bug —
	// map to HTTP 400, not 500.
	ErrDiscoverInvalidEmail = errors.New("discover: invalid email")

	// ErrDiscoverDomainLookup is returned when the verified-domain
	// repository read fails. Upstream-DB problem — map to 503.
	ErrDiscoverDomainLookup = errors.New("discover: domain lookup")

	// ErrDiscoverTenantLookup is returned when the tenant repository
	// read fails on a domain-claimed tenant. Upstream-DB problem — 503.
	ErrDiscoverTenantLookup = errors.New("discover: tenant lookup")

	// ErrDiscoverUserLookup is returned when the global user lookup
	// fails. Upstream-DB problem — 503.
	ErrDiscoverUserLookup = errors.New("discover: user lookup")
)

// DiscoverStep is the failure step for metrics labels. Bounded to the
// finite set of (domain_lookup, tenant_lookup, user_lookup,
// invalid_email) so label cardinality stays under 10.
type DiscoverStep string

const (
	DiscoverStepInvalidEmail  DiscoverStep = "invalid_email"
	DiscoverStepDomainLookup  DiscoverStep = "domain_lookup"
	DiscoverStepTenantLookup  DiscoverStep = "tenant_lookup"
	DiscoverStepUserLookup    DiscoverStep = "user_lookup"
)

// DiscoverError carries the failing step alongside the wrapped cause
// so callers can branch + log without parsing error strings.
type DiscoverError struct {
	Step DiscoverStep
	Err  error
}

func (e *DiscoverError) Error() string {
	if e.Err == nil {
		return string(e.Step)
	}
	return string(e.Step) + ": " + e.Err.Error()
}

func (e *DiscoverError) Unwrap() error { return e.Err }

// Is satisfies errors.Is for the sentinels above — any DiscoverError
// matches its step's sentinel, and the underlying wrapped error is
// still reachable via Unwrap chain.
func (e *DiscoverError) Is(target error) bool {
	switch target {
	case ErrDiscoverInvalidEmail:
		return e.Step == DiscoverStepInvalidEmail
	case ErrDiscoverDomainLookup:
		return e.Step == DiscoverStepDomainLookup
	case ErrDiscoverTenantLookup:
		return e.Step == DiscoverStepTenantLookup
	case ErrDiscoverUserLookup:
		return e.Step == DiscoverStepUserLookup
	}
	return false
}

// DiscoverDomainRepo is the persistence contract for verified email domain lookups.
type DiscoverDomainRepo interface {
	GetVerifiedByDomain(ctx context.Context, domain string) (*models.EmailDomainRegistry, error)
}

// DiscoverTenantRepo is the persistence contract for tenant lookups by primary key.
type DiscoverTenantRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
}

// DiscoverUserRepo is the persistence contract for cross-tenant user lookups.
type DiscoverUserRepo interface {
	GetByEmailGlobal(ctx context.Context, email string) (*models.User, error)
}

// DiscoverIDPRepo is an exported identifier.
// DiscoverIDPRepo is the persistence contract for enabled identity provider lookups.
type DiscoverIDPRepo interface {
	GetEnabledLoginProviders(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) ([]*models.IdentityProvider, error)
}

// DiscoverBrandingRepo is the persistence contract for tenant branding lookups.
type DiscoverBrandingRepo interface {
	GetByTenantID(ctx context.Context, tenantID uuid.UUID) (*models.TenantBranding, error)
}

// DiscoverWebAuthnRepo is the narrow surface DiscoverService needs from
// the WebAuthn repository — only the active-credential count. Optional
// dependency: when nil, has_passkey is reported as false (the safe
// default — falls back to password-only UX).
type DiscoverWebAuthnRepo interface {
	CountActiveByUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error)
}

// DiscoverFeatureFlagRepo is the narrow surface DiscoverService needs from
// the feature-flag repository — only the per-tenant IsEnabled check, so
// resp.LocalAuthDisabled (t-431) reports the real, enforced value rather
// than staying permanently false. Optional dependency: when nil,
// LocalAuthDisabled is reported as false (matches its pre-t-431 dead-field
// behaviour — this is a UI hint only, AuthService.Login is the actual
// enforcement point and gates independently of Discover).
type DiscoverFeatureFlagRepo interface {
	IsEnabled(ctx context.Context, tenantID uuid.UUID, featureKey string) (bool, error)
}

// DiscoverService implements Home Realm Discovery (HRD): given an email address
// it determines which tenant the user belongs to and how they should authenticate.
type DiscoverService struct {
	domainRepo      DiscoverDomainRepo
	tenantRepo      DiscoverTenantRepo
	userRepo        DiscoverUserRepo
	idpRepo         DiscoverIDPRepo
	brandingRepo    DiscoverBrandingRepo
	overrideService *IDPTenantOverrideService
	webauthnRepo    DiscoverWebAuthnRepo    // optional
	featureFlagRepo DiscoverFeatureFlagRepo // optional

	// negativeCache memoises "completely unknown email" verdicts to (a)
	// cut DB load under enumeration attempts, and (b) reduce the
	// timing gap between known-user (extra branding + IDP lookups) and
	// unknown-user paths. Pair with the per-IP rate limiter on
	// /discover (auth_discover EndpointOverride): cache reduces work,
	// rate limit caps attempt-rate. Only NEGATIVE responses go in —
	// caching positives would risk serving a stale Branding/IDP set
	// across the 60s TTL after a tenant admin changes them.
	negativeCache *lru.LRU[string, *models.DiscoverResponse]
}

// SetWebAuthnRepo wires the optional webauthn-count surface so discover
// responses include has_passkey for known users. Without this, has_passkey
// is always reported as false — clients fall back to password-only UX,
// which is safe but misses the surfaced-passkey-button affordance.
func (s *DiscoverService) SetWebAuthnRepo(r DiscoverWebAuthnRepo) {
	s.webauthnRepo = r
}

// SetFeatureFlagRepo wires the optional feature-flag surface so discover
// responses report the real local_auth_disabled state (t-431) instead of
// the permanently-false zero value. Without this, LocalAuthDisabled is
// always false — a UI-hint regression only, not a security gap: the actual
// enforcement lives in AuthService.enforceLocalAuthAllowed and does not
// depend on Discover having been called at all.
func (s *DiscoverService) SetFeatureFlagRepo(r DiscoverFeatureFlagRepo) {
	s.featureFlagRepo = r
}

// isLocalAuthDisabled reports the tenant's local_auth_disabled policy flag.
// No-op (false) when the feature-flag repo isn't wired or the lookup
// errors — matches hasActivePasskey's fail-safe-for-a-UI-hint shape; unlike
// AuthService's enforcement copy of this check, a wrong hint here degrades
// the login page's messaging, not the auth boundary itself.
func (s *DiscoverService) isLocalAuthDisabled(ctx context.Context, tenantID uuid.UUID) bool {
	if s.featureFlagRepo == nil {
		return false
	}
	disabled, err := s.featureFlagRepo.IsEnabled(ctx, tenantID, FeatureKeyLocalAuthDisabled)
	if err != nil {
		return false
	}
	return disabled
}

// hasActivePasskey returns true when the user has at least one active
// WebAuthn credential. No-op when the WebAuthn repo isn't wired; on any
// error we return false (fail-safe — the password input still works).
func (s *DiscoverService) hasActivePasskey(ctx context.Context, userID, tenantID uuid.UUID) bool {
	if s.webauthnRepo == nil {
		return false
	}
	count, err := s.webauthnRepo.CountActiveByUser(ctx, userID, tenantID)
	if err != nil {
		return false
	}
	return count > 0
}

// hasUserPassword returns true when the user has a non-empty password hash.
// Used by Discover to surface has_password so the login UI can hide the
// password input for passkey-only / SSO-only accounts.
func hasUserPassword(user *models.User) bool {
	return user != nil && user.PasswordHash != nil && *user.PasswordHash != ""
}

// NewDiscoverService constructs a new DiscoverService.
// overrideService may be nil; it is only used by the legacy GetDiscoverResponse
// and GetLoginProviders helpers.
func NewDiscoverService(
	domainRepo DiscoverDomainRepo,
	tenantRepo DiscoverTenantRepo,
	userRepo DiscoverUserRepo,
	idpRepo DiscoverIDPRepo,
	brandingRepo DiscoverBrandingRepo,
	overrideService *IDPTenantOverrideService,
) *DiscoverService {
	return &DiscoverService{
		domainRepo:      domainRepo,
		tenantRepo:      tenantRepo,
		userRepo:        userRepo,
		idpRepo:         idpRepo,
		brandingRepo:    brandingRepo,
		overrideService: overrideService,
		// onEvict=nil — we don't need to act on TTL/LRU evictions.
		negativeCache: lru.NewLRU[string, *models.DiscoverResponse](
			discoverNegativeCacheSize, nil, discoverNegativeCacheTTL,
		),
	}
}

// Discover performs Home Realm Discovery for the given email address.
// It returns a DiscoverResponse that tells the login UI how the user should
// authenticate (password, SSO, signup, or contact_admin).
func (s *DiscoverService) Discover(ctx context.Context, req *models.DiscoverRequest) (*models.DiscoverResponse, error) {
	// Step 0 — normalise and validate the email address.
	email := strings.ToLower(strings.TrimSpace(req.Email))
	atIdx := strings.LastIndex(email, "@")
	if atIdx < 0 {
		return nil, &DiscoverError{
			Step: DiscoverStepInvalidEmail,
			Err:  fmt.Errorf("no @ sign in %q", email),
		}
	}
	domain := email[atIdx+1:]
	if domain == "" {
		return nil, &DiscoverError{
			Step: DiscoverStepInvalidEmail,
			Err:  errors.New("empty domain after @"),
		}
	}

	// Step 0b — negative-cache lookup. Only the truly-unknown
	// (no domain, no user) branch is cached: cached entries return a
	// signup response without further DB calls. The cache key is the
	// normalised email; a realm-scoped probe still hits the cache
	// because step 3 (unknown-email signup) does not depend on realm
	// (the signup destination is always a personal account in that
	// branch). Domain-claimed and known-user paths bypass the cache —
	// branding/IDP state changes for those tenants would otherwise
	// take up to TTL to propagate.
	if cached, ok := s.negativeCache.Get(email); ok && cached != nil {
		// Defensive copy so a caller mutating the response (e.g.
		// appending to AvailableProviders) doesn't poison the cached
		// value for subsequent callers.
		clone := *cached
		clone.Email = email
		return &clone, nil
	}

	// Step 1 — domain-based lookup: check whether the domain is registered to a tenant.
	entry, err := s.domainRepo.GetVerifiedByDomain(ctx, domain)
	if err != nil {
		return nil, &DiscoverError{Step: DiscoverStepDomainLookup, Err: err}
	}

	if entry != nil {
		// The domain is claimed by a tenant — route the user through that tenant's policy.
		return s.resolveForTenant(ctx, email, entry.TenantID, req.RealmID, entry.AutoEnroll)
	}

	// Step 2 — no domain match: look up the user globally by email.
	user, err := s.userRepo.GetByEmailGlobal(ctx, email)
	if err != nil {
		return nil, &DiscoverError{Step: DiscoverStepUserLookup, Err: err}
	}

	if user != nil {
		// Known user without a domain claim.  Route through the user's own tenant
		// if they are associated with one.
		//
		// Inactive users (is_active=false — typically pending email verification
		// or admin-disabled) get auth_method=contact_admin so the login UI
		// renders a "your account is not active, contact your administrator"
		// screen instead of the misleading "user not found / signup" path.
		// Doing the routing here (service layer) keeps the repository query
		// simple and gives the UI a single semantic value to switch on.
		authMethod := discoverAuthMethodPassword
		if !user.IsActive {
			authMethod = discoverAuthMethodContactAdmin
		}
		resp := &models.DiscoverResponse{
			Email:      email,
			EmailKnown: true,
			AuthMethod: authMethod,
			HasPassword: hasUserPassword(user),
			HasPasskey:  s.hasActivePasskey(ctx, user.ID, user.TenantID),
		}
		if user.TenantID != uuid.Nil {
			s.enrichWithTenant(ctx, resp, user.TenantID, req.RealmID)
		}
		return resp, nil
	}

	// Step 3 — completely unknown email: offer self-service sign-up as a personal account.
	accountType := "personal"
	resp := &models.DiscoverResponse{
		Email:         email,
		EmailKnown:    false,
		AuthMethod:    discoverAuthMethodSignup,
		SignupAllowed: true,
		AccountType:   &accountType,
	}
	// Cache a defensive copy — see the Get path above for the rationale.
	cached := *resp
	s.negativeCache.Add(email, &cached)
	return resp, nil
}

// resolveForTenant builds the discovery response when the email domain maps to a
// specific tenant.  It loads IDPs and branding, checks for SSO enforcement, and
// decides whether the user should be directed to the password form, SSO redirect,
// sign-up, or contact-admin screen.
func (s *DiscoverService) resolveForTenant(
	ctx context.Context,
	email string,
	tenantID uuid.UUID,
	realmID uuid.UUID,
	autoEnroll bool,
) (*models.DiscoverResponse, error) {
	// Load tenant details.
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, &DiscoverError{Step: DiscoverStepTenantLookup, Err: err}
	}

	// Build the skeleton of the response with tenant context.
	resp := &models.DiscoverResponse{
		Email: email,
	}
	if tenant != nil {
		tenantIDStr := tenantID.String()
		resp.TenantID = &tenantIDStr
		resp.TenantName = &tenant.Name
		slug := tenant.Slug
		resp.TenantSlug = &slug
		resp.LocalAuthDisabled = s.isLocalAuthDisabled(ctx, tenantID)
	}

	// Load enabled identity providers. Passing realmID lets the repo's
	// `scope='realm'` branch surface realm-scoped IDPs alongside the
	// tenant-scoped ones — uuid.Nil collapses to tenant-only lookup,
	// matching pre-realm behaviour.
	providers, err := s.idpRepo.GetEnabledLoginProviders(ctx, tenantID, realmID)
	if err != nil {
		// Non-fatal: log and continue without provider data.
		providers = nil
	}

	// Load branding (optional — ignore errors).
	branding, _ := s.brandingRepo.GetByTenantID(ctx, tenantID)
	if branding != nil {
		resp.Branding = toBrandingDTO(branding)
	}

	// Populate available-providers list for the login UI.
	resp.AvailableProviders = toDiscoverProviderList(providers)

	// Check whether any SSO provider is enforced (saml or oidc with Priority > 0).
	ssoProvider := findEnforcedSSO(providers)
	if ssoProvider != nil {
		idStr := ssoProvider.ID.String()
		resp.AuthMethod = discoverAuthMethodSSO
		resp.SSOProviderID = &idStr
		resp.SSOProviderType = &ssoProvider.Type
		resp.SSOProviderName = &ssoProvider.DisplayName
		return resp, nil
	}

	// No SSO enforcement — determine whether the user is known.
	user, err := s.userRepo.GetByEmailGlobal(ctx, email)
	if err != nil {
		return nil, &DiscoverError{Step: DiscoverStepUserLookup, Err: err}
	}

	if user != nil {
		resp.EmailKnown = true
		// Inactive users surface as contact_admin (see Step 2 above for
		// rationale). Tenant-domain-claimed users hit the same routing.
		resp.AuthMethod = discoverAuthMethodPassword
		if !user.IsActive {
			resp.AuthMethod = discoverAuthMethodContactAdmin
		}
		resp.HasPassword = hasUserPassword(user)
		resp.HasPasskey = s.hasActivePasskey(ctx, user.ID, user.TenantID)
		return resp, nil
	}

	// User is unknown in a domain-claimed tenant.
	if autoEnroll {
		accountType := discoverAccountTypeBusiness
		resp.AuthMethod = discoverAuthMethodSignup
		resp.SignupAllowed = true
		resp.AccountType = &accountType
	} else {
		resp.AuthMethod = discoverAuthMethodContactAdmin
		resp.SignupAllowed = false
	}
	return resp, nil
}

// enrichWithTenant loads tenant details and branding into an existing response.
// Errors are silently swallowed because enrichment is best-effort; the caller
// already has a valid AuthMethod set.
func (s *DiscoverService) enrichWithTenant(
	ctx context.Context,
	resp *models.DiscoverResponse,
	tenantID uuid.UUID,
	realmID uuid.UUID,
) {
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil || tenant == nil {
		return
	}
	idStr := tenantID.String()
	resp.TenantID = &idStr
	resp.TenantName = &tenant.Name
	slug := tenant.Slug
	resp.TenantSlug = &slug
	resp.LocalAuthDisabled = s.isLocalAuthDisabled(ctx, tenantID)

	providers, err := s.idpRepo.GetEnabledLoginProviders(ctx, tenantID, realmID)
	if err == nil {
		resp.AvailableProviders = toDiscoverProviderList(providers)
	}

	branding, _ := s.brandingRepo.GetByTenantID(ctx, tenantID)
	if branding != nil {
		resp.Branding = toBrandingDTO(branding)
	}
}

// findEnforcedSSO returns the highest-priority SAML or OIDC provider whose
// Priority > 0, or nil if no SSO enforcement is configured.
//
// LDAP is intentionally NOT considered an "enforceable SSO provider": LDAP
// authenticates the user inline through the regular password form (the
// password field is rebound against the directory at submit time), so
// there is no redirect-based "enforcement" to surface to the login UI.
// Treating LDAP as enforced would route users to a redirect URL that does
// not exist and dead-end the login. To enforce LDAP-only auth for a
// tenant, set `local_auth_disabled` at the tenant config layer — that
// removes the password form from any non-LDAP path, which is the correct
// layering for that constraint.
func findEnforcedSSO(providers []*models.IdentityProvider) *models.IdentityProvider {
	var best *models.IdentityProvider
	for _, p := range providers {
		if p.Type != discoverIDPTypeSAML && p.Type != "oidc" {
			continue
		}
		if p.Priority <= 0 {
			continue
		}
		if best == nil || p.Priority > best.Priority {
			best = p
		}
	}
	return best
}

// toDiscoverProviderList converts a slice of IdentityProvider into the public-safe
// DiscoverProvider DTOs used in the API response.  LDAP providers are excluded
// because they authenticate transparently through the password form.
func toDiscoverProviderList(providers []*models.IdentityProvider) []models.DiscoverProvider {
	out := make([]models.DiscoverProvider, 0, len(providers))
	for _, p := range providers {
		if p.Type == federationTypeLDAP {
			continue
		}
		out = append(out, models.DiscoverProvider{
			ID:          p.ID.String(),
			Type:        p.Type,
			Name:        p.Name,
			DisplayName: p.DisplayName,
		})
	}
	return out
}

// toBrandingDTO converts a TenantBranding DB model into the public DiscoverBranding DTO.
func toBrandingDTO(b *models.TenantBranding) *models.DiscoverBranding {
	return &models.DiscoverBranding{
		LogoURL:         b.LogoURL,
		PrimaryColor:    b.PrimaryColor,
		BackgroundColor: b.BackgroundColor,
		LoginTitle:      b.LoginTitle,
		LoginSubtitle:   b.LoginSubtitle,
		LoginMessage:    b.LoginMessage,
	}
}

// ─── Legacy helpers (override-service based) ─────────────────────────────────

// DiscoverProvider is the public-safe shape for a provider that appears on the
// login page.  Secrets and internal configuration are excluded.
// This type is used exclusively by the legacy GetDiscoverResponse / GetLoginProviders
// helpers below and is distinct from models.DiscoverProvider.
type DiscoverProvider struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	Name             string `json:"name"`
	DisplayName      string `json:"display_name"`
	Priority         int    `json:"priority"`
	SignupEnabled    bool   `json:"signup_enabled"`
	AssignMembership bool   `json:"assign_membership"`
}

// DiscoverOverrideResponse is the payload returned by the legacy GetDiscoverResponse helper.
type DiscoverOverrideResponse struct {
	AvailableProviders []DiscoverProvider `json:"available_providers"`
	TotalEnabled       int                `json:"total_enabled"`
}

// GetDiscoverResponse builds the discover response for a tenant using the
// override service.  Only providers whose EffectiveShowAsButton() is true appear
// in AvailableProviders; TotalEnabled reflects all enabled providers.
// Returns an error when overrideService is nil.
func (s *DiscoverService) GetDiscoverResponse(
	ctx context.Context,
	tenantID uuid.UUID,
) (*DiscoverOverrideResponse, error) {
	if s.overrideService == nil {
		return nil, fmt.Errorf("discover: GetDiscoverResponse: override service not configured")
	}

	allEnabled, err := s.overrideService.GetEnabledLoginProvidersWithOverrides(
		ctx, tenantID, false,
	)
	if err != nil {
		return nil, fmt.Errorf("discover: load providers: %w", err)
	}

	buttonProviders := make([]DiscoverProvider, 0, len(allEnabled))
	for _, combo := range allEnabled {
		if !combo.EffectiveShowAsButton() {
			continue
		}
		buttonProviders = append(buttonProviders, toOverrideDiscoverProvider(combo))
	}

	return &DiscoverOverrideResponse{
		AvailableProviders: buttonProviders,
		TotalEnabled:       len(allEnabled),
	}, nil
}

// GetLoginProviders returns all enabled providers (including those hidden from
// the login button list) for use by HRD routing and direct-link flows.
// Returns an error when overrideService is nil.
func (s *DiscoverService) GetLoginProviders(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]*models.IDPWithOverride, error) {
	if s.overrideService == nil {
		return nil, fmt.Errorf("discover: GetLoginProviders: override service not configured")
	}
	return s.overrideService.GetEnabledLoginProvidersWithOverrides(
		ctx, tenantID, false,
	)
}

// toOverrideDiscoverProvider converts an IDPWithOverride composite into the
// public-safe DiscoverProvider DTO used by the legacy override-based helpers.
func toOverrideDiscoverProvider(combo *models.IDPWithOverride) DiscoverProvider {
	return DiscoverProvider{
		ID:               combo.Provider.ID.String(),
		Type:             combo.Provider.Type,
		Name:             combo.Provider.Name,
		DisplayName:      combo.EffectiveDisplayName(),
		Priority:         combo.EffectivePriority(),
		SignupEnabled:    combo.EffectiveSignupEnabled(),
		AssignMembership: combo.EffectiveAssignMembership(),
	}
}
