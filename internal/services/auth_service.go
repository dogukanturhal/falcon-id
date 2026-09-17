// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/metrics"
	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/clientctx"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
	"go.uber.org/zap"
)

// AuthService is an exported type.
type AuthService struct {
	config            *config.Config
	userRepo          *repositories.UserRepository
	roleRepo          *repositories.RoleRepository
	sessionRepo       *repositories.SessionRepository
	tokenRepo         *repositories.TokenRepository
	tenantRepo        *repositories.TenantRepository
	tokenService      *TokenService
	auditService      *AuditService
	ldapService       *LDAPService
	mfaService        *MFAService
	mfaEnrollmentSvc  *MFAEnrollmentService
	riskService       *RiskService
	deviceService     *DeviceService
	groupService      *GroupService
	sessionCache      *redis.SessionCache
	appAccessService  *AppAccessService
	loginDiscoverer   loginDiscoverer
	backchannelLogout *BackchannelLogoutService
	// breachChecker is optional. When set, ChangePassword rejects a new
	// password found in the HIBP breach corpus (ASVS V6 / NIST 800-63B).
	// nil-safe: unwired short-circuits to the pre-check behaviour.
	breachChecker breachChecker
	// caepEmitter is the OpenID CAEP 1.0 / SSF 1.0 transmitter (real
	// implementation of SSFEventEmitter — Phase 2 supersedes
	// NoOpSSFEmitter once cmd/services.go wires the real emitter).
	// Optional; nil keeps the legacy "no CAEP transmission" behaviour
	// so deployments without a registered receiver stream don't pay
	// any cost on logout.
	caepEmitter *CAEPEmitter
	// featureFlagRepo and webAuthnRepo are read-only dependencies used by the
	// admin-passkey-required interrupt path (see createPasskeyEnrollmentInterrupt).
	// Both are optional — when either is nil the check short-circuits and
	// behaviour is identical to pre-task-5b.
	featureFlagRepo featureFlagChecker
	webAuthnRepo    *repositories.WebAuthnRepository

	// caeService is optional. When set, ChangePassword and password-
	// reset flows publish CAEPasswordChanged events so receivers
	// (Talon IAP, SSE subscribers) revoke active sessions immediately
	// instead of waiting for the next token refresh. Wired in
	// cmd/services.go alongside the other CAE publish-sites; nil-safe.
	caeService *CAEService

	// realmRepo is optional. When set, the MFA enrollment interrupt
	// path honors RealmSecurityPolicy.MFAGracePeriodDays + MFAEnrollmentMaxSkips
	// — stamping per-user deadline/skip state on first prompt and gating
	// the "Remind me later" skip endpoint. When nil (test harness, boot
	// before realm-repo wiring), grace evaluation short-circuits to the
	// pre-grace hard-block behaviour and login proceeds exactly as it
	// did before migration 235. Set via SetRealmRepository from
	// cmd/services.go after the repository is constructed.
	realmRepo *repositories.RealmRepository

	// webAuthnService is optional. When set, the WebAuthn-as-MFA path
	// (POST /api/v1/auth/mfa/webauthn/{begin,finish}) is active.
	// Required when the deployment expects passkey-only users to be
	// able to complete an MFA challenge after password sign-in
	// (canonical Microsoft Entra / Auth0 / Okta UX). Nil-safe — when
	// unset, BeginWebAuthnMFA / CompleteWebAuthnMFA return an error
	// and getAvailableMFAMethods callers fall back to code-only flows.
	webAuthnService *WebAuthnService

	// securityNotifier sends user-facing emails on security events
	// (password changed, account locked, suspicious login, factor
	// removed). Phase C, 2026-05-26. Nil-safe — DB writes + CAE
	// emission remain authoritative when unset.
	securityNotifier *SecurityNotificationService
}

// SetCAEService wires the CAEP publisher into AuthService. Safe to
// call with nil (disables publish; DB-layer session revocation in
// ChangePassword still holds, only the real-time fan-out degrades).
func (s *AuthService) SetCAEService(svc *CAEService) {
	s.caeService = svc
}

// SetRealmRepository wires the realm repository into AuthService for
// the MFA enrollment grace-period logic (migration 235). Safe to call
// with nil (disables grace evaluation; pre-grace hard-block behaviour
// is preserved). Idempotent.
func (s *AuthService) SetRealmRepository(repo *repositories.RealmRepository) {
	s.realmRepo = repo
}

// SetWebAuthnService wires the WebAuthn assertion service into
// AuthService so the WebAuthn-as-MFA path (BeginWebAuthnMFA /
// CompleteWebAuthnMFA) can issue + verify ceremonies bound to the
// temp MFA session. Nil-safe — when unset, those methods return an
// error and the code-based MFA paths remain the only options.
func (s *AuthService) SetWebAuthnService(svc *WebAuthnService) {
	s.webAuthnService = svc
}

// SetSecurityNotificationService wires the user-facing email notifier
// for security events (Phase C). Nil-safe.
func (s *AuthService) SetSecurityNotificationService(svc *SecurityNotificationService) {
	s.securityNotifier = svc
}

// tenantSlugRegex defines the valid pattern for tenant slugs
// SECURITY: Only lowercase alphanumeric characters and hyphens allowed
// Must start and end with alphanumeric character
// This prevents SQL injection and path traversal attacks
var tenantSlugRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

const (
	federationTypeLDAP = "ldap"
	roleNameAdmin      = "admin"
	authMethodEmail    = "email"
	authMethodTOTP     = "totp"
	// authMethodWebAuthn covers the FIDO2 / WebAuthn / passkey factor.
	// Aligned with the existing MFAEnrollmentWebAuthnBegin / Finish
	// handlers (cmd/routes.go line ~534) which already support
	// registration-interrupt passkey enrollment via the enrollment_token.
	// Surface this as an offered method in createMFAEnrollmentInterrupt
	// so the frontend can present it as the recommended (phishing-
	// resistant per NIST SP 800-63B-4 AAL3 + WebAuthn Level 3) option.
	authMethodWebAuthn = "webauthn"
	authMethodUnknown  = "unknown"
)

// NewAuthService is an exported function.
func NewAuthService(
	cfg *config.Config,
	userRepo *repositories.UserRepository,
	roleRepo *repositories.RoleRepository,
	sessionRepo *repositories.SessionRepository,
	tokenRepo *repositories.TokenRepository,
	tokenService *TokenService,
	auditService *AuditService,
	ldapService *LDAPService,
) *AuthService {
	return &AuthService{
		config:       cfg,
		userRepo:     userRepo,
		roleRepo:     roleRepo,
		sessionRepo:  sessionRepo,
		tokenRepo:    tokenRepo,
		tokenService: tokenService,
		auditService: auditService,
		ldapService:  ldapService,
	}
}

// SetMFAService sets the MFA service (called after initialization to avoid circular deps)
func (s *AuthService) SetMFAService(mfaService *MFAService) {
	s.mfaService = mfaService
}

// SetMFAEnrollmentService wires the registration-interrupt enrollment service.
// Required when risk-based MFA is enabled — without it, an unenrolled user
// crossing the risk threshold has no remediation path and locks themselves out.
func (s *AuthService) SetMFAEnrollmentService(svc *MFAEnrollmentService) {
	s.mfaEnrollmentSvc = svc
}

// SetRiskService sets the risk service (called after initialization to avoid circular deps)
func (s *AuthService) SetRiskService(riskService *RiskService) {
	s.riskService = riskService
}

// SetDeviceService sets the device service (called after initialization to avoid circular deps)
func (s *AuthService) SetDeviceService(deviceService *DeviceService) {
	s.deviceService = deviceService
}

// SetGroupService sets the group service (called after initialization to avoid circular deps)
func (s *AuthService) SetGroupService(groupService *GroupService) {
	s.groupService = groupService
}

// SetCAEPEmitter wires the OpenID CAEP 1.0 transmitter into AuthService.
// When set, every Logout fans out a CAEP `session-revoked` SET to all
// subscribed streams for the tenant. Best-effort + asynchronous —
// mirrors the back-channel logout fan-out pattern (separate goroutine,
// dropped errors logged via the emitter's own logger).
func (s *AuthService) SetCAEPEmitter(em *CAEPEmitter) {
	s.caepEmitter = em
}

// SetBreachChecker wires the HIBP breach-password check (ASVS V6 / NIST
// 800-63B) into ChangePassword. Optional + nil-safe.
func (s *AuthService) SetBreachChecker(c breachChecker) {
	s.breachChecker = c
}

// SetBackchannelLogout wires the back-channel logout service into AuthService.
// When set, the service will fan-out logout tokens to registered RPs after each
// successful logout. The call is best-effort and runs in a background goroutine.
func (s *AuthService) SetBackchannelLogout(svc *BackchannelLogoutService) {
	s.backchannelLogout = svc
}

// SetSessionCache sets the Redis session cache for fast session lookups
func (s *AuthService) SetSessionCache(cache *redis.SessionCache) {
	s.sessionCache = cache
}

// SetTenantRepository sets the tenant repository for tenant slug resolution
func (s *AuthService) SetTenantRepository(tenantRepo *repositories.TenantRepository) {
	s.tenantRepo = tenantRepo
}

// SetAppAccessService sets the app access service for per-app role filtering and audience scoping
func (s *AuthService) SetAppAccessService(appAccessService *AppAccessService) {
	s.appAccessService = appAccessService
}

// featureFlagChecker is the narrow interface AuthService needs from the
// feature-flag store: per-tenant policy gates like require_passkey_for_admin
// (see createPasskeyEnrollmentInterrupt) and local_auth_disabled (t-431's
// SSO-only login gate, see enforceLocalAuthAllowed). Declared as an
// interface rather than the concrete *repositories.FeatureFlagRepository so
// tests can substitute a fake without a real Postgres — mirrors
// loginDiscoverer below. *repositories.FeatureFlagRepository satisfies it
// structurally; production wiring is unchanged.
type featureFlagChecker interface {
	IsEnabled(ctx context.Context, tenantID uuid.UUID, featureKey string) (bool, error)
}

// SetFeatureFlagRepository wires the feature-flag repo so AuthService can
// read tenant-level policy flags like require_passkey_for_admin and
// local_auth_disabled. Optional — when entirely unwired (nil), both gates
// evaluate as inactive, matching every other optional dependency in this
// file (the feature simply isn't deployed yet). Once wired, a *query*
// error on the local_auth_disabled check fails CLOSED (rejects login)
// rather than falling back to "inactive" — c-265: an auth-boundary gate
// that IS deployed must not silently stand down when it can't confirm
// policy. See enforceLocalAuthAllowed.
func (s *AuthService) SetFeatureFlagRepository(repo *repositories.FeatureFlagRepository) {
	s.featureFlagRepo = repo
}

// SetWebAuthnRepository wires the WebAuthn credential repository so
// AuthService can check whether a user has any active passkey before
// deciding to issue an admin-passkey-required interrupt. Optional — when
// unset, the policy gate evaluates as if the user had no passkey, which
// would block all admin logins; production wiring sets it.
func (s *AuthService) SetWebAuthnRepository(repo *repositories.WebAuthnRepository) {
	s.webAuthnRepo = repo
}

// loginDiscoverer is the narrow interface for Home Realm Discovery during login.
// When set, the login flow can resolve tenant context from an email address
// without requiring an explicit tenant_slug or tenant_id.
type loginDiscoverer interface {
	Discover(ctx context.Context, req *models.DiscoverRequest) (*models.DiscoverResponse, error)
}

// SetLoginDiscoverer wires the HRD discoverer for email-based tenant resolution.
// When set, users can log in with just an email address (no tenant_slug required).
func (s *AuthService) SetLoginDiscoverer(discoverer loginDiscoverer) {
	s.loginDiscoverer = discoverer
}

// Validate checks that all non-optional dependencies are non-nil.
// Call this from cmd/services.go after all Set* methods have been invoked to
// catch wiring mistakes at startup rather than at runtime.
func (s *AuthService) Validate() error {
	if s.config == nil {
		return fmt.Errorf("AuthService.Validate: config is nil")
	}
	if s.userRepo == nil {
		return fmt.Errorf("AuthService.Validate: userRepo is nil")
	}
	if s.roleRepo == nil {
		return fmt.Errorf("AuthService.Validate: roleRepo is nil")
	}
	if s.sessionRepo == nil {
		return fmt.Errorf("AuthService.Validate: sessionRepo is nil")
	}
	if s.tokenRepo == nil {
		return fmt.Errorf("AuthService.Validate: tokenRepo is nil")
	}
	if s.tokenService == nil {
		return fmt.Errorf("AuthService.Validate: tokenService is nil")
	}
	if s.auditService == nil {
		return fmt.Errorf("AuthService.Validate: auditService is nil")
	}
	return nil
}

// validateTenantSlug validates that a tenant slug meets security requirements
// SECURITY: This prevents SQL injection, path traversal, and other attacks
// Requirements:
// - Only lowercase alphanumeric characters and hyphens
// - Must start and end with alphanumeric character
// - Length between 1 and 63 characters (DNS label length limit)
// - No consecutive hyphens (prevents --- injection patterns)
func validateTenantSlug(slug string) error {
	// Check length constraints
	if len(slug) < 1 {
		return fmt.Errorf("tenant slug cannot be empty")
	}
	if len(slug) > 63 {
		return fmt.Errorf("tenant slug must be at most 63 characters (got %d)", len(slug))
	}

	// Validate format using regex
	if !tenantSlugRegex.MatchString(slug) {
		return fmt.Errorf("tenant slug must contain only lowercase letters, numbers, and hyphens, and must start and end with a letter or number")
	}

	// Additional check: no consecutive hyphens (prevents injection patterns like '--')
	if strings.Contains(slug, "--") {
		return fmt.Errorf("tenant slug cannot contain consecutive hyphens")
	}

	// Prevent reserved/dangerous slugs
	reservedSlugs := []string{
		"admin", "api", "www", "mail", "ftp", "localhost",
		"test", "demo", "staging", "prod", "production",
		"system", "root", "user", "public", "private",
		"internal", "external", "default",
		// track.<apex> is the click-tracking host (see apps/mearax's
		// apex-domains config) — a tenant slug must never collide with it.
		"track",
	}
	for _, reserved := range reservedSlugs {
		if slug == reserved {
			return fmt.Errorf("tenant slug '%s' is reserved", reserved)
		}
	}

	return nil
}

// tenantContext holds resolved tenant information
type tenantContext struct {
	TenantID   uuid.UUID
	TenantSlug string
	RealmID    uuid.UUID
	RealmSlug  string
	RealmType  string
}

// Login authenticates a user with username/password
func (s *AuthService) Login(ctx context.Context, req *models.LoginRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// 1. Resolve tenant context
	tenantCtx, err := s.resolveTenantContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant context: %w", err)
	}

	// 2. Authenticate credentials
	user, err := s.authenticateCredentials(ctx, tenantCtx.TenantID, req, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("authenticate credentials: %w", err)
	}

	// 3. Check user status (active/locked)
	if err := s.checkUserStatus(ctx, tenantCtx.TenantID, user, req.Username, ipAddress, userAgent); err != nil {
		return nil, fmt.Errorf("check user status: %w", err)
	}

	// 3b. SSO-only tenant gate (t-431, d-169): local_auth_disabled rejects
	// this login even though the password just verified correct. Placed
	// AFTER authenticateCredentials/checkUserStatus specifically so it
	// never touches authenticateLocal's constant-time comparison path
	// (dummyPasswordHash) or introduces a second place that resolves a
	// user by username — the credential check above already did both, and
	// the resolved *models.User is exactly what Q3's admin-review flag
	// needs (a real user with a real password_hash, not a guess).
	if err := s.enforceLocalAuthAllowed(ctx, tenantCtx, user, ipAddress, userAgent); err != nil {
		return nil, fmt.Errorf("local auth policy: %w", err)
	}

	// 4. Assess login risk
	riskAssessment, isNewDevice, err := s.assessLoginRisk(ctx, tenantCtx.TenantID, user, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("assess login risk: %w", err)
	}

	// 5. Handle MFA challenge if required.
	// Source-of-truth factor check: a user with any active factor
	// (TOTP, email, WebAuthn passkey, or push device) is MFA-enrolled.
	// We do NOT trust the denormalized iam_users.mfa_enabled flag here
	// because historical writes (DisableMFA prior to 2026-05-12, the
	// universal-flag fix in 61b4a3a, etc.) could leave it diverged from
	// reality. Companion to the OAuth /authorize ACR step-up gate which
	// was migrated to the same source-of-truth check.
	hasFactor, factorErr := s.userRepo.HasAnyMFAFactor(ctx, user.ID)
	if factorErr != nil {
		return nil, fmt.Errorf("check user MFA factor inventory: %w", factorErr)
	}
	mfaRequired := hasFactor || (riskAssessment != nil && riskAssessment.RequiresMFA)
	if mfaRequired && req.MFACode == "" {
		return s.createMFAChallenge(ctx, tenantCtx, user, req, ipAddress, userAgent, isNewDevice, riskAssessment, hasFactor)
	}

	// 6. Verify MFA code if provided
	if mfaRequired && req.MFACode != "" {
		if err := s.handleMFAChallenge(ctx, tenantCtx.TenantID, user, req, ipAddress, userAgent); err != nil {
			return nil, fmt.Errorf("handle MFA challenge: %w", err)
		}
	}

	// 7. Get user roles and permissions
	roleNames, roles, permNames, permissions, err := s.getUserRolesAndPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get user roles and permissions: %w", err)
	}

	// 7b. App access control: filter roles/permissions by application if client_id is provided
	var appClientID string
	if req.ClientID != "" && s.appAccessService != nil {
		oauthClient, filteredRoles, filteredPerms, appErr := s.appAccessService.ValidateAppAccess(
			ctx, user.ID, tenantCtx.TenantID, req.ClientID, roleNames, permNames,
		)
		if appErr != nil {
			s.auditService.LogLogin(ctx, tenantCtx.TenantID, &user.ID, ipAddress, userAgent, false, appErr.Error())
			return nil, fmt.Errorf("app access denied: %w", appErr)
		}
		roleNames = filteredRoles
		permNames = filteredPerms
		appClientID = oauthClient.ClientID
	}

	// 7c. Admin-passkey-required policy gate. Tenants that flip the
	//     `require_passkey_for_admin` feature flag force any user with an
	//     admin role to authenticate with a FIDO2 passkey before a session
	//     is issued. Users without an active passkey are routed to the
	//     registration-interrupt path with EnrollmentMethods=["webauthn"];
	//     users WITH a passkey continue through this code path (the actual
	//     passkey login enters via /auth/webauthn/login/finish, not /login,
	//     so reaching here without one means a non-passkey login attempt
	//     for an admin on a tier-1 tenant — exactly the case to interrupt).
	if interrupt, err := s.maybePasskeyEnrollmentInterrupt(ctx, tenantCtx, user, req, ipAddress, userAgent, isNewDevice, riskAssessment, roleNames); err != nil {
		return nil, fmt.Errorf("admin passkey gate: %w", err)
	} else if interrupt != nil {
		return interrupt, nil
	}

	// 8. Create session with invalidation
	// RFC 8176: password-only login records `pwd`. An MFA challenge converts this
	// to a distinct CompleteMFALogin flow which records `pwd` + `mfa`.
	// req.RememberMe bifurcates the iam_sessions.expires_at horizon (see
	// sessionTTLForLogin) — false → short TTL (existing behaviour),
	// true → SessionTTLRememberMe (default 30d). The same flag flows
	// down to the cookie Max-Age via response.IsRememberMeSession so
	// DB row + browser cookie expire in lock-step.
	session, err := s.createSessionWithInvalidation(ctx, user.ID, ipAddress, userAgent, []string{"pwd"}, req.RememberMe)
	if err != nil {
		return nil, fmt.Errorf("create session with invalidation: %w", err)
	}

	// 9. Handle device trust (Remember Me)
	isTrustedDevice := s.handleDeviceTrust(ctx, user.ID, req, userAgent, ipAddress)

	// Audit the rememberMe flag so security review can identify which
	// sessions are long-lived. Stamps `details.remember_me = bool` on
	// the iam_audit_log row keyed by the new session_id. Best-effort —
	// audit write failures never break login (the audit service logs
	// internally and returns void).
	if s.auditService != nil {
		s.auditService.LogLoginRememberMe(ctx, tenantCtx.TenantID, user.ID, session.ID, req.RememberMe, ipAddress, userAgent)
	}

	// 10. Generate access token (refresh-token issuance removed Phase 3).
	accessToken, err := s.generateAccessToken(ctx, user, session.ID, roleNames, permNames, appClientID)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 11. Update user login info
	// Save PII before update (which encrypts the user struct in-place)
	savedEmail := user.Email
	savedFirstName := user.FirstName
	savedLastName := user.LastName
	savedDisplayName := user.DisplayName
	savedPhone := user.Phone
	if err := s.updateUserLoginInfo(ctx, user, ipAddress); err != nil {
		logger.Error("Failed to update user login info", zap.Error(err))
	}
	// Restore decrypted PII for the response
	user.Email = savedEmail
	user.FirstName = savedFirstName
	user.LastName = savedLastName
	user.DisplayName = savedDisplayName
	user.Phone = savedPhone

	// 12. Build login response
	resp, err := s.buildLoginResponse(ctx, tenantCtx, user, roles, permissions, accessToken, isTrustedDevice, isNewDevice, riskAssessment)
	if err != nil {
		return nil, err
	}
	// Stamp the rememberMe outcome so the HTTP handler can mirror it
	// onto the falcon_idp_session cookie's Max-Age — keeps cookie
	// horizon aligned with the iam_sessions.expires_at horizon set
	// inside createSession.
	resp.IsRememberMeSession = req.RememberMe
	return resp, nil
}

// resolveTenantContext resolves tenant and realm from request
func (s *AuthService) resolveTenantContext(ctx context.Context, req *models.LoginRequest) (*tenantContext, error) {
	tenantCtx := &tenantContext{}
	var err error

	switch {
	case req.TenantSlug != "" && s.tenantRepo != nil:
		// SECURITY: Validate tenant slug before database query
		if err := validateTenantSlug(req.TenantSlug); err != nil {
			logger.Warn("Invalid tenant slug format",
				zap.String("slug", req.TenantSlug),
				zap.Error(err),
			)
			return nil, fmt.Errorf("invalid tenant")
		}

		tenant, err := s.tenantRepo.GetBySlug(ctx, req.TenantSlug)
		if err != nil {
			logger.Warn("Failed to resolve tenant by slug", zap.String("slug", req.TenantSlug), zap.Error(err))
			return nil, fmt.Errorf("invalid tenant")
		}
		tenantCtx.TenantID = tenant.ID
		tenantCtx.TenantSlug = tenant.Slug
	case req.TenantID != "":
		tenantCtx.TenantID, err = uuid.Parse(req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("invalid tenant ID")
		}
		if s.tenantRepo != nil {
			if tenant, err := s.tenantRepo.GetByID(ctx, tenantCtx.TenantID); err == nil && tenant != nil {
				tenantCtx.TenantSlug = tenant.Slug
			}
		}
	case s.loginDiscoverer != nil && strings.Contains(req.Username, "@"):
		// HRD: resolve tenant from email domain
		discoverResp, discoverErr := s.loginDiscoverer.Discover(ctx, &models.DiscoverRequest{
			Email: req.Username,
		})
		if discoverErr != nil {
			return nil, fmt.Errorf("tenant context required - specify tenant_id or tenant_slug")
		}

		// SSO enforcement: if the domain requires SSO, reject password login
		if discoverResp.AuthMethod == "sso" {
			return nil, fmt.Errorf("SSO authentication required for this domain")
		}

		// Must have resolved a tenant
		if discoverResp.TenantID == nil {
			return nil, fmt.Errorf("tenant context required - no tenant found for email domain")
		}

		tenantCtx.TenantID, err = uuid.Parse(*discoverResp.TenantID)
		if err != nil {
			return nil, fmt.Errorf("invalid tenant ID from discovery")
		}
		if discoverResp.TenantSlug != nil {
			tenantCtx.TenantSlug = *discoverResp.TenantSlug
		}
	default:
		return nil, fmt.Errorf("tenant context required - specify tenant_id or tenant_slug")
	}

	// Parse realm ID (optional)
	if req.RealmID != "" {
		if strings.HasPrefix(req.RealmID, "slug:") {
			tenantCtx.RealmSlug = strings.TrimPrefix(req.RealmID, "slug:")
		} else {
			tenantCtx.RealmID, err = uuid.Parse(req.RealmID)
			if err != nil {
				return nil, fmt.Errorf("invalid realm ID")
			}
		}
	}

	return tenantCtx, nil
}

// authenticateCredentials validates username and password
func (s *AuthService) authenticateCredentials(ctx context.Context, tenantID uuid.UUID, req *models.LoginRequest, ipAddress, userAgent string) (*models.User, error) {
	user, err := s.authenticateLocal(ctx, tenantID, req.Username, req.Password)
	if err != nil {
		errMsg := err.Error()
		if errMsg == "user should authenticate via LDAP" || errMsg == "user not found" {
			user, err = s.authenticateLDAP(ctx, tenantID, req.Username, req.Password)
			if err != nil {
				s.auditService.LogLogin(ctx, tenantID, nil, ipAddress, userAgent, false, err.Error())
				return nil, fmt.Errorf("authentication failed: %w", err)
			}
		} else {
			s.auditService.LogLogin(ctx, tenantID, nil, ipAddress, userAgent, false, err.Error())
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}
	return user, nil
}

// checkUserStatus checks if user is active and not locked
func (s *AuthService) checkUserStatus(ctx context.Context, tenantID uuid.UUID, user *models.User, username, ipAddress, userAgent string) error {
	if !user.IsActive {
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "account disabled")
		logger.SecurityAudit.Warn("Security audit: login denied - account disabled",
			zap.String("event", "auth.login.failed"),
			zap.String("username", username),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.String("reason", "account_disabled"),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return fmt.Errorf("account is disabled")
	}

	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			if err := s.userRepo.UnlockUser(ctx, user.ID); err != nil {
				logger.Error("Failed to unlock user", zap.Error(err))
			}
			user.IsLocked = false
		} else {
			s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "account locked")
			logger.SecurityAudit.Warn("Security audit: login denied - account locked",
				zap.String("event", "auth.login.failed"),
				zap.String("username", username),
				zap.String("user_id", user.ID.String()),
				zap.String("ip", ipAddress),
				zap.String("reason", "account_locked"),
				zap.Time("timestamp", time.Now().UTC()),
			)
			// Typed error so the handler can surface a discriminated
			// response (`error: "account_locked"` + locked_until +
			// lock_reason) instead of the generic "invalid credentials"
			// toast that led to user confusion ("I keep typing the
			// right password and it keeps failing"). Live audit
			// 2026-05-25 flagged this as a P0 procurement-blocker UX
			// gap: users locked out by failed-attempt threshold had
			// no signal as to WHY login kept failing.
			return &AccountLockedError{
				LockedUntil: user.LockedUntil,
				LockReason:  user.LockReason,
			}
		}
	}

	return nil
}

// assessLoginRisk performs risk assessment with device checks
func (s *AuthService) assessLoginRisk(ctx context.Context, tenantID uuid.UUID, user *models.User, ipAddress, userAgent string) (*models.RiskAssessment, bool, error) {
	if s.riskService == nil || s.deviceService == nil {
		return nil, false, nil
	}

	isNewDevice, deviceErr := s.checkDeviceStatus(ctx, user.ID, userAgent, ipAddress)
	if deviceErr != nil {
		logger.Warn("Device status check failed, proceeding with default", zap.Error(deviceErr))
	}

	riskCtx := s.buildRiskContext(ctx, tenantID, user, ipAddress, userAgent, isNewDevice)

	riskAssessment, err := s.riskService.AssessLoginRisk(ctx, riskCtx)
	if err != nil {
		logger.Error("Failed to assess login risk", zap.Error(err))
		return nil, isNewDevice, nil
	}

	// Persist a per-login rollup row to iam_login_risk_events. The outcome
	// classification is the same one the Login flow will follow downstream:
	// blocked → fail; user-MFA-or-risk-MFA → MFA challenge; else → allowed.
	// Errors here are non-fatal — the login flow doesn't depend on event-log
	// writes succeeding (the table is for audit/SIEM, not auth correctness).
	s.recordLoginRiskEvent(ctx, riskAssessment, riskCtx, user)

	if riskAssessment.Blocked {
		return nil, isNewDevice, fmt.Errorf("login blocked: %s", riskAssessment.BlockReason)
	}

	s.applyRiskDelay(ctx, riskAssessment)
	s.logRiskAssessment(user.ID, riskAssessment, isNewDevice)

	return riskAssessment, isNewDevice, nil
}

// recordLoginRiskEvent classifies the outcome and asks the risk service to
// persist it. Best-effort — write failures are logged but never propagated.
func (s *AuthService) recordLoginRiskEvent(
	ctx context.Context,
	assessment *models.RiskAssessment,
	riskCtx *models.RiskContext,
	user *models.User,
) {
	outcome := models.LoginRiskOutcomeAllowed
	mfaTrigger := ""
	switch {
	case assessment.Blocked:
		outcome = models.LoginRiskOutcomeBlocked
	case assessment.RequiresMFA:
		outcome = models.LoginRiskOutcomeMFAChallenged
		// Distinguish policy-driven MFA from level-default MFA so the audit
		// row tells operators which lever fired.
		mfaTrigger = models.MFATriggerRiskPolicy
		for _, action := range assessment.Actions {
			if action.Type == "require_mfa" && action.PolicyID != "" {
				mfaTrigger = models.MFATriggerRiskPolicy
				break
			}
		}
		// Override with default-MFA trigger when no policy set Actions but
		// level still gated MFA.
		hasPolicyMFA := false
		for _, action := range assessment.Actions {
			if action.Type == "require_mfa" {
				hasPolicyMFA = true
				break
			}
		}
		if !hasPolicyMFA {
			switch assessment.Level {
			case models.RiskLevelHigh, models.RiskLevelCritical:
				mfaTrigger = models.MFATriggerRiskDefaultHigh
			case models.RiskLevelMedium:
				mfaTrigger = models.MFATriggerRiskDefaultMedium
			}
		}
	case user.MFAEnabled:
		outcome = models.LoginRiskOutcomeMFAChallenged
		mfaTrigger = models.MFATriggerUserEnrolled
	}

	if err := s.riskService.RecordLoginEvent(ctx, assessment, riskCtx, outcome, mfaTrigger); err != nil {
		logger.Warn("Failed to record login risk event",
			zap.String("user_id", riskCtx.UserID.String()),
			zap.String("outcome", outcome),
			zap.Error(err),
		)
	}
}

// checkDeviceStatus checks if device is new
func (s *AuthService) checkDeviceStatus(ctx context.Context, userID uuid.UUID, userAgent, ipAddress string) (bool, error) {
	isNewDevice, _, err := s.deviceService.CheckDeviceIsNew(ctx, userID, userAgent, ipAddress)
	if err != nil {
		logger.Error("Failed to check device", zap.Error(err))
	}
	return isNewDevice, err
}

// buildRiskContext creates risk context from user and login data.
// Reads Location from ctx (stamped by the handler via
// middleware.WithClientCountry) so the per-attempt audit row in
// iam_login_risk_events captures the originating country alongside the
// IP / user-agent. Empty when CF-IPCountry was missing or untrusted.
func (s *AuthService) buildRiskContext(ctx context.Context, tenantID uuid.UUID, user *models.User, ipAddress, userAgent string, isNewDevice bool) *models.RiskContext {
	riskCtx := &models.RiskContext{
		UserID:      user.ID,
		TenantID:    tenantID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Location:    clientctx.CountryFromContext(ctx),
		LoginTime:   time.Now(),
		IsNewDevice: isNewDevice,
	}

	if user.LastLoginIP != nil {
		riskCtx.LastLoginIP = user.LastLoginIP
	}
	if user.LastLoginAt != nil {
		riskCtx.LastLoginTime = user.LastLoginAt
	}

	return riskCtx
}

// applyRiskDelay applies delay if configured by risk policy.
// It respects context cancellation so the goroutine is released if the client disconnects.
func (s *AuthService) applyRiskDelay(ctx context.Context, riskAssessment *models.RiskAssessment) {
	if riskAssessment.DelaySeconds > 0 {
		logger.Info("Applying login delay due to risk policy",
			zap.Int("delay_seconds", riskAssessment.DelaySeconds),
		)
		select {
		case <-time.After(time.Duration(riskAssessment.DelaySeconds) * time.Second):
		case <-ctx.Done():
		}
	}
}

// logRiskAssessment logs risk assessment results
func (s *AuthService) logRiskAssessment(userID uuid.UUID, riskAssessment *models.RiskAssessment, isNewDevice bool) {
	logger.Info("Risk assessment completed",
		zap.String("user_id", userID.String()),
		zap.Int("risk_score", riskAssessment.TotalScore),
		zap.String("risk_level", string(riskAssessment.Level)),
		zap.Bool("requires_mfa", riskAssessment.RequiresMFA),
		zap.Bool("is_new_device", isNewDevice),
	)
}

// handleMFAChallenge verifies MFA code during login
func (s *AuthService) handleMFAChallenge(ctx context.Context, tenantID uuid.UUID, user *models.User, req *models.LoginRequest, ipAddress, userAgent string) error {
	if !s.verifyMFACode(ctx, user, req.MFACode) {
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "invalid MFA code")
		mfaMethod := authMethodUnknown
		if user.MFAType != nil {
			mfaMethod = *user.MFAType
		}
		logger.SecurityAudit.Warn("Security audit: MFA code verification failed during login",
			zap.String("event", "auth.mfa.failed"),
			zap.String("username", req.Username),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.String("method", mfaMethod),
			zap.String("reason", "invalid_mfa_code"),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return fmt.Errorf("invalid MFA code")
	}
	return nil
}

// createMFAChallenge creates the MFA challenge response when an MFA code is
// required but not yet provided.
//
// Two distinct outcomes:
//
//  1. user.MFAEnabled — issue a normal challenge (email-MFA code, TOTP prompt,
//     etc.) keyed on a 5-minute mfa:session: cache entry; the client then
//     POSTs to /api/v1/auth/mfa/complete to finish login.
//
//  2. !user.MFAEnabled but riskAssessment.RequiresMFA — fork to the
//     registration-interrupt path: do NOT send a code (the destination
//     mailbox isn't a bound authenticator and emailing it would create a
//     phishing surface), instead mint an enrollment_token and return a
//     RequiresMFAEnrollment response. The unauthenticated enrollment UI
//     then drives the user through TOTP or email enrollment via
//     /api/v1/auth/mfa/enrollment/{init,verify}, on success of which a
//     normal session is issued. NIST SP 800-63B-4 §5.1; matches Microsoft
//     Entra ID Protection / Okta enrollment policies / Auth0 Require MFA
//     Enrollment / Keycloak Required Actions (CONFIGURE_TOTP).
func (s *AuthService) createMFAChallenge(ctx context.Context, tenantCtx *tenantContext, user *models.User, req *models.LoginRequest, ipAddress, userAgent string, isNewDevice bool, riskAssessment *models.RiskAssessment, hasFactor bool) (*models.LoginResponse, error) {
	riskMFARequired := riskAssessment != nil && riskAssessment.RequiresMFA

	// Routing on hasFactor (source-of-truth) rather than user.MFAEnabled
	// (denormalized). A user with mfa_enabled=true but zero actual
	// factors (drift state — see auth_service.go:309 comment) was
	// previously routed to the normal-challenge path here, which then
	// failed in determineMFAMethod with no available methods. The
	// enrollment-interrupt path is the correct response.
	if !hasFactor && riskMFARequired {
		return s.createMFAEnrollmentInterrupt(ctx, tenantCtx, user, req, ipAddress, userAgent, isNewDevice, riskAssessment)
	}

	// Source-of-truth passkey check — determines whether the user has
	// an active WebAuthn credential we can challenge against during
	// MFA. Separate from HasAnyMFAFactor (used for the outer mfa-
	// required decision) so getAvailableMFAMethods can know
	// specifically about passkeys without re-scanning every factor
	// table. Errors silently degrade to "no passkey" — the user
	// retains TOTP / email options if those are enabled.
	hasPasskey := false
	if s.userRepo != nil {
		if has, err := s.userRepo.HasActiveWebAuthnCredential(ctx, user.ID); err == nil {
			hasPasskey = has
		}
	}

	mfaMethod, availableMethods := s.determineMFAMethod(user, req.PreferredMFAMethod, riskMFARequired, hasFactor, hasPasskey)

	if mfaMethod == authMethodEmail && s.mfaService != nil {
		if err := s.mfaService.SendEmailMFACode(ctx, user.ID); err != nil {
			logger.Error("Failed to send MFA email code", zap.Error(err))
		}
	}

	tempSessionID := s.storeMFASession(ctx, tenantCtx, user, ipAddress, userAgent, req.ClientID)

	s.logMFAChallenge(user.ID, mfaMethod, availableMethods, false)

	return s.buildMFAChallengeResponse(mfaMethod, availableMethods, tempSessionID, isNewDevice, riskAssessment), nil
}

// createMFAEnrollmentInterrupt mints an enrollment_token, audit-logs the
// interrupt, and returns the RequiresMFAEnrollment LoginResponse. Surfaced
// from createMFAChallenge — see that doc-comment for the full rationale.
//
// If the enrollment service isn't wired (misconfiguration or test harness
// without Redis), we fail closed rather than silently fall back to the
// emailing-an-unverified-mailbox path that originally caused the lockout
// cliff. Operators fix the wiring; users don't get phishing-baited.
func (s *AuthService) createMFAEnrollmentInterrupt(
	ctx context.Context,
	tenantCtx *tenantContext,
	user *models.User,
	req *models.LoginRequest,
	ipAddress, userAgent string,
	isNewDevice bool,
	riskAssessment *models.RiskAssessment,
) (*models.LoginResponse, error) {
	if s.mfaEnrollmentSvc == nil {
		logger.SecurityAudit.Error("Security audit: MFA enrollment service not wired — risk-MFA cannot interrupt",
			zap.String("event", "auth.mfa.enrollment_misconfigured"),
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ipAddress),
			zap.Time("timestamp", time.Now().UTC()),
		)
		return nil, fmt.Errorf("multi-factor enrollment is required but the enrollment service is unavailable")
	}

	riskScore := 0
	riskLevel := ""
	if riskAssessment != nil {
		riskScore = riskAssessment.TotalScore
		riskLevel = string(riskAssessment.Level)
	}

	token, expiresIn, err := s.mfaEnrollmentSvc.CreateSession(
		ctx,
		user.ID,
		tenantCtx.TenantID,
		tenantCtx.TenantSlug,
		ipAddress,
		userAgent,
		req.ClientID,
		riskScore,
		riskLevel,
	)
	if err != nil {
		logger.Error("Failed to mint MFA enrollment session", zap.Error(err))
		return nil, fmt.Errorf("create enrollment session: %w", err)
	}

	logger.SecurityAudit.Info("Security audit: MFA registration interrupt issued",
		zap.String("event", "auth.mfa.enrollment_interrupt"),
		zap.String("user_id", user.ID.String()),
		zap.String("username", user.Username),
		zap.String("ip", ipAddress),
		zap.String("user_agent", userAgent),
		zap.Int("risk_score", riskScore),
		zap.String("risk_level", riskLevel),
		zap.String("client_id", req.ClientID),
		zap.Time("timestamp", time.Now().UTC()),
	)

	// Prometheus instrumentation. `reason` is "risk" today because
	// createMFAEnrollmentInterrupt only fires from the risk-engine
	// path (createMFAChallenge, line ~694). When realm-policy
	// unconditional MFA enforcement lands as a separate interrupt
	// path, label it "policy". `method` stays "any" here because the
	// user hasn't picked yet — the picker call increments
	// MFAEnrollmentMethodPicked with the specific method.
	metrics.MFAEnrollmentInitiated.WithLabelValues("risk", "any").Inc()

	// Methods offered in the interrupt response — ordered by phishing-
	// resistance per NIST SP 800-63B-4: webauthn (AAL3-capable) first,
	// then totp (AAL2), email last (AAL1, deprecated by NIST for primary
	// auth but kept as a fallback for users without a device). The
	// frontend MfaEnrollmentStep renders them in this order with the
	// first item flagged as "Recommended"; downgrading the order here
	// downgrades the recommendation site-wide without a frontend MR.
	resp := &models.LoginResponse{
		RequiresMFAEnrollment: true,
		EnrollmentToken:       token,
		EnrollmentMethods:     []string{authMethodWebAuthn, authMethodTOTP, authMethodEmail},
		EnrollmentExpiresIn:   expiresIn,
		IsNewDevice:           isNewDevice,
	}
	if riskAssessment != nil {
		resp.RiskScore = riskAssessment.TotalScore
		resp.RiskLevel = string(riskAssessment.Level)
		resp.RiskWarnings = riskAssessment.Warnings
	}

	// Grace-period evaluation (migration 235). Returns the per-user
	// deadline + skip budget when the realm has opted into a grace
	// window; emits MFAEnrollmentCanSkip = false when nothing applies
	// so the frontend renders the unconditional pre-grace hard-block UI.
	s.applyMFAEnrollmentGraceFields(ctx, tenantCtx, user, resp)
	return resp, nil
}

// applyMFAEnrollmentGraceFields stamps the LoginResponse with the
// per-user grace deadline + skip budget IF the realm has opted into a
// grace window. Pure side-effect helper that swallows errors (with a
// warn log) — grace is a UX enhancement, not a security gate, so a
// realm-repo blip MUST NOT block login. Hard enforcement of the
// deadline lives in IncrementMFAEnrollmentSkipCount (atomic SQL guard).
//
// Algorithm (mirrors Entra Registration Campaign / Okta "Required
// After" semantics):
//
//  1. If realmRepo or the user is missing grace policy entirely
//     (grace_period_days = NULL or 0): can_skip = false, no deadline.
//
//  2. If first_prompted_at is NULL: stamp NOW + deadline = NOW +
//     grace_period_days. This first-prompt timestamp is the canonical
//     anchor — Auth0 documents this in onExecutePostLogin "schedule
//     enrollment" guidance and Microsoft uses the same anchor in
//     Registration Campaign exposure logs. Re-fetch the user so we
//     emit the just-stamped values to the client.
//
//  3. Compute skips_remaining = max_skips - skip_count. The skip
//     button renders iff skips_remaining > 0 AND deadline > now.
func (s *AuthService) applyMFAEnrollmentGraceFields(ctx context.Context, tenantCtx *tenantContext, user *models.User, resp *models.LoginResponse) {
	if s.realmRepo == nil || user == nil || resp == nil {
		return
	}

	policy, err := s.realmRepo.GetSecurityPolicy(ctx, tenantCtx.RealmID)
	if err != nil {
		logger.Warn("MFA enrollment grace eval: failed to load realm security policy — falling back to hard-block",
			zap.String("realm_id", tenantCtx.RealmID.String()),
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return
	}
	if policy == nil || policy.MFAGracePeriodDays == nil || *policy.MFAGracePeriodDays <= 0 {
		// Realm hasn't opted into grace. Skip button MUST NOT render —
		// the user is on the hard-block path and pressing "Remind me
		// later" would be a no-op (or worse, surface a stale UX state).
		return
	}

	graceDays := *policy.MFAGracePeriodDays
	now := time.Now().UTC()

	// Stamp first-prompt + deadline atomically. The SQL guards on
	// first_prompted_at IS NULL so concurrent logins can't double-stamp.
	if user.MFAEnrollmentFirstPromptedAt == nil {
		deadline := now.AddDate(0, 0, graceDays)
		stamped, stampErr := s.userRepo.StampMFAEnrollmentFirstPrompt(ctx, user.ID, deadline)
		if stampErr != nil {
			logger.Warn("MFA enrollment grace eval: failed to stamp first-prompt — proceeding without grace fields",
				zap.String("user_id", user.ID.String()),
				zap.Error(stampErr),
			)
			return
		}
		if stamped {
			user.MFAEnrollmentFirstPromptedAt = &now
			user.MFAEnrollmentDeadline = &deadline
		} else {
			// Lost the stamp race — another concurrent login already
			// wrote the values. Re-fetch to read the authoritative ones.
			fresh, fetchErr := s.userRepo.GetByID(ctx, user.ID)
			if fetchErr != nil || fresh == nil {
				logger.Warn("MFA enrollment grace eval: failed to refresh after lost stamp race",
					zap.String("user_id", user.ID.String()),
					zap.Error(fetchErr),
				)
				return
			}
			user.MFAEnrollmentFirstPromptedAt = fresh.MFAEnrollmentFirstPromptedAt
			user.MFAEnrollmentDeadline = fresh.MFAEnrollmentDeadline
			user.MFAEnrollmentSkipCount = fresh.MFAEnrollmentSkipCount
		}
	}

	if user.MFAEnrollmentDeadline == nil {
		return
	}
	resp.MFAEnrollmentDeadline = user.MFAEnrollmentDeadline

	// Skip button: available iff deadline > now AND skip budget remains.
	// max_skips = 0 (the default) means the calendar-grace-only mode —
	// user sees the countdown but can't click "Remind me later". This
	// matches Auth0's "deadline only" preset where each successful
	// login post-deadline becomes the de-facto skip.
	if user.MFAEnrollmentDeadline.After(now) {
		remaining := policy.MFAEnrollmentMaxSkips - user.MFAEnrollmentSkipCount
		if remaining < 0 {
			remaining = 0
		}
		resp.MFAEnrollmentSkipsRemaining = remaining
		resp.MFAEnrollmentCanSkip = remaining > 0
	}
}

// determineMFAMethod determines which MFA method to use. hasFactor is
// the source-of-truth factor inventory (TOTP / email / WebAuthn /
// push); it replaces the historical user.MFAEnabled read so a drifted
// flag cannot route a factorless user through the enrolled-user path
// (which would then fail in getAvailableMFAMethods with an empty list).
func (s *AuthService) determineMFAMethod(user *models.User, preferredMethod string, riskMFARequired, hasFactor, hasPasskey bool) (string, []string) {
	var availableMethods []string
	var mfaMethod string

	if hasFactor {
		availableMethods = s.getAvailableMFAMethods(user, hasPasskey)
		mfaMethod = s.selectMFAMethod(user, preferredMethod, availableMethods)
	} else if riskMFARequired {
		mfaMethod = authMethodEmail
		availableMethods = []string{authMethodEmail}
	}

	return mfaMethod, availableMethods
}

// getAvailableMFAMethods returns the list of MFA methods the user can
// actually verify against. ORDER MATTERS — earlier entries are preferred
// by selectMFAMethod when the user has multiple factors enrolled.
//
// Source-of-truth chain (no silent fallbacks):
//
//	user.MFATOTPEnabled    → "totp"
//	user.MFAEmailEnabled   → "email"
//	(passkey present)      → "webauthn"   (NEW 2026-05-26)
//	(backup codes exist)   → "backup_code" (Phase B, not wired yet)
//
// Historical note: prior to 2026-05-26 this function carried a "if
// nothing else matches AND user.IsEmailVerified → fall back to email"
// branch. It was added 2026-05-23 to rescue passkey-only users whose
// only factor was a WebAuthn credential — without the fallback,
// determineMFAMethod returned ("",[]), buildMFAChallengeResponse
// emitted an unresolvable challenge, and the login UI 401-looped.
//
// But the fallback created a worse bug for the inverse case: a user
// who EXPLICITLY disabled email MFA but still had a passkey would get
// silently prompted for an email OTP that VerifyMFACode rejects
// (because mfa_email_enabled=false). Live trigger 2026-05-25T18:55Z:
// dogukanturhal disabled email MFA via /security, then on the next
// password login was prompted for the email OTP — entered the code —
// got "MFA verification failed" — permanently locked out of password
// login despite having a working passkey.
//
// Canonical fix: emit "webauthn" as the method when the user has a
// passkey and no explicit code-based factor. Matches Microsoft Entra
// / Auth0 / Okta / Google — they all support WebAuthn-as-MFA. The
// /api/v1/auth/mfa/webauthn/{begin,finish} endpoints (added in the
// same MR) consume this signal.
//
// hasPasskey is sourced from iam_webauthn_credentials via a repo
// callback so this function stays pure / unit-testable; production
// callers pre-compute the flag once per login from the same source-
// of-truth lookup HasAnyMFAFactor uses, no extra DB round-trip.
func (s *AuthService) getAvailableMFAMethods(user *models.User, hasPasskey bool) []string {
	var methods []string
	if user.MFATOTPEnabled {
		methods = append(methods, authMethodTOTP)
	}
	if user.MFAEmailEnabled {
		methods = append(methods, authMethodEmail)
	}
	if hasPasskey {
		// Append, not prepend — TOTP / email entered before WebAuthn
		// when both are present, because code-entry has zero UA
		// dependencies (works on every browser including mobile
		// Safari with platform-authenticator quirks). selectMFAMethod
		// honours the user's preferred_method when set.
		methods = append(methods, authMethodWebAuthn)
	}
	return methods
}

// storeMFASession stores MFA session in Redis
func (s *AuthService) storeMFASession(ctx context.Context, tenantCtx *tenantContext, user *models.User, ipAddress, userAgent, clientID string) string {
	tempSessionID := uuid.New().String()

	if s.sessionCache != nil {
		mfaSessionData := &models.MFASessionData{
			UserID:     user.ID.String(),
			TenantID:   tenantCtx.TenantID.String(),
			TenantSlug: tenantCtx.TenantSlug,
			IPAddress:  ipAddress,
			UserAgent:  userAgent,
			ClientID:   clientID,
			CreatedAt:  time.Now().Unix(),
		}
		sessionJSON, err := json.Marshal(mfaSessionData)
		if err == nil {
			redisKey := "mfa:session:" + tempSessionID
			if setErr := s.sessionCache.Client().Set(ctx, redisKey, string(sessionJSON), 5*time.Minute); setErr != nil {
				logger.Warn("Failed to store MFA session in Redis", zap.Error(setErr))
			}
		}
	}

	return tempSessionID
}

// logMFAChallenge logs MFA challenge creation
func (s *AuthService) logMFAChallenge(userID uuid.UUID, mfaMethod string, availableMethods []string, isRiskBased bool) {
	reason := "user MFA enabled"
	if isRiskBased {
		reason = "risk-based MFA required"
	}
	logger.Info("MFA required for login",
		zap.String("user_id", userID.String()),
		zap.String("method", mfaMethod),
		zap.Strings("available_methods", availableMethods),
		zap.String("reason", reason),
	)
}

// buildMFAChallengeResponse builds MFA challenge response
func (s *AuthService) buildMFAChallengeResponse(mfaMethod string, availableMethods []string, sessionID string, isNewDevice bool, riskAssessment *models.RiskAssessment) *models.LoginResponse {
	response := &models.LoginResponse{
		RequiresMFA:         true,
		MFAMethod:           mfaMethod,
		AvailableMFAMethods: availableMethods,
		SessionID:           sessionID,
		IsNewDevice:         isNewDevice,
	}

	if riskAssessment != nil {
		response.RiskScore = riskAssessment.TotalScore
		response.RiskLevel = string(riskAssessment.Level)
		response.RiskWarnings = riskAssessment.Warnings
	}

	return response
}

// selectMFAMethod determines the MFA method to use
func (s *AuthService) selectMFAMethod(user *models.User, preferredMethod string, availableMethods []string) string {
	if preferredMethod != "" {
		for _, m := range availableMethods {
			if m == preferredMethod {
				return preferredMethod
			}
		}
	}

	if user.MFAPreferredMethod != nil {
		return *user.MFAPreferredMethod
	}

	if len(availableMethods) > 0 {
		return availableMethods[0]
	}

	if user.MFAType != nil {
		return *user.MFAType
	}

	// LOCKOUT FIX (2026-05-23): default to email instead of TOTP. TOTP
	// requires a pre-enrolled authenticator with a shared secret; if
	// the user has no TOTP enrolled (mfa_totp_enabled=false, mfa_secret
	// empty), defaulting to TOTP guarantees lockout — they cannot
	// produce a valid code because none exists. Email is universally
	// available because is_email_verified=true is a prerequisite for
	// any active account. See getAvailableMFAMethods doc for the full
	// regression context (dogukanturhal passkey lockout, 2026-05-23).
	return authMethodEmail
}

// getUserRolesAndPermissions gets user roles and permissions
func (s *AuthService) getUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) ([]string, []models.Role, []string, []models.Permission, error) {
	roleNames, roles, err := s.getUserRoles(ctx, userID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	permissions, err := s.userRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	permNames := make([]string, len(permissions))
	for i, p := range permissions {
		permNames[i] = p.Name
	}

	return roleNames, roles, permNames, permissions, nil
}

// getUserRoles gets user roles (direct + group-inherited if available)
func (s *AuthService) getUserRoles(ctx context.Context, userID uuid.UUID) ([]string, []models.Role, error) {
	if s.groupService != nil {
		return s.getEffectiveRoles(ctx, userID)
	}
	return s.getDirectRoles(ctx, userID)
}

// getEffectiveRoles gets effective roles (direct + group-inherited)
func (s *AuthService) getEffectiveRoles(ctx context.Context, userID uuid.UUID) ([]string, []models.Role, error) {
	effectiveRoles, err := s.groupService.GetUserEffectiveRoles(ctx, userID)
	if err != nil {
		logger.Warn("Failed to get effective roles, falling back to direct roles", zap.Error(err))
		return s.getDirectRoles(ctx, userID)
	}

	roleSet := make(map[string]bool)
	for _, er := range effectiveRoles {
		roleSet[er.RoleName] = true
	}

	roleNames := make([]string, 0, len(roleSet))
	for name := range roleSet {
		roleNames = append(roleNames, name)
	}

	roles, _ := s.userRepo.GetUserRoles(ctx, userID)
	return roleNames, roles, nil
}

// getDirectRoles gets direct user roles only
func (s *AuthService) getDirectRoles(ctx context.Context, userID uuid.UUID) ([]string, []models.Role, error) {
	roles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}

	return roleNames, roles, nil
}

// createSessionWithInvalidation creates session with security invalidation.
// SECURITY: Implements session ID regeneration on authentication to prevent
// session fixation attacks (Auth0-style CVE pattern). If an existing session
// exists from the same IP, the old session is invalidated and a new session
// is created with PreviousSessionID set, creating an audit trail.
//
// authMethods is forwarded to createSession so the new row records the
// RFC 8176 Authentication Method References of this login event
// (migration 211, docs/oidc-claims-groups-amr.md).
//
// rememberMe is forwarded to createSession to drive the
// iam_sessions.expires_at horizon — false = short TTL (existing
// behaviour, SessionTTLDefault → SessionExpiry), true = extended
// (SessionTTLRememberMe, default 30d).
func (s *AuthService) createSessionWithInvalidation(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, authMethods []string, rememberMe bool) (*models.Session, error) {
	// Find existing sessions from the same IP for regeneration tracking
	var previousSessionID *uuid.UUID
	activeSessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		logger.Warn("Failed to get active sessions for regeneration check", zap.Error(err))
	} else {
		for _, existingSession := range activeSessions {
			if existingSession.IPAddress != nil && *existingSession.IPAddress == ipAddress {
				previousSessionID = &existingSession.ID
				break
			}
		}
	}

	// Invalidate existing sessions from the same IP
	if err := s.invalidateExistingSessionsBeforeLogin(ctx, userID, ipAddress); err != nil {
		logger.Warn("Failed to invalidate existing sessions before login", zap.Error(err))
	}

	session, err := s.createSession(ctx, userID, ipAddress, userAgent, authMethods, rememberMe)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Set session regeneration metadata
	if previousSessionID != nil {
		session.PreviousSessionID = previousSessionID
		session.SessionRegenerated = true

		// Log session regeneration as a security event
		s.auditService.LogSecurityEvent(ctx, &SecurityAuditEvent{
			TenantID:    uuid.Nil, // Tenant resolved from user context by caller
			UserID:      &userID,
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Category:    SecurityCategoryAuthentication,
			Severity:    SecuritySeverityLow,
			Action:      "session_regenerated",
			Description: fmt.Sprintf("Session regenerated on login: old=%s new=%s", previousSessionID.String(), session.ID.String()),
			Details: map[string]interface{}{
				"previous_session_id": previousSessionID.String(),
				"new_session_id":      session.ID.String(),
			},
			Blocked:     false,
			ThreatScore: 0,
		})

		logger.Info("Session regenerated on authentication (fixation protection)",
			zap.String("user_id", userID.String()),
			zap.String("old_session_id", previousSessionID.String()),
			zap.String("new_session_id", session.ID.String()),
			zap.String("ip_address", ipAddress),
		)
	} else {
		logger.Info("New session created after authentication",
			zap.String("user_id", userID.String()),
			zap.String("session_id", session.ID.String()),
			zap.String("ip_address", ipAddress),
		)
	}

	return session, nil
}

// handleDeviceTrust handles Remember Me functionality. Returns true when
// the device is trusted (RememberMe + valid device fingerprint).
//
// Device trust is captured on the iam_oauth_tokens side via the OAuth
// flow's PKCE/JKT binding (RFC 9449) and on the IdP session blob.
func (s *AuthService) handleDeviceTrust(ctx context.Context, userID uuid.UUID, req *models.LoginRequest, userAgent, ipAddress string) bool {
	if req.RememberMe && req.DeviceID != "" {
		return s.trustDeviceIfNeeded(ctx, userID, req.DeviceID, userAgent, ipAddress)
	}
	if req.DeviceID != "" && s.deviceService != nil {
		return s.isDeviceCurrentlyTrusted(ctx, userID, req.DeviceID)
	}
	return false
}

// isDeviceCurrentlyTrusted checks whether the device fingerprint is currently trusted and not expired.
func (s *AuthService) isDeviceCurrentlyTrusted(ctx context.Context, userID uuid.UUID, deviceID string) bool {
	if s.deviceService == nil {
		return false
	}
	existing, _ := s.deviceService.GetDeviceByFingerprint(ctx, userID, deviceID)
	if existing == nil || !existing.IsTrusted {
		return false
	}
	return existing.TrustExpiresAt == nil || time.Now().Before(*existing.TrustExpiresAt)
}

// trustDeviceIfNeeded marks the device as trusted (if not already) and returns whether it is now trusted.
func (s *AuthService) trustDeviceIfNeeded(ctx context.Context, userID uuid.UUID, deviceID, userAgent, ipAddress string) bool {
	if s.deviceService == nil {
		return false
	}
	if s.isDeviceCurrentlyTrusted(ctx, userID, deviceID) {
		return true
	}
	_, err := s.deviceService.TrustDeviceByFingerprint(ctx, userID, deviceID, userAgent, ipAddress, s.config.TrustDurationDays)
	if err != nil {
		logger.Warn("Failed to mark device as trusted", zap.Error(err))
		return false
	}
	logger.Info("Device marked as trusted",
		zap.String("user_id", userID.String()),
		zap.String("device_id", deviceID),
		zap.Int("trust_days", s.config.TrustDurationDays),
	)
	return true
}

// generateAccessToken generates a JWT access token for an authenticated
// session. Picks the correct generator based on per-user v2 rollout +
// client_id audience scoping.
//
// Phase 3 (mig 233): no longer issues a refresh token — iam_refresh_tokens
// is dropped, all rotation flows through OIDC /oauth/token (iam_oauth_tokens)
// minted inside the BFF's internal OIDC code-grant dance (see
// frontend/packages/falcon-id-client/src/server/internal-oauth-dance.ts).
// Callers that previously destructured refreshToken from generateTokens
// drop the second return + the empty-string field on LoginResponse.
func (s *AuthService) generateAccessToken(ctx context.Context, user *models.User, sessionID uuid.UUID, roleNames, permNames []string, clientID string) (string, error) {
	switch {
	case s.tokenService.ShouldUseV2Token(user.ID):
		return s.tokenService.GenerateAccessTokenV2(ctx, user, sessionID, roleNames, TokenGenerationOptions{
			RealmID:  user.RealmID,
			ClientID: clientID,
		})
	case clientID != "":
		// Use options-based generation for audience scoping
		return s.tokenService.GenerateAccessTokenWithOptions(ctx, user, sessionID, roleNames, permNames, TokenGenerationOptions{
			RealmID:  user.RealmID,
			Scope:    "tenant",
			ClientID: clientID,
		})
	default:
		return s.tokenService.GenerateAccessToken(ctx, user, sessionID, roleNames, permNames)
	}
}

// updateUserLoginInfo updates last login timestamp and resets failed attempts
func (s *AuthService) updateUserLoginInfo(ctx context.Context, user *models.User, ipAddress string) error {
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = &ipAddress
	user.FailedLoginAttempts = 0

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if err := s.userRepo.ResetFailedAttempts(ctx, user.ID); err != nil {
		logger.Warn("Failed to reset failed login attempts", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	return nil
}

// buildLoginResponse builds the final login response object.
//
// Phase 3 (mig 233): RefreshToken + RefreshExpiresIn are left empty.
// All token rotation flows through OIDC /oauth/token via the BFF's
// internal OIDC dance (frontend!25). isTrustedDevice still drives the
// IsTrustedDevice response flag for client-side UX (e.g., "remembered
// device" badge) — even though it no longer extends a refresh-token
// TTL, it still captures the trust assessment used elsewhere.
func (s *AuthService) buildLoginResponse(ctx context.Context, tenantCtx *tenantContext, user *models.User, roles []models.Role, permissions []models.Permission, accessToken string, isTrustedDevice, isNewDevice bool, riskAssessment *models.RiskAssessment) (*models.LoginResponse, error) {
	loginIP := ""
	if user.LastLoginIP != nil {
		loginIP = *user.LastLoginIP
	}
	s.auditService.LogLogin(ctx, tenantCtx.TenantID, &user.ID, loginIP, "", true, "")

	user.Roles = roles
	user.Permissions = permissions

	if tenantCtx.RealmSlug == "" && user.RealmID != uuid.Nil {
		tenantCtx.RealmID = user.RealmID
		if tenantCtx.RealmSlug == "" {
			tenantCtx.RealmSlug = "default"
		}
		if tenantCtx.RealmType == "" {
			tenantCtx.RealmType = "shared"
		}
	}

	userResponse := user.ToResponse()

	if tenantCtx.TenantSlug == "" && s.tenantRepo != nil {
		if tenant, err := s.tenantRepo.GetByID(ctx, user.TenantID); err == nil && tenant != nil {
			tenantCtx.TenantSlug = tenant.Slug
		}
	}
	userResponse.TenantSlug = tenantCtx.TenantSlug

	response := &models.LoginResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(s.config.AccessTokenExpiry.Seconds()),
		User:            userResponse,
		RealmID:         tenantCtx.RealmID.String(),
		RealmSlug:       tenantCtx.RealmSlug,
		RealmType:       tenantCtx.RealmType,
		IsNewDevice:     isNewDevice,
		IsTrustedDevice: isTrustedDevice,
	}

	if riskAssessment != nil {
		response.RiskScore = riskAssessment.TotalScore
		response.RiskLevel = string(riskAssessment.Level)
		response.RiskWarnings = riskAssessment.Warnings
	}

	return response, nil
}

// Logout ends a user's session and, if back-channel logout is configured,
// fires best-effort logout token notifications to registered relying parties.
//
// tenantID is used to scope the back-channel fan-out to clients belonging to
// the user's own tenant. Pass uuid.Nil to skip back-channel notification.
//
// Phase 3 (mig 233): the legacy refreshToken parameter was removed.
// Auth-service refresh tokens aren't issued any more so per-token revoke
// has no target — terminateLogoutSessions sweeps the user's iam_oauth_tokens
// rows instead (Phase 3.1).
func (s *AuthService) Logout(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, tenantID uuid.UUID, allDevices bool) error {
	if err := s.terminateLogoutSessions(ctx, userID, sessionID, allDevices); err != nil {
		return err
	}

	// Best-effort back-channel logout notification to all registered RPs.
	// Runs in a background goroutine so it never delays the caller's response.
	if s.backchannelLogout != nil && tenantID != uuid.Nil {
		go func() { //nolint:gosec // goroutine must outlive request context
			if err := s.backchannelLogout.NotifyLogout(
				context.Background(),
				userID,
				sessionID.String(),
				tenantID,
			); err != nil {
				logger.Error("BackchannelLogout.NotifyLogout: unexpected error",
					zap.String("user_id", userID.String()),
					zap.Error(err),
				)
			}
		}()
	}

	// Best-effort OpenID CAEP 1.0 session-revoked SET fan-out to every
	// subscribed receiver stream. Mirrors the backchannel-logout
	// pattern: separate goroutine, dropped errors logged by the
	// emitter, no caller-visible failure on receiver outage.
	//
	// Receivers (Talon, etc.) react to this by tombstoning the user's
	// sessions immediately rather than waiting for the cookie TTL.
	// This closes the "stolen cookie until TTL" gap identified in the
	// 2026-06-02 tier-1 IAP gap analysis.
	if s.caepEmitter != nil && tenantID != uuid.Nil {
		reason := "logout"
		if allDevices {
			reason = "logout_all_devices"
		}
		go func() { //nolint:gosec // goroutine must outlive request context
			_ = s.caepEmitter.EmitSessionRevoked(
				context.Background(),
				tenantID,
				userID,
				reason,
			)
		}()
	}

	return nil
}

// terminateLogoutSessions ends sessions and revokes tokens for a logout operation.
//
// Token revocation sweeps the user's iam_oauth_tokens rows (post-Phase-3
// the only token store). allDevices=false also fires the user-broad
// sweep — auth-service refresh tokens don't exist any more so per-token
// revoke has no target, and the IdP session blacklist (tokenBlacklist
// via auth_handler.Logout) was already user-broad anyway.
func (s *AuthService) terminateLogoutSessions(ctx context.Context, userID, sessionID uuid.UUID, allDevices bool) error {
	if allDevices {
		if err := s.sessionRepo.EndAllUserSessions(ctx, userID, "logout"); err != nil {
			return fmt.Errorf("failed to end sessions: %w", err)
		}
		if err := s.tokenService.RevokeAllUserOAuthTokens(ctx, userID, "logout"); err != nil {
			return fmt.Errorf("failed to revoke OAuth tokens: %w", err)
		}
		return nil
	}
	if err := s.sessionRepo.EndSession(ctx, sessionID, "logout"); err != nil {
		return fmt.Errorf("failed to end session: %w", err)
	}
	if err := s.tokenService.RevokeAllUserOAuthTokens(ctx, userID, "logout"); err != nil {
		logger.Error("Failed to revoke OAuth tokens", zap.Error(err))
	}
	return nil
}

// NOTE: Additional AuthService methods are organized in:
// - auth_credentials_service.go: authenticateLocal, authenticateLDAP, session creation, MFA code verification
// - auth_mfa_service.go: CompleteMFALogin, SwitchMFALoginMethod, MFA session management
// - auth_account_service.go: GetCurrentUser, UpdateProfile, ChangePassword, session management, impersonation
