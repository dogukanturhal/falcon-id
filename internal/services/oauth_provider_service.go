// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/clientctx"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/keys"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/metrics"
)

// ErrClientIDConflict is returned when CreateClient receives a request
// whose `client_id` is already registered. Handlers should map it to
// HTTP 409 Conflict so callers (notably the platform's ServiceClient
// provisioner) can distinguish "this name is taken" from generic
// validation errors and rotate the secret of the existing client
// instead of retrying create.
var ErrClientIDConflict = errors.New("client_id already registered")

// ErrDPoPRequired is returned when an OAuth grant resolves to a scope
// set that requires a DPoP-bound token (RFC 9449 §6) but the token
// request did not carry a valid DPoP proof. The token endpoint maps
// it to the RFC 9449 §7.1 `invalid_dpop_proof` error.
var ErrDPoPRequired = errors.New("invalid_dpop_proof: requested scope requires a DPoP-bound token; resend the token request with a DPoP proof header")

// dpopRequiredScopes lists the scope strings (and prefixes) where the
// platform mandates DPoP-bound tokens. The set covers:
//
//   - admin:* — any platform-admin scope. Bearer-token replay against
//     these is the highest-impact attack we can stop cheaply.
//   - offline_access — long-lived refresh-token issuance. RFC 9449
//     §7.4 explicitly recommends sender-constrained refresh.
//
// Plain bearer remains acceptable for unprivileged scopes (openid,
// email, profile, etc.) so passwordless / public-client SPA flows
// without proof-key infrastructure continue to work.
var dpopRequiredScopes = map[string]struct{}{
	"offline_access": {},
}

const dpopRequiredScopePrefix = "admin:"

// scopeRequiresDPoP reports whether any scope in the slice triggers
// the DPoP-required gate.
func scopeRequiresDPoP(scopes []string) bool {
	for _, s := range scopes {
		if _, ok := dpopRequiredScopes[s]; ok {
			return true
		}
		if strings.HasPrefix(s, dpopRequiredScopePrefix) {
			return true
		}
	}
	return false
}

// contextKey is an unexported context-key type so external packages
// can't accidentally collide with these keys.
type contextKey string

// ctxKeyOAuthResource carries the RFC 8707 `resource` parameter from
// the token endpoint into generateTokens(), where it overrides the
// default `aud=client_id` claim. Empty / missing → fallback to the
// historical default. Set via WithOAuthResource; never mutated.
const ctxKeyOAuthResource contextKey = "oauth_resource"

// ctxKeyDPoPJKT carries the JWK SHA-256 thumbprint extracted by the
// OptionalDPoP middleware at /oauth/token. The token endpoint stashes
// it via WithDPoPJKT; generateTokens reads it back via
// dpopJKTFromContext to embed the RFC 7800 / RFC 9449 cnf.jkt
// confirmation claim on the issued access token.
//
// Empty / missing → no cnf claim → plain bearer (legacy default).
const ctxKeyDPoPJKT contextKey = "oauth_dpop_jkt"

// WithOAuthResource returns a derived context carrying the validated
// RFC 8707 resource URI. The handler validates the value before
// stashing it (absolute URI, no fragment); the service trusts the
// context value and uses it verbatim as the `aud` claim.
func WithOAuthResource(ctx context.Context, resource string) context.Context {
	if resource == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyOAuthResource, resource)
}

// oauthResourceFromContext returns the resource value stashed by
// WithOAuthResource. Empty when not set.
func oauthResourceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyOAuthResource).(string)
	return v
}

// WithDPoPJKT returns a derived context carrying the DPoP proof key
// thumbprint. Stashing on ctx keeps generateTokens' signature stable
// across the existing 3 grants instead of a fan-out parameter add.
func WithDPoPJKT(ctx context.Context, jkt string) context.Context {
	if jkt == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyDPoPJKT, jkt)
}

// dpopJKTFromContext returns the JKT stashed by WithDPoPJKT. Empty
// when no proof was presented at /oauth/token.
func dpopJKTFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyDPoPJKT).(string)
	return v
}

// ctxKeySpiffeID carries the SPIFFE URI of the calling service, as
// supplied by the Linkerd sidecar via the `l5d-client-id` HTTP header.
// The /oauth/token handler stashes it via WithSpiffeID; generateTokens
// reads it back via spiffeIDFromContext to stamp `cnf.spiffe` on tokens
// issued by the RFC 8693 :jwt grant (IAP→BFF bridge). Only the :jwt
// grant emits the claim — other grants get no spiffe binding because
// their callers don't necessarily traverse Linkerd (e.g. the OIDC
// password grant from the user-facing /auth/login endpoint).
const ctxKeySpiffeID contextKey = "oauth_spiffe_id"

// WithSpiffeID returns a derived context carrying the calling
// workload's SPIFFE URI. Empty input → no-op (defensive against the
// header being absent; handler doesn't have to guard).
func WithSpiffeID(ctx context.Context, spiffeID string) context.Context {
	if spiffeID == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeySpiffeID, spiffeID)
}

// spiffeIDFromContext returns the SPIFFE URI stashed by WithSpiffeID.
// Empty when not set — generateTokens then omits the cnf.spiffe claim.
func spiffeIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeySpiffeID).(string)
	return v
}

// ctxKeyRequestIP carries the resolved client IP (after gateway
// X-Forwarded-For) from the token endpoint into generateTokens (where
// it is stamped on the issued OAuthToken row) and into RefreshTokens
// (where it is compared to the prior token's IP to drive CAEP
// CAEIPChanged signals). Empty / missing → no IP capture and no
// IP-change detection — preserves pre-IP-binding behavior.
const ctxKeyRequestIP contextKey = "oauth_request_ip"

// WithRequestIP returns a derived context carrying the gateway-resolved
// client IP for the current /oauth/token request. The handler resolves
// IP via gin.Context.ClientIP() (X-Forwarded-For aware) before stashing
// so the service layer trusts the value verbatim.
func WithRequestIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRequestIP, ip)
}

// requestIPFromContext returns the IP stashed by WithRequestIP. Empty
// when the caller did not stash one (e.g. background revoke flows).
func requestIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestIP).(string)
	return v
}

// ctxKeyRequestUserAgent carries the User-Agent header value into
// RefreshTokens so the rotation flow can detect OS-class drift vs the
// linked iam_sessions row's stored UA. Same propagation pattern as
// ctxKeyRequestIP — the handler stashes verbatim from c.GetHeader,
// service treats the value as already-trusted (the handler runs
// AFTER trust-boundary middleware).
const ctxKeyRequestUserAgent contextKey = "oauth_request_user_agent"

// WithRequestUserAgent returns a derived context carrying the current
// request's User-Agent header. Empty value short-circuits to the
// parent context so legacy / background callers don't accidentally
// stamp an empty UA into the iam_sessions row.
func WithRequestUserAgent(ctx context.Context, ua string) context.Context {
	if ua == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRequestUserAgent, ua)
}

// requestUserAgentFromContext returns the UA stashed by
// WithRequestUserAgent, or "" when absent.
func requestUserAgentFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestUserAgent).(string)
	return v
}

// ctxKeyTokenExchangeActor identifies the OAuth client that initiated
// an RFC 8693 token exchange — used to stamp the issued access
// token's `act` claim (RFC 8693 §4.1). Threaded via context so the
// existing generateTokens signature stays stable across the 4+ grants.
//
// Two-element value: actor sub (typically the BFF client_id) plus
// the issuer of the subject_token when it differs from the actor
// (Talon stamped the subject_token; the BFF is exchanging it). The
// `sub` of the inner `act` is the entity that minted the subject
// token; the outer act.sub is the current actor — mirrors the
// delegation chain RFC 8693 §4.1.1 example A.1.
const ctxKeyTokenExchangeActor contextKey = "oauth_token_exchange_actor"

// TokenExchangeActor captures the parties involved in an RFC 8693
// exchange for `act` claim emission. ActorSub is REQUIRED; everything
// else is optional.
type TokenExchangeActor struct {
	// ActorSub is the `sub` value to write into `act.sub` — the
	// identity that initiated the exchange (the calling client).
	ActorSub string
	// ActorClientID is the OAuth client_id of the actor, written
	// into `act.client_id` so receivers that audit by client_id
	// (alongside sub) get full attribution.
	ActorClientID string
	// SubjectTokenIssuer is the `iss` of the subject_token. When set
	// and different from the actor, it lands in `act.iss` so the
	// delegation chain is recorded ("Talon authenticated the user;
	// BFF acted on the user's behalf").
	SubjectTokenIssuer string
}

// WithTokenExchangeActor returns a derived context carrying the
// exchange actor. Empty ActorSub short-circuits (no-op).
func WithTokenExchangeActor(ctx context.Context, actor TokenExchangeActor) context.Context {
	if actor.ActorSub == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyTokenExchangeActor, actor)
}

// tokenExchangeActorFromContext returns the actor stashed by
// WithTokenExchangeActor, or a zero value if none.
func tokenExchangeActorFromContext(ctx context.Context) TokenExchangeActor {
	v, _ := ctx.Value(ctxKeyTokenExchangeActor).(TokenExchangeActor)
	return v
}

// ctxKeyReuseRefreshToken carries the plaintext refresh_token the
// caller wants generateTokens to RE-USE instead of minting a fresh
// one. Set by RefreshTokens when the client's
// RefreshTokenRotationPolicy is "reuse" (the Duende BFF / OAuth 2.1
// first-party-app pattern for confidential BFFs). Empty / missing →
// canonical rotate semantics: generate a fresh random refresh_token.
//
// Threading through ctx keeps generateTokens' signature stable across
// every other grant path (auth_code, client_credentials,
// token-exchange) — only the refresh-token grant actually opts in.
const ctxKeyReuseRefreshToken contextKey = "oauth_reuse_refresh_token"

// WithReuseRefreshToken returns a derived context that causes the
// next generateTokens call on this ctx to reuse the supplied
// plaintext refresh_token (its hash will be recorded on the new
// access-token row; the same plaintext will be returned in the
// OAuthTokenResponse.RefreshToken field).
//
// Empty input → no-op (defensive); the canonical rotate path runs.
func WithReuseRefreshToken(ctx context.Context, plaintext string) context.Context {
	if plaintext == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyReuseRefreshToken, plaintext)
}

// reuseRefreshTokenFromContext returns the plaintext refresh_token
// stashed by WithReuseRefreshToken. Empty when not set.
func reuseRefreshTokenFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyReuseRefreshToken).(string)
	return v
}

// ctxKeyRefreshTokenFamily carries the RFC 9700 §4.14 token-family (lineage)
// id from RefreshTokens into the generateTokens call it makes, so a rotated
// token inherits its parent's family id instead of starting a fresh family.
// Every other grant path (auth_code, client_credentials, token-exchange)
// leaves this unset, and generateTokens then roots a NEW family at the freshly
// minted token's own id. Threading through ctx keeps generateTokens' signature
// stable across every grant path — only the refresh-token grant opts in.
const ctxKeyRefreshTokenFamily contextKey = "oauth_refresh_token_family"

// WithRefreshTokenFamily returns a derived context that causes the next
// generateTokens call on this ctx to stamp the rotated token row with the
// supplied family id (the parent refresh token's lineage) rather than rooting
// a new family. uuid.Nil input → no-op (defensive); the new token roots its
// own family.
func WithRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) context.Context {
	if familyID == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRefreshTokenFamily, familyID)
}

// refreshTokenFamilyFromContext returns the family id stashed by
// WithRefreshTokenFamily. uuid.Nil when not set (root-of-a-new-family case).
func refreshTokenFamilyFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(ctxKeyRefreshTokenFamily).(uuid.UUID)
	return v
}

const (
	oauthAlgRS256 = "RS256"
	oauthAlgS256  = "S256"
)

// oauthProviderServiceClientRepo defines the OAuth client repository methods needed by OAuthProviderService.
type oauthProviderServiceClientRepo interface {
	Create(ctx context.Context, client *models.OAuthClient) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error)
	GetByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)
	GetByTenantID(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error)
	Update(ctx context.Context, client *models.OAuthClient) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateSecret(ctx context.Context, id uuid.UUID, secretHash string) error
	CreateAuthorizationCode(ctx context.Context, code *models.OAuthAuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (*models.OAuthAuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) error
	// BeginTx opens a transaction used by the authorization_code exchange to
	// consume the code (mark-used CAS) and persist the issued token row
	// atomically — see ExchangeAuthorizationCode / OAuthClientTx.
	BeginTx(ctx context.Context) (repositories.OAuthClientTx, error)
	CreateOAuthToken(ctx context.Context, token *models.OAuthToken) error
	GetOAuthTokenByHash(ctx context.Context, tokenHash string) (*models.OAuthToken, error)
	RevokeOAuthToken(ctx context.Context, tokenHash string) error
	ConsumeRefreshToken(ctx context.Context, tokenID uuid.UUID) (bool, error)
	RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) (int64, error)
	RevokeAllClientTokens(ctx context.Context, clientID uuid.UUID) error
	RevokeUserClientTokens(ctx context.Context, userID, clientID uuid.UUID) error
	GetConsent(ctx context.Context, userID, clientID uuid.UUID) (*models.OAuthConsent, error)
	CreateOrUpdateConsent(ctx context.Context, consent *models.OAuthConsent) error
	RevokeConsent(ctx context.Context, userID, clientID uuid.UUID) error
	GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error)
	GetUserConsentsEnriched(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsentEnriched, error)
}

// oauthProviderServiceUserRepo defines the user repository methods needed by OAuthProviderService.
type oauthProviderServiceUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	HasAnyMFAFactor(ctx context.Context, userID uuid.UUID) (bool, error)
}

// OAuthProviderService handles OAuth2/OIDC provider operations
type OAuthProviderService struct {
	clientRepo oauthProviderServiceClientRepo
	userRepo   oauthProviderServiceUserRepo
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string

	// sessionCache is optional; when set, generateTokens uses it to
	// resolve the RFC 9470 §6.1 / OIDC Core §2 `auth_time` claim by
	// reading IdpSessionData.AuthTime keyed by the authorization
	// code / refresh token's IdpSessionID. Without this lookup the
	// /oauth/token mint path had no source for auth_time and silently
	// emitted no claim — every downstream RequireFreshAuth gate then
	// saw CurrentUser.AuthTime==0 and failed closed (the 6th layer of
	// the passkey-delete redirect loop closed 2026-05-25; the earlier
	// auth_time fixes !242/!243 covered the /api/v1/auth/login path
	// via token_service, not this path).
	//
	// nil-safe: generateTokens falls back to `now()` if unwired or
	// the IdP session has expired, accepting a small freshness window
	// inaccuracy rather than failing token issuance.
	sessionCache idpSessionAuthTimeSource

	// keyManager is optional; when set, DB-persisted keys are used for signing
	// and GetJWKS returns all active+rotated keys for graceful rotation.
	keyManager *keys.KeyManager

	// parStore is optional; when set, PAR (RFC 9126) is enabled.
	parStore parStore

	// rarService handles RFC 9396 Rich Authorization Requests processing.
	rarService *RARService

	// subjectClaims is optional; when set, the service emits `groups` / `roles`
	// claims on id_tokens and access_tokens under scope-gated rules. Production
	// wiring is GroupService (see cmd/server main.go).
	subjectClaims subjectClaimsProvider

	// claimsLogger is optional; when set, diagnostics from subjectClaims
	// failures are emitted at warn level without aborting token issuance.
	claimsLogger *zap.Logger

	// caeService is optional; when set, RevokeToken publishes a
	// `session_revoked` CAEP event so downstream receivers (Talon, SSE
	// subscribers) can invalidate the session within the access-token TTL
	// window instead of waiting for the next refresh. nil-safe — the
	// publish step is a no-op when the service is not wired.
	caeService *CAEService

	// auditService is optional; when set, ClientCredentialsGrant
	// emits a SecurityCategoryAuthentication audit event on every
	// successful token mint so machine-identity issuance is visible
	// in the audit funnel alongside human OIDC logins. nil-safe — the
	// emit step is a no-op when the service is not wired.
	//
	// Rationale (Talon service-token Phase 2, see
	// platform/docs/specs/talon-service-tokens.md): the
	// `iam_oauth_tokens` row is the de-facto record of token issuance
	// today, but it sits in a different table than the
	// `iam_audit_logs` rows the SOC's funnel watches. Without this
	// hook, machine-token mints are invisible to the operator
	// dashboards even though the credential is just as security-
	// relevant as a human session. One small addition closes the gap.
	auditService *AuditService

	// productSubscriptionResolver is optional; when set, generateTokens
	// resolves active iam_product_instances rows for the user's tenant
	// and embeds them as the `products` claim on minted access tokens.
	// Mirrors token_service.productSubscriptionResolver — without this
	// wiring the OAuth /oauth/token mint path (authorization_code,
	// refresh_token, token-exchange grants) silently dropped the claim
	// and downstream product-entitlement middleware (e.g. mearax
	// productSlug gate) had no source for /app/* gating decisions.
	// nil-safe: when unset the claim is omitted and behaviour matches
	// pre-extension.
	productSubscriptionResolver *ProductSubscriptionResolver

	// externalIssuerRepo is optional; when set, TokenExchangeGrant
	// accepts subject_token_type=urn:ietf:params:oauth:token-type:jwt
	// signed by EXTERNAL trusted issuers (most importantly Talon at
	// internal.example.com) and exchanges them for user-bound
	// Falcon-ID access tokens. nil → only Falcon-ID-issued
	// access_token subject types are accepted (backward compat with
	// the pre-extension behaviour).
	externalIssuerRepo externalIssuerRepository
	// externalJWTValidator is the in-tree RS256 JWKS verifier used by
	// the external-JWT branch of TokenExchangeGrant. Optional; the
	// service constructs a default on first call when SetExternalIssuerRepository
	// has been wired.
	externalJWTValidator *ExternalJWTValidator

	// tenantTypeLookup resolves a tenant's Type for redirect_uri policy
	// enforcement at CreateClient / UpdateClient. nil-safe: when unset,
	// redirect_uri validation is skipped (matches pre-policy behaviour
	// for tests that don't construct a tenant repository). cmd/services.go
	// wires the real repository via SetTenantTypeLookup at startup.
	tenantTypeLookup tenantTypeLookup

	// sessionContextSvc is optional. When wired, RefreshTokens compares
	// the inbound request's user-agent and country to the linked
	// iam_sessions row (via token.IdpSessionID) and creates a NEW
	// session row when:
	//   - the linked session no longer exists or is inactive
	//     (refresh-token TTL outlives the session-row TTL — common when
	//     a long-idle browser comes back online)
	//   - the country differs from session.country_code
	//   - the OS-class of the user-agent differs from the stored UA
	//
	// Why: industry canonical pattern (Auth0 / Okta / Entra) keeps
	// iam_sessions IMMUTABLE on UA/IP/geo after creation and cuts a new
	// session row when refresh-token rotation context drifts. Without
	// this, the user-visible "Active Sessions" tab shows stale UA/OS
	// data (e.g. "Chrome on macOS" for a user currently on Chrome on
	// Linux who's riding a long-lived refresh-token cookie originally
	// minted on the Mac). nil-safe — unset = legacy behaviour (token
	// rotation preserves IdpSessionID verbatim, even when the linked
	// session row is gone).
	//
	// See: internal engineering notes research notes
	// + frontend MR adding X-Geo-* to BFF forward-headers (peer fix
	// for the empty-Network-column gap that motivated this work).
	sessionContextSvc sessionContextService
}

// tenantTypeLookup is the minimal repository surface needed to enforce
// the tenant-type-aware redirect_uri policy. The full TenantRepository
// satisfies this interface — it's kept narrow so tests can substitute
// a small fake without depending on the database layer.
type tenantTypeLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
}

// externalIssuerRepository is the subset of
// OAuthTrustedExternalIssuerRepository needed by the OAuth provider
// service. Kept as an interface so tests can supply lightweight
// fakes without standing up a full pgx pool.
type externalIssuerRepository interface {
	GetByIssuer(ctx context.Context, tenantID uuid.UUID, issuerURL string) (*models.OAuthTrustedExternalIssuer, error)
	GetClientGrant(ctx context.Context, clientID, issuerID uuid.UUID) (*models.OAuthClientTrustedExternalIssuer, error)
}

// SetExternalIssuerRepository wires in the trusted-external-issuer
// registry, enabling the subject_token_type=:jwt branch of
// TokenExchangeGrant. Safe to call with nil (disables the branch
// — back to pre-extension behaviour).
func (s *OAuthProviderService) SetExternalIssuerRepository(repo externalIssuerRepository) {
	s.externalIssuerRepo = repo
	if repo != nil && s.externalJWTValidator == nil {
		s.externalJWTValidator = NewExternalJWTValidator()
	}
}

// SetCAEService wires the CAEP event publisher into the OAuth provider
// service. Called from cmd/services.go alongside Redis client construction.
// Safe to call with nil (disables publish).
func (s *OAuthProviderService) SetCAEService(svc *CAEService) {
	s.caeService = svc
}

// SetAuditService wires the audit emitter into the OAuth provider
// service. Used by ClientCredentialsGrant to publish a
// SecurityCategoryAuthentication event on every successful
// client_credentials mint, so machine-identity issuance is visible in
// the audit funnel alongside human OIDC logins. Safe to call with nil
// (disables the emit — back to pre-extension behaviour).
//
// See platform/docs/specs/talon-service-tokens.md §"Falcon-ID audit
// hook" for the rationale.
func (s *OAuthProviderService) SetAuditService(svc *AuditService) {
	s.auditService = svc
}

// SetProductSubscriptionResolver wires the resolver that populates the
// `products` claim on access tokens minted by generateTokens — the OAuth
// 2.1 `/oauth/token` mint path covering authorization_code, refresh_token,
// client_credentials, and token-exchange grants. Mirrors the equivalent
// setter on TokenService (which covers the legacy /api/v1/auth/login mint
// path); without this wiring the OAuth path silently dropped the claim and
// downstream product-entitlement middleware (e.g. mearax) had no source for
// gating /app/*.
//
// nil-safe: when unset (tests, partial deployments) generateTokens skips
// the resolver call entirely — tokens issue without the products claim,
// which matches pre-extension behaviour. Production wiring happens in
// cmd/services.go alongside tokenService.SetProductSubscriptionResolver.
func (s *OAuthProviderService) SetProductSubscriptionResolver(resolver *ProductSubscriptionResolver) {
	s.productSubscriptionResolver = resolver
}

// idpSessionAuthTimeSource is the minimal interface generateTokens
// uses to resolve auth_time from an IdpSessionID. Decoupled from
// concrete pkg/redis.SessionCache so unit tests can inject a stub
// without dragging the full Redis client in.
type idpSessionAuthTimeSource interface {
	GetIdpSessionAuthTime(ctx context.Context, idpSessionID uuid.UUID) (int64, bool, error)
}

// SetSessionCacheAuthTimeSource wires the IdP session AuthTime
// lookup so /oauth/token-minted JWTs carry the RFC 9470 §6.1
// `auth_time` claim. Without this binding generateTokens silently
// dropped the claim and downstream RequireFreshAuth gates saw
// AuthTime=0 on every BFF-exchanged token. Safe to call with nil
// (disables auth_time emission — caller's responsibility to know
// that downstream freshness gates will fail closed).
func (s *OAuthProviderService) SetSessionCacheAuthTimeSource(src idpSessionAuthTimeSource) {
	s.sessionCache = src
}

// resolveAuthTimeForToken returns the Unix-second auth_time to stamp
// on an /oauth/token-minted access token.
//
// Source preference per RFC 9470 §6.1 / OIDC Core §2:
//
//  1. IdpSessionData.AuthTime (canonical — when the user actually
//     proved identity). Looked up via sessionCache when the
//     authorization code / refresh token carried an IdpSessionID.
//  2. now() fallback when the IdP session is missing — e.g. service
//     account / token-exchange paths where the upstream IdP has
//     already validated identity but no falcon_idp_session cookie
//     exists. Treating now() as auth_time in those paths means a
//     single freshness window from token issuance, which is the
//     conservative choice (RequireFreshAuth still gates by max_age
//     from the moment the token was minted).
//
// nil-safe: when sessionCache is unwired, returns now().Unix().
func (s *OAuthProviderService) resolveAuthTimeForToken(ctx context.Context, idpSessionID *uuid.UUID, now time.Time) int64 {
	if s.sessionCache == nil || idpSessionID == nil {
		return now.Unix()
	}
	authTime, ok, err := s.sessionCache.GetIdpSessionAuthTime(ctx, *idpSessionID)
	if err != nil || !ok || authTime == 0 {
		return now.Unix()
	}
	return authTime
}

// SetTenantTypeLookup wires the tenant repository for redirect_uri
// policy enforcement on CreateClient / UpdateClient. Without it the
// redirect-URI policy is silently skipped (matches legacy behaviour
// for unit tests that mock the service). Production wiring is the
// real TenantRepository, set in cmd/services.go.
func (s *OAuthProviderService) SetTenantTypeLookup(t tenantTypeLookup) {
	s.tenantTypeLookup = t
}

// sessionContextService is the minimum surface the OAuth refresh
// rotation flow needs to detect context drift and cut a fresh
// iam_sessions row when the inbound request no longer matches the
// session originally linked via IdpSessionID. AuthService satisfies
// this interface in production wiring (cmd/services.go).
//
// Defined as a local interface (not a concrete *AuthService) so the
// service avoids a circular dependency on the auth package AND so
// unit tests can substitute a stub without spinning up the full
// AuthService graph.
type sessionContextService interface {
	// GetSessionByID returns the iam_sessions row by primary key, or
	// nil when the row does not exist / is no longer active.
	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*models.Session, error)

	// CreateSessionFromRefresh cuts a new iam_sessions row for the
	// supplied user using the inbound /oauth/token request's context
	// (IP / UA / country / geo via ctx) and the auth-methods carried
	// forward from the rotating token. Returns the new session for
	// the caller to link via IdpSessionID on the rotated token.
	CreateSessionFromRefresh(ctx context.Context, userID uuid.UUID, authMethods []string) (*models.Session, error)
}

// SetSessionContextService wires the optional session-drift detector
// into the OAuth provider. nil-safe — unset = pre-drift-detection
// behaviour (token rotation preserves the original IdpSessionID
// verbatim regardless of whether the linked row exists). Production
// wiring is AuthService, set in cmd/services.go.
func (s *OAuthProviderService) SetSessionContextService(svc sessionContextService) {
	s.sessionContextSvc = svc
}

// osClassFromUA extracts a coarse OS-class label ("linux", "macos",
// "windows", "ios", "android", "unknown") from a User-Agent string.
// Used by RefreshTokens to detect OS-class drift across refresh-token
// rotation, which is the visible symptom users care about (e.g.
// "Chrome on macOS" lingering when the user is now on Chrome on
// Linux).
//
// Granularity is deliberately coarse — we DON'T compare full UA
// strings because Chrome / Edge / Safari auto-update bumps the
// version number weekly, which would cut a new session row on every
// browser-bump rotation (toast noise + audit-trail bloat). Only OS
// jumps (Linux ↔ macOS ↔ Windows etc.) signal a real device change.
//
// Matches the OS-detection order in the SPA's parseUserAgent (Linux
// must come AFTER Android because Android UAs also contain "Linux").
func osClassFromUA(ua string) string {
	if ua == "" {
		return "unknown"
	}
	lc := strings.ToLower(ua)
	switch {
	case strings.Contains(lc, "windows phone"):
		return "windows-phone"
	case strings.Contains(lc, "windows"):
		return "windows"
	case strings.Contains(lc, "ipad"):
		return "ipados"
	case strings.Contains(lc, "iphone"), strings.Contains(lc, "ipod"):
		return "ios"
	case strings.Contains(lc, "macintosh"), strings.Contains(lc, "mac os x"):
		return "macos"
	case strings.Contains(lc, "android"):
		return "android"
	case strings.Contains(lc, "cros"), strings.Contains(lc, "chromeos"):
		return "chromeos"
	case strings.Contains(lc, "linux"):
		return "linux"
	}
	return "unknown"
}

// SigningKeyInfo returns the OAuth provider's active signing key ID and public key.
// Used by the composite key resolver to validate self-issued tokens (Keycloak/Auth0 pattern).
func (s *OAuthProviderService) SigningKeyInfo() (keyID string, pubKey *rsa.PublicKey) {
	return s.keyID, s.publicKey
}

// SetKeyManager wires in the DB-backed key manager. When set, token signing uses the
// KeyManager's active key instead of the ephemeral key, and GetJWKS returns all
// active+rotated keys enabling clients to validate tokens issued before rotation.
func (s *OAuthProviderService) SetKeyManager(km *keys.KeyManager) {
	s.keyManager = km
	// Re-sync s.privateKey / s.publicKey / s.keyID from the active DB key so that
	// generateTokens (which references s.privateKey directly) works without further
	// changes to that method.
	if km == nil {
		return
	}
	signer, kid, err := km.ActiveKey()
	if err != nil {
		return
	}
	rsaKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return
	}
	s.privateKey = rsaKey
	s.publicKey = &rsaKey.PublicKey
	s.keyID = kid
}

// NewOAuthProviderService creates a new OAuthProviderService
func NewOAuthProviderService(
	clientRepo oauthProviderServiceClientRepo,
	userRepo oauthProviderServiceUserRepo,
	cfg *config.Config,
) (*OAuthProviderService, error) {
	svc := &OAuthProviderService{
		clientRepo: clientRepo,
		userRepo:   userRepo,
		cfg:        cfg,
		rarService: NewRARService(),
	}

	// Load or generate RSA key pair for signing
	if err := svc.loadOrGenerateKeys(); err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	return svc, nil
}

func (s *OAuthProviderService) loadOrGenerateKeys() error {
	// Try to load from environment or file
	privateKeyPEM := os.Getenv("OAUTH_RSA_PRIVATE_KEY")
	if privateKeyPEM == "" {
		// Try to load from file
		keyPath := os.Getenv("OAUTH_RSA_PRIVATE_KEY_FILE")
		if keyPath != "" {
			data, err := os.ReadFile(keyPath) //nolint:gosec // path is validated before use
			if err == nil {
				privateKeyPEM = string(data)
			}
		}
	}

	if privateKeyPEM != "" {
		key, err := parseOAuthRSAPrivateKey(privateKeyPEM)
		if err != nil {
			return err
		}
		if key != nil {
			s.privateKey = key
			s.publicKey = &key.PublicKey
		}
	}

	// Generate new key pair if not loaded
	if s.privateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		s.privateKey = key
		s.publicKey = &key.PublicKey
	}

	// Generate key ID from public key hash
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(s.publicKey)
	hash := sha256.Sum256(pubKeyBytes)
	s.keyID = base64.RawURLEncoding.EncodeToString(hash[:8])

	return nil
}

// parseOAuthRSAPrivateKey parses a PEM-encoded RSA private key (PKCS1 or PKCS8).
func parseOAuthRSAPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

// ==================== Client Management ====================

// validateOAuth21GrantsAndResponses enforces the OAuth 2.1 / BCP-225
// removal of the implicit flow and the Resource Owner Password
// Credentials grant (RFC 6749 §4.3 ROPC). Both are removed because:
//
//   - Implicit grant: tokens are returned in the URL fragment, leak via
//     browser history / Referer headers / server logs, can't be
//     PKCE-protected, and are no longer recommended for any flow per
//     draft-ietf-oauth-security-topics §2.1.2 + OAuth 2.1 §10.
//   - ROPC: the client handles the user's password directly, defeating
//     federation, blocking step-up MFA at the authentication step, and
//     normalising credential proxying. RFC 6749 §1.3.3 even said it was
//     "for legacy applications" — OAuth 2.1 §10.1 fully removes it.
//
// Returns an `invalid_client_metadata`-style error per RFC 7591 §3.2.2.
// Empty grant_types / response_types pass validation: callers (admin UI,
// XRD provisioner) can supply nothing and receive the per-client default
// downstream. The service-level check at /oauth/token (switch on
// req.GrantType with default → unsupported_grant_type) and at
// /oauth/authorize (containsString check on client.ResponseTypes) is
// the runtime backstop; this validator stops the bad value from ever
// landing in iam_oauth_clients.
func (s *OAuthProviderService) validateOAuth21GrantsAndResponses(grants, responseTypes []string) error {
	for _, g := range grants {
		switch g {
		case "password":
			return fmt.Errorf("invalid_client_metadata: grant_type 'password' (Resource Owner Password Credentials) is removed in OAuth 2.1 (BCP-225 / draft-ietf-oauth-v2-1 §10.1)")
		case "implicit":
			return fmt.Errorf("invalid_client_metadata: grant_type 'implicit' is removed in OAuth 2.1 (BCP-225 / draft-ietf-oauth-v2-1 §10.2)")
		}
	}
	// OAuth 2.1 retains only `code` (with PKCE). The composite
	// hybrid-flow types ("code id_token", "code token", "code id_token
	// token") implicitly include the implicit-flow `token` / `id_token`
	// part and are therefore rejected too.
	for _, rt := range responseTypes {
		// Tokenize on whitespace because composite response_types are
		// space-separated per OIDC Core 1.0 §3.
		for _, part := range strings.Fields(rt) {
			if part == "token" || part == "id_token" {
				return fmt.Errorf("invalid_client_metadata: response_type %q includes implicit-flow token return (only %q is conformant under OAuth 2.1)", rt, "code")
			}
		}
	}
	return nil
}

// CreateClient creates a new OAuth client
func (s *OAuthProviderService) CreateClient(ctx context.Context, tenantID uuid.UUID, req *models.CreateOAuthClientRequest, createdBy *uuid.UUID) (*models.OAuthClient, string, error) {
	if err := s.validateOAuth21GrantsAndResponses(req.GrantTypes, req.ResponseTypes); err != nil {
		return nil, "", err
	}
	// RFC 7591 §2 — validate registered branding URIs are HTTPS-only and
	// well-formed. Done up front so a bad URI rejects with a 400 before
	// any DB write. Same set of checks for create + update keeps the
	// invariant in one place.
	if err := validateBrandingURIs(req.LogoURL, req.ClientURI, req.TosURL, req.PolicyURL); err != nil {
		return nil, "", err
	}

	// Tier-1 redirect_uri policy: production-tier tenants reject http://
	// and loopback hosts; sandbox tenants (TenantTypeDemo) get the
	// developer-experience carve-out. tenantTypeLookup is optional so
	// unit tests that mock the service stay working without a tenant
	// repository.
	if s.tenantTypeLookup != nil && len(req.RedirectURIs) > 0 {
		tenant, err := s.tenantTypeLookup.GetByID(ctx, tenantID)
		if err != nil {
			return nil, "", fmt.Errorf("CreateClient: tenant lookup: %w", err)
		}
		// RFC 8252 native-app gate: a client qualifies for the loopback
		// carve-out iff it is PUBLIC (no client_secret), PKCE-required,
		// AND first-party (HexxLock-vouched). Third-party clients are
		// kept on the strict OAuth 2.1 rails — they go through the
		// normal sandbox-tenant path for any localhost dev work.
		nativeApp := req.IsPublic && req.RequirePKCE && req.IsFirstParty
		if err := validateRedirectURIs(tenant.Type, req.RedirectURIs, nativeApp); err != nil {
			return nil, "", fmt.Errorf("invalid_redirect_uri: %w", err)
		}
	}

	// Resolve the client_id: honor a caller-supplied value when present
	// (after format + uniqueness validation), otherwise generate one.
	// See CreateOAuthClientRequest.ClientID doc for rationale.
	clientID, err := s.resolveClientID(ctx, req.ClientID)
	if err != nil {
		return nil, "", err
	}

	var clientSecret string
	var secretHash string

	// Only confidential clients get a secret
	if !req.IsPublic {
		clientSecret, err = s.generateClientSecret()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate client secret: %w", err)
		}
		secretHash = s.hashSecret(clientSecret)
	}

	// Set defaults
	accessTokenLifetime := 3600 // 1 hour
	if req.AccessTokenLifetime != nil {
		accessTokenLifetime = *req.AccessTokenLifetime
	}

	refreshTokenLifetime := 2592000 // 30 days
	if req.RefreshTokenLifetime != nil {
		refreshTokenLifetime = *req.RefreshTokenLifetime
	}

	idTokenLifetime := 3600 // 1 hour
	if req.IDTokenLifetime != nil {
		idTokenLifetime = *req.IDTokenLifetime
	}

	tokenAuthMethod := "client_secret_basic"
	if req.TokenEndpointAuthMethod != "" {
		tokenAuthMethod = req.TokenEndpointAuthMethod
	}

	idTokenAlg := oauthAlgRS256
	if req.IDTokenSignedResponseAlg != "" {
		idTokenAlg = req.IDTokenSignedResponseAlg
	}

	// Coerce nil slices to empty slices for the columns that the
	// iam_oauth_clients schema declares NOT NULL with a DEFAULT '{}'.
	// The default only fires when the column is OMITTED from the INSERT;
	// passing an explicit NULL still violates the constraint. Bug 3
	// loosened the per-grant validator on redirect_uris/response_types
	// (RFC 6749 §3.1.2 — they don't apply to client_credentials), but
	// the storage layer kept the strict shape, so client_credentials
	// inserts hit `null value in column "redirect_uris" ... violates
	// not-null constraint`. Empty arrays preserve the schema invariant
	// and round-trip cleanly through the OIDC discovery responses.
	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	// Derive response_types from grant_types when the caller omits
	// the field (RFC 7591 §2 leaves it optional with a sensible default
	// per grant). authorization_code → ["code"], implicit → ["token",
	// "id_token"]; otherwise empty. This avoids forcing every caller
	// (provisioner, UI, registration scripts) to repeat the mapping.
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		derived := make([]string, 0, 2)
		for _, g := range req.GrantTypes {
			switch g {
			case "authorization_code":
				if !slices.Contains(derived, "code") {
					derived = append(derived, "code")
				}
			case "implicit":
				if !slices.Contains(derived, "token") {
					derived = append(derived, "token")
				}
				if !slices.Contains(derived, "id_token") {
					derived = append(derived, "id_token")
				}
			}
		}
		responseTypes = derived
	}
	if responseTypes == nil {
		responseTypes = []string{}
	}

	now := time.Now()
	client := &models.OAuthClient{
		ID:                       uuid.New(),
		TenantID:                 tenantID,
		ClientID:                 clientID,
		ClientSecret:             secretHash,
		Name:                     req.Name,
		Description:              req.Description,
		GrantTypes:               req.GrantTypes,
		ResponseTypes:            responseTypes,
		RedirectURIs:             redirectURIs,
		Scopes:                   req.Scopes,
		AccessTokenLifetime:      accessTokenLifetime,
		RefreshTokenLifetime:     refreshTokenLifetime,
		IDTokenLifetime:          idTokenLifetime,
		IsPublic:                 req.IsPublic,
		IsConfidential:           req.IsConfidential,
		IsFirstParty:             req.IsFirstParty,
		RequirePKCE:              req.RequirePKCE,
		IsActive:                 true,
		LogoURL:                  req.LogoURL,
		ClientURI:                req.ClientURI,
		TosURL:                   req.TosURL,
		PolicyURL:                req.PolicyURL,
		ContactEmail:             req.ContactEmail,
		Contacts:                 req.Contacts,
		TokenEndpointAuthMethod:  tokenAuthMethod,
		IDTokenSignedResponseAlg: idTokenAlg,
		PostLogoutRedirectURIs:   req.PostLogoutRedirectURIs,
		AllowedCORSOrigins:       req.AllowedCORSOrigins,
		BackchannelLogoutURI:     req.BackchannelLogoutURI,
		FrontchannelLogoutURI:    req.FrontchannelLogoutURI,
		// FAPI 2.0 Baseline / RFC 9126 §2.1: per-client PAR mandate.
		RequirePushedAuthorizationRequests: req.RequirePushedAuthorizationRequests,
		// RFC 8693 :jwt token-exchange permission (v0.232.237) — gates
		// the external-IdP bridge path. Deny-by-default per the request
		// shape's zero-value.
		AllowExternalJWTExchange: req.AllowExternalJWTExchange,
		CreatedAt:                now,
		UpdatedAt:                now,
		CreatedBy:                createdBy,
	}

	if err := s.clientRepo.Create(ctx, client); err != nil {
		return nil, "", fmt.Errorf("CreateClient: %w", err)
	}

	return client, clientSecret, nil
}

// resolveClientID picks a client_id for a new OAuth client. When the
// caller supplies one, validate format + uniqueness and use it. When
// the caller leaves it nil/empty, generate a random one. The provisioner
// contract relies on this — its Vault entry is keyed by the requested
// id (`svc-<service>`) and assumes the DB row matches.
//
// Returns ErrClientIDConflict (HTTP-mappable to 409) when the requested
// id is already taken — callers should rotate the existing client's
// secret via RegenerateClientSecret rather than re-create.
func (s *OAuthProviderService) resolveClientID(ctx context.Context, requested *string) (string, error) {
	if requested == nil || *requested == "" {
		generated, err := s.generateClientID()
		if err != nil {
			return "", fmt.Errorf("failed to generate client ID: %w", err)
		}
		return generated, nil
	}
	candidate := *requested
	if !validClientID(candidate) {
		return "", fmt.Errorf("invalid_client_metadata: client_id must be 1-128 chars matching [a-zA-Z0-9._-] and start with an alphanumeric")
	}
	existing, err := s.clientRepo.GetByClientID(ctx, candidate)
	if err == nil && existing != nil {
		return "", fmt.Errorf("%w: client_id %q is already registered", ErrClientIDConflict, candidate)
	}
	// "not found" is the success path; any other repo error is fatal.
	// The repo layer wraps not-found in pgx.ErrNoRows-derived errors —
	// callers historically check `err != nil && !errors.Is(err, sql.ErrNoRows)`,
	// but here we accept any error from GetByClientID as "available" because
	// the subsequent INSERT will fail loud-and-clear if the DB itself is down.
	return candidate, nil
}

// validClientID enforces a strict, conservative format: 1-128 chars,
// alphanumeric / dot / hyphen / underscore, must start with an alnum.
// Loose enough to fit existing platform conventions like
// `svc-accounts`, `svc-db-provisioner`, `harbor.system`, but tight
// enough to keep the value safe in URL paths (regenerate-secret takes
// it as a path segment).
func validClientID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	if !isAlnumByte(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlnumByte(c) && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// isAlnumByte returns true for ASCII alphanumerics. Extracted from
// validClientID to keep that function's predicate flat (avoids
// staticcheck QF1001 De-Morgan suggestions and keeps the conditions
// readable as positive assertions).
func isAlnumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// GetClient retrieves an OAuth client by ID
func (s *OAuthProviderService) GetClient(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error) {
	return s.clientRepo.GetByID(ctx, id)
}

// GetClientByClientID retrieves an OAuth client by client_id string
func (s *OAuthProviderService) GetClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	return s.clientRepo.GetByClientID(ctx, clientID)
}

// ListClients lists OAuth clients for a tenant
func (s *OAuthProviderService) ListClients(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.OAuthClient, int64, error) {
	return s.clientRepo.GetByTenantID(ctx, tenantID, page, pageSize)
}

// UpdateClient updates an OAuth client
func (s *OAuthProviderService) UpdateClient(ctx context.Context, id uuid.UUID, req *models.UpdateOAuthClientRequest, updatedBy *uuid.UUID) (*models.OAuthClient, error) {
	// IAM-04: OAuth 2.1 grant_types / response_types validation. Empty
	// slices in the update request mean "no change" (see the
	// `len(req.X) > 0` guards below) — only validate non-empty ones.
	if len(req.GrantTypes) > 0 || len(req.ResponseTypes) > 0 {
		if err := s.validateOAuth21GrantsAndResponses(req.GrantTypes, req.ResponseTypes); err != nil {
			return nil, err
		}
	}
	// RFC 7591 §2 — validate the URIs the caller is updating. Pointer
	// fields that are nil mean "no change" — validateBrandingURIs
	// short-circuits on nil so unchanged fields don't trip on legacy
	// rows that pre-date the validator.
	if err := validateBrandingURIs(req.LogoURL, req.ClientURI, req.TosURL, req.PolicyURL); err != nil {
		return nil, err
	}

	client, err := s.clientRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("UpdateClient: %w", err)
	}

	// Tier-1 redirect_uri policy on update. Only validate when the
	// caller is actually changing the URI list — an absent / empty
	// slice means "no change" per the DTO contract. The tenant type
	// comes from the existing client's tenant_id since the request
	// can't change ownership.
	if s.tenantTypeLookup != nil && len(req.RedirectURIs) > 0 {
		tenant, terr := s.tenantTypeLookup.GetByID(ctx, client.TenantID)
		if terr != nil {
			return nil, fmt.Errorf("UpdateClient: tenant lookup: %w", terr)
		}
		// RFC 8252 native-app gate — read from the live client record
		// since UpdateClient can't change these traits. Same condition
		// as CreateClient: public + PKCE + first-party.
		nativeApp := client.IsPublic && client.RequirePKCE && client.IsFirstParty
		if verr := validateRedirectURIs(tenant.Type, req.RedirectURIs, nativeApp); verr != nil {
			return nil, fmt.Errorf("invalid_redirect_uri: %w", verr)
		}
	}

	// Apply updates
	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.Description != nil {
		client.Description = req.Description
	}
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = req.GrantTypes
	}
	if len(req.ResponseTypes) > 0 {
		client.ResponseTypes = req.ResponseTypes
	}
	if len(req.RedirectURIs) > 0 {
		client.RedirectURIs = req.RedirectURIs
	}
	if len(req.Scopes) > 0 {
		client.Scopes = req.Scopes
	}
	if req.AccessTokenLifetime != nil {
		client.AccessTokenLifetime = *req.AccessTokenLifetime
	}
	if req.RefreshTokenLifetime != nil {
		client.RefreshTokenLifetime = *req.RefreshTokenLifetime
	}
	if req.IDTokenLifetime != nil {
		client.IDTokenLifetime = *req.IDTokenLifetime
	}
	if req.IsPublic != nil {
		client.IsPublic = *req.IsPublic
	}
	if req.IsConfidential != nil {
		client.IsConfidential = *req.IsConfidential
	}
	if req.IsFirstParty != nil {
		client.IsFirstParty = *req.IsFirstParty
	}
	if req.RequirePKCE != nil {
		client.RequirePKCE = *req.RequirePKCE
	}
	if req.IsActive != nil {
		client.IsActive = *req.IsActive
	}
	// FAPI 2.0 Baseline / RFC 9126 §2.1: per-client PAR mandate.
	if req.RequirePushedAuthorizationRequests != nil {
		client.RequirePushedAuthorizationRequests = *req.RequirePushedAuthorizationRequests
	}
	// RFC 8693 :jwt token-exchange permission (v0.232.237) — pointer
	// shape so omission means "no change", explicit false means
	// "revoke the permission".
	if req.AllowExternalJWTExchange != nil {
		client.AllowExternalJWTExchange = *req.AllowExternalJWTExchange
	}
	if req.LogoURL != nil {
		client.LogoURL = req.LogoURL
	}
	if req.ClientURI != nil {
		client.ClientURI = req.ClientURI
	}
	if req.TosURL != nil {
		client.TosURL = req.TosURL
	}
	if req.PolicyURL != nil {
		client.PolicyURL = req.PolicyURL
	}
	if req.ContactEmail != nil {
		client.ContactEmail = req.ContactEmail
	}
	if len(req.Contacts) > 0 {
		client.Contacts = req.Contacts
	}
	if req.TokenEndpointAuthMethod != nil {
		client.TokenEndpointAuthMethod = *req.TokenEndpointAuthMethod
	}
	if req.IDTokenSignedResponseAlg != nil {
		client.IDTokenSignedResponseAlg = *req.IDTokenSignedResponseAlg
	}
	if len(req.PostLogoutRedirectURIs) > 0 {
		client.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	}
	if len(req.AllowedCORSOrigins) > 0 {
		client.AllowedCORSOrigins = req.AllowedCORSOrigins
	}
	if req.BackchannelLogoutURI != nil {
		client.BackchannelLogoutURI = req.BackchannelLogoutURI
	}
	if req.FrontchannelLogoutURI != nil {
		client.FrontchannelLogoutURI = req.FrontchannelLogoutURI
	}

	client.UpdatedAt = time.Now()
	client.UpdatedBy = updatedBy

	if err := s.clientRepo.Update(ctx, client); err != nil {
		return nil, fmt.Errorf("UpdateClient: %w", err)
	}

	return client, nil
}

// DeleteClient deletes an OAuth client
func (s *OAuthProviderService) DeleteClient(ctx context.Context, id uuid.UUID) error {
	return s.clientRepo.Delete(ctx, id)
}

// RegenerateClientSecret regenerates the client secret
func (s *OAuthProviderService) RegenerateClientSecret(ctx context.Context, id uuid.UUID) (string, error) {
	client, err := s.clientRepo.GetByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("RegenerateClientSecret: %w", err)
	}

	if client.IsPublic {
		return "", fmt.Errorf("public clients do not have secrets")
	}

	newSecret, err := s.generateClientSecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate client secret: %w", err)
	}

	secretHash := s.hashSecret(newSecret)
	if err := s.clientRepo.UpdateSecret(ctx, id, secretHash); err != nil {
		return "", fmt.Errorf("RegenerateClientSecret: %w", err)
	}

	return newSecret, nil
}

// ==================== Authorization Flow ====================

// ValidateAuthorizeRequest validates an authorization request
func (s *OAuthProviderService) ValidateAuthorizeRequest(ctx context.Context, req *models.OAuthAuthorizeRequest) (*models.OAuthClient, error) {
	// Get client. Differentiate a legitimate "no such client_id" (RFC 6749
	// §5.2 invalid_client, returned with the canonical wire message) from
	// any underlying DB / pool / pgx failure — those need a structured
	// log line at ERROR level so future incidents are diagnosable from
	// the falcon-id pod's own logs rather than only from PG-side traces.
	client, err := s.clientRepo.GetByClientID(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, repositories.ErrOAuthClientNotFound) {
			return nil, fmt.Errorf("invalid_client: client not found")
		}
		logger.Error("OAuth client lookup failed in ValidateAuthorizeRequest",
			zap.Error(err),
			zap.String("client_id", req.ClientID),
		)
		return nil, fmt.Errorf("invalid_client: %w", err)
	}

	if !client.IsActive {
		return nil, fmt.Errorf("invalid_client: client is not active")
	}

	// Validate response type
	if !s.containsString(client.ResponseTypes, req.ResponseType) {
		return nil, fmt.Errorf("unsupported_response_type: %s is not allowed for this client", req.ResponseType)
	}

	// Validate redirect URI. matchRedirectURI does exact-string match
	// for non-loopback URIs and port-fuzzy match for loopback URIs
	// (127.0.0.1 / ::1 / localhost), per RFC 8252 §7.3.
	if !matchRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return nil, fmt.Errorf("invalid_request: redirect_uri is not registered for this client")
	}

	// OAuth 2.1 PKCE policy — per-client, spec-aligned.
	//
	// draft-ietf-oauth-v2-1 §4.1.1: PKCE is REQUIRED for public clients
	// (no client_secret) and RECOMMENDED for confidential clients that
	// already authenticate to the token endpoint with a client_secret.
	// The previous revision enforced PKCE unconditionally, which blocks
	// confidential clients that don't attach code_challenge (e.g. Pomerium
	// v0.32 ingress-controller with a confidential OAuth client — observed
	// 2026-04-24 on the tier-1 admin-tier rollout).
	//
	// Policy:
	//   - Public clients (IsPublic):              PKCE MANDATORY
	//   - Clients with explicit RequirePKCE=true: PKCE MANDATORY
	//   - Confidential clients (default):         PKCE OPTIONAL
	//                                             (S256 still enforced on
	//                                              code_challenge_method if
	//                                              caller does send one)
	pkceRequired := client.IsPublic || client.RequirePKCE
	if pkceRequired && req.CodeChallenge == "" {
		return nil, fmt.Errorf("invalid_request: code_challenge is required for this client (PKCE)")
	}
	if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != oauthAlgS256 {
		return nil, fmt.Errorf("invalid_request: only S256 code_challenge_method is supported")
	}

	// Validate requested scopes
	requestedScopes := strings.Split(req.Scope, " ")
	for _, scope := range requestedScopes {
		if scope != "" && !s.containsString(client.Scopes, scope) && !s.isStandardScope(scope) {
			return nil, fmt.Errorf("invalid_scope: %s is not allowed for this client", scope)
		}
	}

	// Validate RAR authorization_details if present (RFC 9396 §7).
	if req.AuthorizationDetails != "" {
		details, err := s.rarService.ParseAuthorizationDetails(req.AuthorizationDetails)
		if err != nil {
			return nil, err
		}
		if err := s.rarService.ValidateAgainstClient(details, *client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// CreateAuthorizationCode creates an authorization code for the user
func (s *OAuthProviderService) CreateAuthorizationCode(ctx context.Context, client *models.OAuthClient, userID uuid.UUID, req *models.OAuthAuthorizeRequest) (string, error) {
	// Generate authorization code
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	// Parse scopes
	scopes := strings.Split(req.Scope, " ")

	// Parse and validate RAR authorization_details (RFC 9396 §3).
	// ValidateAuthorizeRequest has already validated these; re-parse here so
	// the authorisation code carries the structured details to the token step.
	rarDetails, err := s.rarService.ParseAuthorizationDetails(req.AuthorizationDetails)
	if err != nil {
		return "", fmt.Errorf("CreateAuthorizationCode: %w", err)
	}

	now := time.Now()
	authCode := &models.OAuthAuthorizationCode{
		ID:                   uuid.New(),
		TenantID:             client.TenantID,
		ClientID:             client.ID,
		UserID:               userID,
		Code:                 s.hashSecret(code),
		RedirectURI:          req.RedirectURI,
		Scopes:               scopes,
		State:                &req.State,
		Nonce:                &req.Nonce,
		CodeChallenge:        &req.CodeChallenge,
		CodeChallengeMethod:  &req.CodeChallengeMethod,
		AuthorizationDetails: rarDetails,
		IsUsed:               false,
		ExpiresAt:            now.Add(10 * time.Minute), // 10 minute expiry
		CreatedAt:            now,
		// Snapshot the session's RFC 8176 authentication methods so id_tokens
		// derived from this code carry a stable `amr` regardless of later
		// session mutation (Okta / RFC 8176 behaviour — not Auth0's default).
		AuthMethodsUsed: append([]string(nil), req.AuthMethodsUsed...),
		// Snapshot the IdP session UUID so id_tokens derived from this code
		// (and from refresh-token rotations of those tokens) emit a stable
		// `sid` claim (OIDC Session Management 1.0 §5; migration 220).
		IdpSessionID: req.IdpSessionID,
	}

	if err := s.clientRepo.CreateAuthorizationCode(ctx, authCode); err != nil {
		return "", fmt.Errorf("CreateAuthorizationCode: %w", err)
	}

	return code, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
// The trailing string is a deprecated dpopJKT param; the canonical
// path threads the JKT via context (services.WithDPoPJKT) so callers
// don't need to update their call sites. Argument retained as `_` for
// signature stability across existing call sites + tests.
func (s *OAuthProviderService) ExchangeAuthorizationCode(ctx context.Context, client *models.OAuthClient, code, redirectURI, codeVerifier, _ string) (*models.OAuthTokenResponse, error) {
	// Find and validate authorization code
	codeHash := s.hashSecret(code)
	authCode, err := s.clientRepo.GetAuthorizationCode(ctx, codeHash)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: authorization code not found or expired")
	}

	// Validate code
	if authCode.IsUsed {
		return nil, fmt.Errorf("invalid_grant: authorization code has already been used")
	}

	if authCode.IsExpired() {
		return nil, fmt.Errorf("invalid_grant: authorization code has expired")
	}

	if authCode.ClientID != client.ID {
		return nil, fmt.Errorf("invalid_grant: authorization code was not issued to this client")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("invalid_grant: redirect_uri does not match")
	}

	// Validate PKCE
	if authCode.CodeChallenge != nil && *authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, fmt.Errorf("invalid_grant: code_verifier is required")
		}

		method := oauthAlgS256
		if authCode.CodeChallengeMethod != nil && *authCode.CodeChallengeMethod != "" {
			method = *authCode.CodeChallengeMethod
		}

		if !s.verifyCodeChallenge(*authCode.CodeChallenge, codeVerifier, method) {
			return nil, fmt.Errorf("invalid_grant: code_verifier is invalid")
		}
	}

	// Get user for ID token. This is a read and no code has been consumed yet,
	// so a lookup failure here leaves the code usable for a retry.
	user, err := s.userRepo.GetByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// RFC 9449 §6 — sender-constrain enforcement at issuance.
	// Sensitive scopes (admin:* / offline_access) MUST be issued only
	// with a DPoP-bound token. The auth-code scope was decided at
	// /authorize time; a misconfigured RP that requested admin:* but
	// didn't send a DPoP proof at /token rates as broken-by-design and
	// gets a deterministic rejection here instead of an unbound
	// access token. Checked BEFORE the code is consumed so a broken request
	// doesn't burn the code (and doesn't even open a transaction).
	if s.cfg.DPoPEnabled && scopeRequiresDPoP(authCode.Scopes) && dpopJKTFromContext(ctx) == "" {
		return nil, ErrDPoPRequired
	}

	// Transactional code consumption (2026-07-21 migration-gap remediation,
	// Fix B). The pre-fix path marked the code used with an independent,
	// already-committed UPDATE and only THEN generated + persisted the token;
	// when the token write failed (migration 0009's token_family_id column was
	// missing fleet-wide) the code was permanently burned, turning a transient
	// failure into a hard "authorization code already used" for that login.
	//
	// We instead run the mark-used CAS and the refresh/access-token INSERT
	// inside ONE transaction and commit only after generateTokens fully
	// succeeds. On any failure the deferred rollback restores is_used = false so
	// the client can retry the SAME code (recoverable, not catastrophic).
	// Single-use is still guaranteed: the CAS (UPDATE ... WHERE is_used = false)
	// is row-locked, so a concurrent second exchange that commits first makes
	// this one's CAS report a loss.
	tx, err := s.clientRepo.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin token exchange: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	won, err := tx.MarkAuthorizationCodeUsedCAS(ctx, authCode.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}
	if !won {
		// Lost the CAS: another exchange already consumed this code and
		// committed. Preserve the exact wire error the fast-path check emits.
		return nil, fmt.Errorf("invalid_grant: authorization code has already been used")
	}

	// Generate tokens, carrying forward any RAR details, the RFC 8176
	// authentication methods, and the IdP session UUID bound to the code. The
	// token-row INSERT runs on tx so it is atomic with the mark-used above; a
	// failure here triggers the deferred rollback and leaves the code usable.
	resp, err := s.generateTokensWithSink(ctx, tx, client, user, authCode.Scopes, authCode.Nonce, authCode.AuthorizationDetails, authCode.AuthMethodsUsed, authCode.IdpSessionID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit token exchange: %w", err)
	}
	committed = true
	return resp, nil
}

// RefreshTokens refreshes access and refresh tokens.
// The trailing string is a deprecated dpopJKT param; the canonical
// path threads the JKT via context (services.WithDPoPJKT). Argument
// retained as `_` for signature stability.
// refreshReuseGraceWindow is the leeway during which a re-presented, freshly
// revoked refresh token is treated as a benign concurrent double-submit rather
// than an attacker replay (Auth0 "leeway" / Okta "grace period" — both default
// to ~10s). Rotation on a busy SPA can legitimately race two refreshes; the
// atomic CAS lets exactly one win, and this window keeps the millisecond-late
// loser from tripping a full family revoke. A replay older than this is an
// older-generation token and trips RFC 9700 §4.14 reuse handling.
const refreshReuseGraceWindow = 10 * time.Second

func (s *OAuthProviderService) RefreshTokens(ctx context.Context, client *models.OAuthClient, refreshToken, _ string) (*models.OAuthTokenResponse, error) {
	// Find refresh token
	tokenHash := s.hashSecret(refreshToken)
	token, err := s.clientRepo.GetOAuthTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: refresh token not found")
	}

	// RFC 9700 §4.14.2 — refresh-token reuse detection. A presented refresh
	// token that is ALREADY revoked is the theft signal: under rotation a
	// prior legitimate rotation already consumed this token and advanced the
	// lineage past it, so a second presentation is a REPLAY of a stale copy —
	// classically an attacker who exfiltrated a refresh token racing the real
	// client. Revoke the ENTIRE token family and emit a CAEP token-theft
	// signal so every RP with a session descended from the grant tears it
	// down.
	//
	// GRACE WINDOW (Auth0 "leeway" / Okta "grace period"): a revoked token
	// re-presented within refreshReuseGraceWindow of its revocation is almost
	// certainly a BENIGN concurrent double-submit — an SPA firing two
	// refreshes at once, or a transparently retried request — whose sibling
	// won the atomic CAS and rotated it milliseconds ago. Treat that as a
	// benign race: fail closed with invalid_grant but do NOT revoke the
	// family (counted as AuthTokenConcurrentRace, not AuthTokenReuseDetected).
	// Only a replay OUTSIDE the window is an older-generation attacker replay
	// that trips the full family revoke + CAEP theft signal.
	//
	// Reuse-policy (BFF) tokens are intentionally never rotated/revoked, so an
	// is_revoked row there can only be an explicit admin/compromise sweep —
	// treat that as a plain invalid_grant, never a theft.
	if token.IsRevoked {
		if client.RefreshTokenRotationPolicy != "reuse" {
			if token.RevokedAt != nil && time.Since(*token.RevokedAt) <= refreshReuseGraceWindow {
				metrics.AuthTokenConcurrentRace.Inc()
				return nil, fmt.Errorf("invalid_grant: refresh token already consumed")
			}
			s.handleRefreshTokenReuse(ctx, token)
		}
		return nil, fmt.Errorf("invalid_grant: refresh token has been revoked")
	}

	if token.IsExpired() {
		return nil, fmt.Errorf("invalid_grant: refresh token has expired")
	}

	if token.ClientID != client.ID {
		return nil, fmt.Errorf("invalid_grant: refresh token was not issued to this client")
	}

	// Branch on the client's RefreshTokenRotationPolicy (migration 242).
	//
	//   "rotate" (default) — canonical OAuth 2.0 / Public-Client
	//     semantics: revoke the inbound refresh_token; generateTokens
	//     mints a fresh pair.
	//
	//   "reuse"           — Duende BFF / IETF draft-ietf-oauth-first-
	//     party-apps semantics for CONFIDENTIAL first-party BFFs: do
	//     NOT revoke the inbound refresh_token, and stash it on the
	//     ctx so generateTokens returns the same plaintext alongside a
	//     freshly-minted access_token. Closes the cross-pod parallel-
	//     refresh revoke-the-old race observed on falcon.ops sessions
	//     (2026-05-14). Safe only because the BFF holds the refresh
	//     in a server-side __Host- cookie the browser cannot read;
	//     the per-client opt-in is enforced at the DB CHECK constraint
	//     and at the seed-update gate (only the six svc-*-bff clients
	//     are flipped, every other client stays rotate).
	// RFC 9700 §4.14 family lineage to propagate onto the rotated (or reused)
	// token so the whole chain stays revocable as one unit. Fall back to the
	// token's own id for pre-migration rows whose family was never stamped.
	familyID := token.ID
	if token.TokenFamilyID != nil {
		familyID = *token.TokenFamilyID
	}
	ctx = WithRefreshTokenFamily(ctx, familyID)

	if client.RefreshTokenRotationPolicy == "reuse" {
		ctx = WithReuseRefreshToken(ctx, refreshToken)
	} else {
		// RFC 9700 §4.14.2 — atomic compare-and-swap consume. The revoked
		// check and the consumption are a SINGLE atomic UPDATE so two
		// concurrent redemptions of this same live token cannot both proceed
		// and fork the family. Exactly one wins (rowcount 1); every loser
		// gets rowcount 0 and fails closed with invalid_grant WITHOUT
		// revoking the family — a lost race is not a theft (the token was
		// live, it merely arrived second). The benign-race counter is
		// deliberately separate from the theft counter so dashboards don't
		// page OnCall on client-side coordination gaps.
		won, consumeErr := s.clientRepo.ConsumeRefreshToken(ctx, token.ID)
		if consumeErr != nil {
			return nil, fmt.Errorf("failed to consume refresh token: %w", consumeErr)
		}
		if !won {
			metrics.AuthTokenConcurrentRace.Inc()
			return nil, fmt.Errorf("invalid_grant: refresh token already consumed")
		}
	}

	// Get user if token has a user
	var user *models.User
	if token.UserID != nil {
		user, err = s.userRepo.GetByID(ctx, *token.UserID)
		if err != nil {
			return nil, fmt.Errorf("user not found: %w", err)
		}
	}

	// RFC 9449 §6.5 — refresh-token rotation MUST keep the binding.
	// If the original access token's scope set requires DPoP, the
	// rotation MUST also be DPoP-bound. (Cnf-jkt carry-through across
	// rotation — same key the original token used — is a separate
	// follow-up; today we accept any valid proof on the rotation.
	// Receivers still verify on each API call via VerifyTokenBinding,
	// so a rotation done with an attacker key issues a token that
	// won't actually verify against the original binding.)
	if s.cfg.DPoPEnabled && scopeRequiresDPoP(token.Scopes) && dpopJKTFromContext(ctx) == "" {
		return nil, ErrDPoPRequired
	}

	// OpenID CAEP §5.3 — emit CAEIPChanged when the new request's IP
	// differs from the IP stamped on the prior token. CAEP is signal,
	// not enforcement: receivers (Talon IAP, SIEM) decide whether to
	// revoke. Best-effort; never fail the refresh on publisher errors.
	// Skips silently when the prior token has no IP captured (pre-fix
	// rows) or when the current request did not flow through ctx
	// (background callers).
	if s.caeService != nil && token.IPAddress != nil && *token.IPAddress != "" {
		newIP := requestIPFromContext(ctx)
		if newIP != "" && newIP != *token.IPAddress {
			userID := uuid.Nil
			if token.UserID != nil {
				userID = *token.UserID
			}
			_ = s.caeService.OnIPChanged(ctx, userID, token.TenantID, *token.IPAddress, newIP, token.IdpSessionID)
		}
	}

	// Session-row drift detection (Auth0 / Okta / Entra canonical
	// pattern; internal engineering notes research).
	//
	// iam_sessions rows are IMMUTABLE on UA/IP/geo after creation. The
	// "Active Sessions" tab in accounts.hexxlock.com reads from this
	// table and a stale-context row produces the user-visible "Chrome
	// on macOS" symptom for someone currently on Chrome on Linux.
	//
	// Cut a new iam_sessions row (and re-link it via the rotated
	// token's IdpSessionID) when ANY of:
	//   1. The linked session no longer exists, OR
	//   2. The linked session is no longer active (ended / expired), OR
	//   3. The current request's CF-IPCountry differs from the
	//      session's country_code, OR
	//   4. The current request's UA OS-class differs from the session's
	//      stored UA OS-class.
	//
	// nil-safe: when sessionContextSvc is unwired (test / minimal
	// build) the rotation preserves the old IdpSessionID verbatim
	// (legacy behaviour).
	idpSessionIDForRotation := token.IdpSessionID
	if s.sessionContextSvc != nil && user != nil && token.IdpSessionID != nil {
		drift, reason := s.detectSessionDrift(ctx, *token.IdpSessionID)
		if drift {
			newSession, sessionErr := s.sessionContextSvc.CreateSessionFromRefresh(ctx, user.ID, token.AuthMethodsUsed)
			if sessionErr != nil {
				// Best-effort — don't fail the refresh on a session-cut
				// error. The user still gets rotated tokens; the
				// Active-Sessions UI will continue showing the stale
				// row. Surface to telemetry so we notice if it spikes.
				if s.claimsLogger != nil {
					s.claimsLogger.Warn("refresh-token rotation: failed to cut new session row on drift",
						zap.String("user_id", user.ID.String()),
						zap.String("drift_reason", reason),
						zap.Error(sessionErr))
				}
			} else {
				newID := newSession.ID
				idpSessionIDForRotation = &newID
				if s.claimsLogger != nil {
					s.claimsLogger.Info("refresh-token rotation: cut new session row on context drift",
						zap.String("user_id", user.ID.String()),
						zap.String("drift_reason", reason),
						zap.String("old_session_id", token.IdpSessionID.String()),
						zap.String("new_session_id", newID.String()))
				}
			}
		}
	}

	// Generate new tokens (refresh does not re-attach RAR details; the resource server
	// should re-authorise if fresh authorization_details are needed). The RFC 8176
	// authentication-method references are preserved from the prior token; the IdP
	// session UUID either passes through unchanged (no drift) or points at the
	// newly-cut session row (drift detected above) so id_tokens issued through
	// this rotation carry the correct `sid` claim for FCL/BCL cascades
	// (migration 220).
	return s.generateTokens(ctx, client, user, token.Scopes, nil, nil, token.AuthMethodsUsed, idpSessionIDForRotation)
}

// handleRefreshTokenReuse executes the RFC 9700 §4.14.2 response to a detected
// refresh-token replay: revoke the ENTIRE token family and emit a CAEP
// token-theft signal so subscribing relying parties terminate every session
// descended from the compromised grant.
//
// Ordering is deliberate — the token store is the source of truth, so the
// family revoke happens FIRST and its failure is loud but non-fatal to the
// caller (the caller returns invalid_grant regardless, so the replayed token
// never yields new tokens). The CAEP emission is best-effort: it only
// accelerates downstream session teardown; a publish failure degrades to the
// next introspection/refresh catching the now-revoked family.
func (s *OAuthProviderService) handleRefreshTokenReuse(ctx context.Context, token *models.OAuthToken) {
	metrics.AuthTokenReuseDetected.Inc()

	familyID := token.ID
	if token.TokenFamilyID != nil {
		familyID = *token.TokenFamilyID
	}

	revoked, err := s.clientRepo.RevokeRefreshTokenFamily(ctx, familyID)
	if err != nil {
		if s.claimsLogger != nil {
			s.claimsLogger.Error("refresh-token REUSE detected — failed to revoke token family (RFC 9700 §4.14)",
				zap.String("family_id", familyID.String()),
				zap.String("token_id", token.ID.String()),
				zap.Error(err))
		}
	} else if s.claimsLogger != nil {
		s.claimsLogger.Warn("refresh-token REUSE detected — revoked token family (RFC 9700 §4.14)",
			zap.String("family_id", familyID.String()),
			zap.String("token_id", token.ID.String()),
			zap.Int64("tokens_revoked", revoked))
	}

	// Emit the CAEP token-theft signal so RPs tear down live sessions now.
	if s.caeService != nil && token.UserID != nil {
		if err := s.caeService.OnRefreshTokenReuse(ctx, *token.UserID, token.TenantID, familyID, token.IdpSessionID); err != nil && s.claimsLogger != nil {
			s.claimsLogger.Warn("refresh-token reuse: CAEP theft signal publish failed (family already revoked)",
				zap.String("family_id", familyID.String()),
				zap.Error(err))
		}
	}
}

// detectSessionDrift returns true (with a short reason label) when the
// /oauth/token rotation's request context no longer matches the
// session row that the inbound refresh-token was originally linked
// to. Reason labels: "session_missing", "session_inactive",
// "country_drift", "os_class_drift".
//
// Called only when sessionContextSvc is wired. Errors looking up the
// session are treated as "session_missing" — fail safe by cutting a
// new row rather than zombie-ing an unverifiable one.
func (s *OAuthProviderService) detectSessionDrift(ctx context.Context, sessionID uuid.UUID) (bool, string) {
	session, err := s.sessionContextSvc.GetSessionByID(ctx, sessionID)
	if err != nil || session == nil {
		return true, "session_missing"
	}
	if !session.IsActive {
		return true, "session_inactive"
	}

	// Country drift — only meaningful when both sides have a value.
	// CF-IPCountry on every CF-routed request (free tier); session's
	// country_code stamped at creation (mig v0.232.245).
	currentCountry := strings.ToUpper(clientctx.CountryFromContext(ctx))
	if currentCountry != "" && session.CountryCode != nil && *session.CountryCode != "" {
		if strings.ToUpper(*session.CountryCode) != currentCountry {
			return true, "country_drift"
		}
	}

	// OS-class drift — coarse comparison (linux vs macos vs windows
	// etc.) to avoid cutting new rows on weekly Chrome auto-update
	// version bumps. Only triggers when both sides have a UA.
	currentUA := requestUserAgentFromContext(ctx)
	if currentUA != "" && session.UserAgent != nil && *session.UserAgent != "" {
		if osClassFromUA(currentUA) != osClassFromUA(*session.UserAgent) {
			return true, "os_class_drift"
		}
	}

	return false, ""
}

// ClientCredentialsGrant handles the client_credentials grant type.
// The trailing string is a deprecated dpopJKT param; the canonical
// path threads the JKT via context (services.WithDPoPJKT). Argument
// retained as `_` for signature stability.
func (s *OAuthProviderService) ClientCredentialsGrant(ctx context.Context, client *models.OAuthClient, requestedScopes []string, _ string) (*models.OAuthTokenResponse, error) {
	// Validate grant type is allowed
	if !s.containsString(client.GrantTypes, "client_credentials") {
		return nil, fmt.Errorf("unauthorized_client: client_credentials grant is not allowed")
	}

	// Validate and filter scopes.
	//
	// RFC 6749 §3.3: "If the client omits the scope parameter when
	// requesting authorization, the authorization server MUST either
	// process the request using a pre-defined default value or fail the
	// request indicating an invalid scope." Pre-fix, omitted-scope
	// produced an empty `scope` claim that resource servers had no way to
	// distinguish from "deliberately narrowed to nothing", and the admin
	// API rejected the resulting token. We default to the client's full
	// registered scope list — matches Auth0/Okta defaults; the client
	// cannot request scopes its registration doesn't grant anyway.
	var scopes []string
	if len(requestedScopes) == 0 ||
		(len(requestedScopes) == 1 && requestedScopes[0] == "") {
		// Caller omitted `scope` (or sent an empty string that
		// strings.Split turns into a single empty element). Default to
		// the client's full registered scopes.
		scopes = append([]string(nil), client.Scopes...)
	} else {
		var dropped []string
		for _, scope := range requestedScopes {
			if scope == "" {
				continue
			}
			if s.containsString(client.Scopes, scope) {
				scopes = append(scopes, scope)
			} else {
				dropped = append(dropped, scope)
			}
		}
		// Visibility only — behaviour is unchanged, the token still
		// mints with exactly the filtered `scopes` above. A requested
		// scope that isn't in the client's registration is silently
		// narrowed away rather than rejected (see the RFC 6749 §3.3
		// note above); that silence is exactly what makes bad
		// ServiceClientClaim grants unfindable until enforcement is
		// switched on elsewhere and traffic starts failing. One line
		// per token request (not one per dropped scope) — a caller
		// missing five registered scopes is one misconfiguration to
		// fix, not five log lines to correlate back into one.
		if len(dropped) > 0 && s.claimsLogger != nil {
			s.claimsLogger.Warn("oauth.client_credentials.scope_dropped",
				zap.String("client_id", client.ClientID),
				zap.Strings("requested_scopes", requestedScopes),
				zap.Strings("granted_scopes", scopes),
				zap.Strings("dropped_scopes", dropped),
			)
		}
	}

	// RFC 9449 §6 — sender-constrain enforcement at issuance.
	// Sensitive scopes (admin:* / offline_access) MUST be issued only
	// with a DPoP-bound token. Reject the request otherwise so the
	// caller has to retry with a proof header instead of getting back
	// a plain bearer that some downstream check might miss.
	if s.cfg.DPoPEnabled && scopeRequiresDPoP(scopes) && dpopJKTFromContext(ctx) == "" {
		return nil, ErrDPoPRequired
	}

	// Generate tokens (no user, no ID token, no RAR — client_credentials callers
	// may pass authorization_details via a separate flow if needed in the future).
	// amr is meaningless for client_credentials (no user authn event) → nil.
	// sid is also nil — there's no IdP session for a client_credentials grant.
	tokens, err := s.generateTokens(ctx, client, nil, scopes, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	// Phase 2 (talon-service-tokens) — emit audit event for machine-
	// identity issuance. Mirrors the visibility human OIDC logins get
	// via LogLogin so SOC dashboards see EVERY credential mint in one
	// funnel. nil-safe: callsite is no-op when auditService is unwired
	// (tests, partial deployments).
	//
	// Category=Authentication + Severity=Low matches the "successful
	// credential mint" semantics (this branch only runs after token
	// generation succeeds — failures bail earlier and could carry a
	// distinct higher-severity emit later when needed). Details
	// surface the bits operators need for forensics: client_id, the
	// final filtered scopes, and the configured access-token TTL so
	// the steal window is visible at-a-glance.
	if s.auditService != nil {
		s.auditService.LogSecurityEvent(ctx, &SecurityAuditEvent{
			TenantID:    client.TenantID,
			Category:    SecurityCategoryAuthentication,
			Severity:    SecuritySeverityLow,
			Action:      "oauth.client_credentials.issued",
			Description: fmt.Sprintf("Machine token issued to client %s for %d scope(s)", client.ClientID, len(scopes)),
			Details: map[string]interface{}{
				"client_id":               client.ClientID,
				"grant_type":              "client_credentials",
				"scopes":                  scopes,
				"access_token_lifetime":   client.AccessTokenLifetime,
				"refresh_token_lifetime":  client.RefreshTokenLifetime,
			},
		})
	}

	return tokens, nil
}

// TokenExchangeGrant implements RFC 8693 OAuth 2.0 Token Exchange.
// The caller (authenticated as `client`) presents `subjectToken` and
// receives a NEW access token (and, on the external-JWT path, a
// fresh refresh token) representing the same end-user, scoped to
// the caller-supplied audience and (optionally) a narrowed scope.
//
// Two subject_token_type dispatch paths:
//
//  1. urn:ietf:params:oauth:token-type:access_token (legacy internal
//     path) — narrows a Falcon-ID-issued token. RFC 8693 §2.2 phrases
//     this as "the resulting access token's scope MUST NOT exceed
//     the source token's scope". Refresh tokens are NOT issued for
//     this path (the exchange is a narrowing, not a fresh login).
//
//  2. urn:ietf:params:oauth:token-type:jwt (external IdP bridge) —
//     when the caller has `allow_external_jwt_exchange = true` and a
//     join row in iam_oauth_client_trusted_external_issuers, the
//     subject_token is parsed as a JWT, the `iss` claim is matched
//     against iam_oauth_trusted_external_issuers, the signature is
//     verified against the issuer's JWKS, and a fresh user-bound
//     access + refresh token pair is minted. THIS is the path tier-1
//     Identity-Aware Proxies (Talon, Pomerium, Google Cloud IAP,
//     Cloudflare Access) use to bridge edge-authenticated sessions
//     into the BFF cookie domain. Refresh tokens ARE issued (this is
//     the BFF's first login event, not a narrowing).
//
// In both paths the issued token carries an RFC 8693 §4.1 `act`
// claim identifying the actor (the calling client) so receivers and
// audit logs see "BFF X acted on behalf of user Y". The chain is
// preserved when the subject token itself carries an `act` (RFC 8693
// §4.1.1 — the prior act becomes act.act on the new token).
//
// The new audience comes from ctx (services.WithOAuthResource),
// which the handler populates from `resource` (RFC 8707) or
// `audience` (RFC 8693 §2.1). When neither is present the issued
// token's `aud` falls back to `client.ClientID`.
func (s *OAuthProviderService) TokenExchangeGrant(
	ctx context.Context,
	client *models.OAuthClient,
	subjectToken, subjectTokenType, requestedTokenType string,
	requestedScopes []string,
) (*models.OAuthTokenResponse, error) {
	// Token-type validation per RFC 8693 §2.1. The handler accepts
	// :access_token (legacy internal path) and :jwt (external IdP
	// bridge added 2026-05-14 for the Talon→BFF token-handler
	// pattern). Other RFC 8693 types (saml2, id_token) remain
	// unsupported until a concrete use-case lands them.
	const (
		accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
		jwtTokenType    = "urn:ietf:params:oauth:token-type:jwt"
	)
	if subjectTokenType != accessTokenType && subjectTokenType != jwtTokenType {
		return nil, fmt.Errorf("invalid_request: subject_token_type %q is not supported (only access_token, jwt)", subjectTokenType)
	}
	if requestedTokenType != "" && requestedTokenType != accessTokenType {
		return nil, fmt.Errorf("invalid_request: requested_token_type %q is not supported (only access_token)", requestedTokenType)
	}

	// :jwt path — external IdP federation (Talon IAP → BFF bridge).
	if subjectTokenType == jwtTokenType {
		return s.tokenExchangeFromExternalJWT(ctx, client, subjectToken, requestedScopes)
	}

	// Validate the subject token's signature + expiry. ValidateAccessToken
	// uses our active public key — anything not signed by us is rejected
	// (we don't trust externally-issued tokens for exchange today). The
	// returned claims are not consumed directly; the iam_oauth_tokens
	// row lookup below is the canonical source for scope/user/tenant.
	if _, vErr := s.ValidateAccessToken(subjectToken); vErr != nil {
		return nil, fmt.Errorf("invalid_grant: subject_token validation failed: %v", vErr)
	}

	// Cross-check the JWT against the iam_oauth_tokens row so a
	// revoked-but-not-yet-expired token can't be exchanged. The `jti`
	// claim is unique per issued token; lookup-by-hash of the full
	// JWT replicates what the resource-server middleware does.
	tokenHash := s.hashSecret(subjectToken)
	row, err := s.clientRepo.GetOAuthTokenByHash(ctx, tokenHash)
	if err != nil || row == nil {
		return nil, fmt.Errorf("invalid_grant: subject_token not found in token store (revoked or never issued)")
	}
	if row.IsRevoked {
		return nil, fmt.Errorf("invalid_grant: subject_token has been revoked")
	}

	// Resolve the original user (if any). Client_credentials subject
	// tokens have no user — the caller is just narrowing the audience
	// of a service-to-service token. Authorization-code subject tokens
	// have a real user we MUST preserve as `sub`.
	var user *models.User
	if row.UserID != nil {
		user, err = s.userRepo.GetByID(ctx, *row.UserID)
		if err != nil {
			return nil, fmt.Errorf("invalid_grant: subject_token user not found: %v", err)
		}
	}

	// Scope handling: requested scope MUST be a subset of the
	// subject's. Empty requested → keep all of the subject's. RFC 8693
	// §2.1 phrases this as "the resulting access token's scope MUST
	// NOT exceed the source token's scope".
	scopes := append([]string(nil), row.Scopes...)
	if len(requestedScopes) > 0 {
		// Filter requested ⋂ subject. Order-preserving.
		allowed := make(map[string]bool, len(row.Scopes))
		for _, s := range row.Scopes {
			allowed[s] = true
		}
		narrowed := make([]string, 0, len(requestedScopes))
		var dropped []string
		for _, s := range requestedScopes {
			if s == "" {
				continue
			}
			if allowed[s] {
				narrowed = append(narrowed, s)
			} else {
				dropped = append(dropped, s)
			}
		}
		if len(narrowed) == 0 {
			return nil, fmt.Errorf("invalid_scope: requested scope is not a subset of subject_token scope")
		}
		// Visibility only — behaviour is unchanged, the token still mints
		// with exactly `narrowed` above. Unlike ClientCredentialsGrant this
		// path already rejects the request outright when NONE of the
		// requested scopes survive; but a partial narrowing (some
		// requested scopes are outside subject_token's scope, some
		// aren't) still mints 200 OK today with the excess silently
		// dropped — same unfindable-until-enforcement gap. One line per
		// token request, not per dropped scope, for the same reason as
		// ClientCredentialsGrant.
		if len(dropped) > 0 && s.claimsLogger != nil {
			s.claimsLogger.Warn("oauth.token_exchange.scope_dropped",
				zap.String("client_id", client.ClientID),
				zap.Strings("requested_scopes", requestedScopes),
				zap.Strings("granted_scopes", narrowed),
				zap.Strings("dropped_scopes", dropped),
			)
		}
		scopes = narrowed
	}

	// Sender-constrain enforcement on the EXCHANGED token, same gate
	// as ClientCredentialsGrant: admin:* / offline_access scopes
	// require a DPoP proof on the exchange call.
	if s.cfg.DPoPEnabled && scopeRequiresDPoP(scopes) && dpopJKTFromContext(ctx) == "" {
		return nil, ErrDPoPRequired
	}

	// Issue the new token. The caller's client identity authenticates
	// the exchange call (existing client-auth chain), but the issued
	// token represents the original user (preserved sub) bound to the
	// requested audience (already in ctx via WithOAuthResource). The
	// new token's `client_id` claim is the EXCHANGE client (today's
	// caller) so receivers can audit which service initiated the
	// narrowing. The original client_id stays in iam_oauth_tokens via
	// the new row's TenantID/ClientID columns.
	//
	// authMethods are intentionally cleared — the exchange does not
	// re-establish authn; receivers should not see "pwd" / "mfa" amr
	// values they'd interpret as a fresh login. Carrying forward the
	// subject's amr would be misleading here.
	//
	// Stamp the RFC 8693 §4.1 `act` claim with the calling client so
	// downstream receivers and audit logs see the delegation chain
	// "client X acted on behalf of user Y". The subject_token here
	// is Falcon-ID-issued (legacy internal path) so SubjectTokenIssuer
	// is implicit (= our own issuer) — left empty so generateTokens
	// emits only the actor identity.
	ctx = WithTokenExchangeActor(ctx, TokenExchangeActor{
		ActorSub:      client.ClientID,
		ActorClientID: client.ClientID,
	})
	return s.generateTokens(ctx, client, user, scopes, nil, nil, nil, row.IdpSessionID)
}

// tokenExchangeFromExternalJWT handles the :jwt subject_token_type
// branch of RFC 8693 — the BFF-fronted Identity-Aware Proxy bridge.
// The subject_token is a JWT signed by an EXTERNAL issuer registered
// in iam_oauth_trusted_external_issuers (most importantly Talon at
// internal.example.com). On success we mint a fresh user-bound
// access + refresh token pair scoped to the caller-requested
// audience, with an `act` claim recording the BFF as the actor.
//
// Trust model — checked in this exact order:
//
//  1. client.AllowExternalJWTExchange must be TRUE. Cheap top-level
//     deny-by-default gate.
//  2. The service must have an externalIssuerRepo wired (see
//     SetExternalIssuerRepository). nil → 501-class error; the
//     caller's request is rejected without leaking the disabled
//     state to a client that shouldn't be probing for it.
//  3. Parse the JWT WITHOUT verifying signature to extract `iss`.
//  4. Lookup iam_oauth_trusted_external_issuers by (tenant_id, iss).
//     Active match required (is_active=true).
//  5. Lookup iam_oauth_client_trusted_external_issuers by
//     (client.ID, issuer.ID). Row must exist — this is the
//     per-client grant gate.
//  6. Verify the JWT's RS256 signature against the issuer's JWKS
//     (kid-dispatched), exp, iat-age ≤ issuer.MaxTokenAgeSeconds,
//     iss equality (defence-in-depth — the unverified parse value
//     could be a Trojan), and aud ∩ (per-client override OR
//     issuer.Audiences) ≠ ∅.
//  7. Resolve the user by `sub` claim — Talon stamps the Falcon-ID
//     user UUID as `sub` (this is the same `sub` Talon got from
//     its OIDC code-exchange against Falcon-ID, recorded in
//     iam_oauth_tokens.user_id and projected as the JWT sub by
//     internal/identityjwt/signer.go). The user must exist + not be
//     disabled. Tenant must match the calling client's tenant.
//  8. Scope derivation — explicit requested_scopes are taken
//     verbatim from the caller (intersection with client.Scopes
//     happens implicitly via generateTokens' downstream gate); when
//     empty the caller's full Scopes are used.
//
// Refresh tokens ARE issued for this path (unlike the legacy
// internal-narrowing path) — the BFF treats the exchange as its
// fresh-login event and needs the refresh token to silently rotate
// the access token over the user's session lifetime without
// requiring another IAP-fronted page-load.
//
//nolint:gocyclo // sequential validation gates — splitting would
// obscure the trust model laid out in the doc comment above.
func (s *OAuthProviderService) tokenExchangeFromExternalJWT(
	ctx context.Context,
	client *models.OAuthClient,
	subjectToken string,
	requestedScopes []string,
) (*models.OAuthTokenResponse, error) {
	if !client.AllowExternalJWTExchange {
		return nil, fmt.Errorf("invalid_grant: client %q is not permitted to perform external-JWT exchange", client.ClientID)
	}
	if s.externalIssuerRepo == nil || s.externalJWTValidator == nil {
		return nil, errors.New("invalid_grant: external-JWT exchange is not enabled on this server")
	}

	// Step 3: unverified parse to extract `iss`. Forgery-tolerant —
	// the next signature verify step is what actually proves trust.
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(subjectToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: subject_token is not a parseable JWT: %v", err)
	}
	issClaim, err := unverified.Claims.GetIssuer()
	if err != nil || issClaim == "" {
		return nil, errors.New("invalid_grant: subject_token missing iss claim")
	}

	// Step 4: tenant-scoped issuer lookup. The repo returns rows
	// regardless of `is_active` so we can distinguish three states:
	//   (a) issuer was never registered for this tenant
	//   (b) issuer was registered but has since been revoked
	//   (c) issuer is currently trusted
	// Pre-2026-05-21 the repo silently filtered, collapsing (a) and
	// (b) and losing the revoked-issuer-replay-attempt audit signal.
	issuer, err := s.externalIssuerRepo.GetByIssuer(ctx, client.TenantID, issClaim)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: issuer lookup failed: %v", err)
	}
	if issuer == nil {
		return nil, fmt.Errorf("invalid_grant: issuer %q is not a trusted external issuer for this tenant", issClaim)
	}
	if !issuer.IsActive {
		// Revoked-issuer replay attempt — emit a structured warn that
		// the SOC can pivot on. Caller still receives the same
		// invalid_grant error so the response shape is unchanged for
		// the (likely-attacker) client; the difference shows up only
		// in the audit log.
		if logger.Log != nil {
			logger.Log.Warn("oauth_token_exchange.revoked_issuer_attempted",
				zap.String("tenant_id", client.TenantID.String()),
				zap.String("client_id", client.ClientID),
				zap.String("issuer_url", issClaim),
				zap.String("issuer_id", issuer.ID.String()),
			)
		}
		return nil, fmt.Errorf("invalid_grant: issuer %q has been revoked for this tenant", issClaim)
	}

	// Step 5: per-client grant lookup. Existence is the trust; no
	// row → deny.
	grant, err := s.externalIssuerRepo.GetClientGrant(ctx, client.ID, issuer.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: client grant lookup failed: %v", err)
	}
	if grant == nil {
		return nil, fmt.Errorf("invalid_grant: client %q is not granted exchange permission for issuer %q", client.ClientID, issClaim)
	}

	// Step 6: signature + standard-claim verification. When the
	// per-client grant carries an Audiences override, narrow the
	// issuer's allowed audiences to the intersection before the
	// validator runs — keeps the per-client downscoping enforcement
	// inside the validator's existing claim-guard pass.
	effectiveAudiences := issuer.Audiences
	if len(grant.Audiences) > 0 {
		effectiveAudiences = intersectStrings(issuer.Audiences, grant.Audiences)
		if len(effectiveAudiences) == 0 {
			return nil, errors.New("invalid_grant: per-client audience override has no intersection with issuer audiences")
		}
	}
	validatorIssuer := *issuer
	validatorIssuer.Audiences = effectiveAudiences
	validated, err := s.externalJWTValidator.Validate(ctx, subjectToken, &validatorIssuer)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: subject_token verification failed: %v", err)
	}

	// Step 7: resolve user by sub. Talon stamps the Falcon-ID user
	// UUID as the JWT sub (see internal/identityjwt/signer.go) —
	// uuid.Parse will reject IAP tokens from other issuers that use
	// non-UUID subs (e.g. SPIFFE IDs) without a separate code path.
	userID, err := uuid.Parse(validated.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: subject_token sub %q is not a Falcon-ID user UUID: %v", validated.Subject, err)
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: subject_token user not found: %v", err)
	}
	if user == nil {
		return nil, fmt.Errorf("invalid_grant: subject_token user %q does not exist", userID)
	}
	if user.TenantID != client.TenantID {
		return nil, fmt.Errorf("invalid_grant: subject_token user tenant %q does not match client tenant %q", user.TenantID, client.TenantID)
	}

	// Step 8: scope derivation.
	//
	// The IAP JWT is the SUBJECT_TOKEN here, and it represents a
	// fresh user-authenticated session at the upstream IdP (Talon's
	// OIDC RP completed the OAuth dance against Falcon-ID and
	// stamped the user identity into the JWT). The issued
	// access_token's job is to authenticate the SAME user against
	// downstream resource servers — so scopes must reflect the
	// USER's role-derived authorization surface, NOT the BFF
	// service-client's own scope (which is typically just
	// `service:exchange` and grants no end-user access).
	//
	// Using client.Scopes here would produce a token with only
	// `service:exchange` → emitSubjectClaims downstream wouldn't
	// emit the `roles` claim (because the requesting scope set
	// doesn't include the OIDC scopes it's gated on) → resource-
	// server middleware on /api/v1/* sees no roles → 401/403 on
	// every dashboard hook. Diagnosed live 2026-05-14.
	//
	// Fix: when the caller didn't request explicit scopes, default
	// to the OIDC standard user-scope set (openid + profile + email
	// + roles + groups). These trigger emitSubjectClaims to write
	// the user's actual platform_admin / iam_admin / etc roles into
	// the access_token's `roles` claim, which is what every
	// resource server downstream reads via middleware.RequireRole.
	//
	// Explicit requested_scopes (when supplied) pass through
	// verbatim — caller can narrow further per RFC 8693 §2.1.
	scopes := append([]string(nil), requestedScopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "roles", "groups"}
	}

	// Sender-constrain gate, same as ClientCredentialsGrant.
	if s.cfg.DPoPEnabled && scopeRequiresDPoP(scopes) && dpopJKTFromContext(ctx) == "" {
		return nil, ErrDPoPRequired
	}

	// Stamp the RFC 8693 §4.1 act claim with the BFF (calling
	// client) and the subject_token's issuer (Talon). Two-element
	// chain — receivers see "Talon issued the subject_token; client
	// BFF exchanged it on behalf of user X".
	ctx = WithTokenExchangeActor(ctx, TokenExchangeActor{
		ActorSub:           client.ClientID,
		ActorClientID:      client.ClientID,
		SubjectTokenIssuer: validated.Issuer,
	})

	// Issue the user-bound access + refresh token pair. nil
	// authMethods because the exchange does not re-establish authn
	// (Talon already did the OIDC + MFA gate upstream — receivers
	// that care about amr can read it from the subject_token via
	// audit logs; carrying it forward here would be misleading
	// because the BFF didn't observe the auth event directly).
	return s.generateTokens(ctx, client, user, scopes, nil, nil, nil, nil)
}

// intersectStrings returns the order-preserving intersection of two
// string slices. Used by the per-client audience override path —
// both lists are tiny in practice.
func intersectStrings(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// ==================== Token Generation ====================

// Token generation, OIDC discovery, JWKS, token validation, client authentication,
// consent management, token revocation, and helpers are in oauth_provider_service_tokens.go
