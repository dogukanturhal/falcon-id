// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/dpop"
	"github.com/dogukanturhal/falcon-id/pkg/keys"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
)

// tokenTokenRepository defines the token repository methods needed by TokenService.
type tokenTokenRepository interface {
	CleanupExpiredPasswordResets(ctx context.Context) (int64, error)
	CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error
	GetPasswordReset(ctx context.Context, tokenHash string) (*models.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id uuid.UUID) error
	InvalidateUserPasswordResets(ctx context.Context, userID uuid.UUID) error
}

// tokenUserRepository defines the user repository methods needed by TokenService.
type tokenUserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
	Update(ctx context.Context, user *models.User) error
}

// tokenSessionRepository defines the session repository methods needed by TokenService.
type tokenSessionRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	// GetByIDWithRealmContext is the RLS-bootstrap-safe lookup used by the
	// session-blacklist database fallback (checkSessionActiveInDB). See
	// internal/repositories/session_repository.go for why this needs realm
	// (not tenant) context and why trusting the JWT's own rid claim here is
	// safe.
	GetByIDWithRealmContext(ctx context.Context, id uuid.UUID, realmID uuid.UUID) (*models.Session, error)
}

// tokenRealmPolicyReader is the narrow surface TokenService needs to let
// per-realm overrides take precedence over global session-lifecycle config
// (SESSION_IDLE_TIMEOUT, REFRESH_TOKEN_ABSOLUTE_MAX). Kept as an interface
// so tests can stub it and so TokenService doesn't depend on the concrete
// RealmRepository type.
type tokenRealmPolicyReader interface {
	GetSecurityPolicy(ctx context.Context, realmID uuid.UUID) (*models.RealmSecurityPolicy, error)
}

// tokenOAuthClientRepo is the narrow surface TokenService needs to fan
// out per-user revocation across iam_oauth_tokens (the table that
// replaced iam_refresh_tokens after Phase 3, falcon-id!122). Kept as an
// interface so tests can stub it and so TokenService doesn't depend on
// the concrete OAuthClientRepository type.
type tokenOAuthClientRepo interface {
	RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error
	RevokeTokensBySession(ctx context.Context, sessionID, userID uuid.UUID) (int64, error)
	GetOAuthTokenByHash(ctx context.Context, tokenHash string) (*models.OAuthToken, error)
}

// TokenService is an exported type.
type TokenService struct {
	config                      *config.Config
	tokenRepo                   tokenTokenRepository
	userRepo                    tokenUserRepository
	sessionRepo                 tokenSessionRepository
	tokenBlacklist              *redis.TokenBlacklist
	sessionCache                *redis.SessionCache
	configProvider              *ConfigProvider
	productSubscriptionResolver *ProductSubscriptionResolver
	jwtKeyProvider              *crypto.JWTKeyProvider
	keyManager                  *keys.KeyManager
	// backchannelLogout fires OIDC BCL to relying parties. Required for
	// the refresh-token reuse-detection path to propagate "this session
	// is compromised" to every app with an active access token — without
	// it, stolen child tokens keep working until natural expiry.
	backchannelLogout *BackchannelLogoutService
	// realmPolicyReader lets per-realm session policy (idle timeout, max
	// lifetime) override the global config values during refresh. When
	// unset OR when the user's realm has zero on both policy fields, the
	// global config wins (backwards compatible).
	realmPolicyReader tokenRealmPolicyReader
	// oauthClientRepo lets TokenService delegate per-user revocation to
	// the iam_oauth_tokens layer (the table that replaced
	// iam_refresh_tokens after Phase 3, falcon-id!122). Optional — when
	// unwired, RevokeAllUserOAuthTokens degrades to a no-op so password-
	// change/logout/data-deletion paths continue to compile and run.
	oauthClientRepo tokenOAuthClientRepo
	// tenantSuspension denies token issue and token validation for suspended
	// tenants (R1-GAPS row 27). Optional; nil disables enforcement.
	tenantSuspension TenantSuspensionChecker
	// platformAuthority decides the is_platform_admin claim. nil (or
	// OPS_STRICT_PLATFORM_ROLES=false) keeps the legacy rule: internal-tenant
	// membership.
	platformAuthority *PlatformAuthority
}

// SetPlatformAuthority wires the strict platform-role model into token
// issuance. Optional; nil keeps the legacy is_platform_admin derivation.
func (s *TokenService) SetPlatformAuthority(pa *PlatformAuthority) { s.platformAuthority = pa }

// SetTenantSuspensionChecker wires the tenant-suspension gate.
func (s *TokenService) SetTenantSuspensionChecker(c TenantSuspensionChecker) {
	s.tenantSuspension = c
}

// NewTokenService is an exported function.
func NewTokenService(cfg *config.Config, tokenRepo tokenTokenRepository, userRepo tokenUserRepository) *TokenService {
	return &TokenService{
		config:    cfg,
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
	}
}

// SetSessionRepository sets the session repository for database fallback when Redis is unavailable
func (s *TokenService) SetSessionRepository(repo tokenSessionRepository) {
	s.sessionRepo = repo
}

// SetOAuthClientRepository wires the iam_oauth_tokens layer so per-user
// revocation can sweep across every relying party the user has signed
// into. Required for Logout / ChangePassword / DataDeletion to actually
// invalidate OAuth tokens after Phase 3 dropped iam_refresh_tokens.
func (s *TokenService) SetOAuthClientRepository(repo tokenOAuthClientRepo) {
	s.oauthClientRepo = repo
}

// RevokeAllUserOAuthTokens sweeps every iam_oauth_tokens row for the
// user, marking is_revoked=true. Replaces the now-no-op
// RevokeAllUserRefreshTokens that used to revoke against the dropped
// iam_refresh_tokens table.
//
// Use cases:
//   - AuthService.terminateLogoutSessions when allDevices=true
//   - auth_account_service.ChangePassword (force re-login on every RP)
//   - data_deletion_service.DeleteUser (wire-up pending — Phase 3.1b)
//
// No-op when oauthClientRepo isn't wired (e.g., tests with a stripped-
// down TokenService). Safe to call from any logout path.
func (s *TokenService) RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	if s.oauthClientRepo == nil {
		return nil
	}
	return s.oauthClientRepo.RevokeAllUserOAuthTokens(ctx, userID, reason)
}

// RevokeOAuthTokensBySession revokes only the tokens bound to one login
// session (per-device sign-out). No-op when oauthClientRepo isn't wired or
// sessionID is uuid.Nil.
func (s *TokenService) RevokeOAuthTokensBySession(ctx context.Context, sessionID, userID uuid.UUID) error {
	if s.oauthClientRepo == nil || sessionID == uuid.Nil {
		return nil
	}
	_, err := s.oauthClientRepo.RevokeTokensBySession(ctx, sessionID, userID)
	return err
}

// ResolveOAuthSession finds the login session an OAuth access token is bound
// to via its iam_oauth_tokens row (session_id and idp_session_id). Used by
// logout when the JWT carries no `sid`. Returns uuid.Nil for either id that
// is unknown, and for tokens that belong to another user.
func (s *TokenService) ResolveOAuthSession(ctx context.Context, rawAccessToken string, userID uuid.UUID) (sessionID, idpSessionID uuid.UUID) {
	if s.oauthClientRepo == nil || rawAccessToken == "" {
		return uuid.Nil, uuid.Nil
	}
	sum := sha256.Sum256([]byte(rawAccessToken))
	row, err := s.oauthClientRepo.GetOAuthTokenByHash(ctx, base64.RawURLEncoding.EncodeToString(sum[:]))
	if err != nil || row == nil || row.UserID == nil || *row.UserID != userID {
		return uuid.Nil, uuid.Nil
	}
	if row.SessionID != nil {
		sessionID = *row.SessionID
	}
	if row.IdpSessionID != nil {
		idpSessionID = *row.IdpSessionID
	}
	return sessionID, idpSessionID
}

// SetTokenBlacklist sets the Redis token blacklist for fast token revocation checks
func (s *TokenService) SetTokenBlacklist(blacklist *redis.TokenBlacklist) {
	s.tokenBlacklist = blacklist
}

// SetSessionCache sets the Redis session cache for storing full user context with minimal tokens
func (s *TokenService) SetSessionCache(cache *redis.SessionCache) {
	s.sessionCache = cache
}

// SetConfigProvider sets the dynamic config provider for per-tenant configuration overrides.
func (s *TokenService) SetConfigProvider(cp *ConfigProvider) {
	s.configProvider = cp
}

// SetProductSubscriptionResolver sets the resolver for populating product subscription claims in JWT tokens.
func (s *TokenService) SetProductSubscriptionResolver(resolver *ProductSubscriptionResolver) {
	s.productSubscriptionResolver = resolver
}

// SetJWTKeyProvider wires in the RSA key provider used for RS256 token signing.
// When set, new tokens are signed with RS256 unless the config overrides the algorithm to HS256.
// Call this in cmd/services.go after NewTokenService.
func (s *TokenService) SetJWTKeyProvider(p *crypto.JWTKeyProvider) {
	s.jwtKeyProvider = p
}

// SetKeyManager wires in the DB-backed key manager for RS256 token signing.
// When set, it takes precedence over JWTKeyProvider for signing and validation,
// enabling graceful key rotation (Keycloak/Auth0 pattern).
func (s *TokenService) SetKeyManager(km *keys.KeyManager) {
	s.keyManager = km
}

// SetBackchannelLogout wires the BCL service so refresh-token reuse detection
// can broadcast session_invalidated to every registered RP. Call after
// constructing the BackchannelLogoutService in cmd/services.go.
func (s *TokenService) SetBackchannelLogout(bcl *BackchannelLogoutService) {
	s.backchannelLogout = bcl
}

// SetRealmPolicyReader wires the realm-policy reader so per-realm session
// lifecycle overrides take precedence over global config during refresh.
// Pass nil or leave unset to keep the global-only behaviour.
func (s *TokenService) SetRealmPolicyReader(reader tokenRealmPolicyReader) {
	s.realmPolicyReader = reader
}

// useRS256 reports whether the service should sign new tokens with RS256.
// RS256 is used when:
//   - JWTSigningAlgorithm is "RS256" (the default), AND
//   - a KeyManager or JWTKeyProvider is available (i.e., the key has been wired in).
//
// Operators can force HS256 by setting JWT_SIGNING_ALGORITHM=HS256.
func (s *TokenService) useRS256() bool {
	if s.keyManager == nil && s.jwtKeyProvider == nil {
		return false
	}
	alg := strings.ToUpper(s.config.JWTSigningAlgorithm)
	return alg == "" || alg == "RS256"
}

// signToken signs a token using either RS256 (preferred) or HS256 (legacy fallback).
// When a KeyManager is wired, it is used for DB-backed key signing with kid rotation.
// It also sets the kid header when using RS256 so verifiers can look up the key.
func (s *TokenService) signToken(claims jwt.Claims) (string, error) {
	if s.keyManager != nil && s.useRS256() {
		signer, kid, err := s.keyManager.ActiveKey()
		if err != nil {
			return "", fmt.Errorf("no active signing key: %w", err)
		}
		rsaKey, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("active key is not RSA")
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		return token.SignedString(rsaKey)
	}
	if s.useRS256() {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = s.jwtKeyProvider.KeyID()
		return token.SignedString(s.jwtKeyProvider.PrivateKey())
	}
	// HS256 is only a migration fallback. With it disabled, fail loudly rather
	// than mint tokens this service's own validator would reject.
	if !s.config.JWTHMACFallbackEnabled {
		return "", fmt.Errorf("no RS256 signing key available and HS256 fallback is disabled")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

// SignClaims signs arbitrary claims with the active access-token key (RS256 +
// kid). Used by services that mint their own token shapes (service accounts).
func (s *TokenService) SignClaims(claims jwt.Claims) (string, error) {
	return s.signToken(claims)
}

// SignLogoutToken signs a JWT for back-channel logout notifications.
// It uses the same signing key and algorithm as access tokens, so relying
// parties can verify the token with the same JWKS endpoint.
func (s *TokenService) SignLogoutToken(claims jwt.Claims) (string, error) {
	return s.signToken(claims)
}

// witnessFreshnessWindow is the validity window stamped into every passkey
// enrollment witness JWS. Must mirror the constant in jess's
// devicepolicy.witnessFreshnessWindow so the freshness pre-check there
// never rejects a JWS that Falcon-ID minted within the allowed window.
const witnessFreshnessWindow = 10 * time.Minute

// witnessOTPFreshnessWindow is the (shorter) validity of an authenticator-app
// (TOTP) witness JWS. A TOTP code is a weaker proof than a passkey assertion,
// so the artefact must be spent quickly.
const witnessOTPFreshnessWindow = 5 * time.Minute

// witnessAudience is the fixed aud claim stamped into every passkey enrollment
// witness JWS. Must match devicepolicy.witnessAudience in jess exactly —
// case-sensitive.
const witnessAudience = "https://jess.internal.example.com/device-attest"

// witnessOTPAudience is the aud of an authenticator-app witness JWS. It is a
// distinct audience so a jess that predates TOTP support rejects these
// artefacts outright instead of treating them as passkey witnesses.
const witnessOTPAudience = "https://jess.internal.example.com/device-attest/otp"

// Witness methods as they appear in the witness_method claim (and the
// iam_devices.witness_method column). The request-side name for the
// authenticator-app flow is "totp"; the claim value is "otp".
const (
	WitnessMethodPasskey = "passkey"
	WitnessMethodOTP     = "otp"
)

// witnessClaims is the JWT payload for an operator enrollment witness JWS.
// device_uuid is always present; the remaining claims are additive and
// omitted only for nothing but legacy-shaped test callers.
type witnessClaims struct {
	jwt.RegisteredClaims
	// DeviceUUID binds the witness to exactly one device, defeating
	// cross-device replay: an operator who witnesses device A cannot
	// have that JWS accepted for device B.
	DeviceUUID string `json:"device_uuid"`
	// AMR is ["hwk"] for a passkey witness and ["otp"] for TOTP.
	AMR []string `json:"amr,omitempty"`
	// WitnessMethod is "passkey" or "otp"; must agree with AMR and aud.
	WitnessMethod string `json:"witness_method,omitempty"`
	// EKPubkeyHash is the lowercase-hex SHA-256 of the raw ek_pubkey_pem
	// bytes the client sends to jess (64 chars) — the exact value jess
	// computes and stores as iam_devices.ek_pubkey_hash. Binds the witness
	// to one physical TPM.
	EKPubkeyHash string `json:"ek_pubkey_hash,omitempty"`
}

// WitnessMintParams are the inputs of MintWitnessJWS.
type WitnessMintParams struct {
	AdminSub   string
	DeviceUUID string
	// EKPubkeyHash is the 64-char lowercase hex digest the operator is
	// witnessing. Required for the OTP method; optional for passkey.
	EKPubkeyHash string
	// Method is WitnessMethodPasskey or WitnessMethodOTP.
	Method string
}

// WitnessJWS is the signed artifact returned to the caller after a
// successful passkey assertion or TOTP verification in the witness flow.
type WitnessJWS struct {
	SignedJWS string    // compact JWS string (header.payload.signature)
	AdminSub  string    // operator's Falcon-ID sub (== JWS "sub" claim)
	IssuedAt  time.Time // JWS iat
	ExpiresAt time.Time // JWS exp
	Method    string    // WitnessMethodPasskey | WitnessMethodOTP
}

// MintWitnessJWS mints a compact JWS signed with the existing RS256 issuer
// key for the ZTNA Path B device-enrollment witness flow (ADR 0043 §3.c.0).
//
// Claims stamped:
//   - iss  = s.config.JWTIssuer   (e.g. "https://id.hexxlock.com")
//   - aud  = witnessAudience (passkey) | witnessOTPAudience (otp)
//   - sub  = AdminSub             (caller's Falcon-ID user UUID string)
//   - iat  = now; exp = now + 10m (passkey) | 5m (otp)
//   - jti  = random UUID
//   - device_uuid, ek_pubkey_hash (cross-device / cross-TPM replay defence)
//   - amr = ["hwk"] | ["otp"], witness_method = "passkey" | "otp"
//
// The JWS header carries the signing key's kid (signToken). It is verified
// by jess via the existing /.well-known/jwks.json endpoint.
//
// Returns ErrNoSigningKey (503-worthy) when neither KeyManager nor
// JWTKeyProvider is wired, so callers can map the error to the correct HTTP
// status without string-matching.
func (s *TokenService) MintWitnessJWS(p WitnessMintParams) (*WitnessJWS, error) {
	aud, window, amr := witnessAudience, witnessFreshnessWindow, "hwk"
	switch p.Method {
	case WitnessMethodPasskey:
	case WitnessMethodOTP:
		if p.EKPubkeyHash == "" {
			return nil, fmt.Errorf("MintWitnessJWS: ek_pubkey_hash is required for the otp method")
		}
		aud, window, amr = witnessOTPAudience, witnessOTPFreshnessWindow, "otp"
	default:
		return nil, fmt.Errorf("MintWitnessJWS: unknown witness method %q", p.Method)
	}
	if !s.useRS256() {
		return nil, ErrNoSigningKey
	}
	now := time.Now().UTC()
	exp := now.Add(window)
	claims := witnessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.JWTIssuer,
			Audience:  jwt.ClaimStrings{aud},
			Subject:   p.AdminSub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
		DeviceUUID:    p.DeviceUUID,
		AMR:           []string{amr},
		WitnessMethod: p.Method,
		EKPubkeyHash:  p.EKPubkeyHash,
	}
	signed, err := s.signToken(claims)
	if err != nil {
		return nil, fmt.Errorf("MintWitnessJWS: sign failed: %w", err)
	}
	return &WitnessJWS{
		SignedJWS: signed,
		AdminSub:  p.AdminSub,
		IssuedAt:  now,
		ExpiresAt: exp,
		Method:    p.Method,
	}, nil
}

// ErrNoSigningKey is returned by MintWitnessJWS when neither a KeyManager nor
// a JWTKeyProvider is wired on the TokenService. Callers should map this to
// HTTP 503 (Service Unavailable) rather than 500, because the condition is
// typically a startup misconfiguration rather than a runtime panic.
var ErrNoSigningKey = fmt.Errorf("token service: no RS256 signing key wired")

// effectiveAccessTokenExpiry returns the access token expiry for a given tenant,
// consulting the ConfigProvider for per-tenant overrides.
func (s *TokenService) effectiveAccessTokenExpiry(ctx context.Context, tenantID uuid.UUID) time.Duration {
	if s.configProvider != nil && tenantID != uuid.Nil {
		return s.configProvider.AccessTokenExpiry(ctx, tenantID)
	}
	return s.config.AccessTokenExpiry
}

// TokenGenerationOptions contains additional options for token generation
type TokenGenerationOptions struct {
	RealmID     uuid.UUID
	RealmSlug   string
	RealmType   string
	Scope       string  // "tenant" for tenant users, "platform" for platform admins
	UseMinimal  bool    // Use minimal token format (v1) instead of legacy (v0)
	DeviceInfo  *string // Device information for session tracking
	IPAddress   *string // IP address for session tracking
	RoleVersion int64   // Role version for cache invalidation
	ClientID    string  // OAuth client_id for audience scoping (e.g., "platform-admin")

	// DPoPJKT is the base64url-encoded JWK SHA-256 thumbprint (RFC 7638) of
	// the DPoP proof key presented at the token endpoint. When non-empty,
	// the issued access token carries a `cnf: {jkt: ...}` claim (RFC 9449
	// §6), and resource servers MUST enforce that incoming DPoP proofs
	// match this thumbprint before honouring the token. Empty string yields
	// a plain bearer token — backwards compatible.
	DPoPJKT string

	// AuthTime is the Unix timestamp of the original authentication event
	// for the session — RFC 9470 §3 / OIDC Core §2 `auth_time`. Carriers
	// pass session.AuthenticatedAt (or session.CreatedAt fallback) at first
	// mint AND at every refresh so the claim stays stable across refresh-
	// token rotations. When zero, the mint path falls back to a sessionRepo
	// lookup keyed by sessionID; if that also fails (sessionRepo unwired)
	// the mint omits the claim — RequireFreshAuth gates then fail closed
	// for that token (treating it as "auth time unknown, can't satisfy
	// freshness check"). Powers step-up enforcement on sensitive endpoints
	// (password change, MFA disable, session revoke).
	AuthTime int64
}

// fillDPoPJKTFromContext lets handlers at every issuance entry point stash
// the DPoP JWK thumbprint on ctx via dpop.WithJKT, so the 12+ call sites
// that eventually reach the generators don't each need to thread a new
// argument. If opts.DPoPJKT is already set we leave it alone — an
// explicit caller value always beats the context fallback.
func fillDPoPJKTFromContext(ctx context.Context, opts *TokenGenerationOptions) {
	if opts.DPoPJKT == "" {
		opts.DPoPJKT = dpop.JKTFromContext(ctx)
	}
}

// fillAuthTimeFromSession ensures opts.AuthTime is populated so the mint
// path can write the RFC 9470 `auth_time` claim. Resolution order:
//
//  1. Caller-supplied value (refresh-token path threads through the prior
//     token's auth_time, login path passes session.AuthenticatedAt or
//     session.CreatedAt).
//  2. sessionRepo lookup keyed by sessionID — picks AuthenticatedAt if
//     present (MFA-completed) else CreatedAt (password-only).
//  3. Zero — the mint omits the claim entirely, which causes
//     RequireFreshAuth gates to fail closed (treating "unknown auth time"
//     as "not fresh enough").
//
// The lookup happens at most once per mint and only when no caller
// supplied a value, so refresh hot-paths that already thread auth_time
// stay zero-DB.
func (s *TokenService) fillAuthTimeFromSession(ctx context.Context, opts *TokenGenerationOptions, sessionID uuid.UUID) {
	if opts.AuthTime != 0 {
		return
	}
	if s.sessionRepo == nil {
		return
	}
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil || session == nil {
		return
	}
	if session.AuthenticatedAt != nil {
		opts.AuthTime = session.AuthenticatedAt.Unix()
		return
	}
	opts.AuthTime = session.CreatedAt.Unix()
}

// GenerateAccessToken creates a JWT access token
func (s *TokenService) GenerateAccessToken(ctx context.Context, user *models.User, sessionID uuid.UUID, roles []string, permissions []string) (string, error) {
	// Use default realm if not set on user
	realmID := user.RealmID
	if realmID == uuid.Nil {
		realmID = models.DefaultRealmID
	}

	return s.GenerateAccessTokenWithOptions(ctx, user, sessionID, roles, permissions, TokenGenerationOptions{
		RealmID:   realmID,
		RealmSlug: "", // Will be populated by caller or defaults
		RealmType: string(models.RealmTypeShared),
		Scope:     "tenant",
	})
}

// GenerateAccessTokenWithOptions creates a JWT access token with realm context
// Supports both legacy (v0) and minimal (v1) token formats
func (s *TokenService) GenerateAccessTokenWithOptions(ctx context.Context, user *models.User, sessionID uuid.UUID, roles []string, permissions []string, opts TokenGenerationOptions) (string, error) {
	if err := checkTenantNotSuspended(ctx, s.tenantSuspension, user.TenantID); err != nil {
		return "", err
	}
	fillDPoPJKTFromContext(ctx, &opts)
	s.fillAuthTimeFromSession(ctx, &opts, sessionID)
	now := time.Now()
	expiresAt := now.Add(s.effectiveAccessTokenExpiry(ctx, user.TenantID))

	// Default to minimal tokens if UseMinimal is set OR if session cache is available
	useMinimal := opts.UseMinimal || s.sessionCache != nil

	var tokenString string
	var err error

	if useMinimal {
		var signedToken string
		signedToken, useMinimal, err = s.generateMinimalToken(ctx, user, sessionID, roles, permissions, opts, now, expiresAt)
		if err != nil {
			return "", err
		}
		if useMinimal {
			tokenString = signedToken
		}
	}

	// Fall back to legacy token format if minimal failed or not requested
	if !useMinimal {
		signed, signErr := s.generateLegacyToken(user, sessionID, roles, permissions, opts, now, expiresAt)
		if signErr != nil {
			return "", signErr
		}
		tokenString = signed
	}

	return tokenString, nil
}

// generateLegacyToken builds and signs a v0 legacy JWT with all claims embedded.
func (s *TokenService) generateLegacyToken(user *models.User, sessionID uuid.UUID, roles, permissions []string, opts TokenGenerationOptions, now, expiresAt time.Time) (string, error) {
	isPlatformAdmin := s.platformAuthority.AdminClaim(context.Background(), user.ID, user.TenantID, user.Email)
	// Multi-audience JWT (RFC 7519 §4.1.3) — see services/audience.go for the
	// rationale. Default is [LegacyServiceMeshAudience, PlatformAPIAudienceURI].
	// When the caller advertised a client_id, prepend it so receivers that
	// validate `aud === client_id` (per the audience-confusion defence) accept.
	legacyAudience := []string{LegacyServiceMeshAudience, PlatformAPIAudienceURI}
	if opts.ClientID != "" {
		legacyAudience = []string{opts.ClientID, LegacyServiceMeshAudience, PlatformAPIAudienceURI}
	}
	claims := jwt.MapClaims{
		"iss":               s.config.JWTIssuer,
		"aud":               legacyAudience,
		"sub":               user.ID.String(),
		"tenant_id":         user.TenantID.String(),
		"tid":               user.TenantID.String(),
		"user_id":           user.ID.String(),
		"username":          user.Username,
		"email":             user.Email,
		"roles":             roles,
		"permissions":       permissions,
		"session_id":        sessionID.String(),
		"iat":               now.Unix(),
		"exp":               expiresAt.Unix(),
		"nbf":               now.Unix(),
		"jti":               uuid.New().String(),
		"is_platform_admin": isPlatformAdmin,
		"realm_id":          opts.RealmID.String(),
		"v":                 models.TokenVersionLegacy,
	}
	if opts.RealmSlug != "" {
		claims["realm_slug"] = opts.RealmSlug
	}
	if opts.RealmType != "" {
		claims["realm_type"] = opts.RealmType
	}
	if opts.Scope != "" {
		claims["scope"] = opts.Scope
	}
	// RFC 9449 §6 DPoP binding — cnf.jkt pins the token to the holder's key.
	if opts.DPoPJKT != "" {
		claims["cnf"] = map[string]string{"jkt": opts.DPoPJKT}
	}
	// RFC 9470 §6.1 / OIDC Core §2 auth_time — preserved across refresh
	// so step-up freshness gates fire against the original authentication
	// event, not the most recent token rotation.
	if opts.AuthTime != 0 {
		claims["auth_time"] = opts.AuthTime
	}
	tokenString, err := s.signToken(claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign legacy token: %w", err)
	}
	logger.Info("Generated legacy JWT token",
		zap.String("session_id", sessionID.String()),
		zap.Int("token_size", len(tokenString)),
		zap.Int("permissions_count", len(permissions)),
	)
	return tokenString, nil
}

// generateMinimalToken builds and signs a v1 minimal JWT, storing session data in Redis.
// Returns (signedToken, stillMinimal, error). stillMinimal is false when Redis storage failed.
func (s *TokenService) generateMinimalToken(ctx context.Context, user *models.User, sessionID uuid.UUID, roles, permissions []string, opts TokenGenerationOptions, now time.Time, expiresAt time.Time) (string, bool, error) {
	// Multi-audience JWT — see services/audience.go for the migration
	// rationale. v1 minimal tokens always carry both the platform API
	// URI and the legacy mesh audience so receivers on either side of
	// the migration window accept the token.
	audience := jwt.ClaimStrings{LegacyServiceMeshAudience, PlatformAPIAudienceURI}
	if opts.ClientID != "" {
		audience = jwt.ClaimStrings{opts.ClientID, LegacyServiceMeshAudience, PlatformAPIAudienceURI}
	}
	minimalClaims := models.MinimalClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.JWTIssuer,
			Subject:   user.ID.String(),
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		SessionID:       sessionID,
		TenantID:        user.TenantID,
		TenantIDVerbose: user.TenantID, // mirrors "tid" under "tenant_id" for external consumers
		RealmID:         opts.RealmID,
		Roles:           roles,
		Scope:           opts.Scope,
		Version:         models.TokenVersionMinimal,
		AuthTime:        opts.AuthTime,
	}
	if opts.DPoPJKT != "" {
		minimalClaims.Confirmation = &models.Confirmation{JKT: opts.DPoPJKT}
	}
	var productClaims []ProductClaim
	if s.productSubscriptionResolver != nil {
		resolved, err := s.productSubscriptionResolver.Resolve(ctx, user.TenantID)
		if err != nil {
			logger.Warn("Failed to resolve product subscriptions for token",
				zap.Error(err),
				zap.String("tenant_id", user.TenantID.String()),
			)
		} else {
			productClaims = resolved
			minimalClaims.ProductSubscriptions = toProductSubscriptionClaims(productClaims)
		}
	}
	if s.sessionCache != nil {
		deviceInfo := ""
		if opts.DeviceInfo != nil {
			deviceInfo = *opts.DeviceInfo
		}
		ipAddress := ""
		if opts.IPAddress != nil {
			ipAddress = *opts.IPAddress
		}
		isPlatformAdmin := s.platformAuthority.AdminClaim(ctx, user.ID, user.TenantID, user.Email)
		var sessionProductSubs []redis.ProductSubscriptionClaim
		for _, pc := range productClaims {
			sessionProductSubs = append(sessionProductSubs, redis.ProductSubscriptionClaim{
				ProductID:   pc.ProductID,
				ProductSlug: pc.ProductSlug,
				PlanID:      pc.PlanID,
				State:       pc.State,
			})
		}
		sessionData := &redis.SessionData{
			UserID:               user.ID,
			TenantID:             user.TenantID,
			Username:             user.Username,
			Email:                user.Email,
			Roles:                roles,
			Permissions:          permissions,
			ProductSubscriptions: sessionProductSubs,
			RealmID:              opts.RealmID,
			RealmSlug:            opts.RealmSlug,
			RealmType:            opts.RealmType,
			RoleVersion:          opts.RoleVersion,
			DeviceInfo:           deviceInfo,
			IPAddress:            ipAddress,
			CreatedAt:            now.Unix(),
			IsPlatformAdmin:      isPlatformAdmin,
			ClientID:             opts.ClientID,
		}
		if err := s.sessionCache.SetSessionData(ctx, sessionID, sessionData); err != nil {
			logger.Warn("Failed to store session data in Redis, falling back to legacy token",
				zap.Error(err),
				zap.String("session_id", sessionID.String()),
			)
			return "", false, nil
		}
	}
	tokenString, err := s.signToken(minimalClaims)
	if err != nil {
		return "", false, fmt.Errorf("failed to sign minimal token: %w", err)
	}
	logger.Info("Generated minimal JWT token",
		zap.String("session_id", sessionID.String()),
		zap.Int("token_size", len(tokenString)),
		zap.Int("permissions_count", len(permissions)),
	)
	return tokenString, true, nil
}

// generateMinimalImpersonationToken builds and signs a v1 minimal JWT with impersonation context,
// storing session data in Redis. Returns (signedToken, stillMinimal, error).
// impersonationTokenTTL is the lifetime of an impersonation access token. There
// is no refresh token: the operator ends the session and starts a new one.
const impersonationTokenTTL = 15 * time.Minute

func (s *TokenService) generateMinimalImpersonationToken(ctx context.Context, user *models.User, sessionID uuid.UUID, roles, permissions []string, opts TokenGenerationOptions, now, expiresAt time.Time, realmID uuid.UUID, impersonatorID, impersonationSessionID uuid.UUID) (string, bool, error) {
	minimalClaims := models.MinimalClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  s.config.JWTIssuer,
			Subject: user.ID.String(),
			// Multi-aud (impersonation tokens still need to land on
			// every service in the mesh — see services/audience.go).
			Audience:  jwt.ClaimStrings{LegacyServiceMeshAudience, PlatformAPIAudienceURI},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		SessionID:       sessionID,
		TenantID:        user.TenantID,
		TenantIDVerbose: user.TenantID, // mirrors "tid" under "tenant_id" for external consumers
		RealmID:         realmID,
		Roles:           roles,
		Scope:           opts.Scope,
		Version:         models.TokenVersionMinimal,
		// RFC 8693 act: the operator on whose behalf the token acts.
		Act:                    &models.TokenActor{Sub: impersonatorID.String()},
		ImpersonatorID:         impersonatorID.String(),
		ImpersonationSessionID: impersonationSessionID.String(),
	}
	if s.sessionCache != nil {
		deviceInfo := ""
		if opts.DeviceInfo != nil {
			deviceInfo = *opts.DeviceInfo
		}
		ipAddress := ""
		if opts.IPAddress != nil {
			ipAddress = *opts.IPAddress
		}
		isPlatformAdmin := s.platformAuthority.AdminClaim(ctx, user.ID, user.TenantID, user.Email)
		sessionData := &redis.SessionData{
			UserID:                 user.ID,
			TenantID:               user.TenantID,
			Username:               user.Username,
			Email:                  user.Email,
			Roles:                  roles,
			Permissions:            permissions,
			RealmID:                realmID,
			RealmSlug:              opts.RealmSlug,
			RealmType:              opts.RealmType,
			RoleVersion:            opts.RoleVersion,
			DeviceInfo:             deviceInfo,
			IPAddress:              ipAddress,
			CreatedAt:              now.Unix(),
			ImpersonatorID:         &impersonatorID,
			ImpersonationSessionID: &impersonationSessionID,
			IsPlatformAdmin:        isPlatformAdmin,
		}
		if err := s.sessionCache.SetSessionData(ctx, sessionID, sessionData); err != nil {
			logger.Warn("Failed to store impersonation session data, falling back to legacy token",
				zap.Error(err),
				zap.String("session_id", sessionID.String()),
			)
			return "", false, nil
		}
	}
	tokenString, err := s.signToken(minimalClaims)
	if err != nil {
		return "", false, fmt.Errorf("failed to sign minimal impersonation token: %w", err)
	}
	logger.Info("Generated minimal impersonation JWT token",
		zap.String("session_id", sessionID.String()),
		zap.String("impersonator_id", impersonatorID.String()),
		zap.Int("token_size", len(tokenString)),
	)
	return tokenString, true, nil
}

// GenerateAccessTokenV2 creates an ultra-minimal JWT access token for SpiceDB-based authorization.
// This token format contains only identity information - ALL permissions are resolved via SpiceDB.
//
// Token Size: ~500 bytes (compared to 4-6KB for legacy)
//
// Use cases:
//   - Users with 100+ permissions (reduces network overhead)
//   - Real-time permission updates needed (no token refresh)
//   - Fine-grained resource-level permissions (ReBAC)
//
// Note: Session data is still stored in Redis for session management (logout, activity),
// but NOT for permission resolution.
func (s *TokenService) GenerateAccessTokenV2(ctx context.Context, user *models.User, sessionID uuid.UUID, roles []string, opts TokenGenerationOptions) (string, error) {
	if err := checkTenantNotSuspended(ctx, s.tenantSuspension, user.TenantID); err != nil {
		return "", err
	}
	fillDPoPJKTFromContext(ctx, &opts)
	// Resolve auth_time from the session row when the caller didn't
	// pre-thread it. Mirrors the v1 mint path
	// (GenerateAccessTokenWithOptions). MUST be called BEFORE the
	// SpiceDBClaims struct literal below — the struct copies
	// opts.AuthTime by value at construction time, so a later assignment
	// to opts wouldn't surface on the issued token. Without this call
	// every v2 (SpiceDB) token ships with no auth_time claim and every
	// RFC 9470 max_age gate downstream sees CurrentUser.AuthTime==0 →
	// "infinitely stale" → infinite redirect loop after fresh re-auth.
	s.fillAuthTimeFromSession(ctx, &opts, sessionID)
	now := time.Now()
	expiresAt := now.Add(s.effectiveAccessTokenExpiry(ctx, user.TenantID))

	// Use default realm if not set
	realmID := opts.RealmID
	if realmID == uuid.Nil && user.RealmID != uuid.Nil {
		realmID = user.RealmID
	}
	if realmID == uuid.Nil {
		realmID = models.DefaultRealmID
	}

	// Generate SpiceDB-optimized claims (v2) — multi-aud, see
	// services/audience.go for rationale.
	v2Audience := jwt.ClaimStrings{LegacyServiceMeshAudience, PlatformAPIAudienceURI}
	if opts.ClientID != "" {
		v2Audience = jwt.ClaimStrings{opts.ClientID, LegacyServiceMeshAudience, PlatformAPIAudienceURI}
	}
	spicedbClaims := models.SpiceDBClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.JWTIssuer,
			Subject:   user.ID.String(),
			Audience:  v2Audience,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(), // JTI for revocation tracking
		},
		SessionID:       sessionID,
		TenantID:        user.TenantID,
		TenantIDVerbose: user.TenantID, // mirrors "tid" under "tenant_id" for external consumers
		RealmID:         realmID,
		Roles:           roles,
		Version:         models.TokenVersionSpiceDB,
		AuthTime:        opts.AuthTime,
	}
	if opts.DPoPJKT != "" {
		spicedbClaims.Confirmation = &models.Confirmation{JKT: opts.DPoPJKT}
	}

	// Resolve active product subscriptions, exactly like the v1 minimal
	// mint path (generateMinimalToken) does. This was missing entirely
	// for v2 tokens — see the ProductSubscriptions field doc on
	// models.SpiceDBClaims for why that is a production-impacting bug,
	// not a stylistic gap. Best-effort: a resolver failure logs and
	// leaves the claim empty rather than failing token issuance, same
	// as the v1 path.
	var productClaims []ProductClaim
	if s.productSubscriptionResolver != nil {
		resolved, err := s.productSubscriptionResolver.Resolve(ctx, user.TenantID)
		if err != nil {
			logger.Warn("Failed to resolve product subscriptions for v2 token",
				zap.Error(err),
				zap.String("tenant_id", user.TenantID.String()),
			)
		} else {
			productClaims = resolved
			spicedbClaims.ProductSubscriptions = toProductSubscriptionClaims(productClaims)
		}
	}

	// Sign token
	tokenString, err := s.signToken(spicedbClaims)
	if err != nil {
		return "", fmt.Errorf("failed to sign v2 token: %w", err)
	}

	// Store minimal session data in Redis for session management only
	// (logout, activity tracking - NOT for permission resolution)
	if s.sessionCache != nil {
		deviceInfo := ""
		if opts.DeviceInfo != nil {
			deviceInfo = *opts.DeviceInfo
		}
		ipAddress := ""
		if opts.IPAddress != nil {
			ipAddress = *opts.IPAddress
		}

		isPlatformAdmin := s.platformAuthority.AdminClaim(ctx, user.ID, user.TenantID, user.Email)
		sessionData := &redis.SessionData{
			UserID:          user.ID,
			TenantID:        user.TenantID,
			Username:        user.Username,
			Email:           user.Email,
			Roles:           nil, // Not stored - resolved from SpiceDB
			Permissions:     nil, // Not stored - resolved from SpiceDB
			RealmID:         realmID,
			RealmSlug:       opts.RealmSlug,
			RealmType:       opts.RealmType,
			RoleVersion:     opts.RoleVersion,
			DeviceInfo:      deviceInfo,
			IPAddress:       ipAddress,
			CreatedAt:       now.Unix(),
			IsPlatformAdmin: isPlatformAdmin,
			ClientID:        opts.ClientID,
		}

		if err := s.sessionCache.SetSessionData(ctx, sessionID, sessionData); err != nil {
			// Log but don't fail - v2 tokens don't require session cache for auth
			logger.Warn("Failed to store v2 session data in Redis",
				zap.Error(err),
				zap.String("session_id", sessionID.String()),
			)
		}
	}

	// Log token generation
	logger.Info("Generated v2 (SpiceDB) JWT token",
		zap.String("session_id", sessionID.String()),
		zap.String("user_id", user.ID.String()),
		zap.Int("token_size", len(tokenString)),
	)

	return tokenString, nil
}

// ShouldUseV2Token determines if a user should receive a v2 (SpiceDB) token.
// Uses canary deployment percentage for gradual rollout.
func (s *TokenService) ShouldUseV2Token(userID uuid.UUID) bool {
	if !s.config.SpiceDBTokenV2Enabled {
		return false
	}

	// 100% means all users get v2 tokens
	if s.config.SpiceDBTokenV2Percentage >= 100 {
		return true
	}

	// 0% means no users get v2 tokens
	if s.config.SpiceDBTokenV2Percentage <= 0 {
		return false
	}

	// Use user ID hash for consistent assignment (same user always gets same token type)
	// This ensures a user doesn't flip between v1 and v2 on different logins
	hash := userID[0] // Use first byte of UUID for simple distribution
	threshold := byte(255 * s.config.SpiceDBTokenV2Percentage / 100)
	return hash < threshold
}

// GenerateImpersonationAccessToken creates a JWT access token for impersonation
func (s *TokenService) GenerateImpersonationAccessToken(
	ctx context.Context,
	user *models.User,
	sessionID uuid.UUID,
	roles []string,
	permissions []string,
	impersonatorID uuid.UUID,
	impersonationSessionID uuid.UUID,
) (string, error) {
	return s.GenerateImpersonationAccessTokenWithOptions(
		ctx, user, sessionID, roles, permissions, impersonatorID, impersonationSessionID,
		TokenGenerationOptions{
			RealmID:   user.RealmID,
			RealmType: string(models.RealmTypeShared),
			Scope:     "tenant",
		},
	)
}

// GenerateImpersonationAccessTokenWithOptions creates a JWT access token for impersonation with realm context
// Supports both legacy (v0) and minimal (v1) token formats
func (s *TokenService) GenerateImpersonationAccessTokenWithOptions(
	ctx context.Context,
	user *models.User,
	sessionID uuid.UUID,
	roles []string,
	permissions []string,
	impersonatorID uuid.UUID,
	impersonationSessionID uuid.UUID,
	opts TokenGenerationOptions,
) (string, error) {
	if err := checkTenantNotSuspended(ctx, s.tenantSuspension, user.TenantID); err != nil {
		return "", err
	}
	now := time.Now()
	// Impersonation tokens have shorter expiry (15 minutes)
	expiresAt := now.Add(impersonationTokenTTL)

	// Use default realm if not set
	realmID := opts.RealmID
	if realmID == uuid.Nil {
		realmID = models.DefaultRealmID
	}

	// Default to minimal tokens if UseMinimal is set OR if session cache is available
	useMinimal := opts.UseMinimal || s.sessionCache != nil

	var tokenString string
	var err error

	if useMinimal {
		var signedToken string
		signedToken, useMinimal, err = s.generateMinimalImpersonationToken(ctx, user, sessionID, roles, permissions, opts, now, expiresAt, realmID, impersonatorID, impersonationSessionID)
		if err != nil {
			return "", err
		}
		if useMinimal {
			tokenString = signedToken
		}
	}

	// Fall back to legacy token format
	if !useMinimal {
		claims := jwt.MapClaims{
			"iss": s.config.JWTIssuer,
			// Multi-aud (legacy impersonation fallback) — see services/audience.go.
			"aud":                      []string{LegacyServiceMeshAudience, PlatformAPIAudienceURI},
			"sub":                      user.ID.String(),
			"tenant_id":                user.TenantID.String(),
			"tid":                      user.TenantID.String(), // SECURITY: Tenant affinity claim for gateway-level validation
			"user_id":                  user.ID.String(),
			"username":                 user.Username,
			"email":                    user.Email,
			"roles":                    roles,
			"permissions":              permissions,
			"session_id":               sessionID.String(),
			"iat":                      now.Unix(),
			"exp":                      expiresAt.Unix(),
			"nbf":                      now.Unix(),
			"jti":                      uuid.New().String(),
			"impersonator_id":          impersonatorID.String(),
			"act":                      map[string]interface{}{"sub": impersonatorID.String()},
			"impersonation_session_id": impersonationSessionID.String(),
			"realm_id":                 realmID.String(),
			"v":                        models.TokenVersionLegacy,
		}

		// Add optional realm fields
		if opts.RealmSlug != "" {
			claims["realm_slug"] = opts.RealmSlug
		}
		if opts.RealmType != "" {
			claims["realm_type"] = opts.RealmType
		}
		if opts.Scope != "" {
			claims["scope"] = opts.Scope
		}

		tokenString, err = s.signToken(claims)
		if err != nil {
			return "", fmt.Errorf("failed to sign legacy impersonation token: %w", err)
		}

		logger.Info("Generated legacy impersonation JWT token",
			zap.String("session_id", sessionID.String()),
			zap.String("impersonator_id", impersonatorID.String()),
			zap.Int("token_size", len(tokenString)),
		)
	}

	return tokenString, nil
}

// Token validation, refresh, password reset, and parsing methods are in token_service_validation.go
