// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/internal/shared/httpclient"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	falconcrypto "github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// oauthStateTTL is the maximum lifetime of a CSRF state token for OAuth flows.
const oauthStateTTL = 10 * time.Minute

const (
	// appleJWKSURL is Apple's public key endpoint for verifying id_token signatures.
	appleJWKSURL = "https://appleid.apple.com/auth/keys"
	// appleJWKSCacheTTL controls how long we cache Apple's JWKS before re-fetching.
	appleJWKSCacheTTL = 1 * time.Hour
)

// appleJWKSCache holds cached Apple public keys.
type appleJWKSCache struct {
	keys      map[string]interface{} // kid -> *ecdsa.PublicKey or *rsa.PublicKey
	fetchedAt time.Time
}

// appleJWK represents a single key from Apple's JWKS response.
type appleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
}

// ssoRedisClient provides minimal Redis access for SSO MFA sessions.
// This interface is satisfied by *redis.Client from go-redis and by the project's
// SessionCacheService, allowing the service layer to remain decoupled from the
// concrete Redis implementation.
type ssoRedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
}

// SocialAuthService is an exported type.
type SocialAuthService struct {
	config  *config.Config
	idpRepo *repositories.IdentityProviderRepository
	// Interfaces, not concrete repositories — see social_auth_repos.go.
	// The concrete types satisfy them structurally, so constructors are
	// unchanged; this exists so the federation path can be executed in a
	// test at all.
	fedAccountRepo socialAuthFedAccountRepo
	userRepo       socialAuthUserRepo
	roleRepo       socialAuthRoleRepo
	tokenService   *TokenService
	auditService   *AuditService
	httpClient     *httpclient.ServiceClient

	// stateStore holds CSRF state tokens for OAuth authorization flows.
	// Each entry is automatically removed after oauthStateTTL via time.AfterFunc.
	stateStore sync.Map

	// appleJWKS caches Apple's public keys fetched from their JWKS endpoint.
	// Protected by appleJWKSMu; refreshed when expired or key not found.
	appleJWKSMu sync.RWMutex
	appleJWKS   *appleJWKSCache

	// sessionRepo creates database session records for SSO logins,
	// enabling session revocation and concurrent session control.
	sessionRepo *repositories.SessionRepository

	// encryptionService decrypts client secrets stored encrypted in the database.
	encryptionService *falconcrypto.EncryptionService

	// Optional dependencies for MFA/risk integration with SSO.
	// These are set via setter methods after construction, keeping the
	// constructor signature stable while supporting Phase 4 features.
	mfaService    *MFAService
	riskService   *RiskService
	deviceService *DeviceService
	redisClient   ssoRedisClient
	tenantRepo    *repositories.TenantRepository
}

// NewSocialAuthService is an exported function.
func NewSocialAuthService(
	cfg *config.Config,
	idpRepo *repositories.IdentityProviderRepository,
	fedAccountRepo *repositories.FederatedAccountRepository,
	userRepo *repositories.UserRepository,
	roleRepo *repositories.RoleRepository,
	tokenService *TokenService,
	auditService *AuditService,
) *SocialAuthService {
	httpLogger := zap.NewNop()
	client := httpclient.NewServiceClient(
		"iam",
		"", // No base URL - social auth has dynamic URLs
		httpLogger,
		httpclient.WithTimeout(httpclient.ExternalAPITimeout),
		httpclient.WithMaxRetries(3),
	)
	return &SocialAuthService{
		config:         cfg,
		idpRepo:        idpRepo,
		fedAccountRepo: fedAccountRepo,
		userRepo:       userRepo,
		roleRepo:       roleRepo,
		tokenService:   tokenService,
		auditService:   auditService,
		httpClient:     client,
	}
}

// SetMFAService injects an MFA service for SSO MFA challenge flows.
func (s *SocialAuthService) SetMFAService(mfaService *MFAService) {
	s.mfaService = mfaService
}

// SetRiskService injects a risk assessment service for login risk evaluation.
func (s *SocialAuthService) SetRiskService(riskService *RiskService) {
	s.riskService = riskService
}

// SetDeviceService injects a device service for device trust checks.
func (s *SocialAuthService) SetDeviceService(deviceService *DeviceService) {
	s.deviceService = deviceService
}

// SetRedisClient injects a Redis client used to store temporary MFA sessions
// created during SSO callback processing.
func (s *SocialAuthService) SetRedisClient(client ssoRedisClient) {
	s.redisClient = client
}

// SetSessionRepository injects the session repository for creating database
// session records during SSO login, enabling session revocation and audit.
func (s *SocialAuthService) SetSessionRepository(repo *repositories.SessionRepository) {
	s.sessionRepo = repo
}

// SetTenantRepository injects the tenant repository for tenant lookups.
func (s *SocialAuthService) SetTenantRepository(repo *repositories.TenantRepository) {
	s.tenantRepo = repo
}

// SetEncryptionService injects the encryption service for decrypting
// client secrets stored encrypted in the database.
func (s *SocialAuthService) SetEncryptionService(svc *falconcrypto.EncryptionService) {
	s.encryptionService = svc
}

// oauthStateEntry is what the state store holds against an issued state.
//
// Before t-150 the stored value was the cleanup timer ALONE, so validation
// could only ever answer "was this issued and not yet consumed". The binding
// hash is what lets it also answer "by the browser now presenting it".
//
// Only the SHA-256 of the binding secret is retained. The secret itself lives
// exclusively in the caller's browser cookie, so a dump of this store — a heap
// capture, a future move to Redis, a log of the map — yields nothing that can
// complete a flow.
type oauthStateEntry struct {
	timer       *time.Timer
	bindingHash [sha256.Size]byte
}

// GenerateOAuthState creates a cryptographically random state value together
// with a BROWSER BINDING SECRET, stores the state with the hash of that secret
// under a TTL, and returns both. The caller must put the state in the
// authorization URL, store the binding secret in a __Host--prefixed cookie,
// and present it again at the callback via ValidateOAuthState.
//
// WHY THE SERVER ISSUES THE BINDING RATHER THAN ACCEPTING ONE (d-064). If the
// caller supplied it, a caller that supplied nothing would silently receive an
// UNBOUND state and the control would be absent exactly where somebody forgot
// to integrate it — the same defaults-to-false trap as SPWantSigned (t-086)
// and CreateUsers (t-132). Issuing it here and refusing a callback that cannot
// present it makes binding the default rather than an integration detail.
//
// WHY __Host- SPECIFICALLY, and why the binding is useless without it: the
// threat is an attacker PLANTING a cookie from a sibling *.example.com origin
// via Domain=.example.com. A binding secret carried in a plantable cookie is
// planted along with it and matches by construction. The __Host- prefix is
// what makes the cookie un-plantable — browsers reject the prefix unless the
// cookie is Secure, Path=/ and carries NO Domain attribute, and cross-site
// planting requires exactly the Domain attribute the prefix forbids.
func (s *SocialAuthService) GenerateOAuthState() (state string, bindingSecret string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random state: %w", err)
	}
	state = base64.RawURLEncoding.EncodeToString(b)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate state binding: %w", err)
	}
	bindingSecret = base64.RawURLEncoding.EncodeToString(nonce)

	// Schedule automatic cleanup after TTL so stale entries do not leak.
	timer := time.AfterFunc(oauthStateTTL, func() {
		s.stateStore.Delete(state)
	})
	s.stateStore.Store(state, &oauthStateEntry{
		timer:       timer,
		bindingHash: sha256.Sum256([]byte(bindingSecret)),
	})

	return state, bindingSecret, nil
}

// ValidateOAuthState checks that the provided state was issued by
// GenerateOAuthState, has not expired, AND is being presented by the same
// browser it was issued to. The state is consumed (deleted) on any lookup hit,
// successful or not, so it can never be re-presented.
//
// CONSUMED BEFORE THE BINDING IS CHECKED, deliberately: a wrong binding means
// either an attack or a broken client, and in both cases the state is burned.
// Leaving it live on a binding failure would hand an attacker unlimited
// guesses against the hash.
func (s *SocialAuthService) ValidateOAuthState(state, bindingSecret string) error {
	if state == "" {
		return fmt.Errorf("missing OAuth state parameter")
	}
	val, loaded := s.stateStore.LoadAndDelete(state)
	if !loaded {
		return fmt.Errorf("invalid or expired OAuth state parameter")
	}

	entry, ok := val.(*oauthStateEntry)
	if !ok {
		// Defensive: nothing else writes this map. A foreign value means the
		// store has been corrupted, which is not something to interpret.
		return fmt.Errorf("invalid or expired OAuth state parameter")
	}
	// Cancel the cleanup timer since we consumed the state early.
	if entry.timer != nil {
		entry.timer.Stop()
	}

	if bindingSecret == "" {
		return ErrOAuthStateBindingMissing
	}

	// Constant-time: the presented secret is attacker-controlled and a
	// byte-wise early exit would leak how much of it was correct.
	presented := sha256.Sum256([]byte(bindingSecret))
	if subtle.ConstantTimeCompare(presented[:], entry.bindingHash[:]) != 1 {
		return ErrOAuthStateBindingMismatch
	}
	return nil
}

// GetAuthorizationURL generates the OAuth2 authorization URL for a provider.
// For Apple Sign In providers, the response_mode and response_type parameters
// are set to satisfy Apple's form_post requirements.
func (s *SocialAuthService) GetAuthorizationURL(ctx context.Context, tenantID, providerID uuid.UUID, redirectURI, state string) (string, error) {
	// Get provider configuration
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return "", fmt.Errorf("failed to get provider: %w", err)
	}
	if provider == nil {
		return "", fmt.Errorf("provider not found")
	}

	// Verify provider belongs to tenant
	if provider.TenantID != tenantID {
		return "", fmt.Errorf("provider does not belong to tenant")
	}

	// Verify provider is active
	if !provider.IsEnabled {
		return "", fmt.Errorf("provider is not active")
	}

	// Parse OAuth2 config from provider
	oauth2Cfg, err := s.parseOAuth2Config(provider)
	if err != nil {
		return "", fmt.Errorf("failed to parse OAuth2 config: %w", err)
	}

	// BACKSTOP: refuse an incompletely configured provider rather than building a
	// redirect from it. Without this an enabled-but-uncredentialed row sends the
	// user to the IdP with client_id= empty, so the failure surfaces on the IdP's
	// property after our button looked fine -- a worse failure than refusing, and
	// one we cannot diagnose from our own logs.
	if cfgErr := provider.LoginConfigurationError(); cfgErr != nil {
		return "", fmt.Errorf("cannot start login: %w", cfgErr)
	}

	// Validate redirect URI against the provider's registered callback URL.
	//
	// The stored value is the authority. The exact-match guard used to be nested
	// inside `oauth2Cfg.RedirectURL != ""`, so a provider row WITHOUT a registered
	// callback accepted whatever the caller supplied -- the guard silently did not
	// apply in exactly the configuration where nothing else constrained the value.
	// Absent configuration must refuse, not defer to the caller.
	if redirectURI != "" {
		if oauth2Cfg.RedirectURL == "" {
			return "", fmt.Errorf("cannot honour a caller-supplied redirect_uri: provider %q has no registered callback URL to validate it against", provider.Name)
		}
		if redirectURI != oauth2Cfg.RedirectURL {
			return "", fmt.Errorf("redirect_uri does not match the provider's registered callback URL")
		}
		oauth2Cfg.RedirectURL = redirectURI
	}

	// Generate authorization URL
	authURL := oauth2Cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// Apple Sign In requires response_mode=form_post for web flows.
	// We add this after generating the base URL so other provider types
	// are not affected.
	if provider.Type == "apple" {
		u, err := url.Parse(authURL)
		if err == nil {
			q := u.Query()
			q.Set("response_mode", "form_post")
			q.Set("response_type", "code")
			u.RawQuery = q.Encode()
			authURL = u.String()
		}
	}

	logger.Debug("Generated OAuth2 authorization URL",
		zap.String("provider", provider.Name),
		zap.String("type", provider.Type),
		zap.String("url", authURL),
	)

	return authURL, nil
}

// HandleCallback handles the OAuth2 callback and authenticates the user.
// The ipAddress, userAgent, and deviceID parameters are used for risk assessment
// and MFA challenge creation when Phase 4 dependencies are wired in.
func (s *SocialAuthService) HandleCallback(ctx context.Context, tenantID uuid.UUID, providerName, code, _, ipAddress, userAgent, _ string) (*models.LoginResponse, error) {
	provider, err := s.resolveOAuthProvider(ctx, tenantID, providerName)
	if err != nil {
		return nil, err
	}

	oauth2Token, userInfo, err := s.exchangeOAuthCode(ctx, provider, code)
	if err != nil {
		return nil, err
	}

	// Resolve identity by PROVIDER SUBJECT before any user lookup.
	//
	// The subject (OIDC `sub`, GitHub numeric id, ...) is the only stable
	// provider-asserted identifier available here. Email is mutable and, on
	// several providers, settable by the holder without verification, so
	// resolving on email lets a caller claim any account whose address they
	// know. See resolveUserForFederation.
	providerUserID := s.extractProviderUserID(provider, userInfo)
	if providerUserID == "" {
		// extractProviderUserID returns "" when the response carries neither
		// sub nor id. Refuse rather than fall back to email — an empty subject
		// would otherwise be stored and later matched by GetByProviderUserID.
		logger.Error("Provider returned no subject identifier",
			zap.String("provider", provider.Name), zap.String("provider_type", provider.Type))
		return nil, fmt.Errorf("provider did not return a stable subject identifier")
	}

	fedAccount, err := s.fedAccountRepo.GetByProviderUserID(ctx, provider.ID, providerUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to check federated account: %w", err)
	}

	user, err := s.resolveUserForFederation(ctx, provider, userInfo, fedAccount)
	if err != nil {
		logger.Error("Failed to resolve user for federation", zap.Error(err))
		return nil, err
	}

	if !user.IsActive {
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "account disabled")
		return nil, fmt.Errorf("account is disabled")
	}

	isFirstFederation, err := s.upsertFederatedAccount(ctx, user, provider, oauth2Token, userInfo, fedAccount)
	if err != nil {
		return nil, err
	}

	// MFA enforcement is UNCONDITIONAL. It was previously reachable only when
	// riskService was wired, and within that, only when assessment succeeded —
	// so a nil riskService or a risk outage silently skipped MFA for users who
	// have a factor enrolled. assessSSOLoginRisk now guards risk internally.
	resp, mfaErr := s.assessSSOLoginRisk(ctx, tenantID, user, provider, ipAddress, userAgent, isFirstFederation)
	if mfaErr != nil {
		return nil, mfaErr
	}
	if resp != nil {
		return resp, nil
	}

	return s.issueSSOTokensAndSession(ctx, tenantID, user, ipAddress, userAgent)
}

// resolveOAuthProvider finds an IdentityProvider by name across all OAuth-like types.
//
// Since 2026-05-21 the underlying repo returns providers regardless of
// `is_active` (Tier-A audit memo — repo is a thin data accessor). This
// method now branches:
//
//   - provider exists + IsEnabled=true  → return it
//   - provider exists + IsEnabled=false → log warn + "provider disabled"
//   - provider does not exist           → "provider not found"
//
// The structured warn `social_auth.disabled_provider_attempted`
// carries tenant_id, provider_id, provider_name so the SOC can
// pivot on "user trying to use a recently-disabled SSO link" —
// often a bookmark-staleness signal but useful for tenant admins
// tracking adoption of a deprecation.
func (s *SocialAuthService) resolveOAuthProvider(ctx context.Context, tenantID uuid.UUID, providerName string) (*models.IdentityProvider, error) {
	providerTypes := []string{"oauth", "google", "microsoft", "github", "linkedin", "oidc", "apple"}
	for _, pType := range providerTypes {
		providers, err := s.idpRepo.GetByTenantAndType(ctx, tenantID, pType)
		if err != nil {
			continue
		}
		for _, p := range providers {
			if !strings.EqualFold(p.Name, providerName) {
				continue
			}
			if !p.IsEnabled {
				logger.Log.Warn("social_auth.disabled_provider_attempted",
					zap.String("tenant_id", tenantID.String()),
					zap.String("provider_id", p.ID.String()),
					zap.String("provider_name", p.Name),
					zap.String("provider_type", p.Type),
				)
				return nil, fmt.Errorf("provider disabled")
			}
			return p, nil
		}
	}
	return nil, fmt.Errorf("provider not found")
}

// exchangeOAuthCode exchanges the authorization code for tokens and user info.
func (s *SocialAuthService) exchangeOAuthCode(ctx context.Context, provider *models.IdentityProvider, code string) (*oauth2.Token, map[string]interface{}, error) {
	if provider.Type == "apple" {
		oauth2Token, userInfo, err := s.handleAppleCallback(ctx, provider, code)
		if err != nil {
			logger.Error("Apple callback failed", zap.Error(err))
			return nil, nil, fmt.Errorf("failed to handle apple callback: %w", err)
		}
		return oauth2Token, userInfo, nil
	}
	oauth2Token, err := s.exchangeCode(ctx, provider, code, "")
	if err != nil {
		logger.Error("Failed to exchange code", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	userInfo, err := s.getUserInfo(ctx, provider, oauth2Token.AccessToken)
	if err != nil {
		logger.Error("Failed to get user info", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}
	return oauth2Token, userInfo, nil
}

// upsertFederatedAccount creates or updates the federated account record and returns isFirstFederation.
// fedAccount is the record already resolved by the caller from the provider
// subject; passing it in avoids a second identical lookup and, more importantly,
// guarantees the caller and this function agree on which identity is being used.
func (s *SocialAuthService) upsertFederatedAccount(ctx context.Context, user *models.User, provider *models.IdentityProvider, oauth2Token *oauth2.Token, userInfo map[string]interface{}, fedAccount *models.FederatedAccount) (bool, error) {
	providerUserID := s.extractProviderUserID(provider, userInfo)
	isFirstFederation := fedAccount == nil
	now := time.Now()
	if fedAccount == nil {
		fedAccount = &models.FederatedAccount{
			UserID:         user.ID,
			ProviderID:     provider.ID,
			ProviderUserID: providerUserID,
			FirstLinkedAt:  now,
		}
		s.applyOAuthTokenToFedAccount(fedAccount, oauth2Token, userInfo, provider, now)
		if err := s.fedAccountRepo.Create(ctx, fedAccount); err != nil {
			return false, fmt.Errorf("failed to create federated account: %w", err)
		}
	} else {
		s.applyOAuthTokenToFedAccount(fedAccount, oauth2Token, userInfo, provider, now)
		if err := s.fedAccountRepo.Update(ctx, fedAccount); err != nil {
			return false, fmt.Errorf("failed to update federated account: %w", err)
		}
	}
	return isFirstFederation, nil
}

// applyOAuthTokenToFedAccount sets token fields and optional PII on a FederatedAccount.
func (s *SocialAuthService) applyOAuthTokenToFedAccount(fedAccount *models.FederatedAccount, oauth2Token *oauth2.Token, userInfo map[string]interface{}, provider *models.IdentityProvider, now time.Time) {
	fedAccount.AccessToken = &oauth2Token.AccessToken
	fedAccount.RefreshToken = &oauth2Token.RefreshToken
	fedAccount.ProfileData = userInfo
	fedAccount.LastUsedAt = &now
	if !oauth2Token.Expiry.IsZero() {
		fedAccount.TokenExpiresAt = &oauth2Token.Expiry
	}
	if email, ok := userInfo["email"].(string); ok {
		fedAccount.ProviderEmail = &email
	}
	if username := s.extractUsername(provider, userInfo); username != "" {
		fedAccount.ProviderUsername = &username
	}
}

// assessSSOLoginRisk evaluates risk and optionally returns an MFA challenge response.
// Returns (nil, nil) when login should proceed normally.
func (s *SocialAuthService) assessSSOLoginRisk(ctx context.Context, tenantID uuid.UUID, user *models.User, provider *models.IdentityProvider, ipAddress, userAgent string, isFirstFederation bool) (*models.LoginResponse, error) {
	var assessment *models.RiskAssessment
	riskCtx := &models.RiskContext{
		UserID:            user.ID,
		TenantID:          tenantID,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		LoginTime:         time.Now(),
		AuthMethod:        "sso",
		SSOProvider:       provider.Type,
		IsFirstFederation: isFirstFederation,
	}
	if s.riskService != nil {
		if s.deviceService != nil && ipAddress != "" {
			isNew, _, deviceErr := s.deviceService.CheckDeviceIsNew(ctx, user.ID, userAgent, ipAddress)
			if deviceErr != nil {
				logger.Error("SSO device check failed", zap.Error(deviceErr))
			} else {
				riskCtx.IsNewDevice = isNew
			}
		}
		a, assessErr := s.riskService.AssessLoginRisk(ctx, riskCtx)
		if assessErr != nil {
			// A risk-service outage must not lock everyone out, so we continue
			// without a risk signal — but we must NOT also skip MFA, which is
			// what returning here previously did. Fall through with a nil
			// assessment; the factor inventory check below still runs.
			logger.Error("SSO risk assessment failed", zap.Error(assessErr))
		} else {
			assessment = a
		}
	}
	if assessment != nil && assessment.Blocked {
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, assessment.BlockReason)
		return nil, fmt.Errorf("login blocked: %s", assessment.BlockReason)
	}
	// Source-of-truth factor inventory check (companion to auth_service +
	// SAML SP + OAuth /authorize gate). Denormalized user.MFAEnabled
	// can drift; the table-level EXISTS query cannot.
	hasFactor, factorErr := s.userRepo.HasAnyMFAFactor(ctx, user.ID)
	if factorErr != nil {
		return nil, fmt.Errorf("social auth: check MFA factor inventory: %w", factorErr)
	}
	// An enrolled factor requires MFA on its own. Risk may only ESCALATE this,
	// never supply it — so a nil riskService or a failed assessment can no
	// longer downgrade a user who has MFA enrolled.
	mfaRequired := hasFactor
	if assessment != nil && assessment.RequiresMFA {
		mfaRequired = true
	}
	if mfaRequired && s.deviceService != nil && ipAddress != "" {
		trusted, trustErr := s.deviceService.IsTrustedDevice(ctx, user.ID, userAgent, ipAddress, nil)
		if trustErr != nil {
			logger.Error("SSO trusted device check failed", zap.Error(trustErr))
		} else if trusted {
			mfaRequired = false
		}
	}
	// Two distinct outcomes, deliberately not collapsed into one condition.
	//
	// No MFA needed: proceed to token issuance.
	if !mfaRequired {
		return nil, nil
	}

	// MFA IS needed but we cannot issue the challenge. Fail CLOSED.
	//
	// The MFA session is stored in Redis, and wireTokenServiceRedis
	// (cmd/services.go) early-returns without calling SetRedisClient when
	// infra.RedisClient is nil — which initRedisComponents does deliberately,
	// logging "continuing without Redis features", whenever Redis is
	// unreachable at boot. So this is a reachable state, not a theoretical one.
	//
	// These two conditions used to share a branch (`if !mfaRequired ||
	// s.redisClient == nil { return nil, nil }`), which meant an absent cache
	// silently downgraded a user who had a factor enrolled: they signed in via
	// SSO with no second factor. MFA is not optional because infrastructure is
	// missing. The password path already gets this right — auth_service.go
	// challenges inline with no Redis in the gate.
	if s.redisClient == nil {
		logger.Error("SSO login refused: MFA required but no Redis client is configured for MFA sessions",
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", tenantID.String()))
		s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, false, "mfa required but mfa session store unavailable")
		return nil, fmt.Errorf("multi-factor authentication is required but cannot be completed right now")
	}

	return s.createSSOMFASession(ctx, tenantID, user, ipAddress, userAgent)
}

// createSSOMFASession creates a temporary MFA session in Redis and returns the MFA challenge response.
func (s *SocialAuthService) createSSOMFASession(ctx context.Context, tenantID uuid.UUID, user *models.User, ipAddress, userAgent string) (*models.LoginResponse, error) {
	mfaSessionID := uuid.New().String()
	sessionData := &models.MFASessionData{
		UserID:     user.ID.String(),
		TenantID:   tenantID.String(),
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		AuthMethod: "sso",
		CreatedAt:  time.Now().Unix(),
	}
	sessionJSON, marshalErr := json.Marshal(sessionData)
	if marshalErr != nil {
		return nil, fmt.Errorf("failed to marshal MFA session: %w", marshalErr)
	}
	redisKey := "mfa:session:" + mfaSessionID
	if setErr := s.redisClient.Set(ctx, redisKey, string(sessionJSON), 5*time.Minute); setErr != nil {
		return nil, fmt.Errorf("failed to store MFA session: %w", setErr)
	}
	methods := make([]string, 0, 2)
	if user.MFATOTPEnabled {
		methods = append(methods, "totp")
	}
	if user.MFAEmailEnabled {
		methods = append(methods, "email")
	}
	if len(methods) == 0 {
		methods = append(methods, "totp")
	}
	return &models.LoginResponse{
		RequiresMFA:         true,
		MFAMethod:           methods[0],
		AvailableMFAMethods: methods,
		SessionID:           mfaSessionID,
	}, nil
}

// issueSSOTokensAndSession creates a session record and issues JWTs for a successful SSO login.
func (s *SocialAuthService) issueSSOTokensAndSession(ctx context.Context, tenantID uuid.UUID, user *models.User, ipAddress, userAgent string) (*models.LoginResponse, error) {
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	permissions, err := s.userRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	permNames := make([]string, len(permissions))
	for i, p := range permissions {
		permNames[i] = p.Name
	}
	var sessionID uuid.UUID
	if s.sessionRepo != nil {
		sessionTokenHash, hashErr := falconcrypto.HashToken(uuid.New().String())
		if hashErr != nil {
			return nil, fmt.Errorf("failed to hash session token: %w", hashErr)
		}
		deviceInfo := parseDeviceInfo(userAgent)
		session := &models.Session{
			UserID:           user.ID,
			SessionTokenHash: sessionTokenHash,
			DeviceInfo:       &deviceInfo,
			IPAddress:        &ipAddress,
			UserAgent:        &userAgent,
			ExpiresAt:        time.Now().Add(s.config.SessionExpiry),
		}
		if createErr := s.sessionRepo.Create(ctx, session); createErr != nil {
			return nil, fmt.Errorf("failed to create SSO session: %w", createErr)
		}
		sessionID = session.ID
	} else {
		sessionID = uuid.New()
	}
	accessToken, err := s.tokenService.GenerateAccessToken(ctx, user, sessionID, roleNames, permNames)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	// Phase 3 (mig 233): auth-service refresh tokens removed — see
	// auth_service.go:generateTokens for the architectural rationale.
	// Returning empty refresh_token preserves the response shape; the
	// social-callback BFF runs the OAuth dance to mint OIDC tokens via
	// /oauth/token (frontend!25 — Phase 1.3).
	refreshToken := ""
	lastLoginTime := time.Now()
	user.LastLoginAt = &lastLoginTime
	if err := s.userRepo.Update(ctx, user); err != nil {
		logger.Error("Failed to update user last login", zap.Error(err))
	}
	s.auditService.LogLogin(ctx, tenantID, &user.ID, ipAddress, userAgent, true, "")
	user.Roles = roles
	user.Permissions = permissions
	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
		User:         user.ToResponse(),
	}, nil
}

// handleAppleCallback handles the Apple Sign In token exchange.
// Apple's flow differs from standard OAuth2: the client_secret is a short-lived
// ES256 JWT signed with an ECDSA private key, and user identity is embedded in
// the id_token rather than returned by a userinfo endpoint.
func (s *SocialAuthService) handleAppleCallback(ctx context.Context, provider *models.IdentityProvider, code string) (*oauth2.Token, map[string]interface{}, error) {
	if provider.AppleConfig == nil {
		return nil, nil, fmt.Errorf("apple config not configured for provider %q", provider.Name)
	}

	appleConfig := provider.AppleConfig

	// Generate the dynamic JWT client_secret required by Apple's token endpoint.
	clientSecret, err := s.generateAppleClientSecret(appleConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate apple client secret: %w", err)
	}

	// Perform the authorization_code token exchange.
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {appleConfig.ServicesID},
		"client_secret": {clientSecret},
		"redirect_uri":  {appleConfig.RedirectURI},
	}

	appleReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://appleid.apple.com/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("apple token exchange request: %w", err)
	}
	appleReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.HTTPClient.Do(appleReq)
	if err != nil {
		return nil, nil, fmt.Errorf("apple token exchange failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("apple token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode apple token response: %w", err)
	}

	// Extract user identity from the id_token. Apple does not expose a
	// userinfo endpoint; all identity claims are in the JWT payload.
	userInfo, err := s.parseAppleIDToken(tokenResp.IDToken, appleConfig.ServicesID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse apple id_token: %w", err)
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, userInfo, nil
}

// generateAppleClientSecret creates the ES256-signed JWT that Apple requires
// in place of a static client_secret. The JWT is valid for five minutes, which
// is the maximum permitted by Apple's documentation.
//
// Reference: https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
func (s *SocialAuthService) generateAppleClientSecret(appleConfig *models.AppleConfig) (string, error) {
	// Decode the PEM-encoded ECDSA private key stored in the provider config.
	block, _ := pem.Decode([]byte(appleConfig.PrivateKeyEncrypted))
	if block == nil {
		return "", fmt.Errorf("failed to decode apple private key PEM: block is nil")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse apple private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("apple private key is not ECDSA (P-256): got %T", key)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": appleConfig.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": appleConfig.ServicesID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	// Apple requires the Key ID header to identify which private key was used.
	token.Header["kid"] = appleConfig.KeyID

	return token.SignedString(ecKey)
}

// parseAppleIDToken verifies and decodes the JWT id_token returned by Apple's
// token endpoint. The signature is verified against Apple's published JWKS
// (https://appleid.apple.com/auth/keys), and the issuer, audience, and expiry
// claims are validated.
func (s *SocialAuthService) parseAppleIDToken(idToken, expectedAudience string) (map[string]interface{}, error) {
	// Parse and verify the token with Apple's JWKS public keys.
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("apple id_token missing kid header")
		}

		// Look up the key in our cached JWKS. If not found, refresh and retry.
		key, err := s.getApplePublicKey(kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get Apple public key for kid %q: %w", kid, err)
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
		jwt.WithIssuer("https://appleid.apple.com"),
		jwt.WithAudience(expectedAudience),
	)
	if err != nil {
		return nil, fmt.Errorf("apple id_token verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from apple id_token")
	}

	// Project the standard Apple claims into the userInfo map format expected
	// by the rest of the service (email, sub for provider user ID).
	userInfo := map[string]interface{}{
		"sub":   claims["sub"],
		"email": claims["email"],
	}
	if emailVerified, exists := claims["email_verified"]; exists {
		userInfo["email_verified"] = emailVerified
	}

	return userInfo, nil
}

// getApplePublicKey returns the public key for the given kid from Apple's JWKS.
// It uses a cached copy and refreshes when the cache is expired or the kid is not found.
func (s *SocialAuthService) getApplePublicKey(kid string) (interface{}, error) {
	// Try cached keys first.
	s.appleJWKSMu.RLock()
	if s.appleJWKS != nil && time.Since(s.appleJWKS.fetchedAt) < appleJWKSCacheTTL {
		if key, ok := s.appleJWKS.keys[kid]; ok {
			s.appleJWKSMu.RUnlock()
			return key, nil
		}
	}
	s.appleJWKSMu.RUnlock()

	// Cache miss or expired — refresh from Apple's JWKS endpoint.
	if err := s.refreshAppleJWKS(); err != nil {
		return nil, err
	}

	s.appleJWKSMu.RLock()
	defer s.appleJWKSMu.RUnlock()
	if key, ok := s.appleJWKS.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("kid %q not found in Apple JWKS", kid)
}

// refreshAppleJWKS fetches Apple's JWKS endpoint and caches the parsed public keys.
func (s *SocialAuthService) refreshAppleJWKS() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appleJWKSURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := s.httpClient.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch Apple JWKS: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apple JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return fmt.Errorf("failed to read Apple JWKS response: %w", err)
	}

	var jwks struct {
		Keys []appleJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse Apple JWKS: %w", err)
	}

	keys := make(map[string]interface{}, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.Use != "sig" {
			continue
		}
		key, err := parseJWKToPublicKey(jwk)
		if err != nil {
			logger.Warn("Skipping unparsable Apple JWK", zap.String("kid", jwk.Kid), zap.Error(err))
			continue
		}
		keys[jwk.Kid] = key
	}

	if len(keys) == 0 {
		return fmt.Errorf("apple JWKS returned no usable signing keys")
	}

	s.appleJWKSMu.Lock()
	s.appleJWKS = &appleJWKSCache{
		keys:      keys,
		fetchedAt: time.Now(),
	}
	s.appleJWKSMu.Unlock()

	logger.Info("Refreshed Apple JWKS cache", zap.Int("key_count", len(keys)))
	return nil
}

// parseJWKToPublicKey converts a JWK to a Go public key (RSA or ECDSA).
func parseJWKToPublicKey(jwk appleJWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAJWK(jwk)
	case "EC":
		return parseECJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func parseRSAJWK(jwk appleJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECJWK(jwk appleJWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC Y coordinate: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// exchangeCode exchanges the authorization code for OAuth2 tokens
func (s *SocialAuthService) exchangeCode(ctx context.Context, provider *models.IdentityProvider, code, redirectURI string) (*oauth2.Token, error) {
	oauth2Cfg, err := s.parseOAuth2Config(provider)
	if err != nil {
		return nil, fmt.Errorf("exchangeCode: parseOAuth2Config failed: %w", err)
	}

	if redirectURI != "" {
		oauth2Cfg.RedirectURL = redirectURI
	}

	token, err := oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	return token, nil
}

// getUserInfo fetches user information from the provider
func (s *SocialAuthService) getUserInfo(ctx context.Context, provider *models.IdentityProvider, accessToken string) (map[string]interface{}, error) {
	oauth2Config, err := s.getOAuth2ConfigFromProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("getUserInfo: getOAuth2ConfigFromProvider failed: %w", err)
	}

	userInfoURL := oauth2Config.UserInfoURL
	if userInfoURL == "" {
		return nil, fmt.Errorf("user info URL not configured")
	}

	// Special handling for GitHub - need to fetch email separately
	if oauth2Config.ProviderName == "github" {
		return s.getGitHubUserInfo(ctx, accessToken)
	}

	// LinkedIn's OIDC UserInfo endpoint requires the Linkedin-Version header
	// starting with the 202501 API version. Without it the request is rejected
	// with a 400 error.
	if oauth2Config.ProviderName == "linkedin" {
		return s.getLinkedInUserInfo(ctx, userInfoURL, accessToken)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}

// getGitHubUserInfo fetches user info from GitHub (requires special handling for email)
func (s *SocialAuthService) getGitHubUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	// Get basic user info
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("getGitHubUserInfo: NewRequest failed: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getGitHubUserInfo: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub user info request failed with status %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("getGitHubUserInfo: %w", err)
	}

	// Fetch email separately if not present
	if userInfo["email"] == nil {
		emails, err := s.getGitHubEmails(ctx, accessToken)
		if err == nil && len(emails) > 0 {
			userInfo["email"] = pickGitHubEmail(emails)
		}
	}

	return userInfo, nil
}

// pickGitHubEmail selects the primary+verified email from the GitHub emails list,
// falling back to the first verified email if no primary is found.
func pickGitHubEmail(emails []interface{}) interface{} {
	// Prefer primary verified email.
	for _, email := range emails {
		emailMap, ok := email.(map[string]interface{})
		if !ok {
			continue
		}
		primary, _ := emailMap["primary"].(bool)
		verified, _ := emailMap["verified"].(bool)
		if primary && verified {
			return emailMap["email"]
		}
	}
	// Fallback to first verified email.
	for _, email := range emails {
		emailMap, ok := email.(map[string]interface{})
		if !ok {
			continue
		}
		if verified, _ := emailMap["verified"].(bool); verified {
			return emailMap["email"]
		}
	}
	return nil
}

// getGitHubEmails fetches email addresses from GitHub
func (s *SocialAuthService) getGitHubEmails(ctx context.Context, accessToken string) ([]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, fmt.Errorf("getGitHubEmails: NewRequest failed: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getGitHubEmails: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub emails request failed with status %d", resp.StatusCode)
	}

	var emails []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, fmt.Errorf("getGitHubEmails: %w", err)
	}

	return emails, nil
}

// linkedInAPIVersion is the LinkedIn versioned API date header value sent with
// every request to LinkedIn's versioned REST API surface. LinkedIn requires
// this header on all calls to endpoints under api.linkedin.com/v2/ starting
// with the 202501 release. The format is YYYYMM.
//
// Reference: https://learn.microsoft.com/en-us/linkedin/shared/api-guide/concepts/versioning
const linkedInAPIVersion = "202603"

// getLinkedInUserInfo fetches OIDC user claims from LinkedIn's UserInfo endpoint.
// Unlike most OIDC providers, LinkedIn requires the Linkedin-Version header on
// all versioned API requests. The endpoint returns standard OIDC claims (sub,
// name, given_name, family_name, email, picture) when the openid, profile, and
// email scopes have been granted.
func (s *SocialAuthService) getLinkedInUserInfo(ctx context.Context, userInfoURL, accessToken string) (map[string]interface{}, error) {
	if userInfoURL == "" {
		userInfoURL = models.LinkedInOIDCUserInfoURL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("getLinkedInUserInfo: NewRequest failed: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	// LinkedIn requires a versioned API header on all calls to api.linkedin.com/v2/.
	// Omitting this header causes the endpoint to return a 400 Bad Request.
	req.Header.Set("Linkedin-Version", linkedInAPIVersion)

	resp, err := s.httpClient.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getLinkedInUserInfo: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LinkedIn userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("getLinkedInUserInfo: failed to decode response: %w", err)
	}

	return userInfo, nil
}

// ErrSocialAccountExists is returned when a social identity presents an email
// that already belongs to a local account which is NOT linked to that identity.
//
// We deliberately refuse rather than link. Linking on an email match means
// trusting a provider-asserted address to grant access to an existing account,
// which is an account-takeover primitive on any provider that lets a holder set
// an address without verifying it (github, generic oauth/oidc) - and is not
// sound even for google/microsoft, which can assert email_verified:false.
//
// The safe path already exists: the user signs in normally and links the
// provider from account settings via LinkAccount, which is authenticated.
// ErrOAuthStateBindingMissing and ErrOAuthStateBindingMismatch report a state
// presented WITHOUT, or with the WRONG, browser binding (t-150 / d-064).
//
// Distinct from "invalid or expired" on purpose: that answer means the state
// was never issued or is already spent, whereas these two mean the state is
// real and the browser presenting it is not the one it was issued to. Callers
// must NOT widen the operator-facing distinction into the end-user response —
// a visitor sees a generic failed login either way.
var (
	ErrOAuthStateBindingMissing  = errors.New("OAuth state was not presented with its browser binding")
	ErrOAuthStateBindingMismatch = errors.New("OAuth state binding does not match the browser it was issued to")
)

var ErrSocialAccountExists = errors.New("an account with this email address already exists; sign in and link this provider from account settings")

// ErrSocialSignupDisabled is returned when a social identity resolves to no
// existing user and this provider is not configured to create one.
//
// The message is written for the END USER, because the callback handler
// surfaces service errors verbatim as the 401 body. The operator-facing
// detail — which provider, and that create_users is the specific gate — is
// logged instead of returned, so diagnosing it does not require showing the
// visitor the IdP's configuration state.
var ErrSocialSignupDisabled = errors.New("this account is not registered, and sign-up with this provider is not enabled; contact your administrator")

// providerAssertsVerifiedEmail reports whether the provider has asserted that
// the email in userInfo is verified.
//
// Extracted so provisioning and any future linking decision consult one rule.
// This logic previously sat inline BELOW an early return and so governed only
// new-user creation.
func (s *SocialAuthService) providerAssertsVerifiedEmail(provider *models.IdentityProvider, userInfo map[string]interface{}) bool {
	switch provider.Type {
	case "google", "microsoft", "linkedin":
		// These providers only return email addresses verified within their own
		// platform. LinkedIn's OIDC flow uses confirmed primary addresses only.
		//
		// NOTE: an assumption about provider behaviour, not something we verify.
		// Google can assert email_verified:false in some Workspace configurations.
		// Retained because it matches previous PROVISIONING behaviour; it carries
		// no weight for LINKING, which no longer happens implicitly at all.
		return true
	default:
		if ev, ok := userInfo["email_verified"]; ok {
			switch v := ev.(type) {
			case bool:
				return v
			case string:
				return v == "true"
			}
		}
		return false
	}
}

// resolveUserForFederation maps a provider assertion to a local user.
//
// Resolution is keyed on the federated account (provider + subject), NEVER on
// email. Three outcomes:
//
//	fedAccount != nil          returning user - load by the linked user ID
//	no account, email unknown  first-time federation - provision a new user
//	no account, email KNOWN    refused (ErrSocialAccountExists)
//
// The third case was previously an account takeover: the old implementation
// looked the user up by email and returned it directly, above the point where
// email verification was even considered.
func (s *SocialAuthService) resolveUserForFederation(
	ctx context.Context,
	provider *models.IdentityProvider,
	userInfo map[string]interface{},
	fedAccount *models.FederatedAccount,
) (*models.User, error) {
	// Returning user: this provider subject is already linked. The ONLY path
	// permitted to resolve to a pre-existing account.
	if fedAccount != nil {
		user, err := s.userRepo.GetByID(ctx, fedAccount.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to load linked user: %w", err)
		}
		if user == nil {
			return nil, fmt.Errorf("federated account references a user that no longer exists")
		}
		if oauth2Config, cfgErr := s.getOAuth2ConfigFromProvider(provider); cfgErr == nil && oauth2Config.UpdateUsers {
			s.updateUserFromProvider(user, oauth2Config, userInfo)
			if err := s.userRepo.Update(ctx, user); err != nil {
				logger.Error("Failed to update user from provider", zap.Error(err))
			}
		}
		return user, nil
	}

	oauth2Config, err := s.getOAuth2ConfigFromProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("resolveUserForFederation: getOAuth2ConfigFromProvider failed: %w", err)
	}

	email := s.extractEmail(oauth2Config, userInfo)
	if email == "" {
		return nil, fmt.Errorf("email not found in provider response")
	}

	// Evaluated BEFORE any matching decision, not after one.
	emailVerified := s.providerAssertsVerifiedEmail(provider, userInfo)

	// First-time federation. If this address already belongs to somebody, refuse
	// - regardless of whether the provider claims it is verified. A verified
	// assertion proves control of the address; it does not express the account
	// owner's intent to merge their account with this identity.
	existing, err := s.userRepo.GetByEmail(ctx, provider.TenantID, email)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user: %w", err)
	}
	if existing != nil {
		logger.Warn("Refused implicit social link to an existing account",
			zap.String("provider", provider.Name),
			zap.String("provider_type", provider.Type),
			zap.Bool("provider_email_verified", emailVerified),
			zap.String("user_id", existing.ID.String()))
		return nil, ErrSocialAccountExists
	}

	// Create new user if configured
	if !oauth2Config.CreateUsers {
		logger.Warn("Refused social sign-in for an unknown identity: provider has user auto-creation disabled",
			zap.String("provider", provider.Name),
			zap.String("provider_type", provider.Type),
			zap.Bool("create_users", oauth2Config.CreateUsers))
		return nil, ErrSocialSignupDisabled
	}

	user := &models.User{
		TenantID:        provider.TenantID,
		Email:           email,
		IsActive:        true,
		IsEmailVerified: emailVerified,
	}

	// Extract user attributes
	s.updateUserFromProvider(user, oauth2Config, userInfo)

	// Set federation info
	fedType := "oauth"
	user.FederationType = &fedType
	providerUserID := s.extractProviderUserID(provider, userInfo)
	user.FederationID = &providerUserID
	user.FederationSource = &provider.Name

	// Generate username from email if not present
	if user.Username == "" {
		user.Username = strings.Split(email, "@")[0]
	}

	// Create user
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign default roles
	defaultRoles, err := s.roleRepo.GetDefaultRoles(ctx, provider.TenantID)
	if err == nil && len(defaultRoles) > 0 {
		roleIDs := make([]uuid.UUID, len(defaultRoles))
		for i, r := range defaultRoles {
			roleIDs[i] = r.ID
		}
		if err := s.userRepo.AssignRoles(ctx, user.ID, roleIDs, nil); err != nil {
			logger.Error("Failed to assign default roles", zap.Error(err))
		}
	}

	return user, nil
}

// LinkAccount links a social provider account to an existing user
func (s *SocialAuthService) LinkAccount(ctx context.Context, userID, providerID uuid.UUID, code, redirectURI string) error {
	// Get provider
	provider, err := s.idpRepo.GetByID(ctx, providerID)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}
	if provider == nil {
		return fmt.Errorf("provider not found")
	}

	// Check if account already linked
	existing, err := s.fedAccountRepo.GetByUserAndProvider(ctx, userID, providerID)
	if err != nil {
		return fmt.Errorf("failed to check existing account: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("account already linked to this provider")
	}

	// Exchange code for token
	oauth2Token, err := s.exchangeCode(ctx, provider, code, redirectURI)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info
	userInfo, err := s.getUserInfo(ctx, provider, oauth2Token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// Create federated account
	providerUserID := s.extractProviderUserID(provider, userInfo)
	if providerUserID == "" {
		return fmt.Errorf("provider did not return a stable subject identifier")
	}

	// Refuse if this provider subject is already bound to a DIFFERENT user.
	// GetByUserAndProvider above only answers "is THIS user linked to this
	// provider"; without this, two accounts could claim one subject and
	// callback resolution - now keyed on the subject - would be ambiguous.
	subjectOwner, err := s.fedAccountRepo.GetByProviderUserID(ctx, providerID, providerUserID)
	if err != nil {
		return fmt.Errorf("failed to check provider subject: %w", err)
	}
	if subjectOwner != nil && subjectOwner.UserID != userID {
		logger.Warn("Refused to link a provider subject already bound to another user",
			zap.String("provider_id", providerID.String()),
			zap.String("requesting_user", userID.String()),
			zap.String("existing_user", subjectOwner.UserID.String()))
		return fmt.Errorf("this provider account is already linked to another user")
	}

	now := time.Now()

	fedAccount := &models.FederatedAccount{
		UserID:         userID,
		ProviderID:     providerID,
		ProviderUserID: providerUserID,
		AccessToken:    &oauth2Token.AccessToken,
		RefreshToken:   &oauth2Token.RefreshToken,
		ProfileData:    userInfo,
		FirstLinkedAt:  now,
		LastUsedAt:     &now,
	}

	if !oauth2Token.Expiry.IsZero() {
		fedAccount.TokenExpiresAt = &oauth2Token.Expiry
	}

	if email, ok := userInfo["email"].(string); ok {
		fedAccount.ProviderEmail = &email
	}
	if username := s.extractUsername(provider, userInfo); username != "" {
		fedAccount.ProviderUsername = &username
	}

	return s.fedAccountRepo.Create(ctx, fedAccount)
}

// UnlinkAccount unlinks a social provider account from a user
func (s *SocialAuthService) UnlinkAccount(ctx context.Context, userID, providerID uuid.UUID) error {
	return s.fedAccountRepo.DeleteByUserAndProvider(ctx, userID, providerID)
}

// GetLinkedAccounts retrieves all linked accounts for a user
func (s *SocialAuthService) GetLinkedAccounts(ctx context.Context, userID uuid.UUID) ([]models.FederatedAccount, error) {
	return s.fedAccountRepo.GetByUser(ctx, userID)
}

// Helper functions

func (s *SocialAuthService) parseOAuth2Config(provider *models.IdentityProvider) (*oauth2.Config, error) {
	oauth2Cfg, err := s.getOAuth2ConfigFromProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("parseOAuth2Config: getOAuth2ConfigFromProvider failed: %w", err)
	}

	return &oauth2.Config{
		ClientID:     oauth2Cfg.ClientID,
		ClientSecret: oauth2Cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oauth2Cfg.AuthURL,
			TokenURL: oauth2Cfg.TokenURL,
		},
		RedirectURL: oauth2Cfg.RedirectURI,
		Scopes:      oauth2Cfg.Scopes,
	}, nil
}

func (s *SocialAuthService) getOAuth2ConfigFromProvider(provider *models.IdentityProvider) (*models.OAuth2Config, error) {
	// Build OAuth2Config from IdentityProvider fields
	oauth2Cfg := &models.OAuth2Config{
		ProviderName: provider.Type,
		Scopes:       provider.Scopes,
	}

	// Get client credentials
	if provider.ClientID != nil {
		oauth2Cfg.ClientID = *provider.ClientID
	}
	if provider.ClientSecretEncrypted != nil && *provider.ClientSecretEncrypted != "" {
		// A stored secret we cannot decrypt is a misconfiguration, not an empty
		// secret. The encryption service is wired conditionally
		// (cmd/services.go:1387), so when it is absent this used to fall through
		// silently and leave ClientSecret empty -- moving the failure to token
		// exchange, where it reads as a credentials problem with the IdP rather
		// than a wiring problem on our side.
		//
		// Providers that legitimately hold no secret (public/PKCE clients) are
		// unaffected: this only fires when a secret IS stored.
		if s.encryptionService == nil {
			return nil, fmt.Errorf("provider %q has an encrypted client secret but no encryption service is wired; refusing to proceed with an empty secret", provider.Name)
		}
		decrypted, err := s.encryptionService.Decrypt(*provider.ClientSecretEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt client secret for provider %q: %w", provider.Name, err)
		}
		oauth2Cfg.ClientSecret = decrypted
	}

	// URLs
	if provider.AuthorizationURL != nil {
		oauth2Cfg.AuthURL = *provider.AuthorizationURL
	}
	if provider.TokenURL != nil {
		oauth2Cfg.TokenURL = *provider.TokenURL
	}
	if provider.UserInfoURL != nil {
		oauth2Cfg.UserInfoURL = *provider.UserInfoURL
	}

	// Get attribute mapping
	if provider.AttributeMapping != nil {
		applyAttributeMapping(provider.AttributeMapping, oauth2Cfg)
	}

	return oauth2Cfg, nil
}

func (s *SocialAuthService) extractProviderUserID(provider *models.IdentityProvider, userInfo map[string]interface{}) string {
	oauth2Cfg, err := s.getOAuth2ConfigFromProvider(provider)
	if err != nil {
		// Fallback to common fields
		if sub, ok := userInfo["sub"].(string); ok {
			return sub
		}
		if id, ok := userInfo["id"].(float64); ok {
			return fmt.Sprintf("%.0f", id)
		}
		if id, ok := userInfo["id"].(string); ok {
			return id
		}
		return ""
	}

	attr := oauth2Cfg.UserIDAttr
	if attr == "" {
		attr = "sub" // Default to OIDC standard
	}

	if val, ok := userInfo[attr]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%.0f", v)
		case int:
			return fmt.Sprintf("%d", v)
		}
	}

	return ""
}

func (s *SocialAuthService) extractEmail(oauth2Cfg *models.OAuth2Config, userInfo map[string]interface{}) string {
	attr := oauth2Cfg.EmailAttr
	if attr == "" {
		attr = "email"
	}

	if val, ok := userInfo[attr].(string); ok {
		return val
	}
	return ""
}

func (s *SocialAuthService) extractUsername(_ *models.IdentityProvider, userInfo map[string]interface{}) string {
	// Try common username fields
	if login, ok := userInfo["login"].(string); ok {
		return login
	}
	if username, ok := userInfo["username"].(string); ok {
		return username
	}
	if preferredUsername, ok := userInfo["preferred_username"].(string); ok {
		return preferredUsername
	}
	return ""
}

func (s *SocialAuthService) updateUserFromProvider(user *models.User, oauth2Cfg *models.OAuth2Config, userInfo map[string]interface{}) {
	// Extract first name
	firstNameAttr := oauth2Cfg.FirstNameAttr
	if firstNameAttr == "" {
		firstNameAttr = "given_name"
	}
	if firstName, ok := userInfo[firstNameAttr].(string); ok && firstName != "" {
		user.FirstName = &firstName
	}

	// Extract last name
	lastNameAttr := oauth2Cfg.LastNameAttr
	if lastNameAttr == "" {
		lastNameAttr = "family_name"
	}
	if lastName, ok := userInfo[lastNameAttr].(string); ok && lastName != "" {
		user.LastName = &lastName
	}

	// Extract display name
	displayNameAttr := oauth2Cfg.DisplayNameAttr
	if displayNameAttr == "" {
		displayNameAttr = "name"
	}
	if displayName, ok := userInfo[displayNameAttr].(string); ok && displayName != "" {
		user.DisplayName = &displayName
	}

	// Extract avatar
	avatarAttr := oauth2Cfg.AvatarAttr
	if avatarAttr == "" {
		avatarAttr = "picture"
	}
	if avatar, ok := userInfo[avatarAttr].(string); ok && avatar != "" {
		user.AvatarURL = &avatar
	}

	// Extract username if not set
	if user.Username == "" {
		user.Username = s.extractUsername(&models.IdentityProvider{}, userInfo)
	}
}

// applyAttributeMapping copies entries from an attribute mapping config into an OAuth2 config struct.
func applyAttributeMapping(mapping map[string]string, cfg *models.OAuth2Config) {
	if v, ok := mapping["user_id"]; ok {
		cfg.UserIDAttr = v
	}
	if v, ok := mapping["email"]; ok {
		cfg.EmailAttr = v
	}
	if v, ok := mapping["first_name"]; ok {
		cfg.FirstNameAttr = v
	}
	if v, ok := mapping["last_name"]; ok {
		cfg.LastNameAttr = v
	}
	if v, ok := mapping["display_name"]; ok {
		cfg.DisplayNameAttr = v
	}
	if v, ok := mapping["avatar"]; ok {
		cfg.AvatarAttr = v
	}
}
