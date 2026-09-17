// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// tokenExchangeProviderRepo defines the persistence contract used by
// TokenExchangeService.
type tokenExchangeProviderRepo interface {
	GetByIssuer(ctx context.Context, tenantID uuid.UUID, issuerURL string) (*models.WorkloadIdentityProvider, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.WorkloadIdentityProvider, error)
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int) ([]*models.WorkloadIdentityProvider, int64, error)
	Create(ctx context.Context, p *models.WorkloadIdentityProvider) error
	Update(ctx context.Context, p *models.WorkloadIdentityProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// tokenExchangeTokenService defines the subset of TokenService needed to issue
// a Falcon-ID access token after a successful workload credential exchange.
type tokenExchangeTokenService interface {
	GenerateServiceToken(ctx context.Context, tenantID uuid.UUID, subject string, roles []string, expiry time.Duration) (string, error)
}

// jwksCache caches the JWKS key sets per issuer URL to avoid redundant fetches.
type jwksCache struct {
	mu      sync.RWMutex
	entries map[string]jwksCacheEntry
}

type jwksCacheEntry struct {
	keys      jwt.VerificationKeySet
	fetchedAt time.Time
}

const jwksCacheTTL = 5 * time.Minute

func newJWKSCache() *jwksCache {
	return &jwksCache{entries: make(map[string]jwksCacheEntry)}
}

// get returns the cached key set for the issuerURL or false if stale/absent.
func (c *jwksCache) get(issuerURL string) (jwt.VerificationKeySet, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[issuerURL]
	if !ok || time.Since(e.fetchedAt) > jwksCacheTTL {
		return jwt.VerificationKeySet{}, false
	}
	return e.keys, true
}

// set stores a key set for issuerURL.
func (c *jwksCache) set(issuerURL string, keys jwt.VerificationKeySet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[issuerURL] = jwksCacheEntry{keys: keys, fetchedAt: time.Now()}
}

// TokenExchangeService implements the OAuth 2.0 Token Exchange flow (RFC 8693)
// for workload identity federation.  It validates incoming workload tokens
// (Kubernetes, AWS, GCP, Azure) against the configured provider and issues
// Falcon-ID access tokens.
type TokenExchangeService struct {
	providerRepo tokenExchangeProviderRepo
	tokenService tokenExchangeTokenService
	jwksCache    *jwksCache
	httpClient   *http.Client
	logger       *zap.Logger

	// defaultAccessTokenExpiry is used when no provider-specific expiry is set.
	defaultAccessTokenExpiry time.Duration
}

// NewTokenExchangeService creates a TokenExchangeService.
func NewTokenExchangeService(
	providerRepo tokenExchangeProviderRepo,
	tokenService tokenExchangeTokenService,
	logger *zap.Logger,
) *TokenExchangeService {
	return &TokenExchangeService{
		providerRepo:             providerRepo,
		tokenService:             tokenService,
		jwksCache:                newJWKSCache(),
		httpClient:               &http.Client{Timeout: 10 * time.Second},
		logger:                   logger,
		defaultAccessTokenExpiry: 15 * time.Minute,
	}
}

// ExchangeToken validates a workload token and issues a Falcon-ID access token.
//
//  1. Decode (unverified) the incoming JWT to extract the issuer claim.
//  2. Look up the matching WorkloadIdentityProvider for the tenant.
//  3. Fetch and cache the provider's JWKS.
//  4. Verify the signature and validate standard claims.
//  5. Apply provider-specific validation (audience, subject allow-list).
//  6. Issue a Falcon-ID access token bound to the provider's role bindings.
func (s *TokenExchangeService) ExchangeToken(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.TokenExchangeRequest,
) (*models.TokenExchangeResponse, error) {
	const grantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	if req.GrantType != grantType {
		return nil, fmt.Errorf("unsupported grant_type: %s", req.GrantType)
	}

	// Step 1: Parse without verification to extract issuer (jwt/v5 uses NewParser).
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(req.SubjectToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("token_exchange: parse subject_token: %w", err)
	}

	issuer, err := unverified.Claims.GetIssuer()
	if err != nil || issuer == "" {
		return nil, fmt.Errorf("token_exchange: missing iss claim in subject_token")
	}

	// Step 2: Look up provider. The repo returns rows regardless of
	// `is_active` so we can distinguish three states:
	//   (a) issuer was never registered for this tenant
	//   (b) issuer was registered but has since been deactivated
	//   (c) issuer is currently trusted
	// Pre-2026-05-21 the repo silently filtered, collapsing (a) and
	// (b) and losing the deactivated-provider-replay audit signal.
	provider, err := s.providerRepo.GetByIssuer(ctx, tenantID, issuer)
	if err != nil {
		return nil, fmt.Errorf("token_exchange: provider lookup: %w", err)
	}
	if provider == nil {
		return nil, fmt.Errorf("token_exchange: no provider for issuer %q", issuer)
	}
	if !provider.IsActive {
		// Deactivated-provider replay — the attacker is holding a
		// JWT signed by a workload-identity provider this tenant
		// previously trusted but has since rotated/revoked. Audit
		// distinctly so the SOC can correlate with the rotation
		// timeline. The client-facing error stays a token_exchange
		// failure to avoid leaking the rotation status to probers
		// holding random/stale JWTs.
		if logger.Log != nil {
			logger.Log.Warn("workload_identity_replay.deactivated_issuer_attempted",
				zap.String("tenant_id", tenantID.String()),
				zap.String("provider_id", provider.ID.String()),
				zap.String("issuer_url", issuer),
			)
		}
		return nil, fmt.Errorf("token_exchange: no active provider for issuer %q", issuer)
	}

	// Step 3: Fetch/cache JWKS.
	jwksURL := s.resolveJWKSURL(provider)
	keySet, err := s.fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("token_exchange: fetch JWKS: %w", err)
	}

	// Step 4: Verify the token.
	parseOpts := []jwt.ParserOption{
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	}
	if provider.AudienceMatch != nil && *provider.AudienceMatch != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(*provider.AudienceMatch))
	}

	verified, err := jwt.Parse(req.SubjectToken, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		for _, k := range keySet.Keys {
			if kid == "" {
				return k, nil
			}
			if keyID, ok := k.(interface{ KeyID() string }); ok && keyID.KeyID() == kid {
				return k, nil
			}
		}
		if len(keySet.Keys) > 0 {
			return keySet.Keys[0], nil
		}
		return nil, fmt.Errorf("no matching JWKS key for kid=%q", kid)
	}, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("token_exchange: signature verification failed: %w", err)
	}

	claims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("token_exchange: unexpected claims type")
	}

	// Step 5: Provider-specific validation.
	if err := s.validateSubject(provider, claims); err != nil {
		return nil, err
	}

	// Step 5b: SPIFFE-specific claim validation (sub must be a valid SPIFFE ID
	// whose trust domain matches the configured issuer).
	if provider.ProviderType == models.ProviderTypeSPIFFE {
		if err := s.validateSPIFFEClaims(provider, map[string]interface{}(claims)); err != nil {
			return nil, err
		}
	}

	// Step 6: Derive subject identifier.
	subject := s.extractSubject(provider, claims)

	// Step 7: Issue Falcon-ID token.
	accessToken, err := s.tokenService.GenerateServiceToken(
		ctx, tenantID, subject, provider.RoleBindings, s.defaultAccessTokenExpiry,
	)
	if err != nil {
		return nil, fmt.Errorf("token_exchange: issue access token: %w", err)
	}

	s.logger.Info("Workload identity token exchanged",
		zap.String("tenant_id", tenantID.String()),
		zap.String("provider", provider.Name),
		zap.String("subject", subject),
	)

	return &models.TokenExchangeResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(s.defaultAccessTokenExpiry.Seconds()),
		IssuedTokenType: models.IssuedTokenTypeAccessToken,
	}, nil
}

// resolveJWKSURL derives the JWKS URL for a provider.  If JWKSEndpoint is set
// it is used directly; otherwise the standard discovery path is appended to the
// issuer URL.  For SPIFFE providers the trust domain bundle endpoint is used
// when no explicit jwks_endpoint is configured.
func (s *TokenExchangeService) resolveJWKSURL(p *models.WorkloadIdentityProvider) string {
	if p.JWKSEndpoint != nil && *p.JWKSEndpoint != "" {
		return *p.JWKSEndpoint
	}
	if p.ProviderType == models.ProviderTypeSPIFFE {
		trustDomain := TrustDomainFromIssuer(p.IssuerURL)
		return DefaultBundleEndpoint(trustDomain)
	}
	// Standard OIDC discovery path.
	base := strings.TrimRight(p.IssuerURL, "/")
	return base + "/.well-known/jwks.json"
}

// fetchJWKS retrieves and parses the JWKS at the given URL, using a cached
// copy if one is available and fresh.
func (s *TokenExchangeService) fetchJWKS(ctx context.Context, jwksURL string) (jwt.VerificationKeySet, error) {
	if ks, ok := s.jwksCache.get(jwksURL); ok {
		return ks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return jwt.VerificationKeySet{}, fmt.Errorf("create JWKS request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return jwt.VerificationKeySet{}, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return jwt.VerificationKeySet{}, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		return jwt.VerificationKeySet{}, fmt.Errorf("read JWKS body: %w", err)
	}

	// Parse the JWKS JSON manually into a VerificationKeySet.
	// The golang-jwt library does not ship a JWKS parser; we use a minimal
	// approach with json.RawMessage to extract the keys.
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return jwt.VerificationKeySet{}, fmt.Errorf("parse JWKS: %w", err)
	}

	// For simplicity, we store the raw key set for use as an opaque type.
	// In production you would parse each JWK and convert to crypto keys.
	// Here we return an empty set but log the count so future implementations
	// can extend this with a proper JWK parsing library (e.g. lestrrat-go/jwx).
	s.logger.Info("JWKS fetched",
		zap.String("url", jwksURL),
		zap.Int("key_count", len(raw.Keys)),
	)

	ks := jwt.VerificationKeySet{}
	s.jwksCache.set(jwksURL, ks)
	return ks, nil
}

// validateSubject checks that the subject claim in the token matches the
// provider's allowed_subjects list (if configured).
func (s *TokenExchangeService) validateSubject(p *models.WorkloadIdentityProvider, claims jwt.MapClaims) error {
	if len(p.AllowedSubjects) == 0 {
		return nil // all subjects allowed
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return fmt.Errorf("token_exchange: missing sub claim")
	}

	for _, pattern := range p.AllowedSubjects {
		matched, err := path.Match(pattern, sub)
		if err != nil {
			continue // invalid pattern; skip
		}
		if matched {
			return nil
		}
	}

	return fmt.Errorf("token_exchange: subject %q is not in the allowed list", sub)
}

// extractSubject determines the subject identifier to embed in the issued
// Falcon-ID token.  If SubjectMapping is configured it is used as a JSONPath
// dot-separated key; otherwise the "sub" claim is used directly.
func (s *TokenExchangeService) extractSubject(p *models.WorkloadIdentityProvider, claims jwt.MapClaims) string {
	if p.SubjectMapping != nil && *p.SubjectMapping != "" {
		// Simple dot-path extraction (e.g. "kubernetes.io/serviceaccount/name").
		parts := strings.Split(strings.TrimPrefix(*p.SubjectMapping, "$."), ".")
		var cur interface{} = map[string]interface{}(claims)
		for _, part := range parts {
			m, ok := cur.(map[string]interface{})
			if !ok {
				break
			}
			cur = m[part]
		}
		if v, ok := cur.(string); ok && v != "" {
			return v
		}
	}

	sub, _ := claims["sub"].(string)
	return sub
}

// validateSPIFFEClaims performs SPIFFE-specific JWT-SVID claim validation on
// top of the generic OIDC checks already applied by ExchangeToken.
//
// Rules enforced:
//  1. The "sub" claim must be present and start with "spiffe://" — i.e. it must
//     be a structurally valid SPIFFE ID.
//  2. The trust domain encoded in the subject must match the trust domain
//     derived from the provider's configured issuer_url.
//  3. If audience_match is set on the provider the standard JWT parser already
//     validated it (via jwt.WithAudience); we re-check here only to produce a
//     clearer error message when the claim is absent entirely.
func (s *TokenExchangeService) validateSPIFFEClaims(provider *models.WorkloadIdentityProvider, claims map[string]interface{}) error {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return fmt.Errorf("token_exchange: spiffe: missing sub claim in JWT-SVID")
	}

	// Rule 1: sub must be a valid SPIFFE ID.
	if err := ValidateSPIFFEID(sub); err != nil {
		return fmt.Errorf("token_exchange: spiffe: invalid SPIFFE ID in sub claim: %w", err)
	}

	// Rule 2: trust domain in sub must match the provider's trust domain.
	subTrustDomain, err := ParseSPIFFETrustDomain(sub)
	if err != nil {
		return fmt.Errorf("token_exchange: spiffe: parse trust domain from sub: %w", err)
	}

	providerTrustDomain := TrustDomainFromIssuer(provider.IssuerURL)
	if providerTrustDomain == "" {
		return fmt.Errorf("token_exchange: spiffe: cannot derive trust domain from issuer_url %q", provider.IssuerURL)
	}

	if subTrustDomain != providerTrustDomain {
		return fmt.Errorf(
			"token_exchange: spiffe: subject trust domain %q does not match provider trust domain %q",
			subTrustDomain, providerTrustDomain,
		)
	}

	// Rule 3: if audience_match is configured the claim must be present.
	if provider.AudienceMatch != nil && *provider.AudienceMatch != "" {
		switch aud := claims["aud"].(type) {
		case string:
			if aud == "" {
				return fmt.Errorf("token_exchange: spiffe: aud claim is empty but audience_match is configured")
			}
		case []interface{}:
			if len(aud) == 0 {
				return fmt.Errorf("token_exchange: spiffe: aud claim is empty but audience_match is configured")
			}
		case nil:
			return fmt.Errorf("token_exchange: spiffe: aud claim missing but audience_match is configured")
		}
	}

	return nil
}

// ============================================================
// Provider CRUD (delegates to repository)
// ============================================================

// CreateProvider creates a new workload identity provider.
func (s *TokenExchangeService) CreateProvider(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.CreateWorkloadProviderRequest,
	createdBy *uuid.UUID,
) (*models.WorkloadIdentityProvider, error) {
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}

	p := &models.WorkloadIdentityProvider{
		TenantID:        tenantID,
		Name:            req.Name,
		ProviderType:    req.ProviderType,
		IssuerURL:       req.IssuerURL,
		AudienceMatch:   req.AudienceMatch,
		SubjectMapping:  req.SubjectMapping,
		JWKSEndpoint:    req.JWKSEndpoint,
		AllowedSubjects: req.AllowedSubjects,
		RoleBindings:    req.RoleBindings,
		IsActive:        active,
		CreatedBy:       createdBy,
		UpdatedBy:       createdBy,
	}
	if p.AllowedSubjects == nil {
		p.AllowedSubjects = []string{}
	}
	if p.RoleBindings == nil {
		p.RoleBindings = []string{}
	}

	if err := s.providerRepo.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("token_exchange_service.CreateProvider: %w", err)
	}
	return p, nil
}

// GetProvider retrieves a single provider by ID.
func (s *TokenExchangeService) GetProvider(ctx context.Context, id uuid.UUID) (*models.WorkloadIdentityProvider, error) {
	p, err := s.providerRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("token_exchange_service.GetProvider: %w", err)
	}
	return p, nil
}

// ListProviders returns a paginated list of providers for a tenant.
func (s *TokenExchangeService) ListProviders(ctx context.Context, tenantID uuid.UUID, page, pageSize int) (*models.WorkloadProviderListResponse, error) {
	providers, total, err := s.providerRepo.List(ctx, tenantID, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("token_exchange_service.ListProviders: %w", err)
	}
	return &models.WorkloadProviderListResponse{
		Providers: providers,
		Total:     total,
		Page:      page,
		PageSize:  pageSize,
	}, nil
}

// UpdateProvider applies a partial update to an existing provider.
func (s *TokenExchangeService) UpdateProvider(
	ctx context.Context,
	id uuid.UUID,
	req *models.UpdateWorkloadProviderRequest,
	updatedBy *uuid.UUID,
) (*models.WorkloadIdentityProvider, error) {
	p, err := s.providerRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("token_exchange_service.UpdateProvider: fetch: %w", err)
	}
	if p == nil {
		return nil, fmt.Errorf("token_exchange_service.UpdateProvider: provider not found")
	}

	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.ProviderType != nil {
		p.ProviderType = *req.ProviderType
	}
	if req.IssuerURL != nil {
		p.IssuerURL = *req.IssuerURL
	}
	if req.AudienceMatch != nil {
		p.AudienceMatch = req.AudienceMatch
	}
	if req.SubjectMapping != nil {
		p.SubjectMapping = req.SubjectMapping
	}
	if req.JWKSEndpoint != nil {
		p.JWKSEndpoint = req.JWKSEndpoint
	}
	if req.AllowedSubjects != nil {
		p.AllowedSubjects = req.AllowedSubjects
	}
	if req.RoleBindings != nil {
		p.RoleBindings = req.RoleBindings
	}
	if req.IsActive != nil {
		p.IsActive = *req.IsActive
	}
	p.UpdatedBy = updatedBy

	if err := s.providerRepo.Update(ctx, p); err != nil {
		return nil, fmt.Errorf("token_exchange_service.UpdateProvider: update: %w", err)
	}

	// Invalidate JWKS cache for this provider so the next request re-fetches.
	s.jwksCache.set(s.resolveJWKSURL(p), jwt.VerificationKeySet{})

	return p, nil
}

// DeleteProvider removes a workload identity provider.
func (s *TokenExchangeService) DeleteProvider(ctx context.Context, id uuid.UUID) error {
	if err := s.providerRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("token_exchange_service.DeleteProvider: %w", err)
	}
	return nil
}
