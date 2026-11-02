// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// ServicePrincipalLookup is the interface for looking up service principals by key ID.
type ServicePrincipalLookup interface {
	LookupPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, string, error) // returns pubkey, service slug, error
}

// ServicePrincipalUsageRecorder records the last-used timestamp and IP for a service principal.
// Implementations must be safe for concurrent use. The update is always fire-and-forget;
// callers must not depend on it completing before the request finishes.
type ServicePrincipalUsageRecorder interface {
	RecordServicePrincipalUsage(ctx context.Context, slug string, ip string, at time.Time) error
}

// Context keys set by ServiceAuth.
const (
	// CtxKeyServiceSlug is the authenticated service principal slug.
	CtxKeyServiceSlug = "service_slug"
	// CtxKeyServiceScopes is the space-separated list of scopes carried in the JWT.
	CtxKeyServiceScopes = "service_scopes"
	// CtxKeyServiceTenantID is the tenant_id claim if present in the JWT.
	CtxKeyServiceTenantID = "service_tenant_id"
	// CtxKeyAuthMethod is the authentication method used (service_jwt | internal_key).
	CtxKeyAuthMethod = "auth_method"
)

// ServiceAuthMiddleware validates service JWT tokens for service-to-service communication.
type ServiceAuthMiddleware struct {
	lookup        ServicePrincipalLookup
	legacyKey     string // Legacy INTERNAL_API_KEY for migration period
	usageRecorder ServicePrincipalUsageRecorder
}

// NewServiceAuthMiddleware creates a new ServiceAuthMiddleware.
func NewServiceAuthMiddleware(lookup ServicePrincipalLookup, legacyKey string) *ServiceAuthMiddleware {
	return &ServiceAuthMiddleware{
		lookup:    lookup,
		legacyKey: legacyKey,
	}
}

// SetUsageRecorder wires an optional usage recorder for audit-trail updates.
// The recorder is called asynchronously after every successful authentication so
// it never blocks the request path.
func (m *ServiceAuthMiddleware) SetUsageRecorder(r ServicePrincipalUsageRecorder) {
	m.usageRecorder = r
}

// ServiceAuth returns a Gin middleware that validates service JWTs.
// During migration, it also accepts the legacy INTERNAL_API_KEY via X-Internal-Key header.
//
// On success the following context values are set:
//   - service_slug   (string)  — the service principal slug (from "iss" / "service_slug" claim)
//   - service_scopes (string)  — space-separated scope list from the "scope" claim (may be empty)
//   - service_tenant_id (string) — tenant_id claim if present
//   - auth_method    (string)  — "service_jwt" or "internal_key"
func (m *ServiceAuthMiddleware) ServiceAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try service JWT first (from Authorization: Bearer header)
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if err := m.validateServiceJWT(c, tokenString); err == nil {
				c.Next()
				return
			}
			// Fall through to legacy key check
		}

		// Legacy: check X-Internal-Key header
		internalKey := c.GetHeader("X-Internal-Key")
		if internalKey != "" && m.legacyKey != "" && subtle.ConstantTimeCompare([]byte(internalKey), []byte(m.legacyKey)) == 1 {
			c.Set(CtxKeyServiceSlug, "legacy-internal")
			c.Set(CtxKeyAuthMethod, "internal_key")
			c.Set(CtxKeyServiceScopes, "")
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "service authentication required",
		})
	}
}

func (m *ServiceAuthMiddleware) validateServiceJWT(c *gin.Context, tokenString string) error {
	token, resolvedSlug, err := m.parseAndVerifyToken(c, tokenString)
	if err != nil {
		logger.Warn("Service JWT validation failed",
			zap.Error(err),
			zap.String("remote_addr", RealClientIP(c)),
		)
		return err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims")
	}
	// Tenant API key tokens are for the business API only, never S2S.
	if typ, _ := claims["type"].(string); typ == services.APIKeyTokenType {
		return fmt.Errorf("API key tokens are not accepted here")
	}

	isSelfIssued := resolvedSlug == "oauth-client"

	// Tokens signed with the OAuth provider key include end-user access
	// tokens, so only genuine client_credentials tokens may pass.
	if isSelfIssued {
		if err := validateClientCredentialsClaims(claims); err != nil {
			return err
		}
	}

	if err := validateServiceJWTAudience(claims, isSelfIssued); err != nil {
		return err
	}

	// `aud` may be a string or an array post-multi-aud migration. Take
	// the first entry as the canonical slug-fallback — for self-issued
	// tokens, client_id wins anyway (resolveServiceSlug); the fallback
	// only fires when the OAuth client itself lacks a client_id claim
	// (defensive path, not expected in normal flow).
	auds := extractAudiences(claims["aud"])
	var aud string
	if len(auds) > 0 {
		aud = auds[0]
	}
	slug := resolveServiceSlug(claims, resolvedSlug, isSelfIssued, aud)

	scopes, _ := claims["scope"].(string)
	tenantIDStr, _ := claims["tenant_id"].(string)

	c.Set(CtxKeyServiceSlug, slug)
	c.Set(CtxKeyServiceScopes, scopes)
	c.Set(CtxKeyServiceTenantID, tenantIDStr)
	c.Set(CtxKeyAuthMethod, "service_jwt")
	if iss, ok := claims["iss"].(string); ok {
		c.Set("service_issuer", iss)
	}

	if m.usageRecorder != nil && slug != "" {
		ip := RealClientIP(c)
		now := time.Now()
		rec := m.usageRecorder
		go func() {
			ctx := context.Background()
			if err := rec.RecordServicePrincipalUsage(ctx, slug, ip, now); err != nil {
				logger.Warn("Failed to record service principal usage",
					zap.String("slug", slug),
					zap.Error(err),
				)
			}
		}()
	}

	return nil
}

// parseAndVerifyToken parses and cryptographically verifies the JWT, returning the resolved service slug.
func (m *ServiceAuthMiddleware) parseAndVerifyToken(c *gin.Context, tokenString string) (*jwt.Token, string, error) {
	var resolvedSlug string

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing kid header")
		}
		pubKey, slug, err := m.lookup.LookupPublicKey(c.Request.Context(), kid)
		if err != nil {
			return nil, fmt.Errorf("unknown kid: %w", err)
		}
		resolvedSlug = slug
		return pubKey, nil
	})
	if err != nil {
		return nil, "", err
	}
	if !token.Valid {
		return nil, "", fmt.Errorf("invalid service JWT")
	}
	return token, resolvedSlug, nil
}

// validateServiceJWTAudience checks that the audience claim is valid for the token type.
//
// `aud` is post-83a128e (feat/multi-audience-api-hexxlock-com) ALWAYS an
// array for tokens minted by /oauth/token — RFC 7519 §4.1.3 + the
// industry-consensus Auth0/Entra/Okta multi-aud pattern for in-place
// audience migration. Receivers MUST evaluate membership ("MY identifier
// is IN aud"), not string equality. ASP.NET's JwtBearerOptions.Audience
// already does this implicitly; the Go middleware here didn't, which
// silently locked out every self-issued (client_credentials) caller —
// including the serviceclient-provisioner Jobs that drive OAuth-client
// provisioning across the whole cluster (caught live 2026-05-30 by a
// fresh ServiceClientClaim stalling at 401 "service authentication
// required" on /api/v1/internal/oauth-clients, with every other
// claim's -gN re-bump also failing).
//
// Both branches accept string OR []interface{} aud:
//   - self-issued: any non-empty entry is acceptable (the slug + scope
//     downstream do the real authorization)
//   - external service JWT: at least one entry must equal "falcon-id"
func validateServiceJWTAudience(claims jwt.MapClaims, isSelfIssued bool) error {
	audValues := extractAudiences(claims["aud"])
	if isSelfIssued {
		if len(audValues) == 0 {
			return fmt.Errorf("missing audience in self-issued token")
		}
		return nil
	}
	for _, a := range audValues {
		if a == "falcon-id" {
			return nil
		}
	}
	return fmt.Errorf("invalid audience: %v", audValues)
}

// validateClientCredentialsClaims accepts a token signed with the OAuth
// provider key only when it is a client_credentials token for a service
// principal. User tokens (authorization_code, refresh, tenant exchange),
// api_key tokens and anything carrying a user/session marker are rejected.
//
// Positive signal: `gty == "client_credentials"`, stamped at minting. Tokens
// minted before that claim existed (no `gty`) are still accepted while they
// live, but only if `sub` equals `client_id` (a user token's sub is a user
// UUID) — remove this fallback once all pre-gty tokens have expired.
func validateClientCredentialsClaims(claims jwt.MapClaims) error {
	if t, _ := claims["type"].(string); t == "api_key" {
		return fmt.Errorf("api_key token not accepted on internal routes")
	}
	for _, k := range []string{"sid", "idp_session", "act", "auth_time", "email"} {
		if _, ok := claims[k]; ok {
			return fmt.Errorf("user-bound token not accepted on internal routes")
		}
	}
	// Tenant-administered clients can also mint client_credentials tokens, so
	// only clients owned by the platform tenant count as service principals.
	if tid, _ := claims["tenant_id"].(string); tid != models.HexxlockInternalTenantID {
		return fmt.Errorf("token tenant is not the platform tenant")
	}
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	if sub == "" || clientID == "" || sub != clientID {
		return fmt.Errorf("token subject is not a service client")
	}
	if gty, present := claims["gty"]; present {
		if g, _ := gty.(string); g != "client_credentials" {
			return fmt.Errorf("token grant type not accepted on internal routes")
		}
	}
	return nil
}

// extractAudiences normalises the JWT `aud` claim into a string slice
// regardless of single-string vs string-array encoding. Returns an
// empty slice when the claim is absent / malformed.
func extractAudiences(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

// resolveServiceSlug determines the final service identity slug from claims.
func resolveServiceSlug(claims jwt.MapClaims, resolvedSlug string, isSelfIssued bool, aud string) string {
	if isSelfIssued {
		if clientID, ok := claims["client_id"].(string); ok && clientID != "" {
			return clientID
		}
		return aud
	}
	slug := resolvedSlug
	if slug == "" {
		if iss, ok := claims["iss"].(string); ok && iss != "" {
			slug = iss
		}
	}
	if svcSlug, ok := claims["service_slug"].(string); ok && svcSlug != "" {
		slug = svcSlug
	}
	return slug
}

// GetServiceScopes returns the authenticated scopes from the Gin context as a
// pre-parsed set. Returns an empty map when no scopes are present.
func GetServiceScopes(c *gin.Context) map[string]struct{} {
	raw, _ := c.Get(CtxKeyServiceScopes)
	scopeStr, _ := raw.(string)
	return parseServiceScopes(scopeStr)
}

// parseServiceScopes splits a space-separated scope string into a set.
func parseServiceScopes(raw string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, s := range strings.Fields(raw) {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	return set
}

// GetServiceTenantID retrieves the tenant_id from the service JWT context.
// Returns uuid.Nil when the claim is absent or invalid.
func GetServiceTenantID(c *gin.Context) uuid.UUID {
	raw, _ := c.Get(CtxKeyServiceTenantID)
	s, _ := raw.(string)
	if s == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// ServicePrincipalLookupAdapter adapts the ServicePrincipalService for middleware use.
type ServicePrincipalLookupAdapter struct {
	getByKeyID func(ctx context.Context, keyID string) (pubKeyPEM string, slug string, err error)
}

// NewServicePrincipalLookupAdapter creates an adapter from a lookup function.
func NewServicePrincipalLookupAdapter(fn func(ctx context.Context, keyID string) (string, string, error)) *ServicePrincipalLookupAdapter {
	return &ServicePrincipalLookupAdapter{getByKeyID: fn}
}

// LookupPublicKey implements ServicePrincipalLookup.
func (a *ServicePrincipalLookupAdapter) LookupPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, string, error) {
	pubKeyPEM, slug, err := a.getByKeyID(ctx, keyID)
	if err != nil {
		return nil, "", err
	}

	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode public key PEM")
	}

	pubIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pubIface.(*rsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("public key is not RSA")
	}

	return rsaPub, slug, nil
}

// CompositeKeyLookup implements ServicePrincipalLookup by trying the OAuth provider's
// own signing key first, then falling back to the service principal registry.
// This follows the Keycloak/Auth0 pattern where the authorization server validates
// its own client_credentials tokens using the same key namespace as external service JWTs.
type CompositeKeyLookup struct {
	oauthKeyID  string
	oauthPubKey *rsa.PublicKey
	spLookup    ServicePrincipalLookup

	oauthResolver func(kid string) (*rsa.PublicKey, bool)
}

// NewCompositeKeyLookup creates a composite key resolver.
// oauthKeyID and oauthPubKey are the OAuth provider's own signing key (for self-issued tokens).
// spLookup is the service principal registry (for externally-signed service JWTs).
func NewCompositeKeyLookup(oauthKeyID string, oauthPubKey *rsa.PublicKey, spLookup ServicePrincipalLookup) *CompositeKeyLookup {
	return &CompositeKeyLookup{
		oauthKeyID:  oauthKeyID,
		oauthPubKey: oauthPubKey,
		spLookup:    spLookup,
	}
}

// WithOAuthKeyResolver makes self-issued kids resolve dynamically (so keys that
// appear after startup, e.g. via rotation, are accepted) instead of only the
// startup key.
func (c *CompositeKeyLookup) WithOAuthKeyResolver(fn func(kid string) (*rsa.PublicKey, bool)) *CompositeKeyLookup {
	c.oauthResolver = fn
	return c
}

// LookupPublicKey resolves the signing key for a given kid.
// If the kid matches the OAuth provider's own key, returns that key with slug derived
// from the token's client_id claim (set later by ServiceAuth middleware).
// Otherwise delegates to the service principal registry.
func (c *CompositeKeyLookup) LookupPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, string, error) {
	if c.oauthResolver != nil {
		if pub, ok := c.oauthResolver(keyID); ok {
			return pub, "oauth-client", nil
		}
	}
	if keyID == c.oauthKeyID {
		// Self-issued token — slug will be overridden from client_id claim in ServiceAuth
		return c.oauthPubKey, "oauth-client", nil
	}
	return c.spLookup.LookupPublicKey(ctx, keyID)
}
