// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// tokenPublicKeyLookup is the narrow interface InternalTokenHandler needs to
// validate tokens. It is satisfied by ServicePrincipalLookupAdapter in
// middleware/service_auth.go without any extra glue.
type tokenPublicKeyLookup interface {
	LookupPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, string, error)
}

// InternalTokenHandler handles token validation endpoints used by other
// microservices that cannot (or choose not to) validate JWTs locally.
type InternalTokenHandler struct {
	lookup tokenPublicKeyLookup
}

// NewInternalTokenHandler creates a new InternalTokenHandler.
func NewInternalTokenHandler(lookup tokenPublicKeyLookup) *InternalTokenHandler {
	return &InternalTokenHandler{lookup: lookup}
}

// validateTokenRequest is the body for POST /api/v1/internal/token/validate.
type validateTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// validateTokenResponse is the success response for token validation.
type validateTokenResponse struct {
	Valid       bool     `json:"valid"`
	ServiceSlug string   `json:"service_slug,omitempty"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	ExpiresAt   int64    `json:"expires_at,omitempty"` // Unix timestamp
}

// Validate handles POST /api/v1/internal/token/validate
//
// Body:   { "token": "<bearer-token>" }
// 200 OK: { "valid": true, "service_slug": "crm", "tenant_id": "...", "scopes": ["events:publish"] }
// 401:    { "valid": false, "error": "..." }
//
// This endpoint is itself protected by ServiceAuth so the caller must already
// be authenticated as a service principal.
func (h *InternalTokenHandler) Validate(c *gin.Context) {
	var req validateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token field is required"})
		return
	}

	resp, err := h.validateToken(c.Request.Context(), req.Token)
	if err != nil {
		logger.Warn("Token validation failed",
			zap.Error(err),
			zap.String("remote_addr", GetClientIP(c)),
		)
		c.JSON(http.StatusUnauthorized, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Introspect handles POST /api/v1/internal/token/introspect
//
// RFC 7662-style endpoint. Returns the same payload as Validate but always
// returns 200 — even for invalid tokens — with "valid": false in the body.
// This follows the RFC 7662 introspection contract used by OAuth2 resource servers.
func (h *InternalTokenHandler) Introspect(c *gin.Context) {
	var req validateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token field is required"})
		return
	}

	resp, err := h.validateToken(c.Request.Context(), req.Token)
	if err != nil {
		// RFC 7662 §2.2: return 200 with active:false for invalid tokens.
		c.JSON(http.StatusOK, gin.H{"valid": false, "active": false})
		return
	}

	// Include RFC 7662 "active" field alongside our own "valid".
	c.JSON(http.StatusOK, gin.H{
		"valid":        resp.Valid,
		"active":       resp.Valid,
		"service_slug": resp.ServiceSlug,
		"tenant_id":    resp.TenantID,
		"scopes":       resp.Scopes,
		"expires_at":   resp.ExpiresAt,
	})
}

// validateToken parses and verifies a service JWT against the public-key store.
func (h *InternalTokenHandler) validateToken(ctx context.Context, tokenString string) (*validateTokenResponse, error) {
	var resolvedSlug string

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return h.resolveSigningKey(ctx, token, &resolvedSlug)
	})
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	if err := validateAudience(claims); err != nil {
		return nil, err
	}

	slug := resolveServiceSlug(claims, resolvedSlug)
	scopes := extractScopes(claims)
	tenantID, _ := claims["tenant_id"].(string)
	expiresAt := extractExpiresAt(claims)

	if expiresAt > 0 && time.Now().Unix() > expiresAt {
		return nil, fmt.Errorf("token has expired")
	}

	return &validateTokenResponse{
		Valid:       true,
		ServiceSlug: slug,
		TenantID:    tenantID,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
	}, nil
}

// resolveSigningKey is the jwt.Keyfunc used by validateToken to look up the RSA public key.
func (h *InternalTokenHandler) resolveSigningKey(ctx context.Context, token *jwt.Token, resolvedSlug *string) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("missing kid header")
	}
	pubKey, slug, err := h.lookup.LookupPublicKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("unknown kid %q: %w", kid, err)
	}
	*resolvedSlug = slug
	return pubKey, nil
}

// resolveServiceSlug picks the best service slug from claims, falling back to
// the slug resolved from the key-store lookup.
func resolveServiceSlug(claims jwt.MapClaims, keyStoreSlug string) string {
	if svcSlug, ok := claims["service_slug"].(string); ok && svcSlug != "" {
		return svcSlug
	}
	if keyStoreSlug == "" {
		if iss, ok := claims["iss"].(string); ok {
			return iss
		}
	}
	return keyStoreSlug
}

// extractScopes splits the space-separated "scope" claim into a string slice.
func extractScopes(claims jwt.MapClaims) []string {
	scopeStr, _ := claims["scope"].(string)
	var scopes []string
	scopes = append(scopes, strings.Fields(scopeStr)...)
	return scopes
}

// extractExpiresAt returns the "exp" claim as a Unix timestamp, or 0 if absent.
func extractExpiresAt(claims jwt.MapClaims) int64 {
	if exp, ok := claims["exp"].(float64); ok {
		return int64(exp)
	}
	return 0
}

// validateAudience checks that the token carries "falcon-id" as an audience.
func validateAudience(claims jwt.MapClaims) error {
	switch aud := claims["aud"].(type) {
	case string:
		if aud == "falcon-id" {
			return nil
		}
		return fmt.Errorf("invalid audience %q", aud)
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == "falcon-id" {
				return nil
			}
		}
		return fmt.Errorf("audience does not contain falcon-id")
	default:
		return fmt.Errorf("missing or malformed aud claim")
	}
}
