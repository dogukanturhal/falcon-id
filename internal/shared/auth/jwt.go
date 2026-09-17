// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenValidator provides JWT token validation functionality
type TokenValidator struct {
	config *Config
}

// NewTokenValidator creates a new TokenValidator with the given configuration
func NewTokenValidator(config *Config) *TokenValidator {
	return &TokenValidator{
		config: config,
	}
}

// ValidateAccessToken validates a JWT access token and returns the claims
func (v *TokenValidator) ValidateAccessToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrMissingToken()
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(v.config.JWTSecret), nil
	})
	if err != nil {
		// Check for specific error types using errors.Is for proper wrapped error detection
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired()
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrInvalidSignature()
		}
		return nil, ErrTokenInvalid(err.Error())
	}

	if !token.Valid {
		return nil, ErrTokenInvalid("token is not valid")
	}

	// Extract claims
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid("failed to parse claims")
	}

	// Parse claims into our Claims struct
	claims, err := parseMapClaims(mapClaims)
	if err != nil {
		return nil, fmt.Errorf("ValidateAccessToken: s failed: %w", err)
	}

	// Validate issuer if required
	if v.config.RequireValidIssuer && v.config.JWTIssuer != "" {
		if claims.Issuer != v.config.JWTIssuer {
			return nil, ErrTokenInvalid("invalid token issuer")
		}
	}

	// Validate expiration
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && claims.ExpiresAt < now {
		return nil, ErrTokenExpired()
	}

	// Validate not-before
	if claims.NotBefore > 0 && claims.NotBefore > now {
		return nil, ErrTokenInvalid("token not yet valid")
	}

	return claims, nil
}

// ParseTokenUnverified parses a token without verifying the signature
// Use this only when you need to extract claims without validation (e.g., for logging)
func ParseTokenUnverified(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrMissingToken()
	}

	// Parse without verification
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, ErrTokenMalformed()
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid("failed to parse claims")
	}

	return parseMapClaims(mapClaims)
}

// parseMapClaims converts jwt.MapClaims to our Claims struct
// Supports both tenant user tokens and platform admin tokens
func parseMapClaims(mapClaims jwt.MapClaims) (*Claims, error) {
	claims := &Claims{}

	// Check if this is a platform admin token (has scope: "platform")
	isPlatformAdmin := false
	if scope, ok := mapClaims["scope"].(string); ok && scope == "platform" {
		isPlatformAdmin = true
		claims.TokenType = "platform_admin"
	}

	parseMapClaimsStrings(mapClaims, claims)

	if err := parseMapClaimsUUIDs(mapClaims, claims, isPlatformAdmin); err != nil {
		return nil, err
	}

	parseMapClaimsTimestamps(mapClaims, claims)
	parseMapClaimsArrays(mapClaims, claims, isPlatformAdmin)

	return claims, nil
}

// parseMapClaimsStrings extracts string scalar fields from JWT map claims.
func parseMapClaimsStrings(mapClaims jwt.MapClaims, claims *Claims) {
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if aud, ok := mapClaims["aud"].(string); ok {
		claims.Audience = aud
	}
	if username, ok := mapClaims["username"].(string); ok {
		claims.Username = username
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}
	if clientID, ok := mapClaims["client_id"].(string); ok {
		claims.ClientID = clientID
	}
	if tokenType, ok := mapClaims["type"].(string); ok {
		claims.TokenType = tokenType
	}
}

// parseMapClaimsUUIDs extracts UUID fields from JWT map claims.
func parseMapClaimsUUIDs(mapClaims jwt.MapClaims, claims *Claims, isPlatformAdmin bool) error {
	// Tenant ID (support both verbose v0 and abbreviated v1/v2 names)
	if tenantIDStr := firstString(mapClaims, "tenant_id", "tid"); tenantIDStr != "" {
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			return ErrTokenInvalid("invalid tenant_id in token")
		}
		claims.TenantID = tenantID
	}

	// User ID (platform admin uses admin_id, others use user_id/sub)
	if err := parseUserIDClaim(mapClaims, claims, isPlatformAdmin); err != nil {
		return err
	}

	// Session ID
	if sessionIDStr := firstString(mapClaims, "session_id", "sid"); sessionIDStr != "" {
		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			return ErrTokenInvalid("invalid session_id in token")
		}
		claims.SessionID = sessionID
	}

	// Optional UUID fields (best-effort, no error on parse failure)
	if saIDStr, ok := mapClaims["service_account_id"].(string); ok && saIDStr != "" {
		if saID, err := uuid.Parse(saIDStr); err == nil {
			claims.ServiceAccountID = &saID
		}
	}
	if impIDStr, ok := mapClaims["impersonator_id"].(string); ok && impIDStr != "" {
		if impID, err := uuid.Parse(impIDStr); err == nil {
			claims.ImpersonatorID = &impID
		}
	}
	if impSessionIDStr, ok := mapClaims["impersonation_session_id"].(string); ok && impSessionIDStr != "" {
		if impSessionID, err := uuid.Parse(impSessionIDStr); err == nil {
			claims.ImpersonationSessionID = &impSessionID
		}
	}
	return nil
}

// parseMapClaimsTimestamps extracts numeric timestamp fields from JWT map claims.
func parseMapClaimsTimestamps(mapClaims jwt.MapClaims, claims *Claims) {
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if nbf, ok := mapClaims["nbf"].(float64); ok {
		claims.NotBefore = int64(nbf)
	}
}

// parseMapClaimsArrays extracts slice fields from JWT map claims.
func parseMapClaimsArrays(mapClaims jwt.MapClaims, claims *Claims, isPlatformAdmin bool) {
	if roles, ok := mapClaims["roles"].([]interface{}); ok {
		claims.Roles = make([]string, 0, len(roles))
		for _, r := range roles {
			if roleStr, ok := r.(string); ok {
				claims.Roles = append(claims.Roles, roleStr)
			}
		}
	}
	// For platform admin tokens, convert singular "role" to roles array
	if isPlatformAdmin {
		if role, ok := mapClaims["role"].(string); ok && role != "" {
			claims.Roles = []string{role, "platform_admin"}
			if role == "super_admin" {
				claims.Roles = append(claims.Roles, "admin", "super_admin")
			}
		}
	}
	if permissions, ok := mapClaims["permissions"].([]interface{}); ok {
		claims.Permissions = make([]string, 0, len(permissions))
		for _, p := range permissions {
			if permStr, ok := p.(string); ok {
				claims.Permissions = append(claims.Permissions, permStr)
			}
		}
	}
	if scopes, ok := mapClaims["scopes"].([]interface{}); ok {
		claims.Scopes = make([]string, 0, len(scopes))
		for _, s := range scopes {
			if scopeStr, ok := s.(string); ok {
				claims.Scopes = append(claims.Scopes, scopeStr)
			}
		}
	}
}

// firstString returns the first non-empty string value found for the given keys
// in a JWT claims map. Used to support both verbose (v0) and abbreviated (v1/v2) claim names.
func firstString(m jwt.MapClaims, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// ExtractBearerToken extracts the token from an Authorization header
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingToken()
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return "", ErrTokenMalformed()
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return "", ErrTokenMalformed()
	}

	return parts[1], nil
}

// parseUserIDClaim extracts the user/admin ID from the JWT map claims.
func parseUserIDClaim(mapClaims jwt.MapClaims, claims *Claims, isPlatformAdmin bool) error {
	if isPlatformAdmin {
		adminIDStr, ok := mapClaims["admin_id"].(string)
		if !ok || adminIDStr == "" {
			return nil
		}
		adminID, err := uuid.Parse(adminIDStr)
		if err != nil {
			return ErrTokenInvalid("invalid admin_id in token")
		}
		claims.UserID = adminID
		return nil
	}
	userIDStr := firstString(mapClaims, "user_id", "sub")
	if userIDStr == "" {
		return nil
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return ErrTokenInvalid("invalid user_id in token")
	}
	claims.UserID = userID
	return nil
}
