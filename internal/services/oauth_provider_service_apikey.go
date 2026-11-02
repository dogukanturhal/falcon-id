// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// API key access token constants.
const (
	// APIKeyTokenType is the `type` claim of tokens minted by the API key exchange.
	APIKeyTokenType = "api_key"
	// APIKeyScopeRead / APIKeyScopeWrite are the ERP scopes a key token carries.
	APIKeyScopeRead  = "erp.read"
	APIKeyScopeWrite = "erp.write"
)

// APIKeyTokenParams is everything the signer needs to mint a key token.
type APIKeyTokenParams struct {
	TenantID uuid.UUID
	// KeyID is the iam_api_keys row id: it is the token `sub`, the SpiceDB
	// subject of the key's role edges and the id used by the business-side
	// company edges.
	KeyID    uuid.UUID
	Access   string // read | write
	Audience string
	TTL      time.Duration
}

// APIKeyScopes maps a key's access level to its token scopes.
func APIKeyScopes(access string) []string {
	if access == "write" {
		return []string{APIKeyScopeRead, APIKeyScopeWrite}
	}
	return []string{APIKeyScopeRead}
}

// BuildAPIKeyClaims builds the claim set of an API key access token. It is a
// pure function so the claim shape can be pinned by a golden test.
//
// Deliberately absent: `roles` and `permissions` (authorization is resolved
// from SpiceDB role/company edges keyed by `sub`), `client_id`, and the legacy
// "hexxlock-services" audience: a key token must never be accepted by the
// internal service mesh.
func BuildAPIKeyClaims(issuer string, now time.Time, jti string, p APIKeyTokenParams) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":        issuer,
		"aud":        jwt.ClaimStrings{p.Audience},
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        now.Add(p.TTL).Unix(),
		"jti":        jti,
		"sub":        p.KeyID.String(),
		"tenant_id":  p.TenantID.String(),
		"type":       APIKeyTokenType,
		"api_key_id": p.KeyID.String(),
		"scope":      strings.Join(APIKeyScopes(p.Access), " "),
	}
}

// MintAPIKeyToken signs an API key access token with the provider's active
// RS256 signing key (the live KeyManager key and kid, as generateTokens uses,
// so rotation applies and existing JWKS validation works).
func (s *OAuthProviderService) MintAPIKeyToken(p APIKeyTokenParams) (string, error) {
	signKey, signKid := s.signingKey()
	if signKey == nil {
		return "", fmt.Errorf("MintAPIKeyToken: signing key not initialised")
	}
	if p.Audience == "" || p.TTL <= 0 {
		return "", fmt.Errorf("MintAPIKeyToken: audience and ttl are required")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, BuildAPIKeyClaims(s.getIssuer(), time.Now(), uuid.NewString(), p))
	token.Header["kid"] = signKid
	signed, err := token.SignedString(signKey)
	if err != nil {
		return "", fmt.Errorf("MintAPIKeyToken: sign: %w", err)
	}
	return signed, nil
}
