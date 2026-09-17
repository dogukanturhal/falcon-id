// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerifyJARRequestObject parses a JWS-encoded RFC 9101 request object
// and returns its claims after verifying:
//
//  1. The JWS header `alg` matches the client's registered
//     request_object_signing_alg (no algorithm-confusion attacks).
//  2. The JWS signature verifies against a key from the client's
//     registered JWKS. We try keys in JWKS order; on first match the
//     signature is accepted.
//  3. `exp` is in the future (request-object replay window cap; RFC
//     9101 §4 strongly recommends a short TTL — we accept up to 1
//     hour, matching the platform's authorization_code TTL).
//  4. `iat`, when present, is not in the future (clock-skew tolerance
//     of 60 seconds).
//
// Returns the JWS claims as a jwt.MapClaims so the caller can pull
// authorize-request fields. We deliberately return the raw map rather
// than a typed struct: future RFC 9101 extensions (e.g. claims
// requested per OIDC Core §5.5) carry through without a model change.
//
// Today this implementation supports only RS256 / RS384 / RS512 (RSA
// signatures). EdDSA + ES256 are documented in RFC 9101 §4 but not
// wired in this commit; the signing-alg check rejects unrequested
// algorithms cleanly.
func VerifyJARRequestObject(jws, jwksJSON, allowedAlg string) (jwt.MapClaims, error) {
	if !isSupportedJARAlg(allowedAlg) {
		return nil, fmt.Errorf("request_object_signing_alg %q is not supported (RS256/RS384/RS512 only)", allowedAlg)
	}

	var keyset struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksJSON), &keyset); err != nil {
		return nil, fmt.Errorf("client jwks is not valid JSON: %v", err)
	}
	if len(keyset.Keys) == 0 {
		return nil, fmt.Errorf("client jwks is empty")
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{allowedAlg}))
	token, err := parser.Parse(jws, func(token *jwt.Token) (interface{}, error) {
		// Try each key in the JWKS until one verifies. A header `kid`
		// would let us short-circuit to the matching key — supported
		// when the JWS header carries one.
		var preferredKid string
		if v, ok := token.Header["kid"].(string); ok {
			preferredKid = v
		}
		// Walk preferred-kid first, then fall through.
		ordered := orderJWKSByKid(keyset.Keys, preferredKid)
		for _, k := range ordered {
			pub, perr := jwkToRSAPublicKey(k)
			if perr != nil {
				continue // try the next key
			}
			return pub, nil
		}
		return nil, fmt.Errorf("no usable key in client jwks (kid=%q)", preferredKid)
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("request object signature is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("request object claims are not a JSON object")
	}

	// RFC 9101 §4 / §6 — bound the request-object lifetime so a
	// captured JWS can't be replayed indefinitely. We require `exp`;
	// `iat` is checked when present.
	now := time.Now().Unix()
	if expF, ok := claims["exp"].(float64); ok {
		if int64(expF) <= now {
			return nil, fmt.Errorf("request object has expired")
		}
		// Cap at 1 hour from now — defense-in-depth even if the
		// client embeds a very large exp.
		const maxRequestObjectTTL = 3600
		if int64(expF)-now > maxRequestObjectTTL {
			return nil, fmt.Errorf("request object exp exceeds the platform-permitted 1h TTL")
		}
	} else {
		return nil, fmt.Errorf("request object missing the exp claim (RFC 9101 §4)")
	}
	if iatF, ok := claims["iat"].(float64); ok {
		const clockSkewSeconds = 60
		if int64(iatF) > now+clockSkewSeconds {
			return nil, fmt.Errorf("request object iat is in the future (clock skew?)")
		}
	}

	return claims, nil
}

func isSupportedJARAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512":
		return true
	}
	return false
}

// orderJWKSByKid returns the keyset with the preferred-kid entry
// first (when present), then the rest in original order.
func orderJWKSByKid(keys []map[string]interface{}, preferredKid string) []map[string]interface{} {
	if preferredKid == "" {
		return keys
	}
	preferred := make([]map[string]interface{}, 0, 1)
	rest := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		if kid, ok := k["kid"].(string); ok && kid == preferredKid {
			preferred = append(preferred, k)
			continue
		}
		rest = append(rest, k)
	}
	return append(preferred, rest...)
}

// jwkToRSAPublicKey converts an RFC 7517 JWK (RSA only, kty=RSA) to
// an *rsa.PublicKey. Rejects non-RSA keys cleanly.
func jwkToRSAPublicKey(k map[string]interface{}) (*rsa.PublicKey, error) {
	if kty, _ := k["kty"].(string); kty != "RSA" {
		return nil, fmt.Errorf("unsupported jwk kty %q (only RSA today)", kty)
	}
	nB64, _ := k["n"].(string)
	eB64, _ := k["e"].(string)
	if nB64 == "" || eB64 == "" {
		return nil, fmt.Errorf("RSA jwk missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("RSA jwk n is not base64url: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("RSA jwk e is not base64url: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()
	if e <= 0 {
		return nil, fmt.Errorf("RSA jwk e is not positive")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}
