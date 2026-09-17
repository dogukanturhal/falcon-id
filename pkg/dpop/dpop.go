// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dpop implements DPoP (Demonstrating Proof of Possession) proof
// validation as defined in RFC 9449. DPoP binds access tokens to a
// client-held public/private key pair, preventing token replay by attackers
// who intercept the token but do not possess the corresponding private key.
//
// Usage overview:
//
//  1. The client generates a DPoP key pair and attaches the proof JWT in the
//     "DPoP" HTTP request header on every request.
//  2. The server calls ValidateProof to verify the proof is:
//     - A well-formed JWT signed with the embedded JWK.
//     - Typed as "dpop+jwt".
//     - Bound to the correct HTTP method (htm) and URI (htu).
//     - Fresh (iat within MaxProofAge, not in the future beyond MaxClockSkew).
//     - Carrying a unique jti (callers must check for replays against storage).
//  3. The JKT (JWK thumbprint per RFC 7638) returned in Proof.JKT can be
//     compared against the cnf.jkt claim of the associated access token to
//     complete token binding verification.
package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MaxClockSkew is the maximum allowable difference between the DPoP proof's
// iat claim and the server's current time. This accommodates minor clock
// drift between client and server.
const MaxClockSkew = 60 * time.Second

// MaxProofAge is the maximum age of a DPoP proof before it is considered
// stale. RFC 9449 Section 11.1 recommends a short window; 5 minutes is a
// widely adopted value. Callers should also persist JTIs and reject replays
// for at least this window.
const MaxProofAge = 5 * time.Minute

// Proof contains the verified claims extracted from a DPoP proof JWT.
// All string fields are guaranteed non-empty on successful validation.
type Proof struct {
	// JKT is the JWK SHA-256 thumbprint (RFC 7638) of the embedded public
	// key. Use this to verify cnf.jkt in the associated access token.
	JKT string

	// JTI is the unique proof identifier. Callers must persist this value
	// and reject proofs with a previously seen JTI within at least MaxProofAge
	// to prevent replay attacks.
	JTI string

	// Method is the HTTP method the proof is bound to (the "htm" claim).
	Method string

	// URI is the HTTP URI the proof is bound to (the "htu" claim).
	URI string

	// IssuedAt is the time the proof was issued ("iat" claim).
	IssuedAt time.Time

	// ATH is the base64url-encoded SHA-256 hash of the ASCII access token
	// (the "ath" claim, RFC 9449 §4.3). Present only on resource server requests
	// that accompany a DPoP-bound access token. Empty string means the claim
	// was not present in the proof (acceptable at the token endpoint).
	ATH string
}

// AccessTokenHash computes the base64url-encoded SHA-256 hash of the ASCII
// representation of the access token. This is the value that MUST appear in
// the "ath" claim of the DPoP proof submitted to a resource server alongside
// a DPoP-bound access token (RFC 9449 §4.3).
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jktContextKeyType is a private type for the context key so external
// callers can't collide by passing a plain string, and so linters don't
// flag `ctx.Value("dpop_jkt")` as a string-key anti-pattern.
type jktContextKeyType struct{}

var jktContextKey = jktContextKeyType{}

// WithJKT returns a copy of ctx carrying the JWK thumbprint that the token
// endpoint should bind the newly issued access token to. Pass empty string
// for unbound (bare bearer) token issuance — this is the default path.
//
// The contract: HTTP handlers at token-issuance sites (login, refresh,
// MFA complete, social callback, code exchange, context switch) validate
// the incoming DPoP proof (if any) and stash the resulting JKT on
// context via WithJKT. Deeper layers — specifically the token service's
// GenerateAccessToken* generators — read it back with JKTFromContext()
// and populate the cnf.jkt claim. This keeps the issuance signature
// stable across ~12 call sites instead of threading a new parameter
// through every one.
func WithJKT(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, jktContextKey, jkt)
}

// JKTFromContext extracts the JWK thumbprint placed by WithJKT. Returns
// "" when absent — callers interpret that as "issue an unbound token".
func JKTFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(jktContextKey).(string); ok {
		return v
	}
	return ""
}

// ValidateProof validates a DPoP proof JWT from the "DPoP" request header.
//
// expectedMethod must match the HTTP request method (e.g., "GET", "POST").
// expectedURI must match the full request URI without a query string, per
// RFC 9449 Section 4.2 — callers should strip the query component before
// passing it here.
//
// ValidateProof does NOT check for JTI replay; callers are responsible for
// persisting seen JTIs and returning an error for duplicates.
func ValidateProof(proofJWT, expectedMethod, expectedURI string) (*Proof, error) {
	// Parse unverified first to extract the embedded JWK from the JOSE header.
	// jwt.WithoutClaimsValidation prevents the library from rejecting the token
	// based on exp/nbf before we have performed our own temporal checks.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(proofJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to parse proof JWT: %w", err)
	}

	// RFC 9449 Section 4.2: the typ JOSE header MUST be "dpop+jwt".
	typ, _ := unverified.Header["typ"].(string)
	if typ != "dpop+jwt" {
		return nil, fmt.Errorf("dpop: invalid typ header: expected dpop+jwt, got %q", typ)
	}

	// RFC 9449 Section 4.2: the jwk JOSE header MUST contain the public key.
	jwkRaw, ok := unverified.Header["jwk"]
	if !ok {
		return nil, fmt.Errorf("dpop: proof is missing the jwk JOSE header")
	}

	jwkJSON, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("dpop: cannot marshal jwk header: %w", err)
	}

	pubKey, err := parseJWK(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("dpop: invalid JWK in proof header: %w", err)
	}

	// Re-parse the JWT and verify the signature against the embedded public key.
	verified, err := jwt.Parse(proofJWT, func(_ *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, fmt.Errorf("dpop: signature verification failed: %w", err)
	}

	claims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("dpop: proof claims are not a MapClaims")
	}

	// Validate htm (HTTP method).
	htm, _ := claims["htm"].(string)
	if htm == "" {
		return nil, fmt.Errorf("dpop: proof is missing the htm claim")
	}
	if htm != expectedMethod {
		return nil, fmt.Errorf("dpop: htm mismatch: expected %q, got %q", expectedMethod, htm)
	}

	// Validate htu (HTTP URI).
	htu, _ := claims["htu"].(string)
	if htu == "" {
		return nil, fmt.Errorf("dpop: proof is missing the htu claim")
	}
	if htu != expectedURI {
		return nil, fmt.Errorf("dpop: htu mismatch: expected %q, got %q", expectedURI, htu)
	}

	// Validate jti (unique proof identifier).
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("dpop: proof is missing or empty jti claim")
	}

	// Validate iat (issued at).
	iatRaw, ok := claims["iat"]
	if !ok {
		return nil, fmt.Errorf("dpop: proof is missing the iat claim")
	}
	iatFloat, ok := iatRaw.(float64)
	if !ok {
		return nil, fmt.Errorf("dpop: iat claim is not a numeric value")
	}
	iat := time.Unix(int64(iatFloat), 0)
	now := time.Now()

	if iat.After(now.Add(MaxClockSkew)) {
		return nil, fmt.Errorf("dpop: proof issued in the future (iat: %s, now: %s)", iat, now)
	}
	if now.Sub(iat) > MaxProofAge {
		return nil, fmt.Errorf("dpop: proof is too old (age: %s, max: %s)", now.Sub(iat), MaxProofAge)
	}

	// Compute the JWK thumbprint (RFC 7638) for cnf.jkt binding.
	jkt, err := computeJKT(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to compute JWK thumbprint: %w", err)
	}

	// Extract the optional ath (access token hash) claim.
	// RFC 9449 §4.3: REQUIRED on resource server requests, OPTIONAL at the
	// token endpoint. Callers that receive a DPoP-bound access token MUST
	// verify that ath matches BASE64URL(SHA-256(ASCII(access_token))).
	ath, _ := claims["ath"].(string)

	return &Proof{
		JKT:      jkt,
		JTI:      jti,
		Method:   htm,
		URI:      htu,
		IssuedAt: iat,
		ATH:      ath,
	}, nil
}

// ComputeJKT computes the JWK SHA-256 thumbprint as specified in RFC 7638.
// The returned value is the base64url-encoded (without padding) SHA-256 hash
// of the canonical JSON representation of the key's required members.
//
// Supported key types: RSA, EC (P-256 and P-384).
func ComputeJKT(jwkJSON []byte) (string, error) {
	return computeJKT(jwkJSON)
}

// computeJKT is the internal implementation shared by ValidateProof and
// ComputeJKT.
func computeJKT(jwkJSON []byte) (string, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return "", fmt.Errorf("dpop: invalid JWK JSON: %w", err)
	}

	kty, _ := jwk["kty"].(string)

	// RFC 7638 Section 3.2 defines the required members for each key type and
	// mandates lexicographic ordering of the JSON object keys.
	var thumbprintInput string
	switch kty {
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return "", fmt.Errorf("dpop: RSA JWK missing required e or n parameters")
		}
		// Required members in lexicographic order per RFC 7638: e, kty, n.
		thumbprintInput = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)

	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return "", fmt.Errorf("dpop: EC JWK missing required crv, x, or y parameters")
		}
		// Required members in lexicographic order per RFC 7638: crv, kty, x, y.
		thumbprintInput = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, x, y)

	default:
		return "", fmt.Errorf("dpop: unsupported JWK key type: %q", kty)
	}

	sum := sha256.Sum256([]byte(thumbprintInput))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// parseJWK deserialises a JSON Web Key into a crypto.PublicKey suitable for
// JWT signature verification. Only the public key parameters are read.
func parseJWK(jwkJSON []byte) (crypto.PublicKey, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, fmt.Errorf("dpop: cannot parse JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	switch kty {
	case "RSA":
		return parseRSAJWK(jwk)
	case "EC":
		return parseECJWK(jwk)
	default:
		return nil, fmt.Errorf("dpop: unsupported JWK key type: %q", kty)
	}
}

// parseRSAJWK constructs an *rsa.PublicKey from the "n" and "e" JWK members.
func parseRSAJWK(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nB64, _ := jwk["n"].(string)
	eB64, _ := jwk["e"].(string)
	if nB64 == "" || eB64 == "" {
		return nil, fmt.Errorf("dpop: RSA JWK missing n or e")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("dpop: invalid RSA n parameter: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("dpop: invalid RSA e parameter: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if e.BitLen() > 32 {
		return nil, fmt.Errorf("dpop: RSA public exponent is unreasonably large")
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// parseECJWK constructs an *ecdsa.PublicKey from the "crv", "x", and "y"
// JWK members. Supported curves: P-256, P-384.
func parseECJWK(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)
	if crv == "" || xB64 == "" || yB64 == "" {
		return nil, fmt.Errorf("dpop: EC JWK missing crv, x, or y")
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("dpop: unsupported EC curve: %q", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("dpop: invalid EC x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("dpop: invalid EC y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	// Validate that the point is on the curve by round-tripping through crypto/ecdh.
	if _, err := pub.ECDH(); err != nil {
		return nil, fmt.Errorf("dpop: EC public key point is not on the %s curve", crv)
	}

	return pub, nil
}
