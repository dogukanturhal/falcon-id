// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ExternalJWTValidator verifies JWTs signed by EXTERNAL issuers
// registered as iam_oauth_trusted_external_issuers rows — most
// importantly the Talon Identity-Aware Proxy at
// internal.example.com. Distinct from
// OAuthProviderService.ValidateAccessToken (which only validates
// JWTs Falcon-ID issued itself, by checking against its own RSA
// public key + iam_oauth_tokens row).
//
// Why a fresh validator rather than reusing TokenExchangeService's
// fetchJWKS: that path's JWKS parser stops at counting keys and
// returns an empty VerificationKeySet (see
// token_exchange_service.go:265-286 — comment notes the gap),
// which silently lets verification pass with NO key validation.
// That's fine for workload tokens that go through the broader
// SPIFFE/k8s validation chain, but is not safe enough for HUMAN
// delegation where the issued user-bound access_token grants full
// portal access. This validator does real RSA key parsing + kid
// dispatch + signature verification.
//
// Algorithm scope is INTENTIONALLY narrow: RS256 only. Talon's
// signer.go locks RS256 (RFC 7518 §3.3 — the OIDC default and
// what every tier-1 IAP we surveyed ships: GCP IAP, Cloudflare
// Access, AWS ALB OIDC, Pomerium). Adding more algs widens the
// alg-confusion attack surface (RFC 8725 §3.1) for no concrete
// benefit. New algs require an explicit code change.
type ExternalJWTValidator struct {
	httpClient *http.Client
	cache      *externalJWKSCache
}

// NewExternalJWTValidator constructs a validator with a 10s
// HTTP timeout and a 5min JWKS cache TTL (matches Cloudflare
// Access's published JWKS TTL — verified 2026-05-13 via curl
// -I https://hexxlock.cloudflareaccess.com/cdn-cgi/access/certs).
func NewExternalJWTValidator() *ExternalJWTValidator {
	return &ExternalJWTValidator{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      newExternalJWKSCache(),
	}
}

// ValidatedExternalJWT is the structured return from a successful
// verify. The full claim map is exposed so callers can pluck app-
// specific extensions (Talon stamps tenant_id, sso_chain_id,
// groups, etc. beyond the RFC 7519 standard set) without this
// package needing to know every issuer's claim shape.
type ValidatedExternalJWT struct {
	Subject  string
	Issuer   string
	Audience []string
	IssuedAt int64
	Expiry   int64
	JTI      string
	Claims   jwt.MapClaims
}

// Validate fetches the issuer's JWKS, parses it into RSA public
// keys, verifies the JWT's RS256 signature against the key
// matching the JWT's `kid` header, and applies the issuer's
// standard claim guards:
//
//   - iss == issuer.IssuerURL (string equality, no wildcarding)
//   - exp present + in the future
//   - iat present + (now - iat) ≤ issuer.MaxTokenAgeSeconds (defense-
//     in-depth against very-long-lived externally-issued JWTs that
//     would slip past the cluster-wide IAP token lifetime norm)
//   - aud ∩ issuer.Audiences ≠ ∅ (when issuer.Audiences is non-empty)
//   - sub present + non-empty
//
// Per-client narrowing (e.g. the calling BFF's
// iam_oauth_client_trusted_external_issuers.audiences override) is
// the CALLER's responsibility — this validator only enforces the
// issuer-level trust boundary.
func (v *ExternalJWTValidator) Validate(
	ctx context.Context,
	tokenString string,
	issuer *models.OAuthTrustedExternalIssuer,
) (*ValidatedExternalJWT, error) {
	if issuer == nil {
		return nil, errors.New("external_jwt_validator: nil issuer")
	}

	keys, err := v.fetchKeys(ctx, issuer.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("external_jwt_validator: fetch JWKS for %s: %w", issuer.IssuerURL, err)
	}

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unsupported signing method %q (RS256 only)", token.Method.Alg())
		}
		kid, _ := token.Header["kid"].(string)
		// Empty kid → must have exactly one key in the JWKS for a safe
		// unambiguous match. Multi-key JWKS without a kid is rejected.
		if kid == "" {
			if len(keys) == 1 {
				for _, k := range keys {
					return k, nil
				}
			}
			return nil, errors.New("token missing kid header; JWKS has multiple keys")
		}
		if k, ok := keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("no JWKS key for kid=%q", kid)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)
	parsed, err := parser.Parse(tokenString, keyfunc)
	if err != nil {
		return nil, fmt.Errorf("external_jwt_validator: parse/verify: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("external_jwt_validator: unexpected claims type")
	}

	gotIss, _ := claims.GetIssuer()
	if gotIss != issuer.IssuerURL {
		return nil, fmt.Errorf("external_jwt_validator: iss mismatch — got %q want %q", gotIss, issuer.IssuerURL)
	}

	gotSub, _ := claims.GetSubject()
	if gotSub == "" {
		return nil, errors.New("external_jwt_validator: missing/empty sub claim")
	}

	expTime, expErr := claims.GetExpirationTime()
	iatTime, iatErr := claims.GetIssuedAt()
	if expErr != nil || expTime == nil {
		return nil, errors.New("external_jwt_validator: missing exp claim")
	}
	if iatErr != nil || iatTime == nil {
		return nil, errors.New("external_jwt_validator: missing iat claim")
	}
	now := time.Now()
	if !expTime.After(now) {
		return nil, fmt.Errorf("external_jwt_validator: token already expired (exp=%s now=%s)", expTime.Time, now)
	}
	if issuer.MaxTokenAgeSeconds > 0 {
		age := now.Sub(iatTime.Time)
		maxAge := time.Duration(issuer.MaxTokenAgeSeconds) * time.Second
		if age > maxAge {
			return nil, fmt.Errorf("external_jwt_validator: token age %s exceeds issuer max %s", age, maxAge)
		}
	}

	audList, audErr := claims.GetAudience()
	if audErr != nil {
		audList = nil
	}
	if len(issuer.Audiences) > 0 && !audIntersects(audList, issuer.Audiences) {
		return nil, fmt.Errorf("external_jwt_validator: aud %v does not match any of issuer's allowed audiences %v", audList, issuer.Audiences)
	}

	jti, _ := claims["jti"].(string)

	return &ValidatedExternalJWT{
		Subject:  gotSub,
		Issuer:   gotIss,
		Audience: audList,
		IssuedAt: iatTime.Unix(),
		Expiry:   expTime.Unix(),
		JTI:      jti,
		Claims:   claims,
	}, nil
}

// fetchKeys returns the parsed RSA public keys for jwksURL, keyed
// by kid. Result is cached per-URL for the cache TTL.
func (v *ExternalJWTValidator) fetchKeys(ctx context.Context, jwksURL string) (map[string]*rsa.PublicKey, error) {
	if ks, ok := v.cache.get(jwksURL); ok {
		return ks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	keys, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	v.cache.set(jwksURL, keys)
	return keys, nil
}

// audIntersects reports whether `got` (the JWT's aud claim list,
// post-normalisation by jwt/v5) shares at least one element with
// `allowed`. Linear scan — both lists are tiny in practice (≤4
// entries).
func audIntersects(got, allowed []string) bool {
	for _, g := range got {
		for _, a := range allowed {
			if g == a {
				return true
			}
		}
	}
	return false
}

// ----------------------------------------------------------------
// JWKS parsing — minimal in-tree RFC 7517 / 7518 reader for
// kty=RSA + alg=RS256. Keeps the dependency surface narrow; the
// fields we read are stable parts of the standard.
// ----------------------------------------------------------------

type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for i, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue // skip non-RSA keys silently
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue // skip alg values we won't honour
		}
		if k.Use != "" && k.Use != "sig" {
			continue // skip enc keys
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("parse JWKS[%d] n: %w", i, err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("parse JWKS[%d] e: %w", i, err)
		}
		// RFC 7518 §6.3.1.2 — e is a base64url-encoded big-endian
		// integer. Common values are AQAB (0x010001 = 65537).
		var e int
		if len(eBytes) > 4 {
			return nil, fmt.Errorf("parse JWKS[%d]: exponent too large", i)
		}
		switch len(eBytes) {
		case 0:
			return nil, fmt.Errorf("parse JWKS[%d]: empty exponent", i)
		case 1:
			e = int(eBytes[0])
		case 2:
			e = int(binary.BigEndian.Uint16(eBytes))
		case 3:
			padded := []byte{0, eBytes[0], eBytes[1], eBytes[2]}
			e = int(binary.BigEndian.Uint32(padded))
		case 4:
			e = int(binary.BigEndian.Uint32(eBytes))
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
		// JWKS without a kid is acceptable; we key by empty string
		// and the Validate-side keyfunc handles the lookup.
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("parse JWKS: no usable RSA RS256 keys found")
	}
	return keys, nil
}

// ----------------------------------------------------------------
// JWKS cache — keyed by URL, 5-minute TTL.
// ----------------------------------------------------------------

type externalJWKSCache struct {
	mu      sync.RWMutex
	entries map[string]externalJWKSEntry
}

type externalJWKSEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

const externalJWKSCacheTTL = 5 * time.Minute

func newExternalJWKSCache() *externalJWKSCache {
	return &externalJWKSCache{entries: make(map[string]externalJWKSEntry)}
}

func (c *externalJWKSCache) get(url string) (map[string]*rsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[url]
	if !ok || time.Since(e.fetchedAt) > externalJWKSCacheTTL {
		return nil, false
	}
	return e.keys, true
}

func (c *externalJWKSCache) set(url string, keys map[string]*rsa.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = externalJWKSEntry{keys: keys, fetchedAt: time.Now()}
}
