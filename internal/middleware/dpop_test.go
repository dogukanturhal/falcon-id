// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/golang-jwt/jwt/v5"
)

// -------------------------------------------------------------------------
// Test infrastructure
// -------------------------------------------------------------------------

// dpopTestEnv holds the components needed for DPoP middleware tests.
type dpopTestEnv struct {
	mr          *miniredis.Miniredis
	redisClient goredis.Cmdable
	mw          *DPoPMiddleware
}

// newDPoPTestEnv creates a miniredis-backed DPoP middleware environment and
// registers a cleanup function to shut down miniredis at the end of the test.
func newDPoPTestEnv(t *testing.T) *dpopTestEnv {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")
	t.Cleanup(mr.Close)

	rdb := goredis.NewClient(&goredis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = rdb.Close() })

	logger := zap.NewNop()
	mw := NewDPoPMiddleware(rdb, logger)

	return &dpopTestEnv{
		mr:          mr,
		redisClient: rdb,
		mw:          mw,
	}
}

// buildDPoPTestRouter returns a Gin engine with a single POST /resource route
// protected by the provided handler chain (middleware + final handler).
func buildDPoPTestRouter(handlers ...gin.HandlerFunc) *gin.Engine {
	router := gin.New()
	router.POST("/resource", handlers...)
	router.GET("/resource", handlers...)
	return router
}

// -------------------------------------------------------------------------
// Key and proof generation helpers
// -------------------------------------------------------------------------

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func generateTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func rsaJWKMap(pub *rsa.PublicKey) map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWKMap(pub *ecdsa.PublicKey) map[string]interface{} {
	// Use ECDH() to extract the uncompressed point (0x04 || X || Y)
	// instead of accessing the deprecated pub.X / pub.Y fields (Go 1.26 SA1019).
	ecdhPub, err := pub.ECDH()
	if err != nil {
		panic("ecJWKMap: failed to convert EC key: " + err.Error())
	}
	raw := ecdhPub.Bytes() // 0x04 || X || Y
	coordLen := (len(raw) - 1) / 2
	xBytes := raw[1 : 1+coordLen]
	yBytes := raw[1+coordLen:]
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

// dpopProofOpts provides per-test overrides for proof generation. The zero
// value produces a valid proof bound to POST http://example.com/resource.
type dpopProofOpts struct {
	typ    string
	method string
	uri    string
	jti    string
	iat    time.Time
	// Structural knobs for negative tests
	omitTyp bool
	omitJWK bool
	omitJTI bool
	omitIAT bool
}

// makeRSAProof creates a signed DPoP proof JWT using the provided RSA key.
func makeRSAProof(t *testing.T, priv *rsa.PrivateKey, opts dpopProofOpts) string {
	t.Helper()
	return makeProof(t, priv, jwt.SigningMethodRS256, rsaJWKMap(&priv.PublicKey), opts)
}

// makeECProof creates a signed DPoP proof JWT using the provided EC key.
func makeECProof(t *testing.T, priv *ecdsa.PrivateKey, opts dpopProofOpts) string {
	t.Helper()
	return makeProof(t, priv, jwt.SigningMethodES256, ecJWKMap(&priv.PublicKey), opts)
}

func makeProof(t *testing.T, signingKey interface{}, method jwt.SigningMethod, jwk map[string]interface{}, opts dpopProofOpts) string {
	t.Helper()

	// Apply defaults.
	typVal := opts.typ
	if typVal == "" && !opts.omitTyp {
		typVal = "dpop+jwt"
	}
	htmVal := opts.method
	if htmVal == "" {
		htmVal = httpMethodPOST
	}
	htuVal := opts.uri
	if htuVal == "" {
		htuVal = "http://example.com/resource"
	}
	jtiVal := opts.jti
	if jtiVal == "" {
		jtiVal = "test-jti-" + t.Name()
	}
	iatVal := opts.iat
	if iatVal.IsZero() {
		iatVal = time.Now()
	}

	token := jwt.New(method)
	if !opts.omitTyp {
		token.Header["typ"] = typVal
	}
	if !opts.omitJWK {
		token.Header["jwk"] = jwk
	}

	claims := jwt.MapClaims{
		"htm": htmVal,
		"htu": htuVal,
	}
	if !opts.omitJTI {
		claims["jti"] = jtiVal
	}
	if !opts.omitIAT {
		claims["iat"] = iatVal.Unix()
	}
	token.Claims = claims

	signed, err := token.SignedString(signingKey)
	require.NoError(t, err, "failed to sign test DPoP proof")
	return signed
}

// newPostRequest builds a POST request to http://example.com/resource and
// optionally sets the DPoP header.
func newPostRequest(t *testing.T, proofJWT string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/resource", nil)
	req.Host = testExampleDomain
	if proofJWT != "" {
		req.Header.Set("DPoP", proofJWT)
	}
	return req
}

// newGetRequest builds a GET request to http://example.com/resource and
// optionally sets the DPoP header.
func newGetRequest(t *testing.T, proofJWT string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/resource", nil)
	req.Host = testExampleDomain
	if proofJWT != "" {
		req.Header.Set("DPoP", proofJWT)
	}
	return req
}

// -------------------------------------------------------------------------
// RequireDPoP tests
// -------------------------------------------------------------------------

// TestRequireDPoP_ValidRSAProof verifies that a correctly formed RSA-signed
// DPoP proof passes the middleware and populates context keys.
func TestRequireDPoP_ValidRSAProof(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	finalCalled := false
	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) {
			finalCalled = true
			jkt, exists := c.Get("dpop_jkt")
			assert.True(t, exists, "dpop_jkt must be set in context")
			assert.NotEmpty(t, jkt)

			jti, exists := c.Get("dpop_jti")
			assert.True(t, exists, "dpop_jti must be set in context")
			assert.Equal(t, "rsa-valid-jti", jti)

			c.Status(http.StatusOK)
		},
	)

	proof := makeRSAProof(t, priv, dpopProofOpts{jti: "rsa-valid-jti"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, finalCalled, "final handler must have been called")
}

// TestRequireDPoP_ValidECProof verifies that EC-signed (P-256) proofs are
// accepted alongside RSA proofs.
func TestRequireDPoP_ValidECProof(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestECKey(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	proof := makeECProof(t, priv, dpopProofOpts{
		method: "GET",
		uri:    "http://example.com/resource",
		jti:    "ec-valid-jti",
	})
	req := newGetRequest(t, proof)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequireDPoP_MissingHeader verifies that requests lacking the DPoP header
// are rejected with 400 Bad Request.
func TestRequireDPoP_MissingHeader(t *testing.T) {
	env := newDPoPTestEnv(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	w := httptest.NewRecorder()
	// Deliberately pass empty string so no DPoP header is set.
	router.ServeHTTP(w, newPostRequest(t, ""))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing DPoP proof header")
}

// TestRequireDPoP_InvalidProof verifies that a malformed or incorrectly signed
// DPoP proof is rejected with 401 Unauthorized.
func TestRequireDPoP_InvalidProof(t *testing.T) {
	env := newDPoPTestEnv(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	req := newPostRequest(t, "this.is.not.a.valid.jwt")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

// TestRequireDPoP_MethodMismatch verifies that a proof bound to a different
// HTTP method than the actual request is rejected.
func TestRequireDPoP_MethodMismatch(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	// Proof says GET but request is POST.
	proof := makeRSAProof(t, priv, dpopProofOpts{
		method: "GET",
		uri:    "http://example.com/resource",
		jti:    "method-mismatch-jti",
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

// TestRequireDPoP_URIMismatch verifies that a proof bound to a different URI
// than the actual request target is rejected.
func TestRequireDPoP_URIMismatch(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	// Proof is bound to /other-resource, request targets /resource.
	proof := makeRSAProof(t, priv, dpopProofOpts{
		method: httpMethodPOST,
		uri:    "http://example.com/other-resource",
		jti:    "uri-mismatch-jti",
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

// TestRequireDPoP_ExpiredProof verifies that a proof with an iat older than
// MaxProofAge is rejected.
func TestRequireDPoP_ExpiredProof(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	proof := makeRSAProof(t, priv, dpopProofOpts{
		jti: "expired-jti",
		iat: time.Now().Add(-10 * time.Minute), // well beyond MaxProofAge (5 min)
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

// TestRequireDPoP_JTIReplay verifies that presenting the same JTI twice is
// rejected on the second attempt as a replay attack.
func TestRequireDPoP_JTIReplay(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	router := buildDPoPTestRouter(env.mw.RequireDPoP(), handler)

	proof := makeRSAProof(t, priv, dpopProofOpts{jti: "replay-jti"})

	// First request: must succeed.
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, newPostRequest(t, proof))
	require.Equal(t, http.StatusOK, w1.Code, "first request must succeed")

	// Second request with same JTI: must be rejected as a replay.
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, newPostRequest(t, proof))
	assert.Equal(t, http.StatusUnauthorized, w2.Code, "replay must be rejected")
	assert.Contains(t, w2.Body.String(), "replay detected")
}

// TestRequireDPoP_DifferentJTIsAreIndependent verifies that two distinct JTIs
// can both succeed — only replays are blocked.
func TestRequireDPoP_DifferentJTIsAreIndependent(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	router := buildDPoPTestRouter(env.mw.RequireDPoP(), handler)

	proof1 := makeRSAProof(t, priv, dpopProofOpts{jti: "independent-jti-1"})
	proof2 := makeRSAProof(t, priv, dpopProofOpts{jti: "independent-jti-2"})

	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, newPostRequest(t, proof1))
	assert.Equal(t, http.StatusOK, w1.Code, "first unique JTI must succeed")

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, newPostRequest(t, proof2))
	assert.Equal(t, http.StatusOK, w2.Code, "second unique JTI must also succeed")
}

// TestRequireDPoP_MissingTypHeader verifies that a JWT without typ=dpop+jwt
// is rejected.
func TestRequireDPoP_MissingTypHeader(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	proof := makeRSAProof(t, priv, dpopProofOpts{
		omitTyp: true,
		jti:     "no-typ-jti",
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRequireDPoP_MissingJWKHeader verifies that a JWT without the jwk JOSE
// header is rejected.
func TestRequireDPoP_MissingJWKHeader(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	router := buildDPoPTestRouter(
		env.mw.RequireDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	proof := makeRSAProof(t, priv, dpopProofOpts{
		omitJWK: true,
		jti:     "no-jwk-jti",
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// -------------------------------------------------------------------------
// OptionalDPoP tests
// -------------------------------------------------------------------------

// TestOptionalDPoP_NoDPoPHeader verifies that requests without a DPoP header
// pass through the optional middleware without any error or context keys.
func TestOptionalDPoP_NoDPoPHeader(t *testing.T) {
	env := newDPoPTestEnv(t)

	finalCalled := false
	router := buildDPoPTestRouter(
		env.mw.OptionalDPoP(),
		func(c *gin.Context) {
			finalCalled = true
			_, jktExists := c.Get("dpop_jkt")
			assert.False(t, jktExists, "dpop_jkt must not be set when header is absent")
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, ""))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, finalCalled)
}

// TestOptionalDPoP_ValidProofSetsContext verifies that a valid DPoP proof in
// optional mode is accepted and sets context keys.
func TestOptionalDPoP_ValidProofSetsContext(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	finalCalled := false
	router := buildDPoPTestRouter(
		env.mw.OptionalDPoP(),
		func(c *gin.Context) {
			finalCalled = true
			jkt, exists := c.Get("dpop_jkt")
			assert.True(t, exists, "dpop_jkt must be set for valid optional proof")
			assert.NotEmpty(t, jkt)
			c.Status(http.StatusOK)
		},
	)

	proof := makeRSAProof(t, priv, dpopProofOpts{jti: "optional-valid-jti"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, newPostRequest(t, proof))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, finalCalled)
}

// TestOptionalDPoP_InvalidProofIsRejected verifies that an invalid DPoP proof
// in optional mode still results in a 401 — partial proofs are not allowed.
func TestOptionalDPoP_InvalidProofIsRejected(t *testing.T) {
	env := newDPoPTestEnv(t)

	router := buildDPoPTestRouter(
		env.mw.OptionalDPoP(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	req := newPostRequest(t, "invalid.jwt.token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

// TestOptionalDPoP_ReplayInOptionalMode verifies that JTI replay is also
// detected in optional mode.
func TestOptionalDPoP_ReplayInOptionalMode(t *testing.T) {
	env := newDPoPTestEnv(t)
	priv := generateTestRSAKey(t)

	handler := func(c *gin.Context) { c.Status(http.StatusOK) }
	router := buildDPoPTestRouter(env.mw.OptionalDPoP(), handler)

	proof := makeRSAProof(t, priv, dpopProofOpts{jti: "optional-replay-jti"})

	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, newPostRequest(t, proof))
	require.Equal(t, http.StatusOK, w1.Code)

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, newPostRequest(t, proof))
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
	assert.Contains(t, w2.Body.String(), "replay detected")
}

// -------------------------------------------------------------------------
// VerifyTokenBinding tests
// -------------------------------------------------------------------------

// TestVerifyTokenBinding_MatchingKeys verifies that matching dpop_jkt and
// token_cnf_jkt context values pass the binding check.
func TestVerifyTokenBinding_MatchingKeys(t *testing.T) {
	finalCalled := false
	router := buildDPoPTestRouter(
		func(c *gin.Context) {
			c.Set("dpop_jkt", "thumbprint-abc123")
			c.Set("token_cnf_jkt", "thumbprint-abc123")
			c.Next()
		},
		VerifyTokenBinding,
		func(c *gin.Context) {
			finalCalled = true
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/resource", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, finalCalled, "final handler must be reached on matching JKTs")
}

// TestVerifyTokenBinding_MismatchedKeys verifies that mismatched dpop_jkt and
// token_cnf_jkt context values cause a 401 Unauthorized.
func TestVerifyTokenBinding_MismatchedKeys(t *testing.T) {
	router := buildDPoPTestRouter(
		func(c *gin.Context) {
			c.Set("dpop_jkt", "proof-key-thumbprint")
			c.Set("token_cnf_jkt", "different-key-thumbprint")
			c.Next()
		},
		VerifyTokenBinding,
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/resource", nil))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "binding mismatch")
}

// TestVerifyTokenBinding_TokenBoundButNoProof verifies the tier-1 security
// semantic required by RFC 9449 §7.1: when the access token carries a
// cnf.jkt claim (it was issued as DPoP-bound) but NO proof header is
// present, the request MUST be rejected. Allowing this case through —
// which an earlier placeholder implementation did — would defeat the
// entire purpose of DPoP: an attacker with a stolen token could present
// it without a proof and be treated as the legitimate holder.
func TestVerifyTokenBinding_TokenBoundButNoProof(t *testing.T) {
	finalCalled := false
	router := buildDPoPTestRouter(
		func(c *gin.Context) {
			// token_cnf_jkt is present (token is DPoP-bound) but dpop_jkt
			// is absent (no proof was submitted with the request).
			c.Set("token_cnf_jkt", "some-token-jkt")
			c.Next()
		},
		VerifyTokenBinding,
		func(c *gin.Context) {
			finalCalled = true
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/resource", nil))

	assert.Equal(t, http.StatusUnauthorized, w.Code, "DPoP-bound token without a proof must be rejected")
	assert.False(t, finalCalled, "downstream handler must not run when binding enforcement aborts")
}

// TestVerifyTokenBinding_NoTokenCNFJKT verifies that when the access token
// has no cnf.jkt (it was not DPoP-bound at issuance), the binding check is
// a no-op even if a DPoP proof was supplied.
func TestVerifyTokenBinding_NoTokenCNFJKT(t *testing.T) {
	finalCalled := false
	router := buildDPoPTestRouter(
		func(c *gin.Context) {
			c.Set("dpop_jkt", "proof-jkt")
			// token_cnf_jkt intentionally absent — token not bound.
			c.Next()
		},
		VerifyTokenBinding,
		func(c *gin.Context) {
			finalCalled = true
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/resource", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, finalCalled, "binding check must be skipped when token_cnf_jkt is absent")
}

// -------------------------------------------------------------------------
// buildRequestURI tests
// -------------------------------------------------------------------------

// TestBuildRequestURI_HTTPSFromTLS verifies that requests arriving over a TLS
// connection produce an https URI. We simulate TLS by setting r.TLS to a
// non-nil *tls.ConnectionState.
func TestBuildRequestURI_HTTPSFromTLS(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/token", nil)
	req.Host = "auth.hexxlock.com"
	// Setting TLS to any non-nil value signals an active TLS connection.
	req.TLS = &cryptotls.ConnectionState{}

	uri := buildRequestURI(req)
	assert.Equal(t, "https://auth.hexxlock.com/api/v1/token", uri)
}

// TestBuildRequestURI_HTTPSFromForwardedProto verifies that X-Forwarded-Proto
// is respected when TLS is not active on the TCP connection (reverse proxy).
func TestBuildRequestURI_HTTPSFromForwardedProto(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/login", nil)
	req.Host = "auth.hexxlock.com"
	req.Header.Set("X-Forwarded-Proto", "https")

	uri := buildRequestURI(req)
	assert.Equal(t, "https://auth.hexxlock.com/api/v1/auth/login", uri)
}

// TestBuildRequestURI_PlainHTTP verifies that a plain HTTP request without any
// TLS or forwarded proto header produces an http URI.
func TestBuildRequestURI_PlainHTTP(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	req.Host = "localhost:8080"

	uri := buildRequestURI(req)
	assert.Equal(t, "http://localhost:8080/health", uri)
}

// TestBuildRequestURI_QueryStringStripped verifies that the query string is
// NOT included in the URI, per RFC 9449 §4.2.
func TestBuildRequestURI_QueryStringStripped(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/resource?foo=bar&baz=qux", nil)
	req.Host = testExampleDomain

	uri := buildRequestURI(req)
	assert.Equal(t, "http://example.com/resource", uri,
		"query string must be excluded from the DPoP htu URI")
	assert.NotContains(t, uri, "?", "URI must not contain query string")
}

// TestBuildRequestURI_XForwardedProtoNormalized verifies that mixed-case
// X-Forwarded-Proto values are normalized to lowercase.
func TestBuildRequestURI_XForwardedProtoNormalized(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/resource", nil)
	req.Host = testExampleDomain
	req.Header.Set("X-Forwarded-Proto", "HTTPS")

	uri := buildRequestURI(req)
	assert.True(t, len(uri) > 0)
	assert.Contains(t, uri, "https://", "protocol must be lowercased")
}

// -------------------------------------------------------------------------
// checkAndStoreJTI unit tests
// -------------------------------------------------------------------------

// TestCheckAndStoreJTI_FirstCallSucceeds verifies that the first call with a
// new JTI succeeds.
func TestCheckAndStoreJTI_FirstCallSucceeds(t *testing.T) {
	env := newDPoPTestEnv(t)

	err := env.mw.checkAndStoreJTI(t.Context(), "brand-new-jti")
	require.NoError(t, err)
}

// TestCheckAndStoreJTI_SecondCallFails verifies that calling with the same JTI
// twice returns an error on the second call.
func TestCheckAndStoreJTI_SecondCallFails(t *testing.T) {
	env := newDPoPTestEnv(t)
	ctx := t.Context()

	require.NoError(t, env.mw.checkAndStoreJTI(ctx, "duplicate-jti"))

	err := env.mw.checkAndStoreJTI(ctx, "duplicate-jti")
	require.Error(t, err, "second call with same JTI must return an error")
	assert.Contains(t, err.Error(), "already seen")
}

// TestCheckAndStoreJTI_TTLExpiry verifies that after the Redis TTL expires
// (fast-forwarded via miniredis), the same JTI can be used again.
func TestCheckAndStoreJTI_TTLExpiry(t *testing.T) {
	env := newDPoPTestEnv(t)
	ctx := t.Context()

	require.NoError(t, env.mw.checkAndStoreJTI(ctx, "expiring-jti"))

	// Fast-forward miniredis clock past the JTI TTL.
	env.mr.FastForward(6 * time.Minute)

	// After expiry the same JTI should be accepted again.
	err := env.mw.checkAndStoreJTI(ctx, "expiring-jti")
	assert.NoError(t, err, "JTI must be reusable after Redis TTL expires")
}

// TestCheckAndStoreJTI_DifferentJTIsAreIndependent verifies that storing
// multiple distinct JTIs does not cause cross-contamination.
func TestCheckAndStoreJTI_DifferentJTIsAreIndependent(t *testing.T) {
	env := newDPoPTestEnv(t)
	ctx := t.Context()

	for i := 0; i < 5; i++ {
		jti := "unique-jti-" + string(rune('a'+i))
		err := env.mw.checkAndStoreJTI(ctx, jti)
		assert.NoError(t, err, "each unique JTI must succeed on first use")
	}
}

// TestCheckAndStoreJTI_RedisUnavailable verifies that a Redis error is
// propagated as a non-nil error rather than silently allowing the request.
// A dedicated low-timeout client is used so the test fails fast.
func TestCheckAndStoreJTI_RedisUnavailable(t *testing.T) {
	// Use a port that has nothing listening on it — connection will be refused
	// immediately without needing to shut down miniredis.
	rdb := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1", // port 1 is always unreachable
		DialTimeout: 50 * time.Millisecond,
		MaxRetries:  0, // fail immediately, no retries
	})
	t.Cleanup(func() { _ = rdb.Close() })

	mw := NewDPoPMiddleware(rdb, zap.NewNop())
	err := mw.checkAndStoreJTI(t.Context(), "any-jti")
	require.Error(t, err, "Redis unavailability must be reported as an error")
	assert.Contains(t, err.Error(), "DPoP JTI cache error")
}
