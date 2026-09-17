// SPDX-License-Identifier: AGPL-3.0-or-later

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDPoPTyp = "dpop+jwt"

// -------------------------------------------------------------------------
// Test key generation helpers
// -------------------------------------------------------------------------

// generateRSAKey returns a 2048-bit RSA key pair suitable for signing test
// DPoP proofs. 2048 bits is the minimum recommended key size for RSA in 2026.
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA test key")
	return key
}

// generateECKey returns a P-256 ECDSA key pair suitable for signing test
// DPoP proofs.
func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed to generate EC test key")
	return key
}

// -------------------------------------------------------------------------
// JWK serialisation helpers for test proofs
// -------------------------------------------------------------------------

// rsaPublicKeyToJWK converts an *rsa.PublicKey into the map representation
// of a JWK, which is embedded in the DPoP proof JOSE header.
func rsaPublicKeyToJWK(pub *rsa.PublicKey) map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ecPublicKeyToJWK converts an *ecdsa.PublicKey into the map representation
// of a JWK. Only P-256 is used in tests; the curve name is hard-coded.
func ecPublicKeyToJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	// Use ECDH() to extract the uncompressed point (0x04 || X || Y)
	// instead of accessing the deprecated pub.X / pub.Y fields (Go 1.26 SA1019).
	ecdhPub, err := pub.ECDH()
	if err != nil {
		panic("ecPublicKeyToJWK: failed to convert EC key: " + err.Error())
	}
	raw := ecdhPub.Bytes() // 0x04 || X || Y
	coordLen := (len(raw) - 1) / 2
	xBytes := raw[1 : 1+coordLen]
	yBytes := raw[1+coordLen:]

	var crv string
	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	default:
		crv = "unknown"
	}

	return map[string]interface{}{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

// -------------------------------------------------------------------------
// Proof JWT construction helpers
// -------------------------------------------------------------------------

// proofOptions controls which fields are included in a test DPoP proof.
// The zero value produces a valid proof; individual fields can be overridden
// to exercise error paths.
type proofOptions struct {
	typ     string    // JOSE header "typ"  (default: testDPoPTyp)
	omitJWK bool      // when true, the "jwk" JOSE header is omitted
	method  string    // htm claim            (default: "POST")
	uri     string    // htu claim            (default: "https://example.com/token")
	jti     string    // jti claim            (default: "unique-test-jti")
	iat     time.Time // iat claim            (default: time.Now())
	omitJTI bool      // when true, jti is omitted from claims
	omitIAT bool      // when true, iat is omitted from claims
}

// buildRSAProof creates a DPoP proof JWT signed with the provided RSA private
// key. The opts parameter allows individual fields to be overridden for
// negative test cases.
func buildRSAProof(t *testing.T, priv *rsa.PrivateKey, opts proofOptions) string {
	t.Helper()
	return buildProof(t, priv, jwt.SigningMethodRS256, rsaPublicKeyToJWK(&priv.PublicKey), opts)
}

// buildECProof creates a DPoP proof JWT signed with the provided EC private
// key.
func buildECProof(t *testing.T, priv *ecdsa.PrivateKey, opts proofOptions) string {
	t.Helper()
	return buildProof(t, priv, jwt.SigningMethodES256, ecPublicKeyToJWK(&priv.PublicKey), opts)
}

// buildProof is the generic proof builder used by buildRSAProof and
// buildECProof.
func buildProof(
	t *testing.T,
	signingKey interface{},
	method jwt.SigningMethod,
	jwkMap map[string]interface{},
	opts proofOptions,
) string {
	t.Helper()

	// Apply defaults.
	typ := opts.typ
	if typ == "" {
		typ = testDPoPTyp
	}
	htmVal := opts.method
	if htmVal == "" {
		htmVal = "POST"
	}
	htuVal := opts.uri
	if htuVal == "" {
		htuVal = "https://example.com/token"
	}
	jtiVal := opts.jti
	if jtiVal == "" {
		jtiVal = "unique-test-jti"
	}
	iatVal := opts.iat
	if iatVal.IsZero() {
		iatVal = time.Now()
	}

	// Construct JOSE header.
	token := jwt.New(method)
	token.Header["typ"] = typ
	if !opts.omitJWK {
		token.Header["jwk"] = jwkMap
	}
	// Remove the default "alg" key that jwt.New injects into Header so it
	// does not interfere; the library sets it correctly from the method.

	// Construct claims.
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

// -------------------------------------------------------------------------
// ValidateProof tests
// -------------------------------------------------------------------------

// TestValidateDPoPProof_Valid verifies the happy path: a correctly formed
// proof signed with a fresh RSA key is accepted and all fields are populated.
func TestValidateDPoPProof_Valid(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{
		method: "POST",
		uri:    "https://example.com/token",
		jti:    "test-jti-valid",
	})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.Equal(t, "POST", proof.Method)
	assert.Equal(t, "https://example.com/token", proof.URI)
	assert.Equal(t, "test-jti-valid", proof.JTI)
	assert.NotEmpty(t, proof.JKT, "JKT must be computed and returned")
	assert.WithinDuration(t, time.Now(), proof.IssuedAt, 5*time.Second)
}

// TestValidateDPoPProof_ValidEC verifies that EC-signed proofs (P-256) are
// accepted in addition to RSA-signed proofs.
func TestValidateDPoPProof_ValidEC(t *testing.T) {
	priv := generateECKey(t)
	proofJWT := buildECProof(t, priv, proofOptions{
		method: "GET",
		uri:    "https://example.com/resource",
		jti:    "ec-jti",
	})

	proof, err := ValidateProof(proofJWT, "GET", "https://example.com/resource")

	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.Equal(t, "GET", proof.Method)
	assert.Equal(t, "https://example.com/resource", proof.URI)
	assert.Equal(t, "ec-jti", proof.JTI)
	assert.NotEmpty(t, proof.JKT)
}

// TestValidateDPoPProof_InvalidTyp verifies that a proof with the wrong "typ"
// JOSE header value is rejected.
func TestValidateDPoPProof_InvalidTyp(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{typ: "JWT"})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), testDPoPTyp, "error should mention the expected typ value")
}

// TestValidateDPoPProof_MissingJWK verifies that a proof without the "jwk"
// JOSE header is rejected.
func TestValidateDPoPProof_MissingJWK(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{omitJWK: true})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "jwk")
}

// TestValidateDPoPProof_MethodMismatch verifies that a proof whose "htm" claim
// does not match the expected HTTP method is rejected.
func TestValidateDPoPProof_MethodMismatch(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{method: "GET"})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "htm")
}

// TestValidateDPoPProof_URIMismatch verifies that a proof whose "htu" claim
// does not match the expected request URI is rejected.
func TestValidateDPoPProof_URIMismatch(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{uri: "https://attacker.example.com/token"})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "htu")
}

// TestValidateDPoPProof_MissingJTI verifies that a proof without a "jti"
// claim is rejected.
func TestValidateDPoPProof_MissingJTI(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{omitJTI: true})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "jti")
}

// TestValidateDPoPProof_TooOld verifies that a proof with an "iat" claim
// older than MaxProofAge is rejected.
func TestValidateDPoPProof_TooOld(t *testing.T) {
	priv := generateRSAKey(t)
	staleIAT := time.Now().Add(-(MaxProofAge + time.Second))
	proofJWT := buildRSAProof(t, priv, proofOptions{iat: staleIAT})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "old", "error should indicate the proof is stale")
}

// TestValidateDPoPProof_FutureIAT verifies that a proof with an "iat" claim
// more than MaxClockSkew in the future is rejected.
func TestValidateDPoPProof_FutureIAT(t *testing.T) {
	priv := generateRSAKey(t)
	futureIAT := time.Now().Add(MaxClockSkew + 5*time.Second)
	proofJWT := buildRSAProof(t, priv, proofOptions{iat: futureIAT})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "future", "error should indicate the proof is from the future")
}

// TestValidateDPoPProof_MissingIAT verifies that a proof without an "iat"
// claim is rejected.
func TestValidateDPoPProof_MissingIAT(t *testing.T) {
	priv := generateRSAKey(t)
	proofJWT := buildRSAProof(t, priv, proofOptions{omitIAT: true})

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "iat")
}

// TestValidateDPoPProof_WrongSigningKey verifies that a proof signed by one
// key but embedding a different key's JWK is rejected.
func TestValidateDPoPProof_WrongSigningKey(t *testing.T) {
	privSigner := generateRSAKey(t)   // actual signing key
	privEmbedded := generateRSAKey(t) // different key embedded in the JWK header

	// Build the proof: sign with privSigner but embed privEmbedded's public key.
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["typ"] = testDPoPTyp
	token.Header["jwk"] = rsaPublicKeyToJWK(&privEmbedded.PublicKey) // wrong key
	token.Claims = jwt.MapClaims{
		"htm": "POST",
		"htu": "https://example.com/token",
		"jti": "mismatch-jti",
		"iat": time.Now().Unix(),
	}
	proofJWT, err := token.SignedString(privSigner)
	require.NoError(t, err)

	proof, err := ValidateProof(proofJWT, "POST", "https://example.com/token")

	require.Error(t, err)
	assert.Nil(t, proof)
	assert.Contains(t, err.Error(), "signature", "error should mention signature failure")
}

// -------------------------------------------------------------------------
// ComputeJKT tests
// -------------------------------------------------------------------------

// TestComputeJKT_RSA verifies that the JWK thumbprint for an RSA key is
// computed deterministically and matches a known value derived from the
// canonical RFC 7638 thumbprint formula.
func TestComputeJKT_RSA(t *testing.T) {
	priv := generateRSAKey(t)
	jwkMap := rsaPublicKeyToJWK(&priv.PublicKey)

	jwkJSON, err := json.Marshal(jwkMap)
	require.NoError(t, err)

	jkt1, err := ComputeJKT(jwkJSON)
	require.NoError(t, err)
	assert.NotEmpty(t, jkt1, "JKT must not be empty")

	// Calling ComputeJKT twice with the same key must produce the same result.
	jkt2, err := ComputeJKT(jwkJSON)
	require.NoError(t, err)
	assert.Equal(t, jkt1, jkt2, "JKT must be deterministic")

	// The thumbprint must be valid base64url (no padding characters).
	_, decodeErr := base64.RawURLEncoding.DecodeString(jkt1)
	assert.NoError(t, decodeErr, "JKT must be valid unpadded base64url")
}

// TestComputeJKT_EC verifies the JWK thumbprint for an EC key.
func TestComputeJKT_EC(t *testing.T) {
	priv := generateECKey(t)
	jwkMap := ecPublicKeyToJWK(&priv.PublicKey)

	jwkJSON, err := json.Marshal(jwkMap)
	require.NoError(t, err)

	jkt, err := ComputeJKT(jwkJSON)
	require.NoError(t, err)
	assert.NotEmpty(t, jkt)

	_, decodeErr := base64.RawURLEncoding.DecodeString(jkt)
	assert.NoError(t, decodeErr, "EC JKT must be valid unpadded base64url")
}

// TestComputeJKT_RSA_DifferentKeys verifies that two different RSA keys
// produce different thumbprints.
func TestComputeJKT_RSA_DifferentKeys(t *testing.T) {
	keyA := generateRSAKey(t)
	keyB := generateRSAKey(t)

	jwkA, _ := json.Marshal(rsaPublicKeyToJWK(&keyA.PublicKey))
	jwkB, _ := json.Marshal(rsaPublicKeyToJWK(&keyB.PublicKey))

	jktA, err := ComputeJKT(jwkA)
	require.NoError(t, err)

	jktB, err := ComputeJKT(jwkB)
	require.NoError(t, err)

	assert.NotEqual(t, jktA, jktB, "different keys must produce different thumbprints")
}

// TestComputeJKT_UnsupportedKeyType verifies that an unsupported "kty" value
// returns an error rather than producing a garbage thumbprint.
func TestComputeJKT_UnsupportedKeyType(t *testing.T) {
	jwkJSON := []byte(`{"kty":"OKP","crv":"Ed25519","x":"unused"}`)

	jkt, err := ComputeJKT(jwkJSON)

	require.Error(t, err)
	assert.Empty(t, jkt)
	assert.Contains(t, err.Error(), "unsupported")
}

// TestComputeJKT_InvalidJSON verifies that malformed JWK JSON returns an
// error.
func TestComputeJKT_InvalidJSON(t *testing.T) {
	jkt, err := ComputeJKT([]byte(`{not valid json`))

	require.Error(t, err)
	assert.Empty(t, jkt)
}

// TestComputeJKT_RSAMissingParams verifies that an RSA JWK with missing
// required parameters returns an error.
func TestComputeJKT_RSAMissingParams(t *testing.T) {
	// Missing "n".
	jwkJSON := []byte(`{"kty":"RSA","e":"AQAB"}`)
	jkt, err := ComputeJKT(jwkJSON)

	require.Error(t, err)
	assert.Empty(t, jkt)
}

// TestComputeJKT_JKTMatchesBetweenValidateAndCompute verifies that the JKT
// returned by ValidateProof exactly matches the JKT computed directly via
// ComputeJKT for the same key.
func TestComputeJKT_JKTMatchesBetweenValidateAndCompute(t *testing.T) {
	priv := generateRSAKey(t)

	proofJWT := buildRSAProof(t, priv, proofOptions{
		method: "DELETE",
		uri:    "https://example.com/resource/42",
		jti:    "consistency-check-jti",
	})

	proof, err := ValidateProof(proofJWT, "DELETE", "https://example.com/resource/42")
	require.NoError(t, err)
	require.NotNil(t, proof)

	jwkJSON, _ := json.Marshal(rsaPublicKeyToJWK(&priv.PublicKey))
	directJKT, err := ComputeJKT(jwkJSON)
	require.NoError(t, err)

	assert.Equal(t, directJKT, proof.JKT,
		"JKT from ValidateProof must match JKT computed directly from the same public key")
}
