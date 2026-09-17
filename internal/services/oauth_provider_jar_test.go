// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the RFC 9101 JWT-Secured Authorization Request
// (JAR) helper. The handler-side tests live alongside the Authorize
// handler; this file isolates the JWS verification + JWKS lookup
// logic.

func generateRSATestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, jwksJSONForKey(t, priv, "test-kid-1")
}

func jwksJSONForKey(t *testing.T, priv *rsa.PrivateKey, kid string) string {
	t.Helper()
	pub := priv.PublicKey
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	keyset := map[string]interface{}{"keys": []interface{}{jwk}}
	b, err := json.Marshal(keyset)
	require.NoError(t, err)
	return string(b)
}

func signJARRequestObject(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

func TestVerifyJARRequestObject_HappyPath(t *testing.T) {
	priv, jwks := generateRSATestKey(t)

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"iss":           "test-client",
		"aud":           "https://falcon-id",
		"client_id":     "test-client",
		"response_type": "code",
		"redirect_uri":  "https://app.example/cb",
		"scope":         "openid profile",
		"state":         "abc",
		"iat":           now,
		"exp":           now + 300,
	}
	jws := signJARRequestObject(t, priv, claims, "test-kid-1")

	out, err := VerifyJARRequestObject(jws, jwks, "RS256")
	require.NoError(t, err)
	assert.Equal(t, "test-client", out["client_id"])
	assert.Equal(t, "code", out["response_type"])
	assert.Equal(t, "openid profile", out["scope"])
}

func TestVerifyJARRequestObject_RejectsExpired(t *testing.T) {
	priv, jwks := generateRSATestKey(t)

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"iss":           "test-client",
		"response_type": "code",
		"iat":           now - 600,
		"exp":           now - 300, // expired
	}
	jws := signJARRequestObject(t, priv, claims, "test-kid-1")

	_, err := VerifyJARRequestObject(jws, jwks, "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifyJARRequestObject_RejectsMissingExp(t *testing.T) {
	priv, jwks := generateRSATestKey(t)

	claims := jwt.MapClaims{
		"iss":           "test-client",
		"response_type": "code",
	}
	jws := signJARRequestObject(t, priv, claims, "test-kid-1")

	_, err := VerifyJARRequestObject(jws, jwks, "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp")
}

func TestVerifyJARRequestObject_RejectsExpTooFarInFuture(t *testing.T) {
	priv, jwks := generateRSATestKey(t)

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"response_type": "code",
		"exp":           now + 7200, // 2h > 1h cap
	}
	jws := signJARRequestObject(t, priv, claims, "test-kid-1")

	_, err := VerifyJARRequestObject(jws, jwks, "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1h TTL")
}

func TestVerifyJARRequestObject_RejectsWrongKey(t *testing.T) {
	// Sign with one key, present a different JWKS for verification.
	priv1, _ := generateRSATestKey(t)
	_, jwks2 := generateRSATestKey(t)

	now := time.Now().Unix()
	claims := jwt.MapClaims{"response_type": "code", "exp": now + 300}
	jws := signJARRequestObject(t, priv1, claims, "test-kid-1")

	_, err := VerifyJARRequestObject(jws, jwks2, "RS256")
	require.Error(t, err)
}

func TestVerifyJARRequestObject_RejectsUnsupportedAlg(t *testing.T) {
	_, err := VerifyJARRequestObject("doesnt.matter.here", `{"keys":[]}`, "HS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RS256/RS384/RS512")
}

func TestVerifyJARRequestObject_RejectsEmptyJWKS(t *testing.T) {
	priv, _ := generateRSATestKey(t)
	now := time.Now().Unix()
	jws := signJARRequestObject(t, priv, jwt.MapClaims{"exp": now + 300}, "")

	_, err := VerifyJARRequestObject(jws, `{"keys":[]}`, "RS256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwks is empty")
}

func TestVerifyJARRequestObject_AlgConfusionRejected(t *testing.T) {
	// Build a JWS signed with HS256 (symmetric), present an RSA JWKS,
	// require RS256. This is the classic alg-confusion attack —
	// jwt.WithValidMethods on the parser blocks it, but we test it
	// anyway as a regression pin.
	pub := []byte("dummy-symmetric-key")
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"response_type": "code",
		"exp":           now + 300,
	})
	jws, err := tok.SignedString(pub)
	require.NoError(t, err)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509Marshal(priv),
	})
	_ = pubPEM

	_, jwks := generateRSATestKey(t)
	_, err = VerifyJARRequestObject(jws, jwks, "RS256")
	require.Error(t, err)
}

func x509Marshal(priv *rsa.PrivateKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return b
}
