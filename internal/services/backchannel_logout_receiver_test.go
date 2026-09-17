// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// genTestRSAKey generates a fresh RSA-2048 keypair for tests. Slow
// (~50ms per call) but only fires per t.Run.
func genTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv
}

// rsaPubToJWK converts an *rsa.PublicKey into a JWK dict the test
// JWKS endpoint can serve.
func rsaPubToJWK(t *testing.T, kid string, pub *rsa.PublicKey) map[string]interface{} {
	t.Helper()
	nBytes := pub.N.Bytes()
	eBytes := []byte{
		byte(pub.E >> 16),
		byte(pub.E >> 8),
		byte(pub.E),
	}
	// Strip leading zeros from the E bytes (canonical JWK form).
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	return map[string]interface{}{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

// startTestIDP runs an httptest.Server that serves the discovery doc
// + JWKS for the given keypair. Returns issuer URL the test should
// use as TrustedIssuer.
func startTestIDP(t *testing.T, kid string, priv *rsa.PrivateKey) (issuer string, cleanup func()) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{rsaPubToJWK(t, kid, &priv.PublicKey)},
		})
	})
	return srv.URL, srv.Close
}

// signLogoutToken builds a logout_token JWT signed by the test IdP's
// keypair. Caller can override claims for negative tests.
func signLogoutToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

func defaultLogoutClaims(issuer, aud, sub string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": issuer,
		"aud": aud,
		"sub": sub,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"jti": "test-jti-" + sub,
		"events": map[string]interface{}{
			bclEventBackchannelLogout: map[string]interface{}{},
		},
	}
}

// TestReceiveJWKSVerify_HappyPath drives the full pipeline:
// httptest IdP serves discovery + JWKS; test signs a logout_token;
// Receive verifies and returns sub.
func TestReceiveJWKSVerify_HappyPath(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "test-kid-1", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{issuer},
		Audience:       "falcon-id-as-rp",
		MaxSkew:        60 * time.Second,
		JWKSCacheTTL:   1 * time.Hour,
	})

	token := signLogoutToken(t, priv, "test-kid-1", defaultLogoutClaims(issuer, "falcon-id-as-rp", "user-123"))
	sub, err := s.Receive(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", sub)
}

// TestReceiveJWKSVerify_UntrustedIssuer rejects tokens whose iss isn't
// in the TrustedIssuers allow-list, even if the signature is otherwise
// valid against THAT issuer's JWKS.
func TestReceiveJWKSVerify_UntrustedIssuer(t *testing.T) {
	priv := genTestRSAKey(t)
	rogueIssuer, cleanup := startTestIDP(t, "rogue-kid", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{"https://only-trusted.example.com"},
		Audience:       "falcon-id-as-rp",
	})

	token := signLogoutToken(t, priv, "rogue-kid",
		defaultLogoutClaims(rogueIssuer, "falcon-id-as-rp", "user-attacker"))
	_, err := s.Receive(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted issuer")
}

// TestReceiveJWKSVerify_AudMismatch rejects when the aud claim doesn't
// match the configured Audience — defense against an attacker
// replaying a token issued for a different RP.
func TestReceiveJWKSVerify_AudMismatch(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "kid-1", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{issuer},
		Audience:       "expected-aud",
	})

	claims := defaultLogoutClaims(issuer, "wrong-aud", "user-1")
	token := signLogoutToken(t, priv, "kid-1", claims)
	_, err := s.Receive(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud mismatch")
}

// TestReceiveJWKSVerify_NonceForbidden rejects per spec §2.4.
func TestReceiveJWKSVerify_NonceForbidden(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "kid-1", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{issuer},
		Audience:       "aud",
	})

	claims := defaultLogoutClaims(issuer, "aud", "user-1")
	claims["nonce"] = "should-not-be-here"
	token := signLogoutToken(t, priv, "kid-1", claims)
	_, err := s.Receive(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

// TestReceiveJWKSVerify_MissingEvents rejects when the spec-§2.4
// events claim is absent — defense against id_token / access_token
// replay disguised as logout_token.
func TestReceiveJWKSVerify_MissingEvents(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "kid-1", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{issuer},
		Audience:       "aud",
	})

	claims := defaultLogoutClaims(issuer, "aud", "user-1")
	delete(claims, "events")
	token := signLogoutToken(t, priv, "kid-1", claims)
	_, err := s.Receive(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "events")
}

// TestReceiveJWKSVerify_NoSubOrSid rejects when both sub and sid are
// absent — at least one is required by spec §2.4.
func TestReceiveJWKSVerify_NoSubOrSid(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "kid-1", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{issuer},
		Audience:       "aud",
	})

	claims := defaultLogoutClaims(issuer, "aud", "user-1")
	delete(claims, "sub")
	// no sid either
	token := signLogoutToken(t, priv, "kid-1", claims)
	_, err := s.Receive(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sub or sid")
}

// TestReceiveJWKSVerify_StaleIat rejects iat > skew window in the
// past. Defense against bound-token replay after the OP-side outbox
// has TTL'd it.
func TestReceiveJWKSVerify_StaleIat(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "kid-1", priv)
	defer cleanup()

	s := NewBackchannelLogoutService(nil, nil, BackchannelLogoutConfig{}, zap.NewNop())
	s.SetReceiverConfig(BackchannelLogoutReceiverConfig{
		TrustedIssuers: []string{issuer},
		Audience:       "aud",
		MaxSkew:        60 * time.Second,
	})

	claims := defaultLogoutClaims(issuer, "aud", "user-1")
	claims["iat"] = time.Now().Add(-10 * time.Minute).Unix() // way past skew
	claims["exp"] = time.Now().Add(2 * time.Minute).Unix()   // exp still valid
	token := signLogoutToken(t, priv, "kid-1", claims)
	_, err := s.Receive(t.Context(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat outside skew")
}

// TestClaimsAudContains exercises the both-shapes audience matcher
// (string vs []interface{}) since spec allows either.
func TestClaimsAudContains(t *testing.T) {
	cases := []struct {
		name   string
		claims jwt.MapClaims
		want   string
		ok     bool
	}{
		{"string-match", jwt.MapClaims{"aud": "talon"}, "talon", true},
		{"string-mismatch", jwt.MapClaims{"aud": "other"}, "talon", false},
		{"slice-contains", jwt.MapClaims{"aud": []interface{}{"a", "talon", "b"}}, "talon", true},
		{"slice-no-match", jwt.MapClaims{"aud": []interface{}{"x", "y"}}, "talon", false},
		{"missing-aud", jwt.MapClaims{}, "talon", false},
		{"non-string-element-skipped", jwt.MapClaims{"aud": []interface{}{42, "talon"}}, "talon", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.ok, claimsAudContains(tc.claims, tc.want))
		})
	}
}

// TestReceiverJWKSCache_FetchAndDecode exercises the JWKS fetch +
// JWK→RSA decode by hitting the test IdP and asserting the returned
// key matches the test private key's public part.
func TestReceiverJWKSCache_FetchAndDecode(t *testing.T) {
	priv := genTestRSAKey(t)
	issuer, cleanup := startTestIDP(t, "kid-1", priv)
	defer cleanup()

	cache := newReceiverJWKSCache(1 * time.Hour)
	got, err := cache.Get(t.Context(), issuer, "kid-1")
	require.NoError(t, err)

	// Compare via SubjectPublicKeyInfo bytes — equality on *rsa.PublicKey
	// pointers wouldn't work; we get a fresh struct from the JWKS decode.
	wantSPKI, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	gotSPKI, _ := x509.MarshalPKIXPublicKey(got)
	assert.Equal(t, wantSPKI, gotSPKI)
}
