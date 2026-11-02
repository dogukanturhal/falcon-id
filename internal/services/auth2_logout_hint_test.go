// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAuth2LogoutHint_VerifiesSignatureIssuerAndAllowsExpiredIDToken(t *testing.T) {
	t.Setenv("OAUTH_ISSUER", "https://id.example.test")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s := &OAuthProviderService{publicKey: &key.PublicKey}
	for _, tc := range []struct {
		name, issuer string
		method       jwt.SigningMethod
		valid        bool
	}{
		{"expired valid ID token", "https://id.example.test", jwt.SigningMethodRS256, true},
		{"wrong issuer", "https://evil.example.test", jwt.SigningMethodRS256, false},
		{"algorithm confusion", "https://id.example.test", jwt.SigningMethodHS256, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": tc.issuer, "sub": uuid.NewString(), "aud": "acmeapp-bff", "exp": time.Now().Add(-time.Hour).Unix()}
			token := jwt.NewWithClaims(tc.method, claims)
			var signingKey any = key
			if tc.method == jwt.SigningMethodHS256 {
				signingKey = []byte("test-signature-only")
			}
			hint, err := token.SignedString(signingKey)
			require.NoError(t, err)
			_, err = s.validateLogoutHint(hint)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
