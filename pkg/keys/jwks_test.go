// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildJWKS_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid, _ := KeyIDFromPublicKey(&key.PublicKey)

	keys := []PublicKeyInfo{
		{KeyID: kid, Algorithm: AlgorithmRS256, PublicKey: &key.PublicKey, Status: StatusActive},
	}

	jwks, err := BuildJWKS(keys)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	assert.Equal(t, "RSA", jwks.Keys[0].KTY)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.Equal(t, kid, jwks.Keys[0].KID)
	assert.Equal(t, AlgorithmRS256, jwks.Keys[0].ALG)
	assert.NotEmpty(t, jwks.Keys[0].N)
	assert.NotEmpty(t, jwks.Keys[0].E)
}

func TestBuildJWKS_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := KeyIDFromPublicKey(&key.PublicKey)

	keys := []PublicKeyInfo{
		{KeyID: kid, Algorithm: AlgorithmES256, PublicKey: &key.PublicKey, Status: StatusActive},
	}

	jwks, err := BuildJWKS(keys)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	assert.Equal(t, "EC", jwks.Keys[0].KTY)
	assert.Equal(t, kid, jwks.Keys[0].KID)
	assert.Equal(t, "P-256", jwks.Keys[0].CRV)
	assert.NotEmpty(t, jwks.Keys[0].X)
	assert.NotEmpty(t, jwks.Keys[0].Y)
}

func TestBuildJWKS_IncludesActiveAndRotatedKeys(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid1, _ := KeyIDFromPublicKey(&key1.PublicKey)

	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2, _ := KeyIDFromPublicKey(&key2.PublicKey)

	keys := []PublicKeyInfo{
		{KeyID: kid1, Algorithm: AlgorithmRS256, PublicKey: &key1.PublicKey, Status: StatusActive},
		{KeyID: kid2, Algorithm: AlgorithmRS256, PublicKey: &key2.PublicKey, Status: StatusRotated},
	}

	jwks, err := BuildJWKS(keys)
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 2)
}

func TestBuildJWKS_ExcludesRevokedKeys(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid1, _ := KeyIDFromPublicKey(&key1.PublicKey)

	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid2, _ := KeyIDFromPublicKey(&key2.PublicKey)

	keys := []PublicKeyInfo{
		{KeyID: kid1, Algorithm: AlgorithmRS256, PublicKey: &key1.PublicKey, Status: StatusActive},
		{KeyID: kid2, Algorithm: AlgorithmRS256, PublicKey: &key2.PublicKey, Status: StatusRevoked},
	}

	jwks, err := BuildJWKS(keys)
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, kid1, jwks.Keys[0].KID)
}

func TestBuildJWKS_EmptyKeys(t *testing.T) {
	jwks, err := BuildJWKS(nil)
	require.NoError(t, err)
	assert.Empty(t, jwks.Keys)
}
