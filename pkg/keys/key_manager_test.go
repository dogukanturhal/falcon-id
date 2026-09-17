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

func TestGenerateRSAKeyPair(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, 2048, key.N.BitLen())
}

func TestGenerateECDSAKeyPair(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, elliptic.P256(), key.Curve)
}

func TestKeyIDFromPublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid, err := KeyIDFromPublicKey(&key.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, kid)

	// Same key produces same kid
	kid2, err := KeyIDFromPublicKey(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, kid, kid2)

	// Different key produces different kid
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid3, err := KeyIDFromPublicKey(&key2.PublicKey)
	require.NoError(t, err)
	assert.NotEqual(t, kid, kid3)
}

func TestKeyIDFromPublicKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid, err := KeyIDFromPublicKey(&key.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, kid)
}

func TestEncryptDecryptPrivateKey(t *testing.T) {
	encKey := make([]byte, 32)
	_, err := rand.Read(encKey)
	require.NoError(t, err)

	// Generate a private key and marshal to PEM
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privPEM, err := marshalPrivateKeyPEM(rsaKey)
	require.NoError(t, err)

	// Encrypt
	encrypted, err := EncryptPrivateKey(privPEM, encKey)
	require.NoError(t, err)
	assert.NotEqual(t, privPEM, encrypted)

	// Decrypt
	decrypted, err := DecryptPrivateKey(encrypted, encKey)
	require.NoError(t, err)
	assert.Equal(t, privPEM, decrypted)
}

func TestEncryptPrivateKey_WrongKeyFails(t *testing.T) {
	encKey := make([]byte, 32)
	_, _ = rand.Read(encKey)

	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privPEM, _ := marshalPrivateKeyPEM(rsaKey)

	encrypted, err := EncryptPrivateKey(privPEM, encKey)
	require.NoError(t, err)

	_, err = DecryptPrivateKey(encrypted, wrongKey)
	assert.Error(t, err)
}

func TestMarshalPrivateKeyPEM_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pem, err := marshalPrivateKeyPEM(key)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "RSA PRIVATE KEY")
}

func TestMarshalPrivateKeyPEM_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pem, err := marshalPrivateKeyPEM(key)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "EC PRIVATE KEY")
}

func TestMarshalPublicKeyPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pem, err := marshalPublicKeyPEM(&key.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "PUBLIC KEY")
}
