// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genRSAPEM generates a 2048-bit RSA key pair and returns PEM-encoded strings for
// the private key (PKCS1) and public key (PKIX).
func genRSAPEM(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privDER := x509.MarshalPKCS1PrivateKey(key)
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	return privPEM, pubPEM
}

func clearJWTEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"JWT_PRIVATE_KEY", "JWT_PRIVATE_KEY_FILE", "JWT_PUBLIC_KEY", "JWT_PUBLIC_KEY_FILE"} {
		t.Setenv(k, "") // t.Setenv restores original value on cleanup
	}
}

func TestNewJWTKeyProvider_Ephemeral(t *testing.T) {
	clearJWTEnv(t)

	p, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)
	require.NotNil(t, p)

	assert.True(t, p.IsEphemeral(), "key generated at startup should be marked ephemeral")
	assert.NotNil(t, p.PrivateKey())
	assert.NotNil(t, p.PublicKey())
	assert.NotEmpty(t, p.KeyID())
	// Derived public key must be the private key's public half.
	assert.Equal(t, &p.PrivateKey().PublicKey, p.PublicKey())
}

func TestNewJWTKeyProvider_ExplicitKeyID(t *testing.T) {
	clearJWTEnv(t)

	p, err := NewJWTKeyProvider(nil, "my-key-v1")
	require.NoError(t, err)
	assert.Equal(t, "my-key-v1", p.KeyID(), "explicit key ID should be returned as-is")
}

func TestNewJWTKeyProvider_LoadFromEnv(t *testing.T) {
	clearJWTEnv(t)

	privPEM, pubPEM := genRSAPEM(t)
	t.Setenv("JWT_PRIVATE_KEY", privPEM)
	t.Setenv("JWT_PUBLIC_KEY", pubPEM)

	p, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)

	assert.False(t, p.IsEphemeral(), "key loaded from env must not be flagged ephemeral")
	assert.NotNil(t, p.PrivateKey())
	assert.NotNil(t, p.PublicKey())
	assert.NotEmpty(t, p.KeyID())
}

func TestNewJWTKeyProvider_LoadFromFile(t *testing.T) {
	clearJWTEnv(t)

	privPEM, _ := genRSAPEM(t)

	f, err := os.CreateTemp(t.TempDir(), "jwt-test-*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(privPEM)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	t.Setenv("JWT_PRIVATE_KEY_FILE", f.Name())

	p, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)

	assert.False(t, p.IsEphemeral())
	assert.NotNil(t, p.PrivateKey())
}

func TestNewJWTKeyProvider_InvalidPEM(t *testing.T) {
	clearJWTEnv(t)
	t.Setenv("JWT_PRIVATE_KEY", "not-a-pem-block")

	_, err := NewJWTKeyProvider(nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestDeriveKeyID_Deterministic(t *testing.T) {
	clearJWTEnv(t)

	privPEM, _ := genRSAPEM(t)
	t.Setenv("JWT_PRIVATE_KEY", privPEM)

	p1, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)

	p2, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)

	assert.Equal(t, p1.KeyID(), p2.KeyID(), "key ID must be deterministic for the same key")
}

func TestNewJWTKeyProvider_EphemeralDifferentPerCall(t *testing.T) {
	clearJWTEnv(t)

	p1, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)

	p2, err := NewJWTKeyProvider(nil, "")
	require.NoError(t, err)

	// Ephemeral keys are generated fresh each call — key IDs must differ.
	assert.NotEqual(t, p1.KeyID(), p2.KeyID(),
		"two ephemeral providers should have different key IDs (different keys)")
}
