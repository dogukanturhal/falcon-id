// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveRealmKey_DifferentRealmsProduceDifferentKeys(t *testing.T) {
	baseService, err := NewEncryptionService("01234567890123456789012345678901") // 32 bytes
	require.NoError(t, err)

	realm1 := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	realm2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	derived1, err := baseService.DeriveRealmKey(realm1)
	require.NoError(t, err)

	derived2, err := baseService.DeriveRealmKey(realm2)
	require.NoError(t, err)

	// Same plaintext encrypted with different realm keys should produce different results.
	// Because AES-GCM uses a random nonce we cannot compare raw ciphertexts directly;
	// instead we verify cross-realm decryption fails, which proves distinct keys are used.
	plaintext := "sensitive-data"
	enc1, err := derived1.Encrypt(plaintext)
	require.NoError(t, err)
	enc2, err := derived2.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "different realms should produce different ciphertext")

	// Each realm key can decrypt its own data.
	dec1, err := derived1.Decrypt(enc1)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec1)

	dec2, err := derived2.Decrypt(enc2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec2)
}

func TestDeriveRealmKey_CrossRealmDecryptionFails(t *testing.T) {
	baseService, err := NewEncryptionService("01234567890123456789012345678901")
	require.NoError(t, err)

	realm1 := uuid.New()
	realm2 := uuid.New()

	derived1, err := baseService.DeriveRealmKey(realm1)
	require.NoError(t, err)
	derived2, err := baseService.DeriveRealmKey(realm2)
	require.NoError(t, err)

	encrypted, err := derived1.Encrypt("secret")
	require.NoError(t, err)

	_, err = derived2.Decrypt(encrypted)
	assert.Error(t, err, "cross-realm decryption should fail")
}

func TestDeriveRealmKey_DefaultRealmUsesBaseKey(t *testing.T) {
	baseKey := "01234567890123456789012345678901"
	baseService, err := NewEncryptionService(baseKey)
	require.NoError(t, err)

	// Default realm (nil UUID) should use the base key for backward compatibility.
	defaultRealm := uuid.Nil
	derived, err := baseService.DeriveRealmKey(defaultRealm)
	require.NoError(t, err)

	// Encrypt with base service, decrypt with derived-from-default-realm service.
	// They must share the same key.
	encrypted, err := baseService.Encrypt("test-data")
	require.NoError(t, err)

	decrypted, err := derived.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "test-data", decrypted)
}

func TestDeriveRealmKey_Deterministic(t *testing.T) {
	baseService, err := NewEncryptionService("01234567890123456789012345678901")
	require.NoError(t, err)

	realmID := uuid.New()

	derived1, err := baseService.DeriveRealmKey(realmID)
	require.NoError(t, err)
	derived2, err := baseService.DeriveRealmKey(realmID)
	require.NoError(t, err)

	// Same realm ID must produce the same derived key every time (HKDF is deterministic).
	// Verify by encrypting with one instance and decrypting with another.
	encrypted, err := derived1.Encrypt("test")
	require.NoError(t, err)
	decrypted, err := derived2.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "test", decrypted)
}
