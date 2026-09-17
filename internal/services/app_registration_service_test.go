// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// newTestAppRegistrationService constructs an AppRegistrationService with nil
// dependencies, valid for tests that only exercise methods that do not touch the
// repository (e.g. generateClientID, generateAndHashSecret).
func newTestAppRegistrationService() *AppRegistrationService {
	return &AppRegistrationService{}
}

// ==================== generateClientID ====================

func TestAppRegistrationService_GenerateClientID_Format(t *testing.T) {
	svc := newTestAppRegistrationService()

	clientID, err := svc.generateClientID()
	require.NoError(t, err)

	t.Run("should start with the app_ prefix", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(clientID, "app_"),
			"client ID %q should start with 'app_'", clientID)
	})

	t.Run("should have 36 total characters (app_ + 32 hex chars)", func(t *testing.T) {
		// "app_" (4) + hex.EncodeToString(16 bytes) = 4 + 32 = 36
		assert.Len(t, clientID, 36,
			"client ID %q should be 36 characters long", clientID)
	})

	t.Run("hex portion should be valid lowercase hex", func(t *testing.T) {
		hexPart := strings.TrimPrefix(clientID, "app_")
		_, err := hex.DecodeString(hexPart)
		assert.NoError(t, err,
			"hex portion %q of client ID should be valid hex", hexPart)
	})
}

func TestAppRegistrationService_GenerateClientID_Uniqueness(t *testing.T) {
	svc := newTestAppRegistrationService()

	const iterations = 500
	seen := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		id, err := svc.generateClientID()
		require.NoError(t, err)

		_, duplicate := seen[id]
		assert.False(t, duplicate,
			"duplicate client ID generated after %d iterations: %s", i, id)
		seen[id] = struct{}{}
	}
}

// ==================== generateAndHashSecret ====================

func TestAppRegistrationService_GenerateAndHashSecret_PlainText(t *testing.T) {
	svc := newTestAppRegistrationService()

	plain, hash, err := svc.generateAndHashSecret()
	require.NoError(t, err)

	t.Run("plain-text secret should be 64 hex characters", func(t *testing.T) {
		// hex.EncodeToString(32 bytes) = 64 characters
		assert.Len(t, plain, 64,
			"plain secret %q should be 64 characters (32 random bytes as hex)", plain)
	})

	t.Run("plain-text secret should be valid hex", func(t *testing.T) {
		_, decErr := hex.DecodeString(plain)
		assert.NoError(t, decErr,
			"plain secret %q should be valid hex", plain)
	})

	t.Run("hash should not be empty", func(t *testing.T) {
		assert.NotEmpty(t, hash)
	})

	t.Run("hash should verify against the plain-text secret", func(t *testing.T) {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
		assert.NoError(t, err,
			"bcrypt hash should verify correctly against the plain-text secret")
	})

	t.Run("hash should look like a bcrypt string", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$"),
			"hash %q should start with a bcrypt prefix", hash)
	})
}

func TestAppRegistrationService_GenerateAndHashSecret_Uniqueness(t *testing.T) {
	svc := newTestAppRegistrationService()

	const iterations = 20 // bcrypt is intentionally slow; keep iterations low
	secrets := make(map[string]struct{}, iterations)
	hashes := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		plain, hash, err := svc.generateAndHashSecret()
		require.NoError(t, err)

		_, dupSecret := secrets[plain]
		assert.False(t, dupSecret,
			"duplicate plain secret generated on iteration %d", i)
		secrets[plain] = struct{}{}

		_, dupHash := hashes[hash]
		assert.False(t, dupHash,
			"duplicate hash generated on iteration %d", i)
		hashes[hash] = struct{}{}
	}
}

func TestAppRegistrationService_GenerateAndHashSecret_HashNotEqualToPlain(t *testing.T) {
	svc := newTestAppRegistrationService()

	plain, hash, err := svc.generateAndHashSecret()
	require.NoError(t, err)

	assert.NotEqual(t, plain, hash,
		"plain-text secret and its bcrypt hash must not be equal")
}

// BenchmarkGenerateClientID measures throughput of client ID generation.
func BenchmarkAppRegistrationService_GenerateClientID(b *testing.B) {
	svc := newTestAppRegistrationService()
	for i := 0; i < b.N; i++ {
		_, _ = svc.generateClientID()
	}
}

// BenchmarkGenerateAndHashSecret measures throughput of secret generation.
// Note: bcrypt makes this intentionally slow.
func BenchmarkAppRegistrationService_GenerateAndHashSecret(b *testing.B) {
	svc := newTestAppRegistrationService()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.generateAndHashSecret()
	}
}
