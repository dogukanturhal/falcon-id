// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// licenseKeyPattern is the expected format for generated license keys:
// HEXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX (9 segments, 128 bits of entropy).
var licenseKeyPattern = regexp.MustCompile(
	`^HEXX(-[0-9A-F]{4}){8}$`,
)

// newTestLicenseService constructs a LicenseService with nil dependencies.
// This is valid for tests that only exercise methods that do not touch the
// repository or config (e.g. generateLicenseKey).
func newTestLicenseService() *LicenseService {
	return &LicenseService{}
}

// ==================== generateLicenseKey ====================

func TestLicenseService_GenerateLicenseKey_Format(t *testing.T) {
	svc := newTestLicenseService()
	key, err := svc.generateLicenseKey()
	require.NoError(t, err)

	t.Run("should match the HEXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX pattern", func(t *testing.T) {
		assert.Regexp(t, licenseKeyPattern, key,
			"generated key %q does not match expected 9-segment pattern", key)
	})

	t.Run("should have exactly nine segments separated by hyphens", func(t *testing.T) {
		parts := strings.Split(key, "-")
		require.Len(t, parts, 9, "expected 9 hyphen-separated segments (HEXX + 8 hex groups)")
	})

	t.Run("should start with HEXX prefix", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(key, "HEXX-"),
			"key %q should start with 'HEXX-'", key)
	})

	t.Run("each subsequent segment should have exactly 4 characters", func(t *testing.T) {
		parts := strings.Split(key, "-")
		for i := 1; i < len(parts); i++ {
			assert.Len(t, parts[i], 4,
				"segment %d of key %q should be 4 characters", i, key)
		}
	})
}

func TestLicenseService_GenerateLicenseKey_ReturnsNoError(t *testing.T) {
	svc := newTestLicenseService()
	key, err := svc.generateLicenseKey()
	require.NoError(t, err, "generateLicenseKey should not return an error with a working crypto/rand")
	assert.NotEmpty(t, key)
}

func TestLicenseService_GenerateLicenseKey_Uniqueness(t *testing.T) {
	svc := newTestLicenseService()

	const iterations = 1000
	seen := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		key, err := svc.generateLicenseKey()
		require.NoError(t, err)
		_, duplicate := seen[key]
		assert.False(t, duplicate,
			"duplicate license key generated after %d iterations: %s", i, key)
		seen[key] = struct{}{}
	}
}

func TestLicenseService_GenerateLicenseKey_UpperCase(t *testing.T) {
	svc := newTestLicenseService()

	for i := 0; i < 20; i++ {
		key, err := svc.generateLicenseKey()
		require.NoError(t, err)
		assert.Equal(t, strings.ToUpper(key), key,
			"key %q should be entirely upper-case", key)
	}
}

func TestLicenseService_GenerateLicenseKey_TotalLength(t *testing.T) {
	svc := newTestLicenseService()
	key, err := svc.generateLicenseKey()
	require.NoError(t, err)

	// "HEXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
	// = 4 + (1+4)*8 = 4 + 40 = 44 chars
	const expectedLen = 44
	assert.Len(t, key, expectedLen,
		"license key %q should be %d characters long", key, expectedLen)
}

func TestLicenseService_GenerateLicenseKey_128BitEntropy(t *testing.T) {
	svc := newTestLicenseService()
	key, err := svc.generateLicenseKey()
	require.NoError(t, err)

	// Remove "HEXX-" prefix and hyphens to get raw hex
	rawHex := strings.ReplaceAll(strings.TrimPrefix(key, "HEXX-"), "-", "")
	// 128 bits = 32 hex characters
	assert.Len(t, rawHex, 32,
		"raw hex portion should be 32 characters (128 bits), got %q", rawHex)
}

// ==================== Sentinel errors ====================

func TestLicenseService_SentinelErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrLicenseNotFound,
		ErrProductNotFound,
		ErrActivationNotFound,
		ErrLicenseNotActive,
		ErrLicenseExpired,
		ErrMaxSeatsReached,
	}

	for i, a := range errs {
		for j, b := range errs {
			if i == j {
				continue
			}
			assert.NotErrorIs(t, a, b,
				"sentinel error %q should not match %q", a, b)
		}
	}
}

func TestLicenseService_SentinelErrors_WrappedStillMatch(t *testing.T) {
	wrapped := fmt.Errorf("%w: some context", ErrLicenseNotFound)
	assert.ErrorIs(t, wrapped, ErrLicenseNotFound,
		"wrapped sentinel error should still match via errors.Is")
	assert.NotErrorIs(t, wrapped, ErrProductNotFound,
		"wrapped ErrLicenseNotFound should NOT match ErrProductNotFound")
}

// BenchmarkGenerateLicenseKey measures the throughput of key generation.
func BenchmarkLicenseService_GenerateLicenseKey(b *testing.B) {
	svc := newTestLicenseService()
	for i := 0; i < b.N; i++ {
		_, _ = svc.generateLicenseKey()
	}
}
