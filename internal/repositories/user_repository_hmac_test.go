// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireEmailHashKey_FailsWithEmptyKey(t *testing.T) {
	// Save current key and restore after test
	originalKey := emailHashKey
	defer func() { emailHashKey = originalKey }()

	emailHashKey = nil
	err := RequireEmailHashKey()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EMAIL_HASH_KEY is required")
}

func TestRequireEmailHashKey_SucceedsWithValidKey(t *testing.T) {
	originalKey := emailHashKey
	defer func() { emailHashKey = originalKey }()

	SetEmailHashKey("test-key-for-validation")
	err := RequireEmailHashKey()
	assert.NoError(t, err)
}

func TestComputeEmailHash_NormalizesCasing(t *testing.T) {
	originalKey := emailHashKey
	defer func() { emailHashKey = originalKey }()

	SetEmailHashKey("test-key")

	hash1 := computeEmailHash("User@Example.COM")
	hash2 := computeEmailHash("user@example.com")
	hash3 := computeEmailHash("  User@Example.COM  ")

	assert.Equal(t, hash1, hash2, "email hash should be case-insensitive")
	assert.Equal(t, hash1, hash3, "email hash should trim whitespace")
}
