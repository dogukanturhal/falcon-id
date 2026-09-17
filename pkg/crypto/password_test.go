// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── HashPassword ────────────────────────────────────────────────────────────

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		config   *PasswordConfig
		wantErr  bool
	}{
		{
			name:     "default config",
			password: "StrongP@ssw0rd!",
			config:   nil, // uses DefaultPasswordConfig
			wantErr:  false,
		},
		{
			name:     "custom config",
			password: "AnotherS3cure#Pass",
			config: &PasswordConfig{
				Time: 1, Memory: 32 * 1024, Threads: 2, KeyLen: 32, SaltLen: 16,
			},
			wantErr: false,
		},
		{
			name:     "empty password still hashes",
			password: "",
			config:   nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, hash)
			assert.True(t, strings.HasPrefix(hash, "$argon2id$"), "hash must use argon2id format")
		})
	}
}

func TestHashPassword_ProducesUniqueSalts(t *testing.T) {
	// Two hashes of the same password must differ (random salt per call).
	password := "SamePassword@123"
	hash1, err := HashPassword(password, nil)
	require.NoError(t, err)
	hash2, err := HashPassword(password, nil)
	require.NoError(t, err)
	assert.NotEqual(t, hash1, hash2, "hashes must be distinct due to random salt")
}

// ─── VerifyPassword ──────────────────────────────────────────────────────────

func TestVerifyPassword(t *testing.T) {
	password := "CorrectHors3Battery#Staple"
	hash, err := HashPassword(password, nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
		},
		{
			name:     "wrong password",
			password: "WrongPass@word1",
			hash:     hash,
			want:     false,
		},
		{
			name:     "empty against valid hash",
			password: "",
			hash:     hash,
			want:     false,
		},
		{
			name:     "invalid hash format returns error",
			password: password,
			hash:     "notahash",
			want:     false,
			wantErr:  true,
		},
		{
			name:     "truncated hash returns error",
			password: password,
			hash:     "$argon2id$v=19$m=65536,t=3,p=4",
			want:     false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := VerifyPassword(tt.password, tt.hash)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func TestVerifyPassword_RoundTrip(t *testing.T) {
	passwords := []string{
		"Simple1!",
		"Unicode€∂∆˚1!Aa",
		strings.Repeat("Long", 20) + "P@ss1",
		"!@#$%^&*()_+Aa1",
	}

	for _, pw := range passwords {
		t.Run(pw[:min(len(pw), 20)], func(t *testing.T) {
			hash, err := HashPassword(pw, nil)
			require.NoError(t, err)

			ok, err := VerifyPassword(pw, hash)
			require.NoError(t, err)
			assert.True(t, ok, "password must verify against its own hash")

			// A slightly different password must NOT match.
			ok2, err := VerifyPassword(pw+"x", hash)
			require.NoError(t, err)
			assert.False(t, ok2)
		})
	}
}

// ─── ValidatePassword ────────────────────────────────────────────────────────

func TestValidatePassword_DefaultPolicy(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{ //nolint:gosec // test fixture value, not a real credential
			name:     "valid strong password",
			password: "Tr0ub4dor&3Xyzzy",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Ab1!",
			wantErr:  true,
			errMsg:   "at least",
		},
		{
			name:     "too long (129 chars)",
			password: strings.Repeat("Aa1!", 33), // 132 chars
			wantErr:  true,
			errMsg:   "at most",
		},
		{
			name:     "missing uppercase",
			password: "nouppercase@1234",
			wantErr:  true,
			errMsg:   "uppercase",
		},
		{
			name:     "missing lowercase",
			password: "NOLOWERCASE@1234",
			wantErr:  true,
			errMsg:   "lowercase",
		},
		{
			name:     "missing digit",
			password: "NoDigitHere@Pass",
			wantErr:  true,
			errMsg:   "digit",
		},
		{
			name:     "missing special char",
			password: "NoSpecialChar123",
			wantErr:  true,
			errMsg:   "special character",
		},
		{
			name:     "common password blocked",
			password: "Password123!", // contains "password"
			wantErr:  true,
			errMsg:   "common",
		},
		{
			name:     "exactly 12 chars valid",
			password: "Abc1@efghijk",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, DefaultPasswordPolicy)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword_NilPolicyUsesDefault(t *testing.T) {
	// nil policy should fall back to DefaultPasswordPolicy
	err := ValidatePassword("Ab1!", nil)
	assert.Error(t, err) // too short
}

func TestValidatePasswordWithContext(t *testing.T) {
	policy := &PasswordPolicy{
		MinLength:          8,
		MaxLength:          128,
		RequireUpper:       true,
		RequireLower:       true,
		RequireDigit:       true,
		RequireSpecial:     false,
		PreventCommon:      false,
		PreventUserContext: true,
	}

	tests := []struct {
		name     string
		password string
		username string
		email    string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "password contains username",
			password: "Johndoe123A",
			username: "johndoe",
			email:    "",
			wantErr:  true,
			errMsg:   "username",
		},
		{
			name:     "password contains email local part",
			password: "Alice123ABob",
			username: "",
			email:    "alice@example.com",
			wantErr:  true,
			errMsg:   "email",
		},
		{
			name:     "password unrelated to user context",
			password: "Secure1Pass",
			username: "johndoe",
			email:    "johndoe@example.com",
			wantErr:  false,
		},
		{
			name:     "short username not checked (< 3 chars)",
			password: "Ab1234567",
			username: "jo",
			email:    "",
			wantErr:  false,
		},
		{
			name:     "short email local part not checked (< 3 chars)",
			password: "Ab1234567",
			username: "",
			email:    "jo@example.com",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordWithContext(tt.password, tt.username, tt.email, policy)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ─── GenerateRandomString ────────────────────────────────────────────────────

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"length 8", 8},
		{"length 16", 16},
		{"length 32", 32},
		{"length 64", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := GenerateRandomString(tt.length)
			require.NoError(t, err)
			assert.Len(t, s, tt.length)
		})
	}
}

func TestGenerateRandomString_ProducesUniqueValues(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		s, err := GenerateRandomString(32)
		require.NoError(t, err)
		assert.False(t, seen[s], "generated string must be unique")
		seen[s] = true
	}
}

// ─── GenerateSecureToken ─────────────────────────────────────────────────────

func TestGenerateSecureToken(t *testing.T) {
	t.Run("returns non-empty token", func(t *testing.T) {
		tok, err := GenerateSecureToken()
		require.NoError(t, err)
		assert.NotEmpty(t, tok)
	})

	t.Run("produces unique tokens", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 20; i++ {
			tok, err := GenerateSecureToken()
			require.NoError(t, err)
			assert.False(t, seen[tok], "token must be unique")
			seen[tok] = true
		}
	})
}

// ─── TokenHasher ─────────────────────────────────────────────────────────────

func TestNewTokenHasher(t *testing.T) {
	tests := []struct {
		name    string
		salt    []byte
		wantErr bool
	}{
		{"valid 16-byte salt", make([]byte, 16), false},
		{"valid 32-byte salt", make([]byte, 32), false},
		{"too short (15 bytes)", make([]byte, 15), true},
		{"too short (8 bytes)", make([]byte, 8), true},
		{"empty salt", []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher, err := NewTokenHasher(tt.salt)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, hasher)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, hasher)
			}
		})
	}
}

func TestTokenHasher_Hash(t *testing.T) {
	salt := make([]byte, 32)
	hasher, err := NewTokenHasher(salt)
	require.NoError(t, err)

	t.Run("returns non-empty hash", func(t *testing.T) {
		h := hasher.Hash("mytoken")
		assert.NotEmpty(t, h)
	})

	t.Run("same token produces same hash (deterministic)", func(t *testing.T) {
		h1 := hasher.Hash("stable-token")
		h2 := hasher.Hash("stable-token")
		assert.Equal(t, h1, h2)
	})

	t.Run("different tokens produce different hashes", func(t *testing.T) {
		h1 := hasher.Hash("token-A")
		h2 := hasher.Hash("token-B")
		assert.NotEqual(t, h1, h2)
	})

	t.Run("different salts produce different hashes for same token", func(t *testing.T) {
		salt2 := make([]byte, 32)
		salt2[0] = 0xFF
		hasher2, err := NewTokenHasher(salt2)
		require.NoError(t, err)

		h1 := hasher.Hash("same-token")
		h2 := hasher2.Hash("same-token")
		assert.NotEqual(t, h1, h2)
	})
}

// ─── InitDefaultTokenHasher / GetDefaultTokenHasher ─────────────────────────

func TestInitAndGetDefaultTokenHasher(t *testing.T) {
	t.Run("empty salt returns error", func(t *testing.T) {
		err := InitDefaultTokenHasher("")
		assert.Error(t, err)
	})

	t.Run("short raw salt returns error", func(t *testing.T) {
		err := InitDefaultTokenHasher("tooshort")
		assert.Error(t, err)
	})

	t.Run("valid raw salt initializes hasher", func(t *testing.T) {
		err := InitDefaultTokenHasher("this-is-a-32-byte-salt-value-ok!")
		require.NoError(t, err)

		hasher, err := GetDefaultTokenHasher()
		require.NoError(t, err)
		assert.NotNil(t, hasher)
	})
}

// ─── HashToken ───────────────────────────────────────────────────────────────

func TestHashToken(t *testing.T) {
	// Ensure hasher is initialized first.
	err := InitDefaultTokenHasher("this-is-a-32-byte-salt-value-ok!")
	require.NoError(t, err)

	t.Run("hashes a token successfully", func(t *testing.T) {
		h, err := HashToken("my-access-token")
		require.NoError(t, err)
		assert.NotEmpty(t, h)
	})

	t.Run("same token hashes to same value", func(t *testing.T) {
		h1, err := HashToken("stable")
		require.NoError(t, err)
		h2, err := HashToken("stable")
		require.NoError(t, err)
		assert.Equal(t, h1, h2)
	})

	t.Run("different tokens produce different hashes", func(t *testing.T) {
		h1, err := HashToken("token-one")
		require.NoError(t, err)
		h2, err := HashToken("token-two")
		require.NoError(t, err)
		assert.NotEqual(t, h1, h2)
	})
}

// ─── helpers ─────────────────────────────────────────────────────────────────
