// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestEnvStringSlice covers the viper env-var slice-splitting fix.
// Background: viper.GetStringSlice() returns a single-element slice
// when the value comes from an env var, not the expected multi-
// element split-on-comma. envStringSlice() makes the split explicit.
// Live failure pre-fix: passkey FinishRegistration rejected every
// origin past the first joined-in entry of WEBAUTHN_RP_ORIGINS.
func TestEnvStringSlice(t *testing.T) {
	t.Run("empty env var returns nil", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		t.Setenv("TEST_SLICE_EMPTY", "")
		got := envStringSlice("TEST_SLICE_EMPTY")
		assert.Nil(t, got)
	})

	t.Run("unset env var returns nil", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		_ = os.Unsetenv("TEST_SLICE_UNSET")
		got := envStringSlice("TEST_SLICE_UNSET")
		assert.Nil(t, got)
	})

	t.Run("single value returns single-element slice", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		t.Setenv("TEST_SLICE_ONE", "https://only.example.com")
		got := envStringSlice("TEST_SLICE_ONE")
		assert.Equal(t, []string{"https://only.example.com"}, got)
	})

	t.Run("comma-separated multi-value splits correctly", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		t.Setenv("TEST_SLICE_MULTI", "https://a.example.com,https://b.example.com,https://c.example.com")
		got := envStringSlice("TEST_SLICE_MULTI")
		assert.Equal(t, []string{
			"https://a.example.com",
			"https://b.example.com",
			"https://c.example.com",
		}, got)
	})

	t.Run("whitespace around entries trimmed", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		t.Setenv("TEST_SLICE_SPACES", " https://a.example.com , https://b.example.com ")
		got := envStringSlice("TEST_SLICE_SPACES")
		assert.Equal(t, []string{
			"https://a.example.com",
			"https://b.example.com",
		}, got)
	})

	t.Run("empty entries dropped (trailing comma, double comma)", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		t.Setenv("TEST_SLICE_EMPTY_ENTRIES", "https://a.example.com,,https://b.example.com,")
		got := envStringSlice("TEST_SLICE_EMPTY_ENTRIES")
		assert.Equal(t, []string{
			"https://a.example.com",
			"https://b.example.com",
		}, got)
	})

	// Regression: viper.GetStringSlice() returns ["a,b"] from env vars.
	// Demonstrate that envStringSlice() returns the expected ["a","b"].
	t.Run("regression: matches expected multi-element shape (not viper default)", func(t *testing.T) {
		viper.Reset()
		viper.AutomaticEnv()
		t.Setenv("TEST_SLICE_REGRESSION", "https://id.example.com,https://accounts.example.com")

		// viper.GetStringSlice's native behaviour on env vars (broken for our use case)
		broken := viper.GetStringSlice("TEST_SLICE_REGRESSION")
		assert.Equal(t, 1, len(broken),
			"viper.GetStringSlice on env var SHOULD return 1 element (the joined string) — if this asserts 2, viper fixed the bug upstream and envStringSlice could be deprecated")

		// envStringSlice — correct multi-element shape
		fixed := envStringSlice("TEST_SLICE_REGRESSION")
		assert.Equal(t, []string{
			"https://id.example.com",
			"https://accounts.example.com",
		}, fixed)
	})
}

func TestValidateJWTSecret(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		expectError bool
		errorMsg    string
	}{
		{ //nolint:gosec // test fixture value, not a real credential
			name:        "valid secret with high entropy",
			secret:      "x7K#mP9$vL2@nQ5&wR8!tY4*zU1^aB3%",
			expectError: false,
		},
		{ //nolint:gosec // test fixture value, not a real credential
			name:        "valid secret - random characters",
			secret:      "Qw3$Rt6#Yp9@Ak2%Fj5^Gm8&Hn1*Bl4!",
			expectError: false,
		},
		{ //nolint:gosec // test fixture value, not a real credential
			name:        "too short - 31 characters",
			secret:      "Qw3$Rt6#Yp9@Ak2%Fj5^Gm8&Hn1*Bl",
			expectError: true,
			errorMsg:    "at least 32 characters",
		},
		{
			name:        "too short - 10 characters",
			secret:      "short_key!",
			expectError: true,
			errorMsg:    "at least 32 characters",
		},
		{
			name:        "low entropy - repeated character",
			secret:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expectError: true,
			errorMsg:    "insufficient entropy",
		},
		{
			name:        "low entropy - only digits sequential",
			secret:      "12345678901234567890123456789012",
			expectError: true,
			errorMsg:    "insufficient entropy",
		},
		{
			name:        "weak pattern - sequential numbers",
			secret:      "11112222333344445555666677778888",
			expectError: true,
			errorMsg:    "insufficient entropy",
		},
		{
			name:        "weak pattern - common secret",
			secret:      "your-256-bit-secret",
			expectError: true,
			errorMsg:    "at least 32 characters",
		},
		{ //nolint:gosec // test fixture value, not a real credential
			name:        "exactly 32 characters with good entropy",
			secret:      "Qw3$Rt6#Yp9@Ak2%Fj5^Gm8&Hn1*Bl4!",
			expectError: false,
		},
		{ //nolint:gosec // test fixture value, not a real credential
			name:        "long secret with good entropy",
			secret:      "Qw3$Rt6#Yp9@Ak2%Fj5^Gm8&Hn1*Bl4!Vx7@Zc9#",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTSecret(tt.secret)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateJWTSecret_EntropyCalculation(t *testing.T) {
	// Test the entropy check specifically
	t.Run("high entropy secret should pass", func(t *testing.T) {
		// Random-looking secret with high entropy and no sequential patterns
		secret := "Qw3$Rt6#Yp9@Ak2%Fj5^Gm8&Hn1*Bl4!" //nolint:gosec // test fixture value, not a real credential
		err := validateJWTSecret(secret)
		assert.NoError(t, err)
	})

	t.Run("low entropy repeated chars should fail", func(t *testing.T) {
		// Low entropy - too few unique characters
		secret := "aaaaaaaabbbbbbbbccccccccdddddddd"
		err := validateJWTSecret(secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient entropy")
	})
}

func TestValidateJWTSecret_WeakPatterns(t *testing.T) {
	weakSecrets := []string{
		"12345678901234567890123456789012",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	for _, secret := range weakSecrets {
		t.Run(secret[:10]+"...", func(t *testing.T) {
			err := validateJWTSecret(secret)
			assert.Error(t, err, "Weak secret should be rejected: %s", secret)
		})
	}
}

func TestValidateSecurityConfig(t *testing.T) {
	t.Run("production requires JWT_SECRET", func(t *testing.T) {
		config := &Config{
			Environment:             "production",
			DatabaseURL:             "postgres://localhost/test",
			ControlPlaneDatabaseURL: "postgres://localhost/control",
			RedisURL:                "redis://localhost:6379",
			JWTSecret:               "",
		}

		err := validateSecurityConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWT_SECRET")
	})

	t.Run("production requires minimum JWT_SECRET length", func(t *testing.T) {
		config := &Config{
			Environment:             "production",
			DatabaseURL:             "postgres://localhost/test",
			ControlPlaneDatabaseURL: "postgres://localhost/control",
			RedisURL:                "redis://localhost:6379",
			JWTSecret:               "short",
			EncryptionKey:           "12345678901234567890123456789012",
			TokenHashSalt:           "some-salt-value",
			InternalAPIKey:          "12345678901234567890123456789012",
		}

		err := validateSecurityConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWT_SECRET")
	})

	t.Run("development allows empty secrets with ALLOW_AUTO_JWT_SECRET", func(t *testing.T) {
		// Set the env var to allow auto-generation
		t.Setenv("ALLOW_AUTO_JWT_SECRET", "true")

		config := &Config{
			Environment:             "development",
			DatabaseURL:             "postgres://localhost/test",
			ControlPlaneDatabaseURL: "postgres://localhost/control",
			RedisURL:                "redis://localhost:6379",
			JWTSecret:               "",
			EncryptionKey:           "",
			TokenHashSalt:           "",
		}

		err := validateSecurityConfig(config)
		assert.NoError(t, err)
		// Config should have auto-generated dev secrets
		assert.NotEmpty(t, config.JWTSecret)
		assert.NotEmpty(t, config.EncryptionKey)
		assert.NotEmpty(t, config.TokenHashSalt)
	})

	t.Run("development requires ALLOW_AUTO_JWT_SECRET for empty secrets", func(t *testing.T) {
		config := &Config{
			Environment:             "development",
			DatabaseURL:             "postgres://localhost/test",
			ControlPlaneDatabaseURL: "postgres://localhost/control",
			RedisURL:                "redis://localhost:6379",
			JWTSecret:               "",
		}

		err := validateSecurityConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ALLOW_AUTO_JWT_SECRET")
	})

	t.Run("environment must be explicitly set", func(t *testing.T) {
		config := &Config{
			Environment: "",
		}

		err := validateSecurityConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ENVIRONMENT must be explicitly set")
	})
}

func TestGenerateSecureDevSecret(t *testing.T) {
	t.Run("generates unique secrets", func(t *testing.T) {
		secret1, err1 := generateSecureDevSecret()
		secret2, err2 := generateSecureDevSecret()

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, secret1, secret2)
	})

	t.Run("generates secrets of appropriate length", func(t *testing.T) {
		secret, err := generateSecureDevSecret()
		assert.NoError(t, err)
		// Base64 encoding of 32 bytes = 44 characters (with padding)
		assert.GreaterOrEqual(t, len(secret), 32)
	})
}
