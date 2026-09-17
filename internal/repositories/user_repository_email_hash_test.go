// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"os"
	"testing"
)

// TestMain seeds the HMAC key that the golden hashes in this file were computed
// with. The init() function that previously provided this default was removed as
// part of the fail-fast hardening; test suites that pin exact digest values must
// set the key explicitly.
func TestMain(m *testing.M) {
	SetEmailHashKey("hexxlock-email-hash-default-key")
	os.Exit(m.Run())
}

func TestComputeEmailHash(t *testing.T) {
	// Expected hashes are HMAC-SHA256 with key "hexxlock-email-hash-default-key".
	// They differ from the previous SHA-256 hashes due to the switch to HMAC
	// (Fix 9: HMAC-SHA256 to prevent rainbow-table attacks).
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "lowercase email",
			email:    "user@example.com",
			expected: "4cbc30afd0c2dead12079abbe59e938d1a1464b012986fd03253a96f9c0a29db",
		},
		{
			name:     "uppercase email",
			email:    "USER@EXAMPLE.COM",
			expected: "4cbc30afd0c2dead12079abbe59e938d1a1464b012986fd03253a96f9c0a29db", // same as lowercase
		},
		{
			name:     "mixed case email",
			email:    "User@Example.Com",
			expected: "4cbc30afd0c2dead12079abbe59e938d1a1464b012986fd03253a96f9c0a29db", // same as lowercase
		},
		{
			name:     "email with leading whitespace",
			email:    "  user@example.com",
			expected: "4cbc30afd0c2dead12079abbe59e938d1a1464b012986fd03253a96f9c0a29db", // same after trim
		},
		{
			name:     "email with trailing whitespace",
			email:    "user@example.com  ",
			expected: "4cbc30afd0c2dead12079abbe59e938d1a1464b012986fd03253a96f9c0a29db", // same after trim
		},
		{
			name:     "email with surrounding whitespace",
			email:    "  user@example.com  ",
			expected: "4cbc30afd0c2dead12079abbe59e938d1a1464b012986fd03253a96f9c0a29db", // same after trim
		},
		{
			name:     "different email",
			email:    "admin@example.com",
			expected: "8df8189f4d72a60e04b8b48b7f392bafff894a4dd6358348d58ae48025ea4698",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeEmailHash(tt.email)
			if result != tt.expected {
				t.Errorf("computeEmailHash(%q) = %q, want %q", tt.email, result, tt.expected)
			}
		})
	}
}

func TestComputeEmailHash_CaseInsensitive(t *testing.T) {
	// Test that different cases produce the same hash
	emails := []string{
		"test@example.com",
		"TEST@EXAMPLE.COM",
		"Test@Example.Com",
		"tEsT@eXaMpLe.CoM",
	}

	var firstHash string
	for i, email := range emails {
		hash := computeEmailHash(email)
		if i == 0 {
			firstHash = hash
		} else if hash != firstHash {
			t.Errorf("Case sensitivity issue: computeEmailHash(%q) = %q, want %q",
				email, hash, firstHash)
		}
	}
}

func TestComputeEmailHash_WhitespaceInsensitive(t *testing.T) {
	// Test that whitespace variations produce the same hash
	emails := []string{
		"test@example.com",
		" test@example.com",
		"test@example.com ",
		"  test@example.com  ",
		"\ttest@example.com\t",
	}

	var firstHash string
	for i, email := range emails {
		hash := computeEmailHash(email)
		if i == 0 {
			firstHash = hash
		} else if hash != firstHash {
			t.Errorf("Whitespace sensitivity issue: computeEmailHash(%q) = %q, want %q",
				email, hash, firstHash)
		}
	}
}

func TestComputeEmailHash_Deterministic(t *testing.T) {
	// Test that the same email always produces the same hash
	email := "consistent@example.com"

	hash1 := computeEmailHash(email)
	hash2 := computeEmailHash(email)
	hash3 := computeEmailHash(email)

	if hash1 != hash2 || hash2 != hash3 {
		t.Errorf("Hash is not deterministic: got %q, %q, %q", hash1, hash2, hash3)
	}
}

func TestComputeEmailHash_Length(t *testing.T) {
	// SHA-256 produces a 64-character hex string
	email := "test@example.com"
	hash := computeEmailHash(email)

	expectedLength := 64
	if len(hash) != expectedLength {
		t.Errorf("Hash length incorrect: got %d, want %d", len(hash), expectedLength)
	}
}

func TestComputeEmailHash_HexEncoding(t *testing.T) {
	// Test that the hash is a valid hex string
	email := "test@example.com"
	hash := computeEmailHash(email)

	for _, char := range hash {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			t.Errorf("Hash contains non-hex character: %c in %s", char, hash)
		}
	}
}

func BenchmarkComputeEmailHash(b *testing.B) {
	email := "benchmark@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeEmailHash(email)
	}
}

func BenchmarkComputeEmailHash_LongEmail(b *testing.B) {
	email := "very.long.email.address.for.testing.performance.characteristics@subdomain.example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeEmailHash(email)
	}
}
