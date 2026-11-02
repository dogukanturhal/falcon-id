// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestNewEncryptionService(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		wantErr     bool
		expectedErr error
	}{
		{
			name:    "Valid 16-byte key (AES-128)",
			key:     "0123456789abcdef",
			wantErr: false,
		},
		{
			name:    "Valid 24-byte key (AES-192)",
			key:     "0123456789abcdef01234567",
			wantErr: false,
		},
		{
			name:    "Valid 32-byte key (AES-256)",
			key:     "0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
		{
			name:        "Invalid 15-byte key",
			key:         "0123456789abcde",
			wantErr:     true,
			expectedErr: ErrInvalidKeyLength,
		},
		{
			name:        "Invalid 17-byte key",
			key:         "0123456789abcdefg",
			wantErr:     true,
			expectedErr: ErrInvalidKeyLength,
		},
		{
			name:        "Invalid 8-byte key",
			key:         "01234567",
			wantErr:     true,
			expectedErr: ErrInvalidKeyLength,
		},
		{
			name:        "Empty key",
			key:         "",
			wantErr:     true,
			expectedErr: ErrInvalidKeyLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewEncryptionService(tt.key)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewEncryptionService() expected error but got nil")
					return
				}
				if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
					t.Errorf("NewEncryptionService() error = %v, expected %v", err, tt.expectedErr)
				}
				return
			}

			if err != nil {
				t.Errorf("NewEncryptionService() unexpected error = %v", err)
				return
			}

			if service == nil {
				t.Errorf("NewEncryptionService() returned nil service")
				return
			}

			if len(service.key) != len(tt.key) {
				t.Errorf("NewEncryptionService() key length = %d, want %d", len(service.key), len(tt.key))
			}
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		plaintext string
	}{
		{
			name:      "Simple text",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: "Hello, World!",
		},
		{
			name:      "Unicode text",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: "Hello 世界! 🔐",
		},
		{
			name:      "Long text",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100),
		},
		{
			name:      "Special characters",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
		},
		{
			name:      "Empty string",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: "",
		},
		{
			name:      "Single character",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: "x",
		},
		{
			name:      "JSON-like string",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: `{"username":"test","password":"secret123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewEncryptionService(tt.key)
			if err != nil {
				t.Fatalf("NewEncryptionService() error = %v", err)
			}

			// Test Encrypt/Decrypt
			encrypted, err := service.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Empty plaintext should return empty ciphertext
			if tt.plaintext == "" {
				if encrypted != "" {
					t.Errorf("Encrypt('') = %q, want empty string", encrypted)
				}
			} else {
				// Encrypted text should be different from plaintext
				if encrypted == tt.plaintext {
					t.Errorf("Encrypt() returned plaintext unchanged")
				}

				// Encrypted text should be base64 encoded
				if !IsEncrypted(encrypted) {
					t.Errorf("Encrypt() returned non-base64 string: %q", encrypted)
				}
			}

			decrypted, err := service.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptBytes_DecryptBytes_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		plaintext []byte
	}{
		{
			name:      "Simple bytes",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "Binary data",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:      "Empty bytes",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: []byte{},
		},
		{
			name:      "Nil bytes",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: nil,
		},
		{
			name:      "Large byte array",
			key:       "0123456789abcdef0123456789abcdef",
			plaintext: make([]byte, 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewEncryptionService(tt.key)
			if err != nil {
				t.Fatalf("NewEncryptionService() error = %v", err)
			}

			encrypted, err := service.EncryptBytes(tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptBytes() error = %v", err)
			}

			// Empty/nil plaintext should return nil
			if len(tt.plaintext) == 0 {
				if encrypted != nil {
					t.Errorf("EncryptBytes(empty) = %v, want nil", encrypted)
				}
			}

			decrypted, err := service.DecryptBytes(encrypted)
			if err != nil {
				t.Fatalf("DecryptBytes() error = %v", err)
			}

			// Compare byte slices
			if len(decrypted) != len(tt.plaintext) {
				t.Errorf("DecryptBytes() length = %d, want %d", len(decrypted), len(tt.plaintext))
				return
			}

			for i := range tt.plaintext {
				if decrypted[i] != tt.plaintext[i] {
					t.Errorf("DecryptBytes()[%d] = %v, want %v", i, decrypted[i], tt.plaintext[i])
				}
			}
		})
	}
}

func TestDecrypt_ErrorCases(t *testing.T) {
	service, err := NewEncryptionService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
		wantErr    bool
	}{
		{
			name:       "Invalid base64",
			ciphertext: "not-valid-base64!!!",
			wantErr:    true,
		},
		{
			name:       "Valid base64 but too short",
			ciphertext: "YWJj", // "abc" in base64
			wantErr:    true,
		},
		{
			name:       "Valid base64 but invalid ciphertext",
			ciphertext: "YWJjZGVmZ2hpamtsbW5vcA==", // random base64
			wantErr:    true,
		},
		{
			name:       "Empty string",
			ciphertext: "",
			wantErr:    false, // Empty string is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Decrypt(tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptBytes_ErrorCases(t *testing.T) {
	service, err := NewEncryptionService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	tests := []struct {
		name        string
		ciphertext  []byte
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "Too short ciphertext",
			ciphertext:  []byte{0x01, 0x02, 0x03},
			wantErr:     true,
			expectedErr: ErrCiphertextTooShort,
		},
		{
			name:        "Invalid ciphertext",
			ciphertext:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
			wantErr:     true,
			expectedErr: ErrDecryptionFailed,
		},
		{
			name:       "Empty bytes",
			ciphertext: []byte{},
			wantErr:    false, // Empty is allowed
		},
		{
			name:       "Nil bytes",
			ciphertext: nil,
			wantErr:    false, // Nil is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.DecryptBytes(tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("DecryptBytes() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}

func TestDecrypt_WithDifferentKey(t *testing.T) {
	service1, err := NewEncryptionService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	service2, err := NewEncryptionService("fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	plaintext := "Secret message"

	// Encrypt with service1
	encrypted, err := service1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with service2 (different key)
	_, err = service2.Decrypt(encrypted)
	if err == nil {
		t.Errorf("Decrypt() with different key should fail but succeeded")
	}
}

func TestRotateKey(t *testing.T) {
	oldKey := "0123456789abcdef0123456789abcdef"
	newKey := "fedcba9876543210fedcba9876543210"
	plaintext := "Secret data that needs rotation"

	// Encrypt with old key
	oldService, err := NewEncryptionService(oldKey)
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	encrypted, err := oldService.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Rotate to new key
	reencrypted, err := oldService.RotateKey(encrypted, newKey)
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	// Verify we can decrypt with new key
	newService, err := NewEncryptionService(newKey)
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	decrypted, err := newService.Decrypt(reencrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypt() after rotation = %q, want %q", decrypted, plaintext)
	}

	// Verify old service can no longer decrypt the rotated data
	_, err = oldService.Decrypt(reencrypted)
	if err == nil {
		t.Errorf("Decrypt() with old key should fail after rotation")
	}
}

func TestRotateKey_ErrorCases(t *testing.T) {
	service, err := NewEncryptionService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
		newKey     string
		wantErr    bool
	}{
		{
			name:       "Invalid ciphertext",
			ciphertext: "invalid-ciphertext",
			newKey:     "fedcba9876543210fedcba9876543210",
			wantErr:    true,
		},
		{
			name:       "Invalid new key",
			ciphertext: "valid-will-not-be-used",
			newKey:     "too-short",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.RotateKey(tt.ciphertext, tt.newKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RotateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsEncrypted(t *testing.T) {
	// IsEncrypted now uses a reliable magic prefix (EncryptedPrefix = "enc:v1:")
	// rather than a base64 heuristic. Update tests accordingly.
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "Prefixed ciphertext (enc:v1:...)",
			input: EncryptedPrefix + "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
			want:  true,
		},
		{
			name:  "Raw base64 without prefix (pre-migration value)",
			input: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
			want:  false,
		},
		{
			name:  "Short base64 string without prefix",
			input: "YWJj",
			want:  false,
		},
		{
			name:  "Invalid base64 without prefix",
			input: "not-base64-!!!",
			want:  false,
		},
		{
			name:  "Empty string",
			input: "",
			want:  false,
		},
		{
			name:  "Plain text",
			input: "Hello, World!",
			want:  false,
		},
		{
			name:  "Exactly the prefix only",
			input: EncryptedPrefix,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEncrypted(tt.input)
			if got != tt.want {
				t.Errorf("IsEncrypted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncrypt_ProducesUniqueCiphertexts(t *testing.T) {
	service, err := NewEncryptionService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewEncryptionService() error = %v", err)
	}

	plaintext := "Same message encrypted multiple times"

	// Encrypt the same plaintext multiple times
	ciphertexts := make(map[string]bool)
	for i := 0; i < 10; i++ {
		encrypted, err := service.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		if ciphertexts[encrypted] {
			t.Errorf("Encrypt() produced duplicate ciphertext")
		}
		ciphertexts[encrypted] = true

		// Verify each can be decrypted correctly
		decrypted, err := service.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if decrypted != plaintext {
			t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
		}
	}

	if len(ciphertexts) != 10 {
		t.Errorf("Expected 10 unique ciphertexts, got %d", len(ciphertexts))
	}
}

func TestEncryptionService_DifferentKeySizes(t *testing.T) {
	plaintext := "Test message"

	keySizes := []struct {
		name string
		key  string
		bits int
	}{
		{"AES-128", "0123456789abcdef", 128},
		{"AES-192", "0123456789abcdef01234567", 192},
		{"AES-256", "0123456789abcdef0123456789abcdef", 256},
	}

	for _, ks := range keySizes {
		t.Run(ks.name, func(t *testing.T) {
			service, err := NewEncryptionService(ks.key)
			if err != nil {
				t.Fatalf("NewEncryptionService() error = %v", err)
			}

			encrypted, err := service.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			decrypted, err := service.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
			}
		})
	}
}
