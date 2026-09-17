// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// EncryptedPrefix is prepended to ciphertext produced by Encrypt (v1 — master key).
// It includes a version identifier so future key rotations / per-tenant DEKs can
// select the correct decryption key. Old values without this prefix are handled
// with backward-compatible decryption.
const EncryptedPrefix = "enc:v1:"

// EncryptedPrefixV2 marks ciphertext encrypted with a per-tenant HKDF-derived
// DEK (`DeriveTenantKey(tenantID)`). The v2 framing means:
//
//   - One leaked DEK does not expose other tenants' PII (blast-radius reduction
//     mandated by SOC 2 CC6.1 and ISO 27018 §8.2.4).
//   - Backward-compatible: v1 ciphertext continues to decrypt with the master
//     key; new writes use v2. Lazy re-encryption happens on the next legitimate
//     UPDATE — no big-bang migration required.
//   - Tenant key derivation is deterministic (HKDF-SHA256 with
//     "hexxlock-tenant-encryption:<tenant-uuid>" info string) — same tenant_id
//     always yields the same DEK from the same master key, so backups + replicas
//     decrypt without coordination.
const EncryptedPrefixV2 = "enc:v2:"

// EncryptionService handles AES-GCM encryption for secrets at rest
type EncryptionService struct {
	key []byte
}

var (
	// ErrInvalidKeyLength is returned when the key length is not 16, 24, or 32 bytes
	ErrInvalidKeyLength = errors.New("encryption key must be 16, 24, or 32 bytes")
	// ErrCiphertextTooShort is returned when the ciphertext is too short
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	// ErrDecryptionFailed is returned when decryption fails
	ErrDecryptionFailed = errors.New("decryption failed")
)

// NewEncryptionService creates a new encryption service
// key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
func NewEncryptionService(key string) (*EncryptionService, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return nil, ErrInvalidKeyLength
	}
	return &EncryptionService{key: keyBytes}, nil
}

// Encrypt encrypts plaintext using AES-GCM and returns a prefixed, base64-encoded ciphertext.
// The format is: EncryptedPrefix + base64(nonce+ciphertext).
// The prefix includes a version tag (v1) to support future key rotation.
func (e *EncryptionService) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	encrypted, err := e.EncryptBytes([]byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("Encrypt: EncryptBytes failed: %w", err)
	}
	return EncryptedPrefix + base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts a ciphertext produced by Encrypt.
// It strips the EncryptedPrefix (backward compatible: values without the prefix
// are still attempted as raw base64 to support pre-migration data).
func (e *EncryptionService) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Strip version prefix if present (forward path); fall back for pre-migration values.
	raw := strings.TrimPrefix(ciphertext, EncryptedPrefix)

	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("Decrypt: base64 decode failed: %w", err)
	}

	decrypted, err := e.DecryptBytes(data)
	if err != nil {
		return "", fmt.Errorf("Decrypt: DecryptBytes failed: %w", err)
	}
	return string(decrypted), nil
}

// EncryptBytes encrypts byte data using AES-GCM
func (e *EncryptionService) EncryptBytes(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("EncryptBytes: NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("EncryptBytes: NewGCM failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("EncryptBytes: %w", err)
	}

	// Seal appends the encrypted data to the nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptBytes decrypts byte data using AES-GCM
func (e *EncryptionService) DecryptBytes(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("DecryptBytes: NewCipher failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("DecryptBytes: NewGCM failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertextData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptStringInPlace decrypts a value-style *string PII field in place.
// No-op when the receiver, the pointer, or the dereferenced value is empty.
// Used by repositories that JOIN iam_users and need to decrypt fields
// like email after scanning into a non-pointer struct field.
//
// The audit-trail use case is: avoid the dangerous "skip decrypt and ship
// ciphertext to the API response" pattern that leaks `enc:v1:base64` to
// admin UIs (members lists, impersonation views, role membership).
func (e *EncryptionService) DecryptStringInPlace(field *string) error {
	if e == nil || field == nil || *field == "" {
		return nil
	}
	decrypted, err := e.Decrypt(*field)
	if err != nil {
		return err
	}
	*field = decrypted
	return nil
}

// DecryptStringPtr decrypts a pointer-style **string PII field in place.
// No-op when the receiver, the outer pointer, the inner pointer, or the
// dereferenced value is empty. Used for nullable PII columns (first_name,
// last_name, display_name) which are stored as *string on the model side.
func (e *EncryptionService) DecryptStringPtr(field **string) error {
	if e == nil || field == nil || *field == nil || **field == "" {
		return nil
	}
	decrypted, err := e.Decrypt(**field)
	if err != nil {
		return err
	}
	*field = &decrypted
	return nil
}

// RotateKey re-encrypts data with a new key
// Returns the re-encrypted data and any error
func (e *EncryptionService) RotateKey(ciphertext string, newKey string) (string, error) {
	// Decrypt with current key
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("RotateKey: Decrypt failed: %w", err)
	}

	// Create new encryption service with new key
	newService, err := NewEncryptionService(newKey)
	if err != nil {
		return "", fmt.Errorf("RotateKey: NewEncryptionService failed: %w", err)
	}

	// Encrypt with new key
	return newService.Encrypt(plaintext)
}

// IsEncrypted reports whether s was produced by Encrypt (i.e., has the versioned prefix).
// This is a reliable check based on the magic prefix rather than a base64 heuristic.
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, EncryptedPrefix)
}

// DeriveRealmKey derives a realm-specific encryption key from the base key using
// HKDF-SHA256. Each realm gets a unique key so that data encrypted for one realm
// cannot be decrypted with another realm's key.
//
// The info string bound into HKDF is "hexxlock-realm-encryption:<realm-uuid>",
// making derived keys both domain-separated and deterministic — the same realm ID
// always yields the same derived key given the same base key.
//
// When realmID is uuid.Nil (the default realm), the base key is returned unchanged
// for backward compatibility with data that was encrypted before per-realm keys were
// introduced.
func (e *EncryptionService) DeriveRealmKey(realmID uuid.UUID) (*EncryptionService, error) {
	// uuid.Nil (all-zero) signals the legacy/default realm; reuse the base key so
	// existing encrypted values remain decryptable without re-encryption.
	if realmID == uuid.Nil {
		keyCopy := make([]byte, len(e.key))
		copy(keyCopy, e.key)
		return &EncryptionService{key: keyCopy}, nil
	}

	// HKDF context string: domain label + realm UUID. This ensures keys derived for
	// different purposes or different realms are cryptographically independent.
	info := []byte("hexxlock-realm-encryption:" + realmID.String())

	// salt=nil is explicitly permitted by RFC 5869 §2.2; HKDF will substitute a
	// zero-filled byte string of HashLen length, which is safe and still deterministic.
	hkdfReader := hkdf.New(sha256.New, e.key, nil, info)

	derivedKey := make([]byte, len(e.key))
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("DeriveRealmKey: HKDF derivation failed: %w", err)
	}

	return &EncryptionService{key: derivedKey}, nil
}

// EncryptForTenant encrypts plaintext using a per-tenant HKDF-derived DEK and
// stamps the result with the v2 framing prefix. Subsequent DecryptForTenant
// (or auto-detecting Decrypt) calls on the same tenantID + same base key
// recover the plaintext.
//
// Compared to base Encrypt:
//   - Each tenant has its own DEK, so a compromised DEK has tenant-bounded
//     blast radius (SOC 2 CC6.1, ISO 27018 §8.2.4).
//   - Forward-compatible: future v3+ formats can swap derivation strings.
//   - Empty plaintext returns "" — no envelope for genuinely-empty values.
func (e *EncryptionService) EncryptForTenant(tenantID uuid.UUID, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	tenantEnc, err := e.DeriveTenantKey(tenantID)
	if err != nil {
		return "", fmt.Errorf("EncryptForTenant: derive key: %w", err)
	}
	encrypted, err := tenantEnc.EncryptBytes([]byte(plaintext))
	if err != nil {
		return "", fmt.Errorf("EncryptForTenant: EncryptBytes failed: %w", err)
	}
	return EncryptedPrefixV2 + base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptForTenant decrypts ciphertext, auto-detecting the v1/v2 framing:
//
//   - v2 prefix → derive tenant key, decrypt
//   - v1 prefix or no prefix → fall through to base master-key Decrypt for
//     backward compatibility with pre-migration data
//
// Lazy migration: callers that read a v1 row and rewrite with EncryptForTenant
// promote that row to v2 on the next write. No big-bang migration needed.
//
// Failure mode: a v1 ciphertext that was actually encrypted under a DIFFERENT
// master key (e.g. rotated) returns ErrDecryptionFailed — callers must handle
// this as data-corruption rather than retry under a different key (RotateKey
// is the supported path for master-key rotation).
func (e *EncryptionService) DecryptForTenant(tenantID uuid.UUID, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if strings.HasPrefix(ciphertext, EncryptedPrefixV2) {
		tenantEnc, err := e.DeriveTenantKey(tenantID)
		if err != nil {
			return "", fmt.Errorf("DecryptForTenant: derive key: %w", err)
		}
		raw := strings.TrimPrefix(ciphertext, EncryptedPrefixV2)
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", fmt.Errorf("DecryptForTenant: base64 decode: %w", err)
		}
		decrypted, err := tenantEnc.DecryptBytes(data)
		if err != nil {
			return "", fmt.Errorf("DecryptForTenant: %w", err)
		}
		return string(decrypted), nil
	}
	// v1 or legacy: fall through to master-key decryption.
	return e.Decrypt(ciphertext)
}

// DeriveTenantKey derives a tenant-specific encryption key from the base key
// using HKDF-SHA256. Each tenant gets a unique key so that a compromised
// tenant key does not expose other tenants' secrets (blast radius reduction).
//
// The info string is "hexxlock-tenant-encryption:<tenant-uuid>", making keys
// domain-separated and deterministic. When tenantID is uuid.Nil, the base key
// is returned unchanged for backward compatibility.
func (e *EncryptionService) DeriveTenantKey(tenantID uuid.UUID) (*EncryptionService, error) {
	if tenantID == uuid.Nil {
		keyCopy := make([]byte, len(e.key))
		copy(keyCopy, e.key)
		return &EncryptionService{key: keyCopy}, nil
	}

	info := []byte("hexxlock-tenant-encryption:" + tenantID.String())
	hkdfReader := hkdf.New(sha256.New, e.key, nil, info)

	derivedKey := make([]byte, len(e.key))
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("DeriveTenantKey: HKDF derivation failed: %w", err)
	}

	return &EncryptionService{key: derivedKey}, nil
}
