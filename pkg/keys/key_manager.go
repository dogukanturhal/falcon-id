// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keys provides asymmetric JWT key management with automated rotation.
// It manages RSA/ECDSA key pairs stored in PostgreSQL, supporting key generation,
// encryption at rest, rotation, and JWKS document building.
package keys

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// SigningKey represents a signing key stored in the database.
type SigningKey struct {
	ID            uuid.UUID  `db:"id"`
	Algorithm     string     `db:"algorithm"`
	PrivateKeyEnc []byte     `db:"private_key_enc"`
	PublicKeyPEM  string     `db:"public_key_pem"`
	KeyID         string     `db:"key_id"`
	Status        string     `db:"status"`
	ActivatedAt   time.Time  `db:"activated_at"`
	RotatedAt     *time.Time `db:"rotated_at"`
	ExpiresAt     time.Time  `db:"expires_at"`
	CreatedAt     time.Time  `db:"created_at"`
}

const (
	// StatusActive is an exported identifier.
	StatusActive = "active"
	// StatusRotated is an exported identifier.
	StatusRotated = "rotated"
	// StatusRevoked is an exported identifier.
	StatusRevoked = "revoked"

	// AlgorithmRS256 is an exported identifier.
	AlgorithmRS256 = "RS256"
	// AlgorithmES256 is an exported identifier.
	AlgorithmES256 = "ES256"
)

// KeyManager manages signing keys for JWT token operations.
type KeyManager struct {
	pool          *pgxpool.Pool
	encryptionKey []byte // 32-byte AES key for encrypting private keys at rest
	logger        *zap.Logger

	mu        sync.RWMutex
	activeKey *cachedKey
	allKeys   map[string]*cachedKey // kid -> cachedKey (active + rotated for validation)
}

type cachedKey struct {
	SigningKey
	privateKey crypto.Signer
	publicKey  crypto.PublicKey
}

// NewKeyManager creates a new KeyManager.
// encryptionKey must be exactly 32 bytes (AES-256).
func NewKeyManager(pool *pgxpool.Pool, encryptionKey []byte, logger *zap.Logger) (*KeyManager, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(encryptionKey))
	}

	km := &KeyManager{
		pool:          pool,
		encryptionKey: encryptionKey,
		logger:        logger,
		allKeys:       make(map[string]*cachedKey),
	}

	return km, nil
}

// Initialize loads existing keys from the database or generates a new one if none exist.
func (km *KeyManager) Initialize(ctx context.Context) error {
	keys, err := km.loadKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to load signing keys: %w", err)
	}

	km.mu.Lock()
	// Note: mu.Unlock is called explicitly below (not deferred) to avoid deadlock
	// when generateAndStore needs to acquire the same lock.

	for _, k := range keys {
		ck, err := km.decryptAndCache(k)
		if err != nil {
			km.logger.Warn("Failed to decrypt signing key, skipping",
				zap.String("key_id", k.KeyID),
				zap.Error(err),
			)
			continue
		}
		km.allKeys[k.KeyID] = ck
		if k.Status == StatusActive {
			km.activeKey = ck
		}
	}

	// If no active key exists, generate one (release lock first to avoid deadlock
	// since generateAndStore also acquires km.mu)
	needsGeneration := km.activeKey == nil
	km.mu.Unlock()

	if needsGeneration {
		km.logger.Info("No active signing key found, generating new RS256 key pair")
		if err := km.generateAndStore(ctx, AlgorithmRS256, 90*24*time.Hour); err != nil {
			return fmt.Errorf("failed to generate initial signing key: %w", err)
		}
	}

	km.mu.RLock()
	km.logger.Info("Key manager initialized",
		zap.Int("total_keys", len(km.allKeys)),
		zap.String("active_kid", km.activeKey.KeyID),
	)
	km.mu.RUnlock()

	return nil
}

// ActiveKey returns the current active signing key's private key and key ID.
func (km *KeyManager) ActiveKey() (crypto.Signer, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.activeKey == nil {
		return nil, "", fmt.Errorf("no active signing key available")
	}
	return km.activeKey.privateKey, km.activeKey.KeyID, nil
}

// PublicKey returns the public key for a given key ID.
func (km *KeyManager) PublicKey(kid string) (crypto.PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	ck, ok := km.allKeys[kid]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", kid)
	}
	return ck.publicKey, nil
}

// AllPublicKeys returns all active and rotated public keys (for JWKS).
func (km *KeyManager) AllPublicKeys() []PublicKeyInfo {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var result []PublicKeyInfo
	for _, ck := range km.allKeys {
		if ck.Status == StatusRevoked {
			continue
		}
		result = append(result, PublicKeyInfo{
			KeyID:     ck.KeyID,
			Algorithm: ck.Algorithm,
			PublicKey: ck.publicKey,
			Status:    ck.Status,
		})
	}
	return result
}

// PublicKeyInfo holds public key metadata for JWKS building.
type PublicKeyInfo struct {
	KeyID     string
	Algorithm string
	PublicKey crypto.PublicKey
	Status    string
}

// Rotate generates a new active key and marks the current active key as rotated.
func (km *KeyManager) Rotate(ctx context.Context) error {
	km.mu.Lock()
	currentActive := km.activeKey
	km.mu.Unlock()

	if currentActive != nil {
		now := time.Now()
		_, err := km.pool.Exec(ctx,
			`UPDATE iam_signing_keys SET status = $1, rotated_at = $2 WHERE id = $3`,
			StatusRotated, now, currentActive.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to mark current key as rotated: %w", err)
		}

		km.mu.Lock()
		currentActive.Status = StatusRotated
		currentActive.RotatedAt = &now
		km.mu.Unlock()

		km.logger.Info("Rotated signing key",
			zap.String("old_kid", currentActive.KeyID),
		)
	}

	// Generate new active key
	if err := km.generateAndStore(ctx, AlgorithmRS256, 90*24*time.Hour); err != nil {
		return fmt.Errorf("failed to generate new signing key: %w", err)
	}

	return nil
}

// RevokeKey marks a key as revoked (removed from JWKS, tokens signed with it become invalid).
func (km *KeyManager) RevokeKey(ctx context.Context, kid string) error {
	_, err := km.pool.Exec(ctx,
		`UPDATE iam_signing_keys SET status = $1 WHERE key_id = $2`,
		StatusRevoked, kid,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}

	km.mu.Lock()
	if ck, ok := km.allKeys[kid]; ok {
		ck.Status = StatusRevoked
	}
	km.mu.Unlock()

	km.logger.Info("Revoked signing key", zap.String("kid", kid))
	return nil
}

// ListKeys returns all signing keys (for admin UI).
func (km *KeyManager) ListKeys(ctx context.Context) ([]SigningKey, error) {
	return km.loadKeys(ctx)
}

// generateAndStore creates a new key pair, encrypts the private key, and stores it.
func (km *KeyManager) generateAndStore(ctx context.Context, algorithm string, lifetime time.Duration) error {
	var privateKey crypto.Signer
	var publicKey crypto.PublicKey
	var err error

	switch algorithm {
	case AlgorithmRS256:
		rsaKey, genErr := rsa.GenerateKey(rand.Reader, 2048)
		if genErr != nil {
			return fmt.Errorf("failed to generate RSA key: %w", genErr)
		}
		privateKey = rsaKey
		publicKey = &rsaKey.PublicKey
	case AlgorithmES256:
		ecKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return fmt.Errorf("failed to generate ECDSA key: %w", genErr)
		}
		privateKey = ecKey
		publicKey = &ecKey.PublicKey
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Compute key ID (SHA-256 thumbprint of public key)
	kid, err := KeyIDFromPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to compute key ID: %w", err)
	}

	// Encode public key to PEM
	pubPEM, err := marshalPublicKeyPEM(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encrypt private key at rest
	privPEM, err := marshalPrivateKeyPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	encrypted, err := EncryptPrivateKey(privPEM, km.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	now := time.Now()
	sk := SigningKey{
		ID:            uuid.New(),
		Algorithm:     algorithm,
		PrivateKeyEnc: encrypted,
		PublicKeyPEM:  string(pubPEM),
		KeyID:         kid,
		Status:        StatusActive,
		ActivatedAt:   now,
		ExpiresAt:     now.Add(lifetime),
		CreatedAt:     now,
	}

	_, err = km.pool.Exec(ctx,
		`INSERT INTO iam_signing_keys (id, algorithm, private_key_enc, public_key_pem, key_id, status, activated_at, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sk.ID, sk.Algorithm, sk.PrivateKeyEnc, sk.PublicKeyPEM, sk.KeyID, sk.Status, sk.ActivatedAt, sk.ExpiresAt, sk.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store signing key: %w", err)
	}

	ck := &cachedKey{
		SigningKey: sk,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	km.mu.Lock()
	km.activeKey = ck
	km.allKeys[kid] = ck
	km.mu.Unlock()

	km.logger.Info("Generated and stored new signing key",
		zap.String("kid", kid),
		zap.String("algorithm", algorithm),
		zap.Time("expires_at", sk.ExpiresAt),
	)

	return nil
}

// loadKeys reads all signing keys from the database.
func (km *KeyManager) loadKeys(ctx context.Context) ([]SigningKey, error) {
	rows, err := km.pool.Query(ctx,
		`SELECT id, algorithm, private_key_enc, public_key_pem, key_id, status, activated_at, rotated_at, expires_at, created_at
		 FROM iam_signing_keys
		 WHERE status IN ($1, $2)
		 ORDER BY activated_at DESC`,
		StatusActive, StatusRotated,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query signing keys: %w", err)
	}
	defer rows.Close()

	var keys []SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PrivateKeyEnc, &k.PublicKeyPEM, &k.KeyID, &k.Status, &k.ActivatedAt, &k.RotatedAt, &k.ExpiresAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan signing key: %w", err)
		}
		keys = append(keys, k)
	}

	return keys, rows.Err()
}

// decryptAndCache decrypts a signing key and creates a cached key.
func (km *KeyManager) decryptAndCache(sk SigningKey) (*cachedKey, error) {
	privPEM, err := DecryptPrivateKey(sk.PrivateKeyEnc, km.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	var privateKey crypto.Signer
	var publicKey crypto.PublicKey

	switch sk.Algorithm {
	case AlgorithmRS256:
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
			}
			rsaKey2, ok := keyIface.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS8 key is not RSA")
			}
			rsaKey = rsaKey2
		}
		privateKey = rsaKey
		publicKey = &rsaKey.PublicKey
	case AlgorithmES256:
		ecKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
			}
			ecKey2, ok := keyIface.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS8 key is not ECDSA")
			}
			ecKey = ecKey2
		}
		privateKey = ecKey
		publicKey = &ecKey.PublicKey
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", sk.Algorithm)
	}

	return &cachedKey{
		SigningKey: sk,
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// KeyIDFromPublicKey computes a key ID (kid) from a public key using SHA-256 thumbprint.
func KeyIDFromPublicKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:12]), nil
}

// EncryptPrivateKey encrypts a private key PEM using AES-256-GCM.
func EncryptPrivateKey(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptPrivateKey decrypts a private key PEM encrypted with AES-256-GCM.
func DecryptPrivateKey(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// marshalPublicKeyPEM encodes a public key to PEM format.
func marshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// marshalPrivateKeyPEM encodes a private key to PEM format.
func marshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}
