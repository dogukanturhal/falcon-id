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
	// StatusPending is a published key that is not yet used for signing; it becomes
	// active once ActivatedAt (the scheduled activation time) has passed.
	StatusPending = "pending"
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
//
// Rotation is publish-before-activate: Rotate inserts the next key as StatusPending
// (served in JWKS, never used for signing). After PublishDelay a single elected
// rotator (advisory lock) promotes it to StatusActive and retires the previous
// active key. Every replica reloads the key set from the store periodically and on
// unknown-kid misses, so all replicas converge on the newest active key.
type KeyManager struct {
	store         keyStore
	encryptionKey []byte // 32-byte AES key for encrypting private keys at rest
	logger        *zap.Logger
	opts          Options
	now           func() time.Time

	mu        sync.RWMutex
	activeKey *cachedKey
	allKeys   map[string]*cachedKey // kid -> cachedKey (pending + active + rotated, minus retired)
	version   uint64                // bumped whenever the visible key set changes

	reloadMu       sync.Mutex // guards lastMissReload
	lastMissReload time.Time
}

type cachedKey struct {
	SigningKey
	privateKey crypto.Signer
	publicKey  crypto.PublicKey
}

// Options tunes the rotation lifecycle. Zero values take the defaults.
type Options struct {
	// PublishDelay is how long a pending key is published before it starts signing.
	// Must exceed the JWKS Cache-Control max-age plus ReloadInterval.
	PublishDelay time.Duration
	// ReloadInterval is how often every replica reloads keys from the store.
	ReloadInterval time.Duration
	// RetireAfter is how long a rotated key stays in JWKS after rotation: at least the
	// longest lifetime of any token it signed plus a margin.
	RetireAfter time.Duration
	// MissReloadInterval rate-limits on-demand reloads triggered by unknown kids.
	MissReloadInterval time.Duration
	// KeyLifetime is the validity of a newly generated key.
	KeyLifetime time.Duration
	// RotationThreshold: rotate when the active key has less than this left.
	RotationThreshold time.Duration
}

// Defaults for Options.
const (
	DefaultPublishDelay       = 75 * time.Minute
	DefaultReloadInterval     = 60 * time.Second
	DefaultRetireAfter        = 24 * time.Hour
	DefaultMissReloadInterval = 10 * time.Second
	DefaultKeyLifetime        = 90 * 24 * time.Hour
	DefaultRotationThreshold  = 7 * 24 * time.Hour
)

// WithDefaults fills zero fields with the package defaults.
func (o Options) WithDefaults() Options {
	if o.PublishDelay <= 0 {
		o.PublishDelay = DefaultPublishDelay
	}
	if o.ReloadInterval <= 0 {
		o.ReloadInterval = DefaultReloadInterval
	}
	if o.RetireAfter <= 0 {
		o.RetireAfter = DefaultRetireAfter
	}
	if o.MissReloadInterval <= 0 {
		o.MissReloadInterval = DefaultMissReloadInterval
	}
	if o.KeyLifetime <= 0 {
		o.KeyLifetime = DefaultKeyLifetime
	}
	if o.RotationThreshold <= 0 {
		o.RotationThreshold = DefaultRotationThreshold
	}
	return o
}

// NewKeyManager creates a new KeyManager backed by PostgreSQL.
// encryptionKey must be exactly 32 bytes (AES-256).
func NewKeyManager(pool *pgxpool.Pool, encryptionKey []byte, logger *zap.Logger) (*KeyManager, error) {
	return newKeyManager(newPGStore(pool), encryptionKey, logger)
}

func newKeyManager(store keyStore, encryptionKey []byte, logger *zap.Logger) (*KeyManager, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(encryptionKey))
	}

	return &KeyManager{
		store:         store,
		encryptionKey: encryptionKey,
		logger:        logger,
		opts:          Options{}.WithDefaults(),
		now:           time.Now,
		allKeys:       make(map[string]*cachedKey),
	}, nil
}

// Configure overrides the rotation options. Call before Initialize.
func (km *KeyManager) Configure(opts Options) {
	km.opts = opts.WithDefaults()
}

// ReloadInterval returns the configured periodic reload interval.
func (km *KeyManager) ReloadInterval() time.Duration { return km.opts.ReloadInterval }

// Version changes whenever the visible key set (including statuses) changes.
// Caches of derived documents (JWKS) key off it.
func (km *KeyManager) Version() uint64 {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.version
}

// Initialize loads existing keys from the store and bootstraps the first key if none
// exist. Bootstrap is serialized across replicas by the rotation lock.
func (km *KeyManager) Initialize(ctx context.Context) error {
	if err := km.Reload(ctx); err != nil {
		return fmt.Errorf("failed to load signing keys: %w", err)
	}

	deadline := km.now().Add(15 * time.Second)
	for {
		if _, _, err := km.ActiveKey(); err == nil {
			break
		}
		acquired, err := km.store.WithRotationLock(ctx, func(ctx context.Context) error {
			if err := km.Reload(ctx); err != nil {
				return err
			}
			if _, _, aerr := km.ActiveKey(); aerr == nil {
				return nil // another replica bootstrapped meanwhile
			}
			km.logger.Info("No active signing key found, generating new RS256 key pair")
			return km.insertNewKey(ctx, AlgorithmRS256, StatusActive, km.now())
		})
		if err != nil {
			return fmt.Errorf("failed to generate initial signing key: %w", err)
		}
		if !acquired {
			if km.now().After(deadline) {
				return fmt.Errorf("timed out waiting for another replica to bootstrap the signing key")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
			if err := km.Reload(ctx); err != nil {
				return err
			}
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

// PublicKey returns the public key for a given key ID. On an unknown kid it reloads
// the key set from the store (rate-limited, once per MissReloadInterval) and retries,
// so a key published by another replica is found without waiting for the periodic
// reload.
func (km *KeyManager) PublicKey(kid string) (crypto.PublicKey, error) {
	if pub, ok := km.lookupPublic(kid); ok {
		return pub, nil
	}
	if km.reloadOnMiss() {
		if pub, ok := km.lookupPublic(kid); ok {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("key not found: %s", kid)
}

func (km *KeyManager) lookupPublic(kid string) (crypto.PublicKey, bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	ck, ok := km.allKeys[kid]
	if !ok || ck.Status == StatusRevoked {
		return nil, false
	}
	return ck.publicKey, true
}

// reloadOnMiss reloads from the store unless one ran within MissReloadInterval.
// Reports whether a reload actually succeeded.
func (km *KeyManager) reloadOnMiss() bool {
	if km.store == nil {
		return false
	}
	km.reloadMu.Lock()
	if now := km.now(); !km.lastMissReload.IsZero() && now.Sub(km.lastMissReload) < km.opts.MissReloadInterval {
		km.reloadMu.Unlock()
		return false
	}
	km.lastMissReload = km.now()
	km.reloadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := km.Reload(ctx); err != nil {
		km.logger.Warn("On-demand signing key reload failed", zap.Error(err))
		return false
	}
	return true
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

// Reload re-reads the key set from the store and swaps it in. The active key is the
// newest key in state active; pending keys are published but never sign. Rotated keys
// older than RetireAfter and revoked keys drop out of the set.
func (km *KeyManager) Reload(ctx context.Context) error {
	if km.store == nil {
		return nil
	}
	rows, err := km.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to query signing keys: %w", err)
	}

	km.mu.RLock()
	old := km.allKeys
	prevActive := km.activeKey
	km.mu.RUnlock()

	now := km.now()
	next := make(map[string]*cachedKey, len(rows))
	var active *cachedKey
	for _, k := range rows {
		if k.Status == StatusRevoked {
			continue
		}
		if k.Status == StatusRotated && k.RotatedAt != nil && now.Sub(*k.RotatedAt) > km.opts.RetireAfter {
			continue
		}
		var ck *cachedKey
		if prev, ok := old[k.KeyID]; ok {
			cp := *prev // reuse decrypted material, refresh state
			cp.SigningKey = k
			ck = &cp
		} else {
			ck, err = km.decryptAndCache(k)
			if err != nil {
				km.logger.Warn("Failed to decrypt signing key, skipping",
					zap.String("key_id", k.KeyID), zap.Error(err))
				continue
			}
		}
		next[k.KeyID] = ck
		if k.Status == StatusActive && (active == nil || k.ActivatedAt.Before(active.ActivatedAt)) {
			active = ck
		}
	}
	if active == nil && prevActive != nil {
		// Keep the previous signer on a partial/failed view, but only while it is
		// still loaded as active, or rotated for less than RetireAfter/2; a revoked,
		// missing or long-rotated key must not keep signing, so the caller mints a new one.
		if ck, ok := next[prevActive.KeyID]; ok {
			youngRotated := ck.Status == StatusRotated && ck.RotatedAt != nil &&
				now.Sub(*ck.RotatedAt) < km.opts.RetireAfter/2
			if ck.Status == StatusActive || youngRotated {
				active = ck
			}
		}
	}

	km.mu.Lock()
	changed := len(old) != len(next) || (km.activeKey == nil) != (active == nil) ||
		(active != nil && km.activeKey != nil && active.KeyID != km.activeKey.KeyID)
	if !changed {
		for kid, ck := range next {
			if o, ok := old[kid]; !ok || o.Status != ck.Status {
				changed = true
				break
			}
		}
	}
	km.allKeys = next
	km.activeKey = active
	if changed {
		km.version++
	}
	km.mu.Unlock()
	return nil
}

// Maintain runs one lifecycle step on the elected rotator: it reloads, activates a
// pending key whose publish delay has elapsed, and otherwise starts a rotation when
// the active key is near expiry. Replicas that do not win the advisory lock only
// reload. Safe to call concurrently from every replica.
func (km *KeyManager) Maintain(ctx context.Context) error {
	if km.store == nil {
		return nil
	}
	acquired, err := km.store.WithRotationLock(ctx, func(ctx context.Context) error {
		// Re-check state inside the lock: another replica may have rotated already.
		if err := km.Reload(ctx); err != nil {
			return err
		}
		return km.maintainLocked(ctx, false)
	})
	if err != nil {
		return err
	}
	if !acquired {
		return km.Reload(ctx)
	}
	return nil
}

// Rotate forces a rotation: it publishes a new pending key (idempotent while one is
// already pending). The key starts signing after PublishDelay via Maintain.
func (km *KeyManager) Rotate(ctx context.Context) error {
	acquired, err := km.store.WithRotationLock(ctx, func(ctx context.Context) error {
		if err := km.Reload(ctx); err != nil {
			return err
		}
		return km.maintainLocked(ctx, true)
	})
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("another replica is rotating signing keys")
	}
	return nil
}

// maintainLocked must run holding the rotation lock after a fresh Reload.
func (km *KeyManager) maintainLocked(ctx context.Context, force bool) error {
	now := km.now()

	km.mu.RLock()
	var pending *cachedKey
	for _, ck := range km.allKeys {
		if ck.Status == StatusPending && (pending == nil || ck.ActivatedAt.After(pending.ActivatedAt)) {
			pending = ck
		}
	}
	active := km.activeKey
	km.mu.RUnlock()

	if pending != nil {
		if now.Before(pending.ActivatedAt) {
			return nil // still in its publish window
		}
		return km.activate(ctx, pending, now)
	}

	if active == nil {
		km.logger.Warn("No active signing key during rotation check, generating one")
		return km.insertNewKey(ctx, AlgorithmRS256, StatusActive, now)
	}
	if active.Status != StatusActive {
		km.logger.Error("No rotation while signing with a non-active key, check the encryption key consistency across replicas",
			zap.String("kid", active.KeyID), zap.String("status", active.Status))
		return nil
	}
	if !force && active.ExpiresAt.Sub(now) > km.opts.RotationThreshold {
		return nil
	}

	km.logger.Info("Publishing next signing key (pending)",
		zap.String("active_kid", active.KeyID),
		zap.Time("active_expires_at", active.ExpiresAt),
		zap.Duration("publish_delay", km.opts.PublishDelay),
	)
	return km.insertNewKey(ctx, AlgorithmRS256, StatusPending, now.Add(km.opts.PublishDelay))
}

// activate promotes pending to active and rotates every other active key.
func (km *KeyManager) activate(ctx context.Context, pending *cachedKey, now time.Time) error {
	km.mu.RLock()
	var retire []uuid.UUID
	var oldKIDs []string
	for _, ck := range km.allKeys {
		if ck.Status == StatusActive && ck.ID != pending.ID {
			retire = append(retire, ck.ID)
			oldKIDs = append(oldKIDs, ck.KeyID)
		}
	}
	km.mu.RUnlock()

	if err := km.store.Promote(ctx, pending.ID, retire, now); err != nil {
		return fmt.Errorf("failed to activate signing key: %w", err)
	}
	if err := km.Reload(ctx); err != nil {
		return err
	}
	km.logger.Info("Activated signing key",
		zap.String("kid", pending.KeyID),
		zap.Strings("rotated_kids", oldKIDs),
	)
	return nil
}

// RevokeKey marks a key as revoked (removed from JWKS, tokens signed with it become invalid).
func (km *KeyManager) RevokeKey(ctx context.Context, kid string) error {
	if err := km.store.Revoke(ctx, kid); err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}
	km.logger.Info("Revoked signing key", zap.String("kid", kid))
	return km.Reload(ctx)
}

// ListKeys returns all signing keys (for admin UI).
func (km *KeyManager) ListKeys(ctx context.Context) ([]SigningKey, error) {
	return km.store.Load(ctx)
}

// insertNewKey generates a key pair, encrypts the private key and stores it with the
// given status; activatedAt is the (scheduled) activation time. The local view is
// refreshed by reloading from the store.
func (km *KeyManager) insertNewKey(ctx context.Context, algorithm, status string, activatedAt time.Time) error {
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

	now := km.now()
	sk := SigningKey{
		ID:            uuid.New(),
		Algorithm:     algorithm,
		PrivateKeyEnc: encrypted,
		PublicKeyPEM:  string(pubPEM),
		KeyID:         kid,
		Status:        status,
		ActivatedAt:   activatedAt,
		ExpiresAt:     activatedAt.Add(km.opts.KeyLifetime),
		CreatedAt:     now,
	}
	if err := km.store.Insert(ctx, sk); err != nil {
		return fmt.Errorf("failed to store signing key: %w", err)
	}

	km.logger.Info("Generated and stored new signing key",
		zap.String("kid", kid),
		zap.String("algorithm", algorithm),
		zap.String("status", status),
		zap.Time("activated_at", sk.ActivatedAt),
		zap.Time("expires_at", sk.ExpiresAt),
	)
	return km.Reload(ctx)
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
