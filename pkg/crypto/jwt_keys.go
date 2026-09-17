// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// JWTKeyProvider holds the RSA key pair used for RS256 JWT signing and a stable key ID.
// The key ID is derived from the SHA-256 hash of the DER-encoded public key so that it
// is deterministic across restarts when the same private key is configured.
type JWTKeyProvider struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	ephemeral  bool // true when the key was generated at startup (no persistence)
}

// NewJWTKeyProvider loads an RSA key pair from environment variables or files and
// returns a ready-to-use provider.
//
// Environment variable resolution order:
//  1. JWT_PRIVATE_KEY       — PEM-encoded private key inline
//  2. JWT_PRIVATE_KEY_FILE  — path to a PEM-encoded private key file
//  3. (fallback)            — ephemeral 2048-bit key generated at startup
//
// The JWT_PUBLIC_KEY / JWT_PUBLIC_KEY_FILE variables are optional; when omitted the
// public key is derived from the private key.
//
// When JWT_KEY_ID is set it overrides the derived key ID, which is useful for key
// rotation scenarios where the operator assigns explicit IDs.
//
// The logger parameter is unused by this constructor: whether an ephemeral key is
// actually in effect depends on whether a KeyManager is later wired, which this
// function has no visibility into. Callers must inspect IsEphemeral() themselves,
// once the KeyManager decision is known, and log accordingly (see cmd/services.go).
// Pass nil; kept for call-site compatibility.
func NewJWTKeyProvider(logger *zap.Logger, explicitKeyID string) (*JWTKeyProvider, error) {
	privateKey, err := loadPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("jwt_keys: load private key: %w", err)
	}

	var ephemeral bool
	if privateKey == nil {
		// No key configured — generate an ephemeral key pair.
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("jwt_keys: generate ephemeral RSA key: %w", err)
		}
		ephemeral = true
	}

	// Derive the public key. Allow an explicit public key to override (e.g. when only
	// the public half is stored in the process, such as in a read-replica node).
	publicKey, err := loadPublicKey()
	if err != nil {
		return nil, fmt.Errorf("jwt_keys: load public key: %w", err)
	}
	if publicKey == nil {
		publicKey = &privateKey.PublicKey
	}

	keyID := explicitKeyID
	if keyID == "" {
		keyID = deriveKeyID(publicKey)
	}

	return &JWTKeyProvider{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		ephemeral:  ephemeral,
	}, nil
}

// PrivateKey returns the RSA private key for signing.
func (p *JWTKeyProvider) PrivateKey() *rsa.PrivateKey {
	return p.privateKey
}

// PublicKey returns the RSA public key for verification.
func (p *JWTKeyProvider) PublicKey() *rsa.PublicKey {
	return p.publicKey
}

// KeyID returns the key ID to embed in JWT headers (kid claim).
func (p *JWTKeyProvider) KeyID() string {
	return p.keyID
}

// IsEphemeral reports whether the key was generated at startup rather than loaded from
// a persistent store. Callers may use this to emit operational warnings.
func (p *JWTKeyProvider) IsEphemeral() bool {
	return p.ephemeral
}

// ==================== private helpers ====================

// loadPrivateKey attempts to load a PKCS1 or PKCS8 RSA private key from the
// JWT_PRIVATE_KEY env var (inline PEM) or JWT_PRIVATE_KEY_FILE (path). Returns nil
// when neither variable is set, signalling that an ephemeral key should be generated.
func loadPrivateKey() (*rsa.PrivateKey, error) {
	pemData := os.Getenv("JWT_PRIVATE_KEY")
	if pemData == "" {
		if path := os.Getenv("JWT_PRIVATE_KEY_FILE"); path != "" {
			data, err := os.ReadFile(path) //nolint:gosec // path is validated before use
			if err != nil {
				return nil, fmt.Errorf("read JWT_PRIVATE_KEY_FILE %q: %w", path, err)
			}
			pemData = string(data)
		}
	}

	if pemData == "" {
		return nil, nil
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY: failed to decode PEM block")
	}

	// Try PKCS1 first (RSA PRIVATE KEY), then PKCS8 (PRIVATE KEY).
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	iface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY: parse PKCS1: %w; parse PKCS8: %w", err, err2)
	}
	rsaKey, ok := iface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY: not an RSA private key")
	}
	return rsaKey, nil
}

// loadPublicKey attempts to load an RSA public key from JWT_PUBLIC_KEY (inline PEM)
// or JWT_PUBLIC_KEY_FILE (path). Returns nil when neither variable is set.
func loadPublicKey() (*rsa.PublicKey, error) {
	pemData := os.Getenv("JWT_PUBLIC_KEY")
	if pemData == "" {
		if path := os.Getenv("JWT_PUBLIC_KEY_FILE"); path != "" {
			data, err := os.ReadFile(path) //nolint:gosec // path is validated before use
			if err != nil {
				return nil, fmt.Errorf("read JWT_PUBLIC_KEY_FILE %q: %w", path, err)
			}
			pemData = string(data)
		}
	}

	if pemData == "" {
		return nil, nil
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY: failed to decode PEM block")
	}

	iface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY: parse PKIX: %w", err)
	}
	rsaKey, ok := iface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY: not an RSA public key")
	}
	return rsaKey, nil
}

// deriveKeyID computes a short, URL-safe key ID from the SHA-256 hash of the
// DER-encoded public key. This mirrors the approach used by OAuthProviderService.
func deriveKeyID(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}
