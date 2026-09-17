// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// TokenHasher provides secure token hashing with configurable salt.
// The salt should be loaded from Vault or environment variables at startup.
type TokenHasher struct {
	salt []byte
}

var (
	defaultTokenHasher *TokenHasher
	tokenHasherMu      sync.RWMutex
)

// NewTokenHasher creates a new TokenHasher with the provided salt.
// The salt must be at least 16 bytes for security.
func NewTokenHasher(salt []byte) (*TokenHasher, error) {
	if len(salt) < 16 {
		return nil, errors.New("token hash salt must be at least 16 bytes")
	}
	return &TokenHasher{salt: salt}, nil
}

// InitDefaultTokenHasher initializes the default token hasher from configuration.
// This should be called during service initialization with the salt from config.
// SECURITY: The salt should be loaded from config.Config which validates requirements.
func InitDefaultTokenHasher(salt string) error {
	// SECURITY: Salt must be provided - config.LoadConfig handles generation for development
	if salt == "" {
		return errors.New("TOKEN_HASH_SALT is required - ensure config.LoadConfig is called first")
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		// If not base64, use the string directly as bytes
		saltBytes = []byte(salt)
	}

	// SECURITY: Validate minimum salt length
	if len(saltBytes) < 16 {
		return fmt.Errorf("TOKEN_HASH_SALT must be at least 16 bytes (got %d)", len(saltBytes))
	}

	hasher, err := NewTokenHasher(saltBytes)
	if err != nil {
		return fmt.Errorf("InitDefaultTokenHasher: NewReader failed: %w", err)
	}

	tokenHasherMu.Lock()
	defaultTokenHasher = hasher
	tokenHasherMu.Unlock()

	return nil
}

// GetDefaultTokenHasher returns the default token hasher.
// SECURITY: Returns an error if InitDefaultTokenHasher was not called first.
// This ensures proper initialization during service startup.
func GetDefaultTokenHasher() (*TokenHasher, error) {
	tokenHasherMu.RLock()
	defer tokenHasherMu.RUnlock()

	if defaultTokenHasher == nil {
		return nil, errors.New("TokenHasher not initialized - call InitDefaultTokenHasher with config.TokenHashSalt during service startup")
	}
	return defaultTokenHasher, nil
}

// Hash creates an Argon2id hash of the token using the configured salt.
func (h *TokenHasher) Hash(token string) string {
	hash := argon2.IDKey(
		[]byte(token),
		h.salt,
		1,
		64*1024,
		4,
		32,
	)
	return base64.RawStdEncoding.EncodeToString(hash)
}

// PasswordConfig is an exported type.
type PasswordConfig struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultPasswordConfig is an exported constant.
var DefaultPasswordConfig = &PasswordConfig{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 4,
	KeyLen:  32,
	SaltLen: 16,
}

// PasswordPolicy is an exported type.
type PasswordPolicy struct {
	MinLength          int
	MaxLength          int
	RequireUpper       bool
	RequireLower       bool
	RequireDigit       bool
	RequireSpecial     bool
	PreventCommon      bool // Check against common password list
	PreventUserContext bool // Prevent passwords containing username/email
}

// DefaultPasswordPolicy provides secure password requirements
// SECURITY: These are production-ready defaults following NIST SP 800-63B guidelines
var DefaultPasswordPolicy = &PasswordPolicy{
	MinLength:          12,  // Minimum 12 characters (NIST recommends 8+, we're stricter)
	MaxLength:          128, // Maximum to prevent DoS via hash computation
	RequireUpper:       true,
	RequireLower:       true,
	RequireDigit:       true,
	RequireSpecial:     true, // Require at least one special character
	PreventCommon:      true, // Block common passwords
	PreventUserContext: true, // Block passwords containing username
}

// commonPasswords contains the most commonly used passwords that should be blocked
// This is a subset - in production, consider using a larger list like Have I Been Pwned
var commonPasswords = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true,
	"abc123": true, "monkey": true, "1234567": true, "letmein": true,
	"trustno1": true, "dragon": true, "baseball": true, "iloveyou": true,
	"master": true, "sunshine": true, "ashley": true, "bailey": true,
	"shadow": true, "123123": true, "654321": true, "superman": true,
	"qazwsx": true, "michael": true, "football": true, "password1": true,
	"password123": true, "welcome": true, "welcome1": true, "admin": true,
	"admin123": true, "login": true, "passw0rd": true, "p@ssw0rd": true,
	"changeme": true, "secret": true, "test": true, "test123": true,
	"guest": true, "root": true, "toor": true, "pass": true,
	"123456789": true, "12345": true, "1234": true, "qwerty123": true,
	"111111": true, "000000": true, "password!": true, "letmein1": true,
	"hexxlock": true, "example": true, // Product-specific common passwords
}

// HashPassword creates an Argon2id hash of the password
func HashPassword(password string, config *PasswordConfig) (string, error) {
	if config == nil {
		config = DefaultPasswordConfig
	}

	salt := make([]byte, config.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("HashPassword: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLen,
	)

	// Encode as $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		config.Memory,
		config.Time,
		config.Threads,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

// VerifyPassword compares a password against a hash
func VerifyPassword(password, encodedHash string) (bool, error) {
	config, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("VerifyPassword: hash parsing failed: %w", err)
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLen,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

func decodeHash(encodedHash string) (*PasswordConfig, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("unsupported hash algorithm")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decodeHash: Sscanf failed: %w", err)
	}

	config := &PasswordConfig{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &config.Memory, &config.Time, &config.Threads)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decodeHash: Sscanf failed: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decodeHash: %w", err)
	}
	config.SaltLen = uint32(len(salt)) //nolint:gosec // value is bounded by bcrypt cost config, safe conversion

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decodeHash: %w", err)
	}
	config.KeyLen = uint32(len(hash)) //nolint:gosec // value is bounded by bcrypt cost config, safe conversion

	return config, salt, hash, nil
}

// ValidatePassword checks if a password meets the policy requirements
func ValidatePassword(password string, policy *PasswordPolicy) error {
	return ValidatePasswordWithContext(password, "", "", policy)
}

// ValidatePasswordWithContext checks password with user context (username, email)
// This prevents passwords containing user-identifying information
func ValidatePasswordWithContext(password, username, email string, policy *PasswordPolicy) error {
	if policy == nil {
		policy = DefaultPasswordPolicy
	}

	// Length validation
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters", policy.MinLength)
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		return fmt.Errorf("password must be at most %d characters", policy.MaxLength)
	}

	if err := validatePasswordCharTypes(password, policy); err != nil {
		return err
	}
	if err := validatePasswordCommon(password, policy); err != nil {
		return err
	}
	if err := validatePasswordUserContext(password, username, email, policy); err != nil {
		return err
	}
	return nil
}

// validatePasswordCharTypes checks character-type requirements.
func validatePasswordCharTypes(password string, policy *PasswordPolicy) error {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}
	if policy.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if policy.RequireDigit && !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if policy.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	return nil
}

// validatePasswordCommon checks if the password matches known common passwords.
func validatePasswordCommon(password string, policy *PasswordPolicy) error {
	if !policy.PreventCommon {
		return nil
	}
	lowerPassword := strings.ToLower(password)
	if commonPasswords[lowerPassword] {
		return errors.New("password is too common, please choose a stronger password")
	}
	for common := range commonPasswords {
		if len(common) >= 4 && strings.Contains(lowerPassword, common) {
			return errors.New("password contains a common word or pattern")
		}
	}
	return nil
}

// validatePasswordUserContext prevents using username/email as password components.
func validatePasswordUserContext(password, username, email string, policy *PasswordPolicy) error {
	if !policy.PreventUserContext {
		return nil
	}
	lowerPassword := strings.ToLower(password)
	if username != "" {
		lowerUsername := strings.ToLower(username)
		if len(lowerUsername) >= 3 && strings.Contains(lowerPassword, lowerUsername) {
			return errors.New("password cannot contain your username")
		}
	}
	if email != "" {
		emailParts := strings.Split(strings.ToLower(email), "@")
		if len(emailParts) > 0 && len(emailParts[0]) >= 3 && strings.Contains(lowerPassword, emailParts[0]) {
			return errors.New("password cannot contain your email address")
		}
	}
	return nil
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("GenerateRandomString: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateSecureToken generates a secure token for refresh tokens, API keys, etc.
func GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("GenerateSecureToken: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// HashToken creates a secure hash of a token for storage using the configured salt.
// SECURITY: The salt is loaded from TOKEN_HASH_SALT environment variable or Vault.
// Returns an error if the token hasher is not initialized.
func HashToken(token string) (string, error) {
	hasher, err := GetDefaultTokenHasher()
	if err != nil {
		return "", fmt.Errorf("HashToken: NewReader failed: %w", err)
	}
	return hasher.Hash(token), nil
}
