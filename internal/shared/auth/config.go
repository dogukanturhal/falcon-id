// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

// ServiceAPIKey represents a scoped API key for a specific service.
// Each service gets its own key with explicitly granted permissions,
// replacing the insecure wildcard "*" permission on the legacy single key.
type ServiceAPIKey struct {
	// Key is the secret API key value for this service
	Key string `json:"key"`

	// ServiceName is a human-readable identifier for the calling service (e.g., "billing", "iam")
	ServiceName string `json:"service_name"`

	// Permissions is the explicit list of permissions granted to this service.
	// Uses the same colon-delimited format as user permissions (e.g., "billing:invoices:read").
	// Wildcard "*" is NOT allowed here -- permissions must be explicitly enumerated.
	Permissions []string `json:"permissions"`
}

// Config holds authentication configuration
type Config struct {
	// JWTSecret is the secret key used to sign and verify JWT tokens
	// Must match the IAM service's JWT_SECRET
	JWTSecret string

	// JWTIssuer is the expected issuer claim in JWT tokens
	JWTIssuer string

	// RequireValidIssuer determines whether to validate the issuer claim
	RequireValidIssuer bool

	// InternalAPIKey is used for service-to-service authentication.
	//
	// Deprecated: Use ServiceAPIKeys instead. This field is retained only for
	// backward compatibility and will be removed in a future release.
	// When both InternalAPIKey and ServiceAPIKeys are configured, ServiceAPIKeys
	// takes precedence. If an incoming key matches InternalAPIKey but is not found
	// in ServiceAPIKeys, a deprecation warning is logged.
	InternalAPIKey string

	// ServiceAPIKeys maps API key values to their scoped service configuration.
	// The map key is the raw API key string; the value contains the service name
	// and the explicit permission set granted to that service.
	ServiceAPIKeys map[string]ServiceAPIKey

	// AccessTokenExpiry is the expected access token lifetime
	AccessTokenExpiry time.Duration

	// AllowExpiredForRefresh allows slightly expired tokens for refresh operations
	AllowExpiredForRefresh bool

	// ExpiredGracePeriod is how long after expiry a token can still be used for refresh
	ExpiredGracePeriod time.Duration
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		JWTIssuer:              "falcon-id",
		RequireValidIssuer:     true,
		AccessTokenExpiry:      15 * time.Minute,
		AllowExpiredForRefresh: false,
		ExpiredGracePeriod:     5 * time.Minute,
	}
}

// LoadFromEnv loads auth configuration from environment variables.
//
// Service API keys can be configured in two ways:
//
// 1. JSON format via SERVICE_API_KEYS env var:
//
//	SERVICE_API_KEYS='[
//	  {"key":"abc123...","service_name":"billing","permissions":["billing:invoices:*","billing:payments:read"]},
//	  {"key":"def456...","service_name":"iam","permissions":["iam:users:*","iam:roles:*"]}
//	]'
//
// 2. Legacy single-key format via INTERNAL_API_KEY (deprecated):
//
//	INTERNAL_API_KEY=your-shared-key
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		cfg.JWTSecret = secret
	}

	if issuer := os.Getenv("JWT_ISSUER"); issuer != "" {
		cfg.JWTIssuer = issuer
	}

	if requireIssuer := os.Getenv("JWT_REQUIRE_VALID_ISSUER"); requireIssuer != "" {
		cfg.RequireValidIssuer = requireIssuer != "false"
	}

	if apiKey := os.Getenv("INTERNAL_API_KEY"); apiKey != "" {
		cfg.InternalAPIKey = apiKey
	}

	// Load scoped service API keys from JSON env var
	if serviceKeysJSON := os.Getenv("SERVICE_API_KEYS"); serviceKeysJSON != "" {
		var keys []ServiceAPIKey
		if err := json.Unmarshal([]byte(serviceKeysJSON), &keys); err == nil {
			cfg.ServiceAPIKeys = make(map[string]ServiceAPIKey, len(keys))
			for _, k := range keys {
				if k.Key != "" && k.ServiceName != "" {
					cfg.ServiceAPIKeys[k.Key] = k
				}
			}
		}
	}

	if expiry := os.Getenv("ACCESS_TOKEN_EXPIRY_MINUTES"); expiry != "" {
		if minutes, err := strconv.Atoi(expiry); err == nil {
			cfg.AccessTokenExpiry = time.Duration(minutes) * time.Minute
		}
	}

	return cfg
}

// Validate checks if the configuration is valid for production use
func (c *Config) Validate() error {
	if c.JWTSecret == "" {
		return ErrTokenInvalid("JWT_SECRET is required")
	}

	if len(c.JWTSecret) < 32 {
		return ErrTokenInvalid("JWT_SECRET should be at least 32 characters")
	}

	return nil
}

// IsServiceAuthEnabled returns true if service-to-service auth is configured
// via either the new scoped ServiceAPIKeys or the legacy InternalAPIKey.
func (c *Config) IsServiceAuthEnabled() bool {
	return len(c.ServiceAPIKeys) > 0 || c.InternalAPIKey != ""
}

// HasScopedKeys returns true if the new per-service scoped API keys are configured.
func (c *Config) HasScopedKeys() bool {
	return len(c.ServiceAPIKeys) > 0
}
