// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// ConfigInvalidationChannel is the Redis pub/sub channel for config invalidation messages.
const ConfigInvalidationChannel = "hexxlock:config:invalidate"

// ConfigProviderConfig holds tuning parameters for the ConfigProvider.
type ConfigProviderConfig struct {
	LocalCacheSize int
	LocalCacheTTL  time.Duration
	RedisCacheTTL  time.Duration
}

// DefaultConfigProviderConfig returns sensible defaults.
func DefaultConfigProviderConfig() *ConfigProviderConfig {
	return &ConfigProviderConfig{
		LocalCacheSize: 10000,
		LocalCacheTTL:  30 * time.Second,
		RedisCacheTTL:  5 * time.Minute,
	}
}

// configCacheEntry represents a cached config value with expiration.
type configCacheEntry struct {
	Value     json.RawMessage
	ExpiresAt time.Time
}

// ConfigProviderMetrics tracks cache hit/miss statistics.
// Fix 1: Fields use sync/atomic.Int64 to eliminate mutex contention at scale.
type ConfigProviderMetrics struct {
	LocalHits   atomic.Int64 `json:"local_hits"`
	LocalMisses atomic.Int64 `json:"local_misses"`
	RedisHits   atomic.Int64 `json:"redis_hits"`
	RedisMisses atomic.Int64 `json:"redis_misses"`
	DBHits      atomic.Int64 `json:"db_hits"`
	DBMisses    atomic.Int64 `json:"db_misses"`
}

// ConfigProviderMetricsSnapshot is a point-in-time snapshot of metrics for serialization.
type ConfigProviderMetricsSnapshot struct {
	LocalHits   int64 `json:"local_hits"`
	LocalMisses int64 `json:"local_misses"`
	RedisHits   int64 `json:"redis_hits"`
	RedisMisses int64 `json:"redis_misses"`
	DBHits      int64 `json:"db_hits"`
	DBMisses    int64 `json:"db_misses"`
}

// configInvalidationMessage is sent via Redis pub/sub to invalidate caches.
type configInvalidationMessage struct {
	TenantID  string `json:"tenant_id"`
	ConfigKey string `json:"config_key"` // empty means invalidate all keys for tenant
}

// ConfigProvider resolves tenant-specific config with a three-layer cache:
// L1: Local LRU (30s TTL) -> L2: Redis HSET (5m TTL) -> L3: DB -> L4: Static default.
type ConfigProvider struct {
	staticConfig      *config.Config
	repo              tenantConfigStore
	redisClient       *redis.Client
	logger            *zap.Logger
	provCfg           *ConfigProviderConfig
	localCache        *lru.Cache[string, *configCacheEntry]
	keyRegistry       map[string]models.ConfigKeyDefinition
	encryptionService atomic.Pointer[crypto.EncryptionService]

	// appHostResolver, when set, backs FrontendURL's L3.5 source: a live
	// lookup against tenant-management's app_host (see
	// TenantAppHostResolver's doc comment). atomic.Pointer so
	// SetAppHostResolver (called once at boot, cmd/services.go) never
	// races FrontendURL's concurrent reads.
	appHostResolver atomic.Pointer[TenantAppHostResolver]

	// metrics uses atomic fields directly; no mutex needed.
	metrics ConfigProviderMetrics

	// registryMu guards keyRegistry if future dynamic registration is added.
	// Currently keyRegistry is written once at init and read-only thereafter,
	// so this mutex is intentionally not held during normal reads.
	registryMu sync.RWMutex

	cancelSubscriber context.CancelFunc
}

// tenantConfigStore is the subset of *repositories.TenantConfigRepository
// ConfigProvider needs. Extracted as an interface so unit tests can supply a
// fake store instead of requiring a live Postgres pool (the concrete
// repository type only takes a *pgxpool.Pool, with no seam for a fake).
type tenantConfigStore interface {
	Get(ctx context.Context, tenantID uuid.UUID, configKey string) (*models.TenantConfig, error)
	GetByScope(ctx context.Context, tenantID uuid.UUID, realmID, appID *uuid.UUID, configKey string) (*models.TenantConfig, error)
	UpsertByScope(ctx context.Context, p repositories.UpsertByScopeParams) error
}

// NewConfigProvider creates a new ConfigProvider.
// redisClient can be nil if Redis is unavailable (L2 cache will be skipped).
func NewConfigProvider(
	staticConfig *config.Config,
	repo tenantConfigStore,
	redisClient *redis.Client,
	logger *zap.Logger,
	provCfg *ConfigProviderConfig,
) (*ConfigProvider, error) {
	if provCfg == nil {
		provCfg = DefaultConfigProviderConfig()
	}

	localCache, err := lru.New[string, *configCacheEntry](provCfg.LocalCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create local LRU cache: %w", err)
	}

	cp := &ConfigProvider{
		staticConfig: staticConfig,
		repo:         repo,
		redisClient:  redisClient,
		logger:       logger,
		provCfg:      provCfg,
		localCache:   localCache,
		keyRegistry:  make(map[string]models.ConfigKeyDefinition),
	}

	cp.registerKeys()

	return cp, nil
}

// SetEncryptionService injects an encryption service for protecting sensitive config values at rest.
// When set, sensitive config values are decrypted on read from DB and skipped in Redis cache.
func (cp *ConfigProvider) SetEncryptionService(enc *crypto.EncryptionService) {
	cp.encryptionService.Store(enc)
}

// SetAppHostResolver wires FrontendURL's live source for tenant-management's
// app_host. When unset, FrontendURL behaves exactly as before this change:
// local cache -> Redis -> DB -> static default, never hitting the network.
func (cp *ConfigProvider) SetAppHostResolver(r TenantAppHostResolver) {
	if r == nil {
		return
	}
	cp.appHostResolver.Store(&r)
}

// registerKeys populates the key registry with all supported dynamic config keys.
func (cp *ConfigProvider) registerKeys() {
	keys := []models.ConfigKeyDefinition{
		// Token settings
		{Key: "access_token_expiry", Description: "Access token expiration duration", Type: "duration", DefaultValue: cp.staticConfig.AccessTokenExpiry.String(), Category: "token", Sensitive: false},
		{Key: "session_expiry", Description: "Session expiration duration", Type: "duration", DefaultValue: cp.staticConfig.SessionExpiry.String(), Category: "session", Sensitive: false},
		{Key: "trusted_device_session_expiry", Description: "Session expiry for trusted devices", Type: "duration", DefaultValue: cp.staticConfig.TrustedDeviceSessionExpiry.String(), Category: "session", Sensitive: false},
		{Key: "session_rotation_on_refresh", Description: "Rotate session ID on token refresh", Type: "bool", DefaultValue: cp.staticConfig.SessionRotationOnRefresh, Category: "session", Sensitive: false},

		// MFA settings
		{Key: "mfa_issuer", Description: "TOTP issuer name shown in authenticator apps", Type: "string", DefaultValue: cp.staticConfig.MFAIssuer, Category: "mfa", Sensitive: false},
		{Key: "mfa_totp_digits", Description: "Number of digits in TOTP codes", Type: "int", DefaultValue: cp.staticConfig.MFATOTPDigits, Category: "mfa", Sensitive: false},
		{Key: "mfa_totp_period", Description: "TOTP code rotation period in seconds", Type: "int", DefaultValue: cp.staticConfig.MFATOTPPeriod, Category: "mfa", Sensitive: false},
		{Key: "mfa_email_code_ttl", Description: "Email MFA code time-to-live", Type: "duration", DefaultValue: cp.staticConfig.MFAEmailCodeTTL.String(), Category: "mfa", Sensitive: false},
		{Key: "mfa_backup_code_count", Description: "Number of backup codes to generate", Type: "int", DefaultValue: cp.staticConfig.MFABackupCodeCount, Category: "mfa", Sensitive: false},

		// Account lockout
		{Key: "max_login_attempts", Description: "Maximum failed login attempts before lockout", Type: "int", DefaultValue: cp.staticConfig.MaxLoginAttempts, Category: "password", Sensitive: false},
		{Key: "lockout_duration", Description: "Account lockout duration after max failed attempts", Type: "duration", DefaultValue: cp.staticConfig.LockoutDuration.String(), Category: "password", Sensitive: false},

		// Password policy
		{Key: "password_min_length", Description: "Minimum password length", Type: "int", DefaultValue: cp.staticConfig.PasswordMinLength, Category: "password", Sensitive: false},
		{Key: "password_require_upper", Description: "Require uppercase characters in passwords", Type: "bool", DefaultValue: cp.staticConfig.PasswordRequireUpper, Category: "password", Sensitive: false},
		{Key: "password_require_lower", Description: "Require lowercase characters in passwords", Type: "bool", DefaultValue: cp.staticConfig.PasswordRequireLower, Category: "password", Sensitive: false},
		{Key: "password_require_digit", Description: "Require digit characters in passwords", Type: "bool", DefaultValue: cp.staticConfig.PasswordRequireDigit, Category: "password", Sensitive: false},
		{Key: "password_require_special", Description: "Require special characters in passwords", Type: "bool", DefaultValue: cp.staticConfig.PasswordRequireSpecial, Category: "password", Sensitive: false},

		// SMTP settings
		{Key: "smtp_host", Description: "SMTP server hostname", Type: "string", DefaultValue: cp.staticConfig.SMTPHost, Category: "smtp", Sensitive: false},
		{Key: "smtp_port", Description: "SMTP server port", Type: "int", DefaultValue: cp.staticConfig.SMTPPort, Category: "smtp", Sensitive: false},
		{Key: "smtp_from", Description: "SMTP sender email address", Type: "string", DefaultValue: cp.staticConfig.SMTPFrom, Category: "smtp", Sensitive: false},
		{Key: "smtp_from_name", Description: "SMTP sender display name shown in the From header (e.g. \"Acme Inc\"); left blank sends with no display name rather than a shared default", Type: "string", DefaultValue: cp.staticConfig.SMTPFromName, Category: "smtp", Sensitive: false},
		{Key: "smtp_username", Description: "SMTP authentication username", Type: "string", DefaultValue: cp.staticConfig.SMTPUsername, Category: "smtp", Sensitive: true},
		{Key: "smtp_password", Description: "SMTP authentication password", Type: "string", DefaultValue: "********", Category: "smtp", Sensitive: true},
		{Key: "smtp_use_tls", Description: "Enable TLS for SMTP connections", Type: "bool", DefaultValue: cp.staticConfig.SMTPUseTLS, Category: "smtp", Sensitive: false},

		// Frontend
		{Key: "frontend_url", Description: "Frontend application URL for links in emails", Type: "string", DefaultValue: cp.staticConfig.FrontendURL, Category: "frontend", Sensitive: false},

		// Rate limiting
		{Key: "rate_limit_requests", Description: "Maximum requests per rate limit window", Type: "int", DefaultValue: cp.staticConfig.RateLimitRequests, Category: "rate_limit", Sensitive: false},
		{Key: "rate_limit_window", Description: "Rate limit window duration", Type: "duration", DefaultValue: cp.staticConfig.RateLimitWindow.String(), Category: "rate_limit", Sensitive: false},
	}

	for _, k := range keys {
		cp.keyRegistry[k.Key] = k
	}
}

// GetKeyRegistry returns a deep copy of all supported config key definitions.
// Fix 2: Returns a copy so callers cannot mutate the internal registry.
func (cp *ConfigProvider) GetKeyRegistry() map[string]models.ConfigKeyDefinition {
	cp.registryMu.RLock()
	defer cp.registryMu.RUnlock()
	result := make(map[string]models.ConfigKeyDefinition, len(cp.keyRegistry))
	for k, v := range cp.keyRegistry {
		result[k] = v
	}
	return result
}

// isSensitive reports whether the given config key is marked sensitive in the registry.
func (cp *ConfigProvider) isSensitive(key string) bool {
	if def, ok := cp.keyRegistry[key]; ok {
		return def.Sensitive
	}
	return false
}

// --- Local cache key ---

func localCacheKey(tenantID uuid.UUID, key string) string {
	return tenantID.String() + ":" + key
}

// --- Redis hash key ---

func redisHashKey(tenantID uuid.UUID) string {
	return "iam:tenant_config:" + tenantID.String()
}

// --- Three-layer lookup ---

// getRaw retrieves a raw JSON value for a tenant config key using the three-layer cache.
// Fix 4: Sensitive values are decrypted after DB read and never written to Redis.
func (cp *ConfigProvider) getRaw(ctx context.Context, tenantID uuid.UUID, key string) (json.RawMessage, error) {
	cacheKey := localCacheKey(tenantID, key)
	sensitive := cp.isSensitive(key)

	// L1: Local LRU cache (stores decrypted values — acceptable for in-process memory).
	if entry, ok := cp.localCache.Get(cacheKey); ok {
		if time.Now().Before(entry.ExpiresAt) {
			cp.metrics.LocalHits.Add(1)
			return entry.Value, nil
		}
		cp.localCache.Remove(cacheKey)
	}
	cp.metrics.LocalMisses.Add(1)

	// L2: Redis HSET — skip for sensitive keys to prevent plaintext exposure in Redis.
	if cp.redisClient != nil && !sensitive {
		val, err := cp.redisClient.HGet(ctx, redisHashKey(tenantID), key).Result()
		if err == nil {
			cp.metrics.RedisHits.Add(1)
			raw := json.RawMessage(val)
			// Populate L1 from Redis (non-sensitive, no decryption needed).
			cp.localCache.Add(cacheKey, &configCacheEntry{
				Value:     raw,
				ExpiresAt: time.Now().Add(cp.provCfg.LocalCacheTTL),
			})
			return raw, nil
		}
		if !errors.Is(err, redis.Nil) {
			cp.logger.Warn("Redis HGET failed for tenant config", zap.Error(err), zap.String("key", key))
		}
		cp.metrics.RedisMisses.Add(1)
	}

	// L3: Database
	tc, err := cp.repo.Get(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if tc != nil {
		return cp.populateCachesFromDB(ctx, tc, tenantID, key, cacheKey, sensitive)
	}

	cp.metrics.DBMisses.Add(1)

	// L4: Not found — caller uses static default
	return nil, nil
}

// populateCachesFromDB stores a DB-sourced config entry into L1 and L2 caches,
// decrypting the value when sensitive, and returns the (possibly decrypted) value.
func (cp *ConfigProvider) populateCachesFromDB(ctx context.Context, tc *models.TenantConfig, tenantID uuid.UUID, key, cacheKey string, sensitive bool) (json.RawMessage, error) {
	cp.metrics.DBHits.Add(1)

	configValue := tc.ConfigValue
	if sensitive && cp.encryptionService.Load() != nil {
		decrypted, decErr := cp.decryptWrappedValue(configValue)
		if decErr != nil {
			cp.logger.Error("Failed to decrypt sensitive config value",
				zap.Error(decErr),
				zap.String("key", key),
				zap.String("tenant_id", tenantID.String()),
			)
			return nil, fmt.Errorf("failed to decrypt config value for key %s: %w", key, decErr)
		}
		configValue = decrypted
	}

	cp.localCache.Add(cacheKey, &configCacheEntry{
		Value:     configValue,
		ExpiresAt: time.Now().Add(cp.provCfg.LocalCacheTTL),
	})

	if cp.redisClient != nil && !sensitive {
		pipe := cp.redisClient.Pipeline()
		pipe.HSet(ctx, redisHashKey(tenantID), key, string(tc.ConfigValue))
		pipe.Expire(ctx, redisHashKey(tenantID), cp.provCfg.RedisCacheTTL)
		if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
			cp.logger.Warn("Failed to populate Redis cache", zap.Error(pipeErr), zap.String("key", key))
		}
	}

	return configValue, nil
}

// decryptWrappedValue decrypts the string value inside a {"v": "<encrypted>"} JSON wrapper.
// It returns a new {"v": "<plaintext>"} JSON message.
func (cp *ConfigProvider) decryptWrappedValue(raw json.RawMessage) (json.RawMessage, error) {
	var wrapper struct {
		V json.RawMessage `json:"v"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("decryptWrappedValue: unmarshal wrapper: %w", err)
	}

	var encryptedStr string
	if err := json.Unmarshal(wrapper.V, &encryptedStr); err != nil {
		// Value may already be plaintext (e.g. migrated pre-encryption data) — return as-is.
		return raw, nil //nolint:nilerr // intentional: if the value is not a JSON string, it may be a pre-encryption plaintext value
	}

	plaintext, err := cp.encryptionService.Load().Decrypt(encryptedStr)
	if err != nil {
		// If decryption fails the value may be stored as plaintext (pre-encryption rows).
		// Log a warning and return the raw value unchanged so the system degrades gracefully.
		cp.logger.Warn("Decrypt failed for sensitive config value — returning raw (may be plaintext pre-migration)",
			zap.Error(err),
		)
		return raw, nil
	}

	out, err := json.Marshal(map[string]interface{}{"v": plaintext})
	if err != nil {
		return nil, fmt.Errorf("decryptWrappedValue: marshal plaintext wrapper: %w", err)
	}
	return json.RawMessage(out), nil
}

// EncryptValueForStorage encrypts a sensitive config value's payload for DB storage.
// The input must be a {"v": "<plaintext>"} JSON message; the output is {"v": "<ciphertext>"}.
// For non-sensitive keys or when no encryption service is configured, the input is returned unchanged.
func (cp *ConfigProvider) EncryptValueForStorage(key string, value json.RawMessage) (json.RawMessage, error) {
	if !cp.isSensitive(key) || cp.encryptionService.Load() == nil {
		return value, nil
	}

	var wrapper struct {
		V json.RawMessage `json:"v"`
	}
	if err := json.Unmarshal(value, &wrapper); err != nil {
		return nil, fmt.Errorf("EncryptValueForStorage: unmarshal wrapper: %w", err)
	}

	var plaintext string
	if err := json.Unmarshal(wrapper.V, &plaintext); err != nil {
		return nil, fmt.Errorf("EncryptValueForStorage: unmarshal string value: %w", err)
	}

	ciphertext, err := cp.encryptionService.Load().Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("EncryptValueForStorage: encrypt: %w", err)
	}

	out, err := json.Marshal(map[string]interface{}{"v": ciphertext})
	if err != nil {
		return nil, fmt.Errorf("EncryptValueForStorage: marshal encrypted wrapper: %w", err)
	}
	return json.RawMessage(out), nil
}

// --- Typed helper methods ---

// wrappedValue is used to unmarshal {"v": <value>} from config_value JSONB.
type wrappedValue struct {
	V json.RawMessage `json:"v"`
}

func (cp *ConfigProvider) getDuration(ctx context.Context, tenantID uuid.UUID, key string, fallback time.Duration) time.Duration {
	raw, err := cp.getRaw(ctx, tenantID, key)
	if err != nil || raw == nil {
		return fallback
	}

	var w wrappedValue
	if err := json.Unmarshal(raw, &w); err != nil {
		cp.logger.Warn("Failed to unmarshal config wrapper", zap.Error(err), zap.String("key", key))
		return fallback
	}

	var s string
	if err := json.Unmarshal(w.V, &s); err != nil {
		cp.logger.Warn("Failed to unmarshal duration string", zap.Error(err), zap.String("key", key))
		return fallback
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		cp.logger.Warn("Failed to parse duration", zap.Error(err), zap.String("key", key), zap.String("value", s))
		return fallback
	}

	return d
}

func (cp *ConfigProvider) getInt(ctx context.Context, tenantID uuid.UUID, key string, fallback int) int {
	raw, err := cp.getRaw(ctx, tenantID, key)
	if err != nil || raw == nil {
		return fallback
	}

	var w wrappedValue
	if err := json.Unmarshal(raw, &w); err != nil {
		cp.logger.Warn("Failed to unmarshal config wrapper", zap.Error(err), zap.String("key", key))
		return fallback
	}

	var v float64
	if err := json.Unmarshal(w.V, &v); err != nil {
		cp.logger.Warn("Failed to unmarshal int", zap.Error(err), zap.String("key", key))
		return fallback
	}

	return int(v)
}

func (cp *ConfigProvider) getString(ctx context.Context, tenantID uuid.UUID, key string, fallback string) string {
	raw, err := cp.getRaw(ctx, tenantID, key)
	if err != nil || raw == nil {
		return fallback
	}

	var w wrappedValue
	if err := json.Unmarshal(raw, &w); err != nil {
		cp.logger.Warn("Failed to unmarshal config wrapper", zap.Error(err), zap.String("key", key))
		return fallback
	}

	var s string
	if err := json.Unmarshal(w.V, &s); err != nil {
		cp.logger.Warn("Failed to unmarshal string", zap.Error(err), zap.String("key", key))
		return fallback
	}

	return s
}

func (cp *ConfigProvider) getBool(ctx context.Context, tenantID uuid.UUID, key string, fallback bool) bool {
	raw, err := cp.getRaw(ctx, tenantID, key)
	if err != nil || raw == nil {
		return fallback
	}

	var w wrappedValue
	if err := json.Unmarshal(raw, &w); err != nil {
		cp.logger.Warn("Failed to unmarshal config wrapper", zap.Error(err), zap.String("key", key))
		return fallback
	}

	var b bool
	if err := json.Unmarshal(w.V, &b); err != nil {
		cp.logger.Warn("Failed to unmarshal bool", zap.Error(err), zap.String("key", key))
		return fallback
	}

	return b
}

// AccessTokenExpiry is an exported identifier.

// AccessTokenExpiry is an exported identifier.
func (cp *ConfigProvider) AccessTokenExpiry(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return cp.getDuration(ctx, tenantID, "access_token_expiry", cp.staticConfig.AccessTokenExpiry)
}

// SessionExpiry is an exported function.
func (cp *ConfigProvider) SessionExpiry(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return cp.getDuration(ctx, tenantID, "session_expiry", cp.staticConfig.SessionExpiry)
}

// TrustedDeviceSessionExpiry is an exported function.
func (cp *ConfigProvider) TrustedDeviceSessionExpiry(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return cp.getDuration(ctx, tenantID, "trusted_device_session_expiry", cp.staticConfig.TrustedDeviceSessionExpiry)
}

// SessionRotationOnRefresh is an exported function.
func (cp *ConfigProvider) SessionRotationOnRefresh(ctx context.Context, tenantID uuid.UUID) bool {
	return cp.getBool(ctx, tenantID, "session_rotation_on_refresh", cp.staticConfig.SessionRotationOnRefresh)
}

// MFAIssuer is an exported identifier.
func (cp *ConfigProvider) MFAIssuer(ctx context.Context, tenantID uuid.UUID) string {
	return cp.getString(ctx, tenantID, "mfa_issuer", cp.staticConfig.MFAIssuer)
}

// MFATOTPDigits is an exported function.
func (cp *ConfigProvider) MFATOTPDigits(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "mfa_totp_digits", cp.staticConfig.MFATOTPDigits)
}

// MFATOTPPeriod is an exported function.
func (cp *ConfigProvider) MFATOTPPeriod(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "mfa_totp_period", cp.staticConfig.MFATOTPPeriod)
}

// MFAEmailCodeTTL is an exported function.
func (cp *ConfigProvider) MFAEmailCodeTTL(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return cp.getDuration(ctx, tenantID, "mfa_email_code_ttl", cp.staticConfig.MFAEmailCodeTTL)
}

// MFABackupCodeCount is an exported function.
func (cp *ConfigProvider) MFABackupCodeCount(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "mfa_backup_code_count", cp.staticConfig.MFABackupCodeCount)
}

// MaxLoginAttempts is an exported identifier.
func (cp *ConfigProvider) MaxLoginAttempts(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "max_login_attempts", cp.staticConfig.MaxLoginAttempts)
}

// LockoutDuration is an exported function.
func (cp *ConfigProvider) LockoutDuration(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return cp.getDuration(ctx, tenantID, "lockout_duration", cp.staticConfig.LockoutDuration)
}

// PasswordMinLength is an exported identifier.
func (cp *ConfigProvider) PasswordMinLength(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "password_min_length", cp.staticConfig.PasswordMinLength)
}

// PasswordRequireUpper is an exported function.
func (cp *ConfigProvider) PasswordRequireUpper(ctx context.Context, tenantID uuid.UUID) bool {
	return cp.getBool(ctx, tenantID, "password_require_upper", cp.staticConfig.PasswordRequireUpper)
}

// PasswordRequireLower is an exported function.
func (cp *ConfigProvider) PasswordRequireLower(ctx context.Context, tenantID uuid.UUID) bool {
	return cp.getBool(ctx, tenantID, "password_require_lower", cp.staticConfig.PasswordRequireLower)
}

// PasswordRequireDigit is an exported function.
func (cp *ConfigProvider) PasswordRequireDigit(ctx context.Context, tenantID uuid.UUID) bool {
	return cp.getBool(ctx, tenantID, "password_require_digit", cp.staticConfig.PasswordRequireDigit)
}

// PasswordRequireSpecial is an exported function.
func (cp *ConfigProvider) PasswordRequireSpecial(ctx context.Context, tenantID uuid.UUID) bool {
	return cp.getBool(ctx, tenantID, "password_require_special", cp.staticConfig.PasswordRequireSpecial)
}

// SMTPHost is an exported identifier.
func (cp *ConfigProvider) SMTPHost(ctx context.Context, tenantID uuid.UUID) string {
	return cp.getString(ctx, tenantID, "smtp_host", cp.staticConfig.SMTPHost)
}

// SMTPPort is an exported function.
func (cp *ConfigProvider) SMTPPort(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "smtp_port", cp.staticConfig.SMTPPort)
}

// SMTPFrom is an exported function.
func (cp *ConfigProvider) SMTPFrom(ctx context.Context, tenantID uuid.UUID) string {
	return cp.getString(ctx, tenantID, "smtp_from", cp.staticConfig.SMTPFrom)
}

// SMTPFromName returns the tenant's configured sender display name, or the
// platform default (empty unless SMTP_FROM_NAME is set) when the tenant has
// not overridden it. An empty result means send with no display name — never
// substitute a brand name the tenant did not choose.
func (cp *ConfigProvider) SMTPFromName(ctx context.Context, tenantID uuid.UUID) string {
	return cp.getString(ctx, tenantID, "smtp_from_name", cp.staticConfig.SMTPFromName)
}

// SMTPUsername is an exported function.
func (cp *ConfigProvider) SMTPUsername(ctx context.Context, tenantID uuid.UUID) string {
	return cp.getString(ctx, tenantID, "smtp_username", cp.staticConfig.SMTPUsername)
}

// SMTPPassword is an exported function.
func (cp *ConfigProvider) SMTPPassword(ctx context.Context, tenantID uuid.UUID) string {
	return cp.getString(ctx, tenantID, "smtp_password", cp.staticConfig.SMTPPassword)
}

// SMTPUseTLS is an exported function.
func (cp *ConfigProvider) SMTPUseTLS(ctx context.Context, tenantID uuid.UUID) bool {
	return cp.getBool(ctx, tenantID, "smtp_use_tls", cp.staticConfig.SMTPUseTLS)
}

// FrontendURL is an exported identifier.
// frontendURLKey is the ConfigProvider key used for FrontendURL below.
const frontendURLKey = "frontend_url"

// FrontendURL resolves the per-tenant frontend URL: local cache -> Redis ->
// DB (an admin-configured per-tenant override, if one exists) -> live
// tenant-management app_host lookup (see SetAppHostResolver) -> static
// default. The live lookup's result is fed back into the L1/L2 caches (see
// populateFrontendURLCache) rather than bypassing them, so a resolver call
// only happens once per cache TTL, not once per request.
//
// Deliberately does NOT read tenants.domain — see
// TenantAppHostResolver's doc comment for why.
func (cp *ConfigProvider) FrontendURL(ctx context.Context, tenantID uuid.UUID) string {
	raw, err := cp.getRaw(ctx, tenantID, frontendURLKey)
	if err == nil && raw != nil {
		if s, ok := decodeWrappedString(raw); ok && s != "" {
			return s
		}
	}

	// L1/L2/L3 all missed — no admin-configured override for this tenant.
	// Resolve from tenant-management's app_host instead of falling
	// straight to the hardcoded static default.
	if resolverPtr := cp.appHostResolver.Load(); resolverPtr != nil {
		resolver := *resolverPtr
		appHost, rErr := resolver.ResolveAppHost(ctx, tenantID)
		if rErr == nil && appHost != "" {
			resolvedURL := appHostToFrontendURL(appHost)
			cp.populateFrontendURLCache(ctx, tenantID, resolvedURL)
			return resolvedURL
		}
		if rErr != nil {
			cp.logger.Warn("app-host resolution failed, falling back to static frontend URL",
				zap.Error(rErr), zap.String("tenant_id", tenantID.String()))
		}
	}

	// L4: static default — unchanged behaviour when no override exists
	// and the resolver is unset, unavailable, or failed.
	return cp.staticConfig.FrontendURL
}

// decodeWrappedString unwraps a {"v": "<string>"} config_value JSON message
// the same way getString does, for callers (FrontendURL) that need to
// short-circuit before falling further down the cache chain.
func decodeWrappedString(raw json.RawMessage) (string, bool) {
	var w wrappedValue
	if err := json.Unmarshal(raw, &w); err != nil {
		return "", false
	}
	var s string
	if err := json.Unmarshal(w.V, &s); err != nil {
		return "", false
	}
	return s, true
}

// appHostToFrontendURL builds a full frontend URL from a bare host (e.g.
// "acme.example.com") returned by tenant-management's app-host endpoint.
// Tolerates a host value that already carries a scheme (defensive; the
// contract describes app_host as a bare host).
func appHostToFrontendURL(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	return "https://" + host
}

// populateFrontendURLCache stores a tenant-management-sourced frontend URL
// into the L1 local cache and L2 Redis cache using the exact same TTLs and
// wrapper format as populateCachesFromDB, so it is indistinguishable to
// future reads from a DB-sourced value. It deliberately does NOT write the
// value back to the DB (iam_tenant_configs stays reserved for explicit
// admin overrides — writing a derived value there would make a stale
// tenant-management read permanent instead of expiring with the cache).
func (cp *ConfigProvider) populateFrontendURLCache(ctx context.Context, tenantID uuid.UUID, url string) {
	valueJSON, err := json.Marshal(url)
	if err != nil {
		cp.logger.Warn("Failed to marshal resolved frontend URL for caching", zap.Error(err))
		return
	}
	wrapped, err := json.Marshal(wrappedValue{V: valueJSON})
	if err != nil {
		cp.logger.Warn("Failed to wrap resolved frontend URL for caching", zap.Error(err))
		return
	}

	cacheKey := localCacheKey(tenantID, frontendURLKey)
	cp.localCache.Add(cacheKey, &configCacheEntry{
		Value:     wrapped,
		ExpiresAt: time.Now().Add(cp.provCfg.LocalCacheTTL),
	})

	if cp.redisClient != nil {
		pipe := cp.redisClient.Pipeline()
		pipe.HSet(ctx, redisHashKey(tenantID), frontendURLKey, string(wrapped))
		pipe.Expire(ctx, redisHashKey(tenantID), cp.provCfg.RedisCacheTTL)
		if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
			cp.logger.Warn("Failed to populate Redis cache with resolved frontend URL", zap.Error(pipeErr))
		}
	}
}

// RateLimitRequests is an exported identifier.
func (cp *ConfigProvider) RateLimitRequests(ctx context.Context, tenantID uuid.UUID) int {
	return cp.getInt(ctx, tenantID, "rate_limit_requests", cp.staticConfig.RateLimitRequests)
}

// RateLimitWindow is an exported function.
func (cp *ConfigProvider) RateLimitWindow(ctx context.Context, tenantID uuid.UUID) time.Duration {
	return cp.getDuration(ctx, tenantID, "rate_limit_window", cp.staticConfig.RateLimitWindow)
}

// --- Scoped config resolution (hierarchical override) ---

// scopedCacheKey generates a cache key for scoped config lookups.
func scopedCacheKey(tenantID uuid.UUID, realmID, appID *uuid.UUID, key string) string {
	rStr := ""
	aStr := ""
	if realmID != nil {
		rStr = realmID.String()
	}
	if appID != nil {
		aStr = appID.String()
	}
	return tenantID.String() + ":" + rStr + ":" + aStr + ":" + key
}

// GetRealmConfig retrieves a config value with realm-level override.
// Resolution: realm override → tenant default → static default.
func (cp *ConfigProvider) GetRealmConfig(ctx context.Context, tenantID, realmID uuid.UUID, key string) (json.RawMessage, error) {
	// Try realm-scoped override first
	cacheKey := scopedCacheKey(tenantID, &realmID, nil, key)
	if entry, ok := cp.localCache.Get(cacheKey); ok {
		if time.Now().Before(entry.ExpiresAt) {
			return entry.Value, nil
		}
		cp.localCache.Remove(cacheKey)
	}

	tc, err := cp.repo.GetByScope(ctx, tenantID, &realmID, nil, key)
	if err != nil {
		return nil, err
	}
	if tc != nil {
		cp.localCache.Add(cacheKey, &configCacheEntry{
			Value:     tc.ConfigValue,
			ExpiresAt: time.Now().Add(cp.provCfg.LocalCacheTTL),
		})
		return tc.ConfigValue, nil
	}

	// Fall back to tenant-level
	return cp.getRaw(ctx, tenantID, key)
}

// GetAppConfig retrieves a config value with application-level override.
// Resolution: app override → tenant default → static default.
func (cp *ConfigProvider) GetAppConfig(ctx context.Context, tenantID, appID uuid.UUID, key string) (json.RawMessage, error) {
	cacheKey := scopedCacheKey(tenantID, nil, &appID, key)
	if entry, ok := cp.localCache.Get(cacheKey); ok {
		if time.Now().Before(entry.ExpiresAt) {
			return entry.Value, nil
		}
		cp.localCache.Remove(cacheKey)
	}

	tc, err := cp.repo.GetByScope(ctx, tenantID, nil, &appID, key)
	if err != nil {
		return nil, err
	}
	if tc != nil {
		cp.localCache.Add(cacheKey, &configCacheEntry{
			Value:     tc.ConfigValue,
			ExpiresAt: time.Now().Add(cp.provCfg.LocalCacheTTL),
		})
		return tc.ConfigValue, nil
	}

	return cp.getRaw(ctx, tenantID, key)
}

// GetScopedConfig retrieves a config value with full hierarchy resolution.
// Resolution: app override → realm override → tenant default → static default.
func (cp *ConfigProvider) GetScopedConfig(ctx context.Context, tenantID uuid.UUID, realmID, appID *uuid.UUID, key string) (json.RawMessage, error) {
	// Try app-scoped first
	if appID != nil {
		val, err := cp.GetAppConfig(ctx, tenantID, *appID, key)
		if err != nil {
			return nil, err
		}
		if val != nil {
			return val, nil
		}
	}

	// Try realm-scoped
	if realmID != nil {
		val, err := cp.GetRealmConfig(ctx, tenantID, *realmID, key)
		if err != nil {
			return nil, err
		}
		if val != nil {
			return val, nil
		}
	}

	// Fall back to tenant-level
	return cp.getRaw(ctx, tenantID, key)
}

// SetRealmConfig writes a config value at the realm scope.
func (cp *ConfigProvider) SetRealmConfig(ctx context.Context, tenantID, realmID uuid.UUID, key string, value json.RawMessage, updatedBy *uuid.UUID) error {
	encrypted, err := cp.EncryptValueForStorage(key, value)
	if err != nil {
		return err
	}

	if err := cp.repo.UpsertByScope(ctx, repositories.UpsertByScopeParams{
		TenantID:    tenantID,
		RealmID:     &realmID,
		ConfigKey:   key,
		ConfigValue: encrypted,
		UpdatedBy:   updatedBy,
	}); err != nil {
		return err
	}

	// Invalidate cached entry
	cp.localCache.Remove(scopedCacheKey(tenantID, &realmID, nil, key))
	return nil
}

// SetAppConfig writes a config value at the application scope.
func (cp *ConfigProvider) SetAppConfig(ctx context.Context, tenantID, appID uuid.UUID, key string, value json.RawMessage, updatedBy *uuid.UUID) error {
	encrypted, err := cp.EncryptValueForStorage(key, value)
	if err != nil {
		return err
	}

	if err := cp.repo.UpsertByScope(ctx, repositories.UpsertByScopeParams{
		TenantID:    tenantID,
		AppID:       &appID,
		ConfigKey:   key,
		ConfigValue: encrypted,
		UpdatedBy:   updatedBy,
	}); err != nil {
		return err
	}

	cp.localCache.Remove(scopedCacheKey(tenantID, nil, &appID, key))
	return nil
}

// --- Invalidation ---

// InvalidateKey evicts a single key from all cache layers and notifies other instances.
func (cp *ConfigProvider) InvalidateKey(ctx context.Context, tenantID uuid.UUID, configKey string) error {
	// 1. Remove from local LRU
	cp.localCache.Remove(localCacheKey(tenantID, configKey))

	if cp.redisClient != nil {
		// 2. Remove from Redis hash
		if err := cp.redisClient.HDel(ctx, redisHashKey(tenantID), configKey).Err(); err != nil {
			cp.logger.Warn("Failed to HDEL from Redis", zap.Error(err), zap.String("key", configKey))
		}

		// 3. Publish invalidation message
		msg := configInvalidationMessage{TenantID: tenantID.String(), ConfigKey: configKey}
		payload, _ := json.Marshal(msg)
		if err := cp.redisClient.Publish(ctx, ConfigInvalidationChannel, string(payload)).Err(); err != nil {
			cp.logger.Warn("Failed to publish config invalidation", zap.Error(err))
		}
	}

	return nil
}

// InvalidateTenant evicts all config entries for a tenant from all cache layers.
// Fix 3: Local LRU entries are now eagerly purged (no longer relying on TTL expiry).
func (cp *ConfigProvider) InvalidateTenant(ctx context.Context, tenantID uuid.UUID) error {
	if cp.redisClient != nil {
		// 1. Delete entire Redis hash for this tenant
		if err := cp.redisClient.Del(ctx, redisHashKey(tenantID)).Err(); err != nil {
			cp.logger.Warn("Failed to DEL Redis hash", zap.Error(err))
		}

		// 2. Publish invalidation message with empty key (means all keys for this tenant)
		msg := configInvalidationMessage{TenantID: tenantID.String(), ConfigKey: ""}
		payload, _ := json.Marshal(msg)
		if err := cp.redisClient.Publish(ctx, ConfigInvalidationChannel, string(payload)).Err(); err != nil {
			cp.logger.Warn("Failed to publish tenant config invalidation", zap.Error(err))
		}
	}

	// 3. Eagerly purge all known keys for this tenant from the local LRU.
	//    This closes the 30s stale window for security-sensitive configs.
	cp.purgeLocalCacheForTenant(tenantID)

	return nil
}

// purgeLocalCacheForTenant removes every known config key for the given tenant from the local LRU.
func (cp *ConfigProvider) purgeLocalCacheForTenant(tenantID uuid.UUID) {
	cp.registryMu.RLock()
	defer cp.registryMu.RUnlock()
	for key := range cp.keyRegistry {
		cp.localCache.Remove(localCacheKey(tenantID, key))
	}
}

// --- Background subscriber ---

// StartInvalidationSubscriber starts a background goroutine that listens for config invalidation
// messages on Redis pub/sub and evicts matching local cache entries.
func (cp *ConfigProvider) StartInvalidationSubscriber(ctx context.Context) {
	if cp.redisClient == nil {
		cp.logger.Info("Config invalidation subscriber skipped - Redis not available")
		return
	}

	subCtx, cancel := context.WithCancel(ctx)
	cp.cancelSubscriber = cancel

	go func() {
		pubsub := cp.redisClient.Subscribe(subCtx, ConfigInvalidationChannel)
		defer pubsub.Close() //nolint:errcheck

		cp.logger.Info("Config invalidation subscriber started")

		ch := pubsub.Channel()
		for {
			select {
			case <-subCtx.Done():
				cp.logger.Info("Config invalidation subscriber stopped")
				return
			case msg, ok := <-ch:
				if !ok {
					cp.logger.Info("Config invalidation channel closed")
					return
				}

				var invMsg configInvalidationMessage
				if err := json.Unmarshal([]byte(msg.Payload), &invMsg); err != nil {
					cp.logger.Warn("Failed to unmarshal invalidation message", zap.Error(err))
					continue
				}

				tenantID, err := uuid.Parse(invMsg.TenantID)
				if err != nil {
					cp.logger.Warn("Invalid tenant ID in invalidation message", zap.String("tenant_id", invMsg.TenantID))
					continue
				}

				if invMsg.ConfigKey != "" {
					// Evict single key from local LRU.
					cp.localCache.Remove(localCacheKey(tenantID, invMsg.ConfigKey))
					cp.logger.Debug("Evicted config from local cache",
						zap.String("tenant_id", invMsg.TenantID),
						zap.String("config_key", invMsg.ConfigKey),
					)
				} else {
					// Fix 3: Empty ConfigKey means tenant-wide invalidation — purge all local entries.
					cp.purgeLocalCacheForTenant(tenantID)
					cp.logger.Debug("Evicted all tenant config entries from local cache",
						zap.String("tenant_id", invMsg.TenantID),
					)
				}
			}
		}
	}()
}

// StopInvalidationSubscriber stops the background subscriber goroutine.
func (cp *ConfigProvider) StopInvalidationSubscriber() {
	if cp.cancelSubscriber != nil {
		cp.cancelSubscriber()
	}
}

// --- Metrics ---

// GetMetrics returns a point-in-time snapshot of cache performance metrics.
// Fix 1: Uses atomic Load() on each field — no mutex required.
func (cp *ConfigProvider) GetMetrics() ConfigProviderMetricsSnapshot {
	return ConfigProviderMetricsSnapshot{
		LocalHits:   cp.metrics.LocalHits.Load(),
		LocalMisses: cp.metrics.LocalMisses.Load(),
		RedisHits:   cp.metrics.RedisHits.Load(),
		RedisMisses: cp.metrics.RedisMisses.Load(),
		DBHits:      cp.metrics.DBHits.Load(),
		DBMisses:    cp.metrics.DBMisses.Load(),
	}
}
