// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"

	shareddb "github.com/dogukanturhal/falcon-id/internal/shared/database"
	sharedtracing "github.com/dogukanturhal/falcon-id/internal/shared/tracing"
	"github.com/dogukanturhal/falcon-id/internal/shared/vault"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/database"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/pkg/redis"
	"github.com/dogukanturhal/falcon-id/pkg/spicedb"
)

// Infrastructure holds all infrastructure dependencies.
type Infrastructure struct {
	Config            *config.Config
	DB                *database.PostgresDB
	ControlPlaneDB    *database.PostgresDB
	RedisClient       *redis.Client
	RateLimiter       *redis.RateLimiter
	SessionCache      *redis.SessionCache
	TokenBlacklist    *redis.TokenBlacklist
	SpiceDBClient     *spicedb.Client
	WatchService      *spicedb.WatchService
	EncryptionService *crypto.EncryptionService
	VaultClient       *vault.Client
	TracerProvider    *trace.TracerProvider
}

// initInfrastructure initializes all infrastructure components.
func initInfrastructure() (*Infrastructure, error) {
	ctx := context.Background()

	vaultClient, transitClient, dbClient := initVaultClients(ctx)
	loadVaultSecrets(ctx, vaultClient, transitClient, dbClient)

	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("initInfrastructure: LoadConfig failed: %w", err)
	}

	logger.InitLogger(cfg.LogLevel, cfg.Environment)
	logVaultStatus(vaultClient, transitClient, dbClient)
	logger.Info("Starting IAM Service",
		zap.String("environment", cfg.Environment),
		zap.String("port", cfg.ServicePort),
	)

	if err := crypto.InitDefaultTokenHasher(cfg.TokenHashSalt); err != nil {
		logger.Fatal("Failed to initialize token hasher", zap.Error(err))
	}
	logger.Info("Token hasher initialized")

	encryptionService := initEncryptionService(cfg)
	tracerProvider := initTracing(cfg)

	shareddb.ValidateProductionSSL(cfg.DatabaseURL)
	if cfg.ControlPlaneDatabaseURL != "" {
		shareddb.ValidateProductionSSL(cfg.ControlPlaneDatabaseURL)
	}

	db := connectDataPlaneDB(cfg)
	controlPlaneDB := connectControlPlaneDB(cfg)

	redisClient, rateLimiter, sessionCache, tokenBlacklist := initRedisComponents(cfg)
	spicedbClient := initSpiceDB(cfg, redisClient)
	watchService := initWatchService(spicedbClient, redisClient)

	return &Infrastructure{
		Config:            cfg,
		DB:                db,
		ControlPlaneDB:    controlPlaneDB,
		RedisClient:       redisClient,
		RateLimiter:       rateLimiter,
		SessionCache:      sessionCache,
		TokenBlacklist:    tokenBlacklist,
		SpiceDBClient:     spicedbClient,
		WatchService:      watchService,
		EncryptionService: encryptionService,
		VaultClient:       vaultClient,
		TracerProvider:    tracerProvider,
	}, nil
}

// initVaultClients initializes Vault clients, logging warnings on failure and returning nils on error.
func initVaultClients(ctx context.Context) (*vault.Client, *vault.TransitClient, *vault.DatabaseClient) {
	vaultClient, transitClient, dbClient, err := vault.InitVaultClients(ctx)
	if err != nil {
		slog.Warn("Failed to initialize Vault clients", "error", err)
		slog.Info("Continuing with environment variable fallback...")
	}
	return vaultClient, transitClient, dbClient
}

// loadVaultSecrets loads secrets from Vault into Viper defaults when Vault is enabled.
func loadVaultSecrets(ctx context.Context, vaultClient *vault.Client, transitClient *vault.TransitClient, dbClient *vault.DatabaseClient) {
	if vaultClient == nil || !vaultClient.IsEnabled() {
		return
	}
	configLoader := vault.InitConfigLoader(vaultClient)
	if transitClient != nil {
		configLoader.SetTransitClient(transitClient)
	}
	if dbClient != nil {
		configLoader.SetDatabaseClient(dbClient)
	}
	if err := configLoader.SetViperDefaults(ctx); err != nil {
		slog.Warn("Failed to load secrets from Vault", "error", err)
		slog.Info("Continuing with environment variable fallback...")
	} else {
		slog.Info("Secrets loaded from Vault successfully")
	}
}

// logVaultStatus logs the Vault integration status after the logger is initialized.
func logVaultStatus(vaultClient *vault.Client, transitClient *vault.TransitClient, dbClient *vault.DatabaseClient) {
	if vaultClient != nil && vaultClient.IsEnabled() {
		logger.Info("Vault integration enabled",
			zap.Bool("transit_enabled", transitClient != nil),
			zap.Bool("database_credentials_enabled", dbClient != nil),
		)
		return
	}
	logger.Info("Vault integration disabled, using environment variables for secrets")
}

// initEncryptionService creates the AES-256-GCM encryption service for PII protection.
// Returns nil when ENCRYPTION_KEY is not configured (logs a GDPR compliance warning).
func initEncryptionService(cfg *config.Config) *crypto.EncryptionService {
	if cfg.EncryptionKey == "" {
		logger.Warn("ENCRYPTION_KEY not configured - PII will NOT be encrypted (GDPR compliance risk)")
		return nil
	}
	svc, err := crypto.NewEncryptionService(cfg.EncryptionKey)
	if err != nil {
		logger.Fatal("Failed to initialize encryption service", zap.Error(err))
	}
	logger.Info("Encryption service initialized for PII protection (GDPR Article 32)")
	return svc
}

// initTracing initializes OpenTelemetry tracing when OTLP_ENDPOINT is set.
func initTracing(cfg *config.Config) *trace.TracerProvider {
	if cfg.OTLPEndpoint == "" {
		return nil
	}
	tp, err := sharedtracing.InitTracer(cfg.ServiceName, cfg.OTLPEndpoint)
	if err != nil {
		logger.Warn("Failed to initialize tracing, continuing without distributed tracing", zap.Error(err))
		return nil
	}
	logger.Info("OpenTelemetry tracing initialized", zap.String("endpoint", cfg.OTLPEndpoint))
	return tp
}

// connectDataPlaneDB connects to the primary (data plane) PostgreSQL database.
func connectDataPlaneDB(cfg *config.Config) *database.PostgresDB {
	db, err := database.NewPostgresDBWithPool(cfg.DatabaseURL, shareddb.LoadPoolConfigPrefixed("DB_"))
	if err != nil {
		logger.Fatal("Failed to connect to data plane database", zap.Error(err))
	}
	logger.Info("Connected to data plane database")
	return db
}

// connectControlPlaneDB connects to the control plane PostgreSQL database.
// Returns nil and logs a warning when the URL is not configured or the connection
// still fails after transient errors (53300, network, ...) were retried.
func connectControlPlaneDB(cfg *config.Config) *database.PostgresDB {
	if cfg.ControlPlaneDatabaseURL == "" {
		logger.Warn("Control plane database URL not configured, platform admin features will be unavailable")
		return nil
	}
	db, err := database.NewPostgresDBWithPool(cfg.ControlPlaneDatabaseURL, shareddb.LoadPoolConfigPrefixed("CONTROL_PLANE_DB_"))
	if err != nil {
		logger.Warn("Failed to connect to control plane database, platform admin features will be unavailable",
			zap.Error(err),
		)
		return nil
	}
	logger.Info("Connected to control plane database")
	return db
}

// initRedisComponents connects to Redis and initializes all Redis-backed sub-components.
// Returns nils for all components when REDIS_URL is not configured or the connection fails,
// unless REDIS_REQUIRED is set: then either case stops startup.
func initRedisComponents(cfg *config.Config) (*redis.Client, *redis.RateLimiter, *redis.SessionCache, *redis.TokenBlacklist) {
	if cfg.RedisURL == "" {
		if err := redisRequiredError(cfg, nil); err != nil {
			logger.Fatal(err.Error())
		}
		return nil, nil, nil, nil
	}

	redisCfg := &redis.Config{
		URL:             cfg.RedisURL,
		MaxRetries:      cfg.RedisMaxRetries,
		MinIdleConns:    cfg.RedisMinIdleConns,
		MaxIdleConns:    cfg.RedisMinIdleConns * 2,
		ConnMaxLifetime: cfg.RedisConnMaxLifetime,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		Environment:     cfg.Environment,
	}

	redisClient, err := redis.NewClient(redisCfg, logger.Log)
	if err != nil {
		if fatal := redisRequiredError(cfg, err); fatal != nil {
			logger.Fatal(fatal.Error(), zap.Error(err), zap.String("redis_url", redactedRedisURL(cfg.RedisURL)))
		}
		logger.Warn("Failed to connect to Redis, continuing without Redis features",
			zap.Error(err),
			zap.String("redis_url", redactedRedisURL(cfg.RedisURL)),
		)
		return nil, nil, nil, nil
	}

	logger.Info("Connected to Redis")
	rateLimiter := redis.NewRateLimiter(redisClient, "iam:ratelimit:")
	sessionCache := redis.NewSessionCache(redisClient, "iam:session:", cfg.RedisSessionCacheTTL)
	sessionCache.SetIdpAbsoluteCap(cfg.SessionTTLRememberMe)
	tokenBlacklist := redis.NewTokenBlacklist(redisClient, "iam:blacklist:")
	logger.Info("Redis components initialized",
		zap.Bool("rate_limiter", rateLimiter != nil),
		zap.Bool("session_cache", sessionCache != nil),
		zap.Bool("token_blacklist", tokenBlacklist != nil),
	)
	return redisClient, rateLimiter, sessionCache, tokenBlacklist
}

// initSpiceDB initializes the SpiceDB client when SpiceDB is enabled and Redis is available.
func initSpiceDB(cfg *config.Config, redisClient *redis.Client) *spicedb.Client {
	if !cfg.SpiceDBEnabled || redisClient == nil {
		logger.Info("SpiceDB disabled - using traditional RBAC/ABAC authorization")
		return nil
	}

	client, err := spicedb.NewClient(context.Background(), cfg, redisClient.Redis())
	if err != nil {
		logger.Error("Failed to initialize SpiceDB client",
			zap.Error(err),
			zap.String("endpoint", cfg.SpiceDBEndpoint),
		)
		return nil
	}

	logger.Info("SpiceDB client initialized successfully",
		zap.String("endpoint", cfg.SpiceDBEndpoint),
	)
	return client
}

// initWatchService initializes the SpiceDB WatchService for real-time permission propagation.
//
// The service streams relationship updates from SpiceDB, invalidates the Redis permission
// cache, and publishes per-user Pub/Sub notifications delivered to browsers via SSE.
// Returns nil when SpiceDB or Redis are unavailable.
func initWatchService(spicedbClient *spicedb.Client, redisClient *redis.Client) *spicedb.WatchService {
	if spicedbClient == nil || redisClient == nil {
		logger.Info("SpiceDB WatchService skipped (SpiceDB or Redis not available)")
		return nil
	}

	watchService := spicedb.NewWatchService(
		spicedbClient.AuthzedClient(),
		redisClient.Redis(),
		logger.Log,
		spicedb.DefaultWatchConfig(),
	)
	watchService.RegisterCacheInvalidationHandler()
	watchService.RegisterUserNotificationHandler()

	go func() {
		if err := watchService.Start(context.Background()); err != nil {
			logger.Error("SpiceDB WatchService stopped unexpectedly", zap.Error(err))
		}
	}()

	logger.Info("SpiceDB WatchService started (real-time permission propagation enabled)")
	return watchService
}

// Close cleans up infrastructure resources.
func (infra *Infrastructure) Close() {
	if infra.WatchService != nil {
		infra.WatchService.Stop()
	}
	if infra.DB != nil {
		infra.DB.Close()
	}
	if infra.ControlPlaneDB != nil {
		infra.ControlPlaneDB.Close()
	}
	if infra.RedisClient != nil {
		_ = infra.RedisClient.Close()
	}
	if infra.VaultClient != nil {
		_ = infra.VaultClient.Close()
	}
}

// redactedRedisURL strips credentials from a Redis URL before it is logged:
// with per-client ACL users the URL carries the username and password.
func redactedRedisURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable redis url>"
	}
	return u.Redacted()
}

// redisRequiredError says whether a missing Redis must stop startup: only when
// REDIS_REQUIRED is set, for an empty REDIS_URL (connectErr nil) or a failed connect.
func redisRequiredError(cfg *config.Config, connectErr error) error {
	if !cfg.RedisRequired {
		return nil
	}
	if connectErr == nil {
		return errors.New("REDIS_REQUIRED is set but REDIS_URL is empty; refusing to start without revocation and rate limits")
	}
	return errors.New("failed to connect to Redis and REDIS_REQUIRED is set; refusing to start without revocation and rate limits")
}
