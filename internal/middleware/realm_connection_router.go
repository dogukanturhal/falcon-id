// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
)

// realmDBPoolKey is the gin context key under which the realm-specific pool is
// stored. Exported via GetRealmPool so that handlers never hard-code the string.
const (
	realmDBPoolKey    = "realm_db_pool"
	realmStatusActive = "active"
)

// realmDatabaseLookup is the narrow interface consumed by RealmConnectionRouter.
// Depending only on this interface (rather than the concrete struct) keeps the
// middleware decoupled from the repository layer and makes unit testing possible
// without a real database.
type realmDatabaseLookup interface {
	GetByRealmID(ctx context.Context, realmID uuid.UUID) (*models.RealmDatabase, error)
}

// RealmConnectionRouter routes incoming requests to a realm-specific pgxpool.Pool.
//
// For realms that have no dedicated database record in realm_databases, the
// defaultPool (shared pool) is used transparently. For realms with a dedicated
// database, a pool is created on first use and then cached for the lifetime of
// the process.
//
// The middleware is safe for concurrent use: a sync.Map guards the pool cache
// and a sync.Mutex serialises pool creation so that two goroutines racing on
// the same realm only create one pool.
//
// Usage:
//
//	router := NewRealmConnectionRouter(defaultPool, realmDBRepo, encSvc, log)
//	engine.Use(router.Middleware())
//
//	// In a handler:
//	pool := GetRealmPool(c) // never nil when middleware is applied
type RealmConnectionRouter struct {
	defaultPool *pgxpool.Pool
	repo        realmDatabaseLookup
	encryption  *crypto.EncryptionService // may be nil — passwords treated as plaintext
	log         *zap.Logger
	pools       sync.Map // map[uuid.UUID]*pgxpool.Pool
	mu          sync.Mutex
}

// NewRealmConnectionRouter constructs a RealmConnectionRouter.
//
//   - defaultPool: used for shared/standard realms — must not be nil.
//   - repo: the RealmDatabaseRepository — must not be nil.
//   - encryption: AES-GCM service for decrypting passwords at rest; pass nil to
//     treat stored passwords as plaintext (not recommended in production).
//   - log: structured logger; pass zap.NewNop() to suppress output.
func NewRealmConnectionRouter(
	defaultPool *pgxpool.Pool,
	repo *repositories.RealmDatabaseRepository,
	encryption *crypto.EncryptionService,
	log *zap.Logger,
) *RealmConnectionRouter {
	if log == nil {
		log = zap.NewNop()
	}
	return &RealmConnectionRouter{
		defaultPool: defaultPool,
		repo:        repo,
		encryption:  encryption,
		log:         log,
	}
}

// newRealmConnectionRouterWithRepo constructs a RealmConnectionRouter using the
// realmDatabaseLookup interface directly. This is package-internal and used by
// unit tests to inject a stub without a real database.
func newRealmConnectionRouterWithRepo(
	defaultPool *pgxpool.Pool,
	repo realmDatabaseLookup,
	encryption *crypto.EncryptionService,
	log *zap.Logger,
) *RealmConnectionRouter {
	if log == nil {
		log = zap.NewNop()
	}
	return &RealmConnectionRouter{
		defaultPool: defaultPool,
		repo:        repo,
		encryption:  encryption,
		log:         log,
	}
}

// Middleware returns a gin.HandlerFunc that injects the realm-appropriate pool
// into the context under the key realmDBPoolKey.
//
// The middleware always calls c.Next() — it never aborts on pool lookup
// failures. Instead it degrades gracefully to the default pool, logs a warning,
// and lets the request continue. This makes the feature a soft rollout rather
// than a hard dependency.
func (r *RealmConnectionRouter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		realmIDVal, exists := c.Get("realm_id")
		if !exists {
			c.Set(realmDBPoolKey, r.defaultPool)
			c.Next()
			return
		}

		realmID, ok := realmIDVal.(uuid.UUID)
		if !ok || realmID == uuid.Nil {
			c.Set(realmDBPoolKey, r.defaultPool)
			c.Next()
			return
		}

		pool, err := r.getOrCreatePool(c.Request.Context(), realmID)
		if err != nil {
			r.log.Warn("realm_connection_router: failed to obtain realm pool, using default",
				zap.String("realm_id", realmID.String()),
				zap.Error(err),
			)
			c.Set(realmDBPoolKey, r.defaultPool)
			c.Next()
			return
		}

		c.Set(realmDBPoolKey, pool)
		c.Next()
	}
}

// getOrCreatePool returns the pool for realmID, creating it when it is not yet
// cached. Returns the default pool (with a nil error) when the realm has no
// dedicated DB entry.
func (r *RealmConnectionRouter) getOrCreatePool(ctx context.Context, realmID uuid.UUID) (*pgxpool.Pool, error) {
	// Fast path: already cached.
	if v, ok := r.pools.Load(realmID); ok {
		return v.(*pgxpool.Pool), nil
	}

	// Slow path: serialise pool creation.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check inside the lock to guard against two goroutines both missing
	// the fast path and racing here.
	if v, ok := r.pools.Load(realmID); ok {
		return v.(*pgxpool.Pool), nil
	}

	realmDB, err := r.repo.GetByRealmID(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("getOrCreatePool: lookup: %w", err)
	}
	if realmDB == nil {
		// No dedicated DB configured for this realm — use the shared pool.
		// We do NOT cache this absence so that a later provisioning of a
		// dedicated DB is picked up on the next request without a restart.
		return r.defaultPool, nil
	}

	if realmDB.Status != realmStatusActive {
		r.log.Warn("realm_connection_router: realm database is not active, using default",
			zap.String("realm_id", realmID.String()),
			zap.String("db_status", realmDB.Status),
		)
		return r.defaultPool, nil
	}

	pool, err := r.buildPool(ctx, realmID, realmDB)
	if err != nil {
		return nil, err
	}

	r.pools.Store(realmID, pool)

	r.log.Info("realm_connection_router: created dedicated pool",
		zap.String("realm_id", realmID.String()),
		zap.String("host", realmDB.Host),
		zap.String("database", realmDB.DatabaseName),
	)

	return pool, nil
}

// buildPool assembles a pgxpool.Pool from a RealmDatabase config record.
func (r *RealmConnectionRouter) buildPool(
	ctx context.Context,
	realmID uuid.UUID,
	realmDB *models.RealmDatabase,
) (*pgxpool.Pool, error) {
	password := realmDB.PasswordEncrypted
	if r.encryption != nil && password != "" {
		decrypted, err := r.encryption.Decrypt(password)
		if err != nil {
			return nil, fmt.Errorf("buildPool: decrypt password for realm %s: %w", realmID, err)
		}
		password = decrypted
	}

	sslMode := realmDB.SSLMode
	if sslMode == "" {
		sslMode = "require"
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		realmDB.Username, password,
		realmDB.Host, realmDB.Port,
		realmDB.DatabaseName, sslMode,
	)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("buildPool: parse DSN for realm %s: %w", realmID, err)
	}

	maxConns := int32(realmDB.PoolSize) //nolint:gosec // value is bounded by config, safe conversion
	if maxConns <= 0 {
		maxConns = 20
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = maxConns / 4

	connMaxLifetimeMin := realmDB.ConnMaxLifetimeMin
	if connMaxLifetimeMin <= 0 {
		connMaxLifetimeMin = 30
	}
	cfg.MaxConnLifetime = time.Duration(connMaxLifetimeMin) * time.Minute
	cfg.MaxConnIdleTime = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("buildPool: create pool for realm %s: %w", realmID, err)
	}
	return pool, nil
}

// GetRealmPool retrieves the realm-specific pool injected by RealmConnectionRouter.
// Returns nil when the middleware was not applied or the context value has an
// unexpected type (which should never occur in practice).
func GetRealmPool(c *gin.Context) *pgxpool.Pool {
	v, exists := c.Get(realmDBPoolKey)
	if !exists {
		return nil
	}
	p, _ := v.(*pgxpool.Pool)
	return p
}

// InvalidatePool removes a cached pool for the given realm and closes it.
// Call this when a realm's database configuration changes so that the next
// request obtains a fresh connection with the updated credentials.
func (r *RealmConnectionRouter) InvalidatePool(realmID uuid.UUID) {
	if v, loaded := r.pools.LoadAndDelete(realmID); loaded {
		v.(*pgxpool.Pool).Close()
		r.log.Info("realm_connection_router: pool invalidated",
			zap.String("realm_id", realmID.String()),
		)
	}
}

// CloseAll closes every cached realm-specific pool. Intended to be called
// during graceful shutdown after the HTTP server has stopped accepting requests.
// The default pool is not touched here — its lifecycle is owned by the caller.
func (r *RealmConnectionRouter) CloseAll() {
	r.pools.Range(func(key, value any) bool {
		value.(*pgxpool.Pool).Close()
		r.pools.Delete(key)
		return true
	})
}
