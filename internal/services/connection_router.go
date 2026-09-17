// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// ConnectionInfo holds the resolved connection parameters for a realm's
// dedicated database. It is safe to cache because realm database host
// assignments change only on provisioning or decommissioning events.
type ConnectionInfo struct {
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	DatabaseName string     `json:"database_name"`
	Schema       string     `json:"schema"`
	Username     string     `json:"username"`
	SSLMode      string     `json:"ssl_mode"`
	HostID       *uuid.UUID `json:"host_id,omitempty"`
	HostAlias    *string    `json:"host_alias,omitempty"`
}

// l1Entry is a single in-process cache entry with a monotonic expiry timestamp.
type l1Entry struct {
	info      *ConnectionInfo
	expiresAt time.Time
}

// ConnectionRouter resolves (realm_id) → ConnectionInfo through a 3-tier cache:
//
//	L1 — in-process sync.Map with a 30-second TTL (zero-allocation read path)
//	L2 — Redis hash with a 5-minute TTL  (shared across multiple replicas)
//	L3 — PostgreSQL query via RealmDatabaseRepository (authoritative source)
//
// InvalidateRealm must be called after any provisioning or decommissioning
// action so that subsequent lookups fetch fresh data from L3.
type ConnectionRouter struct {
	// L1: in-process cache. Values are *l1Entry; the map is never deleted from,
	// expired entries are overwritten lazily on the next write.
	l1Cache sync.Map
	l1TTL   time.Duration

	// L2: Redis cache.
	redis goredis.Cmdable
	l2TTL time.Duration

	// L3: authoritative database lookup.
	realmDBRepo RealmDatabaseRepository

	log *zap.SugaredLogger
}

const (
	defaultL1TTL = 30 * time.Second
	defaultL2TTL = 5 * time.Minute
)

// NewConnectionRouter creates a ConnectionRouter.
// redis may be nil; in that case the L2 tier is skipped and every cache miss
// falls through directly to L3 (PostgreSQL). This allows the router to operate
// correctly in environments where Redis is unavailable.
func NewConnectionRouter(
	redis goredis.Cmdable,
	realmDBRepo RealmDatabaseRepository,
	log *zap.SugaredLogger,
) *ConnectionRouter {
	return &ConnectionRouter{
		l1TTL:       defaultL1TTL,
		redis:       redis,
		l2TTL:       defaultL2TTL,
		realmDBRepo: realmDBRepo,
		log:         log,
	}
}

// l1Key returns the string key used in both the sync.Map and Redis.
func l1Key(realmID uuid.UUID) string {
	return "conn_route:realm:" + realmID.String()
}

// ResolveRealmDB returns the ConnectionInfo for a realm's dedicated database.
// The lookup order is L1 → L2 → L3. On a cache miss the result is populated
// back into all tiers that were missed.
//
// Returns (nil, nil) when the realm has no dedicated database record — callers
// should fall back to the shared master pool in that case.
func (r *ConnectionRouter) ResolveRealmDB(ctx context.Context, realmID uuid.UUID) (*ConnectionInfo, error) {
	key := l1Key(realmID)

	// ---- L1: in-process cache ------------------------------------------------
	if v, ok := r.l1Cache.Load(key); ok {
		entry := v.(*l1Entry)
		if time.Now().Before(entry.expiresAt) {
			return entry.info, nil
		}
		// Expired — fall through to L2/L3.
	}

	// ---- L2: Redis -----------------------------------------------------------
	if r.redis != nil {
		info, err := r.getFromRedis(ctx, key)
		if err != nil {
			// Non-fatal: Redis may be temporarily unavailable.
			r.log.Warnw("ConnectionRouter: Redis L2 miss (error)", "realm_id", realmID, "err", err)
		} else if info != nil {
			r.storeL1(key, info)
			return info, nil
		}
	}

	// ---- L3: database -------------------------------------------------------
	info, err := r.resolveFromDB(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("ConnectionRouter.ResolveRealmDB: %w", err)
	}

	if info != nil {
		r.storeL1(key, info)
		if r.redis != nil {
			if setErr := r.setInRedis(ctx, key, info); setErr != nil {
				r.log.Warnw("ConnectionRouter: failed to populate Redis L2 cache",
					"realm_id", realmID, "err", setErr)
			}
		}
	}

	return info, nil
}

// InvalidateRealm removes cached entries for a realm from both L1 and L2.
// Call this after ProvisionDatabase and DecommissionDatabase to ensure that
// the next lookup fetches fresh data from L3.
func (r *ConnectionRouter) InvalidateRealm(ctx context.Context, realmID uuid.UUID) {
	key := l1Key(realmID)

	// Remove from L1.
	r.l1Cache.Delete(key)

	// Remove from L2.
	if r.redis != nil {
		if err := r.redis.Del(ctx, key).Err(); err != nil {
			r.log.Warnw("ConnectionRouter: failed to delete Redis L2 key on invalidation",
				"realm_id", realmID, "err", err)
		}
	}

	r.log.Infow("ConnectionRouter: realm cache invalidated", "realm_id", realmID)
}

// resolveFromDB queries the RealmDatabaseRepository for the realm's active
// database record and maps it to a ConnectionInfo.
// Returns (nil, nil) when the realm has no dedicated database.
func (r *ConnectionRouter) resolveFromDB(ctx context.Context, realmID uuid.UUID) (*ConnectionInfo, error) {
	rd, err := r.realmDBRepo.GetByRealmID(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("GetByRealmID: %w", err)
	}
	if rd == nil {
		// Realm uses the shared pool — no dedicated connection info.
		return nil, nil
	}

	info := &ConnectionInfo{
		Host:         rd.Host,
		Port:         rd.Port,
		DatabaseName: rd.DatabaseName,
		Schema:       "public",
		Username:     rd.Username,
		SSLMode:      rd.SSLMode,
		HostID:       rd.HostID,
		HostAlias:    rd.HostAlias,
	}
	return info, nil
}

// storeL1 writes a ConnectionInfo into the in-process cache with the
// configured L1 TTL.
func (r *ConnectionRouter) storeL1(key string, info *ConnectionInfo) {
	r.l1Cache.Store(key, &l1Entry{
		info:      info,
		expiresAt: time.Now().Add(r.l1TTL),
	})
}

// getFromRedis fetches a ConnectionInfo from Redis. Returns (nil, nil) on a
// cache miss (redis.Nil error). Any other error is returned directly.
func (r *ConnectionRouter) getFromRedis(ctx context.Context, key string) (*ConnectionInfo, error) {
	data, err := r.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis GET: %w", err)
	}

	var info ConnectionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("unmarshal ConnectionInfo: %w", err)
	}
	return &info, nil
}

// StartCleanupLoop periodically evicts expired entries from the L1 in-process cache.
// Expired entries are normally overwritten lazily on the next write, but this loop
// ensures memory is reclaimed for realms that are no longer active.
//
// The cleanup interval is 5× the L1 TTL (2.5 minutes with the 30-second default).
// Call in a goroutine: go router.StartCleanupLoop(ctx)
func (r *ConnectionRouter) StartCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * r.l1TTL)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			evicted := 0
			r.l1Cache.Range(func(key, value any) bool {
				if entry, ok := value.(*l1Entry); ok {
					if now.After(entry.expiresAt) {
						r.l1Cache.Delete(key)
						evicted++
					}
				}
				return true
			})
			if evicted > 0 && r.log != nil {
				r.log.Debugw("L1 cache cleanup", "evicted", evicted)
			}
		case <-ctx.Done():
			return
		}
	}
}

// setInRedis serialises a ConnectionInfo and stores it in Redis with the L2 TTL.
func (r *ConnectionRouter) setInRedis(ctx context.Context, key string, info *ConnectionInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal ConnectionInfo: %w", err)
	}
	if err := r.redis.Set(ctx, key, data, r.l2TTL).Err(); err != nil {
		return fmt.Errorf("redis SET: %w", err)
	}
	return nil
}
