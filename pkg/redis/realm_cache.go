// SPDX-License-Identifier: AGPL-3.0-or-later

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// RealmCache handles realm and tenant-realm mapping caching in Redis
// Used for high-performance realm lookups in the Full Realm Architecture
type RealmCache struct {
	client *Client
	prefix string
	ttl    time.Duration
}

// CachedRealm represents a cached realm
type CachedRealm struct {
	ID              uuid.UUID  `json:"id"`
	Slug            string     `json:"slug"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	Status          string     `json:"status"`
	ConnectionLimit int        `json:"connection_limit"`
	MaxTenants      int        `json:"max_tenants"`
	AllowedDomains  []string   `json:"allowed_domains,omitempty"`
	ParentRealmID   *uuid.UUID `json:"parent_realm_id,omitempty"`
	CachedAt        time.Time  `json:"cached_at"`
}

// CachedTenantRealm represents a cached tenant-realm mapping
type CachedTenantRealm struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	RealmID   uuid.UUID `json:"realm_id"`
	RealmSlug string    `json:"realm_slug"`
	RealmType string    `json:"realm_type"`
	IsPrimary bool      `json:"is_primary"`
	CachedAt  time.Time `json:"cached_at"`
}

// NewRealmCache creates a new realm cache
func NewRealmCache(client *Client, prefix string, ttl time.Duration) *RealmCache {
	return &RealmCache{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

// Key generation helpers
func (r *RealmCache) realmByIDKey(realmID uuid.UUID) string {
	return fmt.Sprintf("%s:realm:id:%s", r.prefix, realmID.String())
}

func (r *RealmCache) realmBySlugKey(slug string) string {
	return fmt.Sprintf("%s:realm:slug:%s", r.prefix, slug)
}

func (r *RealmCache) tenantRealmKey(tenantID uuid.UUID) string {
	return fmt.Sprintf("%s:tenant:%s:realm", r.prefix, tenantID.String())
}

func (r *RealmCache) realmTenantsKey(realmID uuid.UUID) string {
	return fmt.Sprintf("%s:realm:%s:tenants", r.prefix, realmID.String())
}

// SetRealm stores a realm in the cache (indexed by both ID and slug)
func (r *RealmCache) SetRealm(ctx context.Context, realm *CachedRealm) error {
	realm.CachedAt = time.Now()
	data, err := json.Marshal(realm)
	if err != nil {
		return fmt.Errorf("failed to marshal realm: %w", err)
	}

	pipe := r.client.Redis().Pipeline()

	// Store by ID
	pipe.Set(ctx, r.realmByIDKey(realm.ID), data, r.ttl)

	// Store by slug for slug lookups
	pipe.Set(ctx, r.realmBySlugKey(realm.Slug), data, r.ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("SetRealm: Exec failed: %w", err)
	}
	return nil
}

// GetRealmByID retrieves a realm by ID from the cache
func (r *RealmCache) GetRealmByID(ctx context.Context, realmID uuid.UUID) (*CachedRealm, error) {
	data, err := r.client.Redis().Get(ctx, r.realmByIDKey(realmID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("GetRealmByID: %w", err)
	}

	var realm CachedRealm
	if err := json.Unmarshal(data, &realm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal realm: %w", err)
	}

	return &realm, nil
}

// GetRealmBySlug retrieves a realm by slug from the cache
func (r *RealmCache) GetRealmBySlug(ctx context.Context, slug string) (*CachedRealm, error) {
	data, err := r.client.Redis().Get(ctx, r.realmBySlugKey(slug)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("GetRealmBySlug: %w", err)
	}

	var realm CachedRealm
	if err := json.Unmarshal(data, &realm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal realm: %w", err)
	}

	return &realm, nil
}

// DeleteRealm removes a realm from the cache
func (r *RealmCache) DeleteRealm(ctx context.Context, realmID uuid.UUID, slug string) error {
	keys := []string{r.realmByIDKey(realmID)}
	if slug != "" {
		keys = append(keys, r.realmBySlugKey(slug))
	}
	return r.client.Redis().Del(ctx, keys...).Err()
}

// SetTenantRealm stores a tenant-realm mapping in the cache
func (r *RealmCache) SetTenantRealm(ctx context.Context, mapping *CachedTenantRealm) error {
	mapping.CachedAt = time.Now()
	data, err := json.Marshal(mapping)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant-realm mapping: %w", err)
	}

	pipe := r.client.Redis().Pipeline()

	// Store tenant's realm mapping
	pipe.Set(ctx, r.tenantRealmKey(mapping.TenantID), data, r.ttl)

	// Add tenant to realm's tenant set
	pipe.SAdd(ctx, r.realmTenantsKey(mapping.RealmID), mapping.TenantID.String())
	pipe.Expire(ctx, r.realmTenantsKey(mapping.RealmID), r.ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("SetTenantRealm: Exec failed: %w", err)
	}
	return nil
}

// GetTenantRealm retrieves a tenant's realm mapping from the cache
func (r *RealmCache) GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*CachedTenantRealm, error) {
	data, err := r.client.Redis().Get(ctx, r.tenantRealmKey(tenantID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("GetTenantRealm: %w", err)
	}

	var mapping CachedTenantRealm
	if err := json.Unmarshal(data, &mapping); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tenant-realm mapping: %w", err)
	}

	return &mapping, nil
}

// DeleteTenantRealm removes a tenant-realm mapping from the cache
func (r *RealmCache) DeleteTenantRealm(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) error {
	pipe := r.client.Redis().Pipeline()

	// Delete tenant's realm mapping
	pipe.Del(ctx, r.tenantRealmKey(tenantID))

	// Remove tenant from realm's tenant set
	pipe.SRem(ctx, r.realmTenantsKey(realmID), tenantID.String())

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("DeleteTenantRealm: Exec failed: %w", err)
	}
	return nil
}

// GetRealmTenantCount returns the number of tenants in a realm
func (r *RealmCache) GetRealmTenantCount(ctx context.Context, realmID uuid.UUID) (int64, error) {
	return r.client.Redis().SCard(ctx, r.realmTenantsKey(realmID)).Result()
}

// InvalidateRealmTenants invalidates all tenant mappings for a realm
func (r *RealmCache) InvalidateRealmTenants(ctx context.Context, realmID uuid.UUID) error {
	// Get all tenant IDs in this realm
	tenantIDs, err := r.client.Redis().SMembers(ctx, r.realmTenantsKey(realmID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("InvalidateRealmTenants: %w", err)
	}

	if len(tenantIDs) == 0 {
		return nil
	}

	// Build keys to delete
	keys := make([]string, 0, len(tenantIDs)+1)
	for _, tid := range tenantIDs {
		if uid, err := uuid.Parse(tid); err == nil {
			keys = append(keys, r.tenantRealmKey(uid))
		}
	}
	keys = append(keys, r.realmTenantsKey(realmID))

	return r.client.Redis().Del(ctx, keys...).Err()
}

// Exists checks if a realm exists in the cache
func (r *RealmCache) Exists(ctx context.Context, realmID uuid.UUID) (bool, error) {
	result, err := r.client.Redis().Exists(ctx, r.realmByIDKey(realmID)).Result()
	if err != nil {
		return false, fmt.Errorf("Exists: %w", err)
	}
	return result > 0, nil
}

// RefreshRealm extends the TTL of a cached realm
func (r *RealmCache) RefreshRealm(ctx context.Context, realmID uuid.UUID, slug string) error {
	pipe := r.client.Redis().Pipeline()
	pipe.Expire(ctx, r.realmByIDKey(realmID), r.ttl)
	if slug != "" {
		pipe.Expire(ctx, r.realmBySlugKey(slug), r.ttl)
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("RefreshRealm: Exec failed: %w", err)
	}
	return nil
}

// RefreshTenantRealm extends the TTL of a cached tenant-realm mapping
func (r *RealmCache) RefreshTenantRealm(ctx context.Context, tenantID uuid.UUID, realmID uuid.UUID) error {
	pipe := r.client.Redis().Pipeline()
	pipe.Expire(ctx, r.tenantRealmKey(tenantID), r.ttl)
	pipe.Expire(ctx, r.realmTenantsKey(realmID), r.ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("RefreshTenantRealm: Exec failed: %w", err)
	}
	return nil
}

// WarmupRealm pre-populates the cache with a realm (called at startup or after DB changes)
func (r *RealmCache) WarmupRealm(ctx context.Context, realm *CachedRealm, tenantMappings []*CachedTenantRealm) error {
	// Set the realm
	if err := r.SetRealm(ctx, realm); err != nil {
		return fmt.Errorf("failed to cache realm: %w", err)
	}

	// Set all tenant mappings
	for _, mapping := range tenantMappings {
		if err := r.SetTenantRealm(ctx, mapping); err != nil {
			return fmt.Errorf("failed to cache tenant-realm mapping for tenant %s: %w", mapping.TenantID, err)
		}
	}

	return nil
}
