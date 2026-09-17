# Permission Cache System

A high-performance, multi-layer permission caching system for the ExampleSuite IAM service that replaces embedding permissions in JWT tokens with server-side resolution.

## Architecture

### Multi-Layer Caching Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                     Permission Check Flow                    │
└─────────────────────────────────────────────────────────────┘

Request → Layer 1: Local LRU Cache (30s TTL, 10k entries)
             ├─ HIT  → Return result (< 1μs)
             └─ MISS → Layer 2: Redis Check Cache (1m TTL)
                          ├─ HIT  → Cache in Layer 1 → Return (< 5ms)
                          └─ MISS → Layer 3: Redis Role Mapping (15m TTL)
                                       ├─ HIT  → Resolve + Cache → Return (< 10ms)
                                       └─ MISS → Load from DB → Cache → Return (< 50ms)
```

### Key Design Principles

1. **Ultra-Fast Local Cache**: Per-instance LRU cache serves most requests in microseconds
2. **Distributed Redis Cache**: Shared permission checks across all service instances
3. **Role-Based Mapping**: Cache role→permissions mappings with longer TTL
4. **Smart Invalidation**: Version-based invalidation avoids expensive scans
5. **Wildcard Support**: Efficient pattern matching for hierarchical permissions

## Cache Layers

### Layer 1: Local LRU Cache

- **Size**: 10,000 entries (configurable via `PERMISSION_CACHE_LOCAL_SIZE`)
- **TTL**: 30 seconds (configurable via `PERMISSION_CACHE_LOCAL_TTL`)
- **Key Format**: `sessionID:tenantID:permission`
- **Purpose**: Ultra-fast in-memory cache per service instance
- **Trade-off**: Not shared between instances, short TTL for consistency

**Performance**: ~0.5μs per check (2M+ checks/second per instance)

### Layer 2: Redis Permission Check Cache

- **TTL**: 1 minute (configurable via `PERMISSION_CACHE_CHECK_TTL`)
- **Key Format**: `hexxlock:session:{sessionID}:tenant:{tenantID}:perm_check:{hash}`
- **Value**: "1" (allowed) or "0" (denied)
- **Purpose**: Distributed cache of resolved permission checks
- **Invalidation**: Automatic TTL expiry + manual session invalidation

**Performance**: ~1-5ms per check (depends on network latency)

### Layer 3: Redis Role Permissions Mapping

- **TTL**: 15 minutes (configurable via `PERMISSION_CACHE_ROLE_MAPPING_TTL`)
- **Key Format**: `hexxlock:tenant:{tenantID}:role:{role}:permissions`
- **Value**: Redis SET of permission strings
- **Purpose**: Cache role definitions to avoid DB lookups
- **Invalidation**: Manual on role updates + version tracking

**Performance**: ~5-10ms for role resolution

## Configuration

### Environment Variables

```bash
# Local LRU cache size (number of entries)
PERMISSION_CACHE_LOCAL_SIZE=10000

# Local cache TTL (how long entries live in memory)
PERMISSION_CACHE_LOCAL_TTL=30s

# Redis permission check cache TTL
PERMISSION_CACHE_CHECK_TTL=1m

# Redis role→permissions mapping TTL
PERMISSION_CACHE_ROLE_MAPPING_TTL=15m
```

### Go Configuration

```go
config := &redis.PermissionCacheConfig{
    LocalSize:      10000,
    LocalTTL:       30 * time.Second,
    CheckTTL:       1 * time.Minute,
    RoleMappingTTL: 15 * time.Minute,
}

permCache, err := redis.NewPermissionCache(
    redisClient,
    logger,
    config,
    "hexxlock", // key prefix
)
```

## Usage

### 1. Initialize Permission Cache

```go
// In your IAM service initialization
permCache, err := redis.NewPermissionCache(
    redisClient,
    logger,
    nil, // use defaults
    "hexxlock",
)
if err != nil {
    log.Fatal(err)
}
```

### 2. Cache Role Permissions (On Role Load/Update)

```go
// When loading roles from database or when roles are updated
adminPerms := []string{
    "crm:*",              // Full CRM access
    "invoicing:*",        // Full invoicing access
    "hr:employees:read",  // Specific permission
}

err := permCache.CacheRolePermissions(ctx, tenantID, "admin", adminPerms)
```

### 3. Resolve User Effective Permissions (On Login)

```go
// When user logs in, resolve all their permissions
userRoles := []string{"admin", "user"}

effectivePerms, err := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
if err == redis.ErrRolePermissionsNotCached {
    // Load roles from database first
    for _, role := range userRoles {
        perms := loadRolePermissionsFromDB(tenantID, role)
        permCache.CacheRolePermissions(ctx, tenantID, role, perms)
    }

    // Try again
    effectivePerms, err = permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
}

// Cache individual permission checks for this session
for _, perm := range effectivePerms {
    permCache.CachePermissionCheck(ctx, sessionID, tenantID, perm, true)
}
```

### 4. Check Permission (In Middleware/Authorization)

```go
// Fast path - check cache
allowed, err := permCache.CheckPermission(ctx, sessionID, tenantID, "crm:contacts:read")

if err == redis.ErrPermissionNotCached {
    // Cache miss - resolve permission
    effectivePerms, err := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
    if err != nil {
        return false, err
    }

    // Check with wildcard matching
    allowed = permCache.CheckPermissionWithWildcard(effectivePerms, "crm:contacts:read")

    // Cache result for next time
    permCache.CachePermissionCheck(ctx, sessionID, tenantID, "crm:contacts:read", allowed)
}

return allowed, err
```

## Wildcard Permissions

The permission cache supports hierarchical wildcard permissions:

### Wildcard Patterns

| Pattern | Matches | Description |
|---------|---------|-------------|
| `*` | Everything | Universal wildcard |
| `crm:*` | `crm:contacts:read`, `crm:companies:write`, etc. | Module-level wildcard |
| `crm:contacts:*` | `crm:contacts:read`, `crm:contacts:write`, etc. | Resource-level wildcard |
| `crm:contacts:read` | `crm:contacts:read` only | Exact match |

### Example

```go
userPerms := []string{
    "crm:*",                // Full CRM access
    "invoicing:invoices:*", // All invoice operations
    "hr:employees:read",    // Specific read access
}

// These will return true:
permCache.CheckPermissionWithWildcard(userPerms, "crm:contacts:read")
permCache.CheckPermissionWithWildcard(userPerms, "crm:companies:delete")
permCache.CheckPermissionWithWildcard(userPerms, "invoicing:invoices:read")
permCache.CheckPermissionWithWildcard(userPerms, "hr:employees:read")

// These will return false:
permCache.CheckPermissionWithWildcard(userPerms, "invoicing:payments:read")
permCache.CheckPermissionWithWildcard(userPerms, "hr:employees:write")
```

## Cache Invalidation

### Invalidate Role Permissions

When role definitions change (permissions added/removed):

```go
err := permCache.InvalidateRolePermissions(ctx, tenantID, "admin")
```

This will:
1. Delete the role's permission set from Redis
2. Increment the tenant's role version counter
3. Force re-resolution of permission checks

### Invalidate Session Permissions

When a user's roles change:

```go
err := permCache.InvalidateSessionPermissions(ctx, sessionID, tenantID)
```

This will:
1. Scan and delete all permission checks for this session
2. Clear local cache entries (they expire naturally)

### Invalidate All Tenant Permissions

When tenant's permission structure changes:

```go
err := permCache.InvalidateTenantPermissions(ctx, tenantID)
```

This will:
1. Scan and delete all role permission mappings
2. Increment role version
3. Force complete re-resolution

## Monitoring

### Cache Metrics

```go
metrics := permCache.GetMetrics()

fmt.Printf("Total checks: %d\n", metrics.TotalChecks)
fmt.Printf("Local hit rate: %.2f%%\n",
    float64(metrics.LocalHits)/float64(metrics.TotalChecks)*100)
fmt.Printf("Redis hit rate: %.2f%%\n",
    float64(metrics.RedisHits)/float64(metrics.TotalChecks)*100)
```

### Available Metrics

- `TotalChecks`: Total permission checks performed
- `LocalHits`: Checks served from local cache
- `LocalMisses`: Checks not in local cache
- `RedisHits`: Checks served from Redis
- `RedisMisses`: Checks not in Redis
- `RoleResolutions`: Times role permissions were resolved
- `InvalidationCount`: Number of cache invalidations

### Expected Performance Targets

| Metric | Target | Excellent |
|--------|--------|-----------|
| Local Hit Rate | > 70% | > 85% |
| Redis Hit Rate | > 90% | > 95% |
| Total Cache Hit Rate | > 95% | > 98% |

## Redis Key Patterns

### Permission Check Keys

```
hexxlock:session:{sessionID}:tenant:{tenantID}:perm_check:{hash}
```

**TTL**: 1 minute
**Value**: "1" (allowed) or "0" (denied)

### Role Permission Keys

```
hexxlock:tenant:{tenantID}:role:{role}:permissions
```

**TTL**: 15 minutes
**Type**: SET
**Members**: Permission strings

### Role Version Key

```
hexxlock:tenant:{tenantID}:roles:version
```

**TTL**: None (persistent)
**Value**: Integer (incremented on role changes)

## Integration with Auth Middleware

### Shared Middleware (platform-services/shared/auth/middleware.go)

```go
type AuthMiddleware struct {
    permCache *redis.PermissionCache
    // ... other fields
}

func (m *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        sessionID := getSessionID(c)
        tenantID := getTenantID(c)

        // Fast permission check
        allowed, err := m.permCache.CheckPermission(
            c.Request.Context(),
            sessionID,
            tenantID,
            permission,
        )

        if err == redis.ErrPermissionNotCached {
            // Resolve from user session
            allowed = m.resolvePermission(c, permission)
        }

        if !allowed {
            c.AbortWithStatusJSON(403, gin.H{
                "error": "permission_denied",
                "message": "You don't have permission: " + permission,
            })
            return
        }

        c.Next()
    }
}
```

## Best Practices

### 1. Warm Up Cache on Login

```go
// After successful login, cache all user permissions
effectivePerms, _ := permCache.GetUserEffectivePermissions(ctx, tenantID, userRoles)
for _, perm := range effectivePerms {
    permCache.CachePermissionCheck(ctx, sessionID, tenantID, perm, true)
}
```

### 2. Use Wildcards Strategically

Grant `module:*` for admin roles rather than listing all specific permissions:

```go
// Good: Concise and maintainable
adminPerms := []string{"crm:*", "invoicing:*", "hr:*"}

// Bad: Verbose and hard to maintain
adminPerms := []string{
    "crm:contacts:read", "crm:contacts:write", "crm:contacts:delete",
    "crm:companies:read", "crm:companies:write", "crm:companies:delete",
    // ... 100 more permissions
}
```

### 3. Invalidate Promptly

Always invalidate cache immediately when permissions change:

```go
// After updating role permissions in database
updateRolePermissionsInDB(tenantID, role, newPermissions)

// Immediately invalidate cache
permCache.InvalidateRolePermissions(ctx, tenantID, role)
```

### 4. Handle Cache Misses Gracefully

```go
allowed, err := permCache.CheckPermission(ctx, sessionID, tenantID, permission)

switch err {
case nil:
    // Cache hit - use result
case redis.ErrPermissionNotCached:
    // Expected cache miss - resolve permission
    allowed = resolvePermission(ctx, sessionID, tenantID, permission)
default:
    // Unexpected error - log and deny access
    logger.Error("permission check failed", zap.Error(err))
    allowed = false
}
```

### 5. Monitor Cache Performance

```go
// Periodically log cache metrics
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    for range ticker.C {
        metrics := permCache.GetMetrics()
        logger.Info("permission cache metrics",
            zap.Int64("total", metrics.TotalChecks),
            zap.Float64("local_hit_rate",
                float64(metrics.LocalHits)/float64(metrics.TotalChecks)*100),
        )
    }
}()
```

## Error Handling

### Expected Errors

| Error | Meaning | Action |
|-------|---------|--------|
| `ErrPermissionNotCached` | Permission check not in cache | Resolve from roles |
| `ErrRolePermissionsNotCached` | Role permissions not in cache | Load from database |
| `ErrInvalidPermissionFormat` | Malformed permission string | Reject request |

### Example

```go
allowed, err := permCache.CheckPermission(ctx, sessionID, tenantID, permission)

switch err {
case nil:
    // Use allowed value
case redis.ErrPermissionNotCached:
    // Normal cache miss - resolve
    allowed = resolveFromRoles(ctx, userRoles, permission)
    permCache.CachePermissionCheck(ctx, sessionID, tenantID, permission, allowed)
case redis.ErrInvalidPermissionFormat:
    // Invalid permission string - log error
    logger.Error("invalid permission format", zap.String("permission", permission))
    allowed = false
default:
    // Unexpected Redis error - log and deny
    logger.Error("permission cache error", zap.Error(err))
    allowed = false
}
```

## Performance Optimization

### Tuning Cache Sizes

Based on your tenant size and request patterns:

**Small Deployment** (< 100 users):
```bash
PERMISSION_CACHE_LOCAL_SIZE=1000
PERMISSION_CACHE_LOCAL_TTL=1m
```

**Medium Deployment** (100-1000 users):
```bash
PERMISSION_CACHE_LOCAL_SIZE=10000
PERMISSION_CACHE_LOCAL_TTL=30s
```

**Large Deployment** (> 1000 users):
```bash
PERMISSION_CACHE_LOCAL_SIZE=50000
PERMISSION_CACHE_LOCAL_TTL=30s
```

### Redis Memory Usage

Estimate: ~200 bytes per permission check + ~100 bytes per role permission

**Example**: 1000 active sessions × 20 cached permissions = ~4MB Redis memory

## Security Considerations

1. **Cache Isolation**: All cache keys include `tenantID` to prevent cross-tenant access
2. **Permission Validation**: All permission strings are validated before caching
3. **Fail Closed**: On cache errors, deny access by default
4. **Audit Logging**: Cache invalidations should be logged for security audits

## Troubleshooting

### High Cache Miss Rate

**Symptoms**: Local hit rate < 50%, Redis hit rate < 80%

**Solutions**:
- Increase `PERMISSION_CACHE_LOCAL_SIZE`
- Increase `PERMISSION_CACHE_LOCAL_TTL`
- Pre-warm cache on login

### Memory Pressure

**Symptoms**: Redis memory usage growing unbounded

**Solutions**:
- Decrease `PERMISSION_CACHE_ROLE_MAPPING_TTL`
- Implement Redis eviction policy (volatile-ttl)
- Monitor with `permCache.GetMetrics()`

### Stale Permissions

**Symptoms**: Users have outdated permissions after role changes

**Solutions**:
- Verify invalidation is called on role updates
- Decrease cache TTLs temporarily
- Check role version increments with `GetRoleVersion()`

## Future Enhancements

1. **Attribute-Based Access Control (ABAC)**: Support for context-based permissions
2. **Permission Inheritance**: Hierarchical role structures
3. **Real-time Invalidation**: Redis Pub/Sub for instant cache updates across instances
4. **Metrics Export**: Prometheus metrics for monitoring dashboards
5. **Cache Warming**: Background job to pre-populate cache for active users
