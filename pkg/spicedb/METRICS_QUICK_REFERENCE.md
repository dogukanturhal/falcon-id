# SpiceDB Metrics Quick Reference

## Recording Metrics

### Permission Check
```go
import "github.com/dogukanturhal/platform-services/iam/pkg/spicedb"

start := time.Now()
allowed, err := client.CheckPermission(...)
duration := time.Since(start)

result := "allowed"
if !allowed {
    result = "denied"
}

spicedb.RecordPermissionCheck(tenantID, resourceType, permission, result, duration, cacheHit)
```

### Relationship Write
```go
start := time.Now()
zedToken, err := client.WriteUserRole(...)
duration := time.Since(start)

if err == nil {
    spicedb.RecordRelationshipWrite(tenantID, "role", "member", "touch", duration)
}
```

### Bulk Write
```go
start := time.Now()
zedToken, err := client.BulkWriteRelationships(...)
duration := time.Since(start)

if err == nil {
    spicedb.RecordBulkWrite(tenantID, len(updates), duration)
}
```

### Error
```go
if err != nil {
    spicedb.RecordError("permission_check", "spicedb_unavailable")
}
```

### Cache Operations
```go
// Cache invalidation
spicedb.RecordCacheInvalidation("user", tenantID)

// Cache size (periodic update)
spicedb.SetCacheSize("permission", estimatedBytes)
```

### Security Events
```go
// Tenant validation failure (CRITICAL)
if err := validateTenant(...); err != nil {
    spicedb.RecordTenantValidationFailure(tenantID, "context_mismatch")
}

// Suspicious activity
if denialRate > threshold {
    spicedb.RecordSuspiciousActivity(tenantID, "excessive_denials")
}
```

### Connection Health
```go
// On successful connection
spicedb.SetConnectionStatus(true)
spicedb.RecordConnectionAttempt()

// On connection failure
spicedb.SetConnectionStatus(false)
spicedb.RecordError("connect", "connection_refused")

// Health check
start := time.Now()
err := client.HealthCheck(ctx)
spicedb.RecordHealthCheck(time.Since(start))
```

### Lookup Operations
```go
start := time.Now()
resources, err := client.LookupResources(...)
duration := time.Since(start)

if err == nil {
    spicedb.RecordLookupResources(resourceType, permission, len(resources), duration)
}
```

### ZedToken Operations
```go
// Store
if err := store.StoreToken(...); err == nil {
    spicedb.RecordZedTokenStore("user_role", "success")
} else {
    spicedb.RecordZedTokenStore("user_role", "error")
}

// Retrieve
if token, err := store.GetToken(...); err == nil {
    spicedb.RecordZedTokenRetrieve("user_role", "hit")
} else {
    spicedb.RecordZedTokenRetrieve("user_role", "miss")
}
```

### Consistency Mode
```go
// Track consistency mode usage
spicedb.RecordConsistencyMode("minimize_latency")
spicedb.RecordConsistencyMode("at_least_as_fresh")
spicedb.RecordConsistencyMode("fully_consistent")
```

## Key Metrics

| Metric | Type | Purpose |
|--------|------|---------|
| `iam_spicedb_permission_check_total` | Counter | Track all permission checks |
| `iam_spicedb_permission_check_duration_seconds` | Histogram | Check latency |
| `iam_spicedb_cache_hit_total` | Counter | Cache effectiveness |
| `iam_spicedb_connection_status` | Gauge | Health status |
| `iam_spicedb_error_total` | Counter | Error tracking |
| `iam_spicedb_tenant_validation_failures_total` | Counter | Security (CRITICAL) |

## Common PromQL Queries

### Cache Hit Ratio
```promql
sum(rate(iam_spicedb_cache_hit_total[5m]))
/ (sum(rate(iam_spicedb_cache_hit_total[5m])) + sum(rate(iam_spicedb_cache_miss_total[5m])))
```

### p95 Latency
```promql
histogram_quantile(0.95, sum(rate(iam_spicedb_permission_check_duration_seconds_bucket[5m])) by (le))
```

### Error Rate
```promql
sum(rate(iam_spicedb_error_total[5m])) / sum(rate(iam_spicedb_permission_check_total[5m]))
```

### Top Tenants by Checks
```promql
topk(10, sum(rate(iam_spicedb_permission_check_total[5m])) by (tenant_id))
```

### Denial Rate
```promql
sum(rate(iam_spicedb_permission_check_total{result="denied"}[5m]))
/ sum(rate(iam_spicedb_permission_check_total[5m]))
```

## Alert Priority

### CRITICAL (Immediate Action)
- `SpiceDBConnectionDown` - Connection lost
- `SpiceDBCriticalLatency` - p95 > 500ms
- `SpiceDBTenantValidationFailures` - Security issue
- `SpiceDBCriticalErrorRate` - Error rate > 25%

### WARNING (Monitor & Investigate)
- `SpiceDBHighLatency` - p95 > 100ms
- `SpiceDBCacheHitRateLow` - Hit rate < 70%
- `SpiceDBHighDenialRate` - Denials > 30%
- `SpiceDBRateLimitQueueBuildup` - Queue > 50

### INFO (Awareness)
- `SpiceDBLargeBulkWriteDetected` - Large bulk ops
- `SpiceDBExcessiveFullyConsistentChecks` - Consistency mode usage

## Dashboard Access

- **URL**: https://grafana.example.local/d/example-spicedb
- **Variables**: datasource, tenant_id
- **Panels**: 17 across 5 categories

## Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Latency (p95) | 100ms | 500ms |
| Error Rate | 5% | 25% |
| Cache Hit Ratio | 70% | 50% |
| Denial Rate | 30% | 50% |
| Queue Size | 50 | 100 |
| Tenant Validation Failures | 0 | ANY |

## Integration Checklist

- [ ] Import metrics package
- [ ] Record permission checks
- [ ] Record relationship writes
- [ ] Record errors
- [ ] Set connection status
- [ ] Record security events
- [ ] Add consistency mode tracking
- [ ] Implement cache metrics
- [ ] Add lookup metrics
- [ ] Deploy Prometheus rules
- [ ] Import Grafana dashboard
- [ ] Configure alerting

## Files Reference

- **Metrics**: `/platform-services/iam/pkg/spicedb/metrics.go`
- **Alerts**: `/config/prometheus/rules/spicedb-alerts.yml`
- **Dashboard**: `/config/grafana/dashboards/spicedb-metrics.json`
- **Guide**: `/platform-services/iam/pkg/spicedb/MONITORING_GUIDE.md`
