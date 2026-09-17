# SpiceDB Monitoring & Metrics Guide

## Overview

This guide covers the comprehensive monitoring and metrics implementation for SpiceDB operations in the IAM service. The monitoring stack provides visibility into permission checks, relationship writes, cache performance, errors, and security events.

## Architecture

```
┌─────────────┐
│   SpiceDB   │ ──────────┐
│   Client    │           │
└─────────────┘           │
                          ├──> Prometheus Metrics
┌─────────────┐           │
│   Metrics   │ ──────────┘
│   Package   │
└─────────────┘
       │
       ├──> Prometheus Server
       │         │
       │         ├──> Alert Manager
       │         └──> Grafana Dashboards
       │
       └──> Structured Logs
```

## Metrics Categories

### 1. Permission Check Metrics

**iam_spicedb_permission_check_total**
- **Type**: Counter
- **Labels**: `tenant_id`, `resource_type`, `permission`, `result`
- **Description**: Total permission checks performed
- **Usage**: Track authorization activity and denial rates

**iam_spicedb_permission_check_duration_seconds**
- **Type**: Histogram
- **Labels**: `resource_type`, `cache_hit`
- **Buckets**: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s
- **Description**: Permission check latency
- **Usage**: Monitor performance and SLA compliance

**iam_spicedb_consistency_mode_total**
- **Type**: Counter
- **Labels**: `mode` (minimize_latency, at_least_as_fresh, fully_consistent)
- **Description**: Consistency mode usage tracking
- **Usage**: Understand consistency vs performance trade-offs

### 2. Relationship Write Metrics

**iam_spicedb_relationship_write_total**
- **Type**: Counter
- **Labels**: `tenant_id`, `resource_type`, `relation`, `operation`
- **Description**: Relationship write operations
- **Usage**: Track permission assignment activity

**iam_spicedb_relationship_write_duration_seconds**
- **Type**: Histogram
- **Labels**: `resource_type`, `operation`
- **Buckets**: 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s
- **Description**: Write operation latency
- **Usage**: Monitor write performance

**iam_spicedb_bulk_write_size**
- **Type**: Histogram
- **Labels**: `tenant_id`
- **Buckets**: 1, 5, 10, 25, 50, 100, 250, 500, 1000
- **Description**: Number of relationships in bulk writes
- **Usage**: Track bulk operation patterns

### 3. Cache Metrics

**iam_spicedb_cache_hit_total** / **iam_spicedb_cache_miss_total**
- **Type**: Counter
- **Labels**: `cache_type`, `tenant_id`
- **Description**: Cache hits and misses
- **Usage**: Monitor cache effectiveness

**iam_spicedb_cache_invalidation_total**
- **Type**: Counter
- **Labels**: `invalidation_type`, `tenant_id`
- **Description**: Cache invalidation events
- **Usage**: Track cache churn and invalidation storms

### 4. Error & Security Metrics

**iam_spicedb_error_total**
- **Type**: Counter
- **Labels**: `operation`, `error_type`
- **Description**: Errors by operation and type
- **Usage**: Monitor error rates and types

**iam_spicedb_tenant_validation_failures_total**
- **Type**: Counter
- **Labels**: `tenant_id`, `failure_type`
- **Description**: Tenant isolation validation failures (SECURITY)
- **Usage**: Detect tenant boundary violations

**iam_spicedb_suspicious_activity_total**
- **Type**: Counter
- **Labels**: `tenant_id`, `activity_type`
- **Description**: Suspicious authorization patterns detected
- **Usage**: Security monitoring and threat detection

### 5. Connection & Health Metrics

**iam_spicedb_connection_status**
- **Type**: Gauge
- **Values**: 1 = connected, 0 = disconnected
- **Description**: SpiceDB connection health
- **Usage**: Monitor availability

**iam_spicedb_health_check_duration_seconds**
- **Type**: Histogram
- **Description**: Health check operation latency
- **Usage**: Monitor SpiceDB responsiveness

## Prometheus Alerts

### Critical Alerts

1. **SpiceDBConnectionDown**
   - **Condition**: Connection status = 0 for 1 minute
   - **Impact**: Authorization may fail or be degraded
   - **Action**: Check SpiceDB service health, network connectivity

2. **SpiceDBCriticalLatency**
   - **Condition**: p95 latency > 500ms for 2 minutes
   - **Impact**: Severe performance degradation
   - **Action**: Investigate SpiceDB load, consider scaling

3. **SpiceDBTenantValidationFailures**
   - **Condition**: Any tenant validation failures detected
   - **Impact**: SECURITY - potential tenant isolation bypass
   - **Action**: Immediate investigation required, review audit logs

4. **SpiceDBCriticalErrorRate**
   - **Condition**: Error rate > 25% for 2 minutes
   - **Impact**: Major service degradation
   - **Action**: Check SpiceDB health, review error logs

### Warning Alerts

1. **SpiceDBHighLatency**
   - **Condition**: p95 latency > 100ms for 5 minutes
   - **Threshold**: 100ms
   - **Action**: Monitor trend, investigate if persists

2. **SpiceDBCacheHitRateLow**
   - **Condition**: Cache hit rate < 70% for 10 minutes
   - **Impact**: Performance degradation
   - **Action**: Review cache configuration, check for invalidation storms

3. **SpiceDBHighDenialRate**
   - **Condition**: Denial rate > 30% for 10 minutes
   - **Impact**: May indicate misconfiguration
   - **Action**: Review permission assignments and policies

4. **SpiceDBRateLimitQueueBuildup**
   - **Condition**: Queue size > 50 for 5 minutes
   - **Impact**: Increased latency
   - **Action**: Consider increasing concurrency limit

## Grafana Dashboard

### Access

**URL**: `https://grafana.example.local/d/example-spicedb`

### Panels

#### Overview Row
- **Connection Status**: Real-time connection health gauge
- **Permission Check Rate**: Request rate over time
- **Permission Check Latency**: p50, p95, p99 latencies
- **Cache Hit Ratio**: Current cache effectiveness

#### Cache Performance Row
- **Cache Hit/Miss Rate**: Detailed cache performance by type
- **Cache Invalidations**: Invalidation rate by type

#### Relationship Operations Row
- **Relationship Write Rate**: Write operations by type
- **Relationship Write Latency**: p95 latency by operation

#### Errors & Security Row
- **Error Rate by Type**: Errors categorized by operation and type
- **Security Events**: Validation failures and suspicious activity (CRITICAL)

#### Resource Operations Row
- **Operations by Resource Type**: Distribution pie chart
- **Lookup Resources Latency**: p95 lookup performance

### Variables

- **datasource**: Prometheus data source
- **tenant_id**: Filter by specific tenant (supports "All")

## Integration Guide

### 1. Recording Metrics in Code

```go
import (
    "time"
    "github.com/google/uuid"
    "github.com/dogukanturhal/platform-services/iam/pkg/spicedb"
)

// Record a permission check
start := time.Now()
allowed, err := client.CheckPermission(ctx, tenantID, userID, objectType, objectID, permission)
duration := time.Since(start)

result := "allowed"
if !allowed {
    result = "denied"
}

spicedb.RecordPermissionCheck(
    tenantID,
    objectType,
    permission,
    result,
    duration,
    cacheHit,
)
```

### 2. Recording Relationship Writes

```go
start := time.Now()
zedToken, err := client.WriteUserRole(ctx, tenantID, userID, roleID)
duration := time.Since(start)

if err == nil {
    spicedb.RecordRelationshipWrite(
        tenantID,
        "role",
        "member",
        "touch",
        duration,
    )
}
```

### 3. Recording Errors

```go
if err != nil {
    spicedb.RecordError("permission_check", "spicedb_unavailable")
    return false, err
}
```

### 4. Security Events

```go
if validationErr != nil {
    spicedb.RecordTenantValidationFailure(
        tenantID,
        "context_mismatch",
    )
}

// Detect suspicious patterns
if denialCount > suspiciousThreshold {
    spicedb.RecordSuspiciousActivity(
        tenantID,
        "excessive_denials",
    )
}
```

## Querying Metrics

### PromQL Examples

#### Cache Hit Ratio
```promql
sum(rate(iam_spicedb_cache_hit_total[5m]))
/ (
  sum(rate(iam_spicedb_cache_hit_total[5m]))
  + sum(rate(iam_spicedb_cache_miss_total[5m]))
)
```

#### p95 Latency by Resource Type
```promql
histogram_quantile(0.95,
  sum(rate(iam_spicedb_permission_check_duration_seconds_bucket[5m]))
  by (le, resource_type)
)
```

#### Error Rate
```promql
sum(rate(iam_spicedb_error_total[5m]))
/ sum(rate(iam_spicedb_permission_check_total[5m]))
```

#### Top Tenants by Permission Checks
```promql
topk(10,
  sum(rate(iam_spicedb_permission_check_total[5m]))
  by (tenant_id)
)
```

#### Denial Rate per Tenant
```promql
sum(rate(iam_spicedb_permission_check_total{result="denied"}[5m]))
by (tenant_id)
/ sum(rate(iam_spicedb_permission_check_total[5m]))
by (tenant_id)
```

## Best Practices

### 1. Monitoring

- **Set up alerting**: Configure Alert Manager with proper routing
- **Review dashboards daily**: Check for anomalies and trends
- **Monitor cache hit ratio**: Target > 85% for optimal performance
- **Track p95 latency**: Keep under 50ms for best UX
- **Watch tenant isolation**: Zero tolerance for validation failures

### 2. Performance

- **Cache tuning**: Adjust TTL based on invalidation patterns
- **Concurrency limits**: Monitor queue size and wait times
- **Consistency modes**: Use minimize_latency when possible
- **Bulk operations**: Batch writes when performing multiple updates

### 3. Security

- **Audit validation failures**: Investigate all tenant validation failures immediately
- **Monitor denial patterns**: High denial rates may indicate attacks or misconfigurations
- **Track suspicious activity**: Review and respond to anomalies
- **Regular reviews**: Weekly security metrics review

### 4. Troubleshooting

#### High Latency
1. Check SpiceDB resource utilization
2. Review cache hit ratio
3. Examine query complexity
4. Check network latency
5. Consider scaling SpiceDB

#### High Error Rate
1. Review error types in metrics
2. Check SpiceDB logs
3. Verify network connectivity
4. Review recent schema changes
5. Check for rate limiting

#### Low Cache Hit Ratio
1. Review invalidation patterns
2. Check cache TTL settings
3. Monitor invalidation storms
4. Examine access patterns
5. Consider cache warming

#### Security Alerts
1. **IMMEDIATE**: Review audit logs
2. Identify affected tenants
3. Check for unauthorized access attempts
4. Review recent permission changes
5. Escalate if tenant isolation is compromised

## Runbooks

Detailed runbooks are available at:
- Connection issues: `/docs/runbooks/spicedb/connection-down.md`
- High latency: `/docs/runbooks/spicedb/high-latency.md`
- Cache issues: `/docs/runbooks/spicedb/low-cache-hit-rate.md`
- Security events: `/docs/runbooks/spicedb/tenant-validation-failures.md`

## Metrics Retention

- **Short-term**: 15 days at full resolution
- **Medium-term**: 90 days at 5-minute resolution
- **Long-term**: 1 year at 1-hour resolution

## Support

For questions or issues:
- **Slack**: #example-iam-support
- **Email**: iam-team@example.com
- **On-call**: PagerDuty escalation for critical alerts
