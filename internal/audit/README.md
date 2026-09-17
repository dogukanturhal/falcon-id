# IAM Permission Audit Logging

Comprehensive audit logging for all IAM authorization events including relationship changes and permission checks for GDPR/SOC2 compliance.

## Overview

The audit logging system provides:

- **Relationship Change Tracking**: Logs all SpiceDB relationship creates and deletes
- **Permission Check Monitoring**: Logs denied permission checks for security monitoring
- **Security Event Detection**: Identifies suspicious activity patterns
- **Compliance Reporting**: Query and export audit logs for compliance audits
- **Async Processing**: Non-blocking audit log writes using buffered channels

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SpiceDB Client                         │
│  (WriteUserRole, DeleteUserRole, CheckPermission)           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  AuditedClient Wrapper                       │
│  (Intercepts calls and logs to AuditLogger)                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  AsyncAuditLogger                            │
│  - Buffered channel (1000 entries)                          │
│  - Background worker (flushes every 1s or 100 entries)      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              PostgresAuditRepository                         │
│  - Batch inserts for performance                            │
│  - Indexed queries                                           │
│  - Compliance functions                                      │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              iam_audit_logs (PostgreSQL)                     │
│  - Partitioned by month                                      │
│  - 2-year retention (GDPR)                                   │
│  - Compliance views and functions                            │
└─────────────────────────────────────────────────────────────┘
```

## Database Schema

### iam_audit_logs Table

```sql
CREATE TABLE iam_audit_logs (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    actor_type VARCHAR(50) NOT NULL, -- 'user', 'service', 'system'
    action VARCHAR(100) NOT NULL,    -- 'relationship.created', 'relationship.deleted', 'permission.checked'
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    relation VARCHAR(100),
    subject_type VARCHAR(100),
    subject_id VARCHAR(255),
    result VARCHAR(50),              -- 'success', 'denied', 'error'
    metadata JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    error_message TEXT,
    latency_ms BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Indexes

- `idx_iam_audit_logs_tenant_time`: Fast tenant-scoped queries
- `idx_iam_audit_logs_actor`: User activity tracking
- `idx_iam_audit_logs_resource`: Resource change history
- `idx_iam_audit_logs_denied`: Security monitoring (denied checks only)
- `idx_iam_audit_logs_relationship_changes`: Compliance audits

## Usage

### 1. Initialize Audit Logger

```go
import (
    "github.com/dogukanturhal/platform-services/iam/internal/audit"
)

// Create repository
repo := audit.NewPostgresAuditRepository(db)

// Create async logger
auditLogger := audit.NewAsyncAuditLogger(repo, 1000, 100)
defer auditLogger.Close()
```

### 2. Wrap SpiceDB Client

```go
import (
    "github.com/dogukanturhal/platform-services/iam/pkg/spicedb"
)

// Create regular SpiceDB client
spicedbClient, err := spicedb.NewClient(ctx, cfg, redisClient)
if err != nil {
    log.Fatal(err)
}

// Wrap with audit logging
auditedClient := spicedb.NewAuditedClient(spicedbClient, auditLogger)
```

### 3. Use Audited Client

```go
// Relationship changes are automatically logged
err := auditedClient.WriteUserRole(ctx, tenantID, userID, roleID)

// Permission denials are automatically logged
allowed, err := auditedClient.CheckPermission(ctx, tenantID, userID, "crm_module", "default", "view")

// Security events can be manually logged
auditedClient.LogSecurityEvent(ctx, audit.SecurityAuditEntry{
    TenantID:     tenantID,
    ActorID:      userID,
    EventType:    "cross_tenant_attempt",
    Details:      "User attempted to access different tenant's resources",
    Severity:     "critical",
    ResourceType: "tenant",
    ResourceID:   targetTenantID.String(),
})
```

### 4. Query Audit Logs

```go
// Query with filters
filter := audit.AuditFilter{
    TenantID:  &tenantID,
    Action:    &audit.ActionRelationshipCreated,
    StartDate: &startDate,
    EndDate:   &endDate,
    Limit:     100,
    Offset:    0,
}

logs, total, err := auditLogger.QueryAuditLogs(ctx, filter)
```

### 5. Get Statistics

```go
// Get audit statistics for compliance reporting
stats, err := auditLogger.GetAuditStats(ctx, tenantID, startDate, endDate)

// stats contains:
// - TotalEvents
// - RelationshipCreates
// - RelationshipDeletes
// - PermissionChecks
// - PermissionDenials
// - Errors
// - UniqueActors
// - UniqueResources
// - AvgLatencyMs
```

### 6. Detect Suspicious Activity

```go
// Detect users with excessive permission denials
activities, err := auditLogger.DetectSuspiciousActivity(ctx, tenantID, 24, 10)

// Returns actors with 10+ denials in the last 24 hours
for _, activity := range activities {
    fmt.Printf("Actor %s: %d denials across %d resources\n",
        activity.ActorID,
        activity.DenialCount,
        activity.UniqueResources,
    )
}
```

## API Endpoints

### Query Permission Audit Logs

```
GET /api/admin/audit/permissions
```

**Query Parameters:**
- `tenant_id` (UUID): Filter by tenant
- `actor_id` (UUID): Filter by actor
- `action` (string): Filter by action (relationship.created, etc.)
- `resource_type` (string): Filter by resource type
- `resource_id` (string): Filter by resource ID
- `result` (string): Filter by result (success, denied, error)
- `start_date` (RFC3339): Start date
- `end_date` (RFC3339): End date
- `limit` (int): Page size (default: 100, max: 1000)
- `offset` (int): Pagination offset

**Response:**
```json
{
  "logs": [
    {
      "id": "uuid",
      "tenant_id": "uuid",
      "actor_id": "uuid",
      "actor_type": "user",
      "action": "relationship.created",
      "resource_type": "role",
      "resource_id": "admin",
      "relation": "member",
      "subject_type": "user",
      "subject_id": "user123",
      "result": "success",
      "metadata": {},
      "ip_address": "10.0.30.20",
      "user_agent": "Mozilla/5.0...",
      "request_id": "req-123",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1234,
  "page": 1,
  "limit": 100
}
```

### Get Audit Statistics

```
GET /api/admin/audit/permissions/stats
```

**Query Parameters:**
- `tenant_id` (UUID): Tenant ID (optional, defaults to current)
- `start_date` (RFC3339): Start date (optional, default: 30 days ago)
- `end_date` (RFC3339): End date (optional, default: now)

**Response:**
```json
{
  "stats": {
    "total_events": 5000,
    "relationship_creates": 1200,
    "relationship_deletes": 300,
    "permission_checks": 3000,
    "permission_denials": 500,
    "errors": 0,
    "unique_actors": 45,
    "unique_resources": 120,
    "avg_latency_ms": 12.5
  },
  "tenant_id": "uuid",
  "start_date": "2024-01-01T00:00:00Z",
  "end_date": "2024-01-31T23:59:59Z"
}
```

### Detect Suspicious Activity

```
GET /api/admin/audit/permissions/suspicious
```

**Query Parameters:**
- `tenant_id` (UUID): Tenant ID (optional, defaults to current)
- `lookback_hours` (int): Lookback period in hours (default: 24)
- `denial_threshold` (int): Minimum denials to flag (default: 10)

**Response:**
```json
{
  "activities": [
    {
      "actor_id": "uuid",
      "denial_count": 25,
      "unique_resources": 15,
      "first_denial": "2024-01-15T10:00:00Z",
      "last_denial": "2024-01-15T11:30:00Z",
      "sample_actions": [
        {
          "action": "permission.denied",
          "resource": "crm_module:default",
          "time": "2024-01-15T11:30:00Z"
        }
      ]
    }
  ],
  "tenant_id": "uuid",
  "alert_count": 1
}
```

## Performance Considerations

### Async Processing

- Audit logs are written asynchronously to avoid impacting request latency
- Buffered channel capacity: 1000 entries
- Batch flush size: 100 entries or 1 second interval
- Failed writes are logged but don't block the application

### Indexing Strategy

- Composite indexes for common query patterns
- Partial indexes for security monitoring (denied checks only)
- Consider partitioning by month for large datasets

### Logging Strategy

- **Always log**: Relationship creates and deletes
- **Conditionally log**: Permission denials and errors
- **Don't log**: Successful permission checks (too verbose)

## Compliance Features

### GDPR Compliance

- 2-year retention period (configurable)
- Automatic cleanup of old logs
- Export functionality for data subject access requests
- Immutable audit trail (append-only)

### SOC2 Compliance

- Complete audit trail of authorization changes
- Tamper-evident logging with checksums
- Suspicious activity detection
- Comprehensive reporting capabilities

## Database Functions

### cleanup_iam_audit_logs

Deletes audit logs older than retention period:

```sql
SELECT * FROM cleanup_iam_audit_logs(730); -- 2 years
```

### get_iam_audit_stats

Returns audit statistics for a time period:

```sql
SELECT * FROM get_iam_audit_stats(
    'tenant-uuid'::UUID,
    '2024-01-01'::TIMESTAMPTZ,
    '2024-01-31'::TIMESTAMPTZ
);
```

### detect_suspicious_iam_activity

Detects potential unauthorized access attempts:

```sql
SELECT * FROM detect_suspicious_iam_activity(
    'tenant-uuid'::UUID,
    24,   -- lookback hours
    10    -- denial threshold
);
```

## Monitoring

### Key Metrics

- Audit log write rate
- Buffer utilization
- Failed audit log writes
- Query performance
- Suspicious activity alerts

### Alerts

- Buffer full warnings (potential data loss)
- High denial rates (security concern)
- Failed batch writes (data integrity)
- Cleanup failures (retention compliance)

## Migration

### Running the Migration

```bash
# Run the migration
psql $DATABASE_URL -f migrations/041_iam_permission_audit_logs.sql
```

### Verification

```sql
-- Verify table exists
\d iam_audit_logs

-- Verify indexes
\di iam_audit_logs*

-- Verify functions
\df get_iam_audit_stats
\df detect_suspicious_iam_activity
\df cleanup_iam_audit_logs

-- Test statistics function
SELECT * FROM get_iam_audit_stats(NULL, NOW() - INTERVAL '30 days', NOW());
```

## Troubleshooting

### Buffer Full Warnings

If you see "audit log buffer full" warnings:

1. Increase buffer size: `NewAsyncAuditLogger(repo, 5000, 500)`
2. Increase flush frequency
3. Optimize database write performance
4. Add database connection pooling

### Slow Queries

If audit queries are slow:

1. Check index usage: `EXPLAIN ANALYZE SELECT ...`
2. Add missing indexes for your query patterns
3. Consider partitioning by month
4. Optimize filter combinations

### Missing Audit Logs

If audit logs are missing:

1. Check for buffer overflow warnings in logs
2. Verify database connectivity
3. Check for transaction rollbacks
4. Ensure async logger is not closed prematurely

## Security

### Access Control

- Audit log queries require admin privileges
- Tenant isolation enforced at database level
- IP address and user agent captured for forensics
- Request ID for correlation with application logs

### Data Protection

- Sensitive data should not be stored in metadata
- IP addresses stored as INET type (supports IPv6)
- User agent strings stored for device tracking
- Encryption at rest via PostgreSQL settings

## Best Practices

1. **Always use AuditedClient** instead of raw SpiceDB client
2. **Don't log successful permission checks** (too verbose)
3. **Monitor buffer utilization** to prevent data loss
4. **Run cleanup regularly** (weekly recommended)
5. **Export audit logs** before cleanup for long-term archival
6. **Review suspicious activity** alerts promptly
7. **Test audit logging** in staging before production
8. **Document custom metadata** fields for your use case

## Future Enhancements

- [ ] S3 archival for long-term storage
- [ ] Real-time alerting via webhooks
- [ ] Machine learning for anomaly detection
- [ ] Integration with SIEM systems
- [ ] Automatic incident response workflows
- [ ] Cross-tenant activity correlation
- [ ] Advanced visualization dashboards
