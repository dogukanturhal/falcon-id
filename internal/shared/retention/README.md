# Data Retention Package

A reusable data retention scheduler for ExampleSuite platform services that automates periodic cleanup of expired and old records.

## Overview

This package provides a configurable scheduler that executes retention policies on database tables. It generalizes the cleanup pattern found in the IAM service and makes it available to all platform services.

## Features

- Configurable retention policies with flexible time periods
- Batch-size limiting to prevent performance issues
- Additional WHERE conditions for complex cleanup rules
- Graceful shutdown support
- Context cancellation support
- SQL injection prevention
- Comprehensive logging with zap
- Pre-configured policies for common ExampleSuite data
- **Supports both `database/sql` and `pgxpool.Pool` (pgx v5)**

## Installation

```go
import "github.com/dogukanturhal/platform-shared/retention"
```

## Usage

### Basic Example

```go
package main

import (
    "context"
    "database/sql"
    "time"

    "github.com/dogukanturhal/platform-shared/retention"
    "go.uber.org/zap"
)

func main() {
    // Create database connection
    db, err := sql.Open("postgres", "postgres://...")
    if err != nil {
        panic(err)
    }
    defer db.Close()

    // Create logger
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    // Define retention policies
    policies := []retention.Policy{
        {
            Name:            "expired_sessions",
            Table:           "sessions",
            TimestampColumn: "expires_at",
            RetentionPeriod: 0, // Delete where expires_at < NOW()
            BatchSize:       1000,
        },
        {
            Name:            "old_audit_logs",
            Table:           "audit_logs",
            TimestampColumn: "created_at",
            RetentionPeriod: 90 * 24 * time.Hour, // Keep 90 days
            BatchSize:       500,
        },
    }

    // Create scheduler
    scheduler, err := retention.NewScheduler(retention.Config{
        DB:       db,
        Policies: policies,
        Interval: 1 * time.Hour, // Run every hour
        Logger:   logger,
    })
    if err != nil {
        panic(err)
    }

    // Start scheduler
    ctx := context.Background()
    if err := scheduler.Start(ctx); err != nil {
        panic(err)
    }

    // ... your application runs ...

    // Graceful shutdown
    if err := scheduler.Stop(); err != nil {
        logger.Error("Failed to stop scheduler", zap.Error(err))
    }
}
```

### Using with pgxpool (Recommended for new services)

```go
package main

import (
    "context"
    "time"

    "github.com/dogukanturhal/platform-shared/retention"
    "github.com/jackc/pgx/v5/pgxpool"
    "go.uber.org/zap"
)

func main() {
    // Create pgx pool
    pool, err := pgxpool.New(context.Background(), "postgres://...")
    if err != nil {
        panic(err)
    }
    defer pool.Close()

    // Create logger
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    // Use IAM-specific policies
    policies := retention.IAMPolicies()

    // Create scheduler with pgxpool
    scheduler, err := retention.NewScheduler(retention.Config{
        PgxPool:  pool,
        Policies: policies,
        Interval: 5 * time.Minute,
        Logger:   logger,
    })
    if err != nil {
        panic(err)
    }

    // Start scheduler
    ctx := context.Background()
    if err := scheduler.Start(ctx); err != nil {
        panic(err)
    }

    // ... your application runs ...

    // Graceful shutdown
    if err := scheduler.Stop(); err != nil {
        logger.Error("Failed to stop scheduler", zap.Error(err))
    }
}
```

### Using Default Policies

```go
// Use pre-configured IAM policies
policies := retention.IAMPolicies()

scheduler, err := retention.NewScheduler(retention.Config{
    DB:       db,
    Policies: policies,
    Interval: 5 * time.Minute,
    Logger:   logger,
})
```

### Combining Multiple Policy Sets

```go
// Combine policies from multiple sources
policies := retention.CombinePolicies(
    retention.IAMPolicies(),
    retention.BillingPolicies(),
    []retention.Policy{
        {
            Name:            "custom_policy",
            Table:           "my_table",
            TimestampColumn: "created_at",
            RetentionPeriod: 30 * 24 * time.Hour,
        },
    },
)
```

### Running Cleanup Once

```go
// Useful for manual cleanup or testing
if err := scheduler.RunOnce(ctx); err != nil {
    logger.Error("Cleanup failed", zap.Error(err))
}
```

## Policy Configuration

### Policy Structure

```go
type Policy struct {
    // Name identifies this policy for logging (required)
    Name string

    // Table is the database table to clean up (required)
    Table string

    // TimestampColumn is the column used to determine record age (required)
    TimestampColumn string

    // RetentionPeriod is how long to keep records (required, 0 = use NOW())
    // Examples:
    //   0                    - Delete where timestamp < NOW()
    //   24 * time.Hour      - Delete records older than 24 hours
    //   90 * 24 * time.Hour - Delete records older than 90 days
    RetentionPeriod time.Duration

    // AdditionalCondition is an optional WHERE clause (optional)
    // Example: "status = 'expired'" or "used = false"
    // Do not include the leading "AND" keyword
    AdditionalCondition string

    // BatchSize limits deletions per run (optional, 0 = no limit)
    BatchSize int
}
```

### Policy Examples

**Delete expired records:**
```go
Policy{
    Name:            "expired_sessions",
    Table:           "sessions",
    TimestampColumn: "expires_at",
    RetentionPeriod: 0, // expires_at < NOW()
    BatchSize:       1000,
}
```

**Delete old records with retention period:**
```go
Policy{
    Name:            "old_logs",
    Table:           "logs",
    TimestampColumn: "created_at",
    RetentionPeriod: 30 * 24 * time.Hour, // 30 days
    BatchSize:       2000,
}
```

**Delete with additional condition:**
```go
Policy{
    Name:                "unused_magic_links",
    Table:               "magic_links",
    TimestampColumn:     "expires_at",
    RetentionPeriod:     0,
    AdditionalCondition: "used = false",
    BatchSize:           500,
}
```

## Pre-configured Policy Sets

The package includes pre-configured policies for common ExampleSuite services:

- `DefaultPolicies()` - Generic policies for common tables
- `IAMPolicies()` - Identity and access management
- `BillingPolicies()` - Payment and billing data
- `HelpdeskPolicies()` - Support tickets and activities
- `WorkflowPolicies()` - Workflow engine data
- `DocumentProcessorPolicies()` - Document processing jobs
- `QuotaPolicies()` - Quota usage tracking
- `RealtimePolicies()` - Real-time messaging and presence
- `IntegrationHubPolicies()` - Integration logs and sync data

## Generated SQL

The package generates DELETE queries like:

```sql
DELETE FROM {table}
WHERE {timestamp_column} < NOW() - INTERVAL '{retention_period} seconds'
AND {additional_condition}
LIMIT {batch_size}
```

**Examples:**

Policy with zero retention:
```sql
DELETE FROM sessions WHERE expires_at < NOW() LIMIT 1000
```

Policy with 7-day retention:
```sql
DELETE FROM logs WHERE created_at < NOW() - INTERVAL '604800 seconds' LIMIT 500
```

Policy with additional condition:
```sql
DELETE FROM tokens WHERE expires_at < NOW() AND revoked = true LIMIT 1000
```

## Integration with Services

### IAM Service Example

Replace the existing `startCleanupTask` function in `platform-services/iam/cmd/main.go`:

```go
import (
    "github.com/dogukanturhal/platform-shared/retention"
)

func initRetentionScheduler(db *sql.DB, logger *zap.Logger) *retention.Scheduler {
    policies := retention.IAMPolicies()

    scheduler, err := retention.NewScheduler(retention.Config{
        DB:       db,
        Policies: policies,
        Interval: 5 * time.Minute,
        Logger:   logger,
    })
    if err != nil {
        logger.Fatal("Failed to create retention scheduler", zap.Error(err))
    }

    ctx := context.Background()
    if err := scheduler.Start(ctx); err != nil {
        logger.Fatal("Failed to start retention scheduler", zap.Error(err))
    }

    return scheduler
}

// In main():
scheduler := initRetentionScheduler(db, logger)
defer scheduler.Stop()
```

### Other Services

Any service can use the retention package:

```go
// In cmd/main.go
scheduler := initRetentionScheduler(db, logger)
defer scheduler.Stop()

func initRetentionScheduler(db *sql.DB, logger *zap.Logger) *retention.Scheduler {
    // Use service-specific policies or defaults
    policies := retention.CombinePolicies(
        retention.DefaultPolicies(),
        []retention.Policy{
            // Add custom policies here
        },
    )

    scheduler, err := retention.NewScheduler(retention.Config{
        DB:       db,
        Policies: policies,
        Interval: 1 * time.Hour,
        Logger:   logger,
    })
    if err != nil {
        logger.Fatal("Failed to create retention scheduler", zap.Error(err))
    }

    ctx := context.Background()
    if err := scheduler.Start(ctx); err != nil {
        logger.Fatal("Failed to start retention scheduler", zap.Error(err))
    }

    return scheduler
}
```

## Security

### SQL Injection Prevention

The package prevents SQL injection through:

1. **Identifier sanitization**: Table and column names are validated to only contain alphanumeric characters and underscores
2. **No user input in identifiers**: Policies are configured in code, not from user input
3. **Parameterized intervals**: Time intervals are converted to seconds programmatically

**DO NOT** allow user input to configure table names or column names directly.

**SAFE:**
```go
Policy{
    Table:           "sessions", // Hardcoded in code
    TimestampColumn: "expires_at",
}
```

**UNSAFE:**
```go
Policy{
    Table:           userInput, // NEVER do this!
    TimestampColumn: userInput, // NEVER do this!
}
```

## Performance Considerations

### Batch Sizing

Use appropriate batch sizes to prevent long-running transactions:

- **Small tables (< 10K rows)**: BatchSize = 1000-5000
- **Medium tables (10K-1M rows)**: BatchSize = 500-1000
- **Large tables (> 1M rows)**: BatchSize = 100-500

### Interval Selection

- **High-frequency cleanup**: 5-15 minutes (sessions, tokens)
- **Daily cleanup**: 1-6 hours (logs, events)
- **Weekly cleanup**: 1-7 days (archived data)

### Database Indexes

Ensure indexes exist on timestamp columns:

```sql
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

## Testing

Run tests:

```bash
cd platform-services/shared/retention
go test -v
```

Run tests with coverage:

```bash
go test -v -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

Run benchmarks:

```bash
go test -bench=. -benchmem
```

## Logging

The scheduler logs:

- **INFO**: Startup, shutdown, successful cleanups with record counts
- **DEBUG**: Individual policy execution, SQL queries
- **ERROR**: Policy failures, database errors

Example output:

```
INFO  Retention scheduler started  {"interval": "1h0m0s", "policies": 5}
INFO  Policy executed successfully  {"policy": "expired_sessions", "table": "sessions", "deleted": 127, "retention": "0s"}
INFO  Policy executed successfully  {"policy": "old_audit_logs", "table": "audit_logs", "deleted": 1543, "retention": "2160h0m0s"}
DEBUG Retention cleanup cycle completed  {"duration": "234ms", "total_deleted": 1670}
```

## Error Handling

The scheduler continues running even if individual policies fail:

```go
// Policy 1 fails -> logs error, continues to Policy 2
// Policy 2 succeeds -> executes normally
// Policy 3 succeeds -> executes normally
```

Use the logger to monitor failures and investigate issues.

## Graceful Shutdown

The scheduler supports graceful shutdown:

```go
// Signal handling
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

go func() {
    <-sigCh
    logger.Info("Shutting down...")
    scheduler.Stop()
    os.Exit(0)
}()
```

## Migration from Existing Cleanup

### Before (IAM Service)

```go
func startCleanupTask(tokenService *services.TokenService, ...) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        // Manual cleanup logic
        sessionRepo.CleanupStaleSessions(ctx, timeout)
        sessionRepo.CleanupExpiredSessions(ctx)
        tokenService.CleanupExpiredTokens(ctx)
    }
}
```

### After (Using Retention Package)

```go
import "github.com/dogukanturhal/platform-shared/retention"

func main() {
    policies := retention.IAMPolicies()

    scheduler, _ := retention.NewScheduler(retention.Config{
        DB:       db,
        Policies: policies,
        Interval: 5 * time.Minute,
        Logger:   logger,
    })

    scheduler.Start(context.Background())
    defer scheduler.Stop()

    // ... rest of application ...
}
```

## Contributing

When adding new pre-configured policies:

1. Add the policy set function in `defaults.go`
2. Document the policy set in this README
3. Add tests for the new policies
4. Follow the naming convention: `{Service}Policies()`

## License

Copyright 2026 ExampleSuite. All rights reserved.
