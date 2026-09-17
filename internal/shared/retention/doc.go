// SPDX-License-Identifier: AGPL-3.0-or-later

// Package retention provides a reusable data retention scheduler for ExampleSuite platform services.
//
// This package automates periodic cleanup of expired and old records from database tables,
// generalizing the cleanup pattern found in the IAM service and making it available to all
// platform services.
//
// # Overview
//
// The retention package provides:
//   - Configurable retention policies with flexible time periods
//   - Batch-size limiting to prevent performance issues
//   - Additional WHERE conditions for complex cleanup rules
//   - Graceful shutdown support with context cancellation
//   - SQL injection prevention through identifier sanitization
//   - Comprehensive logging with zap
//   - Pre-configured policies for common ExampleSuite data
//
// # Basic Usage
//
// Create a scheduler with retention policies and start it:
//
//	import (
//	    "context"
//	    "database/sql"
//	    "time"
//	    "github.com/dogukanturhal/falcon-id/internal/shared/retention"
//	    "go.uber.org/zap"
//	)
//
//	func main() {
//	    db, _ := sql.Open("postgres", "...")
//	    logger, _ := zap.NewProduction()
//
//	    policies := []retention.Policy{
//	        {
//	            Name:            "expired_sessions",
//	            Table:           "sessions",
//	            TimestampColumn: "expires_at",
//	            RetentionPeriod: 0, // Delete where expires_at < NOW()
//	            BatchSize:       1000,
//	        },
//	    }
//
//	    scheduler, err := retention.NewScheduler(retention.Config{
//	        DB:       db,
//	        Policies: policies,
//	        Interval: 1 * time.Hour,
//	        Logger:   logger,
//	    })
//	    if err != nil {
//	        panic(err)
//	    }
//
//	    ctx := context.Background()
//	    scheduler.Start(ctx)
//	    defer scheduler.Stop()
//
//	    // ... application runs ...
//	}
//
// # Using Pre-configured Policies
//
// The package includes pre-configured policies for common ExampleSuite services:
//
//	// Use IAM service policies
//	policies := retention.IAMPolicies()
//
//	// Or combine multiple policy sets
//	policies := retention.CombinePolicies(
//	    retention.IAMPolicies(),
//	    retention.BillingPolicies(),
//	)
//
// # Policy Configuration
//
// Policies define how and when data should be cleaned up:
//
//	Policy{
//	    Name:                "expired_tokens",
//	    Table:               "tokens",
//	    TimestampColumn:     "expires_at",
//	    RetentionPeriod:     0, // Delete where expires_at < NOW()
//	    AdditionalCondition: "revoked = true", // Optional WHERE clause
//	    BatchSize:           1000, // Limit deletions per run
//	}
//
// # Generated SQL
//
// Policies generate DELETE queries like:
//
//	DELETE FROM {table}
//	WHERE {timestamp_column} < NOW() - INTERVAL '{retention_period} seconds'
//	AND {additional_condition}
//	LIMIT {batch_size}
//
// # Security
//
// The package prevents SQL injection by:
//   - Validating table and column names to only contain alphanumeric characters and underscores
//   - Using parameterized time intervals
//   - Not accepting user input for identifiers
//
// # Performance
//
// Recommended batch sizes:
//   - Small tables (< 10K rows): 1000-5000
//   - Medium tables (10K-1M rows): 500-1000
//   - Large tables (> 1M rows): 100-500
//
// Ensure database indexes exist on timestamp columns:
//
//	CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
//	CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
//
// # Example: IAM Service Integration
//
// Replace existing cleanup code in platform-services/iam/cmd/main.go:
//
//	import "github.com/dogukanturhal/falcon-id/internal/shared/retention"
//
//	func main() {
//	    // ... existing setup ...
//
//	    scheduler := initRetentionScheduler(db, logger)
//	    defer scheduler.Stop()
//
//	    // ... rest of application ...
//	}
//
//	func initRetentionScheduler(db *sql.DB, logger *zap.Logger) *retention.Scheduler {
//	    policies := retention.IAMPolicies()
//
//	    scheduler, err := retention.NewScheduler(retention.Config{
//	        DB:       db,
//	        Policies: policies,
//	        Interval: 5 * time.Minute,
//	        Logger:   logger,
//	    })
//	    if err != nil {
//	        logger.Fatal("Failed to create retention scheduler", zap.Error(err))
//	    }
//
//	    ctx := context.Background()
//	    if err := scheduler.Start(ctx); err != nil {
//	        logger.Fatal("Failed to start retention scheduler", zap.Error(err))
//	    }
//
//	    return scheduler
//	}
//
// # Available Policy Sets
//
//   - DefaultPolicies() - Generic policies for common tables
//   - IAMPolicies() - Identity and access management
//   - BillingPolicies() - Payment and billing data
//   - HelpdeskPolicies() - Support tickets and activities
//   - WorkflowPolicies() - Workflow engine data
//   - DocumentProcessorPolicies() - Document processing jobs
//   - QuotaPolicies() - Quota usage tracking
//   - RealtimePolicies() - Real-time messaging and presence
//   - IntegrationHubPolicies() - Integration logs and sync data
//
// # Graceful Shutdown
//
// The scheduler supports graceful shutdown:
//
//	sigCh := make(chan os.Signal, 1)
//	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
//
//	go func() {
//	    <-sigCh
//	    scheduler.Stop()
//	    os.Exit(0)
//	}()
//
// # Testing
//
// Run tests with coverage:
//
//	cd platform-services/shared/retention
//	go test -v -cover
//
// Run benchmarks:
//
//	go test -bench=. -benchmem
package retention
