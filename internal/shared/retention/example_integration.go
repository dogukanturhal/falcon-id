// SPDX-License-Identifier: AGPL-3.0-or-later

package retention

// This file contains example integration code for ExampleSuite services.
// Copy and adapt these examples to your service's cmd/main.go file.

/*
Example 1: Basic Integration with IAM Service (using pgxpool)

Replace the existing startCleanupTask function in platform-services/iam/cmd/main.go:

```go
import (
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// ... existing setup code ...
	// db is a *database.PostgresDB with a Pool *pgxpool.Pool

	// Initialize retention scheduler
	retentionScheduler := initRetentionScheduler(db.Pool, logger)
	defer retentionScheduler.Stop()

	// Remove the old startCleanupTask goroutine
	// go startCleanupTask(tokenService, sessionRepo, mfaRepo)

	// ... rest of main function ...
}

func initRetentionScheduler(pool *pgxpool.Pool, logger *zap.Logger) *retention.Scheduler {
	// Use pre-configured IAM policies
	policies := retention.IAMPolicies()

	scheduler, err := retention.NewScheduler(retention.Config{
		PgxPool:  pool,
		Policies: policies,
		Interval: 5 * time.Minute, // Match existing IAM cleanup interval
		Logger:   logger,
	})
	if err != nil {
		logger.Fatal("Failed to create retention scheduler", zap.Error(err))
	}

	ctx := context.Background()
	if err := scheduler.Start(ctx); err != nil {
		logger.Fatal("Failed to start retention scheduler", zap.Error(err))
	}

	logger.Info("Retention scheduler initialized successfully",
		zap.Int("policies", len(policies)),
		zap.Duration("interval", 5*time.Minute))
	return scheduler
}
```

----

Example 2: Custom Policies for a New Service

```go
import (
	"time"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
)

func initRetentionScheduler(db *sql.DB, logger *zap.Logger) *retention.Scheduler {
	// Define custom policies for your service
	customPolicies := []retention.Policy{
		{
			Name:            "expired_api_keys",
			Table:           "api_keys",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0, // Delete immediately when expired
			BatchSize:       500,
		},
		{
			Name:            "old_request_logs",
			Table:           "request_logs",
			TimestampColumn: "created_at",
			RetentionPeriod: 7 * 24 * time.Hour, // Keep 7 days
			BatchSize:       2000,
		},
		{
			Name:                "failed_webhooks",
			Table:               "webhook_deliveries",
			TimestampColumn:     "created_at",
			RetentionPeriod:     30 * 24 * time.Hour, // Keep 30 days
			AdditionalCondition: "status = 'failed'",
			BatchSize:           1000,
		},
	}

	// Combine with default policies
	policies := retention.CombinePolicies(
		retention.DefaultPolicies(),
		customPolicies,
	)

	scheduler, err := retention.NewScheduler(retention.Config{
		DB:       db,
		Policies: policies,
		Interval: 1 * time.Hour, // Run every hour
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

----

Example 3: Graceful Shutdown with Signal Handling

```go
import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
)

func main() {
	// ... existing setup code ...

	// Initialize retention scheduler
	retentionScheduler := initRetentionScheduler(db, logger)

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("Received shutdown signal")

		// Stop retention scheduler first
		if err := retentionScheduler.Stop(); err != nil {
			logger.Error("Failed to stop retention scheduler", zap.Error(err))
		}

		// ... stop other services ...

		os.Exit(0)
	}()

	// ... rest of application ...
}
```

----

Example 4: Conditional Policies Based on Environment

```go
import (
	"os"
	"time"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
)

func initRetentionScheduler(db *sql.DB, logger *zap.Logger) *retention.Scheduler {
	env := os.Getenv("ENVIRONMENT")

	var policies []retention.Policy
	var interval time.Duration

	switch env {
	case "production":
		// Production: stricter retention, more frequent cleanup
		policies = retention.IAMPolicies()
		interval = 5 * time.Minute

	case "staging":
		// Staging: moderate retention, less frequent cleanup
		policies = retention.IAMPolicies()
		interval = 15 * time.Minute

	case "development":
		// Development: longer retention for debugging
		policies = []retention.Policy{
			{
				Name:            "expired_sessions",
				Table:           "sessions",
				TimestampColumn: "expires_at",
				RetentionPeriod: 24 * time.Hour, // Keep expired for 1 day
				BatchSize:       100,
			},
		}
		interval = 1 * time.Hour

	default:
		logger.Warn("Unknown environment, using production defaults", zap.String("env", env))
		policies = retention.IAMPolicies()
		interval = 5 * time.Minute
	}

	scheduler, err := retention.NewScheduler(retention.Config{
		DB:       db,
		Policies: policies,
		Interval: interval,
		Logger:   logger,
	})
	if err != nil {
		logger.Fatal("Failed to create retention scheduler", zap.Error(err))
	}

	ctx := context.Background()
	if err := scheduler.Start(ctx); err != nil {
		logger.Fatal("Failed to start retention scheduler", zap.Error(err))
	}

	logger.Info("Retention scheduler initialized",
		zap.String("environment", env),
		zap.Duration("interval", interval),
		zap.Int("policies", len(policies)))

	return scheduler
}
```

----

Example 5: Manual Cleanup on Service Startup

```go
import (
	"context"
	"time"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
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

	// Run cleanup once on startup to clear any accumulated data
	logger.Info("Running initial cleanup on startup")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := scheduler.RunOnce(ctx); err != nil {
		logger.Error("Initial cleanup failed", zap.Error(err))
		// Don't fail startup, continue with periodic cleanup
	}

	// Start periodic cleanup
	ctx = context.Background()
	if err := scheduler.Start(ctx); err != nil {
		logger.Fatal("Failed to start retention scheduler", zap.Error(err))
	}

	return scheduler
}
```

----

Example 6: Multi-Tenant Service with Per-Tenant Policies

```go
import (
	"fmt"
	"time"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
)

func initRetentionScheduler(db *sql.DB, logger *zap.Logger) *retention.Scheduler {
	// For multi-tenant services, you might want to clean up per-tenant tables
	// Note: This assumes tenant_id is part of the timestamp-based cleanup logic
	policies := []retention.Policy{
		{
			Name:            "expired_tenant_sessions",
			Table:           "tenant_sessions",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0,
			BatchSize:       1000,
		},
		{
			Name:            "old_tenant_audit_logs",
			Table:           "tenant_audit_logs",
			TimestampColumn: "created_at",
			RetentionPeriod: 90 * 24 * time.Hour,
			BatchSize:       500,
		},
	}

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

----

Example 7: Health Check Integration

```go
import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/dogukanturhal/falcon-id/internal/shared/retention"
)

var retentionScheduler *retention.Scheduler

func main() {
	// ... existing setup ...

	retentionScheduler = initRetentionScheduler(db, logger)

	// ... setup HTTP routes ...
	router.GET("/health/retention", healthCheckRetention)

	// ... start server ...
}

func healthCheckRetention(c *gin.Context) {
	// Check if scheduler is running
	policies := retentionScheduler.GetPolicies()

	c.JSON(http.StatusOK, gin.H{
		"status":   "healthy",
		"policies": len(policies),
	})
}
```

----

Example 8: Database Index Recommendations

Before deploying the retention scheduler, ensure your database has appropriate indexes:

```sql
-- IAM Service Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at ON password_resets(expires_at);
CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at ON magic_links(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);

-- Generic Indexes (for other services)
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_rate_limit_events_created_at ON rate_limit_events(created_at);

-- Compound indexes for policies with additional conditions
CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at_used
  ON password_resets(expires_at) WHERE used = false;
CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at_used
  ON magic_links(expires_at) WHERE used = false;
```

Add these indexes in your service's migration files.

*/
