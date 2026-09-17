// SPDX-License-Identifier: AGPL-3.0-or-later

package retention

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func getTestDBURL() string {
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://postgres:postgres@localhost:5432/test_retention?sslmode=disable"
}

func TestPgxPoolAdapter(t *testing.T) {
	// This test requires a running PostgreSQL instance
	// Skip if DATABASE_URL is not set
	dbURL := getTestDBURL()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skip("PostgreSQL not available, skipping pgxpool test:", err)
		return
	}
	defer pool.Close()

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		t.Skip("PostgreSQL not reachable, skipping pgxpool test:", err)
		return
	}

	// Create test table
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS test_sessions (
			id SERIAL PRIMARY KEY,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`)
	require.NoError(t, err)
	defer pool.Exec(ctx, "DROP TABLE IF EXISTS test_sessions") //nolint:errcheck

	// Insert test data
	_, err = pool.Exec(ctx, `
		INSERT INTO test_sessions (expires_at) VALUES
		(NOW() - INTERVAL '1 hour'),
		(NOW() + INTERVAL '1 hour'),
		(NOW() - INTERVAL '2 hours')
	`)
	require.NoError(t, err)

	// Create retention policy
	policy := Policy{
		Name:            "expired_test_sessions",
		Table:           "test_sessions",
		TimestampColumn: "expires_at",
		RetentionPeriod: 0,
		BatchSize:       100,
	}

	// Create scheduler with pgxpool
	logger := zaptest.NewLogger(t)
	scheduler, err := NewScheduler(Config{
		PgxPool:  pool,
		Policies: []Policy{policy},
		Interval: 1 * time.Hour,
		Logger:   logger,
	})
	require.NoError(t, err)

	// Run cleanup once
	err = scheduler.RunOnce(ctx)
	require.NoError(t, err)

	// Verify expired sessions were deleted
	var count int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM test_sessions").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Should have 1 non-expired session remaining")

	// Verify the remaining session is not expired
	var expiresAt time.Time
	err = pool.QueryRow(ctx, "SELECT expires_at FROM test_sessions LIMIT 1").Scan(&expiresAt)
	require.NoError(t, err)
	assert.True(t, expiresAt.After(time.Now()), "Remaining session should not be expired")
}

func TestPgxPoolSchedulerStartStop(t *testing.T) {
	dbURL := getTestDBURL()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skip("PostgreSQL not available, skipping pgxpool test:", err)
		return
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Skip("PostgreSQL not reachable, skipping pgxpool test:", err)
		return
	}

	// Create test table
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS test_tokens (
			id SERIAL PRIMARY KEY,
			expires_at TIMESTAMP NOT NULL
		)
	`)
	require.NoError(t, err)
	defer pool.Exec(ctx, "DROP TABLE IF EXISTS test_tokens") //nolint:errcheck

	policy := Policy{
		Name:            "expired_test_tokens",
		Table:           "test_tokens",
		TimestampColumn: "expires_at",
		RetentionPeriod: 0,
		BatchSize:       100,
	}

	logger := zaptest.NewLogger(t)
	scheduler, err := NewScheduler(Config{
		PgxPool:  pool,
		Policies: []Policy{policy},
		Interval: 100 * time.Millisecond, // Very short interval for testing
		Logger:   logger,
	})
	require.NoError(t, err)

	// Start scheduler
	err = scheduler.Start(ctx)
	require.NoError(t, err)

	// Wait a bit to let it run
	time.Sleep(150 * time.Millisecond)

	// Stop scheduler
	err = scheduler.Stop()
	require.NoError(t, err)

	// Verify it can't be started again while already running
	err = scheduler.Start(ctx)
	require.NoError(t, err) // Should work since we stopped it

	// Stop again
	err = scheduler.Stop()
	require.NoError(t, err)
}

func TestConfigValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a mock pgxpool for validation testing
	dbURL := getTestDBURL()
	ctx := context.Background()
	mockPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		// Use nil pool for validation tests if DB not available
		mockPool = nil
	}
	if mockPool != nil {
		defer mockPool.Close()
	}

	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name: "missing both DB and PgxPool",
			config: Config{
				Policies: []Policy{{Name: "test", Table: "test", TimestampColumn: "created_at"}},
				Logger:   logger,
			},
			expectError: true,
		},
		{
			name: "missing logger",
			config: Config{
				PgxPool:  mockPool,
				Policies: []Policy{{Name: "test", Table: "test", TimestampColumn: "created_at"}},
			},
			expectError: true,
		},
		{
			name: "missing policies",
			config: Config{
				PgxPool: mockPool,
				Logger:  logger,
			},
			expectError: true,
		},
		{
			name: "invalid policy - missing name",
			config: Config{
				PgxPool:  mockPool,
				Logger:   logger,
				Policies: []Policy{{Table: "test", TimestampColumn: "created_at"}},
			},
			expectError: true,
		},
		{
			name: "invalid policy - missing table",
			config: Config{
				PgxPool:  mockPool,
				Logger:   logger,
				Policies: []Policy{{Name: "test", TimestampColumn: "created_at"}},
			},
			expectError: true,
		},
		{
			name: "invalid policy - missing timestamp column",
			config: Config{
				PgxPool:  mockPool,
				Logger:   logger,
				Policies: []Policy{{Name: "test", Table: "test"}},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip tests that require PgxPool if mockPool is nil
			if tt.config.PgxPool != nil && mockPool == nil {
				t.Skip("Database not available for validation test")
				return
			}

			_, err := NewScheduler(tt.config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
