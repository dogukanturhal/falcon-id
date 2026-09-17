// SPDX-License-Identifier: AGPL-3.0-or-later

package retention

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestLoadFromTable_InputValidation covers the input-validation
// branches that fire without touching the database.
func TestLoadFromTable_InputValidation(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	t.Run("nil pool returns error", func(t *testing.T) {
		policies, err := LoadFromTable(ctx, nil, "iam_data_retention_policies", logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pool is nil")
		assert.Nil(t, policies)
	})

	t.Run("empty tableName returns error", func(t *testing.T) {
		// Use a real pool only if available; otherwise the nil-pool
		// branch fires first which we covered above. This branch
		// requires a non-nil pool to reach the tableName check.
		dbURL := getTestDBURL()
		pool, err := pgxpool.New(ctx, dbURL)
		if err != nil {
			t.Skip("PostgreSQL not available, skipping non-nil-pool branch:", err)
			return
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			t.Skip("PostgreSQL not reachable, skipping:", err)
			return
		}

		policies, err := LoadFromTable(ctx, pool, "", logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tableName is empty")
		assert.Nil(t, policies)
	})
}

// TestLoadFromTable_E2E covers the happy path + the 42P01 graceful-
// degradation branch against a real Postgres instance. Skips when
// no DB is reachable (matches sibling pgxpool_test.go conventions).
func TestLoadFromTable_E2E(t *testing.T) {
	dbURL := getTestDBURL()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skip("PostgreSQL not available, skipping LoadFromTable E2E:", err)
		return
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skip("PostgreSQL not reachable, skipping LoadFromTable E2E:", err)
		return
	}

	logger := zaptest.NewLogger(t)

	t.Run("missing table returns (nil, nil) — graceful degrade for 42P01", func(t *testing.T) {
		// Use a table name guaranteed not to exist. The loader's
		// 42P01 branch returns (nil, nil) so the caller can fall back
		// to a static slice (see cmd/background.go::initRetentionScheduler).
		policies, err := LoadFromTable(ctx, pool, "definitely_not_a_real_table_xyz_123", logger)
		require.NoError(t, err, "42P01 must NOT propagate as an error — it must degrade to (nil, nil)")
		assert.Nil(t, policies)
	})

	t.Run("populated registry returns policies in name order", func(t *testing.T) {
		// Build a transient registry table that matches the schema
		// from migration v0.232.250. Drop on exit so re-runs are
		// hermetic.
		_, err := pool.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS test_retention_registry (
				name                     varchar(128) PRIMARY KEY,
				table_name               varchar(128) NOT NULL,
				timestamp_column         varchar(128) NOT NULL,
				retention_period_seconds bigint       NOT NULL DEFAULT 0,
				additional_condition     text         NULL,
				batch_size               integer      NOT NULL DEFAULT 1000,
				enabled                  boolean      NOT NULL DEFAULT true,
				registered_by_migration  varchar(64)  NOT NULL DEFAULT 'test',
				created_at               timestamptz  NOT NULL DEFAULT now(),
				updated_at               timestamptz  NOT NULL DEFAULT now()
			)
		`)
		require.NoError(t, err)
		defer pool.Exec(ctx, "DROP TABLE IF EXISTS test_retention_registry") //nolint:errcheck

		// Two enabled + one disabled — disabled MUST be filtered out.
		_, err = pool.Exec(ctx, `
			INSERT INTO test_retention_registry
				(name, table_name, timestamp_column, retention_period_seconds, additional_condition, batch_size, enabled)
			VALUES
				('a_first',  'tbl_a', 'expires_at', 0,      NULL,                  1000, true),
				('b_second', 'tbl_b', 'created_at', 604800, 'status = ''closed''', 500,  true),
				('c_disabled', 'tbl_c', 'expires_at', 0,    NULL,                  100,  false)
		`)
		require.NoError(t, err)

		policies, err := LoadFromTable(ctx, pool, "test_retention_registry", logger)
		require.NoError(t, err)
		require.Len(t, policies, 2, "disabled rows must be filtered out")

		// Name-order pin: 'a_first' < 'b_second'.
		assert.Equal(t, "a_first", policies[0].Name)
		assert.Equal(t, "tbl_a", policies[0].Table)
		assert.Equal(t, "expires_at", policies[0].TimestampColumn)
		assert.Equal(t, time.Duration(0), policies[0].RetentionPeriod)
		assert.Empty(t, policies[0].AdditionalCondition, "NULL additional_condition must map to empty string, not zero-bytes")
		assert.Equal(t, 1000, policies[0].BatchSize)

		assert.Equal(t, "b_second", policies[1].Name)
		assert.Equal(t, "tbl_b", policies[1].Table)
		assert.Equal(t, "created_at", policies[1].TimestampColumn)
		assert.Equal(t, 604800*time.Second, policies[1].RetentionPeriod)
		assert.Equal(t, "status = 'closed'", policies[1].AdditionalCondition)
		assert.Equal(t, 500, policies[1].BatchSize)
	})

	t.Run("empty registry returns ([], nil)", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS test_retention_registry_empty (
				name                     varchar(128) PRIMARY KEY,
				table_name               varchar(128) NOT NULL,
				timestamp_column         varchar(128) NOT NULL,
				retention_period_seconds bigint       NOT NULL DEFAULT 0,
				additional_condition     text         NULL,
				batch_size               integer      NOT NULL DEFAULT 1000,
				enabled                  boolean      NOT NULL DEFAULT true,
				registered_by_migration  varchar(64)  NOT NULL DEFAULT 'test'
			)
		`)
		require.NoError(t, err)
		defer pool.Exec(ctx, "DROP TABLE IF EXISTS test_retention_registry_empty") //nolint:errcheck

		policies, err := LoadFromTable(ctx, pool, "test_retention_registry_empty", logger)
		require.NoError(t, err)
		assert.Empty(t, policies)
	})
}
