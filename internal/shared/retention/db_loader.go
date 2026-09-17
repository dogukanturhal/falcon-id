// SPDX-License-Identifier: AGPL-3.0-or-later

package retention

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// LoadFromTable reads retention policies from a registry table and
// returns them as []Policy ready to feed into NewScheduler.
//
// WHY THIS EXISTS — incident-driven (2026-05-20):
//
// Pre-2026-05-20 each service hard-coded its retention policies in
// a Go slice (defaults.go::IAMPolicies(), BillingPolicies(), ...).
// Migration 233 dropped iam_refresh_tokens but the matching slice
// entry was left behind; the worker fired
//   DELETE FROM "iam_refresh_tokens" WHERE expires_at < NOW() LIMIT 5000
// every ~60s, postgres returned 42P01 every tick — 291 errors in
// 8 hours of silent operational noise.
//
// Per the post-incident research synthesis (Datadog / AWS RDS /
// Spanner patterns + Google SRE Workbook "Distributed Periodic
// Scheduling"), the proper shape is owner-coupled lifecycle:
// retention policy is *data*, not *code*. Each migration that
// CREATEs a retention-eligible table also INSERTs into the registry
// table; each DROP migration DELETEs from it. Atomic with the
// schema change, so the two never diverge.
//
// This function is the consumer side of that pattern: given a
// pgxpool + the registry table's name, return []Policy.
//
// Caller passes the table name because each service owns its own
// registry table (iam_data_retention_policies for falcon-id,
// billing_data_retention_policies for billing, ...). Same SQL
// schema across services — see migration falcon-id-v0.232.250 for
// the canonical column definition.
//
// Returns (nil, nil) when the registry table doesn't exist (42P01)
// — defense in depth, lets a service deploy with the new code
// before the migration has run. Caller can fall back to a static
// slice in that case.
//
// Returns ([], nil) when the registry table exists but is empty —
// also valid; the service has no retention policies (e.g., during
// initial bootstrap).
//
// Returns (nil, err) on any other database error — caller decides
// whether to fall back or fail-fast.
func LoadFromTable(ctx context.Context, pool *pgxpool.Pool, tableName string, logger *zap.Logger) ([]Policy, error) {
	if pool == nil {
		return nil, errors.New("retention.LoadFromTable: pool is nil")
	}
	if tableName == "" {
		return nil, errors.New("retention.LoadFromTable: tableName is empty")
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	// pgx.Identifier.Sanitize() wraps identifiers in quotes + escapes
	// internal quotes per the Postgres SQL identifier spec. Required
	// here because tableName is a parameter — concatenating it raw
	// into the SQL would be a SQL-injection sink even though the
	// caller is trusted internal code (defense in depth).
	safe := pgx.Identifier{tableName}.Sanitize()

	query := fmt.Sprintf(`
		SELECT name, table_name, timestamp_column,
		       retention_period_seconds, additional_condition, batch_size
		FROM %s
		WHERE enabled = true
		ORDER BY name`,
		safe,
	)

	rows, err := pool.Query(ctx, query)
	if err != nil {
		// 42P01 = relation does not exist. Treat as "no policies"
		// instead of a hard error so a service can deploy the new
		// code before the migration creating its registry table has
		// run. Caller falls back to a static slice in that case.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			logger.Warn("retention registry table does not exist — returning empty policy set",
				zap.String("table", tableName),
				zap.String("hint", "ensure the schema migration that creates this table has run"),
			)
			return nil, nil
		}
		return nil, fmt.Errorf("retention.LoadFromTable: query %s: %w", safe, err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var (
			name, tableNm, tsCol string
			retSec               int64
			addCond              *string
			batchSize            int
		)
		if err := rows.Scan(&name, &tableNm, &tsCol, &retSec, &addCond, &batchSize); err != nil {
			return nil, fmt.Errorf("retention.LoadFromTable: scan %s row: %w", safe, err)
		}
		p := Policy{
			Name:            name,
			Table:           tableNm,
			TimestampColumn: tsCol,
			RetentionPeriod: time.Duration(retSec) * time.Second,
			BatchSize:       batchSize,
		}
		if addCond != nil {
			p.AdditionalCondition = *addCond
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("retention.LoadFromTable: iterate %s rows: %w", safe, err)
	}

	logger.Info("retention policies loaded from registry table",
		zap.String("table", tableName),
		zap.Int("policy_count", len(policies)),
	)
	return policies, nil
}
