// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"fmt"
	"log"
	"time"

	sharedDB "github.com/dogukanturhal/falcon-id/internal/shared/database"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDB is an exported type.
type PostgresDB struct {
	Pool *pgxpool.Pool
}

// NewPostgresDB is an exported function.
func NewPostgresDB(databaseURL string) (*PostgresDB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool from environment (defaults: 50 open, 10 idle, 5m lifetime, 1m idle time)
	poolConfig := sharedDB.LoadPoolConfig()
	poolConfig.ApplyToPgxPool(config)
	log.Printf("Database pool configured: %s", poolConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresDB{Pool: pool}, nil
}

// Close is an exported function.
func (db *PostgresDB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// Health is an exported function. It is the cheapest reachability check —
// a pgx Ping that exercises a connection from the pool and runs the
// PostgreSQL "Ping" no-op. Used by /health/ready (kubelet readiness)
// because readiness should flip on transient blips so the Service
// load-balancer drains traffic.
func (db *PostgresDB) Health(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}

// LiveDeep is a stronger liveness check that issues a real SQL statement
// against an application table. Used by /health/live-deep (kubelet
// liveness) so a pod whose pool reports "Ping OK" but cannot actually
// run statements — the failure mode behind the 2026-05-01 OAuth outage,
// where a malformed prepared statement returned column-not-found in
// ~200µs without ever touching iam_oauth_clients — is detected and the
// pod is restarted.
//
// Implementation notes:
//
//   - The query is keyed off iam_oauth_clients because every OAuth flow
//     goes through OAuthClientRepository.GetByClientID. If this table is
//     unreachable the IdP is functionally down regardless of what
//     Ping says.
//   - SELECT count(*) (not SELECT 1 ... LIMIT 1) so the probe still
//     succeeds when the table is legitimately empty — empty IS the
//     correct steady-state on a fresh deploy and must not flap the
//     liveness probe.
//   - count(*) on a small reference table (~10s of rows in steady
//     state) is sub-millisecond and uses an index-only path.
//   - The caller is expected to wrap ctx with a timeout (the kubelet
//     livenessProbe.timeoutSeconds bounds it from the outside, but
//     defense-in-depth a shorter handler-side deadline is still a good
//     idea — the route handler in cmd/routes.go does that).
func (db *PostgresDB) LiveDeep(ctx context.Context) error {
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM iam_oauth_clients`).Scan(&n); err != nil {
		return fmt.Errorf("LiveDeep iam_oauth_clients probe failed: %w", err)
	}
	return nil
}
