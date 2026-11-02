// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	sharedDB "github.com/dogukanturhal/falcon-id/internal/shared/database"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDB is an exported type.
type PostgresDB struct {
	Pool *pgxpool.Pool
}

// NewPostgresDB connects using the pool configuration from the DB_* environment.
func NewPostgresDB(databaseURL string) (*PostgresDB, error) {
	return NewPostgresDBWithPool(databaseURL, sharedDB.LoadPoolConfig())
}

// NewPostgresDBWithPool connects with an explicit pool configuration. Transient
// failures (server out of connection slots, starting up, network errors) are
// retried with exponential backoff within DB_CONNECT_RETRY_MAX (default 90s).
func NewPostgresDBWithPool(databaseURL string, poolConfig sharedDB.PoolConfig) (*PostgresDB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	poolConfig.ApplyToPgxPool(config)
	log.Printf("Database pool configured: %s", poolConfig)

	var pool *pgxpool.Pool
	err = retryTransient(connectRetryMax(), time.Now, time.Sleep, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		p, cerr := pgxpool.NewWithConfig(ctx, config)
		if cerr != nil {
			return fmt.Errorf("failed to create connection pool: %w", cerr)
		}
		if perr := p.Ping(ctx); perr != nil {
			p.Close()
			return fmt.Errorf("failed to ping database: %w", perr)
		}
		pool = p
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &PostgresDB{Pool: pool}, nil
}

const (
	defaultConnectRetryMax = 90 * time.Second
	retryInitialBackoff    = 1 * time.Second
	retryMaxBackoff        = 8 * time.Second
)

// connectRetryMax reads DB_CONNECT_RETRY_MAX (duration, default 90s).
func connectRetryMax() time.Duration {
	val := os.Getenv("DB_CONNECT_RETRY_MAX")
	if val == "" {
		return defaultConnectRetryMax
	}
	d, err := time.ParseDuration(val)
	if err != nil || d < 0 {
		log.Printf("WARNING: invalid duration for DB_CONNECT_RETRY_MAX=%q, using default %s", val, defaultConnectRetryMax)
		return defaultConnectRetryMax
	}
	return d
}

// isTransientConnectError reports whether a connect failure is worth retrying:
// SQLSTATE 53300 (too many clients), 57P03 (cannot connect now), class 08
// (connection exception), and dial/network errors.
func isTransientConnectError(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "53300" || pgErr.Code == "57P03" || strings.HasPrefix(pgErr.Code, "08")
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded)
}

// retryTransient runs attempt until it succeeds, fails non-transiently, or the
// next backoff would exceed budget. now and sleep are injectable for tests.
func retryTransient(budget time.Duration, now func() time.Time, sleep func(time.Duration), attempt func() error) error {
	start := now()
	backoff := retryInitialBackoff
	for n := 1; ; n++ {
		err := attempt()
		if err == nil {
			return nil
		}
		if !isTransientConnectError(err) {
			return err
		}
		if now().Sub(start)+backoff > budget {
			return fmt.Errorf("database not reachable after %d attempts: %w", n, err)
		}
		log.Printf("WARNING: database connect attempt %d failed (transient), retrying in %s: %v", n, backoff, err)
		sleep(backoff)
		if backoff *= 2; backoff > retryMaxBackoff {
			backoff = retryMaxBackoff
		}
	}
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
