// SPDX-License-Identifier: AGPL-3.0-or-later

// Package database provides shared database connection pool configuration
// for all Go platform services. It supports both database/sql and pgxpool connections.
package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig holds database connection pool parameters.
// Values can be loaded from environment variables or used with defaults.
type PoolConfig struct {
	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns int

	// MinConns is the number of connections a pgxpool keeps open (pinned) even
	// when idle. Keep it low: every pinned connection counts against the
	// server's max_connections for the whole life of the pod.
	MinConns int

	// MaxIdleConns is the maximum number of idle connections in a database/sql
	// pool. It does not affect pgxpool (see MinConns).
	MaxIdleConns int

	// ConnMaxLifetime is the maximum amount of time a connection may be reused.
	ConnMaxLifetime time.Duration

	// ConnMaxIdleTime is the maximum amount of time a connection may be idle.
	ConnMaxIdleTime time.Duration

	// HealthCheckPeriod is the interval between health checks for pgxpool connections.
	HealthCheckPeriod time.Duration
}

// DefaultPoolConfig returns a PoolConfig with sensible defaults suitable
// for most platform services.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:      10,
		MinConns:          0,
		MaxIdleConns:      10,
		ConnMaxLifetime:   5 * time.Minute,
		ConnMaxIdleTime:   1 * time.Minute,
		HealthCheckPeriod: 1 * time.Minute,
	}
}

// LoadPoolConfig reads pool configuration from environment variables, falling
// back to defaults for any value not set. Environment variables:
//
//	DB_MAX_OPEN_CONNS    - maximum open connections (default: 10)
//	DB_MIN_CONNS         - pgxpool connections kept open when idle (default: 0)
//	DB_MAX_IDLE_CONNS    - database/sql max idle connections (default: 10)
//	DB_CONN_MAX_LIFETIME - connection max lifetime (default: 5m)
//	DB_CONN_MAX_IDLE_TIME - connection max idle time (default: 1m)
//	DB_HEALTH_CHECK_PERIOD - health check period for pgxpool (default: 1m)
func LoadPoolConfig() PoolConfig {
	return LoadPoolConfigPrefixed("DB_")
}

// LoadPoolConfigPrefixed reads pool configuration from <prefix>MAX_OPEN_CONNS,
// <prefix>MIN_CONNS, <prefix>MAX_IDLE_CONNS, <prefix>CONN_MAX_LIFETIME,
// <prefix>CONN_MAX_IDLE_TIME and <prefix>HEALTH_CHECK_PERIOD. Each value falls
// back to the matching DB_* variable, then to the default. This lets a second
// database (e.g. CONTROL_PLANE_DB_) get its own, smaller pool.
func LoadPoolConfigPrefixed(prefix string) PoolConfig {
	defaults := DefaultPoolConfig()

	return PoolConfig{
		MaxOpenConns:      getEnvIntPrefixed(prefix, "MAX_OPEN_CONNS", defaults.MaxOpenConns),
		MinConns:          getEnvIntPrefixed(prefix, "MIN_CONNS", defaults.MinConns),
		MaxIdleConns:      getEnvIntPrefixed(prefix, "MAX_IDLE_CONNS", defaults.MaxIdleConns),
		ConnMaxLifetime:   getEnvDurationPrefixed(prefix, "CONN_MAX_LIFETIME", defaults.ConnMaxLifetime),
		ConnMaxIdleTime:   getEnvDurationPrefixed(prefix, "CONN_MAX_IDLE_TIME", defaults.ConnMaxIdleTime),
		HealthCheckPeriod: getEnvDurationPrefixed(prefix, "HEALTH_CHECK_PERIOD", defaults.HealthCheckPeriod),
	}
}

func getEnvIntPrefixed(prefix, name string, fallback int) int {
	return getEnvInt(prefix+name, getEnvInt("DB_"+name, fallback))
}

func getEnvDurationPrefixed(prefix, name string, fallback time.Duration) time.Duration {
	return getEnvDuration(prefix+name, getEnvDuration("DB_"+name, fallback))
}

// Apply configures the given *sql.DB connection pool with the values from
// this PoolConfig. This is used by services that connect via database/sql.
func (c PoolConfig) Apply(db *sql.DB) {
	db.SetMaxOpenConns(c.MaxOpenConns)
	db.SetMaxIdleConns(c.MaxIdleConns)
	db.SetConnMaxLifetime(c.ConnMaxLifetime)
	db.SetConnMaxIdleTime(c.ConnMaxIdleTime)
}

// ApplyToPgxPool configures the given *pgxpool.Config with the values from
// this PoolConfig. This is used by services that connect via pgxpool.
func (c PoolConfig) ApplyToPgxPool(config *pgxpool.Config) {
	config.MaxConns = int32(c.MaxOpenConns) //nolint:gosec // value is bounded by pool size config, safe conversion
	config.MinConns = int32(c.MinConns) //nolint:gosec // value is bounded by pool size config, safe conversion
	config.MaxConnLifetime = c.ConnMaxLifetime
	config.MaxConnIdleTime = c.ConnMaxIdleTime
	config.HealthCheckPeriod = c.HealthCheckPeriod
}

// String returns a human-readable summary of the pool configuration,
// useful for startup logging.
func (c PoolConfig) String() string {
	return fmt.Sprintf(
		"PoolConfig{MaxOpenConns: %d, MinConns: %d, MaxIdleConns: %d, ConnMaxLifetime: %s, ConnMaxIdleTime: %s, HealthCheckPeriod: %s}",
		c.MaxOpenConns,
		c.MinConns,
		c.MaxIdleConns,
		c.ConnMaxLifetime,
		c.ConnMaxIdleTime,
		c.HealthCheckPeriod,
	)
}

// getEnvInt reads an integer from the named environment variable.
// If the variable is not set or cannot be parsed, the fallback value is returned.
func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("WARNING: invalid integer for %s=%q, using default %d: %v", key, val, fallback, err) //nolint:gosec // log message contains sanitized connection string
		return fallback
	}

	return parsed
}

// getEnvDuration reads a time.Duration from the named environment variable.
// The value should be a string parseable by time.ParseDuration (e.g. "5m", "30s", "1h").
// If the variable is not set or cannot be parsed, the fallback value is returned.
func getEnvDuration(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(val)
	if err != nil {
		log.Printf("WARNING: invalid duration for %s=%q, using default %s: %v", key, val, fallback, err) //nolint:gosec // log message contains sanitized connection string
		return fallback
	}

	return parsed
}
