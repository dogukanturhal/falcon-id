// SPDX-License-Identifier: AGPL-3.0-or-later

// Package database provides database migration utilities.
package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// Migration represents a single migration file.
type Migration struct {
	Version  int
	Filename string
	SQL      string
	Checksum string
}

// Migrator handles automatic database schema migrations.
type Migrator struct {
	pool   *pgxpool.Pool
	fs     fs.FS
	logger *zap.Logger
}

// NewMigrator creates a new Migrator instance.
func NewMigrator(pool *pgxpool.Pool, fsys fs.FS, logger *zap.Logger) *Migrator {
	return &Migrator{
		pool:   pool,
		fs:     fsys,
		logger: logger,
	}
}

// Run executes all pending migrations in order.
func (m *Migrator) Run(ctx context.Context) error {
	start := time.Now()
	m.logger.Info("Starting database migration check")

	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied versions: %w", err)
	}

	available, err := m.getAvailableMigrations()
	if err != nil {
		return fmt.Errorf("failed to get available migrations: %w", err)
	}

	if len(available) == 0 {
		m.logger.Warn("No migration files found in embedded filesystem")
		return nil
	}

	// Check for checksum mismatches on already-applied migrations
	for _, mig := range available {
		if existing, ok := applied[mig.Version]; ok && existing != mig.Checksum {
			m.logger.Warn("Migration checksum mismatch — file has been modified after it was applied",
				zap.Int("version", mig.Version),
				zap.String("filename", mig.Filename),
				zap.String("applied_checksum", existing),
				zap.String("current_checksum", mig.Checksum),
			)
		}
	}

	// Determine pending migrations
	var pending []Migration
	for _, mig := range available {
		if _, ok := applied[mig.Version]; !ok {
			pending = append(pending, mig)
		}
	}

	if len(pending) == 0 {
		m.logger.Info("Database schema is up to date",
			zap.Int("applied", len(applied)),
			zap.Int("available", len(available)),
			zap.Duration("check_duration", time.Since(start)),
		)
		return nil
	}

	m.logger.Info("Applying pending migrations",
		zap.Int("pending", len(pending)),
		zap.Int("already_applied", len(applied)),
		zap.Int("total_available", len(available)),
	)

	for _, mig := range pending {
		if err := m.applyMigration(ctx, mig); err != nil {
			return fmt.Errorf("failed to apply migration %d (%s): %w", mig.Version, mig.Filename, err)
		}
	}

	m.logger.Info("Database migrations completed",
		zap.Int("applied", len(pending)),
		zap.Int("total", len(available)),
		zap.Duration("duration", time.Since(start)),
	)

	return nil
}

// ensureMigrationsTable creates the schema_migrations table if it doesn't exist,
// and upgrades the schema if migrating from the legacy IAM migrator.
func (m *Migrator) ensureMigrationsTable(ctx context.Context) error {
	_, err := m.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER PRIMARY KEY,
			filename    VARCHAR(255) NOT NULL DEFAULT '',
			checksum    VARCHAR(64) NOT NULL DEFAULT '',
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return err
	}

	// Upgrade legacy schema: add filename column if missing (old IAM migrator didn't have it)
	_, _ = m.pool.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS filename VARCHAR(255) NOT NULL DEFAULT ''`)
	// Upgrade legacy schema: add checksum column if missing
	_, _ = m.pool.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum VARCHAR(64) NOT NULL DEFAULT ''`)

	return nil
}

// getAppliedVersions returns a map of version -> checksum for all applied migrations.
func (m *Migrator) getAppliedVersions(ctx context.Context) (map[int]string, error) {
	rows, err := m.pool.Query(ctx, "SELECT version, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]string)
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, err
		}
		applied[version] = checksum
	}
	return applied, rows.Err()
}

// getAvailableMigrations reads and parses all migration files from the embedded FS.
func (m *Migrator) getAvailableMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(m.fs, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var migrations []Migration
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !isUpMigration(name) {
			continue
		}

		version, err := parseVersion(name)
		if err != nil {
			m.logger.Warn("Skipping file with unparseable version", zap.String("filename", name), zap.Error(err))
			continue
		}

		content, err := fs.ReadFile(m.fs, name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", name, err)
		}

		checksum := checksumBytes(content)
		migrations = append(migrations, Migration{
			Version:  version,
			Filename: name,
			SQL:      string(content),
			Checksum: checksum,
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// applyMigration runs a single migration inside a transaction.
func (m *Migrator) applyMigration(ctx context.Context, mig Migration) error {
	migStart := time.Now()
	m.logger.Info("Applying migration",
		zap.Int("version", mig.Version),
		zap.String("filename", mig.Filename),
	)

	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, mig.SQL); err != nil {
		return fmt.Errorf("failed to execute SQL: %w", err)
	}

	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations (version, filename, checksum, applied_at) VALUES ($1, $2, $3, NOW())",
		mig.Version, mig.Filename, mig.Checksum,
	); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	m.logger.Info("Migration applied successfully",
		zap.Int("version", mig.Version),
		zap.String("filename", mig.Filename),
		zap.Duration("duration", time.Since(migStart)),
	)

	return nil
}

// migrationFilePattern matches filenames like "001_description.sql" or "045_description.up.sql"
var migrationFilePattern = regexp.MustCompile(`^(\d+)_.+\.sql$`)

// isUpMigration returns true if the filename is an "up" migration (not a down or verify file).
func isUpMigration(name string) bool {
	if !migrationFilePattern.MatchString(name) {
		return false
	}
	if strings.HasSuffix(name, ".down.sql") {
		return false
	}
	if strings.HasPrefix(name, "verify_") {
		return false
	}
	return true
}

// parseVersion extracts the numeric version prefix from a migration filename.
func parseVersion(name string) (int, error) {
	matches := migrationFilePattern.FindStringSubmatch(name)
	if len(matches) < 2 {
		return 0, fmt.Errorf("filename %q does not match migration pattern", name)
	}
	return strconv.Atoi(matches[1])
}

// Advisory lock keys used by the migrator to prevent concurrent execution.
// These are stable constants chosen to avoid collisions with application data.
const (
	// advisoryLockMigrate is the PostgreSQL advisory lock key used to ensure
	// only one process runs migrations at a time (e.g., across K8s replicas).
	advisoryLockMigrate int64 = 857491002
)

// RunWithLock wraps Run() with a PostgreSQL advisory lock to prevent concurrent
// migration execution across multiple replicas. The lock is held for the
// duration of the migration and released automatically when done.
// This is the recommended entry point for production deployments.
func (m *Migrator) RunWithLock(ctx context.Context) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for migration lock: %w", err)
	}
	defer conn.Release()

	// Blocking advisory lock — migrations MUST run exactly once, so we wait
	// rather than skip. The lock is session-scoped and released when the
	// connection is returned to the pool.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockMigrate); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", advisoryLockMigrate)
	}()

	m.logger.Info("Migration advisory lock acquired")
	return m.Run(ctx)
}

// checksumBytes returns the hex-encoded SHA-256 checksum of the given data.
func checksumBytes(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}
