// SPDX-License-Identifier: AGPL-3.0-or-later

package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// DBExecutor is an interface that supports both database/sql and pgxpool.
type DBExecutor interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// pgxAdapter wraps pgxpool.Pool to implement DBExecutor interface.
type pgxAdapter struct {
	pool *pgxpool.Pool
}

func (p *pgxAdapter) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	tag, err := p.pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ExecContext: %w", err)
	}
	return pgxResult{tag: tag}, nil
}

// pgxResult wraps pgconn.CommandTag to implement sql.Result.
type pgxResult struct {
	tag interface{ RowsAffected() int64 }
}

func (r pgxResult) LastInsertId() (int64, error) {
	return 0, fmt.Errorf("not supported")
}

func (r pgxResult) RowsAffected() (int64, error) {
	return r.tag.RowsAffected(), nil
}

// Policy defines a data retention cleanup policy.
type Policy struct {
	// Name identifies this policy for logging.
	Name string

	// Table is the database table to clean up.
	Table string

	// TimestampColumn is the column used to determine record age.
	TimestampColumn string

	// RetentionPeriod is how long to keep records.
	// A zero duration means "delete records where timestamp < NOW()"
	RetentionPeriod time.Duration

	// AdditionalCondition is an optional WHERE clause condition (e.g., "status = 'expired'").
	// Do not include the leading "AND" keyword.
	AdditionalCondition string

	// BatchSize limits how many records are deleted per run (0 = no limit).
	BatchSize int
}

// Scheduler manages periodic data cleanup according to configured policies.
type Scheduler struct {
	db       DBExecutor
	policies []Policy
	interval time.Duration
	logger   *zap.Logger
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	running  bool
	stopOnce sync.Once
}

// Config configures the retention scheduler.
type Config struct {
	// DB is the database connection to use for cleanup (database/sql).
	DB *sql.DB

	// PgxPool is the pgx pool to use for cleanup (alternative to DB).
	PgxPool *pgxpool.Pool

	// Policies are the retention policies to enforce.
	Policies []Policy

	// Interval is how often to run cleanup (default: 1 hour).
	Interval time.Duration

	// Logger is the logger to use for output.
	Logger *zap.Logger
}

// NewScheduler creates a new retention scheduler with the given configuration.
func NewScheduler(cfg Config) (*Scheduler, error) {
	var executor DBExecutor
	switch {
	case cfg.DB != nil:
		executor = cfg.DB
	case cfg.PgxPool != nil:
		executor = &pgxAdapter{pool: cfg.PgxPool}
	default:
		return nil, fmt.Errorf("either DB or PgxPool is required")
	}

	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	if len(cfg.Policies) == 0 {
		return nil, fmt.Errorf("at least one policy is required")
	}

	// Validate policies
	for i, policy := range cfg.Policies {
		if err := validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("invalid policy at index %d (%s): %w", i, policy.Name, err)
		}
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = 1 * time.Hour
	}

	return &Scheduler{
		db:       executor,
		policies: cfg.Policies,
		interval: interval,
		logger:   cfg.Logger,
		stopCh:   make(chan struct{}),
	}, nil
}

// validatePolicy validates a policy configuration.
func validatePolicy(p Policy) error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Table == "" {
		return fmt.Errorf("table name is required")
	}
	if p.TimestampColumn == "" {
		return fmt.Errorf("timestamp column is required")
	}
	if p.RetentionPeriod < 0 {
		return fmt.Errorf("retention period cannot be negative")
	}
	if p.BatchSize < 0 {
		return fmt.Errorf("batch size cannot be negative")
	}
	return nil
}

// Start begins the retention scheduler. It runs in the background until Stop is called.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler is already running")
	}
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.run(ctx)

	s.logger.Info("Retention scheduler started",
		zap.Duration("interval", s.interval),
		zap.Int("policies", len(s.policies)))

	return nil
}

// Stop gracefully stops the retention scheduler.
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()

	s.logger.Info("Retention scheduler stopped")
	return nil
}

// run is the main loop that executes cleanup policies.
func (s *Scheduler) run(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run immediately on start
	s.executeAllPolicies(ctx)

	for {
		select {
		case <-ticker.C:
			s.executeAllPolicies(ctx)
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// executeAllPolicies executes all configured cleanup policies.
func (s *Scheduler) executeAllPolicies(ctx context.Context) {
	s.logger.Debug("Starting retention cleanup cycle")
	startTime := time.Now()

	totalDeleted := int64(0)
	for _, policy := range s.policies {
		deleted, err := s.executePolicy(ctx, policy)
		if err != nil {
			s.logger.Error("Policy execution failed",
				zap.String("policy", policy.Name),
				zap.Error(err))
			continue
		}

		totalDeleted += deleted
		if deleted > 0 {
			s.logger.Info("Policy executed successfully",
				zap.String("policy", policy.Name),
				zap.String("table", policy.Table),
				zap.Int64("deleted", deleted),
				zap.Duration("retention", policy.RetentionPeriod))
		}
	}

	duration := time.Since(startTime)
	s.logger.Debug("Retention cleanup cycle completed",
		zap.Duration("duration", duration),
		zap.Int64("total_deleted", totalDeleted))
}

// executePolicy executes a single cleanup policy.
func (s *Scheduler) executePolicy(ctx context.Context, policy Policy) (int64, error) {
	query, err := buildDeleteQuery(policy)
	if err != nil {
		return 0, fmt.Errorf("failed to build delete query: %w", err)
	}

	s.logger.Debug("Executing retention policy",
		zap.String("policy", policy.Name),
		zap.String("query", query))

	result, err := s.db.ExecContext(ctx, query)
	if err != nil {
		// Skip policies for tables that don't exist yet (e.g., not migrated).
		// Log at debug level to avoid noisy errors every cleanup cycle.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // undefined_table
			s.logger.Debug("Skipping retention policy for non-existent table",
				zap.String("policy", policy.Name),
				zap.String("table", policy.Table))
			return 0, nil
		}
		return 0, fmt.Errorf("failed to execute cleanup query: %w", err)
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return deleted, nil
}

// buildDeleteQuery constructs a DELETE query from a policy.
// Table and column names are validated and quoted to prevent SQL injection.
func buildDeleteQuery(policy Policy) (string, error) {
	// Validate and quote table and column identifiers
	table, err := sanitizeIdentifier(policy.Table)
	if err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}
	column, err := sanitizeIdentifier(policy.TimestampColumn)
	if err != nil {
		return "", fmt.Errorf("invalid column name: %w", err)
	}
	safeTable := quoteRetentionIdentifier(table)
	safeColumn := quoteRetentionIdentifier(column)

	query := fmt.Sprintf("DELETE FROM %s WHERE %s < NOW()", safeTable, safeColumn)

	// Add retention period if specified (using integer seconds, safe from injection)
	if policy.RetentionPeriod > 0 {
		query += fmt.Sprintf(" - INTERVAL '%d seconds'", int64(policy.RetentionPeriod.Seconds()))
	}

	// Add additional condition if specified
	// SECURITY: AdditionalCondition is set by server-side code via Policy structs,
	// not by user input. It should only contain safe, pre-validated SQL fragments.
	if policy.AdditionalCondition != "" {
		query += fmt.Sprintf(" AND (%s)", policy.AdditionalCondition)
	}

	// Add batch size limit if specified — PostgreSQL doesn't support DELETE...LIMIT,
	// so use a ctid-based subquery instead.
	if policy.BatchSize > 0 {
		// Wrap the existing WHERE clause in a subquery
		whereClause := fmt.Sprintf("%s < NOW()", safeColumn)
		if policy.RetentionPeriod > 0 {
			whereClause = fmt.Sprintf("%s < NOW() - INTERVAL '%d seconds'", safeColumn, int64(policy.RetentionPeriod.Seconds()))
		}
		if policy.AdditionalCondition != "" {
			whereClause += fmt.Sprintf(" AND (%s)", policy.AdditionalCondition)
		}
		query = fmt.Sprintf("DELETE FROM %s WHERE ctid IN (SELECT ctid FROM %s WHERE %s LIMIT %d)",
			safeTable, safeTable, whereClause, policy.BatchSize)
	}

	return query, nil
}

// sanitizeIdentifier sanitizes a SQL identifier (table or column name).
// Only allows alphanumeric characters and underscores. Returns an error
// if invalid characters are found, ensuring invalid identifiers
// are never used in queries.
func sanitizeIdentifier(identifier string) (string, error) {
	if identifier == "" {
		return "", fmt.Errorf("empty identifier")
	}

	// Only allow alphanumeric and underscores
	var result strings.Builder
	for _, r := range identifier {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			result.WriteRune(r)
		}
	}

	safe := result.String()
	if safe == "" || safe != identifier {
		return "", fmt.Errorf("invalid identifier: %q contains characters not in [a-zA-Z0-9_]", identifier)
	}

	// Truncate to max identifier length (63 for PostgreSQL)
	if len(safe) > 63 {
		safe = safe[:63]
	}

	return safe, nil
}

// quoteRetentionIdentifier properly quotes a PostgreSQL identifier to prevent
// SQL injection in retention queries. Wraps the name in double quotes and
// escapes any embedded double-quote characters.
func quoteRetentionIdentifier(name string) string {
	return fmt.Sprintf(`"%s"`, strings.ReplaceAll(name, `"`, `""`))
}

// RunOnce executes all policies once and returns immediately.
// This is useful for manual cleanup or testing.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler is already running, use Stop() first")
	}
	s.mu.Unlock()

	s.executeAllPolicies(ctx)
	return nil
}

// GetPolicies returns the configured policies.
func (s *Scheduler) GetPolicies() []Policy {
	return append([]Policy{}, s.policies...)
}
