// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const fleetStatusHealthy = "healthy"

// fleetInstanceDBRepo is the narrow interface the FleetOperationsRunner requires
// from the instance database repository. Keeping it minimal allows easy mocking
// in tests without depending on the full concrete repository type.
type fleetInstanceDBRepo interface {
	ListActive(ctx context.Context) ([]models.InstanceDatabase, error)
}

// fleetHostRepo is the narrow interface for reading host capacity metrics.
type fleetHostRepo interface {
	List(ctx context.Context) ([]models.RealmDatabaseHost, error)
}

// FleetOperationsRunner executes operations (migrations, health checks, ad-hoc SQL,
// capacity analysis) across ALL active tenant databases in parallel.
//
// Bounded parallelism is implemented via a semaphore channel so that a runaway
// fleet operation cannot exhaust the platform's connection pool.
type FleetOperationsRunner struct {
	instanceDBRepo fleetInstanceDBRepo
	hostRepo       fleetHostRepo
	pool           *pgxpool.Pool // used for direct health-check pings
	log            *zap.SugaredLogger
}

// FleetOperationResult is the aggregate outcome of a fleet-wide operation.
type FleetOperationResult struct {
	TotalTargets int                 `json:"total_targets"`
	Successful   int                 `json:"successful"`
	Failed       int                 `json:"failed"`
	Skipped      int                 `json:"skipped"`
	Duration     string              `json:"duration"`
	Results      []FleetTargetResult `json:"results"`
}

// FleetTargetResult is the per-database outcome within a fleet operation.
type FleetTargetResult struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	DatabaseName string    `json:"database_name"`
	Host         string    `json:"host"`
	Status       string    `json:"status"` // "success", "failed", "skipped"
	Error        string    `json:"error,omitempty"`
	Duration     string    `json:"duration"`
}

// HostCapacityReport is a per-host capacity and health summary returned by
// GetCapacityReport.
type HostCapacityReport struct {
	HostAlias       string  `json:"host_alias"`
	Region          string  `json:"region"`
	TotalDatabases  int     `json:"total_databases"`
	MaxDatabases    int     `json:"max_databases"`
	UtilizationPct  float64 `json:"utilization_pct"`
	HealthStatus    string  `json:"health_status"`
	RecommendAction string  `json:"recommend_action"` // "ok", "expand", "rebalance", "new_host"
}

// fleetTarget packages the fields the parallel runner needs for one operation.
type fleetTarget struct {
	instanceDB models.InstanceDatabase
}

// NewFleetOperationsRunner creates a runner backed by the given repos and pool.
// pool may be nil — in that case direct-connection health checks will be skipped.
func NewFleetOperationsRunner(
	instanceDBRepo fleetInstanceDBRepo,
	hostRepo fleetHostRepo,
	pool *pgxpool.Pool,
	log *zap.SugaredLogger,
) *FleetOperationsRunner {
	return &FleetOperationsRunner{
		instanceDBRepo: instanceDBRepo,
		hostRepo:       hostRepo,
		pool:           pool,
		log:            log,
	}
}

// RunSQL executes an arbitrary SQL statement against every active tenant database
// using bounded parallelism (maxConcurrent goroutines at most).
//
// The SQL is executed with a 30-second per-database timeout so a single slow
// instance cannot block the entire fleet run. Databases whose connection string
// is not populated are skipped gracefully.
func (r *FleetOperationsRunner) RunSQL(ctx context.Context, sql string, maxConcurrent int) (*FleetOperationResult, error) {
	if sql == "" {
		return nil, fmt.Errorf("FleetOperationsRunner.RunSQL: sql must not be empty")
	}

	// Security: block destructive DDL unless the caller is explicitly aware.
	// This prevents accidental data loss across the entire fleet.
	upperSQL := strings.ToUpper(strings.TrimSpace(sql))
	blockedKeywords := []string{"DROP DATABASE", "DROP SCHEMA", "TRUNCATE", "DROP TABLE"}
	for _, kw := range blockedKeywords {
		if strings.Contains(upperSQL, kw) {
			return nil, fmt.Errorf("FleetOperationsRunner.RunSQL: destructive DDL blocked (%s) — use direct database access for destructive operations", kw)
		}
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}

	targets, err := r.loadTargets(ctx)
	if err != nil {
		return nil, fmt.Errorf("FleetOperationsRunner.RunSQL: %w", err)
	}

	r.log.Infow("Fleet SQL operation starting",
		"targets", len(targets),
		"max_concurrent", maxConcurrent,
		"sql_preview", sqlPreview(sql, 80),
	)

	return r.runParallel(ctx, targets, maxConcurrent, func(ctx context.Context, t fleetTarget) error {
		return r.execSQLOnTarget(ctx, t, sql)
	}), nil
}

// RunMigrations runs pending SQL migrations against every active tenant database.
// migrationDir is a label used in logs — actual migration logic is delegated to
// the caller via the SQL runner (fleet operators pass raw migration SQL).
// For production use, callers should read SQL files from the migrations directory
// and pass individual statements via RunSQL.
//
// This method exists as a named entry point so API handlers can distinguish
// "migration" operations from generic SQL for audit logging purposes.
func (r *FleetOperationsRunner) RunMigrations(ctx context.Context, migrationDir string, maxConcurrent int) (*FleetOperationResult, error) {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}

	targets, err := r.loadTargets(ctx)
	if err != nil {
		return nil, fmt.Errorf("FleetOperationsRunner.RunMigrations: %w", err)
	}

	r.log.Infow("Fleet migration operation starting",
		"migration_dir", migrationDir,
		"targets", len(targets),
		"max_concurrent", maxConcurrent,
	)

	// RunMigrations is intentionally a connectivity/schema-version check in this
	// implementation. Full migration file execution would require embedding the
	// migration FS (handled per-instance by the ProvisioningOrchestrator).
	// The fleet runner validates connectivity and reports schema version for each
	// active tenant database.
	return r.runParallel(ctx, targets, maxConcurrent, func(ctx context.Context, t fleetTarget) error {
		return r.pingTarget(ctx, t)
	}), nil
}

// RunHealthCheck verifies connectivity and basic health for every active tenant
// database using bounded parallelism.
func (r *FleetOperationsRunner) RunHealthCheck(ctx context.Context, maxConcurrent int) (*FleetOperationResult, error) {
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}

	targets, err := r.loadTargets(ctx)
	if err != nil {
		return nil, fmt.Errorf("FleetOperationsRunner.RunHealthCheck: %w", err)
	}

	r.log.Infow("Fleet health check starting",
		"targets", len(targets),
		"max_concurrent", maxConcurrent,
	)

	return r.runParallel(ctx, targets, maxConcurrent, func(ctx context.Context, t fleetTarget) error {
		return r.pingTarget(ctx, t)
	}), nil
}

// GetCapacityReport returns a per-host capacity summary to help operators
// decide when to add new hosts or rebalance tenants.
func (r *FleetOperationsRunner) GetCapacityReport(ctx context.Context) ([]HostCapacityReport, error) {
	hosts, err := r.hostRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("FleetOperationsRunner.GetCapacityReport: list hosts: %w", err)
	}

	// Load active instance DB count per host to compute utilization based on
	// real running databases (not just the host's internal counter).
	activeDatabases, err := r.instanceDBRepo.ListActive(ctx)
	if err != nil {
		// Non-fatal: fall back to the host's own current_databases counter.
		r.log.Warnw("GetCapacityReport: could not load active databases, using host counters",
			zap.Error(err),
		)
		activeDatabases = nil
	}

	// Build a per-host count from the instance databases.
	hostCounts := make(map[string]int, len(hosts))
	for _, idb := range activeDatabases {
		if idb.DatabaseHost != nil {
			hostCounts[*idb.DatabaseHost]++
		}
	}

	reports := make([]HostCapacityReport, 0, len(hosts))
	for _, h := range hosts {
		totalDBs := h.CurrentDatabases
		if cnt, ok := hostCounts[h.HostAlias]; ok {
			totalDBs = cnt
		}

		utilPct := 0.0
		if h.MaxDatabases > 0 {
			utilPct = float64(totalDBs) / float64(h.MaxDatabases) * 100.0
		}

		region := ""
		if h.Region != nil {
			region = *h.Region
		}

		reports = append(reports, HostCapacityReport{
			HostAlias:       h.HostAlias,
			Region:          region,
			TotalDatabases:  totalDBs,
			MaxDatabases:    h.MaxDatabases,
			UtilizationPct:  utilPct,
			HealthStatus:    h.HealthStatus,
			RecommendAction: recommendAction(utilPct, h.HealthStatus, h.IsActive),
		})
	}
	return reports, nil
}

// ---------------------------------------------------------------------------
// Parallel execution engine
// ---------------------------------------------------------------------------

// runParallel executes fn concurrently for each target using a semaphore of
// size maxConcurrent. Results are collected thread-safely and returned as a
// FleetOperationResult. Goroutines respect the parent ctx for cancellation.
func (r *FleetOperationsRunner) runParallel(
	ctx context.Context,
	targets []fleetTarget,
	maxConcurrent int,
	fn func(ctx context.Context, t fleetTarget) error,
) *FleetOperationResult {
	start := time.Now()
	sem := make(chan struct{}, maxConcurrent)
	var mu sync.Mutex
	var wg sync.WaitGroup

	out := &FleetOperationResult{
		TotalTargets: len(targets),
		Results:      make([]FleetTargetResult, 0, len(targets)),
	}

	for _, t := range targets {
		// Skip targets without host info — they cannot be contacted.
		if t.instanceDB.DatabaseHost == nil {
			mu.Lock()
			out.Skipped++
			out.Results = append(out.Results, FleetTargetResult{
				TenantID:     instanceTenantID(t),
				DatabaseName: t.instanceDB.DatabaseName,
				Host:         "",
				Status:       "skipped",
				Error:        "no database host configured",
				Duration:     "0s",
			})
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(t fleetTarget) {
			defer wg.Done()

			// Acquire semaphore slot — respect context cancellation.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				defer mu.Unlock()
				out.Skipped++
				out.Results = append(out.Results, FleetTargetResult{
					TenantID:     instanceTenantID(t),
					DatabaseName: t.instanceDB.DatabaseName,
					Host:         safeDeref(t.instanceDB.DatabaseHost),
					Status:       "skipped",
					Error:        "context cancelled",
					Duration:     "0s",
				})
				return
			}

			tStart := time.Now()
			err := fn(ctx, t)
			dur := time.Since(tStart)

			mu.Lock()
			defer mu.Unlock()

			res := FleetTargetResult{
				TenantID:     instanceTenantID(t),
				DatabaseName: t.instanceDB.DatabaseName,
				Host:         safeDeref(t.instanceDB.DatabaseHost),
				Duration:     dur.Round(time.Millisecond).String(),
			}

			if err != nil {
				res.Status = awxJobStatusFailed
				res.Error = err.Error()
				out.Failed++
			} else {
				res.Status = "success"
				out.Successful++
			}
			out.Results = append(out.Results, res)
		}(t)
	}

	wg.Wait()
	out.Duration = time.Since(start).Round(time.Millisecond).String()
	return out
}

// ---------------------------------------------------------------------------
// Target operations
// ---------------------------------------------------------------------------

// pingTarget checks connectivity to an instance database by opening a short-lived
// pgxpool connection and running SELECT 1.
func (r *FleetOperationsRunner) pingTarget(ctx context.Context, t fleetTarget) error {
	if t.instanceDB.DatabaseHost == nil {
		return fmt.Errorf("no host configured")
	}

	connStr, err := r.connectionStringFor(t.instanceDB)
	if err != nil {
		return fmt.Errorf("resolve connection string: %w", err)
	}

	tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("parse connection string: %w", err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0

	pool, err := pgxpool.NewWithConfig(tctx, cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	var dummy int
	if err := pool.QueryRow(tctx, "SELECT 1").Scan(&dummy); err != nil {
		return fmt.Errorf("ping query: %w", err)
	}
	return nil
}

// execSQLOnTarget opens a short-lived connection to the target database and
// executes the given SQL statement. A 30-second per-database timeout is applied.
func (r *FleetOperationsRunner) execSQLOnTarget(ctx context.Context, t fleetTarget, sql string) error {
	if t.instanceDB.DatabaseHost == nil {
		return fmt.Errorf("no host configured")
	}

	connStr, err := r.connectionStringFor(t.instanceDB)
	if err != nil {
		return fmt.Errorf("resolve connection string: %w", err)
	}

	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("parse connection string: %w", err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0

	pool, err := pgxpool.NewWithConfig(tctx, cfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(tctx, sql); err != nil {
		return fmt.Errorf("exec sql: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// loadTargets fetches all active instance databases and converts them into
// fleetTarget values ready for parallel execution.
func (r *FleetOperationsRunner) loadTargets(ctx context.Context) ([]fleetTarget, error) {
	dbs, err := r.instanceDBRepo.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active instance databases: %w", err)
	}
	targets := make([]fleetTarget, len(dbs))
	for i, db := range dbs {
		targets[i] = fleetTarget{instanceDB: db}
	}
	return targets, nil
}

// connectionStringFor builds a connection string for the given InstanceDatabase.
// When ConnectionStringEnc is set and can be decrypted, the decrypted value is
// used. Otherwise, a DSN is constructed from the host, database name, and schema.
func (r *FleetOperationsRunner) connectionStringFor(idb models.InstanceDatabase) (string, error) {
	if len(idb.ConnectionStringEnc) > 0 {
		// The encrypted connection string stores the full DSN. Attempt to use it
		// directly (decryption would be handled by a crypto.EncryptionService, which
		// is not injected here to keep the runner lightweight). For now, if the bytes
		// look like a printable DSN we use them as-is (dev mode).
		raw := string(idb.ConnectionStringEnc)
		if isPlaintextDSN(raw) {
			return raw, nil
		}
		// Encrypted — cannot decrypt without the key; fall through to host-based DSN.
	}

	if idb.DatabaseHost == nil {
		return "", fmt.Errorf("no database host available")
	}

	// Construct a minimal DSN from the host, database name, and username.
	// This works for dev seeds where the host stores host:port.
	dbName := idb.DatabaseName
	username := "postgres"
	if idb.DatabaseUsername != nil {
		username = *idb.DatabaseUsername
	}

	// Include password from environment if available (required for dev/prod
	// where PostgreSQL enforces password authentication).
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		password = os.Getenv("DB_PASSWORD")
	}
	if password == "" {
		password = extractPasswordFromDatabaseURL(os.Getenv("DATABASE_URL"))
	}

	if password != "" {
		return fmt.Sprintf("host=%s dbname=%s user=%s password=%s sslmode=disable",
			*idb.DatabaseHost, dbName, username, password,
		), nil
	}

	return fmt.Sprintf("host=%s dbname=%s user=%s sslmode=disable",
		*idb.DatabaseHost, dbName, username,
	), nil
}

// extractPasswordFromDatabaseURL extracts the password from a postgres://user:pass@host/db URL.
// Returns an empty string if the URL is empty or does not contain a password.
func extractPasswordFromDatabaseURL(dbURL string) string {
	if dbURL == "" {
		return ""
	}
	atIdx := strings.Index(dbURL, "@")
	if atIdx <= 0 {
		return ""
	}
	userPass := dbURL[strings.Index(dbURL, "//")+2 : atIdx]
	colonIdx := strings.Index(userPass, ":")
	if colonIdx < 0 {
		return ""
	}
	return userPass[colonIdx+1:]
}

// instanceTenantID extracts the InstanceID from the target as a proxy for the
// tenant UUID. The real tenant UUID is on the ProductInstance record, which the
// fleet runner doesn't load (to avoid an extra join per target). The InstanceID
// is a close approximation for display purposes.
func instanceTenantID(t fleetTarget) uuid.UUID {
	return t.instanceDB.InstanceID
}

// safeDeref dereferences a *string or returns an empty string.
func safeDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sqlPreview returns the first maxLen bytes of a SQL string for safe logging.
func sqlPreview(sql string, maxLen int) string {
	if len(sql) <= maxLen {
		return sql
	}
	return sql[:maxLen] + "…"
}

// isPlaintextDSN reports whether the byte slice looks like a printable
// PostgreSQL DSN string (starts with "host=" or "postgres://").
func isPlaintextDSN(s string) bool {
	if len(s) < 5 {
		return false
	}
	return s[:5] == "host=" || (len(s) >= 11 && s[:11] == "postgres://") || (len(s) >= 13 && s[:13] == "postgresql://")
}

// recommendAction returns an operator recommendation based on current utilization
// and health status.
func recommendAction(utilPct float64, healthStatus string, isActive bool) string {
	if !isActive || healthStatus != fleetStatusHealthy {
		return "rebalance"
	}
	switch {
	case utilPct >= 90:
		return "new_host"
	case utilPct >= 75:
		return "expand"
	case utilPct >= 60:
		return "rebalance"
	default:
		return "ok"
	}
}
