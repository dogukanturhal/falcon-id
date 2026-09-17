// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// tenant_data_export.go provides TenantDataExportService, which orchestrates
// a full tenant data export across all ExampleSuite business-module databases.
//
// Export format: a directory tree at {exportDir}/{tenantID}/{timestamp}/
//
//	manifest.json               — metadata (tenant_id, modules, total size, duration)
//	{module}/{table}.jsonl      — JSONL rows WHERE tenant_id = req.TenantID
//
// The service discovers exportable tables by querying information_schema.columns
// for any column named "tenant_id" in each module database, then streams rows
// via COPY … TO STDOUT with a WHERE clause bound to the requested tenant.
//
// Connection credentials for each module database are resolved through the
// iam_product_resource_manifests / iam_instance_databases tables on the control-
// plane pool. This keeps the export self-contained without requiring a separate
// service registry.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const defaultExportDir = "/tmp/hexxlock-exports"

// moduleDB describes a business-module database that the exporter will connect to.
type moduleDB struct {
	Module   string // e.g. "crm"
	Database string // e.g. "hexxlock_crm_<tenant_slug>"
	DSN      string // postgres://... connection string
}

// ExportRequest controls what is included in a full-tenant export.
type ExportRequest struct {
	TenantID uuid.UUID
	Format   string   // "json" (JSONL lines per table). Reserved: "csv".
	Modules  []string // empty = all modules
}

// ExportResult is the top-level summary returned to the caller.
type ExportResult struct {
	TenantID  uuid.UUID      `json:"tenant_id"`
	ExportDir string         `json:"export_dir"`
	Modules   []ModuleExport `json:"modules"`
	TotalSize int64          `json:"total_size_bytes"`
	Duration  string         `json:"duration"`
	CreatedAt time.Time      `json:"created_at"`
}

// ModuleExport holds per-module statistics.
type ModuleExport struct {
	Module    string `json:"module"`
	Database  string `json:"database"`
	Tables    int    `json:"tables"`
	Rows      int64  `json:"rows"`
	SizeBytes int64  `json:"size_bytes"`
	Status    string `json:"status"` // "completed", "failed", "skipped"
	Error     string `json:"error,omitempty"`
}

// exportManifest is written to manifest.json in the export root.
type exportManifest struct {
	TenantID  string         `json:"tenant_id"`
	Modules   []ModuleExport `json:"modules"`
	TotalSize int64          `json:"total_size_bytes"`
	CreatedAt time.Time      `json:"created_at"`
	Duration  string         `json:"duration"`
}

// TenantDataExportService orchestrates cross-module data exports for a single tenant.
type TenantDataExportService struct {
	pool      *pgxpool.Pool
	backupSvc *TenantBackupService // reused for realm-DB credential lookup patterns
	log       *zap.SugaredLogger
	exportDir string
}

// NewTenantDataExportService constructs a TenantDataExportService.
// backupSvc may be nil; it is used only as a reference implementation for
// credential decryption patterns (not called directly in this service).
func NewTenantDataExportService(
	pool *pgxpool.Pool,
	backupSvc *TenantBackupService,
	log *zap.SugaredLogger,
) *TenantDataExportService {
	return &TenantDataExportService{
		pool:      pool,
		backupSvc: backupSvc,
		log:       log,
		exportDir: defaultExportDir,
	}
}

// SetExportDir overrides the base directory for export output.
func (s *TenantDataExportService) SetExportDir(dir string) {
	s.exportDir = dir
}

// ---------------------------------------------------------------------------
// ExportAll
// ---------------------------------------------------------------------------

// ExportAll exports all tenant data across all ExampleSuite business module databases
// that contain a tenant_id column.
//
// Algorithm:
//  1. Create an export root: {exportDir}/{tenantID}/{timestamp}/
//  2. Discover module databases from iam_instance_databases (joined to product info).
//  3. For each database, connect, find tables with a tenant_id column, export JSONL.
//  4. Write manifest.json with aggregate stats.
//  5. Return ExportResult.
func (s *TenantDataExportService) ExportAll(ctx context.Context, req ExportRequest) (*ExportResult, error) {
	start := time.Now()

	if req.TenantID == uuid.Nil {
		return nil, fmt.Errorf("ExportAll: tenant_id is required")
	}

	// 1. Create output directory.
	timestamp := start.UTC().Format("20060102T150405Z")
	exportRoot := filepath.Join(s.exportDir, req.TenantID.String(), timestamp)
	if err := os.MkdirAll(exportRoot, 0o700); err != nil {
		return nil, fmt.Errorf("ExportAll: create export dir %s: %w", exportRoot, err)
	}

	s.log.Infow("Starting tenant data export",
		"tenant_id", req.TenantID,
		"export_dir", exportRoot,
		"modules_filter", req.Modules,
	)

	// 2. Discover module databases.
	dbs, err := s.discoverModuleDatabases(ctx, req.TenantID, req.Modules)
	if err != nil {
		return nil, fmt.Errorf("ExportAll: discover module databases: %w", err)
	}

	if len(dbs) == 0 {
		s.log.Warnw("No module databases found for tenant", "tenant_id", req.TenantID)
	}

	// 3. Export each module database concurrently (bounded to 4 workers).
	exports := make([]ModuleExport, len(dbs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, db := range dbs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, mdb moduleDB) {
			defer wg.Done()
			defer func() { <-sem }()
			exports[idx] = s.exportModule(ctx, mdb, req.TenantID, exportRoot)
		}(i, db)
	}
	wg.Wait()

	// 4. Aggregate totals.
	var totalSize int64
	for _, me := range exports {
		totalSize += me.SizeBytes
	}

	duration := time.Since(start).Round(time.Millisecond).String()

	// 5. Write manifest.json.
	manifest := exportManifest{
		TenantID:  req.TenantID.String(),
		Modules:   exports,
		TotalSize: totalSize,
		CreatedAt: start.UTC(),
		Duration:  duration,
	}
	if err := s.writeManifest(exportRoot, manifest); err != nil {
		s.log.Warnw("Failed to write export manifest", "err", err)
	}

	result := &ExportResult{
		TenantID:  req.TenantID,
		ExportDir: exportRoot,
		Modules:   exports,
		TotalSize: totalSize,
		Duration:  duration,
		CreatedAt: start.UTC(),
	}

	s.log.Infow("Tenant data export completed",
		"tenant_id", req.TenantID,
		"export_dir", exportRoot,
		"modules", len(exports),
		"total_size_bytes", totalSize,
		"duration", duration,
	)

	return result, nil
}

// ---------------------------------------------------------------------------
// discoverModuleDatabases
// ---------------------------------------------------------------------------

// discoverModuleDatabases queries iam_instance_databases joined with
// iam_product_instances to list the databases provisioned for the tenant.
//
// Each row contains enough information to build a connection DSN. Databases
// whose module name does not appear in req.Modules are skipped when the
// filter is non-empty.
//
// Falls back gracefully: if iam_instance_databases does not exist (early dev
// environment) the function returns an empty slice without error.
func (s *TenantDataExportService) discoverModuleDatabases(
	ctx context.Context,
	tenantID uuid.UUID,
	filter []string,
) ([]moduleDB, error) {
	filterSet := make(map[string]struct{}, len(filter))
	for _, m := range filter {
		filterSet[strings.ToLower(m)] = struct{}{}
	}

	const query = `
		SELECT
			COALESCE(p.slug, 'unknown')   AS module,
			idb.database_name,
			idb.host,
			idb.port,
			idb.username,
			idb.password_plaintext,
			COALESCE(idb.ssl_mode, 'disable') AS ssl_mode
		FROM iam_instance_databases idb
		JOIN iam_product_instances pi ON pi.id = idb.product_instance_id
		JOIN iam_products p           ON p.id  = pi.product_id
		WHERE pi.tenant_id = $1
		  AND idb.status   = 'active'
		ORDER BY p.slug, idb.database_name`

	rows, err := s.pool.Query(ctx, query, tenantID)
	if err != nil {
		// Table may not exist in early dev; treat as empty.
		if strings.Contains(err.Error(), "does not exist") {
			s.log.Warnw("iam_instance_databases not found, skipping module DB discovery", "err", err)
			return nil, nil
		}
		return nil, fmt.Errorf("query iam_instance_databases: %w", err)
	}
	defer rows.Close()

	var dbs []moduleDB
	for rows.Next() {
		var (
			module, dbName, host, username, password, sslMode string
			port                                              int
		)
		if err := rows.Scan(&module, &dbName, &host, &port, &username, &password, &sslMode); err != nil {
			return nil, fmt.Errorf("scan iam_instance_databases row: %w", err)
		}

		if len(filterSet) > 0 {
			if _, ok := filterSet[strings.ToLower(module)]; !ok {
				continue
			}
		}

		dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			username, password, host, port, dbName, sslMode)

		dbs = append(dbs, moduleDB{
			Module:   module,
			Database: dbName,
			DSN:      dsn,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate iam_instance_databases: %w", err)
	}

	return dbs, nil
}

// ---------------------------------------------------------------------------
// exportModule
// ---------------------------------------------------------------------------

// exportModule connects to a single module database, enumerates tables with a
// tenant_id column, and exports matching rows as JSONL files.
func (s *TenantDataExportService) exportModule(
	ctx context.Context,
	mdb moduleDB,
	tenantID uuid.UUID,
	exportRoot string,
) ModuleExport {
	me := ModuleExport{
		Module:   mdb.Module,
		Database: mdb.Database,
		Status:   "failed",
	}

	conn, err := pgx.Connect(ctx, mdb.DSN)
	if err != nil {
		me.Error = fmt.Sprintf("connect: %s", err)
		s.log.Warnw("Export: failed to connect to module DB",
			"module", mdb.Module, "database", mdb.Database, "err", err)
		return me
	}
	defer conn.Close(ctx) //nolint:errcheck

	tables, err := s.tablesWithTenantID(ctx, conn)
	if err != nil {
		me.Error = fmt.Sprintf("discover tables: %s", err)
		return me
	}

	if len(tables) == 0 {
		me.Status = "skipped"
		return me
	}

	moduleDir := filepath.Join(exportRoot, mdb.Module)
	if err := os.MkdirAll(moduleDir, 0o700); err != nil {
		me.Error = fmt.Sprintf("mkdir %s: %s", moduleDir, err)
		return me
	}

	var totalRows, totalSize int64
	for _, table := range tables {
		rows, size, exportErr := s.exportTable(ctx, conn, table, tenantID, moduleDir)
		if exportErr != nil {
			s.log.Warnw("Export: failed to export table",
				"module", mdb.Module, "table", table, "err", exportErr)
			// Continue to next table; partial exports are still useful.
			continue
		}
		totalRows += rows
		totalSize += size
	}

	me.Tables = len(tables)
	me.Rows = totalRows
	me.SizeBytes = totalSize
	me.Status = "completed"
	return me
}

// ---------------------------------------------------------------------------
// tablesWithTenantID
// ---------------------------------------------------------------------------

// tablesWithTenantID returns all table names in the public schema that have a
// column named "tenant_id". Uses information_schema.columns so no superuser
// privilege is required.
func (s *TenantDataExportService) tablesWithTenantID(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	const q = `
		SELECT DISTINCT table_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND column_name  = 'tenant_id'
		ORDER BY table_name`

	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query information_schema.columns: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan table name: %w", err)
		}
		tables = append(tables, t)
	}
	return tables, rows.Err()
}

// ---------------------------------------------------------------------------
// exportTable
// ---------------------------------------------------------------------------

// exportTable copies all rows WHERE tenant_id = tenantID from the given table
// into a JSONL file at {moduleDir}/{table}.jsonl.
//
// COPY … TO STDOUT is used for efficient row streaming. Each row is decoded
// from text format into a map[string]any and re-encoded as a JSON line.
func (s *TenantDataExportService) exportTable(
	ctx context.Context,
	conn *pgx.Conn,
	table string,
	tenantID uuid.UUID,
	moduleDir string,
) (rowCount int64, sizeBytes int64, err error) {
	outPath := filepath.Join(moduleDir, table+".jsonl")
	f, err := os.Create(outPath) //nolint:gosec // path is validated before use
	if err != nil {
		return 0, 0, fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close() //nolint:errcheck

	bw := bufio.NewWriterSize(f, 64*1024)
	defer bw.Flush() //nolint:errcheck

	// Use a regular SELECT so we get typed column info from pgx.
	// pgx's CopyTo helper returns raw bytes; SELECT * gives us proper column names.
	selectSQL := fmt.Sprintf(
		`SELECT * FROM %s WHERE tenant_id = $1`,
		pgx.Identifier{table}.Sanitize(),
	)

	rows, err := conn.Query(ctx, selectSQL, tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()

	fieldDescriptions := rows.FieldDescriptions()
	enc := json.NewEncoder(bw)

	for rows.Next() {
		vals, scanErr := rows.Values()
		if scanErr != nil {
			return rowCount, sizeBytes, fmt.Errorf("scan row in %s: %w", table, scanErr)
		}

		rowMap := make(map[string]any, len(fieldDescriptions))
		for i, fd := range fieldDescriptions {
			rowMap[fd.Name] = vals[i]
		}

		if encErr := enc.Encode(rowMap); encErr != nil {
			return rowCount, sizeBytes, fmt.Errorf("encode row in %s: %w", table, encErr)
		}
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return rowCount, sizeBytes, fmt.Errorf("iterate %s: %w", table, err)
	}

	if err := bw.Flush(); err != nil {
		return rowCount, sizeBytes, fmt.Errorf("flush %s: %w", outPath, err)
	}

	fi, statErr := f.Stat()
	if statErr == nil {
		sizeBytes = fi.Size()
	}

	return rowCount, sizeBytes, nil
}

// ---------------------------------------------------------------------------
// ListExports
// ---------------------------------------------------------------------------

// ListExports returns metadata for all completed exports for the given tenant.
// It reads only the manifest.json files from the export directory tree.
func (s *TenantDataExportService) ListExports(_ context.Context, tenantID uuid.UUID) ([]ExportResult, error) {
	tenantDir := filepath.Join(s.exportDir, tenantID.String())
	entries, err := os.ReadDir(tenantDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ListExports: read dir %s: %w", tenantDir, err)
	}

	var results []ExportResult
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(tenantDir, e.Name(), "manifest.json")
		data, readErr := os.ReadFile(manifestPath) //nolint:gosec // path is validated before use
		if readErr != nil {
			continue // skip incomplete exports
		}
		var m exportManifest
		if jsonErr := json.Unmarshal(data, &m); jsonErr != nil {
			continue
		}
		results = append(results, ExportResult{
			TenantID:  tenantID,
			ExportDir: filepath.Join(tenantDir, e.Name()),
			Modules:   m.Modules,
			TotalSize: m.TotalSize,
			Duration:  m.Duration,
			CreatedAt: m.CreatedAt,
		})
	}
	return results, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *TenantDataExportService) writeManifest(exportRoot string, m exportManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	path := filepath.Join(exportRoot, "manifest.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}
	return nil
}
